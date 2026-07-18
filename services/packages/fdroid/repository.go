// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package fdroid

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	packages_model "forgejo.org/models/packages"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	packages_module "forgejo.org/modules/packages"
	fdroid_module "forgejo.org/modules/packages/fdroid"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/sync"
	packages_service "forgejo.org/services/packages"
)

const (
	EntryJARFilename   = "entry.jar"
	IndexV1JARFilename = "index-v1.jar"

	retainedV2Indexes = 5
)

var (
	repositoryLocker  = sync.NewExclusivePool()
	indexV2FilenameRE = regexp.MustCompile(`^index-v2\.[0-9a-f]{64}\.json$`)
)

// RepositoryURL returns the canonical base URL clients should configure.
func RepositoryURL(ownerName string) string {
	return strings.TrimSuffix(setting.AppURL, "/") + "/api/packages/" + url.PathEscape(ownerName) + "/fdroid/repo"
}

// GetRepositoryFingerprint returns the certificate fingerprint used by F-Droid
// clients to pin this owner's repository metadata.
func GetRepositoryFingerprint(ctx context.Context, ownerID int64) (string, error) {
	_, certificate, err := GetOrCreateRepositoryKey(ctx, ownerID)
	if err != nil {
		return "", err
	}
	return RepositoryFingerprint(certificate), nil
}

// GetOrCreateRepositoryVersion gets the internal package version that stores
// signed repository metadata.
func GetOrCreateRepositoryVersion(ctx context.Context, ownerID int64) (*packages_model.PackageVersion, error) {
	return packages_service.GetOrCreateInternalPackageVersion(ctx, ownerID, packages_model.TypeFDroid, fdroid_module.RepositoryPackage, fdroid_module.RepositoryVersion)
}

// BuildAllRepositoryFiles rebuilds the complete F-Droid repository snapshot.
func BuildAllRepositoryFiles(ctx context.Context, ownerID int64) error {
	return BuildRepository(ctx, ownerID)
}

// BuildRepository publishes signed v1 and v2 indexes for all current APKs.
func BuildRepository(ctx context.Context, ownerID int64) error {
	return buildRepository(ctx, ownerID, 0)
}

// BuildRepositoryWithoutFile publishes a snapshot that excludes one APK. It is
// used before deleting that file, so a failed deletion leaves an unindexed file
// instead of a signed index that points at a missing APK.
func BuildRepositoryWithoutFile(ctx context.Context, ownerID, excludedFileID int64) error {
	if excludedFileID <= 0 {
		return errors.New("F-Droid excluded file ID must be positive")
	}
	return buildRepository(ctx, ownerID, excludedFileID)
}

func buildRepository(ctx context.Context, ownerID, excludedFileID int64) error {
	lockKey := fmt.Sprintf("pkg_%d_fdroid_repository", ownerID)
	repositoryLocker.CheckIn(lockKey)
	defer repositoryLocker.CheckOut(lockKey)

	owner, err := user_model.GetUserByID(ctx, ownerID)
	if err != nil {
		return err
	}
	privateKey, certificate, err := GetOrCreateRepositoryKey(ctx, ownerID)
	if err != nil {
		return err
	}

	data, err := collectRepositoryData(ctx, owner, RepositoryFingerprint(certificate), time.Now(), excludedFileID)
	if err != nil {
		return err
	}
	generated, err := BuildIndexes(data)
	if err != nil {
		return err
	}
	entryJAR, err := CreateSignedJAR(EntryJSONFilename, generated.EntryJSON, certificate, privateKey, JARSignatureProfileSHA256)
	if err != nil {
		return fmt.Errorf("sign F-Droid entry: %w", err)
	}
	indexV1JAR, err := CreateSignedJAR(IndexV1JSONFilename, generated.IndexV1JSON, certificate, privateKey, JARSignatureProfileSHA1)
	if err != nil {
		return fmt.Errorf("sign F-Droid v1 index: %w", err)
	}

	repositoryVersion, err := GetOrCreateRepositoryVersion(ctx, ownerID)
	if err != nil {
		return err
	}
	// Publish immutable content first, the legacy index next, and the signed v2
	// entry point last. A client therefore always sees a valid referenced index.
	if err := saveRepositoryFile(ctx, repositoryVersion, generated.IndexV2Filename, generated.IndexV2JSON); err != nil {
		return err
	}
	if err := saveRepositoryFile(ctx, repositoryVersion, IndexV2JSONFilename, generated.IndexV2JSON); err != nil {
		return err
	}
	if err := saveRepositoryFile(ctx, repositoryVersion, IndexV1JARFilename, indexV1JAR); err != nil {
		return err
	}
	if err := saveRepositoryFile(ctx, repositoryVersion, EntryJARFilename, entryJAR); err != nil {
		return err
	}

	return pruneRepositoryIndexes(ctx, repositoryVersion, generated.IndexV2Filename)
}

func collectRepositoryData(ctx context.Context, owner *user_model.User, fingerprint string, now time.Time, excludedFileID int64) (RepositoryData, error) {
	versions, err := packages_model.GetVersionsByPackageType(ctx, owner.ID, packages_model.TypeFDroid)
	if err != nil {
		return RepositoryData{}, err
	}
	sort.Slice(versions, func(i, j int) bool {
		if versions[i].CreatedUnix != versions[j].CreatedUnix {
			return versions[i].CreatedUnix > versions[j].CreatedUnix
		}
		return versions[i].ID > versions[j].ID
	})

	apps := make(map[int64]*AppData)
	for _, version := range versions {
		pck, err := packages_model.GetPackageByID(ctx, version.PackageID)
		if err != nil {
			return RepositoryData{}, err
		}
		file, excluded, err := findPackageFile(ctx, version.ID, excludedFileID)
		if err != nil {
			return RepositoryData{}, fmt.Errorf("F-Droid package %s version %s: %w", pck.Name, version.Version, err)
		}
		if file == nil {
			if excluded {
				continue
			}
			return RepositoryData{}, fmt.Errorf("F-Droid package %s version %s has no lead APK", pck.Name, version.Version)
		}

		properties, err := packages_model.GetProperties(ctx, packages_model.PropertyTypeFile, file.ID)
		if err != nil {
			return RepositoryData{}, err
		}
		metadataJSON := propertyValue(properties, fdroid_module.PropertyFileMetadata)
		if metadataJSON == "" {
			return RepositoryData{}, fmt.Errorf("F-Droid APK %s has no metadata", file.Name)
		}
		var fileMetadata fdroid_module.FileMetadata
		if err := json.Unmarshal([]byte(metadataJSON), &fileMetadata); err != nil {
			return RepositoryData{}, fmt.Errorf("decode F-Droid APK metadata for %s: %w", file.Name, err)
		}
		if fileMetadata.PackageName != pck.Name || strconv.FormatInt(fileMetadata.VersionCode, 10) != version.Version {
			return RepositoryData{}, fmt.Errorf("F-Droid APK %s metadata does not match its package version", file.Name)
		}

		packageProperties, err := packages_model.GetPropertiesByName(ctx, packages_model.PropertyTypePackage, pck.ID, fdroid_module.PropertySignerSHA256)
		if err != nil {
			return RepositoryData{}, err
		}
		if len(packageProperties) != 1 {
			return RepositoryData{}, fmt.Errorf("F-Droid package %s does not have exactly one pinned signer", pck.Name)
		}
		pinnedSigner := strings.ToLower(packageProperties[0].Value)
		if strings.ToLower(fileMetadata.SignerSHA256) != pinnedSigner || strings.ToLower(propertyValue(properties, fdroid_module.PropertySignerSHA256)) != pinnedSigner {
			return RepositoryData{}, fmt.Errorf("F-Droid APK %s signer does not match the pinned package signer", file.Name)
		}

		blob, err := packages_model.GetBlobByID(ctx, file.BlobID)
		if err != nil {
			return RepositoryData{}, err
		}
		var versionMetadata fdroid_module.VersionMetadata
		if err := json.Unmarshal([]byte(version.MetadataJSON), &versionMetadata); err != nil {
			return RepositoryData{}, fmt.Errorf("decode F-Droid package metadata for %s: %w", pck.Name, err)
		}

		added := file.CreatedUnix.AsTime().UnixMilli()
		app := apps[pck.ID]
		if app == nil {
			name := versionMetadata.Name
			if name == "" {
				name = pck.Name
			}
			app = &AppData{
				PackageName:     pck.Name,
				Name:            name,
				Summary:         versionMetadata.Summary,
				Description:     versionMetadata.Description,
				License:         versionMetadata.License,
				Website:         versionMetadata.Website,
				SourceCode:      versionMetadata.SourceCode,
				IssueTracker:    versionMetadata.IssueTracker,
				Added:           added,
				LastUpdated:     added,
				PreferredSigner: pinnedSigner,
			}
			apps[pck.ID] = app
		}
		if added < app.Added {
			app.Added = added
		}
		if added > app.LastUpdated {
			app.LastUpdated = added
		}

		versionName := fileMetadata.VersionName
		if versionName == "" {
			versionName = version.Version
		}
		app.Versions = append(app.Versions, VersionData{
			Added:              added,
			APKName:            file.Name,
			SHA256:             blob.HashSHA256,
			Size:               blob.Size,
			VersionName:        versionName,
			VersionCode:        fileMetadata.VersionCode,
			MinSDKVersion:      fileMetadata.MinSDKVersion,
			TargetSDKVersion:   fileMetadata.TargetSDKVersion,
			MaxSDKVersion:      positiveInt(fileMetadata.MaxSDKVersion),
			Signers:            []string{pinnedSigner},
			HasMultipleSigners: false,
			Permissions:        permissionData(fileMetadata.Permissions),
			PermissionsSDK23:   permissionData(fileMetadata.PermissionsSDK23),
			ABIs:               append([]string(nil), fileMetadata.NativeCode...),
			Features:           append([]string(nil), fileMetadata.Features...),
		})
	}

	appList := make([]AppData, 0, len(apps))
	for _, app := range apps {
		appList = append(appList, *app)
	}
	maxAge := 14
	return RepositoryData{
		Address:     RepositoryURL(owner.Name),
		Name:        owner.DisplayName() + " F-Droid Repository",
		Description: "Android packages published by " + owner.DisplayName() + " on Forgejo.",
		Fingerprint: fingerprint,
		Timestamp:   now.UnixMilli(),
		MaxAge:      &maxAge,
		Apps:        appList,
	}, nil
}

func findPackageFile(ctx context.Context, versionID, excludedFileID int64) (*packages_model.PackageFile, bool, error) {
	files, err := packages_model.GetFilesByVersionID(ctx, versionID)
	if err != nil {
		return nil, false, err
	}
	var candidate *packages_model.PackageFile
	excluded := false
	for _, file := range files {
		if file.ID == excludedFileID {
			excluded = true
			continue
		}
		if !file.IsLead || !strings.HasSuffix(strings.ToLower(file.Name), ".apk") {
			continue
		}
		if candidate != nil {
			return nil, excluded, errors.New("multiple lead APK files")
		}
		candidate = file
	}
	return candidate, excluded, nil
}

func saveRepositoryFile(ctx context.Context, version *packages_model.PackageVersion, filename string, data []byte) error {
	buffer, err := packages_module.CreateHashedBufferFromReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer buffer.Close()

	_, err = packages_service.AddFileToPackageVersionInternal(ctx, version, &packages_service.PackageFileCreationInfo{
		PackageFileInfo:   packages_service.PackageFileInfo{Filename: filename},
		Creator:           user_model.NewGhostUser(),
		Data:              buffer,
		OverwriteExisting: true,
	})
	if err != nil {
		return fmt.Errorf("publish F-Droid repository file %s: %w", filename, err)
	}
	return nil
}

func pruneRepositoryIndexes(ctx context.Context, version *packages_model.PackageVersion, currentFilename string) error {
	files, err := packages_model.GetFilesByVersionID(ctx, version.ID)
	if err != nil {
		return err
	}
	indexes := make([]*packages_model.PackageFile, 0)
	for _, file := range files {
		if IsIndexV2Filename(file.Name) {
			indexes = append(indexes, file)
		}
	}
	sort.Slice(indexes, func(i, j int) bool { return indexes[i].ID > indexes[j].ID })

	keep := make(map[int64]struct{}, retainedV2Indexes)
	for _, file := range indexes {
		if file.Name == currentFilename {
			keep[file.ID] = struct{}{}
			break
		}
	}
	for _, file := range indexes {
		if len(keep) >= retainedV2Indexes {
			break
		}
		keep[file.ID] = struct{}{}
	}
	for _, file := range indexes {
		if _, ok := keep[file.ID]; ok {
			continue
		}
		if err := packages_service.DeletePackageFile(ctx, file); err != nil {
			return err
		}
	}
	return nil
}

// IsIndexV2Filename reports whether filename is one of Forgejo's immutable v2
// indexes.
func IsIndexV2Filename(filename string) bool {
	return indexV2FilenameRE.MatchString(filename)
}

// IsRepositoryMetadataFilename reports whether a request targets generated
// repository metadata rather than an uploaded APK.
func IsRepositoryMetadataFilename(filename string) bool {
	return filename == EntryJARFilename || filename == IndexV1JARFilename || filename == IndexV2JSONFilename || IsIndexV2Filename(filename)
}

// GetRepositoryFile returns a generated metadata file or an uploaded APK.
func GetRepositoryFile(ctx context.Context, ownerID int64, filename string) (io.ReadSeekCloser, *url.URL, *packages_model.PackageFile, error) {
	if IsRepositoryMetadataFilename(filename) {
		version, err := GetOrCreateRepositoryVersion(ctx, ownerID)
		if err != nil {
			return nil, nil, nil, err
		}
		return packages_service.GetFileStreamByPackageVersion(ctx, version, &packages_service.PackageFileInfo{Filename: filename})
	}

	files, _, err := packages_model.SearchFiles(ctx, &packages_model.PackageFileSearchOptions{
		OwnerID:     ownerID,
		PackageType: packages_model.TypeFDroid,
		Query:       filename,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	var match *packages_model.PackageFile
	for _, file := range files {
		if file.LowerName != strings.ToLower(filename) {
			continue
		}
		if match != nil {
			return nil, nil, nil, fmt.Errorf("multiple F-Droid files match %s", filename)
		}
		match = file
	}
	if match == nil {
		return nil, nil, nil, packages_model.ErrPackageFileNotExist
	}
	return packages_service.GetPackageFileStream(ctx, match)
}

func propertyValue(properties []*packages_model.PackageProperty, name string) string {
	for _, property := range properties {
		if property.Name == name {
			return property.Value
		}
	}
	return ""
}

func positiveInt(value int) *int {
	if value <= 0 {
		return nil
	}
	return &value
}

func permissionData(permissions []fdroid_module.Permission) []PermissionData {
	result := make([]PermissionData, 0, len(permissions))
	for _, permission := range permissions {
		result = append(result, PermissionData{
			Name:          permission.Name,
			MaxSDKVersion: permission.MaxSDKVersion,
		})
	}
	return result
}
