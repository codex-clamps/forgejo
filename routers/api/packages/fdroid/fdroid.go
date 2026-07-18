// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package fdroid

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	packages_model "forgejo.org/models/packages"
	"forgejo.org/modules/json"
	packages_module "forgejo.org/modules/packages"
	fdroid_module "forgejo.org/modules/packages/fdroid"
	"forgejo.org/modules/sync"
	"forgejo.org/modules/util"
	"forgejo.org/routers/api/packages/helper"
	"forgejo.org/services/context"
	packages_service "forgejo.org/services/packages"
	fdroid_service "forgejo.org/services/packages/fdroid"
)

var (
	applicationIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$`)
	mutationLocker       = sync.NewExclusivePool()
)

func apiError(ctx *context.Context, status int, obj any) {
	helper.LogAndProcessError(ctx, status, obj, func(message string) {
		ctx.PlainText(status, message)
	})
}

func lockOwner(ownerID int64) func() {
	key := fmt.Sprintf("pkg_%d_fdroid_mutation", ownerID)
	mutationLocker.CheckIn(key)
	return func() { mutationLocker.CheckOut(key) }
}

// UploadPackage verifies and publishes an APK without modifying its signature.
func UploadPackage(ctx *context.Context) {
	upload, needToClose, err := ctx.UploadStream()
	if err != nil {
		if context.IsFormError(err) {
			apiError(ctx, http.StatusBadRequest, err)
		} else {
			apiError(ctx, http.StatusInternalServerError, err)
		}
		return
	}
	if needToClose {
		defer upload.Close()
	}

	buffer, err := packages_module.CreateHashedBufferFromReader(upload)
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	defer buffer.Close()

	pck, err := fdroid_service.ParsePackage(ctx, buffer)
	if err != nil {
		apiError(ctx, http.StatusBadRequest, err)
		return
	}
	if !applicationIDPattern.MatchString(pck.Name) || pck.FileMetadata.PackageName != pck.Name || pck.FileMetadata.VersionCode <= 0 {
		apiError(ctx, http.StatusBadRequest, "invalid Android application ID or version code")
		return
	}
	if pck.FileMetadata.VersionName == "" {
		pck.FileMetadata.VersionName = strconv.FormatInt(pck.FileMetadata.VersionCode, 10)
	}
	pck.Version = strconv.FormatInt(pck.FileMetadata.VersionCode, 10)
	if pck.VersionMetadata.Name == "" {
		pck.VersionMetadata.Name = pck.Name
	}
	pck.FileMetadata.SignerSHA256 = strings.ToLower(pck.FileMetadata.SignerSHA256)

	metadataJSON, err := json.Marshal(pck.FileMetadata)
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	if _, err := buffer.Seek(0, io.SeekStart); err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}

	release := lockOwner(ctx.Package.Owner.ID)
	defer release()
	if err := validatePinnedSigner(ctx, pck.Name, pck.FileMetadata.SignerSHA256); err != nil {
		if errors.Is(err, fdroid_service.ErrAPKSignerMismatch) {
			apiError(ctx, http.StatusConflict, err)
		} else {
			apiError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	filename := fmt.Sprintf("%s_%d.apk", pck.Name, pck.FileMetadata.VersionCode)
	_, _, err = packages_service.CreatePackageOrAddFileToExisting(
		ctx,
		&packages_service.PackageCreationInfo{
			PackageInfo: packages_service.PackageInfo{
				Owner:       ctx.Package.Owner,
				PackageType: packages_model.TypeFDroid,
				Name:        pck.Name,
				Version:     pck.Version,
			},
			Creator:  ctx.Doer,
			Metadata: pck.VersionMetadata,
			PackageProperties: map[string]string{
				fdroid_module.PropertySignerSHA256: pck.FileMetadata.SignerSHA256,
			},
		},
		&packages_service.PackageFileCreationInfo{
			PackageFileInfo: packages_service.PackageFileInfo{Filename: filename},
			Creator:         ctx.Doer,
			Data:            buffer,
			IsLead:          true,
			Properties: map[string]string{
				fdroid_module.PropertyFileMetadata: string(metadataJSON),
				fdroid_module.PropertySignerSHA256: pck.FileMetadata.SignerSHA256,
			},
		},
	)
	if err != nil {
		switch {
		case errors.Is(err, packages_model.ErrDuplicatePackageVersion), errors.Is(err, packages_model.ErrDuplicatePackageFile):
			apiError(ctx, http.StatusConflict, err)
		case errors.Is(err, packages_service.ErrQuotaTotalCount), errors.Is(err, packages_service.ErrQuotaTypeSize), errors.Is(err, packages_service.ErrQuotaTotalSize):
			apiError(ctx, http.StatusForbidden, err)
		default:
			apiError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	if err := fdroid_service.BuildRepository(ctx, ctx.Package.Owner.ID); err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	ctx.Status(http.StatusCreated)
}

func validatePinnedSigner(ctx *context.Context, packageName, signer string) error {
	pck, err := packages_model.GetPackageByName(ctx, ctx.Package.Owner.ID, packages_model.TypeFDroid, packageName)
	if err != nil {
		if errors.Is(err, packages_model.ErrPackageNotExist) {
			return nil
		}
		return err
	}
	properties, err := packages_model.GetPropertiesByName(ctx, packages_model.PropertyTypePackage, pck.ID, fdroid_module.PropertySignerSHA256)
	if err != nil {
		return err
	}
	if len(properties) != 1 || !strings.EqualFold(properties[0].Value, signer) {
		return fdroid_service.ErrAPKSignerMismatch
	}
	return nil
}

// GetRepositoryFile serves signed indexes and the APKs referenced by them.
func GetRepositoryFile(ctx *context.Context) {
	filename := ctx.Params("filename")
	if filename == "" || strings.ContainsAny(filename, `/\\`) {
		ctx.Status(http.StatusNotFound)
		return
	}

	stream, redirectURL, file, err := fdroid_service.GetRepositoryFile(ctx, ctx.Package.Owner.ID, filename)
	if err != nil {
		if errors.Is(err, util.ErrNotExist) {
			apiError(ctx, http.StatusNotFound, err)
		} else {
			apiError(ctx, http.StatusInternalServerError, err)
		}
		return
	}

	contentType := "application/octet-stream"
	cacheDuration := 5 * time.Minute
	switch {
	case strings.HasSuffix(filename, ".apk"):
		contentType = "application/vnd.android.package-archive"
		cacheDuration = 24 * time.Hour
	case strings.HasSuffix(filename, ".jar"):
		contentType = "application/java-archive"
	case filename == fdroid_service.IndexV2JSONFilename:
		contentType = "application/json"
	case fdroid_service.IsIndexV2Filename(filename):
		contentType = "application/json"
		cacheDuration = 24 * time.Hour
	}
	helper.ServePackageFile(ctx, stream, redirectURL, file, &context.ServeHeaderOptions{
		ContentType:   contentType,
		Disposition:   "inline",
		Filename:      filename,
		CacheDuration: cacheDuration,
		LastModified:  file.CreatedUnix.AsLocalTime(),
	})
}

// DeletePackage removes an APK after first publishing an index that no longer
// references it.
func DeletePackage(ctx *context.Context) {
	filename := ctx.Params("filename")
	if filename == "" || !strings.HasSuffix(strings.ToLower(filename), ".apk") || strings.ContainsAny(filename, `/\\`) {
		ctx.Status(http.StatusNotFound)
		return
	}

	release := lockOwner(ctx.Package.Owner.ID)
	defer release()
	file, err := findPackageFile(ctx, filename)
	if err != nil {
		if errors.Is(err, util.ErrNotExist) {
			apiError(ctx, http.StatusNotFound, err)
		} else {
			apiError(ctx, http.StatusInternalServerError, err)
		}
		return
	}
	if err := fdroid_service.BuildRepositoryWithoutFile(ctx, ctx.Package.Owner.ID, file.ID); err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	if err := packages_service.RemovePackageFileAndVersionIfUnreferenced(ctx, ctx.Doer, file); err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

func findPackageFile(ctx *context.Context, filename string) (*packages_model.PackageFile, error) {
	files, _, err := packages_model.SearchFiles(ctx, &packages_model.PackageFileSearchOptions{
		OwnerID:     ctx.Package.Owner.ID,
		PackageType: packages_model.TypeFDroid,
		Query:       filename,
	})
	if err != nil {
		return nil, err
	}
	var match *packages_model.PackageFile
	for _, file := range files {
		if file.LowerName != strings.ToLower(filename) {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("multiple F-Droid files match %s", filename)
		}
		match = file
	}
	if match == nil {
		return nil, packages_model.ErrPackageFileNotExist
	}
	return match, nil
}

// RebuildRepository regenerates both supported index formats from the current
// package database.
func RebuildRepository(ctx *context.Context) {
	release := lockOwner(ctx.Package.Owner.ID)
	defer release()
	if err := fdroid_service.BuildRepository(ctx, ctx.Package.Owner.ID); err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}
