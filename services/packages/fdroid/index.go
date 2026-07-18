// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package fdroid

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"forgejo.org/modules/json"
)

const (
	// IndexVersion is the current fdroidserver metadata/index schema version.
	IndexVersion int64 = 30000

	DefaultLocale       = "en-US"
	IndexV1JSONFilename = "index-v1.json"
	IndexV2JSONFilename = "index-v2.json"
	EntryJSONFilename   = "entry.json"
)

// RepositoryData is the neutral input model used to generate both supported
// F-Droid index formats. All timestamps are Unix epoch milliseconds.
type RepositoryData struct {
	Address     string
	Name        string
	Description string
	Icon        string
	Fingerprint string
	Timestamp   int64
	MaxAge      *int
	Mirrors     []string
	Apps        []AppData
}

type AppData struct {
	PackageName     string
	Name            string
	Summary         string
	Description     string
	License         string
	Website         string
	SourceCode      string
	IssueTracker    string
	Added           int64
	LastUpdated     int64
	Categories      []string
	PreferredSigner string
	Versions        []VersionData
}

type VersionData struct {
	Added              int64
	APKName            string
	SHA256             string
	Size               int64
	VersionName        string
	VersionCode        int64
	MinSDKVersion      int
	TargetSDKVersion   int
	MaxSDKVersion      *int
	Signers            []string
	HasMultipleSigners bool
	Permissions        []PermissionData
	PermissionsSDK23   []PermissionData
	ABIs               []string
	Features           []string
}

type PermissionData struct {
	Name          string
	MaxSDKVersion *int
}

// GeneratedIndexes contains unsigned JSON payloads. IndexV1JSON and EntryJSON
// are intended to be placed into their respective signed JAR files.
type GeneratedIndexes struct {
	IndexV1JSON     []byte
	IndexV2JSON     []byte
	EntryJSON       []byte
	IndexV2Filename string
	Fingerprint     string
}

type Entry struct {
	Timestamp int64                  `json:"timestamp"`
	Version   int64                  `json:"version"`
	MaxAge    *int                   `json:"maxAge,omitempty"`
	Index     EntryFileV2            `json:"index"`
	Diffs     map[string]EntryFileV2 `json:"diffs,omitempty"`
}

type EntryFileV2 struct {
	Name        string `json:"name"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	NumPackages int    `json:"numPackages"`
}

type IndexV2 struct {
	Repo     RepoV2               `json:"repo"`
	Packages map[string]PackageV2 `json:"packages"`
}

type RepoV2 struct {
	Name        LocalizedTextV2       `json:"name,omitempty"`
	Address     string                `json:"address"`
	Description LocalizedTextV2       `json:"description,omitempty"`
	Mirrors     []MirrorV2            `json:"mirrors,omitempty"`
	Timestamp   int64                 `json:"timestamp"`
	Categories  map[string]CategoryV2 `json:"categories,omitempty"`
}

type MirrorV2 struct {
	URL string `json:"url"`
}

type CategoryV2 struct {
	Name        LocalizedTextV2 `json:"name"`
	Description LocalizedTextV2 `json:"description,omitempty"`
}

type LocalizedTextV2 map[string]string

type PackageV2 struct {
	Metadata MetadataV2                  `json:"metadata"`
	Versions map[string]PackageVersionV2 `json:"versions"`
}

type MetadataV2 struct {
	Name            LocalizedTextV2 `json:"name,omitempty"`
	Summary         LocalizedTextV2 `json:"summary,omitempty"`
	Description     LocalizedTextV2 `json:"description,omitempty"`
	Added           int64           `json:"added"`
	LastUpdated     int64           `json:"lastUpdated"`
	Website         string          `json:"webSite,omitempty"`
	License         string          `json:"license,omitempty"`
	SourceCode      string          `json:"sourceCode,omitempty"`
	IssueTracker    string          `json:"issueTracker,omitempty"`
	PreferredSigner string          `json:"preferredSigner,omitempty"`
	Categories      []string        `json:"categories,omitempty"`
}

type PackageVersionV2 struct {
	Added    int64      `json:"added"`
	File     FileV2     `json:"file"`
	Manifest ManifestV2 `json:"manifest"`
}

type FileV2 struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type ManifestV2 struct {
	VersionName         string         `json:"versionName"`
	VersionCode         int64          `json:"versionCode"`
	UsesSDK             *UsesSDKV2     `json:"usesSdk,omitempty"`
	MaxSDKVersion       *int           `json:"maxSdkVersion,omitempty"`
	Signer              *SignerV2      `json:"signer,omitempty"`
	UsesPermission      []PermissionV2 `json:"usesPermission,omitempty"`
	UsesPermissionSDK23 []PermissionV2 `json:"usesPermissionSdk23,omitempty"`
	NativeCode          []string       `json:"nativecode,omitempty"`
	Features            []FeatureV2    `json:"features,omitempty"`
}

type UsesSDKV2 struct {
	MinSDKVersion    int `json:"minSdkVersion"`
	TargetSDKVersion int `json:"targetSdkVersion"`
}

type SignerV2 struct {
	SHA256             []string `json:"sha256"`
	HasMultipleSigners bool     `json:"hasMultipleSigners,omitempty"`
}

type PermissionV2 struct {
	Name          string `json:"name"`
	MaxSDKVersion *int   `json:"maxSdkVersion,omitempty"`
}

type FeatureV2 struct {
	Name string `json:"name"`
}

type IndexV1 struct {
	Repo     RepoV1                 `json:"repo"`
	Requests RequestsV1             `json:"requests"`
	Apps     []AppV1                `json:"apps"`
	Packages map[string][]PackageV1 `json:"packages"`
}

type RepoV1 struct {
	Timestamp   int64    `json:"timestamp"`
	Version     int64    `json:"version"`
	MaxAge      *int     `json:"maxage,omitempty"`
	Name        string   `json:"name"`
	Icon        string   `json:"icon"`
	Address     string   `json:"address"`
	Description string   `json:"description"`
	Mirrors     []string `json:"mirrors,omitempty"`
}

type RequestsV1 struct {
	Install   []string `json:"install"`
	Uninstall []string `json:"uninstall"`
}

type AppV1 struct {
	Categories           []string `json:"categories,omitempty"`
	Summary              string   `json:"summary,omitempty"`
	Description          string   `json:"description,omitempty"`
	IssueTracker         string   `json:"issueTracker,omitempty"`
	SourceCode           string   `json:"sourceCode,omitempty"`
	Name                 string   `json:"name,omitempty"`
	SuggestedVersionName string   `json:"suggestedVersionName,omitempty"`
	SuggestedVersionCode string   `json:"suggestedVersionCode,omitempty"`
	License              string   `json:"license"`
	Website              string   `json:"webSite,omitempty"`
	Added                int64    `json:"added,omitempty"`
	PackageName          string   `json:"packageName"`
	LastUpdated          int64    `json:"lastUpdated,omitempty"`
}

type PackageV1 struct {
	Added               int64          `json:"added,omitempty"`
	APKName             string         `json:"apkName"`
	Hash                string         `json:"hash"`
	HashType            string         `json:"hashType"`
	MinSDKVersion       *int           `json:"minSdkVersion,omitempty"`
	MaxSDKVersion       *int           `json:"maxSdkVersion,omitempty"`
	TargetSDKVersion    *int           `json:"targetSdkVersion,omitempty"`
	PackageName         string         `json:"packageName"`
	Signer              string         `json:"signer,omitempty"`
	Size                int64          `json:"size"`
	UsesPermission      []PermissionV1 `json:"uses-permission,omitempty"`
	UsesPermissionSDK23 []PermissionV1 `json:"uses-permission-sdk-23,omitempty"`
	VersionCode         int64          `json:"versionCode"`
	VersionName         string         `json:"versionName"`
	NativeCode          []string       `json:"nativecode,omitempty"`
	Features            []string       `json:"features,omitempty"`
}

// PermissionV1 is encoded as [name, maxSdkVersion], as required by index-v1.
type PermissionV1 struct {
	Name          string
	MaxSDKVersion *int
}

func (p PermissionV1) MarshalJSON() ([]byte, error) {
	return json.Marshal([2]any{p.Name, p.MaxSDKVersion})
}

func (p *PermissionV1) UnmarshalJSON(data []byte) error {
	var values []any
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	if len(values) != 2 {
		return errors.New("F-Droid v1 permission must contain two elements")
	}
	name, ok := values[0].(string)
	if !ok {
		return errors.New("F-Droid v1 permission name must be a string")
	}
	p.Name = name
	if values[1] == nil {
		p.MaxSDKVersion = nil
		return nil
	}
	encodedMaxSDKVersion, err := json.Marshal(values[1])
	if err != nil {
		return err
	}
	var maxSDKVersion int
	if err := json.Unmarshal(encodedMaxSDKVersion, &maxSDKVersion); err != nil {
		return err
	}
	p.MaxSDKVersion = &maxSDKVersion
	return nil
}

// BuildIndexes builds deterministic v1, v2, and entry JSON from one snapshot.
func BuildIndexes(data RepositoryData) (*GeneratedIndexes, error) {
	normalized, err := normalizeRepositoryData(data)
	if err != nil {
		return nil, err
	}

	indexV1JSON, err := buildIndexV1JSON(normalized)
	if err != nil {
		return nil, err
	}
	indexV2JSON, err := buildIndexV2JSON(normalized)
	if err != nil {
		return nil, err
	}
	indexV2Filename, entryJSON, err := BuildEntryJSON(normalized.Timestamp, normalized.MaxAge, indexV2JSON, len(normalized.Apps))
	if err != nil {
		return nil, err
	}

	return &GeneratedIndexes{
		IndexV1JSON:     indexV1JSON,
		IndexV2JSON:     indexV2JSON,
		EntryJSON:       entryJSON,
		IndexV2Filename: indexV2Filename,
		Fingerprint:     normalized.Fingerprint,
	}, nil
}

// BuildEntryJSON creates an entry that points at an immutable content-addressed
// v2 index filename. The returned filename does not include the leading slash.
func BuildEntryJSON(timestamp int64, maxAge *int, indexV2JSON []byte, numPackages int) (string, []byte, error) {
	if len(indexV2JSON) == 0 {
		return "", nil, errors.New("F-Droid v2 index is empty")
	}
	if numPackages < 0 {
		return "", nil, errors.New("F-Droid package count cannot be negative")
	}
	if maxAge != nil && *maxAge < 0 {
		return "", nil, errors.New("F-Droid max age cannot be negative")
	}
	var index struct {
		Repo struct {
			Timestamp int64 `json:"timestamp"`
		} `json:"repo"`
		Packages map[string]any `json:"packages"`
	}
	if err := json.Unmarshal(indexV2JSON, &index); err != nil {
		return "", nil, fmt.Errorf("invalid F-Droid v2 index: %w", err)
	}
	if index.Repo.Timestamp != timestamp {
		return "", nil, fmt.Errorf("F-Droid entry timestamp %d does not match index timestamp %d", timestamp, index.Repo.Timestamp)
	}
	if len(index.Packages) != numPackages {
		return "", nil, fmt.Errorf("F-Droid package count %d does not match index package count %d", numPackages, len(index.Packages))
	}

	digest := sha256.Sum256(indexV2JSON)
	digestHex := hex.EncodeToString(digest[:])
	filename := "index-v2." + digestHex + ".json"
	entry := Entry{
		Timestamp: timestamp,
		Version:   IndexVersion,
		MaxAge:    cloneInt(maxAge),
		Index: EntryFileV2{
			Name:        "/" + filename,
			SHA256:      digestHex,
			Size:        int64(len(indexV2JSON)),
			NumPackages: numPackages,
		},
	}
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return "", nil, err
	}
	return filename, entryJSON, nil
}

func buildIndexV1JSON(data RepositoryData) ([]byte, error) {
	apps := make([]AppV1, 0, len(data.Apps))
	packages := make(map[string][]PackageV1, len(data.Apps))
	for _, app := range data.Apps {
		appV1 := AppV1{
			Categories:   cloneStrings(app.Categories),
			Summary:      app.Summary,
			Description:  app.Description,
			IssueTracker: app.IssueTracker,
			SourceCode:   app.SourceCode,
			Name:         app.Name,
			License:      app.License,
			Website:      app.Website,
			Added:        app.Added,
			PackageName:  app.PackageName,
			LastUpdated:  app.LastUpdated,
		}
		if len(app.Versions) > 0 {
			appV1.SuggestedVersionName = app.Versions[0].VersionName
			appV1.SuggestedVersionCode = strconv.FormatInt(app.Versions[0].VersionCode, 10)
		}
		apps = append(apps, appV1)

		versions := make([]PackageV1, 0, len(app.Versions))
		for _, version := range app.Versions {
			packageV1 := PackageV1{
				Added:               version.Added,
				APKName:             version.APKName,
				Hash:                version.SHA256,
				HashType:            "sha256",
				MinSDKVersion:       sdkPointer(version.MinSDKVersion),
				MaxSDKVersion:       cloneInt(version.MaxSDKVersion),
				TargetSDKVersion:    sdkPointer(version.TargetSDKVersion),
				PackageName:         app.PackageName,
				Size:                version.Size,
				UsesPermission:      permissionsV1(version.Permissions),
				UsesPermissionSDK23: permissionsV1(version.PermissionsSDK23),
				VersionCode:         version.VersionCode,
				VersionName:         version.VersionName,
				NativeCode:          cloneStrings(version.ABIs),
				Features:            cloneStrings(version.Features),
			}
			if len(version.Signers) > 0 {
				packageV1.Signer = version.Signers[0]
			}
			versions = append(versions, packageV1)
		}
		packages[app.PackageName] = versions
	}

	index := IndexV1{
		Repo: RepoV1{
			Timestamp:   data.Timestamp,
			Version:     IndexVersion,
			MaxAge:      cloneInt(data.MaxAge),
			Name:        data.Name,
			Icon:        data.Icon,
			Address:     data.Address,
			Description: data.Description,
			Mirrors:     cloneStrings(data.Mirrors),
		},
		Requests: RequestsV1{Install: []string{}, Uninstall: []string{}},
		Apps:     apps,
		Packages: packages,
	}
	return json.Marshal(index)
}

func buildIndexV2JSON(data RepositoryData) ([]byte, error) {
	packages := make(map[string]PackageV2, len(data.Apps))
	categories := make(map[string]CategoryV2)
	for _, app := range data.Apps {
		for _, category := range app.Categories {
			categories[category] = CategoryV2{Name: localizedText(category)}
		}
		versions := make(map[string]PackageVersionV2, len(app.Versions))
		preferredSigner := app.PreferredSigner
		for _, version := range app.Versions {
			manifest := ManifestV2{
				VersionName:         version.VersionName,
				VersionCode:         version.VersionCode,
				MaxSDKVersion:       cloneInt(version.MaxSDKVersion),
				UsesPermission:      permissionsV2(version.Permissions),
				UsesPermissionSDK23: permissionsV2(version.PermissionsSDK23),
				NativeCode:          cloneStrings(version.ABIs),
				Features:            featuresV2(version.Features),
			}
			if version.MinSDKVersion > 0 || version.TargetSDKVersion > 0 {
				manifest.UsesSDK = &UsesSDKV2{
					MinSDKVersion:    version.MinSDKVersion,
					TargetSDKVersion: version.TargetSDKVersion,
				}
			}
			if len(version.Signers) > 0 {
				manifest.Signer = &SignerV2{
					SHA256:             cloneStrings(version.Signers),
					HasMultipleSigners: version.HasMultipleSigners,
				}
				if preferredSigner == "" {
					preferredSigner = version.Signers[0]
				}
			}
			versions[version.SHA256] = PackageVersionV2{
				Added: version.Added,
				File: FileV2{
					Name:   ensureLeadingSlash(version.APKName),
					SHA256: version.SHA256,
					Size:   version.Size,
				},
				Manifest: manifest,
			}
		}
		packages[app.PackageName] = PackageV2{
			Metadata: MetadataV2{
				Name:            localizedText(app.Name),
				Summary:         localizedText(app.Summary),
				Description:     localizedText(app.Description),
				Added:           app.Added,
				LastUpdated:     app.LastUpdated,
				Website:         app.Website,
				License:         app.License,
				SourceCode:      app.SourceCode,
				IssueTracker:    app.IssueTracker,
				PreferredSigner: preferredSigner,
				Categories:      cloneStrings(app.Categories),
			},
			Versions: versions,
		}
	}

	mirrors := make([]MirrorV2, 0, len(data.Mirrors))
	for _, mirror := range data.Mirrors {
		mirrors = append(mirrors, MirrorV2{URL: mirror})
	}
	index := IndexV2{
		Repo: RepoV2{
			Name:        localizedText(data.Name),
			Address:     data.Address,
			Description: localizedText(data.Description),
			Mirrors:     mirrors,
			Timestamp:   data.Timestamp,
			Categories:  categories,
		},
		Packages: packages,
	}
	return json.Marshal(index)
}

func normalizeRepositoryData(data RepositoryData) (RepositoryData, error) {
	data.Address = strings.TrimSpace(data.Address)
	data.Name = strings.TrimSpace(data.Name)
	data.Icon = strings.TrimSpace(data.Icon)
	if data.Address == "" {
		return RepositoryData{}, errors.New("F-Droid repository address is required")
	}
	if data.Name == "" {
		return RepositoryData{}, errors.New("F-Droid repository name is required")
	}
	if data.Fingerprint != "" {
		var err error
		data.Fingerprint, err = normalizeSHA256(data.Fingerprint)
		if err != nil {
			return RepositoryData{}, fmt.Errorf("F-Droid repository fingerprint: %w", err)
		}
	}
	if data.MaxAge != nil && *data.MaxAge < 0 {
		return RepositoryData{}, errors.New("F-Droid max age cannot be negative")
	}
	data.MaxAge = cloneInt(data.MaxAge)
	data.Mirrors = sortedUniqueStrings(data.Mirrors)
	data.Mirrors = removeString(data.Mirrors, data.Address)

	apps := make([]AppData, len(data.Apps))
	copy(apps, data.Apps)
	seenApps := make(map[string]struct{}, len(apps))
	for i := range apps {
		app := &apps[i]
		app.PackageName = strings.TrimSpace(app.PackageName)
		if app.PackageName == "" {
			return RepositoryData{}, errors.New("F-Droid package name is required")
		}
		if _, exists := seenApps[app.PackageName]; exists {
			return RepositoryData{}, fmt.Errorf("duplicate F-Droid package %q", app.PackageName)
		}
		seenApps[app.PackageName] = struct{}{}
		app.Categories = sortedUniqueStrings(app.Categories)
		if app.PreferredSigner != "" {
			var err error
			app.PreferredSigner, err = normalizeSHA256(app.PreferredSigner)
			if err != nil {
				return RepositoryData{}, fmt.Errorf("package %s preferred signer: %w", app.PackageName, err)
			}
		}

		versions := make([]VersionData, len(app.Versions))
		copy(versions, app.Versions)
		seenVersions := make(map[string]struct{}, len(versions))
		for j := range versions {
			version := &versions[j]
			version.APKName = strings.TrimLeft(strings.TrimSpace(version.APKName), "/")
			if version.APKName == "" {
				return RepositoryData{}, fmt.Errorf("package %s has a version without an APK name", app.PackageName)
			}
			if version.VersionName == "" {
				return RepositoryData{}, fmt.Errorf("package %s has a version without a version name", app.PackageName)
			}
			if version.VersionCode <= 0 {
				return RepositoryData{}, fmt.Errorf("package %s version code must be positive", app.PackageName)
			}
			if version.Size < 0 {
				return RepositoryData{}, fmt.Errorf("package %s APK size cannot be negative", app.PackageName)
			}
			var err error
			version.SHA256, err = normalizeSHA256(version.SHA256)
			if err != nil {
				return RepositoryData{}, fmt.Errorf("package %s APK: %w", app.PackageName, err)
			}
			if _, exists := seenVersions[version.SHA256]; exists {
				return RepositoryData{}, fmt.Errorf("package %s has duplicate APK hash %s", app.PackageName, version.SHA256)
			}
			seenVersions[version.SHA256] = struct{}{}

			version.Signers, err = normalizedSHA256List(version.Signers)
			if err != nil {
				return RepositoryData{}, fmt.Errorf("package %s signer: %w", app.PackageName, err)
			}
			if version.HasMultipleSigners && len(version.Signers) < 2 {
				return RepositoryData{}, fmt.Errorf("package %s marks an APK as multi-signer without multiple signers", app.PackageName)
			}
			if version.MinSDKVersion < 0 || version.TargetSDKVersion < 0 {
				return RepositoryData{}, fmt.Errorf("package %s SDK versions cannot be negative", app.PackageName)
			}
			if version.MinSDKVersion == 0 && version.TargetSDKVersion > 0 {
				version.MinSDKVersion = 1
			}
			if version.TargetSDKVersion == 0 && version.MinSDKVersion > 0 {
				version.TargetSDKVersion = version.MinSDKVersion
			}
			if version.MaxSDKVersion != nil && *version.MaxSDKVersion < 0 {
				return RepositoryData{}, fmt.Errorf("package %s max SDK version cannot be negative", app.PackageName)
			}
			version.MaxSDKVersion = cloneInt(version.MaxSDKVersion)
			version.Permissions, err = normalizedPermissions(version.Permissions)
			if err != nil {
				return RepositoryData{}, fmt.Errorf("package %s permission: %w", app.PackageName, err)
			}
			version.PermissionsSDK23, err = normalizedPermissions(version.PermissionsSDK23)
			if err != nil {
				return RepositoryData{}, fmt.Errorf("package %s SDK 23 permission: %w", app.PackageName, err)
			}
			version.ABIs = sortedUniqueStrings(version.ABIs)
			version.Features = sortedUniqueStrings(version.Features)
		}
		sort.Slice(versions, func(i, j int) bool {
			if versions[i].VersionCode != versions[j].VersionCode {
				return versions[i].VersionCode > versions[j].VersionCode
			}
			if versions[i].VersionName != versions[j].VersionName {
				return versions[i].VersionName > versions[j].VersionName
			}
			if versions[i].APKName != versions[j].APKName {
				return versions[i].APKName < versions[j].APKName
			}
			return versions[i].SHA256 < versions[j].SHA256
		})
		app.Versions = versions
	}
	sort.Slice(apps, func(i, j int) bool {
		return apps[i].PackageName < apps[j].PackageName
	})
	data.Apps = apps
	return data, nil
}

func normalizeSHA256(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf("invalid SHA-256 %q", value)
	}
	return value, nil
}

func normalizedSHA256List(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized, err := normalizeSHA256(value)
		if err != nil {
			return nil, err
		}
		result = append(result, normalized)
	}
	return sortedUniqueStrings(result), nil
}

func normalizedPermissions(values []PermissionData) ([]PermissionData, error) {
	result := make([]PermissionData, len(values))
	for i, permission := range values {
		permission.Name = strings.TrimSpace(permission.Name)
		if permission.Name == "" {
			return nil, errors.New("permission name is required")
		}
		if permission.MaxSDKVersion != nil && *permission.MaxSDKVersion < 0 {
			return nil, fmt.Errorf("permission %s has a negative max SDK version", permission.Name)
		}
		permission.MaxSDKVersion = cloneInt(permission.MaxSDKVersion)
		result[i] = permission
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		if result[i].MaxSDKVersion == nil {
			return result[j].MaxSDKVersion != nil
		}
		if result[j].MaxSDKVersion == nil {
			return false
		}
		return *result[i].MaxSDKVersion < *result[j].MaxSDKVersion
	})
	return result, nil
}

func sortedUniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func permissionsV1(values []PermissionData) []PermissionV1 {
	if len(values) == 0 {
		return nil
	}
	result := make([]PermissionV1, 0, len(values))
	for _, permission := range values {
		result = append(result, PermissionV1{
			Name:          permission.Name,
			MaxSDKVersion: cloneInt(permission.MaxSDKVersion),
		})
	}
	return result
}

func permissionsV2(values []PermissionData) []PermissionV2 {
	if len(values) == 0 {
		return nil
	}
	result := make([]PermissionV2, 0, len(values))
	for _, permission := range values {
		result = append(result, PermissionV2{
			Name:          permission.Name,
			MaxSDKVersion: cloneInt(permission.MaxSDKVersion),
		})
	}
	return result
}

func featuresV2(values []string) []FeatureV2 {
	if len(values) == 0 {
		return nil
	}
	result := make([]FeatureV2, 0, len(values))
	for _, feature := range values {
		result = append(result, FeatureV2{Name: feature})
	}
	return result
}

func localizedText(value string) LocalizedTextV2 {
	if value == "" {
		return nil
	}
	return LocalizedTextV2{DefaultLocale: value}
}

func ensureLeadingSlash(value string) string {
	return "/" + strings.TrimLeft(value, "/")
}

func sdkPointer(value int) *int {
	if value == 0 {
		return nil
	}
	return &value
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func removeString(values []string, value string) []string {
	for i, candidate := range values {
		if candidate == value {
			return append(values[:i:i], values[i+1:]...)
		}
	}
	return values
}
