// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package fdroid

const (
	PropertyFileMetadata = "fdroid.file.metadata"
	PropertySignerSHA256 = "fdroid.signer.sha256"

	SettingKeyPrivateKey  = "fdroid.key.private"
	SettingKeyCertificate = "fdroid.key.certificate"

	RepositoryPackage = "_fdroid"
	RepositoryVersion = "_repository"
)

type Package struct {
	Name            string
	Version         string
	VersionMetadata VersionMetadata
	FileMetadata    FileMetadata
}

type VersionMetadata struct {
	Name         string `json:"name,omitempty"`
	Summary      string `json:"summary,omitempty"`
	Description  string `json:"description,omitempty"`
	License      string `json:"license,omitempty"`
	Website      string `json:"website,omitempty"`
	SourceCode   string `json:"source_code,omitempty"`
	IssueTracker string `json:"issue_tracker,omitempty"`
}

type Permission struct {
	Name          string `json:"name"`
	MaxSDKVersion *int   `json:"max_sdk_version,omitempty"`
}

type FileMetadata struct {
	PackageName      string       `json:"package_name"`
	VersionName      string       `json:"version_name"`
	VersionCode      int64        `json:"version_code"`
	MinSDKVersion    int          `json:"min_sdk_version,omitempty"`
	TargetSDKVersion int          `json:"target_sdk_version,omitempty"`
	MaxSDKVersion    int          `json:"max_sdk_version,omitempty"`
	Permissions      []Permission `json:"permissions,omitempty"`
	PermissionsSDK23 []Permission `json:"permissions_sdk_23,omitempty"`
	Features         []string     `json:"features,omitempty"`
	NativeCode       []string     `json:"native_code,omitempty"`
	SignerSHA256     string       `json:"signer_sha256"`
	SignerLineage    []string     `json:"signer_lineage,omitempty"`
	SignatureScheme  int          `json:"signature_scheme"`
}
