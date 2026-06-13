// Copyright 2024 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package apex

import (
	"bytes"
	"fmt"
	"strings"
)

const (
	PropertyOrg         = "apex.org"
	PropertyDescription = "apex.description"
	PropertyFiles       = "apex.files"
	PropertyArch        = "apex.architecture"
	PropertyMicroArch   = "apex.micro_architecture_level"
	PropertyApiLevel    = "apex.api_level"
	PropertyProvides    = "apex.provides"

	SettingKeyPublic  = "apex.key.public"
	SettingKeyPrivate = "apex.key.private"

	RepositoryPackage = "_apex"
	RepositoryVersion = "_repository"
)

type Package struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	VersionMetadata VersionMetadata
	FileMetadata    FileMetadata
}

type VersionMetadata struct {
	Org          string   `json:"org"`
	Description  string   `json:"description"`
	ProjectURL   string   `json:"project_url"`
	Provides     []string `json:"provides,omitempty"`
	License      []string `json:"license,omitempty"`
	Depends      []string `json:"depends,omitempty"`
}

type FileMetadata struct {
	CompressedSize int64  `json:"compressed_size"`
	InstalledSize  int64  `json:"installed_size"`
	SHA256         string `json:"sha256"`
	BuildDate      int64  `json:"build_date"`
	Packager       string `json:"packager"`
	Arch           string `json:"arch"`
	MicroArchLevel string `json:"micro_architecture_level,omitempty"`
	ApiLevel       string `json:"api_level,omitempty"`
	Extension      string `json:"extension"`

	Files []string `json:"files,omitempty"`
}

// Desc Create apex-repo database description file.
func (p *Package) Desc(filename string) string {
	entries := []string{
		"FILENAME", filename,
		"NAME", p.Name,
		"ORG", p.VersionMetadata.Org,
		"VERSION", p.Version,
		"DESC", p.VersionMetadata.Description,
		"CSIZE", fmt.Sprintf("%d", p.FileMetadata.CompressedSize),
		"ISIZE", fmt.Sprintf("%d", p.FileMetadata.InstalledSize),
		"SHA256SUM", p.FileMetadata.SHA256,
		"URL", p.VersionMetadata.ProjectURL,
		"LICENSE", strings.Join(p.VersionMetadata.License, "\n"),
		"ARCH", p.FileMetadata.Arch,
		"MICROARCH", p.FileMetadata.MicroArchLevel,
		"APILEVEL", p.FileMetadata.ApiLevel,
		"BUILDDATE", fmt.Sprintf("%d", p.FileMetadata.BuildDate),
		"PACKAGER", p.FileMetadata.Packager,
		"PROVIDES", strings.Join(p.VersionMetadata.Provides, "\n"),
		"DEPENDS", strings.Join(p.VersionMetadata.Depends, "\n"),
	}

	var buf bytes.Buffer
	for i := 0; i < len(entries); i += 2 {
		if entries[i+1] != "" {
			_, _ = fmt.Fprintf(&buf, "%%%s%%\n%s\n\n", entries[i], entries[i+1])
		}
	}
	return buf.String()
}

func (p *Package) Files() string {
	var buf bytes.Buffer
	buf.WriteString("%FILES%\n")
	for _, item := range p.FileMetadata.Files {
		_, _ = fmt.Fprintf(&buf, "%s\n", item)
	}
	return buf.String()
}
