// Copyright 2024 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package apex

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"forgejo.org/modules/packages"

	"github.com/shogo82148/androidbinary"
	"github.com/shogo82148/androidbinary/apk"
	apex_module "forgejo.org/modules/packages/apex"
)

// ParsePackage parses an APEX/CAPEX package buffer and extracts its metadata
func ParsePackage(ctx context.Context, buf *packages.HashedBuffer) (*apex_module.Package, error) {
	_, err := buf.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	size := buf.Size()
	reader, err := zip.NewReader(buf, size)
	if err != nil {
		return nil, err
	}

	// List files in the zip
	var fileList []string
	var manifestFile *zip.File
	var originalApexFile *zip.File
	var pubKeyFile *zip.File

	for _, f := range reader.File {
		fileList = append(fileList, f.Name)
		if f.Name == "AndroidManifest.xml" {
			manifestFile = f
		} else if f.Name == "original_apex" {
			originalApexFile = f
		} else if f.Name == "apex_pubkey" {
			pubKeyFile = f
		}
	}

	// If this is a CAPEX, we need to extract the original_apex to get the real AndroidManifest.xml
	if originalApexFile != nil {
		rc, err := originalApexFile.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()

		// original_apex is also a zip file
		innerBuf, err := io.ReadAll(rc)
		if err != nil {
			return nil, err
		}

		innerReader, err := zip.NewReader(bytes.NewReader(innerBuf), int64(len(innerBuf)))
		if err != nil {
			return nil, err
		}

		for _, f := range innerReader.File {
			if f.Name == "AndroidManifest.xml" {
				manifestFile = f
			} else if f.Name == "apex_pubkey" && pubKeyFile == nil {
				pubKeyFile = f
			}
		}
	}

	if manifestFile == nil {
		return nil, errors.New("AndroidManifest.xml not found")
	}

	// Extract AndroidManifest.xml
	rc, err := manifestFile.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	manifestBytes, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}

	// Parse AXML using androidbinary
	xmlFile, err := androidbinary.NewXMLFile(bytes.NewReader(manifestBytes))
	if err != nil {
		return nil, err
	}

	var pkg apk.Manifest
	err = xmlFile.Decode(&pkg, nil, nil)
	if err != nil {
		return nil, err
	}

	pkgName, _ := pkg.Package.String()
	pkgVersion, _ := pkg.VersionName.String()

	extension := "apex"
	if originalApexFile != nil {
		extension = "capex"
	}

	apiLevel, _ := pkg.SDK.Min.Int32()
	apiLevelStr := fmt.Sprintf("%d", apiLevel)
	if apiLevel == 0 {
		apiLevelStr = "29"
	}

	// Create apex package representation
	p := &apex_module.Package{
		Name:    pkgName,
		Version: pkgVersion,
		FileMetadata: apex_module.FileMetadata{
			CompressedSize: size,
			Files:          fileList,
			Extension:      extension,
			ApiLevel:       apiLevelStr,
		},
	}

	// Calculate sums
	_, _, sha256, _, _ := buf.Sums()
	p.FileMetadata.SHA256 = hex.EncodeToString(sha256)

	// Extract meta-data tags
	for _, meta := range pkg.App.MetaData {
		name, _ := meta.Name.String()
		value, _ := meta.Value.String()

		switch name {
		case "org":
			p.VersionMetadata.Org = value
		case "pkgdesc":
			p.VersionMetadata.Description = value
		case "url":
			p.VersionMetadata.ProjectURL = value
		case "arch":
			p.FileMetadata.Arch = value
		case "packager":
			p.FileMetadata.Packager = value
		case "license":
			p.VersionMetadata.License = strings.Split(value, " ")
		case "depends":
			p.VersionMetadata.Depends = strings.Split(value, " ")
		case "provides":
			p.VersionMetadata.Provides = strings.Split(value, " ")
		}

		// Handle dynamic microarch level
		if strings.HasSuffix(name, "_micro_architecture_level") {
			p.FileMetadata.MicroArchLevel = value
		}
	}

	// Logic to suppress dependency checks when the APEX contains no dynamic libraries/binaries.
	hasBinaries := false
	for _, f := range fileList {
		if strings.HasPrefix(f, "lib/") || strings.HasPrefix(f, "bin/") || strings.HasSuffix(f, ".so") {
			hasBinaries = true
			break
		}
	}
	if !hasBinaries {
		p.VersionMetadata.Depends = nil
	}

	return p, nil
}
