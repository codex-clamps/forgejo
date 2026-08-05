// Copyright 2024 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package apex

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/hex"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"forgejo.org/modules/json"
	"forgejo.org/modules/packages"
	apex_module "forgejo.org/modules/packages/apex"

	"github.com/shogo82148/androidbinary"
	"github.com/shogo82148/androidbinary/apk"
	"google.golang.org/protobuf/encoding/protowire"
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
	var pbFile *zip.File
	var jsonFile *zip.File
	var buildInfoFile *zip.File

	for _, f := range reader.File {
		fileList = append(fileList, f.Name)
		switch f.Name {
		case "AndroidManifest.xml":
			manifestFile = f
		case "original_apex":
			originalApexFile = f
		case "apex_pubkey":
			pubKeyFile = f
		case "apex_manifest.pb":
			pbFile = f
		case "apex_manifest.json":
			jsonFile = f
		case "apex_build_info.pb":
			buildInfoFile = f
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
		tmpFile, err := os.CreateTemp("", "original_apex_*.zip")
		if err != nil {
			return nil, err
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		size, err := io.Copy(tmpFile, rc)
		if err != nil {
			return nil, err
		}

		innerReader, err := zip.NewReader(tmpFile, size)
		if err != nil {
			return nil, err
		}

		for _, f := range innerReader.File {
			if f.Name == "AndroidManifest.xml" {
				manifestFile = f
			} else if f.Name == "apex_pubkey" && pubKeyFile == nil {
				pubKeyFile = f
			} else if f.Name == "apex_manifest.pb" && pbFile == nil {
				pbFile = f
			} else if f.Name == "apex_manifest.json" && jsonFile == nil {
				jsonFile = f
			} else if f.Name == "apex_build_info.pb" && buildInfoFile == nil {
				buildInfoFile = f
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
	if pkgVersion == "" {
		vCode, _ := pkg.VersionCode.Int32()
		if vCode > 0 {
			pkgVersion = fmt.Sprintf("%d", vCode)
		}
	}

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
			APILevel:       apiLevelStr,
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

	if p.FileMetadata.Arch == "" {
		p.FileMetadata.Arch = "any"
	}

	var manifestName string
	var manifestVersionName string
	var manifestVersion int64

	// Parse apex_manifest.pb if available
	if pbFile != nil {
		rcPb, err := pbFile.Open()
		if err == nil {
			pbBytes, err := io.ReadAll(rcPb)
			rcPb.Close()
			if err == nil {
				data := pbBytes
				for len(data) > 0 {
					num, typ, tagLen := protowire.ConsumeTag(data)
					if tagLen < 0 {
						break
					}
					valLen := protowire.ConsumeFieldValue(num, typ, data[tagLen:])
					if valLen < 0 {
						break
					}
					fieldVal := data[tagLen : tagLen+valLen]
					switch typ {
					case protowire.BytesType:
						v, n := protowire.ConsumeBytes(fieldVal)
						if n >= 0 {
							switch num {
							case 1: // name
								manifestName = string(v)
							case 5: // versionName
								manifestVersionName = string(v)
							case 7: // provideNativeLibs
								p.VersionMetadata.Provides = append(p.VersionMetadata.Provides, string(v))
							case 8: // requireNativeLibs
								p.VersionMetadata.Depends = append(p.VersionMetadata.Depends, string(v))
							}
						}
					case protowire.VarintType:
						v, n := protowire.ConsumeVarint(fieldVal)
						if n >= 0 {
							switch num {
							case 2: // version
								manifestVersion = int64(v)
							}
						}
					}
					data = data[tagLen+valLen:]
				}
			}
		}
	} else if jsonFile != nil {
		rcJSON, err := jsonFile.Open()
		if err == nil {
			jsonBytes, err := io.ReadAll(rcJSON)
			rcJSON.Close()
			if err == nil {
				var manifest struct {
					Name              string          `json:"name"`
					Version           stdjson.RawMessage `json:"version"`
					VersionName       string          `json:"versionName"`
					ProvideNativeLibs []string        `json:"provideNativeLibs"`
					RequireNativeLibs []string        `json:"requireNativeLibs"`
				}
				if err := json.Unmarshal(jsonBytes, &manifest); err == nil {
					if manifest.Name != "" {
						manifestName = manifest.Name
					}
					if manifest.VersionName != "" {
						manifestVersionName = manifest.VersionName
					}
					if len(manifest.Version) > 0 {
						var vInt int64
						var vStr string
						if err := json.Unmarshal(manifest.Version, &vInt); err == nil {
							manifestVersion = vInt
						} else if err := json.Unmarshal(manifest.Version, &vStr); err == nil && manifestVersionName == "" {
							manifestVersionName = vStr
						}
					}
					p.VersionMetadata.Provides = append(p.VersionMetadata.Provides, manifest.ProvideNativeLibs...)
					p.VersionMetadata.Depends = append(p.VersionMetadata.Depends, manifest.RequireNativeLibs...)
				}
			}
		}
	}

	var buildInfoName string
	var buildInfoMinSDK string

	if buildInfoFile != nil {
		rcInfo, err := buildInfoFile.Open()
		if err == nil {
			infoBytes, err := io.ReadAll(rcInfo)
			rcInfo.Close()
			if err == nil {
				data := infoBytes
				for len(data) > 0 {
					num, typ, tagLen := protowire.ConsumeTag(data)
					if tagLen < 0 {
						break
					}
					valLen := protowire.ConsumeFieldValue(num, typ, data[tagLen:])
					if valLen < 0 {
						break
					}
					fieldVal := data[tagLen : tagLen+valLen]
					if typ == protowire.BytesType {
						v, n := protowire.ConsumeBytes(fieldVal)
						if n >= 0 {
							switch num {
							case 5: // min_sdk_version
								buildInfoMinSDK = string(v)
							case 8: // module_name
								buildInfoName = string(v)
							}
						}
					}
					data = data[tagLen+valLen:]
				}
			}
		}
	}

	if buildInfoName != "" {
		p.Name = buildInfoName
	} else if p.Name == "" && manifestName != "" {
		p.Name = manifestName
	}

	if p.Name == "" {
		return nil, errors.New("APEX package metadata missing name")
	}

	if buildInfoMinSDK != "" {
		p.FileMetadata.APILevel = buildInfoMinSDK
	}

	if manifestVersionName != "" {
		p.Version = manifestVersionName
	} else if manifestVersion > 0 {
		p.Version = strconv.FormatInt(manifestVersion, 10)
	}

	if p.Version == "" {
		return nil, errors.New("APEX package metadata missing version")
	}

	p.VersionMetadata.Provides = sliceUnique(p.VersionMetadata.Provides)
	p.VersionMetadata.Depends = sliceUnique(p.VersionMetadata.Depends)

	return p, nil
}

func sliceUnique(slice []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, exists := seen[item]; !exists {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
