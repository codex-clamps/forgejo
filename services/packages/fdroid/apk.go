// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package fdroid

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"

	"forgejo.org/modules/packages"
	fdroid_module "forgejo.org/modules/packages/fdroid"

	"github.com/avast/apkverifier"
	"github.com/avast/apkverifier/signingblock"
	"github.com/shogo82148/androidbinary"
)

const maxAndroidManifestSize = 4 * 1024 * 1024

var (
	ErrInvalidAPKSignature = errors.New("invalid APK signature")
	ErrMultipleAPKSigners  = errors.New("multiple APK signers are not supported")
	ErrAPKKeyRotation      = errors.New("APK signing key rotation is not supported")
	ErrAPKSignerMismatch   = errors.New("APK signer does not match the expected certificate")
)

type manifestAttribute struct {
	Name          string `xml:"http://schemas.android.com/apk/res/android name,attr"`
	MaxSDKVersion string `xml:"http://schemas.android.com/apk/res/android maxSdkVersion,attr"`
}

type manifestXML struct {
	Package          string `xml:"package,attr"`
	VersionCode      string `xml:"http://schemas.android.com/apk/res/android versionCode,attr"`
	VersionCodeMajor string `xml:"http://schemas.android.com/apk/res/android versionCodeMajor,attr"`
	VersionName      string `xml:"http://schemas.android.com/apk/res/android versionName,attr"`
	Application      struct {
		Label string `xml:"http://schemas.android.com/apk/res/android label,attr"`
	} `xml:"application"`
	UsesSDK struct {
		Min    string `xml:"http://schemas.android.com/apk/res/android minSdkVersion,attr"`
		Target string `xml:"http://schemas.android.com/apk/res/android targetSdkVersion,attr"`
		Max    string `xml:"http://schemas.android.com/apk/res/android maxSdkVersion,attr"`
	} `xml:"uses-sdk"`
	Permissions      []manifestAttribute `xml:"uses-permission"`
	PermissionsSDK23 []manifestAttribute `xml:"uses-permission-sdk-23"`
	PermissionsSDKM  []manifestAttribute `xml:"uses-permission-sdk-m"`
	Features         []manifestAttribute `xml:"uses-feature"`
}

type apkManifestMetadata struct {
	packageName      string
	versionName      string
	versionCode      int64
	minSDKVersion    int
	targetSDKVersion int
	maxSDKVersion    int
	label            string
	permissions      []fdroid_module.Permission
	permissionsSDK23 []fdroid_module.Permission
	features         []string
	nativeCode       []string
}

type apkSignerIdentity struct {
	scheme      int
	certificate *x509.Certificate
	lineage     []*x509.Certificate
}

// ParsePackage verifies an APK and extracts the metadata needed by F-Droid indexes.
func ParsePackage(ctx context.Context, buf *packages.HashedBuffer) (*fdroid_module.Package, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	manifest, err := parseAPKManifest(buf, buf.Size())
	if err != nil {
		return nil, err
	}

	signer, err := verifyAPKSignature(buf, manifest.minSDKVersion)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	signerSHA256 := sha256.Sum256(signer.certificate.Raw)
	var signerLineage []string
	for _, cert := range signer.lineage {
		if cert != nil {
			fp := sha256.Sum256(cert.Raw)
			signerLineage = append(signerLineage, hex.EncodeToString(fp[:]))
		}
	}

	return &fdroid_module.Package{
		Name:    manifest.packageName,
		Version: strconv.FormatInt(manifest.versionCode, 10),
		VersionMetadata: fdroid_module.VersionMetadata{
			Name: manifest.label,
		},
		FileMetadata: fdroid_module.FileMetadata{
			PackageName:      manifest.packageName,
			VersionName:      manifest.versionName,
			VersionCode:      manifest.versionCode,
			MinSDKVersion:    manifest.minSDKVersion,
			TargetSDKVersion: manifest.targetSDKVersion,
			MaxSDKVersion:    manifest.maxSDKVersion,
			Permissions:      manifest.permissions,
			PermissionsSDK23: manifest.permissionsSDK23,
			Features:         manifest.features,
			NativeCode:       manifest.nativeCode,
			SignerSHA256:     hex.EncodeToString(signerSHA256[:]),
			SignerLineage:    signerLineage,
			SignatureScheme:  signer.scheme,
		},
	}, nil
}

func parseAPKManifest(r io.ReaderAt, size int64) (*apkManifestMetadata, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("invalid APK ZIP: %w", err)
	}

	var manifestFile *zip.File
	nativeCode := make(map[string]struct{})
	for _, file := range zr.File {
		switch {
		case file.Name == "AndroidManifest.xml":
			if manifestFile != nil {
				return nil, errors.New("APK contains multiple AndroidManifest.xml entries")
			}
			manifestFile = file
		case strings.HasPrefix(file.Name, "lib/") && !file.FileInfo().IsDir():
			parts := strings.Split(file.Name, "/")
			if len(parts) >= 3 && parts[1] != "" && parts[1] != "." && parts[1] != ".." {
				nativeCode[parts[1]] = struct{}{}
			}
		}
	}
	if manifestFile == nil {
		return nil, errors.New("AndroidManifest.xml not found")
	}

	manifestData, err := readLimitedZIPFile(manifestFile, maxAndroidManifestSize)
	if err != nil {
		return nil, fmt.Errorf("read AndroidManifest.xml: %w", err)
	}
	xmlFile, err := androidbinary.NewXMLFile(bytes.NewReader(manifestData))
	if err != nil {
		return nil, fmt.Errorf("parse AndroidManifest.xml: %w", err)
	}

	metadata, err := decodeManifestXML(xmlFile.Reader())
	if err != nil {
		return nil, err
	}
	metadata.nativeCode = sortedKeys(nativeCode)
	return metadata, nil
}

func decodeManifestXML(r io.Reader) (*apkManifestMetadata, error) {
	var manifest manifestXML
	if err := xml.NewDecoder(r).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode AndroidManifest.xml: %w", err)
	}
	if manifest.Package == "" {
		return nil, errors.New("AndroidManifest.xml has no package name")
	}

	versionCode, err := parseLongVersionCode(manifest.VersionCode, manifest.VersionCodeMajor)
	if err != nil {
		return nil, err
	}
	minSDKVersion, err := parseSDKVersion(manifest.UsesSDK.Min, 1, "minSdkVersion")
	if err != nil {
		return nil, err
	}
	targetSDKVersion, err := parseSDKVersion(manifest.UsesSDK.Target, minSDKVersion, "targetSdkVersion")
	if err != nil {
		return nil, err
	}
	maxSDKVersion, err := parseSDKVersion(manifest.UsesSDK.Max, 0, "maxSdkVersion")
	if err != nil {
		return nil, err
	}

	permissions, err := normalizePermissions(manifest.Permissions)
	if err != nil {
		return nil, err
	}
	permissionsSDK23, err := normalizePermissions(append(append([]manifestAttribute(nil), manifest.PermissionsSDK23...), manifest.PermissionsSDKM...))
	if err != nil {
		return nil, err
	}

	featuresMap := make(map[string]struct{})
	for _, feature := range manifest.Features {
		if feature.Name != "" {
			featuresMap[feature.Name] = struct{}{}
		}
	}

	versionName := manifest.VersionName
	if androidbinary.IsResID(versionName) {
		versionName = ""
	}
	label := manifest.Application.Label
	if label == "" || androidbinary.IsResID(label) {
		label = manifest.Package
	}

	return &apkManifestMetadata{
		packageName:      manifest.Package,
		versionName:      versionName,
		versionCode:      versionCode,
		minSDKVersion:    minSDKVersion,
		targetSDKVersion: targetSDKVersion,
		maxSDKVersion:    maxSDKVersion,
		label:            label,
		permissions:      permissions,
		permissionsSDK23: permissionsSDK23,
		features:         sortedKeys(featuresMap),
	}, nil
}

func normalizePermissions(attributes []manifestAttribute) ([]fdroid_module.Permission, error) {
	permissions := make([]fdroid_module.Permission, 0, len(attributes))
	seenPermissions := make(map[string]struct{})
	for _, permission := range attributes {
		if permission.Name == "" {
			continue
		}
		var maxSDKVersion *int
		if permission.MaxSDKVersion != "" {
			value, err := parseSDKVersion(permission.MaxSDKVersion, 0, "permission maxSdkVersion")
			if err != nil {
				return nil, err
			}
			maxSDKVersion = &value
		}
		key := permission.Name + "\x00"
		if maxSDKVersion != nil {
			key += strconv.Itoa(*maxSDKVersion)
		}
		if _, exists := seenPermissions[key]; exists {
			continue
		}
		seenPermissions[key] = struct{}{}
		permissions = append(permissions, fdroid_module.Permission{Name: permission.Name, MaxSDKVersion: maxSDKVersion})
	}
	sort.Slice(permissions, func(i, j int) bool {
		if permissions[i].Name != permissions[j].Name {
			return permissions[i].Name < permissions[j].Name
		}
		if permissions[i].MaxSDKVersion == nil {
			return true
		}
		if permissions[j].MaxSDKVersion == nil {
			return false
		}
		return *permissions[i].MaxSDKVersion < *permissions[j].MaxSDKVersion
	})
	return permissions, nil
}

func parseLongVersionCode(versionCode, versionCodeMajor string) (int64, error) {
	if versionCode == "" {
		return 0, errors.New("AndroidManifest.xml has no versionCode")
	}
	low, err := strconv.ParseUint(versionCode, 0, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid versionCode %q: %w", versionCode, err)
	}
	var high uint64
	if versionCodeMajor != "" {
		high, err = strconv.ParseUint(versionCodeMajor, 0, 31)
		if err != nil {
			return 0, fmt.Errorf("invalid versionCodeMajor %q: %w", versionCodeMajor, err)
		}
	}
	combined := high<<32 | low
	if combined == 0 || combined > math.MaxInt64 {
		return 0, fmt.Errorf("invalid long versionCode %d", combined)
	}
	return int64(combined), nil
}

func parseSDKVersion(value string, defaultValue int, name string) (int, error) {
	if value == "" {
		return defaultValue, nil
	}
	parsed, err := strconv.ParseInt(value, 0, 32)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("invalid %s %q", name, value)
	}
	return int(parsed), nil
}

func verifyAPKSignature(r io.ReadSeeker, minSDKVersion int) (*apkSignerIdentity, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	result, err := apkverifier.VerifyReader(r, nil)
	if err != nil {
		if policyErr := apkSignerPolicyError(result); policyErr != nil {
			return nil, policyErr
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidAPKSignature, err)
	}
	identity, err := signerIdentityFromResult(result)
	if err != nil {
		return nil, err
	}

	for _, sdkVersion := range representativeSDKVersions(minSDKVersion) {
		if _, err := r.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		result, err := apkverifier.VerifyWithSdkVersionReader(r, nil, sdkVersion, sdkVersion)
		if err != nil {
			return nil, fmt.Errorf("%w for Android SDK %d: %v", ErrInvalidAPKSignature, sdkVersion, err)
		}
		candidate, err := signerIdentityFromResult(result)
		if err != nil {
			return nil, err
		}
		if err := ensureSameAPKSigner(identity, candidate); err != nil {
			return nil, err
		}
	}

	return identity, nil
}

func ensureSameAPKSigner(expected, candidate *apkSignerIdentity) error {
	if expected == nil || expected.certificate == nil || candidate == nil || candidate.certificate == nil {
		return ErrInvalidAPKSignature
	}
	if bytes.Equal(expected.certificate.Raw, candidate.certificate.Raw) {
		return nil
	}
	for _, cert := range expected.lineage {
		if cert != nil && bytes.Equal(cert.Raw, candidate.certificate.Raw) {
			return nil
		}
	}
	for _, cert := range candidate.lineage {
		if cert != nil && bytes.Equal(cert.Raw, expected.certificate.Raw) {
			return nil
		}
	}
	return ErrAPKSignerMismatch
}

func signerIdentityFromResult(result apkverifier.Result) (*apkSignerIdentity, error) {
	if err := apkSignerPolicyError(result); err != nil {
		return nil, err
	}
	if len(result.SignerCerts) == 0 || len(result.SignerCerts[0]) == 0 {
		return nil, ErrInvalidAPKSignature
	}
	var lineage []*x509.Certificate
	if result.SigningBlockResult != nil && result.SigningBlockResult.SigningLineage != nil {
		for _, node := range result.SigningBlockResult.SigningLineage.Nodes {
			if node.SigningCert != nil {
				lineage = append(lineage, node.SigningCert)
			}
		}
	}
	return &apkSignerIdentity{
		scheme:      result.SigningSchemeId,
		certificate: result.SignerCerts[0][0],
		lineage:     lineage,
	}, nil
}

func apkSignerPolicyError(result apkverifier.Result) error {
	if len(result.SignerCerts) > 1 {
		return ErrMultipleAPKSigners
	}
	return nil
}

func verificationResultHasRotation(result *signingblock.VerificationResult) bool {
	if result == nil {
		return false
	}
	if result.SchemeId == 31 || (result.SigningLineage != nil && len(result.SigningLineage.Nodes) > 1) {
		return true
	}
	for _, extraResult := range result.ExtraResults {
		if verificationResultHasRotation(extraResult) {
			return true
		}
	}
	return false
}

func representativeSDKVersions(minSDKVersion int) []int32 {
	levels := make([]int32, 0, 4)
	add := func(level int) {
		if slices.Contains(levels, int32(level)) {
			return
		}
		levels = append(levels, int32(level))
	}
	if minSDKVersion <= 23 {
		add(23)
	}
	if minSDKVersion <= 27 {
		add(max(minSDKVersion, 24))
	}
	if minSDKVersion <= 32 {
		add(max(minSDKVersion, 28))
	}
	add(max(minSDKVersion, 33))
	return levels
}

func readLimitedZIPFile(file *zip.File, limit uint64) ([]byte, error) {
	if file.UncompressedSize64 > limit {
		return nil, fmt.Errorf("%s exceeds the %d byte limit", file.Name, limit)
	}
	r, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()

	data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds the %d byte limit", file.Name, limit)
	}
	return data, nil
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
