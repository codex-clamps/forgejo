// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package fdroid

import (
	"context"
	"crypto/x509"
	"os"
	"strings"
	"testing"

	packages_module "forgejo.org/modules/packages"
	fdroid_module "forgejo.org/modules/packages/fdroid"

	"github.com/avast/apkverifier"
	"github.com/avast/apkverifier/signingblock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePackage(t *testing.T) {
	packageMetadata, err := parseAPKFixture(t, "valid-v1v2v3.apk")
	require.NoError(t, err)

	assert.Equal(t, "android.appsecurity.cts.tinyapp", packageMetadata.Name)
	assert.Equal(t, "10", packageMetadata.Version)
	assert.Equal(t, int64(10), packageMetadata.FileMetadata.VersionCode)
	assert.Equal(t, 23, packageMetadata.FileMetadata.MinSDKVersion)
	assert.Equal(t, 3, packageMetadata.FileMetadata.SignatureScheme)
	assert.Len(t, packageMetadata.FileMetadata.SignerSHA256, 64)
	assert.Equal(t, []string{"armeabi"}, packageMetadata.FileMetadata.NativeCode)
}

func TestVerifyAPKSignatureRejectsUnsupportedSignatures(t *testing.T) {
	testCases := []struct {
		name     string
		fixture  string
		expected error
	}{
		{name: "unsigned", fixture: "unsigned.apk", expected: ErrInvalidAPKSignature},
		{name: "invalid", fixture: "invalid-signature.apk", expected: ErrInvalidAPKSignature},
		{name: "multiple signers", fixture: "multiple-signers.apk", expected: ErrMultipleAPKSigners},
		{name: "key rotation", fixture: "rotated-signing-key.apk", expected: ErrAPKKeyRotation},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			buffer := openAPKFixture(t, testCase.fixture)
			_, err := verifyAPKSignature(buffer, 1)
			require.Error(t, err)
			require.ErrorIs(t, err, testCase.expected)
		})
	}
}

func TestDecodeManifestXML(t *testing.T) {
	manifest := `<manifest xmlns:android="http://schemas.android.com/apk/res/android"
		package="org.example.app" android:versionCode="25" android:versionCodeMajor="1" android:versionName="2.5">
		<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34" android:maxSdkVersion="35"/>
		<uses-permission android:name="android.permission.READ_MEDIA_IMAGES" android:maxSdkVersion="32"/>
		<uses-permission android:name="android.permission.INTERNET"/>
		<uses-permission android:name="android.permission.READ_MEDIA_IMAGES" android:maxSdkVersion="32"/>
		<uses-permission-sdk-23 android:name="android.permission.CAMERA"/>
		<uses-permission-sdk-m android:name="android.permission.RECORD_AUDIO" android:maxSdkVersion="33"/>
		<uses-feature android:name="android.hardware.camera"/>
		<uses-feature android:name="android.hardware.bluetooth"/>
		<uses-feature android:name="android.hardware.camera"/>
		<application android:label="Example App"/>
	</manifest>`

	metadata, err := decodeManifestXML(strings.NewReader(manifest))
	require.NoError(t, err)

	assert.Equal(t, "org.example.app", metadata.packageName)
	assert.Equal(t, "2.5", metadata.versionName)
	assert.Equal(t, int64(4_294_967_321), metadata.versionCode)
	assert.Equal(t, 21, metadata.minSDKVersion)
	assert.Equal(t, 34, metadata.targetSDKVersion)
	assert.Equal(t, 35, metadata.maxSDKVersion)
	assert.Equal(t, "Example App", metadata.label)
	assert.Equal(t, []fdroid_module.Permission{
		{Name: "android.permission.INTERNET"},
		{Name: "android.permission.READ_MEDIA_IMAGES", MaxSDKVersion: new(32)},
	}, metadata.permissions)
	assert.Equal(t, []fdroid_module.Permission{
		{Name: "android.permission.CAMERA"},
		{Name: "android.permission.RECORD_AUDIO", MaxSDKVersion: new(33)},
	}, metadata.permissionsSDK23)
	assert.Equal(t, []string{"android.hardware.bluetooth", "android.hardware.camera"}, metadata.features)
}

func TestSignerIdentityFromResult(t *testing.T) {
	certificate := &x509.Certificate{Raw: []byte("certificate")}

	_, err := signerIdentityFromResult(apkverifier.Result{
		SigningSchemeId: 2,
		SignerCerts:     [][]*x509.Certificate{{certificate}, {certificate}},
	})
	require.ErrorIs(t, err, ErrMultipleAPKSigners)

	_, err = signerIdentityFromResult(apkverifier.Result{
		SigningSchemeId: 3,
		SignerCerts:     [][]*x509.Certificate{{certificate}},
		SigningBlockResult: &signingblock.VerificationResult{
			SigningLineage: &signingblock.V3SigningLineage{
				Nodes: make(signingblock.V3LineageSigningCertificateNodeList, 2),
			},
		},
	})
	require.ErrorIs(t, err, ErrAPKKeyRotation)
}

func TestEnsureSameAPKSigner(t *testing.T) {
	first := &apkSignerIdentity{certificate: &x509.Certificate{Raw: []byte("first")}}
	same := &apkSignerIdentity{certificate: &x509.Certificate{Raw: []byte("first")}}
	different := &apkSignerIdentity{certificate: &x509.Certificate{Raw: []byte("second")}}

	require.NoError(t, ensureSameAPKSigner(first, same))
	require.ErrorIs(t, ensureSameAPKSigner(first, different), ErrAPKSignerMismatch)
	require.ErrorIs(t, ensureSameAPKSigner(first, nil), ErrInvalidAPKSignature)
}

func TestRepresentativeSDKVersions(t *testing.T) {
	assert.Equal(t, []int32{23, 24, 28, 33}, representativeSDKVersions(1))
	assert.Equal(t, []int32{26, 28, 33}, representativeSDKVersions(26))
	assert.Equal(t, []int32{34}, representativeSDKVersions(34))
}

func parseAPKFixture(t *testing.T, name string) (*fdroid_module.Package, error) {
	t.Helper()
	buffer := openAPKFixture(t, name)
	return ParsePackage(context.Background(), buffer)
}

func openAPKFixture(t *testing.T, name string) *packages_module.HashedBuffer {
	t.Helper()

	file, err := os.Open("testdata/" + name)
	require.NoError(t, err)
	defer file.Close()

	buffer, err := packages_module.CreateHashedBufferFromReader(file)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, buffer.Close()) })
	return buffer
}
