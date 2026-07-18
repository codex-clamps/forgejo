// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package fdroid

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"

	"forgejo.org/modules/json"

	"github.com/stretchr/testify/require"
)

const (
	testAPKHashA        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testAPKHashB        = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testAPKHashC        = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testSignerA         = "1111111111111111111111111111111111111111111111111111111111111111"
	testSignerB         = "2222222222222222222222222222222222222222222222222222222222222222"
	testRepoFingerprint = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

func repositoryFixture() RepositoryData {
	return RepositoryData{
		Address:     "https://forge.example/api/packages/alice/fdroid/repo",
		Name:        "Alice's apps",
		Description: "Android packages published by Alice.",
		Icon:        "icon.png",
		Fingerprint: testRepoFingerprint,
		Timestamp:   1784332800123,
		MaxAge:      new(14),
		Mirrors: []string{
			"https://forge.example/api/packages/alice/fdroid/repo",
			"https://mirror-b.example/fdroid/repo",
			"https://mirror-a.example/fdroid/repo",
			"https://mirror-b.example/fdroid/repo",
		},
		Apps: []AppData{
			{
				PackageName: "org.example.zeta",
				Name:        "Zeta",
				Summary:     "The Zeta app",
				License:     "MIT",
				Added:       1700000000000,
				LastUpdated: 1784332800000,
				Categories:  []string{"Utilities", "Internet", "Utilities"},
				Versions: []VersionData{
					{
						Added:            1700000000000,
						APKName:          "org.example.zeta_1.apk",
						SHA256:           testAPKHashA,
						Size:             100,
						VersionName:      "1.0",
						VersionCode:      1,
						MinSDKVersion:    21,
						TargetSDKVersion: 28,
						Signers:          []string{testSignerA},
					},
					{
						Added:              1784332800000,
						APKName:            "/org.example.zeta_2.apk",
						SHA256:             testAPKHashB,
						Size:               200,
						VersionName:        "2.0",
						VersionCode:        2,
						MinSDKVersion:      23,
						TargetSDKVersion:   35,
						MaxSDKVersion:      new(36),
						Signers:            []string{testSignerB, testSignerA},
						HasMultipleSigners: true,
						Permissions: []PermissionData{
							{Name: "android.permission.INTERNET"},
							{Name: "android.permission.BLUETOOTH", MaxSDKVersion: new(30)},
						},
						PermissionsSDK23: []PermissionData{{Name: "android.permission.POST_NOTIFICATIONS"}},
						ABIs:             []string{"x86_64", "arm64-v8a", "x86_64"},
						Features:         []string{"android.hardware.camera", "android.hardware.bluetooth"},
					},
				},
			},
			{
				PackageName: "org.example.alpha",
				Name:        "Alpha",
				License:     "Apache-2.0",
				Added:       1710000000000,
				LastUpdated: 1710000000000,
				Versions: []VersionData{{
					Added:       1710000000000,
					APKName:     "org.example.alpha_42.apk",
					SHA256:      testAPKHashC,
					Size:        300,
					VersionName: "42",
					VersionCode: 42,
					Signers:     []string{testSignerA},
				}},
			},
		},
	}
}

func TestBuildIndexes(t *testing.T) {
	generated, err := BuildIndexes(repositoryFixture())
	require.NoError(t, err)

	digest := sha256.Sum256(generated.IndexV2JSON)
	digestHex := hex.EncodeToString(digest[:])
	require.Equal(t, "index-v2."+digestHex+".json", generated.IndexV2Filename)
	require.Equal(t, testRepoFingerprint, generated.Fingerprint)
	require.NotContains(t, string(generated.IndexV1JSON), testRepoFingerprint)
	require.NotContains(t, string(generated.IndexV2JSON), testRepoFingerprint)

	var entry Entry
	require.NoError(t, json.Unmarshal(generated.EntryJSON, &entry))
	require.Equal(t, int64(1784332800123), entry.Timestamp)
	require.Equal(t, IndexVersion, entry.Version)
	require.Equal(t, "/"+generated.IndexV2Filename, entry.Index.Name)
	require.Equal(t, digestHex, entry.Index.SHA256)
	require.Equal(t, int64(len(generated.IndexV2JSON)), entry.Index.Size)
	require.Equal(t, 2, entry.Index.NumPackages)

	var indexV2 IndexV2
	require.NoError(t, json.Unmarshal(generated.IndexV2JSON, &indexV2))
	require.Equal(t, entry.Timestamp, indexV2.Repo.Timestamp)
	require.Equal(t, []MirrorV2{
		{URL: "https://mirror-a.example/fdroid/repo"},
		{URL: "https://mirror-b.example/fdroid/repo"},
	}, indexV2.Repo.Mirrors)
	require.Equal(t, CategoryV2{Name: LocalizedTextV2{DefaultLocale: "Internet"}}, indexV2.Repo.Categories["Internet"])
	require.Equal(t, CategoryV2{Name: LocalizedTextV2{DefaultLocale: "Utilities"}}, indexV2.Repo.Categories["Utilities"])
	zetaV2 := indexV2.Packages["org.example.zeta"]
	require.Equal(t, testSignerA, zetaV2.Metadata.PreferredSigner)
	latestV2 := zetaV2.Versions[testAPKHashB]
	require.Equal(t, "/org.example.zeta_2.apk", latestV2.File.Name)
	require.Equal(t, &UsesSDKV2{MinSDKVersion: 23, TargetSDKVersion: 35}, latestV2.Manifest.UsesSDK)
	require.Equal(t, []string{testSignerA, testSignerB}, latestV2.Manifest.Signer.SHA256)
	require.True(t, latestV2.Manifest.Signer.HasMultipleSigners)
	require.Equal(t, []string{"arm64-v8a", "x86_64"}, latestV2.Manifest.NativeCode)
	require.Equal(t, []PermissionV2{
		{Name: "android.permission.BLUETOOTH", MaxSDKVersion: new(30)},
		{Name: "android.permission.INTERNET"},
	}, latestV2.Manifest.UsesPermission)
	require.Equal(t, []FeatureV2{
		{Name: "android.hardware.bluetooth"},
		{Name: "android.hardware.camera"},
	}, latestV2.Manifest.Features)

	var indexV1 IndexV1
	require.NoError(t, json.Unmarshal(generated.IndexV1JSON, &indexV1))
	require.Equal(t, IndexVersion, indexV1.Repo.Version)
	require.Empty(t, indexV1.Requests.Install)
	require.Empty(t, indexV1.Requests.Uninstall)
	require.Equal(t, "org.example.alpha", indexV1.Apps[0].PackageName)
	require.Equal(t, "org.example.zeta", indexV1.Apps[1].PackageName)
	require.Equal(t, "2", indexV1.Apps[1].SuggestedVersionCode)
	require.Equal(t, int64(2), indexV1.Packages["org.example.zeta"][0].VersionCode)
	require.Equal(t, testSignerA, indexV1.Packages["org.example.zeta"][0].Signer)
	require.Equal(t, []PermissionV1{
		{Name: "android.permission.BLUETOOTH", MaxSDKVersion: new(30)},
		{Name: "android.permission.INTERNET"},
	}, indexV1.Packages["org.example.zeta"][0].UsesPermission)
}

func TestBuildIndexesIsDeterministic(t *testing.T) {
	first := repositoryFixture()
	second := repositoryFixture()
	slices.Reverse(second.Apps)
	slices.Reverse(second.Mirrors)
	for i := range second.Apps {
		slices.Reverse(second.Apps[i].Versions)
		slices.Reverse(second.Apps[i].Categories)
		for j := range second.Apps[i].Versions {
			slices.Reverse(second.Apps[i].Versions[j].Signers)
			slices.Reverse(second.Apps[i].Versions[j].Permissions)
			slices.Reverse(second.Apps[i].Versions[j].ABIs)
			slices.Reverse(second.Apps[i].Versions[j].Features)
		}
	}

	firstGenerated, err := BuildIndexes(first)
	require.NoError(t, err)
	secondGenerated, err := BuildIndexes(second)
	require.NoError(t, err)
	require.Equal(t, firstGenerated, secondGenerated)
}

func TestBuildIndexesDoesNotMutateInput(t *testing.T) {
	data := repositoryFixture()
	expected := repositoryFixture()

	_, err := BuildIndexes(data)
	require.NoError(t, err)
	require.Equal(t, expected, data)
}

func TestBuildIndexesUsesSDKDefaults(t *testing.T) {
	data := repositoryFixture()
	data.Apps = data.Apps[:1]
	data.Apps[0].Versions = data.Apps[0].Versions[:1]
	data.Apps[0].Versions[0].MinSDKVersion = 0
	data.Apps[0].Versions[0].TargetSDKVersion = 35

	generated, err := BuildIndexes(data)
	require.NoError(t, err)
	var index IndexV2
	require.NoError(t, json.Unmarshal(generated.IndexV2JSON, &index))
	require.Equal(t, &UsesSDKV2{MinSDKVersion: 1, TargetSDKVersion: 35}, index.Packages["org.example.zeta"].Versions[testAPKHashA].Manifest.UsesSDK)
}

func TestBuildIndexesAllowsMissingRepositoryIcon(t *testing.T) {
	data := repositoryFixture()
	data.Icon = ""

	generated, err := BuildIndexes(data)
	require.NoError(t, err)
	var index IndexV1
	require.NoError(t, json.Unmarshal(generated.IndexV1JSON, &index))
	require.Empty(t, index.Repo.Icon)
}

func TestPermissionV1JSON(t *testing.T) {
	permission := PermissionV1{Name: "android.permission.BLUETOOTH", MaxSDKVersion: new(30)}
	data, err := json.Marshal(permission)
	require.NoError(t, err)
	require.Equal(t, `["android.permission.BLUETOOTH",30]`, string(data))

	var decoded PermissionV1
	require.NoError(t, json.Unmarshal([]byte(`["android.permission.INTERNET",null]`), &decoded))
	require.Equal(t, "android.permission.INTERNET", decoded.Name)
	require.Nil(t, decoded.MaxSDKVersion)
	require.Error(t, json.Unmarshal([]byte(`["android.permission.INTERNET"]`), &decoded))
}

func TestBuildEntryJSONValidation(t *testing.T) {
	index := []byte(`{"repo":{"timestamp":42},"packages":{"org.example.app":{}}}`)
	_, _, err := BuildEntryJSON(41, nil, index, 1)
	require.ErrorContains(t, err, "does not match index timestamp")

	_, _, err = BuildEntryJSON(42, nil, index, 0)
	require.ErrorContains(t, err, "does not match index package count")

	_, _, err = BuildEntryJSON(42, nil, []byte(`not-json`), 1)
	require.ErrorContains(t, err, "invalid F-Droid v2 index")
}

func TestBuildIndexesValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RepositoryData)
	}{
		{
			name: "missing address",
			mutate: func(data *RepositoryData) {
				data.Address = ""
			},
		},
		{
			name: "invalid repository fingerprint",
			mutate: func(data *RepositoryData) {
				data.Fingerprint = "bad"
			},
		},
		{
			name: "duplicate package",
			mutate: func(data *RepositoryData) {
				data.Apps = append(data.Apps, data.Apps[0])
			},
		},
		{
			name: "invalid APK hash",
			mutate: func(data *RepositoryData) {
				data.Apps[0].Versions[0].SHA256 = "not-a-hash"
			},
		},
		{
			name: "invalid signer",
			mutate: func(data *RepositoryData) {
				data.Apps[0].Versions[0].Signers = []string{"bad"}
			},
		},
		{
			name: "invalid multi-signer",
			mutate: func(data *RepositoryData) {
				data.Apps[0].Versions[0].HasMultipleSigners = true
			},
		},
		{
			name: "negative permission SDK",
			mutate: func(data *RepositoryData) {
				data.Apps[0].Versions[0].Permissions = []PermissionData{{Name: "permission", MaxSDKVersion: new(-1)}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := repositoryFixture()
			test.mutate(&data)
			_, err := BuildIndexes(data)
			require.Error(t, err)
		})
	}
}
