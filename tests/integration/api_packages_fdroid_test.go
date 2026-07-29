// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"forgejo.org/models/db"
	packages_model "forgejo.org/models/packages"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	fdroid_module "forgejo.org/modules/packages/fdroid"
	"forgejo.org/modules/setting"
	fdroid_service "forgejo.org/services/packages/fdroid"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/smallstep/pkcs7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fdroidTestPackageName = "android.appsecurity.cts.tinyapp"
	fdroidTestVersion     = "10"
	fdroidTestFilename    = fdroidTestPackageName + "_10.apk"
)

func TestPackageFDroid(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	rootURL := fmt.Sprintf("/api/packages/%s/fdroid", owner.Name)
	validAPK := readFDroidFixture(t, "valid-v1v2v3.apk")

	t.Run("UploadAuthenticationAndVerification", func(t *testing.T) {
		MakeRequest(t, NewRequestWithBody(t, "PUT", rootURL, bytes.NewReader(validAPK)), http.StatusUnauthorized)

		for _, fixture := range []string{"unsigned.apk", "invalid-signature.apk", "multiple-signers.apk"} {
			req := NewRequestWithBody(t, "PUT", rootURL, bytes.NewReader(readFDroidFixture(t, fixture))).AddBasicAuth(owner.Name)
			MakeRequest(t, req, http.StatusBadRequest)
		}

		req := NewRequestWithBody(t, "PUT", rootURL, bytes.NewReader(validAPK)).AddBasicAuth(owner.Name)
		MakeRequest(t, req, http.StatusCreated)

		req = NewRequestWithBody(t, "PUT", rootURL, bytes.NewReader(validAPK)).AddBasicAuth(owner.Name)
		MakeRequest(t, req, http.StatusConflict)
	})

	var signerFingerprint string
	t.Run("DatabaseMetadataAndSignerPin", func(t *testing.T) {
		versions, err := packages_model.GetVersionsByPackageType(db.DefaultContext, owner.ID, packages_model.TypeFDroid)
		require.NoError(t, err)
		require.Len(t, versions, 1)

		descriptor, err := packages_model.GetPackageDescriptor(db.DefaultContext, versions[0])
		require.NoError(t, err)
		require.IsType(t, &fdroid_module.VersionMetadata{}, descriptor.Metadata)
		assert.Equal(t, fdroidTestPackageName, descriptor.Package.Name)
		assert.Equal(t, fdroidTestVersion, descriptor.Version.Version)

		files, err := packages_model.GetFilesByVersionID(db.DefaultContext, versions[0].ID)
		require.NoError(t, err)
		require.Len(t, files, 1)
		assert.Equal(t, fdroidTestFilename, files[0].Name)
		assert.True(t, files[0].IsLead)

		fileProperties, err := packages_model.GetProperties(db.DefaultContext, packages_model.PropertyTypeFile, files[0].ID)
		require.NoError(t, err)
		var metadata fdroid_module.FileMetadata
		require.NoError(t, json.Unmarshal([]byte(packagePropertyValue(fileProperties, fdroid_module.PropertyFileMetadata)), &metadata))
		assert.Equal(t, fdroidTestPackageName, metadata.PackageName)
		assert.Equal(t, int64(10), metadata.VersionCode)
		assert.Equal(t, 23, metadata.MinSDKVersion)
		assert.Equal(t, 3, metadata.SignatureScheme)
		signerFingerprint = metadata.SignerSHA256
		require.Len(t, signerFingerprint, 64)

		packageProperties, err := packages_model.GetPropertiesByName(db.DefaultContext, packages_model.PropertyTypePackage, descriptor.Package.ID, fdroid_module.PropertySignerSHA256)
		require.NoError(t, err)
		require.Len(t, packageProperties, 1)
		assert.Equal(t, signerFingerprint, packageProperties[0].Value)

		originalSigner := packageProperties[0].Value
		packageProperties[0].Value = strings.Repeat("0", 64)
		require.NoError(t, packages_model.UpdateProperty(db.DefaultContext, packageProperties[0]))
		req := NewRequestWithBody(t, "PUT", rootURL, bytes.NewReader(validAPK)).AddBasicAuth(owner.Name)
		MakeRequest(t, req, http.StatusConflict)
		packageProperties[0].Value = originalSigner
		require.NoError(t, packages_model.UpdateProperty(db.DefaultContext, packageProperties[0]))
	})

	var firstIndexFilename string
	t.Run("SignedIndexesAndDownload", func(t *testing.T) {
		entryResponse := MakeRequest(t, NewRequest(t, "GET", rootURL+"/repo/"+fdroid_service.EntryJARFilename), http.StatusOK)
		assert.Equal(t, "application/java-archive", entryResponse.Header().Get("Content-Type"))
		entryFiles := readFDroidJAR(t, entryResponse.Body.Bytes())
		entryCertificate := signedJARCertificate(t, entryFiles)
		repositoryFingerprint := fdroid_service.RepositoryFingerprint(entryCertificate)
		require.Len(t, repositoryFingerprint, 64)

		var entry fdroid_service.Entry
		require.NoError(t, json.Unmarshal(entryFiles[fdroid_service.EntryJSONFilename], &entry))
		assert.Equal(t, fdroid_service.IndexVersion, entry.Version)
		assert.Equal(t, 1, entry.Index.NumPackages)
		firstIndexFilename = strings.TrimPrefix(entry.Index.Name, "/")
		assert.True(t, fdroid_service.IsIndexV2Filename(firstIndexFilename))

		headResponse := MakeRequest(t, NewRequest(t, "HEAD", rootURL+"/repo/"+fdroid_service.EntryJARFilename), http.StatusOK)
		assert.Empty(t, headResponse.Body.Bytes())

		indexV2Response := MakeRequest(t, NewRequest(t, "GET", rootURL+"/repo/"+firstIndexFilename), http.StatusOK)
		indexV2JSON := indexV2Response.Body.Bytes()
		indexHash := sha256.Sum256(indexV2JSON)
		assert.Equal(t, entry.Index.SHA256, hex.EncodeToString(indexHash[:]))
		assert.Equal(t, entry.Index.Size, int64(len(indexV2JSON)))

		var indexV2 fdroid_service.IndexV2
		require.NoError(t, json.Unmarshal(indexV2JSON, &indexV2))
		packageV2, ok := indexV2.Packages[fdroidTestPackageName]
		require.True(t, ok)
		require.Len(t, packageV2.Versions, 1)
		for hash, version := range packageV2.Versions {
			assert.Equal(t, hash, version.File.SHA256)
			assert.Equal(t, "/"+fdroidTestFilename, version.File.Name)
			assert.Equal(t, int64(10), version.Manifest.VersionCode)
			require.NotNil(t, version.Manifest.Signer)
			assert.Equal(t, []string{signerFingerprint}, version.Manifest.Signer.SHA256)
		}
		stableIndexResponse := MakeRequest(t, NewRequest(t, "GET", rootURL+"/repo/"+fdroid_service.IndexV2JSONFilename), http.StatusOK)
		stableHash := sha256.Sum256(stableIndexResponse.Body.Bytes())
		assert.Equal(t, indexHash, stableHash)

		indexV1Response := MakeRequest(t, NewRequest(t, "GET", rootURL+"/repo/"+fdroid_service.IndexV1JARFilename), http.StatusOK)
		indexV1Files := readFDroidJAR(t, indexV1Response.Body.Bytes())
		assert.Equal(t, entryCertificate.Raw, signedJARCertificate(t, indexV1Files).Raw)
		var indexV1 fdroid_service.IndexV1
		require.NoError(t, json.Unmarshal(indexV1Files[fdroid_service.IndexV1JSONFilename], &indexV1))
		require.Len(t, indexV1.Apps, 1)
		require.Len(t, indexV1.Packages[fdroidTestPackageName], 1)
		assert.Equal(t, signerFingerprint, indexV1.Packages[fdroidTestPackageName][0].Signer)

		apkResponse := MakeRequest(t, NewRequest(t, "GET", rootURL+"/repo/"+fdroidTestFilename), http.StatusOK)
		assert.Equal(t, "application/vnd.android.package-archive", apkResponse.Header().Get("Content-Type"))
		assert.Equal(t, validAPK, apkResponse.Body.Bytes())

		pageURL := fmt.Sprintf("/%s/-/packages/fdroid/%s/%s", owner.Name, fdroidTestPackageName, fdroidTestVersion)
		pageResponse := MakeRequest(t, NewRequest(t, "GET", pageURL), http.StatusOK)
		pageHTML := pageResponse.Body.String()
		page := NewHTMLParser(t, pageResponse.Body)
		installURL := ""
		page.Find("origin-url").EachWithBreak(func(_ int, selection *goquery.Selection) bool {
			value, ok := selection.Attr("data-url")
			if ok && strings.Contains(value, "/fdroid/repo?fingerprint=") {
				installURL = value
				return false
			}
			return true
		})
		assert.Contains(t, installURL, repositoryFingerprint)
		assert.Contains(t, pageHTML, signerFingerprint)
	})

	t.Run("ManualRebuild", func(t *testing.T) {
		MakeRequest(t, NewRequest(t, "POST", rootURL+"/rebuild"), http.StatusUnauthorized)
		MakeRequest(t, NewRequest(t, "POST", rootURL+"/rebuild").AddBasicAuth(owner.Name), http.StatusNoContent)
		MakeRequest(t, NewRequest(t, "GET", rootURL+"/repo/"+firstIndexFilename), http.StatusOK)
		for range 6 {
			MakeRequest(t, NewRequest(t, "POST", rootURL+"/rebuild").AddBasicAuth(owner.Name), http.StatusNoContent)
		}
		repositoryVersion, err := fdroid_service.GetOrCreateRepositoryVersion(db.DefaultContext, owner.ID)
		require.NoError(t, err)
		files, err := packages_model.GetFilesByVersionID(db.DefaultContext, repositoryVersion.ID)
		require.NoError(t, err)
		indexCount := 0
		for _, file := range files {
			if fdroid_service.IsIndexV2Filename(file.Name) {
				indexCount++
			}
		}
		assert.LessOrEqual(t, indexCount, 5)
	})

	t.Run("DeletePublishesEmptyRepository", func(t *testing.T) {
		deleteURL := rootURL + "/repo/" + fdroidTestFilename
		MakeRequest(t, NewRequest(t, "DELETE", deleteURL), http.StatusUnauthorized)
		MakeRequest(t, NewRequest(t, "DELETE", deleteURL).AddBasicAuth(owner.Name), http.StatusNoContent)
		MakeRequest(t, NewRequest(t, "GET", deleteURL), http.StatusNotFound)

		entryResponse := MakeRequest(t, NewRequest(t, "GET", rootURL+"/repo/"+fdroid_service.EntryJARFilename), http.StatusOK)
		entryFiles := readFDroidJAR(t, entryResponse.Body.Bytes())
		var entry fdroid_service.Entry
		require.NoError(t, json.Unmarshal(entryFiles[fdroid_service.EntryJSONFilename], &entry))
		assert.Zero(t, entry.Index.NumPackages)

		indexFilename := strings.TrimPrefix(entry.Index.Name, "/")
		indexResponse := MakeRequest(t, NewRequest(t, "GET", rootURL+"/repo/"+indexFilename), http.StatusOK)
		var index fdroid_service.IndexV2
		require.NoError(t, json.Unmarshal(indexResponse.Body.Bytes(), &index))
		assert.Empty(t, index.Packages)

		indexV1Response := MakeRequest(t, NewRequest(t, "GET", rootURL+"/repo/"+fdroid_service.IndexV1JARFilename), http.StatusOK)
		var indexV1 fdroid_service.IndexV1
		require.NoError(t, json.Unmarshal(readFDroidJAR(t, indexV1Response.Body.Bytes())[fdroid_service.IndexV1JSONFilename], &indexV1))
		assert.Empty(t, indexV1.Apps)
		assert.Empty(t, indexV1.Packages)
	})

	t.Run("UploadRotatedKey", func(t *testing.T) {
		rotatedAPK := readFDroidFixture(t, "rotated-signing-key.apk")
		reqRotated := NewRequestWithBody(t, "PUT", rootURL, bytes.NewReader(rotatedAPK)).AddBasicAuth(owner.Name)
		MakeRequest(t, reqRotated, http.StatusCreated)
	})
}

func readFDroidFixture(t *testing.T, filename string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(setting.AppWorkPath, "services", "packages", "fdroid", "testdata", filename))
	require.NoError(t, err)
	return content
}

func readFDroidJAR(t *testing.T, content []byte) map[string][]byte {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	require.NoError(t, err)
	files := make(map[string][]byte, len(reader.File))
	for _, file := range reader.File {
		stream, err := file.Open()
		require.NoError(t, err)
		data, err := io.ReadAll(stream)
		require.NoError(t, err)
		require.NoError(t, stream.Close())
		files[file.Name] = data
	}
	return files
}

func signedJARCertificate(t *testing.T, files map[string][]byte) *x509.Certificate {
	t.Helper()
	signedData, err := pkcs7.Parse(files["META-INF/FORGEJO.RSA"])
	require.NoError(t, err)
	require.Len(t, signedData.Certificates, 1)
	signedData.Content = files["META-INF/FORGEJO.SF"]
	require.NoError(t, signedData.Verify())
	return signedData.Certificates[0]
}

func packagePropertyValue(properties []*packages_model.PackageProperty, name string) string {
	for _, property := range properties {
		if property.Name == name {
			return property.Value
		}
	}
	return ""
}
