// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package fdroid

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateSignedJAR(t *testing.T) {
	certificate, privateKey := newTestJARSigner(t)
	testCases := []struct {
		name       string
		filename   string
		profile    JARSignatureProfile
		digestName string
	}{
		{name: "legacy index", filename: "index-v1.json", profile: JARSignatureProfileSHA1, digestName: "SHA1"},
		{name: "entry", filename: "entry.json", profile: JARSignatureProfileSHA256, digestName: "SHA-256"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			content := []byte(`{"repo":{"name":"Forgejo"}}`)
			first, err := CreateSignedJAR(testCase.filename, content, certificate, privateKey, testCase.profile)
			require.NoError(t, err)
			second, err := CreateSignedJAR(testCase.filename, content, certificate, privateKey, testCase.profile)
			require.NoError(t, err)
			assert.Equal(t, first, second, "signed JAR generation must be deterministic")

			files := readJARFiles(t, first)
			require.Len(t, files, 4)
			assert.Equal(t, content, files[testCase.filename])

			manifest := files["META-INF/MANIFEST.MF"]
			signatureFile := files["META-INF/FORGEJO.SF"]
			signatureBlock := files["META-INF/FORGEJO.RSA"]
			require.NotEmpty(t, manifest)
			require.NotEmpty(t, signatureFile)
			require.NotEmpty(t, signatureBlock)
			assert.Contains(t, string(manifest), testCase.digestName+"-Digest: ")
			assert.Contains(t, string(signatureFile), testCase.digestName+"-Digest-Manifest: ")
			assertValidJARManifestLines(t, manifest)
			assertValidJARManifestLines(t, signatureFile)

			signedData, err := pkcs7.Parse(signatureBlock)
			require.NoError(t, err)
			require.Len(t, signedData.Certificates, 1)
			assert.Equal(t, certificate.Raw, signedData.Certificates[0].Raw)
			signedData.Content = signatureFile
			require.NoError(t, signedData.Verify())
		})
	}
}

func TestCreateSignedJARWrapsLongAttributes(t *testing.T) {
	certificate, privateKey := newTestJARSigner(t)
	filename := strings.Repeat("long-name-", 12) + "index.json"

	jar, err := CreateSignedJAR(filename, []byte("{}"), certificate, privateKey, JARSignatureProfileSHA256)
	require.NoError(t, err)
	files := readJARFiles(t, jar)

	assert.Contains(t, string(files["META-INF/MANIFEST.MF"]), "\r\n ")
	assertValidJARManifestLines(t, files["META-INF/MANIFEST.MF"])
	assertValidJARManifestLines(t, files["META-INF/FORGEJO.SF"])
}

func TestCreateSignedJARValidatesInput(t *testing.T) {
	certificate, privateKey := newTestJARSigner(t)
	invalidNames := []string{"", ".", "../entry.json", "/entry.json", "directory/", "META-INF/entry.json", "meta-inf/entry.json", "entry\\name.json", "entry\n.json"}
	for _, name := range invalidNames {
		t.Run(name, func(t *testing.T) {
			_, err := CreateSignedJAR(name, nil, certificate, privateKey, JARSignatureProfileSHA256)
			require.ErrorIs(t, err, ErrInvalidJARFilename)
		})
	}

	_, err := CreateSignedJAR("entry.json", nil, certificate, privateKey, JARSignatureProfile(255))
	require.ErrorIs(t, err, ErrUnsupportedSignatureProfile)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, err = CreateSignedJAR("entry.json", nil, certificate, otherKey, JARSignatureProfileSHA256)
	require.ErrorIs(t, err, ErrJARKeyMismatch)
}

func TestCreateSignedJARJavaVerification(t *testing.T) {
	jarsigner, err := exec.LookPath("jarsigner")
	if err != nil {
		t.Skip("jarsigner is not installed")
	}
	certificate, privateKey := newTestJARSigner(t)

	for _, testCase := range []struct {
		name     string
		filename string
		profile  JARSignatureProfile
	}{
		{name: "SHA1", filename: "index-v1.json", profile: JARSignatureProfileSHA1},
		{name: "SHA256", filename: "entry.json", profile: JARSignatureProfileSHA256},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			jar, err := CreateSignedJAR(testCase.filename, []byte("{}\n"), certificate, privateKey, testCase.profile)
			require.NoError(t, err)
			jarPath := filepath.Join(t.TempDir(), testCase.name+".jar")
			require.NoError(t, os.WriteFile(jarPath, jar, 0o600))

			args := []string{"-verify", "-verbose", jarPath}
			if testCase.profile == JARSignatureProfileSHA1 {
				securityProperties := filepath.Join(t.TempDir(), "java.security")
				require.NoError(t, os.WriteFile(securityProperties, []byte("jdk.jar.disabledAlgorithms=MD2, MD5, RSA keySize < 1024\n"), 0o600))
				args = append([]string{"-J-Djava.security.properties=" + securityProperties}, args...)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, jarsigner, args...)
			command.Env = append(os.Environ(), "LC_ALL=C")
			output, err := command.CombinedOutput()
			require.NoError(t, err, "%s", output)
			assert.Contains(t, strings.ToLower(string(output)), "jar verified")
		})
	}
}

func newTestJARSigner(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Forgejo F-Droid Test"},
		NotBefore:    time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2040, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return certificate, privateKey
}

func readJARFiles(t *testing.T, data []byte) map[string][]byte {
	t.Helper()

	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	files := make(map[string][]byte, len(reader.File))
	for _, file := range reader.File {
		r, err := file.Open()
		require.NoError(t, err)
		content := new(bytes.Buffer)
		_, err = content.ReadFrom(r)
		require.NoError(t, err)
		require.NoError(t, r.Close())
		files[file.Name] = content.Bytes()
	}
	return files
}

func assertValidJARManifestLines(t *testing.T, data []byte) {
	t.Helper()

	withoutCRLF := bytes.ReplaceAll(data, []byte("\r\n"), nil)
	assert.NotContains(t, string(withoutCRLF), "\r")
	assert.NotContains(t, string(withoutCRLF), "\n")
	for line := range bytes.SplitSeq(data, []byte("\r\n")) {
		assert.LessOrEqual(t, len(line), 70, "JAR manifest physical lines may be at most 72 bytes including CRLF")
	}
}
