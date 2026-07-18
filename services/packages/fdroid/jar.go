// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package fdroid

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 is required for legacy F-Droid index-v1 compatibility.
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"path"
	"strings"
	"time"

	"github.com/smallstep/pkcs7"
)

const jarSignerAlias = "FORGEJO"

var (
	ErrInvalidJARFilename          = errors.New("invalid signed JAR content filename")
	ErrUnsupportedSignatureProfile = errors.New("unsupported JAR signature profile")
	ErrJARKeyMismatch              = errors.New("JAR certificate does not match the private key")
)

// JARSignatureProfile selects the digest and RSA signature algorithms used by an F-Droid index JAR.
type JARSignatureProfile uint8

const (
	// JARSignatureProfileSHA1 produces the legacy SHA-1/SHA1withRSA format required by index-v1.jar.
	JARSignatureProfileSHA1 JARSignatureProfile = iota
	// JARSignatureProfileSHA256 produces the SHA-256/SHA256withRSA format required by entry.jar.
	JARSignatureProfileSHA256
)

type jarSignatureAlgorithms struct {
	digestName string
	digestOID  asn1.ObjectIdentifier
	newHash    func() hash.Hash
}

// CreateSignedJAR creates a v1/JAR-signed archive containing content under filename.
// The content bytes are hashed and stored without modification.
func CreateSignedJAR(filename string, content []byte, certificate *x509.Certificate, privateKey crypto.Signer, profile JARSignatureProfile) ([]byte, error) {
	if err := validateJARFilename(filename); err != nil {
		return nil, err
	}
	algorithms, err := profile.algorithms()
	if err != nil {
		return nil, err
	}
	if err := validateJARSigner(certificate, privateKey); err != nil {
		return nil, err
	}

	manifestMain, manifestEntry, err := createJARManifest(filename, content, algorithms)
	if err != nil {
		return nil, err
	}
	manifest := append(append([]byte(nil), manifestMain...), manifestEntry...)
	signatureFile, err := createJARSignatureFile(filename, manifestMain, manifestEntry, manifest, algorithms)
	if err != nil {
		return nil, err
	}
	signatureBlock, err := createPKCS7Signature(signatureFile, certificate, privateKey, algorithms)
	if err != nil {
		return nil, err
	}

	var output bytes.Buffer
	zw := zip.NewWriter(&output)
	files := []struct {
		name string
		data []byte
	}{
		{"META-INF/MANIFEST.MF", manifest},
		{"META-INF/" + jarSignerAlias + ".SF", signatureFile},
		{"META-INF/" + jarSignerAlias + ".RSA", signatureBlock},
		{filename, content},
	}
	for _, file := range files {
		if err := writeJARFile(zw, file.name, file.data); err != nil {
			_ = zw.Close()
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func (profile JARSignatureProfile) algorithms() (jarSignatureAlgorithms, error) {
	switch profile {
	case JARSignatureProfileSHA1:
		return jarSignatureAlgorithms{
			digestName: "SHA1",
			digestOID:  pkcs7.OIDDigestAlgorithmSHA1,
			newHash:    sha1.New, //nolint:gosec // Required for legacy F-Droid clients.
		}, nil
	case JARSignatureProfileSHA256:
		return jarSignatureAlgorithms{
			digestName: "SHA-256",
			digestOID:  pkcs7.OIDDigestAlgorithmSHA256,
			newHash:    sha256.New,
		}, nil
	default:
		return jarSignatureAlgorithms{}, ErrUnsupportedSignatureProfile
	}
}

func validateJARFilename(filename string) error {
	if filename == "" || filename == "." || filename == ".." || strings.HasPrefix(filename, "../") || strings.HasSuffix(filename, "/") || path.IsAbs(filename) || path.Clean(filename) != filename || strings.HasPrefix(strings.ToUpper(filename), "META-INF/") || strings.Contains(filename, "\\") {
		return ErrInvalidJARFilename
	}
	for i := 0; i < len(filename); i++ {
		if filename[i] < 0x20 || filename[i] > 0x7e {
			return ErrInvalidJARFilename
		}
	}
	return nil
}

func validateJARSigner(certificate *x509.Certificate, privateKey crypto.Signer) error {
	if certificate == nil || privateKey == nil {
		return ErrJARKeyMismatch
	}
	if _, ok := certificate.PublicKey.(*rsa.PublicKey); !ok {
		return errors.New("F-Droid repository certificates must use RSA")
	}
	if _, ok := privateKey.Public().(*rsa.PublicKey); !ok {
		return errors.New("F-Droid repository private keys must use RSA")
	}
	certificateKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return err
	}
	privateKeyPublic, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return err
	}
	if !bytes.Equal(certificateKey, privateKeyPublic) {
		return ErrJARKeyMismatch
	}
	return nil
}

func createJARManifest(filename string, content []byte, algorithms jarSignatureAlgorithms) (mainSection, entrySection []byte, err error) {
	var main bytes.Buffer
	if err := writeJARAttribute(&main, "Manifest-Version", "1.0"); err != nil {
		return nil, nil, err
	}
	if err := writeJARAttribute(&main, "Created-By", "Forgejo"); err != nil {
		return nil, nil, err
	}
	main.WriteString("\r\n")

	var entry bytes.Buffer
	if err := writeJARAttribute(&entry, "Name", filename); err != nil {
		return nil, nil, err
	}
	if err := writeJARAttribute(&entry, algorithms.digestName+"-Digest", digestBase64(content, algorithms)); err != nil {
		return nil, nil, err
	}
	entry.WriteString("\r\n")
	return main.Bytes(), entry.Bytes(), nil
}

func createJARSignatureFile(filename string, manifestMain, manifestEntry, manifest []byte, algorithms jarSignatureAlgorithms) ([]byte, error) {
	var signatureFile bytes.Buffer
	if err := writeJARAttribute(&signatureFile, "Signature-Version", "1.0"); err != nil {
		return nil, err
	}
	if err := writeJARAttribute(&signatureFile, "Created-By", "Forgejo"); err != nil {
		return nil, err
	}
	if err := writeJARAttribute(&signatureFile, algorithms.digestName+"-Digest-Manifest", digestBase64(manifest, algorithms)); err != nil {
		return nil, err
	}
	if err := writeJARAttribute(&signatureFile, algorithms.digestName+"-Digest-Manifest-Main-Attributes", digestBase64(manifestMain, algorithms)); err != nil {
		return nil, err
	}
	signatureFile.WriteString("\r\n")
	if err := writeJARAttribute(&signatureFile, "Name", filename); err != nil {
		return nil, err
	}
	if err := writeJARAttribute(&signatureFile, algorithms.digestName+"-Digest", digestBase64(manifestEntry, algorithms)); err != nil {
		return nil, err
	}
	signatureFile.WriteString("\r\n")
	return signatureFile.Bytes(), nil
}

func createPKCS7Signature(signatureFile []byte, certificate *x509.Certificate, privateKey crypto.Signer, algorithms jarSignatureAlgorithms) ([]byte, error) {
	signedData, err := pkcs7.NewSignedData(signatureFile)
	if err != nil {
		return nil, err
	}
	signedData.SetDigestAlgorithm(algorithms.digestOID)
	if err := signedData.SignWithoutAttr(certificate, privateKey, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}
	signedData.Detach()
	return signedData.Finish()
}

func digestBase64(data []byte, algorithms jarSignatureAlgorithms) string {
	digest := algorithms.newHash()
	_, _ = digest.Write(data)
	return base64.StdEncoding.EncodeToString(digest.Sum(nil))
}

func writeJARAttribute(output *bytes.Buffer, name, value string) error {
	if name == "" || strings.ContainsAny(name, "\r\n:") || strings.ContainsAny(value, "\r\n") {
		return errors.New("invalid JAR manifest attribute")
	}
	line := fmt.Appendf(nil, "%s: %s", name, value)
	for first := true; len(line) > 0; first = false {
		lineLength := 70
		if !first {
			output.WriteByte(' ')
			lineLength--
		}
		if lineLength > len(line) {
			lineLength = len(line)
		}
		output.Write(line[:lineLength])
		output.WriteString("\r\n")
		line = line[lineLength:]
	}
	return nil
}

func writeJARFile(zw *zip.Writer, name string, data []byte) error {
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.Modified = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)
	w, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
