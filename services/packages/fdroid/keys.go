// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package fdroid

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	user_model "forgejo.org/models/user"
	"forgejo.org/modules/keying"
	fdroid_module "forgejo.org/modules/packages/fdroid"
	"forgejo.org/modules/sync"
	"forgejo.org/modules/util"
)

const repositoryKeyBits = 3072

var repositoryKeyLocker = sync.NewExclusivePool()

func GetOrCreateRepositoryKey(ctx context.Context, ownerID int64) (*rsa.PrivateKey, *x509.Certificate, error) {
	lockKey := fmt.Sprintf("pkg_%d_fdroid_repository_key", ownerID)
	repositoryKeyLocker.CheckIn(lockKey)
	defer repositoryKeyLocker.CheckOut(lockKey)

	privateValue, privateErr := user_model.GetSetting(ctx, ownerID, fdroid_module.SettingKeyPrivateKey)
	if privateErr != nil && !errors.Is(privateErr, util.ErrNotExist) {
		return nil, nil, privateErr
	}
	certificateValue, certificateErr := user_model.GetSetting(ctx, ownerID, fdroid_module.SettingKeyCertificate)
	if certificateErr != nil && !errors.Is(certificateErr, util.ErrNotExist) {
		return nil, nil, certificateErr
	}

	if privateValue != "" && certificateValue != "" {
		privateKey, certificate, err := decodeRepositoryKey(ownerID, privateValue, certificateValue)
		if err == nil {
			return privateKey, certificate, nil
		}
		return nil, nil, err
	}

	owner, err := user_model.GetUserByID(ctx, ownerID)
	if err != nil {
		return nil, nil, err
	}
	privateKey, certificate, err := generateRepositoryKey(owner.Name, time.Now())
	if err != nil {
		return nil, nil, err
	}
	privateValue, certificateValue, err = encodeRepositoryKey(ownerID, privateKey, certificate)
	if err != nil {
		return nil, nil, err
	}
	if err := user_model.SetUserSetting(ctx, ownerID, fdroid_module.SettingKeyPrivateKey, privateValue); err != nil {
		return nil, nil, err
	}
	if err := user_model.SetUserSetting(ctx, ownerID, fdroid_module.SettingKeyCertificate, certificateValue); err != nil {
		return nil, nil, err
	}
	return privateKey, certificate, nil
}

func RepositoryFingerprint(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(sum[:])
}

func generateRepositoryKey(owner string, now time.Time) (*rsa.PrivateKey, *x509.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, repositoryKeyBits)
	if err != nil {
		return nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   owner + " F-Droid Repository",
			Organization: []string{"Forgejo"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(30, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, certificate, nil
}

func encodeRepositoryKey(ownerID int64, privateKey *rsa.PrivateKey, certificate *x509.Certificate) (string, string, error) {
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}
	encrypted := keying.FDroidRepository.Encrypt(privateDER, keying.ColumnAndID("setting_value", ownerID))
	return base64.RawStdEncoding.EncodeToString(encrypted), base64.RawStdEncoding.EncodeToString(certificate.Raw), nil
}

func decodeRepositoryKey(ownerID int64, privateValue, certificateValue string) (*rsa.PrivateKey, *x509.Certificate, error) {
	encrypted, err := base64.RawStdEncoding.DecodeString(privateValue)
	if err != nil {
		return nil, nil, err
	}
	privateDER, err := keying.FDroidRepository.Decrypt(encrypted, keying.ColumnAndID("setting_value", ownerID))
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		return nil, nil, err
	}
	privateKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("F-Droid repository key is not RSA")
	}
	certificateDER, err := base64.RawStdEncoding.DecodeString(certificateValue)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, nil, err
	}
	if !privateKey.PublicKey.Equal(certificate.PublicKey) {
		return nil, nil, errors.New("F-Droid repository key and certificate do not match")
	}
	return privateKey, certificate, nil
}
