// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package fdroid

import (
	"testing"
	"time"

	"forgejo.org/modules/keying"

	"github.com/stretchr/testify/require"
)

func TestRepositoryKeyEncoding(t *testing.T) {
	keying.Init([]byte("fdroid-repository-test-secret"))
	now := time.Date(2026, time.July, 18, 0, 0, 0, 0, time.UTC)
	privateKey, certificate, err := generateRepositoryKey("example", now)
	require.NoError(t, err)
	require.Equal(t, repositoryKeyBits, privateKey.N.BitLen())
	require.True(t, certificate.NotBefore.Before(now))
	require.True(t, certificate.NotAfter.After(now.AddDate(29, 0, 0)))
	require.Len(t, RepositoryFingerprint(certificate), 64)

	privateValue, certificateValue, err := encodeRepositoryKey(42, privateKey, certificate)
	require.NoError(t, err)
	require.NotContains(t, privateValue, "PRIVATE KEY")

	decodedPrivateKey, decodedCertificate, err := decodeRepositoryKey(42, privateValue, certificateValue)
	require.NoError(t, err)
	require.True(t, privateKey.Equal(decodedPrivateKey))
	require.Equal(t, certificate.Raw, decodedCertificate.Raw)

	_, _, err = decodeRepositoryKey(43, privateValue, certificateValue)
	require.Error(t, err)
}
