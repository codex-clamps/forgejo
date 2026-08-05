// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package apex

import (
	"os"
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/modules/packages"

	"github.com/stretchr/testify/require"
)

func TestParseDownloadedApexFiles(t *testing.T) {
	paths := []string{
		"/home/shadichy/Downloads/any_34_com_google_android_devicelock_1.apex",
		"/home/shadichy/Downloads/any_33_com_google_mainline_primary_libs_1.apex",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Skipf("File %s not found", path)
			continue
		}

		f, err := os.Open(path)
		require.NoError(t, err)

		buf, err := packages.CreateHashedBufferFromReader(f)
		f.Close()
		require.NoError(t, err)

		p, err := ParsePackage(db.DefaultContext, buf)
		buf.Close()
		require.NoError(t, err)

		t.Logf("File: %s", path)
		t.Logf("  Name: %q", p.Name)
		t.Logf("  Version: %q", p.Version)
		t.Logf("  Arch: %q", p.FileMetadata.Arch)
		t.Logf("  APILevel: %q", p.FileMetadata.APILevel)
	}
}
