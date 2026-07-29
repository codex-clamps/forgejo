// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"forgejo.org/models/db"
	packages_model "forgejo.org/models/packages"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	packages_module "forgejo.org/modules/packages"
	apex_module "forgejo.org/modules/packages/apex"
	packages_service "forgejo.org/services/packages"
	apex_service "forgejo.org/services/packages/apex"
	"forgejo.org/tests"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	apexTestPackageName    = "org.example.demo"
	apexTestPackageVersion = "1"
	apexTestPackagePath    = "x86_64/29/org/example/demo/1.apex"
)

func addApexPackageFile(t *testing.T, owner *user_model.User, group, filename string, isLead bool) {
	t.Helper()

	data, err := packages_module.CreateHashedBufferFromReader(strings.NewReader(group + ":" + filename))
	require.NoError(t, err)
	defer data.Close()

	pv, _, err := packages_service.CreatePackageOrAddFileToExisting(
		db.DefaultContext,
		&packages_service.PackageCreationInfo{
			PackageInfo: packages_service.PackageInfo{
				Owner:       owner,
				PackageType: packages_model.TypeApex,
				Name:        apexTestPackageName,
				Version:     apexTestPackageVersion,
			},
			Creator: owner,
			Metadata: &apex_module.VersionMetadata{
				Org:         "org.example",
				Description: "APEX integration test package",
			},
		},
		&packages_service.PackageFileCreationInfo{
			PackageFileInfo: packages_service.PackageFileInfo{
				Filename:     filename,
				CompositeKey: group,
			},
			Creator: owner,
			Data:    data,
			IsLead:  isLead,
			Properties: map[string]string{
				apex_module.PropertyArch: "x86_64",
			},
		},
	)
	require.NoError(t, err)
	require.NotNil(t, pv)
}

func addInternalApexRepositoryFile(t *testing.T, owner *user_model.User, pv *packages_model.PackageVersion, group, filename string) {
	t.Helper()

	data, err := packages_module.CreateHashedBufferFromReader(strings.NewReader(group + ":" + filename))
	require.NoError(t, err)
	defer data.Close()

	_, err = packages_service.AddFileToPackageVersionInternal(db.DefaultContext, pv, &packages_service.PackageFileCreationInfo{
		PackageFileInfo: packages_service.PackageFileInfo{
			Filename:     filename,
			CompositeKey: group,
		},
		Creator: owner,
		Data:    data,
	})
	require.NoError(t, err)
}

func apexRepositoryConfig(t *testing.T, owner *user_model.User) (string, []string) {
	t.Helper()

	url := fmt.Sprintf("/%s/-/packages/apex/%s/%s", owner.Name, apexTestPackageName, apexTestPackageVersion)
	resp := MakeRequest(t, NewRequest(t, "GET", url), http.StatusOK)
	configBlock := NewHTMLParser(t, resp.Body).Find("pre.code-block code").First()
	config := configBlock.Text()
	require.NotEmpty(t, config)

	urls := make([]string, 0, configBlock.Find("origin-url").Length())
	configBlock.Find("origin-url").Each(func(_ int, selection *goquery.Selection) {
		dataURL, exists := selection.Attr("data-url")
		require.True(t, exists)
		urls = append(urls, dataURL)
	})
	return config, urls
}

func TestPackageApexRepositorySetup(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	addApexPackageFile(t, owner, "stable", apexTestPackagePath, true)
	addApexPackageFile(t, owner, "stable", apexTestPackagePath+".sig", false)

	config, urls := apexRepositoryConfig(t, owner)
	require.Equal(t, 1, strings.Count(config, "[stable]"))
	require.Equal(t, []string{fmt.Sprintf("/api/packages/%s/apex/stable", owner.Name)}, urls)
	assert.NotContains(t, config, "[testing]")

	addApexPackageFile(t, owner, "testing", apexTestPackagePath, false)
	addApexPackageFile(t, owner, "testing", apexTestPackagePath+".sig", false)

	config, urls = apexRepositoryConfig(t, owner)
	require.Equal(t, 1, strings.Count(config, "[stable]"))
	require.Equal(t, 1, strings.Count(config, "[testing]"))
	require.Equal(t, []string{
		fmt.Sprintf("/api/packages/%s/apex/stable", owner.Name),
		fmt.Sprintf("/api/packages/%s/apex/testing", owner.Name),
	}, urls)
	assert.Less(t, strings.Index(config, "[stable]"), strings.Index(config, "[testing]"))
}

func TestPackageApexRemovesStaleRepositoryFiles(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	pv, err := apex_service.GetOrCreateRepositoryVersion(db.DefaultContext, owner.ID)
	require.NoError(t, err)

	for _, filename := range []string{"stable.db", "stable.db.sig", "stable.files", "stable.providers"} {
		addInternalApexRepositoryFile(t, owner, pv, "stable", filename)
	}
	addInternalApexRepositoryFile(t, owner, pv, "stable", "keep.txt")
	addInternalApexRepositoryFile(t, owner, pv, "testing", "testing.db")

	require.NoError(t, apex_service.BuildApexDB(db.DefaultContext, owner.ID, "stable", ""))

	files, err := packages_model.GetFilesByVersionID(db.DefaultContext, pv.ID)
	require.NoError(t, err)
	filenames := make([]string, 0, len(files))
	for _, file := range files {
		filenames = append(filenames, file.CompositeKey+":"+file.Name)
	}
	slices.Sort(filenames)

	assert.Equal(t, []string{"stable:keep.txt", "testing:testing.db"}, filenames)
}

func TestPackageApexRepositoryDBFallback(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	pv, err := apex_service.GetOrCreateRepositoryVersion(db.DefaultContext, owner.ID)
	require.NoError(t, err)

	addInternalApexRepositoryFile(t, owner, pv, "stable", "stable.db")
	addInternalApexRepositoryFile(t, owner, pv, "stable", "stable.db.sig")

	for _, reqPath := range []string{
		fmt.Sprintf("/api/packages/%s/apex/stable/stable.db", owner.Name),
		fmt.Sprintf("/api/packages/%s/apex/stable/stable.db.tar.gz", owner.Name),
		fmt.Sprintf("/api/packages/%s/apex/stable/stable.files", owner.Name),
		fmt.Sprintf("/api/packages/%s/apex/stable/stable.files.tar.gz", owner.Name),
		fmt.Sprintf("/api/packages/%s/apex/stable/stable.db.sig", owner.Name),
		fmt.Sprintf("/api/packages/%s/apex/stable/stable.db.tar.gz.sig", owner.Name),
	} {
		req := NewRequest(t, "GET", reqPath)
		resp := MakeRequest(t, req, http.StatusOK)
		assert.NotEmpty(t, resp.Body.Bytes())
	}
}
