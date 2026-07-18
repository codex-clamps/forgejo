// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package apex

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	packages_model "forgejo.org/models/packages"
	packages_module "forgejo.org/modules/packages"
	apex_module "forgejo.org/modules/packages/apex"
	"forgejo.org/modules/sync"
	"forgejo.org/modules/util"
	"forgejo.org/routers/api/packages/helper"
	"forgejo.org/services/context"
	packages_service "forgejo.org/services/packages"
	apex_service "forgejo.org/services/packages/apex"
)

var (
	apexPkgOrSig = regexp.MustCompile(`^.*\.c?apex(\.sig)*$`)
	apexDBOrSig  = regexp.MustCompile(`^.*\.(db|files|providers)(\.tar\.gz)*(\.sig)*$`)
	apexGroup    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	locker       = sync.NewExclusivePool()
)

func isValidGroup(group string) bool {
	return apexGroup.MatchString(group)
}

func apiError(ctx *context.Context, status int, obj any) {
	helper.LogAndProcessError(ctx, status, obj, func(message string) {
		ctx.PlainText(status, message)
	})
}

func refreshLocker(ctx *context.Context, group string) func() {
	key := fmt.Sprintf("pkg_%d_apex_pkg_%s", ctx.Package.Owner.ID, group)
	locker.CheckIn(key)
	return func() {
		locker.CheckOut(key)
	}
}

func GetRepositoryKey(ctx *context.Context) {
	_, pub, err := apex_service.GetOrCreateKeyPair(ctx, ctx.Package.Owner.ID)
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}

	ctx.ServeContent(strings.NewReader(pub), &context.ServeHeaderOptions{
		ContentType: "application/pgp-keys",
		Filename:    "repository.key",
	})
}

func PushPackage(ctx *context.Context) {
	group := strings.Trim(ctx.Params("*"), "/")
	if !isValidGroup(group) {
		apiError(ctx, http.StatusBadRequest, "invalid repository group")
		return
	}
	releaser := refreshLocker(ctx, group)
	defer releaser()
	upload, needToClose, err := ctx.UploadStream()
	if err != nil {
		if context.IsFormError(err) {
			apiError(ctx, http.StatusBadRequest, err)
		} else {
			apiError(ctx, http.StatusInternalServerError, err)
		}
		return
	}
	if needToClose {
		defer upload.Close()
	}

	buf, err := packages_module.CreateHashedBufferFromReader(upload)
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	defer buf.Close()

	p, err := apex_service.ParsePackage(ctx, buf)
	if err != nil {
		apiError(ctx, http.StatusBadRequest, err)
		return
	}

	_, err = buf.Seek(0, io.SeekStart)
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	sign, err := apex_service.NewFileSign(ctx, ctx.Package.Owner.ID, buf)
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	defer sign.Close()
	_, err = buf.Seek(0, io.SeekStart)
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	_, err = sign.Seek(0, io.SeekStart)
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}

	microArchPath := ""
	if p.FileMetadata.MicroArchLevel != "" {
		microArchPath = "v" + p.FileMetadata.MicroArchLevel + "/"
	}

	filename := fmt.Sprintf("%s/%s%s/%s/%s.%s", p.FileMetadata.Arch, microArchPath, p.FileMetadata.APILevel, strings.ReplaceAll(p.Name, ".", "/"), p.Version, p.FileMetadata.Extension)

	properties := map[string]string{
		apex_module.PropertyDescription: p.Desc(filename),
		apex_module.PropertyFiles:       p.Files(),
		apex_module.PropertyArch:        p.FileMetadata.Arch,
		apex_module.PropertyProvides:    strings.Join(p.VersionMetadata.Provides, "\n"),
		apex_module.PropertyMicroArch:   p.FileMetadata.MicroArchLevel,
		apex_module.PropertyAPILevel:    p.FileMetadata.APILevel,
	}

	version, _, err := packages_service.CreatePackageOrAddFileToExisting(
		ctx,
		&packages_service.PackageCreationInfo{
			PackageInfo: packages_service.PackageInfo{
				Owner:       ctx.Package.Owner,
				PackageType: packages_model.TypeApex,
				Name:        p.Name,
				Version:     p.Version,
			},
			Creator:  ctx.Doer,
			Metadata: p.VersionMetadata,
		},
		&packages_service.PackageFileCreationInfo{
			PackageFileInfo: packages_service.PackageFileInfo{
				Filename:     filename,
				CompositeKey: group,
			},
			OverwriteExisting: false,
			IsLead:            true,
			Creator:           ctx.ContextUser,
			Data:              buf,
			Properties:        properties,
		},
	)
	if err != nil {
		switch {
		case errors.Is(err, packages_model.ErrDuplicatePackageVersion), errors.Is(err, packages_model.ErrDuplicatePackageFile):
			apiError(ctx, http.StatusConflict, err)
		case errors.Is(err, packages_service.ErrQuotaTotalCount), errors.Is(err, packages_service.ErrQuotaTypeSize), errors.Is(err, packages_service.ErrQuotaTotalSize):
			apiError(ctx, http.StatusForbidden, err)
		default:
			apiError(ctx, http.StatusInternalServerError, err)
		}
		return
	}
	// add sign file
	_, err = packages_service.AddFileToPackageVersionInternal(ctx, version, &packages_service.PackageFileCreationInfo{
		PackageFileInfo: packages_service.PackageFileInfo{
			CompositeKey: group,
			Filename:     filename + ".sig",
		},
		OverwriteExisting: true,
		IsLead:            false,
		Creator:           ctx.Doer,
		Data:              sign,
	})
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	if err = apex_service.BuildApexDB(ctx, ctx.Package.Owner.ID, group, p.FileMetadata.Arch); err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	if p.FileMetadata.Arch == "any" {
		if err = apex_service.BuildCustomRepositoryFiles(ctx, ctx.Package.Owner.ID, group); err != nil {
			apiError(ctx, http.StatusInternalServerError, err)
			return
		}
	}
	ctx.Status(http.StatusCreated)
}

func GetPackageOrDB(ctx *context.Context) {
	path := strings.Trim(ctx.Params("*"), "/")
	pathGroups := strings.Split(path, "/")
	if len(pathGroups) < 2 {
		ctx.Status(http.StatusNotFound)
		return
	}
	group := pathGroups[0]
	if !isValidGroup(group) {
		ctx.Status(http.StatusNotFound)
		return
	}
	file := strings.Join(pathGroups[1:], "/")

	if apexPkgOrSig.MatchString(file) {
		pkg, u, pf, err := apex_service.GetPackageFile(ctx, group, file, ctx.Package.Owner.ID)
		if err != nil {
			if errors.Is(err, util.ErrNotExist) {
				apiError(ctx, http.StatusNotFound, err)
			} else {
				apiError(ctx, http.StatusInternalServerError, err)
			}
			return
		}
		helper.ServePackageFile(ctx, pkg, u, pf)
		return
	}

	if apexDBOrSig.MatchString(file) {
		pkg, u, pf, err := apex_service.GetPackageDBFile(ctx, ctx.Package.Owner.ID, group, file, strings.HasSuffix(file, ".sig"))
		if err != nil {
			if errors.Is(err, util.ErrNotExist) {
				apiError(ctx, http.StatusNotFound, err)
			} else {
				apiError(ctx, http.StatusInternalServerError, err)
			}
			return
		}
		helper.ServePackageFile(ctx, pkg, u, pf)
		return
	}

	ctx.Status(http.StatusNotFound)
}

func RemovePackage(ctx *context.Context) {
	path := strings.Trim(ctx.Params("*"), "/")
	pathGroups := strings.Split(path, "/")
	if len(pathGroups) < 2 {
		ctx.Status(http.StatusBadRequest)
		return
	}
	group := pathGroups[0]
	if !isValidGroup(group) {
		ctx.Status(http.StatusBadRequest)
		return
	}
	file := strings.Join(pathGroups[1:], "/")

	// `file` should be architecture-v<microarch>/reverse/domain/org/name/version.apex
	// Parse the path to get pkg, ver, pkgArch
	fileParts := strings.Split(file, "/")
	if len(fileParts) < 4 {
		ctx.Status(http.StatusBadRequest)
		return
	}

	orgStartIndex := 2
	if strings.HasPrefix(fileParts[1], "v") {
		orgStartIndex = 3
	}

	if len(fileParts) <= orgStartIndex+1 {
		ctx.Status(http.StatusBadRequest)
		return
	}

	orgPathParts := fileParts[orgStartIndex : len(fileParts)-1]
	pkg := strings.Join(orgPathParts, ".")

	verFile := fileParts[len(fileParts)-1]
	ver := strings.TrimSuffix(verFile, ".apex")
	ver = strings.TrimSuffix(ver, ".capex")
	ver = strings.TrimSuffix(ver, ".sig")

	releaser := refreshLocker(ctx, group)
	defer releaser()
	pv, err := packages_model.GetVersionByNameAndVersion(
		ctx, ctx.Package.Owner.ID, packages_model.TypeApex, pkg, ver,
	)
	if err != nil {
		if errors.Is(err, util.ErrNotExist) {
			apiError(ctx, http.StatusNotFound, err)
		} else {
			apiError(ctx, http.StatusInternalServerError, err)
		}
		return
	}
	files, err := packages_model.GetFilesByVersionID(ctx, pv.ID)
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	deleted := false
	fileRequest := file
	for _, file := range files {
		if file.CompositeKey == group && file.LowerName == strings.ToLower(fileRequest) {
			deleted = true
			err := packages_service.RemovePackageFileAndVersionIfUnreferenced(ctx, ctx.ContextUser, file)
			if err != nil {
				apiError(ctx, http.StatusInternalServerError, err)
				return
			}
		}
	}
	if deleted {
		err = apex_service.BuildCustomRepositoryFiles(ctx, ctx.Package.Owner.ID, group)
		if err != nil {
			apiError(ctx, http.StatusInternalServerError, err)
			return
		}
		ctx.Status(http.StatusNoContent)
	} else {
		ctx.Error(http.StatusNotFound)
	}
}

func ForceBuildDB(ctx *context.Context) {
	group := strings.Trim(ctx.Params("*"), "/")
	if !isValidGroup(group) {
		ctx.Status(http.StatusBadRequest)
		return
	}
	err := apex_service.BuildApexDB(ctx, ctx.Package.Owner.ID, group, "")
	if err != nil {
		apiError(ctx, http.StatusInternalServerError, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}
