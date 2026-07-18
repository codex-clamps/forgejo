// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package permissions

import (
	"net/http"

	issues_model "forgejo.org/models/issues"
)

func ReqRepoBranchWriter(ctx Context, branch string) {
	if !issues_model.CanMaintainerWriteToBranch(ctx.Context(), *ctx.Permission(), branch, ctx.Doer()) && !IsUserSiteAdmin(ctx) {
		ctx.Error(http.StatusForbidden, "reqRepoBranchWriter", "user should have a permission to write to this branch")
	}
}
