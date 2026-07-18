// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"fmt"

	"forgejo.org/modules/translation"
)

type PreExecutionWarning int64

// PreExecutionWarning values are stored in the database in ActionRun.PreExecutionWarningCodes and therefore values
// can't be reordered or changed without a database migration.  Translation arguments are stored in the database in
// PreExecutionWarningDetails, and so they can't be changed or reordered without creating a migration or a new error
// code to represent the new argument details.
const (
	WarningCodePermissions PreExecutionWarning = iota + 1
)

func TranslatePreExecutionWarning(lang translation.Locale, run *ActionRun) []string {
	warnings := make([]string, len(run.PreExecutionWarningCodes))
	for i, code := range run.PreExecutionWarningCodes {
		switch code {
		case WarningCodePermissions:
			warnings[i] = lang.TrString("actions.workflow.permissions_warning", run.PreExecutionWarningDetails[i]...)
		default:
			warnings[i] = fmt.Sprintf("unsupported warning: code=%v details=%#v", code, run.PreExecutionWarningDetails[i])
		}
	}
	if len(warnings) == 0 {
		return nil
	}
	return warnings
}
