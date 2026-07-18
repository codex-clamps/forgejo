// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"testing"

	"forgejo.org/modules/translation"

	"github.com/stretchr/testify/assert"
)

func TestTranslatePreExecutionWarning(t *testing.T) {
	translation.InitLocales(t.Context())
	lang := translation.NewLocale("en-US")

	tests := []struct {
		name     string
		run      *ActionRun
		expected []string
	}{
		{
			name:     "no warning",
			run:      &ActionRun{},
			expected: nil,
		},
		{
			name: "WarningCodePermissions",
			run: &ActionRun{
				PreExecutionWarningCodes: []PreExecutionWarning{WarningCodePermissions},
				PreExecutionWarningDetails: [][]any{
					{"job1", "https://forgejo.org/docs/latest/user/authorized-integrations/"},
				},
			},
			expected: []string{"Job <code>job1</code> or its workflow has a <code>permissions</code> field, which is not supported in Forgejo and will be ignored. Use <a href=\"https://forgejo.org/docs/latest/user/authorized-integrations/\">Authorized Integrations</a> to grant capabilities to this job instead."},
		},
		{
			name: "MultipleWarnings",
			run: &ActionRun{
				PreExecutionWarningCodes: []PreExecutionWarning{WarningCodePermissions, WarningCodePermissions},
				PreExecutionWarningDetails: [][]any{
					{"job1", "https://forgejo.org/docs/latest/user/authorized-integrations/"},
					{"job4", "https://forgejo.org/docs/latest/user/authorized-integrations/"},
				},
			},
			expected: []string{
				"Job <code>job1</code> or its workflow has a <code>permissions</code> field, which is not supported in Forgejo and will be ignored. Use <a href=\"https://forgejo.org/docs/latest/user/authorized-integrations/\">Authorized Integrations</a> to grant capabilities to this job instead.",
				"Job <code>job4</code> or its workflow has a <code>permissions</code> field, which is not supported in Forgejo and will be ignored. Use <a href=\"https://forgejo.org/docs/latest/user/authorized-integrations/\">Authorized Integrations</a> to grant capabilities to this job instead.",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := TranslatePreExecutionWarning(lang, tt.run)
			assert.Equal(t, tt.expected, err)
		})
	}
}
