// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package apex

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidGroup(t *testing.T) {
	testCases := []struct {
		name  string
		group string
		valid bool
	}{
		{name: "simple", group: "stable", valid: true},
		{name: "punctuation", group: "stable-v1.2_x86-64", valid: true},
		{name: "empty", group: "", valid: false},
		{name: "current directory", group: ".", valid: false},
		{name: "parent directory", group: "..", valid: false},
		{name: "forward slash", group: "stable/testing", valid: false},
		{name: "backslash", group: `stable\testing`, valid: false},
		{name: "query delimiter", group: "stable?testing", valid: false},
		{name: "fragment delimiter", group: "stable#testing", valid: false},
		{name: "whitespace", group: "stable testing", valid: false},
		{name: "leading punctuation", group: "-stable", valid: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.valid, isValidGroup(testCase.group))
		})
	}
}
