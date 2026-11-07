// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
	"testing"
)

func TestDecideClaudeProjectRead(t *testing.T) {
	denied := errors.New("user cannot read project")
	unexpected := errors.New("project path is not local")
	for _, tc := range []struct {
		name               string
		accessErr, readErr error
		want               claudeProjectReadDecision
	}{
		{"readable", nil, nil, claudeProjectKeep},
		{"missing file", nil, os.ErrNotExist, claudeProjectKeep},
		{"directory denied", denied, nil, claudeProjectRefused},
		{"project path rejected", unexpected, nil, claudeProjectRefused},
		{"file read failed", nil, denied, claudeProjectUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideClaudeProjectRead(tc.accessErr, tc.readErr); got != tc.want {
				t.Fatalf("decision = %v, want %v", got, tc.want)
			}
		})
	}
}
