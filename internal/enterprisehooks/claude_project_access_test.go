// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestDecideClaudeProjectRead(t *testing.T) {
	denied := fmt.Errorf("%w: user cannot read project", errClaudeProjectAccessDenied)
	unexpected := errors.New("token unavailable")
	for _, tc := range []struct {
		name               string
		accessErr, readErr error
		want               claudeProjectReadDecision
	}{
		{"readable", nil, nil, claudeProjectKeep},
		{"missing file", nil, os.ErrNotExist, claudeProjectKeep},
		{"directory denied", denied, nil, claudeProjectRefused},
		{"token unavailable", unexpected, nil, claudeProjectUnreadable},
		{"file read failed", nil, denied, claudeProjectUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideClaudeProjectRead(tc.accessErr, tc.readErr); got != tc.want {
				t.Fatalf("decision = %v, want %v", got, tc.want)
			}
		})
	}
}
