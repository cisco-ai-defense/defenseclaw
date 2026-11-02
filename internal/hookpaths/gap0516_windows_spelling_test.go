// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestGAP0516WindowsHomeSpellings(t *testing.T) {
	for _, home := range []string{`C:\Users\Alice`, `C:/Users/Alice`} {
		keys := strings.TrimRight(home, `\/`) + `/.ssh/authorized_keys`
		for _, row := range []struct{ name, command, want string }{
			{"head-then-marker", `head -n 1 */*; echo done`, ""},
			{"discard-then-marker", `head -n 1 */* 2>/dev/null; echo done`, ""},
			{"head-then-pwd", `head -n 1 */*; pwd`, ""},
			{"echo-glob-then-marker", `echo */*; echo done`, ""},
			{"relative-write", `head -n 1 */*; echo marker >> .ssh/authorized_keys`, "protected-target"},
			{"tilde-write", `echo */*; echo marker >> ~/.ssh/authorized_keys`, "protected-target"},
			{"absolute-write", `head -n 1 */*; echo marker >> "` + keys + `"`, "protected-target"},
		} {
			t.Run(home+"/"+row.name, func(t *testing.T) {
				if got := ActionCommandDecisionWithDialectAndGlobFacts(row.command, home, home, actionfacts.DialectPOSIX, nil); got != row.want {
					t.Errorf("%q: got %q, want %q", row.command, got, row.want)
				}
			})
		}
	}
}
