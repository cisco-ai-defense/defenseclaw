// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// An old per-user config can still say open during upgrade. A foreign
// listener or a native connected-peer refusal reaches fail_unreachable;
// that branch must block despite the stale value. An administrator's managed
// outage setting remains open when no integrity failure is involved.
func TestPerUserListenerFailureCannotUseAnOldOpenMode(t *testing.T) {
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(t.TempDir(), "_hardening.sh")
	if err := os.WriteFile(helper, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, managed, strict, want string }{
		{"per-user old open", "0", "0", "closed"},
		{"managed admin outage open", "1", "0", "open"},
		{"managed strict", "1", "1", "closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := `FAIL_MODE=open; DEFENSECLAW_MANAGED_HOOK="$2"; DEFENSECLAW_STRICT_AVAILABILITY="$3"; . "$1"; if defenseclaw_should_fail_closed_on_unreachable; then echo closed; else echo open; fi`
			out, err := exec.Command("bash", "-c", script, "bash", helper, tc.managed, tc.strict).CombinedOutput()
			if err != nil || strings.TrimSpace(string(out)) != tc.want {
				t.Fatalf("listener failure mode=%q error=%v; want %s", out, err, tc.want)
			}
		})
	}
}
