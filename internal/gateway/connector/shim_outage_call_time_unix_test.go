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

// GAP-1989: the PATH shims kept the fail mode rendered at setup, so
// `guardrail use-pack strict` with the gateway stopped still ran curl, nc and
// ssh unchecked. A shim installed open asks the config at call time: the
// strict tier refuses the call, the default tier runs it with the warning.
func TestPathShimsOutageFollowsTheConfigNow(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required by the shim templates")
	}
	for _, tc := range []struct {
		name, mode string
		runs       bool
	}{{"default tier", "open", true}, {"strict tier saved after setup", "closed", false}} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			dataDir := filepath.Join(home, ".defenseclaw")
			if err := SetupSubprocessEnforcement(SubprocessShims, SetupOpts{DataDir: dataDir, APIAddr: freeLoopbackAddrForOutageTest(t), HookFailMode: "open"}); err != nil {
				t.Fatal(err)
			}
			binDir := filepath.Join(home, ".local", "bin")
			if err := os.MkdirAll(binDir, 0o700); err != nil {
				t.Fatal(err)
			}
			// The account gateway: hook-post finds no gateway (7), and
			// hook-outage-mode answers what the config says now.
			gateway := "#!/bin/sh\nif [ \"$1\" = hook-outage-mode ]; then printf '" + tc.mode + "\\n'; exit 0; fi\ncat >/dev/null\nexit 7\n"
			if err := os.WriteFile(filepath.Join(binDir, "defenseclaw-gateway"), []byte(gateway), 0o700); err != nil {
				t.Fatal(err)
			}
			realDir := filepath.Join(root, "real-tools")
			if err := os.MkdirAll(realDir, 0o700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(root, "curl.ran")
			if err := os.WriteFile(filepath.Join(realDir, "curl"), []byte("#!/bin/sh\n: > \"$DC_SHIM_REAL_RAN\"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(systemBashForTest(t), filepath.Join(dataDir, "shims", "curl"), "--version")
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home,
				"PATH="+filepath.Join(dataDir, "shims")+":"+realDir+":/usr/bin:/bin", "DC_SHIM_REAL_RAN="+marker)
			out, err := cmd.CombinedOutput()
			_, ranErr := os.Stat(marker)
			if ran := err == nil && ranErr == nil; ran != tc.runs {
				t.Fatalf("real curl ran=%v, want %v (exit %v): %s", ran, tc.runs, err, out)
			}
			if !tc.runs && !strings.Contains(string(out), "refusing to exec curl") {
				t.Fatalf("strict refusal text missing: %s", out)
			}
		})
	}
}
