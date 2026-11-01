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
// ssh unchecked. A shim installed open asks the config at call time for the
// outage mode of the connector that installed it (its per-connector choice,
// else the global one): closed refuses the call, open runs it with the
// warning. The stub gateway answers per --connector, so a shim that asks for
// another connector (it asked for "subprocess") gets the wrong answer.
func TestPathShimsOutageFollowsTheConfigNow(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required by the shim templates")
	}
	for _, tc := range []struct {
		name, installer string
		// modes is what hook-outage-mode prints per --connector; "*" is
		// every other connector (the global mode).
		modes map[string]string
		runs  bool
	}{
		{"default tier", "openclaw", map[string]string{"*": "open"}, true},
		{"strict tier saved after setup", "openclaw", map[string]string{"*": "closed"}, false},
		{"openclaw closed, global unset", "openclaw", map[string]string{"openclaw": "closed", "*": "open"}, false},
		{"global closed, openclaw open", "openclaw", map[string]string{"openclaw": "open", "*": "closed"}, true},
		{"zeptoclaw closed, global unset", "zeptoclaw", map[string]string{"zeptoclaw": "closed", "*": "open"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			dataDir := filepath.Join(home, ".defenseclaw")
			if err := SetupSubprocessEnforcement(SubprocessShims, SetupOpts{DataDir: dataDir, APIAddr: freeLoopbackAddrForOutageTest(t), HookFailMode: "open"}, tc.installer); err != nil {
				t.Fatal(err)
			}
			shim, err := os.ReadFile(filepath.Join(dataDir, "shims", "curl"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(shim), "hook-outage-mode --connector "+tc.installer+" ") || strings.Contains(string(shim), "{{") {
				t.Fatalf("shim does not ask the outage mode of %s:\n%s", tc.installer, shim)
			}
			binDir := filepath.Join(home, ".local", "bin")
			if err := os.MkdirAll(binDir, 0o700); err != nil {
				t.Fatal(err)
			}
			// The account gateway: hook-post finds no gateway (7), and
			// hook-outage-mode answers what the config gives --connector now.
			cases := ""
			for conn, mode := range tc.modes {
				if conn != "*" {
					cases += conn + ") printf '" + mode + "\\n' ;; "
				}
			}
			gateway := "#!/bin/sh\nif [ \"$1\" = hook-outage-mode ]; then\n  [ \"$2\" = --connector ] || exit 9\n  case \"$3\" in " + cases +
				"*) printf '" + tc.modes["*"] + "\\n' ;; esac\n  exit 0\nfi\ncat >/dev/null\nexit 7\n"
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
				t.Fatalf("closed refusal text missing: %s", out)
			}
		})
	}
}

// A connector name the shim would carry unquoted must be a plain name.
func TestPathShimsRefuseAConnectorNameThatIsNotPlain(t *testing.T) {
	for _, name := range []string{"", "subprocess x", "open;claw", "$(id)"} {
		if err := SetupSubprocessEnforcement(SubprocessShims, SetupOpts{DataDir: t.TempDir(), HookFailMode: "open"}, name); err == nil {
			t.Fatalf("connector name %q was rendered into the shims", name)
		}
	}
}
