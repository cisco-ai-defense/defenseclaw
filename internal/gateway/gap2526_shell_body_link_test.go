// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-2526: a benign link made inside a literal shell -c body is the link the
// plain ln makes; the protected-target twins keep blocking. GAP-2528: a bare
// cp with no operands is a call with no write, never an evaluator panic.
func TestR105ShellBodyLinkReadsAsThePlainLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix shell rows")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(home, ".ssh"), filepath.Join(home, ".local", "bin"), filepath.Join(cwd, "src"), filepath.Join(cwd, "build")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "a.txt"), filepath.Join(cwd, "src", "a.txt")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	rows := []struct {
		command string
		block   bool
	}{
		{`sh -c "ln -s build/out bin"`, false},
		{`bash -c "ln -sf ../src/main.go link.go"`, false},
		{`nohup sh -c "ln -s build/out bin"`, false},
		{`timeout 60 sh -c "ln -s build/out bin"`, false},
		{`setsid sh -c "ln -sf ../src/main.go link.go"`, false},
		{`setsid sh -c "npm ci && ln -s build/out bin"`, false},
		{`stdbuf -oL bash -c "ln -s src/a.txt a-link.txt"`, false},
		{`setsid sh -c "cp a.txt b.txt && ln -s b.txt c.txt"`, false},
		{`ln -s build/out bin`, false},
		{`cp`, false},
		{`ls; cp`, false},
		{`sh -c "cp"`, false},
		{`sh -c "ln -sf /tmp/k ~/.ssh/authorized_keys"`, true},
		{`sh -c "ln -s ~/.ssh/authorized_keys k && echo x >> k"`, true},
		{`bash -c "ln -s ~/.ssh s && echo x >> s/authorized_keys"`, true},
		{`sh -c "ln -s ~/.defenseclaw/config.yaml c && cp a.txt c"`, true},
		{`ln -s ~/.ssh/authorized_keys k && sh -c "echo x >> k"`, true},
		{`cp a.txt ~/.defenseclaw/config.yaml; cp`, true},
		// RV-c1-1: a link made outside the body and renamed inside it is
		// still the protected target under its new name.
		{`ln -s ~/.defenseclaw/config.yaml c; sh -c "mv c d"; echo x > d`, true},
		{`ln -s ~/.defenseclaw/config.yaml c; bash -c "rename c d c"; echo x > d`, true},
		{`ln -s ~/.defenseclaw/config.yaml c; sh -c "mv c d; echo x > d"`, true},
		{`ln -s ~/.defenseclaw/config.yaml c; sh -c "mv -f c d"; cp a.txt d`, true},
		{`ln -s ~/.defenseclaw c; sh -c "mv c d"; echo x > d/config.yaml`, true},
	}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		for _, row := range rows {
			var findings []RuleFinding
			panicked := ""
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						panicked = fmt.Sprint(rec)
					}
				}()
				findings = dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input:              actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home},
					Connector:          connectorName,
					EnforcementCapable: true,
				})
			}()
			if panicked != "" {
				t.Errorf("%s %q: evaluator panic %s", connectorName, row.command, panicked)
				continue
			}
			if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
				t.Errorf("%s %q: block=%v want %v (%v)", connectorName, row.command, blocked, row.block, findings)
			}
		}
	}
}
