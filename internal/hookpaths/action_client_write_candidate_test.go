// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGAP0288WrappedCopyVariableDestinationEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX client evidence")
	}
	root := t.TempDir()
	home, project := filepath.Join(root, "home"), filepath.Join(root, "home", "proj")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.ssh/authorized_keys", filepath.Join(project, "disklink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, row := range []struct {
		name, command string
		protected     bool
	}{
		{"wrapped-known-link", `cd ~ && f=proj/disklink; for x in 1; do env cp proj/a.txt $f; done`, true},
		{"direct-known-link", `cd ~ && f=proj/disklink; for x in 1; do cp proj/a.txt $f; done`, true},
		{"wrapped-ordinary", `cd ~ && f=proj/out.txt; for x in 1; do env cp proj/a.txt $f; done`, false},
		{"wrapped-source-link", `cd ~ && f=proj/out.txt; for x in 1; do env cp proj/disklink $f; done`, false},
		{"wrapped-suffix", `cd ~ && f=proj/disklink; for x in 1; do env cp proj/a.txt "$f.bak"; done`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{
				"session_id": "g288", "hook_event_name": "PreToolUse", "cwd": project,
				"tool_name": "Bash", "tool_input": map[string]any{"command": row.command},
			})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			if !ok {
				t.Fatal("client evidence did not decode")
			}
			if got := targets[ActionDecisionKey] == ProtectedTargetDecision; got != row.protected {
				t.Errorf("client protected decision = %v, want %v", got, row.protected)
			}
		})
	}
}

func TestActionClientWriteCandidate(t *testing.T) {
	for _, row := range []struct {
		command string
		want    bool
	}{
		{"format source.go", false},
		{"terraform plan", false},
		{"npm run build 2>&1", false},
		{"go test ./... > build/test.log 2>&1", true},
		{"echo x >& build/out.log", true},
		{"rm -f sshlink/authorized_keys", true},
		{"pwsh -c \"Set-Content -Path keylink -Value k\"", true},
	} {
		if got := actionClientWriteCandidate(row.command); got != row.want {
			t.Errorf("%q: candidate %v, want %v", row.command, got, row.want)
		}
	}
}

func TestActionClientDeadValueProofDeclinesChangedShellExpansion(t *testing.T) {
	// The proof needs an absolute working directory, as every hook reports;
	// /tmp/project is not one on Windows.
	root := t.TempDir()
	cwd, home := filepath.Join(root, "project"), filepath.Join(root, "home")
	for _, row := range []struct {
		name, command string
		want          bool
	}{
		{"ordinary-redirect", `f=keylink; f=a.txt; echo m >> "$f"`, true},
		{"quoted-install", `f=keylink; f=a.txt; install b.txt "$f"`, true},
		{"quoted-rsync", `f=keylink; f=a.txt; rsync b.txt "$f"`, true},
		{"rebound-home", `HOME=/tmp/project; f=~/keylink; echo m >> "$f"`, false},
		{"directory-stack-tilde", `f=~+/keylink; echo m >> "$f"`, false},
		{"unquoted-install", `f=keylink; f=a.txt; install b.txt $f`, false},
		{"unquoted-rsync", `f=keylink; f=a.txt; rsync b.txt $f`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := actionClientProvedSafeVariableTargets(row.command, cwd, home); got != row.want {
				t.Errorf("proof %v, want %v for %q", got, row.want, row.command)
			}
		})
	}
}
