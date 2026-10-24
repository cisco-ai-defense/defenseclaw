// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// Parse uncertainty describes coverage. It does not prove a persistence
// target. These rows exercise both the gateway-only and client-header routes.
func TestBalancedActionOnlyResolvedProtectedTargets(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "disklink")); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"build.sh": "printf ok > report.txt\n",
		"run.sh":   "printf ok > report.txt\n",
		"safe.mk":  "safe:\n\tprintf ok > report.txt\n",
	} {
		if err := os.WriteFile(filepath.Join(cwd, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{
		"make safe", "npm test", "go test ./...", "cargo test", "pip install -e .", "gradle test",
		"git describe --always", "git rev-list HEAD", "git merge-base HEAD HEAD", "git --no-optional-locks fetch",
		"./run.sh test", "bash build.sh release", "bash ../outside.sh", "source ~/.nvm/nvm.sh",
		"go test $(go list ./...)", "cp \"$src\" report.txt", "xargs sed -i s/a/b/",
		"python manage.py test", "python -u manage.py test", "node server.js --port 3000",
		"echo \"$(id)\" > report.txt", "for f in regular.txt; do cp \"$f\" copy/; done; echo ok > second-report.txt",
		"git -C sub pull --ff-only && echo benign > notes.txt",
		"cat ~/.ssh/authorized_keys", "grep marker ~/.ssh/authorized_keys",
		"echo " + filepath.Join(home, ".ssh", "authorized_keys") + " > out-*.txt",
		"printf '%s\\n' " + filepath.Join(home, ".ssh", "authorized_keys") + " > out-*.txt",
		"cat " + filepath.Join(home, ".ssh", "authorized_keys") + " > out-*.txt",
		"grep marker " + filepath.Join(home, ".ssh", "authorized_keys") + " > out-*.txt",
		"rg marker " + filepath.Join(home, ".ssh", "authorized_keys") + " > out-*.txt",
		"f=report.txt; echo marker >> \"${f:-alias}\"",
		"out=report-0509.txt; awk \"BEGIN {print \\\"marker\\\" >> \\\"$out\\\"}\"",
	} {
		t.Run(command, func(t *testing.T) {
			for route, denied := range r104ReviewProtectedWrite(t, command, cwd, home) {
				if denied {
					t.Fatalf("route %d claimed authorized-keys persistence for ordinary work", route)
				}
			}
		})
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "out-protected.txt")); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"echo marker >> ~/.ssh/authorized_keys",
		"echo marker >> alias",
		"cp payload alias",
		"f=other; unset f; echo marker >> \"${f:-alias}\"",
		"f=other; unset f; echo marker >> \"${f:-disklink}\"",
		"echo marker > out-*.txt",
	} {
		t.Run("protected/"+command, func(t *testing.T) {
			for route, denied := range r104ReviewProtectedWrite(t, command, cwd, home) {
				if !denied {
					t.Fatalf("route %d missed resolved protected target", route)
				}
			}
		})
	}
}

func TestBalancedActionUncertaintyIsAuditOnly(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	input := actionfacts.Input{Tool: "Bash", Command: "git merge-base HEAD HEAD", CWD: cwd, ActiveHome: home}
	args, err := json.Marshal(map[string]string{"command": input.Command})
	if err != nil {
		t.Fatal(err)
	}
	input.Args = args
	reason := hookpaths.ActionCommandAuditReason(input.Command, cwd, home)
	if reason == "" {
		t.Fatal("fixture must exercise parser uncertainty")
	}
	request := trustedActionRequest{Input: input, Connector: "codex", EnforcementCapable: true,
		ResolvedWriteTargets: map[string]string{hookpaths.UnprovenReasonKey: reason}}
	for _, finding := range dispatchTrustedAction(t.Context(), request) {
		if finding.RuleID == "persistence.ssh_authorized_keys_command" {
			t.Fatalf("parse reason became a persistence finding: %+v", finding)
		}
	}
	ctx := context.WithValue(context.Background(), resolvedWritesContextKey{}, request.ResolvedWriteTargets)
	if got := hookRequestAuditExtra(ctx, connector.HookProfile{})["unresolved_command"]; got != reason {
		t.Fatalf("audit note = %q, want %q", got, reason)
	}
	if got := hookActionCommandAuditExtra(agentHookRequest{ToolName: "Bash", ToolArgs: args, CWD: cwd}, home)["unresolved_command"]; got != reason {
		t.Fatalf("header-free audit note = %q, want %q", got, reason)
	}
}

func TestBalancedActionWindowsOrdinaryCommands(t *testing.T) {
	for _, command := range []string{
		"Write-Output ok; Start-Sleep -Seconds 70",
		"py -m unittest -q",
		"make safe", "npm test", "go test ./...", "cargo test", "pip install -e .", "gradle test",
		"pwsh.exe -NoProfile -File C:/work/build.ps1",
		"pwsh.exe -NoProfile -File C:/work/build.ps1 C:/Users/alice/.ssh/authorized_keys",
		"python C:/work/build.py C:/Users/alice/.ssh/authorized_keys",
		"Write-Output C:/Users/alice/.ssh/authorized_keys; pwsh -File C:/work/build.ps1",
		".\\gradlew.bat test",
		"cmd.exe /c \"echo hello > benign.txt\" && type benign.txt",
	} {
		t.Run(command, func(t *testing.T) {
			input := actionfacts.Input{Tool: "exec_command", Command: command,
				CWD: "C:/work", ActiveHome: "C:/Users/alice", DialectHint: actionfacts.DialectPowerShell}
			if trustedWindowsLocationAuthorizedKeysWrite(input) {
				t.Fatal("ordinary Windows command classified as authorized-keys write")
			}
		})
	}
}

func TestBalancedActionScriptArgumentsAreData(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	for name, body := range map[string]string{
		"build.sh":     "printf ok > report.txt\n",
		"build.py":     "print('ok')\n",
		"write.sh":     "printf marker >> ~/.ssh/authorized_keys\n",
		"write-pos.sh": "printf marker >> \"$1\"\n",
		"write.py":     "open('" + filepath.Join(home, ".ssh", "authorized_keys") + "', 'a').write('marker')\n",
	} {
		if err := os.WriteFile(filepath.Join(cwd, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keyPath := filepath.Join(home, ".ssh", "authorized_keys")
	for _, command := range []string{
		"python build.py " + keyPath,
		"python -u build.py " + keyPath,
		"bash build.sh " + keyPath,
		"./build.sh " + keyPath,
		"source build.sh " + keyPath,
	} {
		t.Run(command, func(t *testing.T) {
			for route, denied := range r104ReviewProtectedWrite(t, command, cwd, home) {
				if denied {
					t.Fatalf("route %d claimed a script's data argument as a write target", route)
				}
			}
		})
	}
	for _, command := range []string{
		"bash write.sh " + keyPath,
		"python write.py " + keyPath,
		"bash write-pos.sh " + keyPath,
		"./write-pos.sh " + keyPath,
	} {
		for route, denied := range r104ReviewProtectedWrite(t, command, cwd, home) {
			if !denied {
				t.Fatalf("route %d missed the script body's protected write: %q", route, command)
			}
		}
	}
}

func TestBalancedActionSelectedMakeRecipes(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(home, "writer.mk"), "write-key:\n\tprintf marker >> alias\n")
	if err := os.Mkdir(filepath.Join(home, "evil"), 0o700); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(home, "evil", "Makefile"), "write-key:\n\tprintf marker >> ../project/alias\n")
	for _, tc := range []struct {
		name, makefile, command string
		blocked                 bool
	}{
		{"ordinary", "safe:\n\tprintf ok > report.txt\n", "make safe", false},
		{"protected copy source is data", "safe:\n\tcp ~/.ssh/authorized_keys report.txt\n", "make safe", false},
		{"unselected protected recipe", "safe:\n\tprintf ok > report.txt\nwrite-key:\n\tprintf marker >> alias\n", "make safe", false},
		{"selected link recipe", "write-key:\n\tprintf marker >> alias\n", "make write-key", true},
		{"external file", "safe:\n\tprintf ok > report.txt\n", "make -f ../writer.mk write-key", true},
		{"directory option", "safe:\n\tprintf ok > report.txt\n", "make -C ../evil write-key", true},
		{"include", "include ../writer.mk\n", "make write-key", true},
		{"MAKEFLAGS", "safe:\n\tprintf ok > report.txt\n", "MAKEFLAGS=-f../writer.mk make write-key", true},
		{"eval", "safe:\n\tprintf ok > report.txt\n", "make --eval='x: ; printf marker >> ~/.ssh/authorized_keys' x", true},
		{"unselected eval", "safe:\n\tprintf ok > report.txt\n", "make --eval='x: ; printf marker >> ~/.ssh/authorized_keys' safe", false},
		{"pattern", "%.key:\n\tprintf marker >> ~/.ssh/authorized_keys\n", "make token.key", true},
		{"pattern prerequisite", "%.key: %.prep\n\t@true\na.prep:\n\t@true\nb.prep:\n\tprintf marker >> ~/.ssh/authorized_keys\n", "make a.key b.key", true},
		{"stdin", "safe:\n\tprintf ok > report.txt\n", "make -f - safe <<'EOF'\nsafe:\n\tprintf marker >> ~/.ssh/authorized_keys\nEOF", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write(filepath.Join(cwd, "Makefile"), tc.makefile)
			for route, got := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				if got != tc.blocked {
					t.Fatalf("route %d: blocked=%v, want %v", route, got, tc.blocked)
				}
			}
		})
	}
}

func TestBalancedActionPrivateKeyReadUsesKeyRule(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte("safe:\n\tcp ~/.ssh/id_ed25519 report.txt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"head -c 0 ~/.ssh/id_ed25519; echo done",
		"cat ~/.ssh/id_ed25519 | head -c 0",
		"cp ~/.ssh/id_ed25519 report.txt",
		"make safe",
	} {
		t.Run(command, func(t *testing.T) {
			input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home,
				DialectHint: actionfacts.DialectPOSIX}
			request := trustedActionRequest{Input: input, Connector: "codex", EnforcementCapable: true}
			keyFinding := false
			for _, finding := range dispatchTrustedAction(t.Context(), request) {
				if finding.RuleID == "persistence.ssh_authorized_keys_command" {
					t.Fatalf("private-key read misclassified as persistence: %+v", finding)
				}
				if finding.RuleID == "PATH-SSH-KEY" || finding.RuleID == "PATH-WIN-SSH-KEY" {
					keyFinding = true
				}
			}
			if !keyFinding {
				t.Fatal("protected private-key read has no key finding")
			}
		})
	}
}
