// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func gap0994And0996Dispatch(t *testing.T, connector, command, cwd, home string, dialect actionfacts.Dialect) bool {
	t.Helper()
	args, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	input := actionfacts.Input{Tool: "Bash", Args: args, Command: command, CWD: cwd,
		ActiveHome: home, DialectHint: dialect}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: string(args), Connector: connector, EnforcementCapable: true,
	})
	return buildVerdict(findings, "tool_call").Action == guardrailActionBlock
}

func TestGAP0994WindowsPrivateKeyDispatch(t *testing.T) {
	for _, connector := range []string{"claudecode", "codex"} {
		installToolCallCorpusProfileConnector(t, connector, "default")
		for _, tc := range []struct {
			name, command string
			block         bool
		}{
			{"head zero bytes", `head -c 0 ~/.ssh/id_ed25519; echo done`, true},
			{"tail through env", `env tail -c 4096 %USERPROFILE%\.ssh\id_rsa`, true},
			{"public key read", `head -c 4096 ~/.ssh/id_ed25519.pub`, false},
			{"authorized keys read", `cat ~/.ssh/authorized_keys`, false},
			{"ssh identity", `ssh -i ~/.ssh/id_ed25519 host.example`, false},
		} {
			t.Run(connector+"/"+tc.name, func(t *testing.T) {
				got := gap0994And0996Dispatch(t, connector, tc.command,
					`C:\Users\Alice\project`, `C:\Users\Alice`, actionfacts.DialectPOSIX)
				if got != tc.block {
					t.Fatalf("blocked=%t, want %t", got, tc.block)
				}
			})
		}
	}
}

func TestGAP0996MakeDispatch(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	sub := filepath.Join(cwd, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		filepath.Join(cwd, "Makefile"):   "write-key:\n\tprintf 'fixture\\n' >> alias\n",
		filepath.Join(home, "writer.mk"): "write-key:\n\tprintf 'fixture\\n' >> $(HOME)/.ssh/authorized_keys\n",
		filepath.Join(home, "common.mk"): "safe:\n\tprintf 'ok\\n' > report.txt\n",
		filepath.Join(sub, "Makefile"):   "all:\n\tprintf 'ok\\n' > build.txt\n",
	} {
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, connector := range []string{"claudecode", "codex"} {
		installToolCallCorpusProfileConnector(t, connector, "default")
		for _, tc := range []struct {
			name, command string
			block         bool
		}{
			{"protected link recipe", `make write-key`, true},
			{"outside protected makefile", `make -f ../writer.mk write-key`, true},
			{"MAKEFILES outside protected makefile", `MAKEFILES=../../writer.mk make -C sub write-key`, true},
			{"MAKEFILES target not built", `MAKEFILES=../../writer.mk make -C sub all`, false},
			{"outside ordinary makefile", `make -f ../common.mk safe`, false},
			{"ordinary subdirectory build", `make -C sub all`, false},
			{"parallel ordinary build", `MAKEFLAGS=-j8 make -C sub all`, false},
		} {
			t.Run(connector+"/"+tc.name, func(t *testing.T) {
				got := gap0994And0996Dispatch(t, connector, tc.command, cwd, home, actionfacts.DialectPOSIX)
				if got != tc.block {
					t.Fatalf("blocked=%t, want %t", got, tc.block)
				}
			})
		}
	}
}

func TestGAP0996MakeRefixDispatch(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	makefile := "TARGET := ~/.ssh/authorized_keys\n%.key:\n\tprintf ok >> ~/.ssh/authorized_keys\nsafe:\n\t@true\n"
	if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte(makefile), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, connector := range []string{"claudecode", "codex"} {
		installToolCallCorpusProfileConnector(t, connector, "default")
		for _, tc := range []struct {
			name, command string
			block         bool
		}{
			{"inert makefile text", "make safe", false},
			{"matching pattern", "make token.key", true},
			{"visible stdin", "make -f - safe <<'EOF'\nsafe:\n\t@true\nEOF", false},
			{"hidden stdin", "make -f - safe", true},
		} {
			t.Run(connector+"/"+tc.name, func(t *testing.T) {
				got := gap0994And0996Dispatch(t, connector, tc.command, cwd, home, actionfacts.DialectPOSIX)
				if got != tc.block {
					t.Fatalf("blocked=%t, want %t", got, tc.block)
				}
			})
		}
	}
}
