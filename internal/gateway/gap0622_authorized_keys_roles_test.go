// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestGAP0622AuthorizedKeysOperandRoles(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		block         bool
	}{
		{"diff", `diff ~/.ssh/authorized_keys a.txt`, false},
		{"diff pipeline", `diff ~/.ssh/authorized_keys a.txt | head -5`, false},
		{"diff and count", `diff ~/.ssh/authorized_keys a.txt | head -5; wc -l ~/.ssh/authorized_keys`, false},
		{"copy source", `cp ~/.ssh/authorized_keys /var/tmp/keys-backup`, false},
		{"linked source", `cp disklink report.txt`, false},
		{"known source", `src=~/.ssh/authorized_keys; cp "$src" report.txt`, false},
		{"display name", `echo reminder: check ~/.ssh/authorized_keys`, false},
		{"known display", `f=~/.ssh/authorized_keys; echo "$f"`, false},
		{"read", `cat ~/.ssh/authorized_keys`, false},
		{"read and list", `grep -c ssh-ed25519 ~/.ssh/authorized_keys; ls -l ~/.ssh/authorized_keys`, false},
		{"count", `wc -l ~/.ssh/authorized_keys`, false},
		{"list", `ls -l ~/.ssh/authorized_keys`, false},
		{"ordinary copy", `cp a.txt report.txt`, false},
		{"copy source and report", `cp ~/.ssh/authorized_keys report.txt; echo done > a.txt`, false},
		{"display name and report", `echo ~/.ssh/authorized_keys > report.txt`, false},
		{"quoted source", `cp "$HOME/.ssh/authorized_keys" report.txt`, false},
		{"install destination", `install -m 600 a.txt ~/.ssh/authorized_keys`, true},
		{"append destination", `cat a.txt >> ~/.ssh/authorized_keys`, true},
		{"tee destination", `tee -a ~/.ssh/authorized_keys < a.txt`, true},
		{"copy destination", `cp a.txt ~/.ssh/authorized_keys`, true},
		{"link destination", `ln -sf a.txt ~/.ssh/authorized_keys`, true},
		{"known destination", `f=~/.ssh/authorized_keys; cp a.txt "$f"`, true},
		{"executing assignment", `src=$(echo marker >> ~/.ssh/authorized_keys); cp "$src" report.txt`, true},
		{"linked destination", `cp a.txt disklink`, true},
		{"expanded redirect destination", `echo marker >> {keylink,}`, true},
		{"attached variable destination", `f=a.txt; printf -vf %s disklink; echo marker >> "$f"`, true},
		{"quoted variable destination", `f=a.txt; printf -v"f" %s disklink; echo marker >> "$f"`, true},
		{"descriptor destination", `g=disklink; echo marker >& "$g"`, true},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, row := range rows {
				t.Run(fmt.Sprintf("%s/managed=%t/%s", connector, managed, row.name), func(t *testing.T) {
					got := postDynamicWordParity(t, home, project, connector, managed, row.command, nil)
					if row.block {
						if !strings.HasPrefix(got, `{"action":"block"`) ||
							!strings.Contains(got, "persistence.ssh_authorized_keys_command") {
							t.Fatalf("protected destination = %.300s", got)
						}
					} else if !strings.HasPrefix(got, `{"action":"allow"`) {
						t.Fatalf("ordinary operand = %.300s", got)
					}
				})
			}
		}
	}
}

func TestGAP0622StrictPolicyKeepsPossibleMentions(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for _, command := range []string{
				`diff ~/.ssh/authorized_keys a.txt`,
				`cp ~/.ssh/authorized_keys report.txt`,
				`echo ~/.ssh/authorized_keys`,
				`cp a.txt ~/.ssh/authorized_keys`,
			} {
				t.Run(fmt.Sprintf("%s/managed=%t/%s", connector, managed, command), func(t *testing.T) {
					cfg := &config.Config{}
					cfg.Guardrail.Mode = "action"
					cfg.Guardrail.Connector = connector
					cfg.Guardrail.RulePack = "strict"
					api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
					body := mustJSON(t, map[string]any{"session_id": "gap0622-strict", "hook_event_name": "PreToolUse",
						"tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": command, "description": "d"}})
					req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
					if connector == "codex" {
						setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
					}
					if managed {
						req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
						req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
					}
					recorder := httptest.NewRecorder()
					api.handleAgentHook(connector).ServeHTTP(recorder, req)
					if got := recorder.Body.String(); !strings.HasPrefix(got, `{"action":"block"`) ||
						!strings.Contains(got, "persistence.ssh_authorized_keys_command") {
						t.Fatalf("strict target decision = %.300s", got)
					}
				})
			}
		}
	}
}

func TestGAP0622PatternRedirectTargetRole(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	command := `echo ~/.ssh/authorized_keys > out-*.txt`
	for _, connector := range []string{"claudecode", "codex"} {
		if got := postDynamicWordParity(t, home, project, connector, false, command, nil); !strings.HasPrefix(got, `{"action":"allow"`) {
			t.Fatalf("ordinary pattern = %.300s", got)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "out-protected.txt")); err != nil {
		t.Fatal(err)
	}
	for _, connector := range []string{"claudecode", "codex"} {
		if got := postDynamicWordParity(t, home, project, connector, false, command, nil); !strings.HasPrefix(got, `{"action":"block"`) {
			t.Fatalf("protected pattern = %.300s", got)
		}
	}
}

func TestGAP0622HardlinkDestinationRemainsProtected(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	if err := os.Link(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "hardlink")); err != nil {
		t.Fatal(err)
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			if got := postDynamicWordParity(t, home, project, connector, managed, `cp a.txt hardlink`, nil); !strings.HasPrefix(got, `{"action":"block"`) {
				t.Fatalf("%s managed=%t: protected identity = %.300s", connector, managed, got)
			}
		}
	}
}

func TestGAP0622OrdinaryRoleProofRequiresHomeAndRejectsOtherAccount(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	for _, row := range []struct {
		name, command, activeHome string
	}{
		{"missing home", `echo /home/other/.ssh/authorized_keys > report.txt`, ""},
		{"other account", `cp a.txt /home/other/.ssh/authorized_keys`, home},
	} {
		t.Run(row.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "Bash", Command: row.command,
				CWD: project, ActiveHome: row.activeHome, DialectHint: actionfacts.DialectPOSIX}
			request := trustedActionRequest{Input: input, targetMemo: hookpaths.NewTargetMemo()}
			if trustedOrdinaryKeyOperandRoles(request, input, actionfacts.Analyze(input)) {
				t.Fatal("protected destination received an ordinary role proof")
			}
		})
	}
}
