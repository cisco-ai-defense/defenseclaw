// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows name POSIX homes and shell commands; the tool-call corpus rows
// cover the Windows home spellings.

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

const credentialFileWriteRule = "secrets.credential_file_write"

// credentialFileFixture is one account: home h with the four credential
// files the agent's CLIs read (AWS credentials and config, kubeconfig,
// Docker config), and the project p with look-alike fixtures.
type credentialFileFixture struct{ home, project string }

func newCredentialFileFixture(t *testing.T) credentialFileFixture {
	t.Helper()
	root := t.TempDir()
	f := credentialFileFixture{home: filepath.Join(root, "home"), project: filepath.Join(root, "home", "proj")}
	for _, dir := range []string{".aws", ".kube", ".docker", "proj/.aws", "proj/fixtures/.kube"} {
		if err := os.MkdirAll(filepath.Join(f.home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{".aws/credentials", ".aws/config", ".kube/config", ".docker/config.json",
		"proj/notes.txt", "proj/.aws/credentials", "proj/fixtures/.kube/config"} {
		if err := os.WriteFile(filepath.Join(f.home, file), []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", f.home)
	t.Setenv("USERPROFILE", f.home)
	t.Chdir(f.project)
	return f
}

func (f credentialFileFixture) path(template string) string {
	return strings.NewReplacer("{H}", f.home, "{P}", f.project).Replace(template)
}

// credentialFileHookCall is one PreToolUse-equivalent call of a connector's
// tool with its arguments.
type credentialFileHookCall struct {
	connector, tool string
	args            map[string]any
}

func (c credentialFileHookCall) body(t *testing.T, cwd string) string {
	t.Helper()
	return nativeWriteCall{connector: c.connector, tool: c.tool, args: func(string) map[string]any { return c.args }}.body(t, cwd, fmt.Sprint(c.args))
}

// postCredentialFileHook posts call to the connector's hook in action mode
// on the profile pack, per-user or as a managed gateway that knows the
// caller, and returns the decision (block, alert or allow) and the response.
func postCredentialFileHook(t *testing.T, f credentialFileFixture, profile string, managed bool, call credentialFileHookCall) (string, string) {
	t.Helper()
	installToolCallCorpusProfileConnector(t, call.connector, profile)
	body := call.body(t, f.project)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = call.connector
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+call.connector+"/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	switch call.connector {
	case "copilot":
		req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
		req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector("copilot", "", "preToolUse", []byte(body)))
	default:
		req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector(call.connector, "", "PreToolUse", []byte(body)))
	}
	if call.connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	if managed {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: f.home}))
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(call.connector).ServeHTTP(recorder, req)
	out := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %.400s", recorder.Code, out)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("verdict %q: %v", out, err)
	}
	action, _ := resp["action"].(string)
	return action, out
}

// credentialFileTargets are the four files whose native and shell writes
// the default pack let through with no finding (gas-ux-r1:GAP-0052).
var credentialFileTargets = []string{"{H}/.aws/credentials", "{H}/.aws/config", "{H}/.kube/config", "{H}/.docker/config.json"}

// credentialFileWriteCalls is every file-tool write of every connector
// (Claude Code Write, Edit and MultiEdit, OpenCode write, edit and patch,
// Codex and Copilot apply_patch, Copilot edit and create) and the shell
// redirect, tee and delete forms of Claude Code and Codex Bash, for target.
// Each file tool uses its reviewed argument schema.
func credentialFileWriteCalls(target string) []credentialFileHookCall {
	var calls []credentialFileHookCall
	for _, call := range nativeWriteCalls() {
		calls = append(calls, credentialFileHookCall{call.connector, call.tool, call.args(target)})
	}
	tilde := "~" + strings.TrimPrefix(target, os.Getenv("HOME"))
	for _, connector := range []string{"claudecode", "codex"} {
		for _, command := range []string{
			"printf 'aws_access_key_id = x\\n' > " + target,
			"printf 'x\\n' >> " + tilde,
			"printf 'x\\n' | tee " + target,
			"printf 'x\\n' | tee -a " + tilde,
			"rm " + target,
		} {
			calls = append(calls, credentialFileHookCall{connector, "Bash", map[string]any{"command": command}})
		}
	}
	return calls
}

func credentialFileTopology(managed bool) string {
	if managed {
		return "managed"
	}
	return "per-user"
}

// TestCredentialFileWritesAlertInBalancedAndBlockInStrict: a write, append
// or delete of ~/.aws/credentials, ~/.aws/config, ~/.kube/config or
// ~/.docker/config.json through any connector's file tool or a shell
// redirect, tee or rm is a HIGH secrets.credential_file_write finding. The
// balanced default alerts and allows, so aws configure and kubectl config
// keep working; strict, per-user and managed, blocks (gas-ux-r1:GAP-0052).
func TestCredentialFileWritesAlertInBalancedAndBlockInStrict(t *testing.T) {
	for _, profile := range []string{"default", "strict"} {
		want := map[string]string{"default": "alert", "strict": "block"}[profile]
		for _, managed := range []bool{false, true} {
			for _, target := range credentialFileTargets {
				t.Run(profile+"/"+credentialFileTopology(managed)+"/"+strings.TrimPrefix(target, "{H}/"), func(t *testing.T) {
					f := newCredentialFileFixture(t)
					for i, call := range credentialFileWriteCalls(f.path(target)) {
						got, out := postCredentialFileHook(t, f, profile, managed, call)
						if got != want || !strings.Contains(out, credentialFileWriteRule) {
							t.Errorf("%d %s %s %v: decision %s, want %s by %s: %.600s",
								i, call.connector, call.tool, call.args, got, want, credentialFileWriteRule, out)
						}
					}
				})
			}
		}
	}
}

// TestCredentialFileReadsAndOrdinaryWritesAreUnchanged: the new write rule
// changes neither the verdict of a read of the same files (the read rules
// keep their MEDIUM alert) nor any write of an ordinary or look-alike
// project file, in either pack, per-user or managed.
func TestCredentialFileReadsAndOrdinaryWritesAreUnchanged(t *testing.T) {
	reads := map[string]string{
		"{H}/.aws/credentials":      "PATH-AWS-CREDS",
		"{H}/.kube/config":          "PATH-KUBE",
		"{H}/.docker/config.json":   "PATH-DOCKER",
		"~/.aws/credentials":        "PATH-AWS-CREDS",
		"$HOME/.docker/config.json": "PATH-DOCKER",
	}
	ordinary := []string{"{P}/notes.txt", "{P}/.aws/credentials", "{P}/fixtures/.kube/config", "{P}/docker/config.json"}
	for _, profile := range []string{"default", "strict"} {
		for _, managed := range []bool{false, true} {
			t.Run(profile+"/"+credentialFileTopology(managed), func(t *testing.T) {
				f := newCredentialFileFixture(t)
				for target, rule := range reads {
					for _, call := range []credentialFileHookCall{
						{"claudecode", "Read", map[string]any{"file_path": strings.NewReplacer("~", f.home, "$HOME", f.home).Replace(f.path(target))}},
						{"claudecode", "Bash", map[string]any{"command": "cat " + f.path(target)}},
						{"codex", "Bash", map[string]any{"command": "cat " + f.path(target)}},
					} {
						got, out := postCredentialFileHook(t, f, profile, managed, call)
						if got != "alert" || !strings.Contains(out, rule) || strings.Contains(out, credentialFileWriteRule) {
							t.Errorf("read %s %s %v: decision %s, want the %s alert and no write finding: %.600s",
								call.connector, call.tool, call.args, got, rule, out)
						}
					}
				}
				for _, target := range ordinary {
					for _, call := range credentialFileWriteCalls(f.path(target)) {
						got, out := postCredentialFileHook(t, f, profile, managed, call)
						if got != "allow" || strings.Contains(out, credentialFileWriteRule) {
							t.Errorf("ordinary %s %s %v: decision %s, want allow with no %s: %.600s",
								call.connector, call.tool, call.args, got, credentialFileWriteRule, out)
						}
					}
				}
			})
		}
	}
}
