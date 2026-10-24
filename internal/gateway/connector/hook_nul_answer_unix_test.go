// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// nulAnswers are gateway answers with a NUL byte. Bash command substitution
// drops NUL bytes, so before GAP-1008 "al<NUL>low" read as "allow" in every
// shell hook. A running gateway's unusable answer is never an outage: each
// one blocks in every tier, here the outage-open default tier.
var nulAnswers = []struct{ name, body string }{
	{"NUL inside the action", "{\"action\":\"al\x00low\",\"raw_action\":\"allow\",\"severity\":\"NONE\",\"hook_output\":{}}"},
	{"NUL after the answer", "{\"action\":\"allow\",\"raw_action\":\"allow\",\"severity\":\"NONE\",\"hook_output\":{}}\x00"},
	{"NUL between fields", "{\"action\":\"allow\",\x00\"raw_action\":\"allow\",\"severity\":\"NONE\",\"hook_output\":{}}"},
}

const nulControlAnswer = `{"action":"allow","raw_action":"allow","severity":"NONE","hook_output":{}}`

// Per-user shell hooks post through the native helper (hook-post
// --curl-output), whose output the hook reads with command substitution.
func TestPerUserShellHooksRefuseANulInTheAnswer(t *testing.T) {
	cases := append([]struct{ name, body string }{{"control: clean allow", nulControlAnswer}}, nulAnswers...)
	for _, conn := range hookArgvShellConnectors {
		for _, tc := range cases {
			// Sequential: each call runs the real native helper within the
			// hook's answer budget, which a loaded runner can outlast.
			t.Run(conn.Name()+"/"+tc.name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(tc.body))
				}))
				defer server.Close()
				invoke := hookArgvConnectorCase(t, conn.Name())
				home := t.TempDir()
				installNativeGatewayForHookTest(t, home)
				hookDir := filepath.Join(home, "hooks")
				opts := SetupOpts{DataDir: home, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "scoped-test-token", HookFailMode: "open"}
				if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, invoke.script)}, invoke.args...)...)
				cmd.Stdin = strings.NewReader(invoke.stdin)
				cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home)
				out, err := cmd.CombinedOutput()
				blocked := hookCallBlocked(err, string(out))
				if want := tc.body != nulControlAnswer; blocked != want {
					t.Fatalf("blocked=%v, want %v (exit %v):\n%s", blocked, want, err, out)
				}
			})
		}
	}
}

// Managed hooks post with curl (here the shared inspect hooks over TCP).
func TestManagedShellHooksRefuseANulInTheAnswer(t *testing.T) {
	cases := append([]struct{ name, body string }{{"control: clean allow", `{"action":"allow"}`}}, nulAnswers...)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			home := t.TempDir()
			hooks := filepath.Join(home, "hooks")
			if err := writeHookScriptsCommonWithTransport(hooks, strings.TrimPrefix(server.URL, "http://"), "test-token", "open", HookFailModeSourceConfig, nil, true, "codex", true, "", "", false, false); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"inspect-request.sh", "inspect-tool.sh", "inspect-response.sh", "inspect-tool-response.sh"} {
				t.Run(name, func(t *testing.T) {
					cmd := exec.Command("bash", filepath.Join(hooks, name))
					cmd.Stdin = strings.NewReader(`{"tool":"Bash","content":"marker"}`)
					cmd.Env = append(sanitizedTestEnv(), "HOME="+home)
					out, err := cmd.CombinedOutput()
					blocked := hookCallBlocked(err, string(out))
					if want := tc.name != "control: clean allow"; blocked != want {
						t.Fatalf("blocked=%v, want %v (exit %v):\n%s", blocked, want, err, out)
					}
				})
			}
		})
	}
}

// OpenShell sandbox hooks post with their own curl call (_sandbox.sh).
func TestSandboxHooksRefuseANulInTheAnswer(t *testing.T) {
	code, control, _ := strings.Cut(allowResponse, "|")
	encode := func(body string) string {
		return "b64:" + base64.StdEncoding.EncodeToString([]byte(body+"\n"+code))
	}
	for _, tc := range sandboxHookCases() {
		files := sandboxArtifactsFor(t, tc.provider, tc.version).Files
		h := newSandboxHookHarnessFiles(t, files, SandboxHookPATH)
		for _, name := range []string{".token", ".hook-" + tc.connector + ".token"} {
			if err := os.WriteFile(filepath.Join(h.path(SandboxHookDir), name), []byte("DEFENSECLAW_GATEWAY_TOKEN=\"host\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		script := SandboxHookDir + "/" + tc.script
		env := map[string]string{SandboxTokenEnv: "tok"}
		t.Run(tc.script+"/control: clean allow", func(t *testing.T) {
			if run := h.run(t, script, tc.args, tc.stdin, env, []string{encode(control)}); tc.blocked(run) {
				t.Fatalf("clean allow blocked: exit %d stdout=%q stderr=%s", run.exitCode, run.stdout, run.stderr)
			}
		})
		for _, answer := range []struct{ name, body string }{
			{"NUL inside the action", strings.Replace(control, `"allow"`, "\"al\x00low\"", 1)},
			{"NUL after the answer", control + "\x00"},
		} {
			t.Run(tc.script+"/"+answer.name, func(t *testing.T) {
				if !strings.Contains(answer.body, "\x00") {
					t.Fatal("test answer has no NUL")
				}
				if run := h.run(t, script, tc.args, tc.stdin, env, []string{encode(answer.body)}); !tc.blocked(run) {
					t.Fatalf("not blocked: exit %d stdout=%q stderr=%s", run.exitCode, run.stdout, run.stderr)
				}
			})
		}
	}
}
