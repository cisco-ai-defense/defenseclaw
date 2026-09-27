// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// sandboxCurlStub stands in for curl on the baked hook PATH. It records the
// argv, environment and stdin of every call and replays one scripted
// response per call:
// "exit:<code>" makes curl fail, "<status>|<body>" prints body and status the
// way `curl -w '\n%{http_code}'` does.
const sandboxCurlStub = `#!/bin/bash
dir="$(cd "$(dirname "$0")" && pwd)"
n=$(( $(cat "$dir/count" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$dir/count"
printf '%s\n' "$@" > "$dir/args.$n"
/usr/bin/env > "$dir/env.$n"
cat > "$dir/body.$n"
line="$(sed -n "${n}p" "$dir/responses")"
case "$line" in
  exit:*) exit "${line#exit:}" ;;
  '') exit 7 ;;
  *) printf '%s\n%s' "${line#*|}" "${line%%|*}" ;;
esac
`

type sandboxCurlCall struct {
	argv    []string
	headers map[string]string
	env     map[string]string
	body    string
}

func (c sandboxCurlCall) url() string {
	for _, arg := range c.argv {
		if strings.HasPrefix(arg, "http://") {
			return arg
		}
	}
	return ""
}

func (c sandboxCurlCall) flagValue(flag string) string {
	for i, arg := range c.argv {
		if arg == flag && i+1 < len(c.argv) {
			return c.argv[i+1]
		}
	}
	return ""
}

type sandboxHookHarness struct {
	root    string
	stubDir string
	// bakedPATH replaces SandboxHookPATH in the rendered helpers.
	bakedPATH string
}

// newSandboxHookHarness materializes a rendered artifact set under a scratch
// root and points the baked PATH at the curl stub (followed by the real
// system directories for jq, sed, od, ...).
func newSandboxHookHarness(t *testing.T, provider SandboxArtifactProvider, version string) *sandboxHookHarness {
	t.Helper()
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required")
	}
	artifacts, err := provider.SandboxArtifacts(SandboxRenderTarget{IngressPort: 18971, AgentVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	h := &sandboxHookHarness{root: t.TempDir(), stubDir: t.TempDir()}
	stubPath := h.stubDir + ":/usr/bin:/bin:/usr/sbin:/sbin"
	h.bakedPATH = stubPath
	for _, file := range artifacts.Files {
		data := file.Data
		switch filepath.Base(file.Path) {
		case "_hardening.sh":
			data = bytes.Replace(data, []byte(`DEFENSECLAW_BAKED_HOOK_PATH="`+SandboxHookPATH+`"`),
				[]byte(`DEFENSECLAW_BAKED_HOOK_PATH="`+stubPath+`"`), 1)
		case codexSandboxNotifyScript:
			data = bytes.Replace(data, []byte("PATH="+SandboxHookPATH+"\n"), []byte("PATH="+stubPath+"\n"), 1)
		}
		dest := filepath.Join(h.root, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, data, file.Mode|0o200); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(h.stubDir, "curl"), []byte(sandboxCurlStub), 0o755); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *sandboxHookHarness) path(inImage string) string {
	return filepath.Join(h.root, filepath.FromSlash(inImage))
}

type sandboxHookRun struct {
	exitCode int
	stdout   string
	stderr   string
	calls    []sandboxCurlCall
}

func (h *sandboxHookHarness) run(t *testing.T, script string, args []string, stdin string, env map[string]string, responses []string) sandboxHookRun {
	t.Helper()
	for _, name := range []string{"count", "responses"} {
		_ = os.Remove(filepath.Join(h.stubDir, name))
	}
	for _, pattern := range []string{"args.*", "body.*", "env.*"} {
		stale, _ := filepath.Glob(filepath.Join(h.stubDir, pattern))
		for _, file := range stale {
			_ = os.Remove(file)
		}
	}
	if err := os.WriteFile(filepath.Join(h.stubDir, "responses"), []byte(strings.Join(responses, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(h.path(script), args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir()}
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	result := sandboxHookRun{stdout: stdout.String(), stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		result.exitCode = exitErr.ExitCode()
	default:
		t.Fatalf("run %s: %v", script, err)
	}
	count, _ := os.ReadFile(filepath.Join(h.stubDir, "count"))
	n, _ := strconv.Atoi(strings.TrimSpace(string(count)))
	for i := 1; i <= n; i++ {
		rawArgs, err := os.ReadFile(filepath.Join(h.stubDir, "args."+strconv.Itoa(i)))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := os.ReadFile(filepath.Join(h.stubDir, "body."+strconv.Itoa(i)))
		call := sandboxCurlCall{
			argv:    strings.Split(strings.TrimSuffix(string(rawArgs), "\n"), "\n"),
			headers: map[string]string{},
			env:     map[string]string{},
			body:    string(body),
		}
		rawEnv, _ := os.ReadFile(filepath.Join(h.stubDir, "env."+strconv.Itoa(i)))
		for _, line := range strings.Split(strings.TrimSuffix(string(rawEnv), "\n"), "\n") {
			if name, value, ok := strings.Cut(line, "="); ok {
				call.env[name] = value
			}
		}
		for j, arg := range call.argv {
			if arg == "-H" && j+1 < len(call.argv) {
				name, value, _ := strings.Cut(call.argv[j+1], ": ")
				call.headers[strings.ToLower(name)] = value
			}
		}
		result.calls = append(result.calls, call)
	}
	return result
}

var sandboxIdempotencyKeyRE = regexp.MustCompile(`^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})$`)

const (
	claudePreToolUse = `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"ls"}}`
	codexPreToolUse  = `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"ls"}}`
	allowResponse    = `200|{"action":"allow"}`
)

func TestSandboxClaudeHookRetriesOnceWithIdempotencyKey(t *testing.T) {
	h := newSandboxHookHarness(t, &ClaudeCodeConnector{}, "2.1.156")
	hook := SandboxHookDir + "/claude-code-hook.sh"
	env := map[string]string{SandboxTokenEnv: "openshell:resolve:env:v1_DEFENSECLAW_SANDBOX_TOKEN"}

	for name, first := range map[string]string{"empty-reply": "exit:52", "relay-503": `503|{}`, "timeout": "exit:28"} {
		t.Run(name, func(t *testing.T) {
			run := h.run(t, hook, nil, claudePreToolUse, env, []string{first, allowResponse})
			if run.exitCode != 0 {
				t.Fatalf("exit %d, stderr=%s", run.exitCode, run.stderr)
			}
			if len(run.calls) != 2 {
				t.Fatalf("calls = %d, want 2", len(run.calls))
			}
			key := run.calls[0].headers["x-defenseclaw-hook-idempotency-key"]
			if !sandboxIdempotencyKeyRE.MatchString(key) {
				t.Fatalf("idempotency key %q is not a random 128-bit key", key)
			}
			for i, call := range run.calls {
				if call.headers["x-defenseclaw-hook-idempotency-key"] != key {
					t.Fatalf("call %d changed the idempotency key", i)
				}
				if call.url() != "http://host.openshell.internal:18971/api/v1/claude-code/hook" {
					t.Fatalf("call %d url = %q", i, call.url())
				}
				if call.headers["authorization"] != "Bearer "+env[SandboxTokenEnv] {
					t.Fatalf("call %d authorization = %q", i, call.headers["authorization"])
				}
				if call.body != claudePreToolUse {
					t.Fatalf("call %d body = %q", i, call.body)
				}
				if call.argv[0] != "-q" || call.flagValue("--noproxy") != "*" {
					t.Fatalf("call %d must ignore curlrc and proxies: %v", i, call.argv)
				}
			}
			if run.calls[0].flagValue("--max-time") != strconv.Itoa(sandboxHookMaxTimeSeconds) ||
				run.calls[1].flagValue("--max-time") != strconv.Itoa(sandboxHookRetryMaxTimeSeconds) {
				t.Fatalf("attempt budgets = %s/%s", run.calls[0].flagValue("--max-time"), run.calls[1].flagValue("--max-time"))
			}
		})
	}
}

func TestSandboxClaudeHookFailsClosedWithoutEnvOverrides(t *testing.T) {
	h := newSandboxHookHarness(t, &ClaudeCodeConnector{}, "2.1.156")
	hook := SandboxHookDir + "/claude-code-hook.sh"
	token := "openshell:resolve:env:v2_DEFENSECLAW_SANDBOX_TOKEN"
	// A planted host token file and every host override must be ignored.
	if err := os.WriteFile(filepath.Join(h.path(SandboxHookDir), ".token"), []byte("DEFENSECLAW_GATEWAY_TOKEN=\"host\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hostOverrides := map[string]string{
		"DEFENSECLAW_FAIL_MODE":           "open",
		"DEFENSECLAW_STRICT_AVAILABILITY": "0",
		"DEFENSECLAW_GATEWAY_TOKEN":       "host-master",
		"DEFENSECLAW_HOME":                "/nonexistent",
		"DEFENSECLAW_CONNECTOR":           "cursor",
	}
	withToken := map[string]string{SandboxTokenEnv: token}
	for key, value := range hostOverrides {
		withToken[key] = value
	}

	t.Run("ingress-down", func(t *testing.T) {
		run := h.run(t, hook, nil, claudePreToolUse, withToken, []string{"exit:7", "exit:7"})
		if run.exitCode != 2 {
			t.Fatalf("exit %d, want 2 (fail closed); stderr=%s", run.exitCode, run.stderr)
		}
		if len(run.calls) != 2 {
			t.Fatalf("calls = %d, want one attempt plus one retry", len(run.calls))
		}
	})
	t.Run("missing-token", func(t *testing.T) {
		run := h.run(t, hook, nil, claudePreToolUse, hostOverrides, []string{allowResponse})
		if run.exitCode != 2 || len(run.calls) != 0 {
			t.Fatalf("exit %d calls %d, want 2 and no request; stderr=%s", run.exitCode, len(run.calls), run.stderr)
		}
		if !strings.Contains(run.stderr, "DEFENSECLAW_SANDBOX_TOKEN") {
			t.Fatalf("stderr does not explain the missing token: %s", run.stderr)
		}
	})
	t.Run("unauthorized-not-retried", func(t *testing.T) {
		run := h.run(t, hook, nil, claudePreToolUse, withToken, []string{`401|{"error":"bad token"}`, allowResponse})
		if run.exitCode != 2 || len(run.calls) != 1 {
			t.Fatalf("exit %d calls %d, want 2 and a single request", run.exitCode, len(run.calls))
		}
	})
	t.Run("token-never-from-host", func(t *testing.T) {
		run := h.run(t, hook, nil, claudePreToolUse, withToken, []string{allowResponse})
		if run.exitCode != 0 || len(run.calls) != 1 {
			t.Fatalf("exit %d calls %d; stderr=%s", run.exitCode, len(run.calls), run.stderr)
		}
		if got := run.calls[0].headers["authorization"]; got != "Bearer "+token {
			t.Fatalf("authorization = %q, want the sandbox token only", got)
		}
	})
}

func TestSandboxClaudeHookRendersBlockVerdict(t *testing.T) {
	h := newSandboxHookHarness(t, &ClaudeCodeConnector{}, "2.1.156")
	output := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"nope"}}`
	run := h.run(t, SandboxHookDir+"/claude-code-hook.sh", nil, claudePreToolUse,
		map[string]string{SandboxTokenEnv: "tok"},
		[]string{`200|{"action":"block","reason":"nope","claude_code_output":` + output + `}`})
	if run.exitCode != 0 {
		t.Fatalf("exit %d; stderr=%s", run.exitCode, run.stderr)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(run.stdout)), &decoded); err != nil {
		t.Fatalf("stdout is not the structured verdict: %q", run.stdout)
	}
	if decoded["hookSpecificOutput"].(map[string]interface{})["permissionDecision"] != "deny" {
		t.Fatalf("verdict = %v", decoded)
	}
}

func TestSandboxHooksIgnoreShellInjectionThroughEnvironment(t *testing.T) {
	h := newSandboxHookHarness(t, &ClaudeCodeConnector{}, "2.1.156")
	marker := filepath.Join(t.TempDir(), "pwned")
	evil := filepath.Join(t.TempDir(), "evil.sh")
	if err := os.WriteFile(evil, []byte("touch "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		SandboxTokenEnv:    "tok",
		"BASH_ENV":         evil,
		"ENV":              evil,
		"BASH_FUNC_curl%%": "() { touch " + marker + "; printf '{\"action\":\"allow\"}\\n200'; }",
		"http_proxy":       "http://127.0.0.1:9",
		"HTTPS_PROXY":      "http://127.0.0.1:9",
	}
	run := h.run(t, SandboxHookDir+"/claude-code-hook.sh", nil, claudePreToolUse, env, []string{allowResponse})
	if run.exitCode != 0 || len(run.calls) != 1 {
		t.Fatalf("exit %d calls %d; stderr=%s", run.exitCode, len(run.calls), run.stderr)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("environment-injected shell code ran inside the sandbox hook")
	}
}

// writeMarkerTool writes an executable that only records that it ran.
func writeMarkerTool(t *testing.T, dir, name, markerDir string) {
	t.Helper()
	script := "#!/bin/sh\n: > '" + filepath.Join(markerDir, name) + "'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// sandboxHookChildEnv is every variable a sandbox hook may hand to its child
// processes: the inputs it reads, what the hook and _hardening.sh set, and
// what the recording stub's own bash adds (PWD, SHLVL, OLDPWD, _).
var sandboxHookChildEnv = map[string]bool{
	"PATH": true, "HOME": true, "PWD": true, "OLDPWD": true, "SHLVL": true, "_": true,
	"LC_ALL": true, "LANG": true, "GIT_CONFIG_NOSYSTEM": true, "GIT_CONFIG_GLOBAL": true,
	"DEFENSECLAW_HOME": true, "DEFENSECLAW_MANAGED_HOOK": true,
	"DEFENSECLAW_HOOK_CONNECTOR": true, "DEFENSECLAW_HOOK_NAME": true,
	SandboxTokenEnv: true, "DEFENSECLAW_TRACEPARENT": true, "CLAUDE_TOOL_NAME": true,
}

// sandboxEnvAttack is the scratch state of one polluted-environment run.
type sandboxEnvAttack struct {
	h *sandboxHookHarness
	// markers collects one file per planted program that ran.
	markers string
	// planted holds marker versions of the tools the hooks run.
	planted string
	// pyDir holds a sitecustomize.py that leaves a marker.
	pyDir string
	// victim stands for a workload directory the hook must never adopt as
	// its HOME (and so never remove); keep is a file inside it.
	victim, keep string
	// tmpdir is an inherited TMPDIR the hook must ignore.
	tmpdir string
}

func newSandboxEnvAttack(t *testing.T, h *sandboxHookHarness) *sandboxEnvAttack {
	t.Helper()
	a := &sandboxEnvAttack{h: h, markers: t.TempDir(), planted: t.TempDir(), pyDir: t.TempDir(), victim: t.TempDir(), tmpdir: t.TempDir()}
	for _, tool := range []string{"mktemp", "curl", "jq", "head", "sed", "tr", "od", "id", "uname", "cat", "python3"} {
		writeMarkerTool(t, a.planted, tool, a.markers)
	}
	site := "open(" + strconv.Quote(filepath.Join(a.markers, "sitecustomize")) + ", 'w').close()\n"
	if err := os.WriteFile(filepath.Join(a.pyDir, "sitecustomize.py"), []byte(site), 0o644); err != nil {
		t.Fatal(err)
	}
	a.keep = filepath.Join(a.victim, "keep")
	if err := os.WriteFile(a.keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return a
}

// TestSandboxHooksScrubInheritedEnvironment runs every sandbox hook with an
// environment the workload controls (Claude Code applies settings env blocks
// to hook processes): a PATH entry ahead of the baked one, a PYTHONPATH
// sitecustomize, bash knobs that would abort or reroute the hook, the hook's
// own variable names, and assorted interpreter inputs. Each hook must still
// forward the untouched payload to the baked ingress, run none of the
// planted code, and hand its children only the variables it reads.
func TestSandboxHooksScrubInheritedEnvironment(t *testing.T) {
	const traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	hooks := []struct {
		name     string
		provider SandboxArtifactProvider
		version  string
		script   string
		args     []string
		stdin    string
		route    string
		traced   bool
	}{
		{"claude-code-hook", &ClaudeCodeConnector{}, "2.1.156", "claude-code-hook.sh", nil, claudePreToolUse, "/api/v1/claude-code/hook", true},
		{"codex-hook", &CodexConnector{}, "0.146.0", "codex-hook.sh",
			[]string{"--event", "PreToolUse", "--hook-contract", "codex-hooks-v4"}, codexPreToolUse, "/api/v1/codex/hook", true},
		{"inspect-tool", &ClaudeCodeConnector{}, "2.1.156", "inspect-tool.sh", nil, `{"command":"ls"}`, "/api/v1/inspect/tool", false},
	}
	vectors := map[string]func(t *testing.T, a *sandboxEnvAttack) map[string]string{
		"planted-path": func(t *testing.T, a *sandboxEnvAttack) map[string]string {
			return map[string]string{"PATH": a.planted + ":/usr/bin:/bin"}
		},
		"pythonpath-sitecustomize": func(t *testing.T, a *sandboxEnvAttack) map[string]string {
			if _, err := exec.LookPath("python3"); err != nil {
				t.Skip("python3 is required")
			}
			return map[string]string{"PYTHONPATH": a.pyDir, "PYTHONSTARTUP": filepath.Join(a.pyDir, "sitecustomize.py")}
		},
		"python3-never-started": func(t *testing.T, a *sandboxEnvAttack) map[string]string {
			// python3 on the baked PATH itself.
			writeMarkerTool(t, a.h.stubDir, "python3", a.markers)
			return nil
		},
		"bash-knobs": func(t *testing.T, a *sandboxEnvAttack) map[string]string {
			return map[string]string{"FUNCNEST": "1", "TMOUT": "1", "POSIXLY_CORRECT": "1", "EXECIGNORE": "*/jq", "BASH_COMPAT": "31"}
		},
		"hook-variables": func(t *testing.T, a *sandboxEnvAttack) map[string]string {
			return map[string]string{
				"HOOK_DIR":                    "/nonexistent",
				"DEFENSECLAW_BAKED_HOOK_PATH": a.planted,
				"DEFENSECLAW_HOOK_HOME":       a.victim,
				"DEFENSECLAW_HOOK_MAX_BODY":   "4",
				"DEFENSECLAW_FAIL_MODE":       "open",
				"DC_SANDBOX_INGRESS":          "attacker.invalid:1",
				"FAIL_MODE":                   "open",
				"TMPDIR":                      a.tmpdir,
			}
		},
		"interpreter-inputs": func(t *testing.T, a *sandboxEnvAttack) map[string]string {
			return map[string]string{"PERL5LIB": a.pyDir, "RUBYOPT": "-W0", "NODE_OPTIONS": "--no-warnings", "GCONV_PATH": a.pyDir, "DC_TEST_CANARY": "1"}
		},
	}
	vectors["all-at-once"] = func(t *testing.T, a *sandboxEnvAttack) map[string]string {
		env := map[string]string{}
		for name, vector := range vectors {
			if name == "all-at-once" || name == "pythonpath-sitecustomize" {
				continue
			}
			for key, value := range vector(t, a) {
				env[key] = value
			}
		}
		env["PYTHONPATH"] = a.pyDir
		return env
	}

	for _, hook := range hooks {
		for name, vector := range vectors {
			t.Run(hook.name+"/"+name, func(t *testing.T) {
				h := newSandboxHookHarness(t, hook.provider, hook.version)
				a := newSandboxEnvAttack(t, h)
				env := map[string]string{
					SandboxTokenEnv:           "tok",
					"DEFENSECLAW_TRACEPARENT": traceparent,
					"CLAUDE_TOOL_NAME":        "Bash",
				}
				for key, value := range vector(t, a) {
					env[key] = value
				}

				run := h.run(t, SandboxHookDir+"/"+hook.script, hook.args, hook.stdin, env, []string{allowResponse})
				if run.exitCode != 0 || len(run.calls) != 1 {
					t.Fatalf("exit %d calls %d; stderr=%s", run.exitCode, len(run.calls), run.stderr)
				}
				call := run.calls[0]
				if want := "http://host.openshell.internal:18971" + hook.route; call.url() != want {
					t.Fatalf("url = %q, want %q", call.url(), want)
				}
				forwarded := call.body
				if hook.script == "inspect-tool.sh" {
					var body map[string]string
					if err := json.Unmarshal([]byte(call.body), &body); err != nil {
						t.Fatalf("inspect body %q: %v", call.body, err)
					}
					forwarded = body["args"]
				}
				if forwarded != hook.stdin {
					t.Fatalf("forwarded payload = %q, want the hook input %q", forwarded, hook.stdin)
				}
				if hook.traced && call.headers["traceparent"] != traceparent {
					t.Fatalf("allowlisted trace context lost: headers %v", call.headers)
				}
				if ran, _ := os.ReadDir(a.markers); len(ran) != 0 {
					var names []string
					for _, entry := range ran {
						names = append(names, entry.Name())
					}
					t.Fatalf("planted code ran inside the sandbox hook: %v", names)
				}
				if _, err := os.Stat(a.keep); err != nil {
					t.Fatalf("an inherited DEFENSECLAW_HOOK_HOME was adopted and removed: %v", err)
				}
				if call.env["PATH"] != h.bakedPATH {
					t.Fatalf("child PATH = %q, want the baked %q", call.env["PATH"], h.bakedPATH)
				}
				if home := call.env["HOME"]; home == "" || strings.HasPrefix(home, a.victim) || strings.HasPrefix(home, a.tmpdir) {
					t.Fatalf("child HOME = %q must be a fresh mktemp directory outside the inherited TMPDIR", home)
				}
				for key, value := range call.env {
					if !sandboxHookChildEnv[key] {
						t.Errorf("child process inherited %s=%q", key, value)
					}
				}
			})
		}
	}
}

// TestSandboxHookPayloadCapWithoutPython checks that the head(1) tier the
// sandbox hooks use in place of python3 still refuses an oversized payload,
// and that an inherited cap is ignored in both directions.
func TestSandboxHookPayloadCapWithoutPython(t *testing.T) {
	h := newSandboxHookHarness(t, &ClaudeCodeConnector{}, "2.1.156")
	markers := t.TempDir()
	writeMarkerTool(t, h.stubDir, "python3", markers)
	hook := SandboxHookDir + "/claude-code-hook.sh"
	oversized := `{"hook_event_name":"PreToolUse","tool_input":{"command":"` + strings.Repeat("a", 1<<20) + `"}}`
	run := h.run(t, hook, nil, oversized, map[string]string{SandboxTokenEnv: "tok", "DEFENSECLAW_HOOK_MAX_BODY": "99999999"}, []string{allowResponse})
	if run.exitCode != 2 || len(run.calls) != 0 {
		t.Fatalf("oversized payload: exit %d calls %d, want 2 and no request; stderr=%s", run.exitCode, len(run.calls), run.stderr)
	}
	run = h.run(t, hook, nil, claudePreToolUse, map[string]string{SandboxTokenEnv: "tok", "DEFENSECLAW_HOOK_MAX_BODY": "4"}, []string{allowResponse})
	if run.exitCode != 0 || len(run.calls) != 1 || run.calls[0].body != claudePreToolUse {
		t.Fatalf("normal payload: exit %d calls %d; stderr=%s", run.exitCode, len(run.calls), run.stderr)
	}
	if ran, _ := os.ReadDir(markers); len(ran) != 0 {
		t.Fatal("a sandbox hook started python3")
	}
}

func TestSandboxCodexHookBindsEventAndContract(t *testing.T) {
	h := newSandboxHookHarness(t, &CodexConnector{}, "0.146.0")
	hook := SandboxHookDir + "/codex-hook.sh"
	env := map[string]string{SandboxTokenEnv: "tok", "DEFENSECLAW_FAIL_MODE": "open"}

	run := h.run(t, hook, []string{"--event", "PreToolUse", "--hook-contract", "codex-hooks-v4"}, codexPreToolUse, env, []string{"exit:56", allowResponse})
	if run.exitCode != 0 || len(run.calls) != 2 {
		t.Fatalf("exit %d calls %d; stderr=%s", run.exitCode, len(run.calls), run.stderr)
	}
	call := run.calls[1]
	if call.url() != "http://host.openshell.internal:18971/api/v1/codex/hook" ||
		call.headers["x-defenseclaw-hook-event"] != "PreToolUse" ||
		call.headers["x-defenseclaw-hook-contract"] != "codex-hooks-v4" ||
		call.headers["authorization"] != "Bearer tok" {
		t.Fatalf("unexpected request: %v", call.argv)
	}

	sessionEnd := `{"hook_event_name":"SessionEnd","session_id":"s1"}`
	run = h.run(t, hook, []string{"--event", "SessionEnd", "--hook-contract", "codex-hooks-v4"}, sessionEnd, env, []string{allowResponse})
	if run.exitCode != 0 || len(run.calls) != 1 {
		t.Fatalf("SessionEnd exit %d calls %d; stderr=%s", run.exitCode, len(run.calls), run.stderr)
	}
	if got := run.calls[0].flagValue("--max-time"); got != strconv.Itoa(sandboxHookSessionEndMaxTimeSeconds) {
		t.Fatalf("SessionEnd --max-time = %s", got)
	}

	// The registered binding is still enforced and fails closed despite the
	// open override.
	run = h.run(t, hook, []string{"--event", "Stop", "--hook-contract", "codex-hooks-v4"}, codexPreToolUse, env, []string{allowResponse})
	if run.exitCode != 2 || len(run.calls) != 0 {
		t.Fatalf("mismatched event exit %d calls %d", run.exitCode, len(run.calls))
	}
	run = h.run(t, hook, []string{"--event", "PreToolUse", "--hook-contract", "codex-hooks-v4"}, codexPreToolUse, env, []string{"exit:7", "exit:7"})
	if run.exitCode != 2 {
		t.Fatalf("ingress down exit %d, want 2", run.exitCode)
	}
}

func TestSandboxInspectHookBakesConnector(t *testing.T) {
	h := newSandboxHookHarness(t, &ClaudeCodeConnector{}, "2.1.156")
	env := map[string]string{SandboxTokenEnv: "tok", "CLAUDE_TOOL_NAME": "Bash", "DEFENSECLAW_CONNECTOR": "cursor"}
	run := h.run(t, SandboxHookDir+"/inspect-tool.sh", nil, `{"command":"ls"}`, env, []string{allowResponse})
	if run.exitCode != 0 || len(run.calls) != 1 {
		t.Fatalf("exit %d calls %d; stderr=%s", run.exitCode, len(run.calls), run.stderr)
	}
	call := run.calls[0]
	if call.url() != "http://host.openshell.internal:18971/api/v1/inspect/tool" || call.headers["x-defenseclaw-connector"] != "claudecode" {
		t.Fatalf("unexpected request: %v", call.argv)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(call.body), &body); err != nil || body["tool"] != "Bash" {
		t.Fatalf("body = %q", call.body)
	}
	run = h.run(t, SandboxHookDir+"/inspect-tool.sh", nil, `{}`, map[string]string{"DEFENSECLAW_GATEWAY_TOKEN": "host"}, []string{allowResponse})
	if run.exitCode != 2 || len(run.calls) != 0 {
		t.Fatalf("inspect without sandbox token exit %d calls %d", run.exitCode, len(run.calls))
	}
}

func TestSandboxCodexNotifyBridge(t *testing.T) {
	h := newSandboxHookHarness(t, &CodexConnector{}, "0.146.0")
	notify := SandboxHookDir + "/" + codexSandboxNotifyScript
	payload := `{"type":"agent-turn-complete","turn-id":"t1"}`
	run := h.run(t, notify, []string{payload}, "", map[string]string{SandboxTokenEnv: "tok"}, []string{`200|{}`})
	if run.exitCode != 0 || len(run.calls) != 1 {
		t.Fatalf("exit %d calls %d", run.exitCode, len(run.calls))
	}
	if run.calls[0].url() != "http://host.openshell.internal:18971/api/v1/codex/notify" ||
		run.calls[0].headers["authorization"] != "Bearer tok" || run.calls[0].body != payload {
		t.Fatalf("unexpected notify request: %v body=%q", run.calls[0].argv, run.calls[0].body)
	}
	run = h.run(t, notify, []string{payload}, "", nil, []string{`200|{}`})
	if run.exitCode != 0 || len(run.calls) != 0 {
		t.Fatalf("notify without token exit %d calls %d", run.exitCode, len(run.calls))
	}
	run = h.run(t, notify, []string{payload}, "", map[string]string{SandboxTokenEnv: "tok"}, []string{"exit:7"})
	if run.exitCode != 0 || run.stdout != "" || run.stderr != "" {
		t.Fatalf("notify outage must be silent: exit %d out=%q err=%q", run.exitCode, run.stdout, run.stderr)
	}
}

func TestSandboxClaudeOtelHeadersHelper(t *testing.T) {
	h := newSandboxHookHarness(t, &ClaudeCodeConnector{}, "2.1.156")
	helper := h.path(claudeCodeSandboxOtelHelperPath)
	for _, tc := range []struct {
		token    string
		wantAuth string
	}{
		{"openshell:resolve:env:v9_DEFENSECLAW_SANDBOX_TOKEN", "Bearer openshell:resolve:env:v9_DEFENSECLAW_SANDBOX_TOKEN"},
		{`bad"token`, ""},
		{"", ""},
	} {
		cmd := exec.Command(helper)
		cmd.Env = []string{"PATH=/usr/bin:/bin", SandboxTokenEnv + "=" + tc.token}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("helper: %v", err)
		}
		var headers map[string]string
		if err := json.Unmarshal(out, &headers); err != nil {
			t.Fatalf("helper output %q is not JSON: %v", out, err)
		}
		if headers["Authorization"] != tc.wantAuth || headers["x-defenseclaw-source"] != "claudecode" {
			t.Fatalf("token %q: headers = %v", tc.token, headers)
		}
	}
}

func TestSandboxHookScriptsParse(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	for _, tc := range sandboxGoldenTargets {
		artifacts := renderSandboxGolden(t, tc.provider, tc.version)
		for _, file := range artifacts.Files {
			if !strings.HasSuffix(file.Path, ".sh") {
				continue
			}
			shell := "/bin/bash"
			if bytes.HasPrefix(file.Data, []byte("#!/bin/sh")) {
				shell = "/bin/sh"
			}
			cmd := exec.Command(shell, "-n")
			cmd.Stdin = bytes.NewReader(file.Data)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s %s: %v\n%s", tc.connector, file.Path, err, out)
			}
		}
	}
}
