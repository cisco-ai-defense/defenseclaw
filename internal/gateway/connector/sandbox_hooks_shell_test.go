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
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// sandboxCurlStub stands in for curl on the baked hook PATH. It records the
// argv, environment, stdin and --config files of every call and replays one
// scripted response per call:
// "exit:<code>" makes curl fail, "<status>|<body>" prints body and status the
// way `curl -w '\n%{http_code}'` does.
//
// The stub records the hook's environment before running anything, then
// switches to the system PATH so its own tools never show up in a trace of
// what the hooks execute (TestSandboxHookRuntimeBinariesCoverEveryTool).
const sandboxCurlStub = `#!/bin/bash
dir="${0%/*}"
/usr/bin/env > "$dir/env.now"
PATH=/usr/bin:/bin
n=$(( $(cat "$dir/count" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$dir/count"
mv "$dir/env.now" "$dir/env.$n"
printf '%s\n' "$@" > "$dir/args.$n"
: > "$dir/config.$n"
prev=""
for arg in "$@"; do
  case "$prev" in --config|-K) cat "$arg" >> "$dir/config.$n" ;; esac
  prev="$arg"
done
cat > "$dir/body.$n"
line="$(sed -n "${n}p" "$dir/responses")"
case "$line" in
  exit:*) exit "${line#exit:}" ;;
  '') exit 7 ;;
  *) printf '%s\n%s' "${line#*|}" "${line%%|*}" ;;
esac
`

type sandboxCurlCall struct {
	argv []string
	// headers are the -H arguments and the header lines of the --config
	// files, by lower-case name.
	headers map[string]string
	env     map[string]string
	body    string
	// config is what the call's --config files held.
	config string
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
	return newSandboxHookHarnessFiles(t, sandboxArtifactsFor(t, provider, version).Files, SandboxHookPATH)
}

// newSandboxHookHarnessFiles materializes an explicit sandbox file set whose
// baked PATH is the curl stub directory followed by systemPATH.
func newSandboxHookHarnessFiles(t *testing.T, files []SandboxFile, systemPATH string) *sandboxHookHarness {
	t.Helper()
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required")
	}
	h := &sandboxHookHarness{root: t.TempDir(), stubDir: t.TempDir()}
	stubPath := h.stubDir + ":" + systemPATH
	h.bakedPATH = stubPath
	for _, file := range files {
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
	for _, pattern := range []string{"args.*", "body.*", "env.*", "config.*"} {
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
		config, _ := os.ReadFile(filepath.Join(h.stubDir, "config."+strconv.Itoa(i)))
		call.config = string(config)
		for _, line := range strings.Split(call.config, "\n") {
			quoted, ok := strings.CutPrefix(strings.TrimSpace(line), "header = ")
			if !ok {
				continue
			}
			// curl unescapes \" and \\ in a quoted value, as Go does.
			header, err := strconv.Unquote(quoted)
			if err != nil {
				t.Fatalf("curl config line %q: %v", line, err)
			}
			name, value, _ := strings.Cut(header, ": ")
			call.headers[strings.ToLower(name)] = value
		}
		result.calls = append(result.calls, call)
	}
	return result
}

var sandboxIdempotencyKeyRE = regexp.MustCompile(`^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})$`)

const (
	claudePreToolUse      = `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"ls"}}`
	codexPreToolUse       = `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"ls"}}`
	copilotPreToolUse     = `{"sessionId":"s1","timestamp":1790483549431,"cwd":"/work/proj","toolName":"bash","toolArgs":{"command":"ls","description":"list"}}`
	cursorPreToolUse      = `{"hook_event_name":"beforeShellExecution","conversation_id":"c1","command":"ls","cwd":"/work/proj","cursor_version":"2026.07.23-e383d2b"}`
	kiroPreToolUse        = `{"hook_event_name":"preToolUse","cwd":"/work/proj","session_id":"s1","tool_name":"shell","tool_input":{"command":"ls"}}`
	devinPreToolUse       = `{"hook_event_name":"PreToolUse","session_id":"s1","cwd":"/work/proj","tool_name":"exec","tool_input":{"command":"ls"}}`
	hermesPreToolCall     = `{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"ls"},"session_id":"s1","cwd":"/work/p","extra":{}}`
	openHandsPreToolUse   = `{"event_type":"PreToolUse","tool_name":"terminal","tool_input":{"command":"ls"},"session_id":"s1","working_dir":"/work/p","metadata":{}}`
	antigravityPreToolUse = `{"toolName":"run_command","toolInput":{"CommandLine":"ls"}}`
	allowResponse         = `200|{"action":"allow"}`
)

var (
	codexPreToolUseArgs   = []string{"--event", "PreToolUse", "--hook-contract", "codex-hooks-v4"}
	copilotPreToolUseArgs = []string{"--event", "preToolUse"}
)

// sandboxHookCase is one sandbox hook script run on a PreToolUse event.
type sandboxHookCase struct {
	connector string
	provider  SandboxArtifactProvider
	version   string
	script    string
	args      []string
	stdin     string
	route     string
	// headers are sent with every request.
	headers map[string]string
	// wrapsBody: the hook posts its input inside a JSON envelope.
	wrapsBody bool
	// lifecycle hooks accept only allow, alert, block and confirm; the
	// inspect hooks allow every verdict other than block.
	lifecycle bool
	// blocked reports whether a run is a block under the harness's own
	// contract: Hermes enforces only a stdout block directive (its exit
	// status is ignored), Antigravity only a synchronous {"decision":"deny"},
	// Kiro exit 2 with nothing on stdout (it adds stdout to the context),
	// every other harness exit 2 (see sandboxHookFailObject).
	blocked func(sandboxHookRun) bool
}

// lastJSON decodes the last stdout line of a hook run.
func lastJSON(run sandboxHookRun) map[string]interface{} {
	lines := strings.Split(strings.TrimSpace(run.stdout), "\n")
	var out map[string]interface{}
	_ = json.Unmarshal([]byte(lines[len(lines)-1]), &out)
	return out
}

// sandboxHookFailObject reports, for the harnesses that also want one, the
// event-native object a failure on a known event prints with its exit 2.
var sandboxHookFailObject = map[string]func(sandboxHookRun) bool{
	"cursor": func(run sandboxHookRun) bool { return lastJSON(run)["permission"] == "deny" },
	// Devin shows an exit-2 stdout verbatim: a plain reason, never JSON.
	"devin": func(run sandboxHookRun) bool {
		out := strings.TrimSpace(run.stdout)
		return out != "" && !strings.HasPrefix(out, "{")
	},
}

func sandboxHookCases() []sandboxHookCase {
	exit2 := func(run sandboxHookRun) bool { return run.exitCode == 2 }
	return []sandboxHookCase{
		{"claudecode", &ClaudeCodeConnector{}, "2.1.156", "claude-code-hook.sh", nil, claudePreToolUse, "/api/v1/claude-code/hook", nil, false, true, exit2},
		{"codex", &CodexConnector{}, "0.146.0", "codex-hook.sh", codexPreToolUseArgs, codexPreToolUse, "/api/v1/codex/hook",
			map[string]string{"x-defenseclaw-hook-event": "PreToolUse", "x-defenseclaw-hook-contract": "codex-hooks-v4"}, false, true, exit2},
		{"copilot", NewCopilotConnector(), "1.0.88", "copilot-hook.sh", copilotPreToolUseArgs, copilotPreToolUse, "/api/v1/copilot/hook",
			map[string]string{"x-defenseclaw-copilot-event": "preToolUse"}, false, true, exit2},
		{"cursor", NewCursorConnector(), "2026.07.23-e383d2b", "cursor-hook.sh", nil, cursorPreToolUse, "/api/v1/cursor/hook", nil, false, true, exit2},
		{"kiro", NewKiroConnector(), "2.24.1", "kiro-hook.sh", nil, kiroPreToolUse, "/api/v1/kiro/hook",
			map[string]string{"x-defenseclaw-kiro-surface": ""}, false, true,
			func(run sandboxHookRun) bool { return run.exitCode == 2 && run.stdout == "" }},
		{"devin", NewDevinConnector(), "3000.4.25", "devin-hook.sh", nil, devinPreToolUse, "/api/v1/devin/hook", nil, false, true, exit2},
		{"hermes", NewHermesConnector(), "0.19.0", "hermes-hook.sh", nil, hermesPreToolCall, "/api/v1/hermes/hook", nil, false, true,
			func(run sandboxHookRun) bool {
				d := lastJSON(run)
				return d["action"] == "block" || d["decision"] == "block"
			}},
		{"openhands", NewOpenHandsConnector(), "1.16.0", "openhands-hook.sh", nil, openHandsPreToolUse, "/api/v1/openhands/hook", nil, false, true, exit2},
		{"antigravity", NewAntigravityConnector(), "1.2.12", "antigravity-hook.sh", []string{"PreToolUse"}, antigravityPreToolUse, "/api/v1/antigravity/hook",
			map[string]string{"x-defenseclaw-antigravity-event": "PreToolUse"}, false, true,
			func(run sandboxHookRun) bool { return run.exitCode == 0 && lastJSON(run)["decision"] == "deny" }},
		{"claudecode", &ClaudeCodeConnector{}, "2.1.156", "inspect-tool.sh", nil, `{"command":"ls"}`, "/api/v1/inspect/tool",
			map[string]string{"x-defenseclaw-connector": "claudecode"}, true, false, exit2},
		{"claudecode", &ClaudeCodeConnector{}, "2.1.156", "inspect-tool-response.sh", nil, `{"output":"ok"}`, "/api/v1/inspect/tool-response", nil, true, false, exit2},
		{"codex", &CodexConnector{}, "0.146.0", "inspect-request.sh", nil, `{"content":"hi"}`, "/api/v1/inspect/request", nil, true, false, exit2},
		{"codex", &CodexConnector{}, "0.146.0", "inspect-response.sh", nil, `{"content":"hi"}`, "/api/v1/inspect/response", nil, true, false, exit2},
	}
}

// TestSandboxHooksRetryOnceWithIdempotencyKey pins the transport every
// sandbox hook posts with: the baked ingress route, curlrc and proxies
// ignored, one retry with the same random 128-bit key after a dropped
// request, a relay 503 or a timeout (the relay occasionally drops a request,
// possibly after the ingress acted on it) within its own time budget, and the
// binding token only in curl configuration on a descriptor: every process in
// the sandbox can read curl's command line, and with token_delivery: env the
// token is the credential itself (quoted, so one with a quote or a backslash
// still arrives intact).
func TestSandboxHooksRetryOnceWithIdempotencyKey(t *testing.T) {
	const token = `dcsb_env-delivered"token\x`
	// The inspect hooks bake their connector, whatever the environment says.
	env := map[string]string{SandboxTokenEnv: token, "CLAUDE_TOOL_NAME": "Bash", "DEFENSECLAW_CONNECTOR": "cursor"}
	for _, tc := range sandboxHookCases() {
		h := newSandboxHookHarness(t, tc.provider, tc.version)
		for name, first := range map[string]string{"empty-reply": "exit:52", "relay-503": `503|{}`, "timeout": "exit:28"} {
			t.Run(tc.script+"/"+name, func(t *testing.T) {
				run := h.run(t, SandboxHookDir+"/"+tc.script, tc.args, tc.stdin, env, []string{first, allowResponse})
				if run.exitCode != 0 || tc.blocked(run) || len(run.calls) != 2 {
					t.Fatalf("exit %d calls %d stdout %q; stderr=%s", run.exitCode, len(run.calls), run.stdout, run.stderr)
				}
				key := run.calls[0].headers["x-defenseclaw-hook-idempotency-key"]
				if !sandboxIdempotencyKeyRE.MatchString(key) {
					t.Fatalf("idempotency key %q is not a random 128-bit key", key)
				}
				for i, call := range run.calls {
					argv := strings.Join(call.argv, "\n")
					switch {
					case call.headers["x-defenseclaw-hook-idempotency-key"] != key:
						t.Fatalf("call %d changed the idempotency key", i)
					case call.url() != "http://host.openshell.internal:18971"+tc.route:
						t.Fatalf("call %d url = %q", i, call.url())
					case !tc.wrapsBody && call.body != tc.stdin:
						t.Fatalf("call %d body = %q", i, call.body)
					case call.argv[0] != "-q" || call.flagValue("--noproxy") != "*":
						t.Fatalf("call %d must ignore curlrc and proxies: %v", i, call.argv)
					case strings.Contains(argv, "dcsb_env-delivered") || strings.Contains(strings.ToLower(argv), "authorization"):
						t.Fatalf("call %d put the bearer on curl's command line:\n%s", i, argv)
					case call.flagValue("--config") != "/dev/fd/7" || call.headers["authorization"] != "Bearer "+token:
						t.Fatalf("call %d: config %q, authorization %q", i, call.config, call.headers["authorization"])
					}
					for name, want := range tc.headers {
						if call.headers[name] != want {
							t.Fatalf("call %d %s = %q, want %q", i, name, call.headers[name], want)
						}
					}
				}
				if run.calls[0].flagValue("--max-time") != strconv.Itoa(sandboxHookMaxTimeSeconds) ||
					run.calls[1].flagValue("--max-time") != strconv.Itoa(sandboxHookRetryMaxTimeSeconds) {
					t.Fatalf("attempt budgets = %s/%s", run.calls[0].flagValue("--max-time"), run.calls[1].flagValue("--max-time"))
				}
			})
		}
	}
}

// TestSandboxHooksFailClosed pins that no reply the workload can provoke
// turns into an allow: a garbage DEFENSECLAW_SANDBOX_TOKEN earns a 401, a
// request flood a 429, an unversioned placeholder a relay 500, and a relay
// can garble the body. The hook templates are rendered with an "open" fail
// mode forced into the template data (resolveSandboxTarget refuses it) and
// run with every host override and host token file in place, so the test also
// proves the sandbox branches never consult them. A missing token and an
// oversized payload (the head(1) tier the sandbox hooks use in place of
// python3, with an inherited cap ignored in both directions) block without a
// request.
func TestSandboxHooksFailClosed(t *testing.T) {
	replies := map[string][]string{
		"ingress-down":   {"exit:7", "exit:7"},
		"unauthorized":   {`401|{"error":"bad token"}`},
		"forbidden":      {`403|{"error":"route not allowed"}`},
		"not-found":      {`404|{"error":"no route"}`},
		"too-large":      {`413|{"error":"payload too large"}`},
		"rate-limited":   {`429|{"error":"slow down"}`},
		"relay-500":      {`500|placeholder did not resolve`},
		"relay-502":      {`502|{}`, `502|{}`},
		"no-status":      {`|`},
		"garbled-status": {`2x0|{"action":"allow"}`},
		"not-json":       {`200|<html>proxy</html>`},
		"empty-2xx":      {`204|`},
		"no-action":      {`200|{"ok":true}`},
	}
	hostOverrides := map[string]string{
		"DEFENSECLAW_FAIL_MODE": "open", "DEFENSECLAW_STRICT_AVAILABILITY": "0", "DEFENSECLAW_GATEWAY_TOKEN": "host-master",
		"DEFENSECLAW_HOME": "/nonexistent", "DEFENSECLAW_CONNECTOR": "cursor", "CLAUDE_TOOL_NAME": "Bash",
	}
	with := func(extra map[string]string) map[string]string {
		env := map[string]string{}
		for _, m := range []map[string]string{hostOverrides, extra} {
			for k, v := range m {
				env[k] = v
			}
		}
		return env
	}
	for _, tc := range sandboxHookCases() {
		rt, err := resolveSandboxTarget(tc.connector, SandboxRenderTarget{IngressPort: 18971, AgentVersion: tc.version})
		if err != nil {
			t.Fatal(err)
		}
		rt.failMode = "open"
		files, err := renderSandboxHookFiles(tc.connector, rt)
		if err != nil {
			t.Fatal(err)
		}
		h := newSandboxHookHarnessFiles(t, files, SandboxHookPATH)
		for _, name := range []string{".token", ".hook-" + tc.connector + ".token"} {
			if err := os.WriteFile(filepath.Join(h.path(SandboxHookDir), name), []byte("DEFENSECLAW_GATEWAY_TOKEN=\"host\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		markers := t.TempDir()
		writeMarkerTool(t, h.stubDir, "python3", markers)
		script := SandboxHookDir + "/" + tc.script
		cases := map[string][]string{}
		for name, r := range replies {
			cases[name] = r
		}
		if tc.lifecycle {
			cases["unknown-action"] = []string{`200|{"action":"maybe"}`}
		}
		for name, responses := range cases {
			t.Run(tc.script+"/"+name, func(t *testing.T) {
				run := h.run(t, script, tc.args, tc.stdin, with(map[string]string{SandboxTokenEnv: "garbage"}), responses)
				if f := sandboxHookFailObject[tc.connector]; !tc.blocked(run) || tc.lifecycle && f != nil && !f(run) {
					t.Fatalf("not blocked: exit %d stdout=%q stderr=%s", run.exitCode, run.stdout, run.stderr)
				}
				// Only transport failures and relay 502-504s are retried.
				if len(run.calls) != len(responses) {
					t.Fatalf("calls = %d, want %d", len(run.calls), len(responses))
				}
				for _, call := range run.calls {
					if call.headers["authorization"] != "Bearer garbage" {
						t.Fatalf("authorization = %q, want the sandbox token only", call.headers["authorization"])
					}
				}
			})
		}
		t.Run(tc.script+"/missing-token", func(t *testing.T) {
			run := h.run(t, script, tc.args, tc.stdin, with(nil), []string{allowResponse})
			// Cursor still denies the event it read.
			if !tc.blocked(run) || len(run.calls) != 0 || !strings.Contains(run.stderr, SandboxTokenEnv) || tc.connector == "cursor" && !sandboxHookFailObject["cursor"](run) {
				t.Fatalf("exit %d calls %d stdout=%q stderr=%q, want a block naming %s and no request", run.exitCode, len(run.calls), run.stdout, run.stderr, SandboxTokenEnv)
			}
		})
		t.Run(tc.script+"/oversized-payload", func(t *testing.T) {
			big := strings.Replace(tc.stdin, `"ls"`, `"`+strings.Repeat("a", 1<<20)+`"`, 1)
			big = strings.Replace(big, `"ok"`, `"`+strings.Repeat("a", 1<<20)+`"`, 1)
			big = strings.Replace(big, `"hi"`, `"`+strings.Repeat("a", 1<<20)+`"`, 1)
			run := h.run(t, script, tc.args, big, with(map[string]string{SandboxTokenEnv: "tok", "DEFENSECLAW_HOOK_MAX_BODY": "99999999"}), []string{allowResponse})
			if !tc.blocked(run) || len(run.calls) != 0 {
				t.Fatalf("exit %d calls %d stdout=%q, want a block and no request", run.exitCode, len(run.calls), run.stdout)
			}
		})
		t.Run(tc.script+"/allow", func(t *testing.T) {
			run := h.run(t, script, tc.args, tc.stdin, with(map[string]string{SandboxTokenEnv: "tok", "DEFENSECLAW_HOOK_MAX_BODY": "4"}), []string{allowResponse})
			if tc.blocked(run) || run.exitCode != 0 || len(run.calls) != 1 || !tc.wrapsBody && run.calls[0].body != tc.stdin {
				t.Fatalf("allow: exit %d calls %d stdout=%q stderr=%s", run.exitCode, len(run.calls), run.stdout, run.stderr)
			}
		})
		if ran, _ := os.ReadDir(markers); len(ran) != 0 {
			t.Fatalf("%s started python3", tc.script)
		}
	}
}

// Certification AG-MAC-F6: the sandbox Antigravity hook's deny says why it
// failed closed. An HTTP 400 for a malformed (empty) hook input told agy
// "DefenseClaw policy service is unavailable." while DefenseClaw was up and
// had refused the request; only an unreachable DefenseClaw (a transport
// failure, a 5xx) is reported so. Every case still denies the tool call.
func TestSandboxAntigravityHookDenySaysWhy(t *testing.T) {
	agy := newSandboxHookHarness(t, NewAntigravityConnector(), "1.2.12")
	token := map[string]string{SandboxTokenEnv: "tok"}
	for _, tc := range []struct {
		name, stdin string
		env         map[string]string
		responses   []string
		want        string
	}{
		{"malformed input", "", token, []string{`400|{"error":"invalid JSON"}`}, "DefenseClaw hook request was refused (HTTP 400), so the tool call is blocked."},
		{"rate limited", antigravityPreToolUse, token, []string{`429|{"error":"slow down"}`}, "DefenseClaw hook request was refused (HTTP 429), so the tool call is blocked."},
		{"no verdict", antigravityPreToolUse, token, []string{`200|{"ok":true}`}, "DefenseClaw answered the hook request without a verdict, so the tool call is blocked."},
		{"not json", antigravityPreToolUse, token, []string{`200|<html>proxy</html>`}, "DefenseClaw answered the hook request without a verdict, so the tool call is blocked."},
		{"ingress down", antigravityPreToolUse, token, []string{"exit:7", "exit:7"}, "DefenseClaw policy service is unavailable."},
		{"relay 500", antigravityPreToolUse, token, []string{`500|placeholder did not resolve`}, "DefenseClaw policy service is unavailable."},
		{"no token", antigravityPreToolUse, nil, []string{allowResponse}, "DefenseClaw hook has no valid sandbox binding token, so the tool call is blocked."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := agy.run(t, SandboxHookDir+"/antigravity-hook.sh", []string{"PreToolUse"}, tc.stdin, tc.env, tc.responses)
			got := lastJSON(run)
			if run.exitCode != 0 || got["decision"] != "deny" || got["reason"] != tc.want {
				t.Fatalf("exit %d stdout %q, want a deny with reason %q; stderr=%s", run.exitCode, run.stdout, tc.want, run.stderr)
			}
		})
	}
}

// TestSandboxHookFailClosedNamesThePrompt pins the wording the harness shows
// when the ingress is down: a prompt hook blocks the prompt, a tool hook the
// tool call.
func TestSandboxHookFailClosedNamesThePrompt(t *testing.T) {
	for _, tc := range []struct {
		provider SandboxArtifactProvider
		version  string
		hook     string
		args     []string
		payload  string
		want     string
	}{
		{&ClaudeCodeConnector{}, "2.1.156", "claude-code-hook.sh", nil,
			`{"hook_event_name":"UserPromptSubmit","session_id":"s1","prompt":"hi"}`, "blocking claude-code prompt (fail mode closed)"},
		{&ClaudeCodeConnector{}, "2.1.156", "claude-code-hook.sh", nil, claudePreToolUse, "blocking claude-code tool (fail mode closed)"},
		{&CodexConnector{}, "0.146.0", "codex-hook.sh", []string{"--event", "UserPromptSubmit", "--hook-contract", "codex-hooks-v4"},
			`{"hook_event_name":"UserPromptSubmit","session_id":"s1","turn_id":"t1","prompt":"hi"}`, "blocking codex prompt (fail mode closed)"},
	} {
		h := newSandboxHookHarness(t, tc.provider, tc.version)
		run := h.run(t, SandboxHookDir+"/"+tc.hook, tc.args, tc.payload, map[string]string{SandboxTokenEnv: "tok"}, []string{"exit:7", "exit:7"})
		if run.exitCode != 2 || !strings.Contains(run.stderr, tc.want) {
			t.Fatalf("%s: exit %d stderr %q, want exit 2 and %q", tc.hook, run.exitCode, run.stderr, tc.want)
		}
		// The reason says what is down and how the user brings it back,
		// not "sandbox ingress unreachable" (GAP-0272).
		// A daemon just started takes a moment to answer (GAP-0332).
		if !strings.Contains(run.stderr, "its daemon is stopped or restarting, or was started less than a minute ago") ||
			!strings.Contains(run.stderr, "`defenseclaw-gateway start` there if it is stopped, and after a start retries in a minute") {
			t.Fatalf("%s: stderr %q does not name the stopped daemon and defenseclaw-gateway start", tc.hook, run.stderr)
		}
	}
}

// TestSandboxHooksRenderVerdicts pins what each harness gets for a verdict:
// the gateway's event-native object where it rendered one, the harness's own
// block signal with the gateway's reason where it did not, and for an
// advisory finding (action "alert", would_block false) the harness notice
// with the tool left to run (an alert used to be "invalid or missing
// action", a fail-closed block).
func TestSandboxHooksRenderVerdicts(t *testing.T) {
	claudeDeny := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"nope"}}`
	cursorDeny := `{"permission":"deny","user_message":"nope","agent_message":"nope"}`
	copilotDeny := `{"permissionDecision":"deny","permissionDecisionReason":"nope"}`
	devinContext := `{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"note"}}`
	const any = "*"
	cases := map[string]sandboxHookCase{}
	for _, tc := range sandboxHookCases() {
		if tc.lifecycle {
			cases[tc.connector] = tc
		}
	}
	for _, v := range []struct {
		name, connector string
		stdin           string // the case's PreToolUse payload when empty
		args            []string
		reply           string
		// exit is the exit status (-1: the harness's block signal and
		// failure object instead);
		// stdout is the exact trimmed stdout (any: not checked); reason must
		// appear on stdout or stderr.
		exit           int
		stdout, reason string
	}{
		{"claude block verdict", "claudecode", "", nil, `{"action":"block","reason":"nope","claude_code_output":` + claudeDeny + `}`, 0, claudeDeny, ""},
		{"copilot block verdict", "copilot", "", nil, `{"action":"block","reason":"nope","hook_output":` + copilotDeny + `}`, 0, copilotDeny, ""},
		// Copilot's only hook deny besides the verdict is exit 2.
		{"copilot bare block", "copilot", "", nil, `{"action":"block","reason":"nope"}`, 2, any, "nope"},
		{"copilot session start unknown action", "copilot", `{"sessionId":"s1"}`, []string{"--event", "sessionStart"}, `{"action":"maybe"}`, 2, any, ""},
		{"cursor allow", "cursor", "", nil, `{"action":"allow"}`, 0, `{"permission":"allow"}`, ""},
		{"cursor block verdict", "cursor", "", nil, `{"action":"block","reason":"nope","hook_output":` + cursorDeny + `}`, 2, cursorDeny, ""},
		{"cursor bare block", "cursor", "", nil, `{"action":"block","reason":"nope"}`, -1, any, ""},
		// A prompt gate says continue, an observation event prints {}.
		{"cursor prompt allow", "cursor", `{"hook_event_name":"beforeSubmitPrompt","prompt":"hi"}`, nil, `{"action":"allow"}`, 0, `{"continue":true}`, ""},
		{"cursor prompt block", "cursor", `{"hook_event_name":"beforeSubmitPrompt","prompt":"hi"}`, nil, `{"action":"block","reason":"nope"}`, 2, any, `"continue":false`},
		{"cursor observation", "cursor", `{"hook_event_name":"afterShellExecution","command":"ls"}`, nil, `{"action":"allow"}`, 0, `{}`, ""},
		// Kiro adds stdout to the agent context: it stays empty.
		{"kiro allow", "kiro", "", nil, `{"action":"allow"}`, 0, "", ""},
		{"kiro block verdict", "kiro", "", nil, `{"action":"block","reason":"nope","hook_output":{"decision":"block","reason":"nope"}}`, -1, "", "nope"},
		{"kiro bare block", "kiro", "", nil, `{"action":"block","reason":"nope"}`, -1, "", "nope"},
		{"kiro verdict deny", "kiro", "", nil, `{"action":"allow","hook_output":{"decision":"deny","reason":"nope"}}`, -1, "", "nope"},
		{"devin allow", "devin", "", nil, `{"action":"allow"}`, 0, "", ""},
		{"devin block verdict", "devin", "", nil, `{"action":"block","reason":"nope","hook_output":{"decision":"block","reason":"nope"}}`, -1, "nope", ""},
		{"devin bare block", "devin", "", nil, `{"action":"block","reason":"nope"}`, -1, any, "nope"},
		// Context for an observation event is printed without blocking.
		{"devin context", "devin", `{"hook_event_name":"PostToolUse","tool_name":"exec"}`, nil, `{"action":"alert","hook_output":` + devinContext + `}`, 0, devinContext, ""},
		{"hermes block verdict", "hermes", "", nil, `{"action":"block","reason":"rule X","hook_output":{"decision":"block","reason":"rule X"}}`, -1, any, "rule X"},
		{"hermes bare block", "hermes", "", nil, `{"action":"block","reason":"rule Y"}`, -1, any, "rule Y"},
		{"openhands block verdict", "openhands", "", nil, `{"action":"block","reason":"rule X","hook_output":{"decision":"deny","reason":"rule X"}}`, -1, any, "rule X"},
		{"openhands bare block", "openhands", "", nil, `{"action":"block","reason":"rule Y"}`, -1, any, "rule Y"},
		{"antigravity block verdict", "antigravity", "", nil, `{"action":"block","reason":"rule X","hook_output":{"decision":"deny","reason":"rule X"}}`, -1, any, "rule X"},
		{"antigravity bare block", "antigravity", "", nil, `{"action":"block","reason":"rule Y"}`, -1, any, "rule Y"},
		{"claude alert", "claudecode", "", nil, alertVerdict, 0, alertNotice, ""},
		{"claude bare alert", "claudecode", "", nil, `{"action":"alert","would_block":false}`, 0, "", ""},
		{"codex alert", "codex", "", nil, alertVerdict, 0, alertNotice, ""},
		{"codex bare alert", "codex", "", nil, `{"action":"alert","would_block":false}`, 0, "", ""},
		{"copilot alert", "copilot", "", nil, alertVerdict, 0, any, ""},
		{"cursor alert", "cursor", "", nil, alertVerdict, 0, any, ""},
		{"kiro alert", "kiro", "", nil, alertVerdict, 0, any, ""},
		{"devin alert", "devin", "", nil, alertVerdict, 0, any, ""},
	} {
		t.Run(v.name, func(t *testing.T) {
			tc := cases[v.connector]
			stdin, args := tc.stdin, tc.args
			if v.stdin != "" {
				stdin, args = v.stdin, v.args
			}
			run := newSandboxHookHarness(t, tc.provider, tc.version).run(t, SandboxHookDir+"/"+tc.script, args, stdin,
				map[string]string{SandboxTokenEnv: "tok", "DEFENSECLAW_FAIL_MODE": "open"}, []string{"200|" + v.reply})
			if len(run.calls) != 1 || strings.Contains(run.stderr, "invalid or missing action") && v.exit == 0 {
				t.Fatalf("calls %d stderr %s", len(run.calls), run.stderr)
			}
			if f := sandboxHookFailObject[v.connector]; v.exit < 0 && (!tc.blocked(run) || f != nil && !f(run)) || v.exit >= 0 && run.exitCode != v.exit {
				t.Fatalf("exit %d stdout %q stderr %q, want exit %d (-1: the harness's block)", run.exitCode, run.stdout, run.stderr, v.exit)
			}
			if v.stdout != any && strings.TrimSpace(run.stdout) != v.stdout {
				t.Fatalf("stdout = %q, want %q", run.stdout, v.stdout)
			}
			if !strings.Contains(run.stdout+run.stderr, v.reason) {
				t.Fatalf("stdout %q stderr %q lack %q", run.stdout, run.stderr, v.reason)
			}
		})
	}
}

// TestSandboxKiroHookNamesDefenseClawOnce: Kiro shows the veto's stderr as
// "PreToolHook blocked the tool execution: <stderr>". DefenseClaw's own
// reason is printed as is ("defenseclaw: Blocked by DefenseClaw rule ..."
// named it twice, cert kiro:KR-F10); any other reason keeps the prefix.
func TestSandboxKiroHookNamesDefenseClawOnce(t *testing.T) {
	var tc sandboxHookCase
	for _, c := range sandboxHookCases() {
		if c.connector == "kiro" && c.lifecycle {
			tc = c
		}
	}
	for reason, want := range map[string]string{
		"Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command": "Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command\n",
		"marker rule matched": "defenseclaw: marker rule matched\n",
	} {
		reply := `{"action":"block","reason":"` + reason + `","hook_output":{"decision":"block","reason":"` + reason + `"}}`
		run := newSandboxHookHarness(t, tc.provider, tc.version).run(t, SandboxHookDir+"/"+tc.script, tc.args, tc.stdin,
			map[string]string{SandboxTokenEnv: "tok", "DEFENSECLAW_FAIL_MODE": "open"}, []string{"200|" + reply})
		if !tc.blocked(run) || run.stdout != "" || run.stderr != want {
			t.Errorf("reason %q: exit %d stdout %q stderr %q, want stderr %q", reason, run.exitCode, run.stdout, run.stderr, want)
		}
	}
}

// TestSandboxHooksBindTheRegisteredEvent: a hook posts only the event its
// registration names (argv, never an exported variable), fails closed on any
// other registration, and a Codex SessionEnd gets its short time budget.
func TestSandboxHooksBindTheRegisteredEvent(t *testing.T) {
	env := map[string]string{SandboxTokenEnv: "tok", "DEFENSECLAW_FAIL_MODE": "open", "HOOK_EVENT": "Stop"}
	codex := newSandboxHookHarness(t, &CodexConnector{}, "0.146.0")
	run := codex.run(t, SandboxHookDir+"/codex-hook.sh", []string{"--event", "SessionEnd", "--hook-contract", "codex-hooks-v4"},
		`{"hook_event_name":"SessionEnd","session_id":"s1"}`, env, []string{allowResponse})
	if run.exitCode != 0 || len(run.calls) != 1 || run.calls[0].flagValue("--max-time") != strconv.Itoa(sandboxHookSessionEndMaxTimeSeconds) {
		t.Fatalf("SessionEnd exit %d calls %d; stderr=%s", run.exitCode, len(run.calls), run.stderr)
	}
	agy := newSandboxHookHarness(t, NewAntigravityConnector(), "1.2.12")
	run = agy.run(t, SandboxHookDir+"/antigravity-hook.sh", []string{"PostToolUse"}, `{}`, env, []string{allowResponse})
	if run.exitCode != 0 || len(run.calls) != 1 || run.calls[0].headers["x-defenseclaw-antigravity-event"] != "PostToolUse" {
		t.Fatalf("exit %d calls %d headers %v", run.exitCode, len(run.calls), run.calls)
	}
	copilot := newSandboxHookHarness(t, NewCopilotConnector(), "1.0.88")
	for _, tc := range []struct {
		name string
		h    *sandboxHookHarness
		hook string
		args []string
		// denied reports the harness's block for a PreToolUse whose
		// registration is broken (nil: only no request is required).
		denied func(sandboxHookRun) bool
	}{
		{"codex mismatched event", codex, "codex-hook.sh", []string{"--event", "Stop", "--hook-contract", "codex-hooks-v4"}, nil},
		{"copilot no args", copilot, "copilot-hook.sh", nil, nil},
		{"copilot unknown event", copilot, "copilot-hook.sh", []string{"--event", "futureEvent"}, nil},
		{"copilot extra args", copilot, "copilot-hook.sh", []string{"--event", "preToolUse", "--x"}, nil},
		{"antigravity none", agy, "antigravity-hook.sh", nil, nil},
		{"antigravity unknown", agy, "antigravity-hook.sh", []string{"BeforeTool"}, nil},
		{"antigravity extra", agy, "antigravity-hook.sh", []string{"PreToolUse", "x"},
			func(run sandboxHookRun) bool { return lastJSON(run)["decision"] == "deny" }},
	} {
		stdin := map[string]string{"codex-hook.sh": codexPreToolUse, "copilot-hook.sh": copilotPreToolUse, "antigravity-hook.sh": antigravityPreToolUse}[tc.hook]
		run := tc.h.run(t, SandboxHookDir+"/"+tc.hook, tc.args, stdin, env, []string{allowResponse})
		if len(run.calls) != 0 || tc.denied == nil && tc.hook != "antigravity-hook.sh" && run.exitCode != 2 || tc.denied != nil && !tc.denied(run) {
			t.Errorf("%s: exit %d calls %d stdout %q, want no request and a block", tc.name, run.exitCode, len(run.calls), run.stdout)
		}
	}
}

func TestSandboxArtifactsRefuseOpenFailMode(t *testing.T) {
	for _, tc := range sandboxGoldenTargets {
		for _, mode := range []string{"open", " open ", "OPEN", "fail-open", "observe"} {
			_, err := tc.provider.SandboxArtifacts(SandboxRenderTarget{IngressPort: 18971, AgentVersion: tc.version, FailMode: mode})
			if err == nil || !strings.Contains(err.Error(), "always fail closed") {
				t.Fatalf("%s fail mode %q: err = %v, want a refusal", tc.connector, mode, err)
			}
		}
		for _, mode := range []string{"", "closed", " closed "} {
			if _, err := tc.provider.SandboxArtifacts(SandboxRenderTarget{IngressPort: 18971, AgentVersion: tc.version, FailMode: mode}); err != nil {
				t.Fatalf("%s fail mode %q: %v", tc.connector, mode, err)
			}
		}
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

// TestSandboxHooksScrubInheritedEnvironment runs every sandbox hook with an
// environment the workload controls (Claude Code applies settings env blocks
// to hook processes): a PATH entry ahead of the baked one, a PYTHONPATH
// sitecustomize, bash knobs that would abort or reroute the hook, the hook's
// own variable names, and assorted interpreter inputs. Each hook must still
// forward the untouched payload to the baked ingress, run none of the
// planted code, and hand its children only the variables it reads.
func TestSandboxHooksScrubInheritedEnvironment(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sandbox hooks run only inside the Linux sandbox image (bash 5); macOS /bin/bash 3.2 differs")
	}
	const traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	// markers collects one file per planted program that ran; planted holds
	// marker versions of the tools the hooks run; pyDir a sitecustomize.py
	// that leaves a marker; victim a workload directory the hook must never
	// adopt as its HOME (and so never remove); tmpdir an inherited TMPDIR.
	type attack struct{ markers, planted, pyDir, victim, tmpdir string }
	vectors := map[string]func(t *testing.T, h *sandboxHookHarness, a attack) map[string]string{
		"planted-path": func(t *testing.T, h *sandboxHookHarness, a attack) map[string]string {
			return map[string]string{"PATH": a.planted + ":/usr/bin:/bin"}
		},
		"pythonpath-sitecustomize": func(t *testing.T, h *sandboxHookHarness, a attack) map[string]string {
			return map[string]string{"PYTHONPATH": a.pyDir, "PYTHONSTARTUP": filepath.Join(a.pyDir, "sitecustomize.py")}
		},
		"python3-never-started": func(t *testing.T, h *sandboxHookHarness, a attack) map[string]string {
			// python3 on the baked PATH itself.
			writeMarkerTool(t, h.stubDir, "python3", a.markers)
			return nil
		},
		"bash-knobs": func(t *testing.T, h *sandboxHookHarness, a attack) map[string]string {
			return map[string]string{"FUNCNEST": "1", "TMOUT": "1", "POSIXLY_CORRECT": "1", "EXECIGNORE": "*/jq", "BASH_COMPAT": "31"}
		},
		"hook-variables": func(t *testing.T, h *sandboxHookHarness, a attack) map[string]string {
			return map[string]string{
				"HOOK_DIR": "/nonexistent", "DEFENSECLAW_BAKED_HOOK_PATH": a.planted, "DEFENSECLAW_HOOK_HOME": a.victim,
				"DEFENSECLAW_HOOK_MAX_BODY": "4", "DEFENSECLAW_FAIL_MODE": "open", "DC_SANDBOX_INGRESS": "attacker.invalid:1",
				"FAIL_MODE": "open", "TMPDIR": a.tmpdir,
			}
		},
		"interpreter-inputs": func(t *testing.T, h *sandboxHookHarness, a attack) map[string]string {
			return map[string]string{"PERL5LIB": a.pyDir, "RUBYOPT": "-W0", "NODE_OPTIONS": "--no-warnings", "GCONV_PATH": a.pyDir, "DC_TEST_CANARY": "1"}
		},
	}
	vectors["all-at-once"] = func(t *testing.T, h *sandboxHookHarness, a attack) map[string]string {
		env := map[string]string{}
		for name, vector := range vectors {
			if name != "all-at-once" {
				for key, value := range vector(t, h, a) {
					env[key] = value
				}
			}
		}
		return env
	}
	for _, hook := range sandboxHookCases() {
		if hook.script == "inspect-tool-response.sh" || hook.script == "inspect-request.sh" || hook.script == "inspect-response.sh" {
			continue
		}
		for name, vector := range vectors {
			t.Run(hook.script+"/"+name, func(t *testing.T) {
				h := newSandboxHookHarness(t, hook.provider, hook.version)
				a := attack{markers: t.TempDir(), planted: t.TempDir(), pyDir: t.TempDir(), victim: t.TempDir(), tmpdir: t.TempDir()}
				for _, tool := range []string{"mktemp", "curl", "jq", "head", "sed", "tr", "od", "id", "uname", "cat", "python3"} {
					writeMarkerTool(t, a.planted, tool, a.markers)
				}
				site := "open(" + strconv.Quote(filepath.Join(a.markers, "sitecustomize")) + ", 'w').close()\n"
				if err := os.WriteFile(filepath.Join(a.pyDir, "sitecustomize.py"), []byte(site), 0o644); err != nil {
					t.Fatal(err)
				}
				keep := filepath.Join(a.victim, "keep")
				if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				env := map[string]string{SandboxTokenEnv: "tok", "DEFENSECLAW_TRACEPARENT": traceparent, "CLAUDE_TOOL_NAME": "Bash"}
				for key, value := range vector(t, h, a) {
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
				if hook.wrapsBody {
					var body map[string]string
					if err := json.Unmarshal([]byte(call.body), &body); err != nil {
						t.Fatalf("inspect body %q: %v", call.body, err)
					}
					forwarded = body["args"]
				}
				if forwarded != hook.stdin {
					t.Fatalf("forwarded payload = %q, want the hook input %q", forwarded, hook.stdin)
				}
				if !hook.wrapsBody && call.headers["traceparent"] != traceparent {
					t.Fatalf("allowlisted trace context lost: headers %v", call.headers)
				}
				if ran, _ := os.ReadDir(a.markers); len(ran) != 0 {
					var names []string
					for _, entry := range ran {
						names = append(names, entry.Name())
					}
					t.Fatalf("planted code ran inside the sandbox hook: %v", names)
				}
				if _, err := os.Stat(keep); err != nil {
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

// TestSandboxInspectHookSendsTheToolName: the inspect hook reads the tool
// name the harness exports and wraps the payload with it.
func TestSandboxInspectHookSendsTheToolName(t *testing.T) {
	h := newSandboxHookHarness(t, &ClaudeCodeConnector{}, "2.1.156")
	run := h.run(t, SandboxHookDir+"/inspect-tool.sh", nil, `{"command":"ls"}`, map[string]string{SandboxTokenEnv: "tok", "CLAUDE_TOOL_NAME": "Bash"}, []string{allowResponse})
	var body map[string]string
	if run.exitCode != 0 || len(run.calls) != 1 || json.Unmarshal([]byte(run.calls[0].body), &body) != nil || body["tool"] != "Bash" || body["args"] != `{"command":"ls"}` {
		t.Fatalf("exit %d calls %+v", run.exitCode, run.calls)
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
	if argv := strings.Join(run.calls[0].argv, "\n"); strings.Contains(argv, "tok\n") || strings.Contains(argv, "Authorization") ||
		run.calls[0].env[SandboxTokenEnv] != "" {
		t.Fatalf("the bearer reached curl's command line or environment: %v", run.calls[0].argv)
	}
	// No token, or one curl configuration could not quote: nothing is sent.
	for _, env := range []map[string]string{nil, {SandboxTokenEnv: `bad"tok`}} {
		if run := h.run(t, notify, []string{payload}, "", env, []string{`200|{}`}); run.exitCode != 0 || len(run.calls) != 0 {
			t.Fatalf("notify with token %q: exit %d calls %d", env[SandboxTokenEnv], run.exitCode, len(run.calls))
		}
	}
	run = h.run(t, notify, []string{payload}, "", map[string]string{SandboxTokenEnv: "tok"}, []string{"exit:7"})
	if run.exitCode != 0 || run.stdout != "" || run.stderr != "" {
		t.Fatalf("notify outage must be silent: exit %d out=%q err=%q", run.exitCode, run.stdout, run.stderr)
	}
}

func TestSandboxClaudeOtelHeadersHelper(t *testing.T) {
	h := newSandboxHookHarness(t, &ClaudeCodeConnector{}, "2.1.156")
	helper := h.path(claudeCodeSandboxOtelHelperPath)
	for token, wantAuth := range map[string]string{
		"openshell:resolve:env:v9_DEFENSECLAW_SANDBOX_TOKEN": "Bearer openshell:resolve:env:v9_DEFENSECLAW_SANDBOX_TOKEN",
		`bad"token`: "",
		"":          "",
	} {
		cmd := exec.Command(helper)
		cmd.Env = []string{"PATH=/usr/bin:/bin", SandboxTokenEnv + "=" + token}
		out, err := cmd.Output()
		var headers map[string]string
		if err != nil || json.Unmarshal(out, &headers) != nil {
			t.Fatalf("helper: %v, output %q", err, out)
		}
		if headers["Authorization"] != wantAuth || headers["x-defenseclaw-source"] != "claudecode" {
			t.Fatalf("token %q: headers = %v", token, headers)
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

// TestSandboxHookRuntimeBinariesCoverEveryTool runs the sandbox hooks through
// their allow, block, retry, outage, oversized-payload, auth-failure and
// helper paths with every tool on the baked PATH replaced by a tracing
// wrapper, and requires each tool they started to be listed by
// sandboxHookRuntimeBinaries: the image probe resolves exactly those on the
// baked PATH and requires them to be root-owned.
func TestSandboxHookRuntimeBinariesCoverEveryTool(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	traceDir, traceLog := t.TempDir(), filepath.Join(t.TempDir(), "trace")
	for _, dir := range strings.Split(SandboxHookPATH, ":") {
		entries, _ := os.ReadDir(dir)
		for _, entry := range entries {
			name := entry.Name()
			if strings.ContainsAny(name, "'\\\n") {
				continue
			}
			wrapper := filepath.Join(traceDir, name)
			if _, err := os.Lstat(wrapper); err == nil {
				continue // an earlier PATH entry wins, as in the hook
			}
			info, err := os.Stat(filepath.Join(dir, name))
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
				continue
			}
			script := "#!/bin/sh\nprintf '%s\\n' '" + name + "' >>'" + traceLog + "'\nexec '" + filepath.Join(dir, name) + "' \"$@\"\n"
			if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	listed := map[string]bool{}
	for _, bin := range sandboxHookRuntimeBinaries() {
		listed[bin.Name] = true
	}
	type scenario struct {
		script    string
		args      []string
		stdin     string
		env       map[string]string
		responses []string
	}
	token := map[string]string{SandboxTokenEnv: "tok", "CLAUDE_TOOL_NAME": "Bash", "DEFENSECLAW_TRACEPARENT": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"}
	oversized := `{"hook_event_name":"PreToolUse","tool_input":{"command":"` + strings.Repeat("a", 1<<20) + `"}}`
	// Every hook: allow, block, a native verdict, retry, outage, auth
	// failure, oversized payload and a missing token.
	paths := func(tc sandboxHookCase, verdict string) []scenario {
		out := []scenario{}
		for _, responses := range [][]string{{allowResponse}, {`200|{"action":"block","reason":"nope"}`}, {`200|{"action":"block","reason":"nope","hook_output":` + verdict + `}`},
			{"exit:52", allowResponse}, {"exit:7", "exit:7"}, {`401|{}`}} {
			out = append(out, scenario{tc.script, tc.args, tc.stdin, token, responses})
		}
		return append(out, scenario{tc.script, tc.args, oversized, token, nil}, scenario{tc.script, tc.args, tc.stdin, nil, nil})
	}
	verdicts := map[string]string{
		"copilot": `{"permissionDecision":"deny"}`, "cursor": `{"permission":"deny"}`, "kiro": `{"decision":"block","reason":"nope"}`,
		"devin": `{"decision":"block","reason":"nope"}`, "hermes": `{"decision":"block","reason":"nope"}`,
	}
	scenarios := map[string][]scenario{
		// The extra paths: Codex's SessionEnd budget, a mismatched event and
		// the notify bridge; Copilot's session start; Cursor's allow verdict;
		// agy's unknown event.
		"codex": {
			{"codex-hook.sh", []string{"--event", "SessionEnd", "--hook-contract", "codex-hooks-v4"}, `{"hook_event_name":"SessionEnd"}`, token, []string{allowResponse}},
			{"codex-hook.sh", []string{"--event", "Stop", "--hook-contract", "codex-hooks-v4"}, codexPreToolUse, token, nil},
			{codexSandboxNotifyScript, []string{`{"type":"agent-turn-complete"}`}, "", token, []string{`200|{}`}},
		},
		"copilot":     {{"copilot-hook.sh", []string{"--event", "sessionStart"}, `{"sessionId":"s1"}`, token, []string{allowResponse}}},
		"cursor":      {{"cursor-hook.sh", nil, cursorPreToolUse, token, []string{`200|{"action":"allow","hook_output":{"permission":"allow"}}`}}},
		"antigravity": {{"antigravity-hook.sh", []string{"Unknown"}, antigravityPreToolUse, token, nil}},
	}
	for _, tc := range sandboxHookCases() {
		scenarios[tc.connector] = append(scenarios[tc.connector], paths(tc, verdicts[tc.connector])...)
	}
	for _, target := range sandboxGoldenTargets {
		sc, ok := scenarios[target.connector]
		if !ok {
			continue
		}
		t.Run(target.connector, func(t *testing.T) {
			h := newSandboxHookHarnessFiles(t, sandboxArtifactsFor(t, target.provider, target.version).Files, traceDir)
			_ = os.Remove(traceLog)
			for _, s := range sc {
				h.run(t, SandboxHookDir+"/"+s.script, s.args, s.stdin, s.env, s.responses)
			}
			if target.connector == "claudecode" {
				cmd := exec.Command(h.path(claudeCodeSandboxOtelHelperPath))
				cmd.Env = []string{"PATH=" + traceDir, SandboxTokenEnv + "=tok"}
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("otel helper: %v %s", err, out)
				}
			}
			raw, err := os.ReadFile(traceLog)
			if err != nil {
				t.Fatalf("no tool was traced (the wrappers are not on the baked PATH?): %v", err)
			}
			seen := map[string]bool{}
			for _, name := range strings.Fields(string(raw)) {
				seen[name] = true
			}
			var missing, names []string
			for name := range seen {
				names = append(names, name)
				if !listed[name] {
					missing = append(missing, name)
				}
			}
			sort.Strings(missing)
			sort.Strings(names)
			t.Logf("%s hooks ran: %s", target.connector, strings.Join(names, " "))
			if len(missing) > 0 {
				t.Fatalf("sandboxHookRuntimeBinaries does not list %s, which the %s hooks run", strings.Join(missing, ", "), target.connector)
			}
		})
	}
}
