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

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

// argvGoldenRecordEnv names a defenseclaw-hook binary built from the full-CLI
// main (rel/1.0.10 9efb4f1799, before W1). With it set, the test runs every
// case against that binary and writes the golden file for this GOOS instead
// of comparing.
const argvGoldenRecordEnv = "DEFENSECLAW_HOOK_ARGV_RECORD"

// argvGoldenCompareEnv names a full-CLI defenseclaw-hook binary to compare
// with case by case on this host, without a golden file: the check for an OS
// whose answers depend on what is installed on the host (Windows, macOS).
const argvGoldenCompareEnv = "DEFENSECLAW_HOOK_ARGV_COMPARE"

const argvGoldenHelperEnv = "DEFENSECLAW_HOOK_ARGV_HELPER"

type argvCase struct {
	Name       string
	Args       []string
	Stdin      string
	NullStdin  bool
	MaskStdout bool
	// DataDir creates the account data directory (HOME/.defenseclaw), so a
	// per-user hook gets as far as its gateway.
	DataDir bool
}

type argvResult struct {
	Name   string `json:"name"`
	Exit   int    `json:"exit"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

const (
	claudePreToolUse = `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`
	codexPreToolUse  = `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{"command":["echo","ok"]}}`
	cursorEvent      = `{"conversation_id":"c","generation_id":"g","hook_event_name":"beforeShellExecution","cursor_version":"1.7.0","command":"echo ok"}`
	hookPostRequest  = `{"path":"/api/v1/claude-code/hook","headers":{},"body":"{}"}`
	hookPostBadPath  = `{"path":"/api/v1/nowhere","headers":{},"body":"{}"}`
	closedAddr       = "127.0.0.1:1"
)

// argvCases is every entry the slim main keeps: version and identity, the
// launcher guard and Cowork argv, the no-argument Claude Code and Cursor
// starts, the hook, hook-post and notify commands with each hidden flag, and
// the missing-runtime answers. <TMP> is a fresh folder per case.
func argvCases() []argvCase {
	gone := filepath.Join("<TMP>", "gone", "defenseclaw-hook.exe")
	return []argvCase{
		{Name: "version", Args: []string{"--version"}},
		{Name: "version-json", Args: []string{"--version-json"}},
		{Name: "version-json-extra", Args: []string{"--version-json", "extra"}},
		{Name: "no-args-no-stdin", NullStdin: true},
		{Name: "no-args-cursor-event", Stdin: cursorEvent},
		{Name: "no-args-claude-event", Stdin: claudePreToolUse},
		{Name: "no-args-other-json", Stdin: `{"hello":"world"}`},
		{Name: "daemon-command", Args: []string{"start"}},
		{Name: "root-flag", Args: []string{"--bogus"}},
		{Name: "hook-no-connector", Args: []string{"hook"}, Stdin: claudePreToolUse},
		{Name: "hook-unknown-flag", Args: []string{"hook", "--connector", "claudecode", "--bogus"}, Stdin: claudePreToolUse},
		{Name: "hook-stray-arg", Args: []string{"hook", "--connector", "claudecode", "stray"}, Stdin: claudePreToolUse},
		{Name: "hook-bad-surface", Args: []string{"hook", "--connector", "claudecode", "--hook-surface", "v3"}, Stdin: claudePreToolUse},
		{Name: "hook-unknown-connector", Args: []string{"hook", "--connector", "nosuchagent", "--event", "PreToolUse", "--api-addr", closedAddr}, Stdin: claudePreToolUse},
		{Name: "hook-claude-no-gateway", Args: []string{"hook", "--connector", "claudecode", "--event", "PreToolUse", "--api-addr", closedAddr}, Stdin: claudePreToolUse},
		{Name: "hook-claude-gateway-down", Args: []string{"hook", "--connector", "claudecode", "--event", "PreToolUse", "--api-addr", closedAddr}, Stdin: claudePreToolUse, DataDir: true},
		{Name: "hook-codex-gateway-down", Args: []string{"hook", "--connector", "codex", "--event", "PreToolUse", "--api-addr", closedAddr}, Stdin: codexPreToolUse, DataDir: true},
		{Name: "hook-claude-fail-open", Args: []string{"hook", "--connector", "claudecode", "--event", "PreToolUse", "--api-addr", closedAddr, "--fail-mode", "open"}, Stdin: claudePreToolUse},
		{Name: "hook-claude-contract", Args: []string{"hook", "--connector", "claudecode", "--event", "PreToolUse", "--api-addr", closedAddr, "--hook-contract", "bogus"}, Stdin: claudePreToolUse},
		{Name: "hook-codex-no-gateway", Args: []string{"hook", "--connector", "codex", "--event", "PreToolUse", "--api-addr", closedAddr}, Stdin: codexPreToolUse},
		{Name: "hook-managed-no-runtime", Args: []string{"hook", "--connector", "claudecode", "--enterprise-managed", "--event", "PreToolUse"}, Stdin: claudePreToolUse},
		{Name: "hook-managed-codex-no-runtime", Args: []string{"hook", "--connector", "codex", "--enterprise-managed", "--event", "PreToolUse"}, Stdin: codexPreToolUse},
		{Name: "hook-hermes-probe", Args: []string{"hook", "--connector", "hermes", "--defenseclaw-execution-probe"}, NullStdin: true},
		{Name: "hook-hermes-probe-extra", Args: []string{"hook", "--connector", "hermes", "--defenseclaw-execution-probe", "--event", "pre_tool_call"}, NullStdin: true},
		{Name: "hook-foreign-check", Args: []string{"hook", "--connector", "amp", "--foreign-hook-check"}, Stdin: `{}`},
		{Name: "hook-input-file", Args: []string{"hook", "--connector", "cursor", "--input-file", filepath.Join("<TMP>", "event.json")}, NullStdin: true},
		{Name: "hook-resolve-writes", Args: []string{"hook", "resolve-writes"}, Stdin: `{}`},
		{Name: "hook-session-facts", Args: []string{"hook", "session-facts"}, NullStdin: true, MaskStdout: true},
		{Name: "hook-post-no-addr", Args: []string{"hook-post"}, Stdin: hookPostRequest},
		{Name: "hook-post-bad-time", Args: []string{"hook-post", "--api-addr", closedAddr, "--max-time", "0"}, Stdin: hookPostRequest},
		{Name: "hook-post-unknown-flag", Args: []string{"hook-post", "--api-addr", closedAddr, "--bogus"}, Stdin: hookPostRequest},
		{Name: "hook-post-bad-int", Args: []string{"hook-post", "--api-addr", closedAddr, "--max-time", "soon"}, Stdin: hookPostRequest},
		{Name: "hook-post-stray-arg", Args: []string{"hook-post", "--api-addr", closedAddr, "stray"}, Stdin: hookPostRequest},
		{Name: "hook-post-no-gateway", Args: []string{"hook-post", "--api-addr", closedAddr, "--curl-output"}, Stdin: hookPostRequest},
		{Name: "hook-post-no-gateway-json", Args: []string{"hook-post", "--api-addr", closedAddr}, Stdin: hookPostRequest},
		{Name: "hook-post-bad-path", Args: []string{"hook-post", "--api-addr", closedAddr}, Stdin: hookPostBadPath},
		{Name: "notify-no-payload", Args: []string{"notify"}, NullStdin: true},
		{Name: "notify-unknown-flag", Args: []string{"notify", "--bogus", `{}`}, NullStdin: true},
		{Name: "guard-missing-launcher", Args: []string{hookguard.Subcommand, gone, "hook", "--connector", "claudecode"}, Stdin: claudePreToolUse},
		{Name: "guard-wrapped-missing-launcher", Args: []string{hookguard.WrappedSubcommand, gone, "hook", "--connector", "claudecode", "--enterprise-managed", "--event", "PreToolUse"}, Stdin: claudePreToolUse},
		{Name: "guard-open-missing-launcher", Args: []string{hookguard.Subcommand, gone, "hook", "--connector", "claudecode", "--event", "PreToolUse", "--unavailable-mode", "open"}, Stdin: claudePreToolUse},
		{Name: "guard-other-connector", Args: []string{hookguard.Subcommand, gone, "hook", "--connector", "codex"}, Stdin: claudePreToolUse},
		{Name: "cowork-missing-launcher", Args: []string{hookguard.CoworkSubcommand, filepath.Join("<TMP>", ".defenseclaw"), gone, "PreToolUse"}, Stdin: claudePreToolUse},
	}
}

// TestHookArgvGoldenHelper is the child process that runs main with the
// case argv. A main that returns ends the process with 0, as the binary does.
func TestHookArgvGoldenHelper(t *testing.T) {
	raw, ok := os.LookupEnv(argvGoldenHelperEnv)
	if !ok {
		t.Skip("helper process")
	}
	os.Args = os.Args[:1]
	if raw != "" {
		os.Args = append(os.Args, strings.Split(raw, "\x1f")...)
	}
	main()
	os.Exit(0)
}

// argvEnv is a clean environment rooted in dir: no DefenseClaw variables,
// no account data directory, no installed runtime.
func argvEnv(dir string) []string {
	home := filepath.Join(dir, "home")
	_ = os.MkdirAll(home, 0o700)
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home}
	if runtime.GOOS == "windows" {
		for _, name := range []string{"SystemRoot", "windir", "ComSpec", "SystemDrive", "PATHEXT", "ProgramData", "ProgramFiles"} {
			if value, ok := os.LookupEnv(name); ok {
				env = append(env, name+"="+value)
			}
		}
		env = append(env, "USERPROFILE="+home, "APPDATA="+filepath.Join(home, "AppData", "Roaming"),
			"LOCALAPPDATA="+filepath.Join(home, "AppData", "Local"), "TEMP="+dir, "TMP="+dir)
	} else {
		env = append(env, "TMPDIR="+dir)
	}
	return env
}

func runArgvCase(t *testing.T, binary string, tc argvCase) argvResult {
	t.Helper()
	dir := t.TempDir()
	if tc.DataDir {
		if err := os.MkdirAll(filepath.Join(dir, "home", ".defenseclaw"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	args := make([]string, len(tc.Args))
	for i, arg := range tc.Args {
		args[i] = strings.ReplaceAll(arg, "<TMP>", dir)
	}
	var cmd *exec.Cmd
	env := argvEnv(dir)
	if binary == "" {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd = exec.Command(self, "-test.run=^TestHookArgvGoldenHelper$")
		env = append(env, argvGoldenHelperEnv+"="+strings.Join(args, "\x1f"))
	} else {
		cmd = exec.Command(binary, args...)
	}
	cmd.Env = env
	cmd.Dir = dir
	if !tc.NullStdin {
		cmd.Stdin = strings.NewReader(tc.Stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("%s: %v", tc.Name, err)
	}
	result := argvResult{Name: tc.Name, Exit: code, Stdout: normalizeArgvOutput(stdout.String(), dir), Stderr: normalizeArgvOutput(stderr.String(), dir)}
	if tc.MaskStdout && result.Stdout != "" {
		result.Stdout = "<masked>"
	}
	return result
}

// argvEventID is the per-refusal event id a hook prints.
var argvEventID = regexp.MustCompile(`event_id=[0-9a-f-]{36}`)

// normalizeArgvOutput replaces the per-case folder, in every spelling a
// path can take on this OS, with <TMP>, the account home (a managed hook
// takes it from the account database, not from HOME) with <HOME>, and the
// event id of a refusal with <ID>.
func normalizeArgvOutput(text, dir string) string {
	text = argvEventID.ReplaceAllString(text, "event_id=<ID>")
	forms := []string{dir}
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		forms = append(forms, real)
	}
	for _, form := range append([]string(nil), forms...) {
		forms = append(forms, filepath.ToSlash(form), strings.ReplaceAll(form, `\`, `\\`))
	}
	for _, form := range forms {
		if form != "" {
			text = strings.ReplaceAll(text, form, "<TMP>")
		}
	}
	if account, err := user.Current(); err == nil && len(account.HomeDir) > 1 {
		for _, form := range []string{account.HomeDir, filepath.ToSlash(account.HomeDir), strings.ReplaceAll(account.HomeDir, `\`, `\\`)} {
			text = strings.ReplaceAll(text, form, "<HOME>")
		}
	}
	return strings.ReplaceAll(text, "\r\n", "\n")
}

// The slim main answers every entry exactly as the full-CLI main did: same
// exit code, stdout and stderr (DESIGN 16.5 test 3).
func TestArgvGoldenMatchesTheFullCLIMain(t *testing.T) {
	golden := filepath.Join("testdata", "argv-golden-"+runtime.GOOS+".json")
	if compare := os.Getenv(argvGoldenCompareEnv); compare != "" {
		for _, tc := range argvCases() {
			want, got := runArgvCase(t, compare, tc), runArgvCase(t, "", tc)
			if got != want {
				t.Errorf("%s:\n got exit %d stdout %q stderr %q\nwant exit %d stdout %q stderr %q", got.Name, got.Exit, got.Stdout, got.Stderr, want.Exit, want.Stdout, want.Stderr)
			}
		}
		return
	}
	record := os.Getenv(argvGoldenRecordEnv)
	var results []argvResult
	for _, tc := range argvCases() {
		results = append(results, runArgvCase(t, record, tc))
	}
	if record != "" {
		body, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, append(body, 10), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("recorded %d cases from %s into %s", len(results), record, golden)
		return
	}
	body, err := os.ReadFile(golden)
	if os.IsNotExist(err) && runtime.GOOS != "linux" {
		// The answers of the managed and per-user entries depend on what the
		// host has installed, so the golden is the Linux one; on Windows and
		// macOS the slim main was compared with the full-CLI main on the test
		// hosts (argvGoldenCompareEnv).
		t.Skipf("no golden for %s; compare on a host with %s=<full-CLI defenseclaw-hook>", runtime.GOOS, argvGoldenCompareEnv)
	}
	if err != nil {
		t.Fatalf("no golden for %s (record it with %s=<full-CLI defenseclaw-hook>): %v", runtime.GOOS, argvGoldenRecordEnv, err)
	}
	var want []argvResult
	if err := json.Unmarshal(body, &want); err != nil {
		t.Fatal(err)
	}
	byName := map[string]argvResult{}
	for _, w := range want {
		byName[w.Name] = w
	}
	for _, got := range results {
		w, ok := byName[got.Name]
		if !ok {
			t.Errorf("%s: no golden entry", got.Name)
			continue
		}
		if got != w {
			t.Errorf("%s:\n got exit %d stdout %q stderr %q\nwant exit %d stdout %q stderr %q", got.Name, got.Exit, got.Stdout, got.Stderr, w.Exit, w.Stdout, w.Stderr)
		}
	}
	if len(want) != len(results) {
		t.Errorf("golden has %d entries, the table %d", len(want), len(results))
	}
}
