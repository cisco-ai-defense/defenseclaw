// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const hermesGuardTestBinary = "/opt/cisco/defenseclaw/bin/defenseclaw-hook"

// The foreign-hook guard directives in hermes-hook.sh render to nothing when
// the guard is off, so every Hermes hook other than the Linux and macOS
// standalone one (per-user, Secure Client, Windows) keeps its exact bytes.
func TestHermesHookRendersUnchangedWithoutTheForeignHookGuard(t *testing.T) {
	content, err := hookFS.ReadFile("hooks/hermes-hook.sh")
	if err != nil {
		t.Fatal(err)
	}
	current := string(content)
	previous := strings.Replace(current, "{{if .ForeignHookGuardSH}}DEFENSECLAW_GUARD_AGENT_HOME=\"$HOME\"\n{{end}}", "", 1)
	previous = strings.Replace(previous, "{{.ForeignHookGuardSH}}", "", 1)
	if previous == current || strings.Contains(previous, "ForeignHookGuardSH") {
		t.Fatal("hermes-hook.sh no longer carries the two foreign-hook guard directives this test removes")
	}
	for _, data := range []templateData{
		{APIAddr: "127.0.0.1:18970", FailMode: "closed", TokenFile: ".token"},
		{APIAddr: "127.0.0.1:18970", FailMode: "closed", Managed: true, TokenFile: ".token-hermes", ScopedToken: true, ConnectorName: "hermes"},
		{APIAddr: "127.0.0.1:18970", FailMode: "closed", Managed: true, TokenFile: ".token-hermes", ScopedToken: true, ConnectorName: "hermes",
			HookSocketTransportSH: shellHookSocketTransport("/var/run/defenseclaw/hook.sock", 461)},
	} {
		want, err := renderTemplate(previous, data)
		if err != nil {
			t.Fatal(err)
		}
		got, err := renderTemplate(current, data)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("hermes-hook.sh without the guard differs from its previous render (socket=%v)", data.HookSocketTransportSH != "")
		}
	}
}

// Only the Hermes hook of a standalone install with a hook socket and an
// administrator-owned hook binary renders the guard; it runs after the
// socket check and before the gateway request, with the binary as one
// shell word.
func TestOnlyTheStandaloneHermesHookRendersTheForeignHookGuard(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Hermes shell hook is not used on Windows")
	}
	standalone := SetupOpts{
		APIAddr:                "127.0.0.1:18970",
		APIToken:               "tok",
		ManagedEnterprise:      true,
		HookFailMode:           "closed",
		ManagedHookSocket:      "/var/run/defenseclaw/hook.sock",
		ManagedServiceUID:      461,
		ForeignHookGuardBinary: "/opt/cisco/defense'claw/bin/defenseclaw-hook",
	}
	render := func(opts SetupOpts, conn Connector, script string) string {
		t.Helper()
		opts.DataDir = filepath.Join(t.TempDir(), ".defenseclaw")
		hookDir := filepath.Join(opts.DataDir, "hooks")
		if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(hookDir, script))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	hook := render(standalone, NewHermesConnector(), "hermes-hook.sh")
	if !strings.Contains(hook, "DEFENSECLAW_FOREIGN_GUARD='/opt/cisco/defense'\"'\"'claw/bin/defenseclaw-hook'\n") ||
		!strings.Contains(hook, `"$DEFENSECLAW_FOREIGN_GUARD" hook --connector hermes --foreign-hook-check`) {
		t.Fatal("the standalone Hermes hook does not run the guard binary as one shell word")
	}
	capture := strings.Index(hook, `DEFENSECLAW_GUARD_AGENT_HOME="$HOME"`)
	hardening := strings.Index(hook, "defenseclaw_harden_env\n")
	socket := strings.Index(hook, "if ! defenseclaw_hook_socket_trusted; then")
	guard := strings.Index(hook, "DEFENSECLAW_FOREIGN_GUARD=")
	request := strings.Index(hook, "RESPONSE=$(curl")
	if capture < 0 || hardening < capture || socket < 0 || guard < socket || request < guard {
		t.Fatalf("guard order: agent HOME %d, hardening %d, socket check %d, guard %d, request %d", capture, hardening, socket, guard, request)
	}

	noGuard := standalone
	noGuard.ForeignHookGuardBinary = ""
	perUser := standalone
	perUser.ManagedHookSocket, perUser.ManagedServiceUID, perUser.ManagedEnterprise = "", 0, false
	noSocket := standalone
	noSocket.ManagedHookSocket = ""
	for name, opts := range map[string]SetupOpts{"no guard binary": noGuard, "per-user": perUser, "no hook socket": noSocket} {
		if hook := render(opts, NewHermesConnector(), "hermes-hook.sh"); strings.Contains(hook, "foreign-hook-check") || strings.Contains(hook, "DEFENSECLAW_GUARD_AGENT_HOME") {
			t.Fatalf("%s: the Hermes hook rendered the guard", name)
		}
	}
	if hook := render(standalone, NewOpenHandsConnector(), "openhands-hook.sh"); strings.Contains(hook, "foreign-hook-check") {
		t.Fatal("another connector's shell hook rendered the Hermes guard")
	}
}

// A standalone Hermes hook rendered before it ran the guard (or for another
// hook binary) is a repair signal; the install's own lock is not.
func TestHookForeignGuardDriftedFollowsTheRenderedGuard(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Hermes shell hook is not used on Windows")
	}
	opts := SetupOpts{
		DataDir:                t.TempDir(),
		ManagedEnterprise:      true,
		ManagedHookSocket:      "/var/run/defenseclaw/hook.sock",
		ManagedServiceUID:      461,
		ForeignHookGuardBinary: hermesGuardTestBinary,
	}
	lock := NewHookContractLockEntry(opts, NewHermesConnector(), "test")
	if lock.RegistrationPosture == nil || lock.RegistrationPosture.ForeignHookGuard != hermesGuardTestBinary {
		t.Fatalf("the lock does not record the rendered guard: %+v", lock.RegistrationPosture)
	}
	if HookForeignGuardDrifted(lock, opts) {
		t.Fatal("the install's own lock drifted")
	}
	before := lock
	posture := *lock.RegistrationPosture
	posture.ForeignHookGuard = ""
	before.RegistrationPosture = &posture
	if !HookForeignGuardDrifted(before, opts) {
		t.Fatal("a Hermes hook rendered without the guard must be repaired")
	}
	other := opts
	other.ForeignHookGuardBinary = "/usr/local/bin/defenseclaw-hook"
	if !HookForeignGuardDrifted(lock, other) {
		t.Fatal("a Hermes hook rendered for another guard binary must be repaired")
	}
	devin := NewHookContractLockEntry(opts, NewDevinConnector(), "test")
	if devin.RegistrationPosture.ForeignHookGuard != "" || HookForeignGuardDrifted(devin, opts) {
		t.Fatalf("only the Hermes shell hook records a guard: %+v", devin.RegistrationPosture)
	}
}

// TestStandaloneHermesHookBlocksWhileTheForeignHookGuardDenies runs the
// rendered standalone Hermes hook against a stand-in for the
// administrator-owned hook binary. A pre_tool_call the guard denies is
// blocked with the Hermes block object the guard rendered and never reaches
// the gateway; any answer but an explicit allow blocks too, and a check that
// gives no decision is named in the block and reported to the gateway's
// session route for its audit row. An allowed call, a session start (which
// cannot be blocked) and events that cannot change a tool call reach the
// gateway as before; only tool calls and session starts run the guard, with
// the agent's own HOME and without the hook's address-space limit.
func TestStandaloneHermesHookBlocksWhileTheForeignHookGuardDenies(t *testing.T) {
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl is required to run shell hooks")
	}
	f := newHookSocketFixture(t, "dchg", nil)
	root, socketPath, gateway := f.root, f.socket, f.gateway

	// The stand-in records what the hook passed and prints the answer file.
	stub := filepath.Join(root, "stub")
	if err := os.Mkdir(stub, 0o755); err != nil {
		t.Fatal(err)
	}
	guardBinary := filepath.Join(root, "bin", "defenseclaw-hook")
	if err := os.Mkdir(filepath.Dir(guardBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/bash\n" +
		"printf '%s' \"$HOME\" > " + shellSingleQuoteForTest(filepath.Join(stub, "home")) + "\n" +
		"printf '%s' \"$*\" > " + shellSingleQuoteForTest(filepath.Join(stub, "args")) + "\n" +
		"{ ulimit -S -v; ulimit -H -v; } > " + shellSingleQuoteForTest(filepath.Join(stub, "vlimit")) + "\n" +
		"[ -e " + shellSingleQuoteForTest(filepath.Join(stub, "noread")) + " ] || cat > " + shellSingleQuoteForTest(filepath.Join(stub, "stdin")) + "\n" +
		"cat " + shellSingleQuoteForTest(filepath.Join(stub, "answer")) + " 2>/dev/null\n" +
		"exit \"$(cat " + shellSingleQuoteForTest(filepath.Join(stub, "rc")) + " 2>/dev/null || echo 0)\"\n"
	if err := os.WriteFile(guardBinary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	agentHome := filepath.Join(root, "home")
	dataDir := filepath.Join(agentHome, ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	opts := SetupOpts{
		DataDir:                dataDir,
		APIAddr:                "127.0.0.1:1",
		APIToken:               "tok",
		ManagedEnterprise:      true,
		HookFailMode:           "closed",
		ManagedHookSocket:      socketPath,
		ManagedServiceUID:      os.Getuid(),
		ForeignHookGuardBinary: guardBinary,
	}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewHermesConnector()); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(hookDir, "hermes-hook.sh")
	bakeHookPathForTest(t, hookPath, filepath.Dir(curlPath)+":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")

	answer := func(body string, rc int) {
		t.Helper()
		for _, name := range []string{"home", "args", "stdin"} {
			_ = os.Remove(filepath.Join(stub, name))
		}
		if err := os.WriteFile(filepath.Join(stub, "answer"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stub, "rc"), []byte(strconv.Itoa(rc)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var runPayload func(string) (int, string, string, string)
	requests := func() int {
		paths, _, _ := gateway.recorded()
		return len(paths)
	}
	run := func(event string) (int, string, string, string) {
		t.Helper()
		return runPayload(`{"hook_event_name":"` + event + `","session_id":"s-1","tool_name":"terminal","tool_input":{"command":"echo marker"}}`)
	}
	runPayload = func(payload string) (int, string, string, string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", hookPath)
		cmd.Env = append(os.Environ(), "HOME="+agentHome)
		cmd.Stdin = strings.NewReader(payload)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		code := 0
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else if err != nil {
			t.Fatalf("run hook: %v", err)
		}
		return code, strings.TrimSpace(stdout.String()), stderr.String(), payload
	}
	stubRead := func(name string) (string, bool) {
		data, err := os.ReadFile(filepath.Join(stub, name))
		return string(data), err == nil
	}

	// Denied: the guard's own block object, no gateway request.
	block := `{"action":"block","message":"DefenseClaw blocked this tool call: the user file ` + agentHome + `/.hermes/config.yaml defines a hook (digest sha256:abc). (enterprise_foreign_hook_blocked)"}`
	answer(`{"deny":true,"reason":"enterprise_foreign_hook_blocked: the user file defines a hook","hook_output":`+block+`}`+"\n", 0)
	code, stdout, stderr, payload := run("pre_tool_call")
	if code != 0 || stdout != block {
		t.Fatalf("denied tool call: exit %d stdout=%q stderr=%q, want the guard's block", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "enterprise_foreign_hook_blocked") {
		t.Fatalf("the block reason is not on stderr: %q", stderr)
	}
	if n := requests(); n != 0 {
		t.Fatalf("a denied tool call reached the gateway (%d requests)", n)
	}
	if home, _ := stubRead("home"); home != agentHome {
		t.Fatalf("the guard ran with HOME=%q, want the agent's %q", home, agentHome)
	}
	if args, _ := stubRead("args"); args != "hook --connector hermes --foreign-hook-check" {
		t.Fatalf("guard arguments = %q", args)
	}
	if stdin, _ := stubRead("stdin"); strings.TrimSuffix(stdin, "\n") != payload {
		t.Fatalf("the guard did not get the Hermes payload: %q", stdin)
	}
	// The check is a Go program, which cannot start under the hook's
	// address-space limit (Linux enforces it): it runs without that limit.
	if limits, _ := stubRead("vlimit"); len(strings.Fields(limits)) != 2 || strings.Fields(limits)[0] != strings.Fields(limits)[1] {
		t.Fatalf("the guard ran under an address-space limit (soft and hard: %q)", limits)
	}

	// No decision (the check exited without an answer): a fixed block that
	// names why, and the block sent to the gateway's session route, which
	// writes its audit row; the tool call itself does not reach the gateway.
	answer("", 2)
	if code, stdout, stderr, _ = run("pre_tool_call"); code != 0 || !strings.HasPrefix(stdout, `{"action":"block","message":"DefenseClaw blocked this tool call`) ||
		!strings.Contains(stdout, "status 2") || !strings.Contains(stderr, "enterprise_foreign_hook_check_failed") {
		t.Fatalf("failed check: exit %d stdout=%q stderr=%q, want a block naming the exit status", code, stdout, stderr)
	}
	paths, _, bodies := gateway.recorded()
	var report struct {
		Key      struct{ Connector, Session string }
		Decision struct {
			Deny   bool
			Reason string
		}
	}
	if len(paths) != 1 || paths[0] != "/api/v1/foreign-hook-session/hermes" || json.Unmarshal([]byte(bodies[0]), &report) != nil ||
		report.Key.Connector != "hermes" || report.Key.Session != "s-1" || !report.Decision.Deny ||
		!strings.HasPrefix(report.Decision.Reason, "enterprise_foreign_hook_check_failed: ") {
		t.Fatalf("failed check: gateway requests %q bodies %q, want one session-route block report", paths, bodies)
	}

	// Allowed: the gateway decides.
	answer(`{"deny":false}`+"\n", 0)
	if code, stdout, stderr, _ = run("pre_tool_call"); code != 0 || !strings.Contains(stdout, "hook-socket") || requests() != 2 {
		t.Fatalf("allowed tool call: exit %d stdout=%q stderr=%q requests=%d", code, stdout, stderr, requests())
	}

	// A session start runs the guard (the gateway records the session) but
	// cannot be blocked.
	answer(`{"deny":true,"reason":"enterprise_foreign_hook_blocked: x","hook_output":`+block+`}`+"\n", 0)
	if code, stdout, stderr, _ = run("on_session_start"); code != 0 || strings.Contains(stdout, `"block"`) || requests() != 3 {
		t.Fatalf("session start: exit %d stdout=%q stderr=%q requests=%d", code, stdout, stderr, requests())
	}
	if _, ran := stubRead("args"); !ran {
		t.Fatal("the session start did not run the guard")
	}

	// A check that answers without reading the payload (the guard is off)
	// still allows a large tool call.
	answer(`{"deny":false}`+"\n", 0)
	if err := os.WriteFile(filepath.Join(stub, "noread"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	large := `{"hook_event_name":"pre_tool_call","session_id":"s-1","tool_name":"write_file","tool_input":{"content":"` + strings.Repeat("x", 100<<10) + `"}}`
	if code, stdout, stderr, _ = runPayload(large); code != 0 || !strings.Contains(stdout, "hook-socket") || requests() != 4 {
		t.Fatalf("large allowed tool call: exit %d stdout=%q stderr=%q requests=%d", code, stdout, stderr, requests())
	}
	if err := os.Remove(filepath.Join(stub, "noread")); err != nil {
		t.Fatal(err)
	}

	// Other events never run the guard.
	answer(`{"deny":true}`+"\n", 0)
	if code, stdout, stderr, _ = run("post_tool_call"); code != 0 || strings.Contains(stdout, `"block"`) || requests() != 5 {
		t.Fatalf("post_tool_call: exit %d stdout=%q stderr=%q requests=%d", code, stdout, stderr, requests())
	}
	if _, ran := stubRead("args"); ran {
		t.Fatal("post_tool_call ran the guard")
	}
}

// The cleanup rewrites only the hooks mapping; every other byte stays.
func TestReplaceTopLevelYAMLFieldKeepsTheRestOfTheFile(t *testing.T) {
	original := []byte("# user settings\nmodel:\n  default: \"x\" # keep\nhooks:\n  pre_tool_call:\n    - command: a\n    - command: b\nterminal:\n  backend: local\n")
	got, err := ReplaceTopLevelYAMLField("config.yaml", original, "hooks", map[string]any{"pre_tool_call": []any{map[string]any{"command": "a"}}})
	if err != nil {
		t.Fatal(err)
	}
	want := "# user settings\nmodel:\n  default: \"x\" # keep\nhooks:\n    pre_tool_call:\n        - command: a\nterminal:\n  backend: local\n"
	if string(got) != want {
		t.Fatalf("rewrite:\n%s\nwant:\n%s", got, want)
	}
}
