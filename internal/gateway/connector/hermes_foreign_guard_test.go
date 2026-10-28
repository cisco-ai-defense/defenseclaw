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

func TestHermesOutageBlockExplainsRecoveryByProfile(t *testing.T) {
	asset, err := hookFS.ReadFile("hooks/hermes-hook.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data templateData
		want string
		omit string
	}{
		// Per-user and managed outages print hermes_block_message, which names
		// the cause and the next step at run time (per-user: defenseclaw-gateway
		// start or status; managed: the gateway service and the administrator;
		// TestPerUserHermesHookBlocksAToolCallWhileTheGatewayIsDown,
		// TestManagedStandaloneHermesHookBlockSaysWhy).
		{"per-user", templateData{}, "hermes_block transport \"$1\"", "DefenseClaw hook failed closed"},
		{"managed", templateData{Managed: true}, "hermes_block transport \"$1\"", "DefenseClaw hook failed closed"},
		{"secure-client", templateData{Managed: true, SecureClient: true}, "DefenseClaw hook failed closed", "hermes_block transport"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook, err := renderTemplate(string(asset), tc.data)
			if err != nil {
				t.Fatal(err)
			}
			start := strings.Index(hook, "fail_unreachable() {")
			if start < 0 {
				t.Fatal("rendered Hermes outage handler missing")
			}
			end := strings.Index(hook[start:], "fail_response() {")
			if end < 0 {
				t.Fatal("rendered Hermes outage handler missing")
			}
			block := hook[start : start+end]
			if !strings.Contains(block, tc.want) || strings.Contains(block, tc.omit) {
				t.Fatalf("outage block for %s has wrong recovery text: %s", tc.name, block)
			}
			if tc.name == "secure-client" && !strings.Contains(block, "if defenseclaw_should_fail_closed_on_unreachable; then\n    printf '{\"action\":\"block\",\"message\":\"DefenseClaw hook failed closed\"}\\n'\n    exit 2\n") {
				t.Fatal("Secure Client outage block changed its rendered bytes")
			}
		})
	}
}

// The foreign-hook guard renders to nothing when the guard is off (its
// directive in hermes-hook.sh and its place in the socket transport), so
// every Hermes hook other than the Linux and macOS standalone one (per-user,
// Secure Client, Windows) keeps its exact bytes.
func TestHermesHookRendersUnchangedWithoutTheForeignHookGuard(t *testing.T) {
	content, err := hookFS.ReadFile("hooks/hermes-hook.sh")
	if err != nil {
		t.Fatal(err)
	}
	current := string(content)
	previous := strings.Replace(current, "{{if .ForeignHookGuardSH}}DEFENSECLAW_GUARD_AGENT_HOME=\"$HOME\"\n{{end}}", "", 1)
	if previous == current || strings.Contains(previous, "ForeignHookGuardSH") {
		t.Fatal("hermes-hook.sh no longer carries the foreign-hook guard directive this test removes")
	}
	if !strings.Contains(shellHookSocketTransportBlock, "@GUARD@") ||
		shellHookSocketTransport("/var/run/defenseclaw/hook.sock", 461, "", "") != strings.Replace(renderShellHookSocket(strings.Replace(shellHookSocketTransportBlock, "@GUARD@", "", 1), "/var/run/defenseclaw/hook.sock", 461), "@FACTS@", "", 1) {
		t.Fatal("the socket transport without the guard differs from its render without the guard placeholder")
	}
	for _, data := range []templateData{
		{APIAddr: "127.0.0.1:18970", FailMode: "closed", TokenFile: ".token"},
		{APIAddr: "127.0.0.1:18970", FailMode: "closed", Managed: true, TokenFile: ".token-hermes", ScopedToken: true, ConnectorName: "hermes"},
		{APIAddr: "127.0.0.1:18970", FailMode: "closed", Managed: true, TokenFile: ".token-hermes", ScopedToken: true, ConnectorName: "hermes",
			HookSocketTransportSH: shellHookSocketTransport("/var/run/defenseclaw/hook.sock", 461, "", "")},
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
// socket trust functions, before the socket checks (a stopped gateway's
// missing socket must not end the hook before the guard, GAP-0354) and
// before the gateway request, with the binary as one shell word.
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
	trust := strings.Index(hook, "defenseclaw_hook_socket_trusted() {")
	guard := strings.Index(hook, "DEFENSECLAW_FOREIGN_GUARD=")
	missing := strings.Index(hook, `if [ ! -e "$DEFENSECLAW_HOOK_SOCKET" ]`)
	socket := strings.Index(hook, "\nif ! defenseclaw_hook_socket_trusted; then")
	request := strings.Index(hook, "RESPONSE=$(defenseclaw_hook_post)")
	if capture < 0 || hardening < capture || trust < hardening || guard < trust || missing < guard || socket < missing || request < socket {
		t.Fatalf("guard order: agent HOME %d, hardening %d, socket trust functions %d, guard %d, missing-socket check %d, socket trust check %d, request %d",
			capture, hardening, trust, guard, missing, socket, request)
	}
	if strings.Count(hook, "DEFENSECLAW_FOREIGN_GUARD=") != 1 {
		t.Fatal("the standalone Hermes hook renders the guard more than once")
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
	// A managed hook also runs this binary for `hook session-facts` (on macOS
	// always); that read is not a guard run, so the stub records only guard runs.
	script := "#!/bin/bash\n" +
		"[ \"$*\" = \"hook session-facts\" ] && exit 0\n" +
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

// GAP-0354: a stopped gateway removes the hook socket, and the socket checks
// end the hook in fail_unreachable, which allows under fail mode open. The
// standalone Hermes hook runs the foreign-hook guard before those checks, so
// the guard's check (which denies a guarded connector whose session the
// gateway cannot answer for, in every fail mode) blocks the tool call with
// its Hermes block object under fail mode open and closed alike. A check
// that allows (foreign_hooks report, or the guard off) leaves the outage to
// the hook's fail mode, as before.
func TestStandaloneHermesHookRunsTheGuardWhileTheGatewayIsStopped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Hermes shell hook is not used on Windows")
	}
	root, err := os.MkdirTemp("/tmp", "dchs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	runDir := filepath.Join(root, "run")
	if err := os.Mkdir(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The socket's directory is trusted; the socket itself is gone, as when
	// the gateway service and its socket are stopped.
	socketPath := filepath.Join(runDir, "hook.sock")
	guardBinary := filepath.Join(root, "bin", "defenseclaw-hook")
	if err := os.Mkdir(filepath.Dir(guardBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	answerPath := filepath.Join(root, "answer")
	ranPath := filepath.Join(root, "ran")
	script := "#!/bin/bash\n" +
		"[ \"$*\" = \"hook session-facts\" ] && exit 0\n" +
		"cat > /dev/null\n" +
		"printf '%s' \"$*\" > " + shellSingleQuoteForTest(ranPath) + "\n" +
		"cat " + shellSingleQuoteForTest(answerPath) + "\n"
	if err := os.WriteFile(guardBinary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	notRunning := "DefenseClaw blocked this tool call: the DefenseClaw gateway service is not running on this computer. (enterprise_managed_gateway_not_running)"
	deny := `{"deny":true,"reason":"` + notRunning + `","hook_output":{"action":"block","message":"` + notRunning + `"}}`
	block := `{"action":"block","message":"` + notRunning + `"}`
	for _, failMode := range []string{"open", "closed"} {
		t.Run(failMode, func(t *testing.T) {
			agentHome := filepath.Join(root, "home-"+failMode)
			dataDir := filepath.Join(agentHome, ".defenseclaw")
			hookDir := filepath.Join(dataDir, "hooks")
			opts := SetupOpts{
				DataDir:                dataDir,
				APIAddr:                "127.0.0.1:1",
				APIToken:               "tok",
				ManagedEnterprise:      true,
				HookFailMode:           failMode,
				ManagedHookSocket:      socketPath,
				ManagedServiceUID:      os.Getuid(),
				ForeignHookGuardBinary: guardBinary,
			}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewHermesConnector()); err != nil {
				t.Fatal(err)
			}
			hookPath := filepath.Join(hookDir, "hermes-hook.sh")
			if data, err := os.ReadFile(hookPath); err != nil || !strings.Contains(string(data), `FAIL_MODE="`+failMode+`"`) {
				t.Fatalf("the hook was not rendered for fail mode %s: %v", failMode, err)
			}
			bakeHookPathForTest(t, hookPath, "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
			run := func(answer string) (int, string, string) {
				t.Helper()
				_ = os.Remove(ranPath)
				if err := os.WriteFile(answerPath, []byte(answer+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "bash", hookPath)
				cmd.Env = append(os.Environ(), "HOME="+agentHome)
				cmd.Stdin = strings.NewReader(`{"hook_event_name":"pre_tool_call","session_id":"s-1","tool_name":"terminal","tool_input":{"command":"echo marker"}}`)
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				err := cmd.Run()
				code := 0
				if exitErr, ok := err.(*exec.ExitError); ok {
					code = exitErr.ExitCode()
				} else if err != nil {
					t.Fatalf("run hook: %v", err)
				}
				if args, _ := os.ReadFile(ranPath); string(args) != "hook --connector hermes --foreign-hook-check" {
					t.Fatalf("the guard did not run before the socket checks (args %q, stderr %q)", args, stderr.String())
				}
				return code, strings.TrimSpace(stdout.String()), stderr.String()
			}
			if code, stdout, stderr := run(deny); code != 0 || stdout != block || !strings.Contains(stderr, "blocking hermes tool") || strings.Contains(stderr, "allowing") {
				t.Fatalf("the guard's outage denial: exit %d stdout=%q stderr=%q, want its Hermes block", code, stdout, stderr)
			}
			code, stdout, stderr := run(`{"deny":false}`)
			if !strings.Contains(stderr, "enterprise_managed_gateway_not_running") {
				t.Fatalf("an allowed check must reach the missing-socket outage: stderr=%q", stderr)
			}
			if failMode == "open" && (code != 0 || stdout != "") {
				t.Fatalf("open, check allows: exit %d stdout=%q, want the outage allow", code, stdout)
			}
			if failMode == "closed" && (code != 2 || !strings.HasPrefix(stdout, `{"action":"block"`)) {
				t.Fatalf("closed, check allows: exit %d stdout=%q, want the outage block", code, stdout)
			}
		})
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
