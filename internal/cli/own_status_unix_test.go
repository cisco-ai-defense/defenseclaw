// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// cowork-1-0-8 GAP-0053: on a managed computer `defenseclaw status` shows the
// standard user their own protection state from the hook socket, instead of
// refusing; --json keeps deployment_mode managed_enterprise, which the
// quickstart's stop rule reads.
func TestLauncherStatusShowsOwnState(t *testing.T) {
	previousSocket, previousFetch := ownProfileExplainSocket, ownStatusFetch
	t.Cleanup(func() { ownProfileExplainSocket, ownStatusFetch = previousSocket, previousFetch })
	ownProfileExplainSocket = func() string { return "/run/defenseclaw/hook.sock" }
	answer := `{"own":true,"managed":true,"managed_by":"your organization","account":{"uid":"5001","name":"alice"},` +
		`"claude_code":{"protected":true},"connectors":{"claudecode":{"protected":true},"codex":{"protected":true},"opencode":{"protected":false}},` +
		`"cowork":{"protected":true,"state":"protected: Cowork runs the Claude Code hooks your organization manages","last_event_at":"2026-11-04T09:00:00Z"}}`
	fetched := 0
	ownStatusFetch = func(_ context.Context, socket string) (int, []byte, error) {
		fetched++
		if socket != "/run/defenseclaw/hook.sock" {
			t.Fatalf("socket %q", socket)
		}
		return http.StatusOK, []byte(answer), nil
	}
	run := func(args ...string) (int, string, string) {
		var ran []string
		root := launcherTestRoot(&ran)
		var stdout, stderr bytes.Buffer
		root.SetOut(&stdout)
		root.SetErr(&stderr)
		code := executeLauncherInTest(t, root, args)
		if len(ran) != 0 {
			t.Fatalf("%v ran the gateway's %v", args, ran)
		}
		return code, stdout.String(), stderr.String()
	}
	code, stdout, stderr := run("status")
	if code != 0 || !strings.Contains(stdout, "This computer is managed by your organization.") ||
		!strings.Contains(stdout, "alice (uid 5001)") || !strings.Contains(stdout, "Claude Code   protected") ||
		!strings.Contains(stdout, "Cowork        protected") || !strings.Contains(stdout, "Codex         protected") ||
		!strings.Contains(stdout, "OpenCode      not protected") || strings.Contains(stdout, "none from you yet") {
		t.Fatalf("status = %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	originalAnswer := answer
	answer = `{"own":true,"managed":true,"account":{"uid":"5001","name":"alice"},` +
		`"claude_code":{"protected":false},"connectors":{"codex":{"protected":true,"state":"protected"}},` +
		`"cowork":{"protected":false,"state":"not protected"}}`
	code, stdout, stderr = run("status")
	if code != 0 || !strings.Contains(stdout, "Codex         protected") || strings.Contains(stdout, "Claude Code   ") {
		t.Fatalf("Codex-only status = %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	answer = originalAnswer
	code, stdout, _ = run("status", "--json")
	var out map[string]any
	if code != 0 || json.Unmarshal([]byte(stdout), &out) != nil || out["deployment_mode"] != "managed_enterprise" || out["own"] != true {
		t.Fatalf("status --json = %d %s", code, stdout)
	}
	if code, _, stderr := run("status", "--user", "bob"); code == 0 || fetched != 3 {
		t.Fatalf("status --user is not a launcher flag: exit %d %s", code, stderr)
	}

	// A gateway that refuses or does not answer is an error, and the JSON
	// still says the computer is managed.
	ownStatusFetch = func(context.Context, string) (int, []byte, error) {
		return http.StatusForbidden, []byte(`{"error":"peer_unverified"}`), nil
	}
	code, stdout, _ = run("status", "--json")
	out = nil
	if code == 0 || json.Unmarshal([]byte(stdout), &out) != nil || out["deployment_mode"] != "managed_enterprise" || out["error"] == nil {
		t.Fatalf("refused status --json = %d %s", code, stdout)
	}
	ownProfileExplainSocket = func() string { return "" }
	if code, _, stderr := run("status"); code == 0 || !strings.Contains(stderr, "hook socket is not available") {
		t.Fatalf("status without a hook socket = %d %s", code, stderr)
	}
}

// The reported row: a connector on the roster that is not installed for the
// account prints its reason and next step in `defenseclaw status`, like the
// OpenCode row; an older gateway that sends a bare state gets one too.
func TestLauncherStatusSaysWhyEveryNotProtectedConnectorIsNotProtected(t *testing.T) {
	previousSocket, previousFetch := ownProfileExplainSocket, ownStatusFetch
	t.Cleanup(func() { ownProfileExplainSocket, ownStatusFetch = previousSocket, previousFetch })
	ownProfileExplainSocket = func() string { return "/run/defenseclaw/hook.sock" }
	answer := `{"own":true,"managed":true,"account":{"uid":"507","name":"alice"},` +
		`"claude_code":{"protected":true},"connectors":{"claudecode":{"protected":true,"state":"protected"},` +
		`"hermes":{"protected":false,"state":"not protected: DefenseClaw has not set up protection for this agent on your account. Install it, or ask IT"},` +
		`"copilot":{"protected":false},"opencode":{"protected":false,"state":"not confirmed"}},` +
		`"cowork":{"protected":true,"state":"protected: Cowork runs the Claude Code hooks your organization manages"}}`
	ownStatusFetch = func(context.Context, string) (int, []byte, error) { return http.StatusOK, []byte(answer), nil }
	var ran []string
	root := launcherTestRoot(&ran)
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	if code := executeLauncherInTest(t, root, []string{"status"}); code != 0 {
		t.Fatalf("status = %d\nstdout %s\nstderr %s", code, stdout.String(), stderr.String())
	}
	for _, line := range strings.Split(stdout.String(), "\n") {
		for _, label := range []string{"Hermes", "Copilot", "OpenCode"} {
			if !strings.HasPrefix(strings.TrimSpace(line), label) {
				continue
			}
			if !strings.Contains(line, "not ") || !strings.Contains(line, ": ") || !strings.Contains(line, "ask IT") && !strings.Contains(line, "Ask IT") {
				t.Fatalf("%s line says no reason and next step: %q", label, line)
			}
		}
	}
	for _, want := range []string{"Claude Code   protected\n", "Hermes        not protected: DefenseClaw has not set up protection for this agent on your account."} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("status lacks %q:\n%s", want, stdout.String())
		}
	}
}

// The gateway keeps each row state to one word and sends the reason and the
// next step in their own fields. `defenseclaw status` prints them after the
// state, and `defenseclaw status --json` hands the answer on unchanged, so a
// script that matches the state keeps working.
func TestLauncherStatusKeepsJSONStateAndPrintsSeparateReason(t *testing.T) {
	previousSocket, previousFetch := ownProfileExplainSocket, ownStatusFetch
	t.Cleanup(func() { ownProfileExplainSocket, ownStatusFetch = previousSocket, previousFetch })
	ownProfileExplainSocket = func() string { return "/run/defenseclaw/hook.sock" }
	answer := `{"own":true,"managed":true,"account":{"uid":"507","name":"alice"},` +
		`"claude_code":{"protected":true},"connectors":{"claudecode":{"protected":true,"state":"protected"},` +
		`"hermes":{"protected":false,"state":"not protected","reason_code":"no_setup","reason":"DefenseClaw has not set up protection for this agent on your account","next_step":"Install it, or ask IT"},` +
		`"opencode":{"protected":false,"state":"not confirmed","reason_code":"scan_unknown","reason":"DefenseClaw has no recent protection check for this computer","next_step":"Run defenseclaw status again in a few minutes, and ask IT if it stays this way"}},` +
		`"cowork":{"protected":true,"state":"protected","reason_code":"cowork_hooks","reason":"Cowork runs the Claude Code hooks your organization manages"}}`
	ownStatusFetch = func(context.Context, string) (int, []byte, error) { return http.StatusOK, []byte(answer), nil }
	run := func(args ...string) string {
		var ran []string
		root := launcherTestRoot(&ran)
		var stdout, stderr bytes.Buffer
		root.SetOut(&stdout)
		root.SetErr(&stderr)
		if code := executeLauncherInTest(t, root, args); code != 0 {
			t.Fatalf("%v = %d\nstdout %s\nstderr %s", args, code, stdout.String(), stderr.String())
		}
		return stdout.String()
	}
	text := run("status")
	for _, want := range []string{
		"  Claude Code   protected\n",
		"  Hermes        not protected: DefenseClaw has not set up protection for this agent on your account. Install it, or ask IT\n",
		"  OpenCode      not confirmed: DefenseClaw has no recent protection check for this computer. Run defenseclaw status again in a few minutes, and ask IT if it stays this way\n",
		"  Cowork        protected: Cowork runs the Claude Code hooks your organization manages\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("status lacks %q:\n%s", want, text)
		}
	}
	var out struct {
		Connectors map[string]ownStatusRow `json:"connectors"`
	}
	if err := json.Unmarshal([]byte(run("status", "--json")), &out); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"claudecode": "protected", "hermes": "not protected", "opencode": "not confirmed"} {
		if got := out.Connectors[name].State; got != want {
			t.Fatalf("status --json %s state = %q, want %q", name, got, want)
		}
	}
	if row := out.Connectors["hermes"]; row.ReasonCode != "no_setup" || row.Reason == "" || row.NextStep == "" {
		t.Fatalf("status --json hermes row = %+v, want the reason code, reason and next step in their own fields", row)
	}
}
