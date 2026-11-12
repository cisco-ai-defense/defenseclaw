// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A per-user Codex Bash call on a host where Codex runs its shell commands in
// PowerShell (Windows; pinned here on every OS) that dot-sources, through
// bash -c, a writer behind as many folder links as the system opens in one
// name is blocked on the authorized-keys rule in the default and strict
// packs, well inside the Codex hook window. Its arguments are already the
// plain command shape, so its command is read once as the call tool and once
// as PowerShell: a third reading of the same text took a Windows call to the
// hook deadline, where it failed open in default (GAP-1079). The same
// spelling of an ordinary script behind three links is allowed; it runs
// first, so the timed calls do not pay the first evaluation of the process.
// Outside a race build each writer call is held to 2.5 s on Windows (hosted
// runners are about twice as slow as a test host; the hook client start-up
// takes the rest of the 4 s window) and to 1.5 s plus 25 percent elsewhere.
func TestCodexDotSourcedWriterBehindTheLinkBoundBlocksInsideTheHookWindow(t *testing.T) {
	previous := codexShellRunsPowerShell
	codexShellRunsPowerShell = true
	t.Cleanup(func() { codexShellRunsPowerShell = previous })
	home, _ := r104ReviewHome(t)
	if runtime.GOOS != "windows" {
		resolved, err := filepath.EvalSymlinks(home)
		if err != nil {
			t.Fatal(err)
		}
		home = resolved
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	live := filepath.Join(home, "proj", "live")
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"wk.sh": "echo marker >> ~/.ssh/authorized_keys\n",
		"ok.sh": "echo ordinary >> ~/proj/out.txt\n",
	} {
		if err := os.WriteFile(filepath.Join(live, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	bound := homeLinkChain(t, home, hookpaths.SystemLinkLimit(), live)
	short := homeLinkChain(t, home, 3, live)
	budget, tolerance := 1500*time.Millisecond, "1.5 s plus 25 percent"
	if runtime.GOOS == "windows" {
		budget, tolerance = 2500*time.Millisecond, "inside the Codex hook window"
	} else {
		budget += budget / 4
	}
	rows := []struct {
		name, script string
		strict       bool
		block        bool
	}{
		{"ordinary/default", short + "/ok.sh", false, false},
		{"writer/default", bound + "/wk.sh", false, true},
		{"writer/strict", bound + "/wk.sh", true, true},
	}
	for _, row := range rows {
		command := `bash -c ". ./` + row.script + `"`
		payload := mustJSON(t, map[string]any{"session_id": "chain", "turn_id": "chain", "hook_event_name": "PreToolUse",
			"cwd": home, "model": "x", "permission_mode": "default", "tool_name": "Bash", "tool_use_id": "call_chain",
			"tool_input": map[string]any{"command": command}})
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = "codex"
		if row.strict {
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
		}
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
		recorder := httptest.NewRecorder()
		start := time.Now()
		api.handleAgentHook("codex").ServeHTTP(recorder, req)
		elapsed := time.Since(start)
		body := recorder.Body.String()
		switch {
		case row.block && (!strings.HasPrefix(body, `{"action":"block"`) ||
			!strings.Contains(body, "persistence.ssh_authorized_keys_command")):
			t.Errorf("%s: want a persistence.ssh_authorized_keys_command block, got %.300s", row.name, body)
		case !row.block && !strings.HasPrefix(body, `{"action":"allow"`):
			t.Errorf("%s: want allow, got %.300s", row.name, body)
		}
		t.Logf("%s: answered in %s", row.name, elapsed.Round(time.Millisecond))
		if row.block && !hookAnswerRaceBuild && elapsed > budget {
			t.Errorf("%s: answered in %s, want under %s (%s)", row.name, elapsed.Round(time.Millisecond), budget, tolerance)
		}
	}
}
