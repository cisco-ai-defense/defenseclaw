// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// serviceGatewayStateRow is one Claude Code Bash call. {E} is a folder
// outside the home that holds y, a disk link to ~/.defenseclaw, x, a disk
// link to ~/.ssh, and ok, a plain folder; {EB} is {E} with backslashes (the
// mklink spelling), {EM} {E} as Git Bash spells a drive. rule is the rule a
// blocked row names; "" is an allowed row; rowParity is a row whose verdict
// only has to be the same for the per-user and the service gateway.
type serviceGatewayStateRow struct {
	name, command, rule string
	windowsOnly         bool
}

const rowParity = "parity"

// judgeServiceGatewayStateRows runs rows through the Claude Code hook of a
// per-user action-mode gateway and, on Windows, of the service gateway of a
// managed host, which serves the user by a verified user-scoped identity
// and reads that user's home (the managed runtime home holds hooks/ and the
// hook contract lock). Both give the same verdict for every row.
func judgeServiceGatewayStateRows(t *testing.T, rows []serviceGatewayStateRow) {
	t.Helper()
	home := t.TempDir()
	ext := t.TempDir()
	project := filepath.Join(home, "proj")
	state := filepath.Join(home, ".defenseclaw")
	keys := filepath.Join(home, ".ssh")
	for _, dir := range []string{filepath.Join(state, "hooks"), filepath.Join(state, "logs"), keys, project, filepath.Join(ext, "ok")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{filepath.Join(state, "config.yaml"): "x: 1\n",
		filepath.Join(state, "hooks", ".token"): "t\n", filepath.Join(state, "hooks", ".hookcfg"): "c\n",
		filepath.Join(state, "hook_contract_lock.json"): "{}\n", filepath.Join(keys, "authorized_keys"): "k\n",
		filepath.Join(project, "README.md"): "x\n", filepath.Join(ext, "ok", "a.txt"): "x\n"} {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(state, filepath.Join(ext, "y")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(ext, "x")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	const sid = "S-1-5-21-1-2-3-1101"
	savedHome := userScopedIdentityHome
	userScopedIdentityHome = func(identity string) string {
		if identity == sid {
			return home
		}
		return ""
	}
	t.Cleanup(func() { userScopedIdentityHome = savedHome })
	slashed := filepath.ToSlash(ext)
	msys := slashed
	if len(slashed) > 2 && slashed[1:2] == ":" {
		msys = "/" + strings.ToLower(slashed[:1]) + slashed[2:]
	}
	replacer := strings.NewReplacer("{EB}", filepath.FromSlash(ext), "{EM}", msys, "{E}", slashed)
	contexts := []bool{false}
	if runtime.GOOS == "windows" {
		contexts = append(contexts, true)
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if row.windowsOnly && runtime.GOOS != "windows" {
				t.Skip("a Windows spelling")
			}
			command := replacer.Replace(row.command)
			payload := mustJSON(t, map[string]any{"session_id": "service-gateway-state", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "cwd": project, "tool_input": map[string]string{"command": command}})
			verdicts := map[bool]bool{}
			for _, managed := range contexts {
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = "claudecode"
				store, logger := testStoreAndLogger(t)
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(string(payload)))
				req.Header.Set("Content-Type", "application/json")
				if header := hookpaths.ResolveConnector("claudecode", "", "PreToolUse", payload); header != "" {
					req.Header.Set(hookpaths.Header, header)
				}
				ctx := req.Context()
				if managed {
					ctx = context.WithValue(withServiceAccountGateway(ctx), verifiedUserScopedIdentityContextKey{}, sid)
				}
				recorder := httptest.NewRecorder()
				api.handleAgentHook("claudecode").ServeHTTP(recorder, req.WithContext(ctx))
				got := recorder.Body.String()
				blocked := strings.Contains(got, `"action":"block"`)
				verdicts[managed] = blocked
				if row.rule == rowParity {
					continue
				}
				if blocked != (row.rule != "") {
					t.Errorf("managed=%v %q: block=%v, want %v: %.400s", managed, command, blocked, row.rule != "", got)
				} else if row.rule != "" && !strings.Contains(got, row.rule) {
					t.Errorf("managed=%v %q: blocked by another rule, want %s: %.400s", managed, command, row.rule, got)
				}
			}
			if len(verdicts) == 2 && verdicts[true] != verdicts[false] {
				t.Errorf("%q: service gateway block=%v, per-user block=%v", command, verdicts[true], verdicts[false])
			}
		})
	}
}

// On a managed Windows host the service gateway judges a write to the
// user's DefenseClaw state through a link or junction the command makes to
// an outside folder that holds a disk link to ~/.defenseclaw, plain, after
// a cd, nested, wrapped and renamed, and a write through the disk link
// itself, as the per-user gateway and Linux do: tamper.detector_state_write
// (rel-1-0-4:GAP-2534, managed Windows leg). A new name that is no state
// file gets the same verdict from both gateways.
func TestServiceGatewayWriteThroughLinkToStateMatchesPerUser(t *testing.T) {
	const stateRule = "tamper.detector_state_write"
	const keysRule = "persistence.ssh_authorized_keys_command"
	judgeServiceGatewayStateRows(t, []serviceGatewayStateRow{
		{name: "direct config", command: `echo x >> ~/.defenseclaw/config.yaml`, rule: stateRule},
		{name: "direct hook token", command: `echo x >> ~/.defenseclaw/hooks/.token`, rule: stateRule},
		{name: "disk link config", command: `echo x >> {E}/y/config.yaml`, rule: stateRule},
		{name: "disk link hook config", command: `echo x >> {E}/y/hooks/.hookcfg`, rule: stateRule},
		{name: "disk link config Git Bash drive", command: `echo x >> {EM}/y/config.yaml`, rule: stateRule, windowsOnly: true},
		{name: "command link plain", command: `ln -s {E} L1; echo x >> L1/y/config.yaml`, rule: stateRule},
		{name: "command link cd", command: `ln -s {E} L2 && cd L2/y && echo x > config.yaml`, rule: stateRule},
		{name: "command link renamed", command: `ln -s {E} L5; mv L5 L6; echo x >> L6/y/config.yaml`, rule: stateRule},
		{name: "command link wrapped", command: `bash -c "ln -s {E} L4; echo x >> L4/y/config.yaml"`, rule: stateRule},
		{name: "junction plain", command: `cmd //c "mklink /J L1 {EB}" ; echo x >> L1/y/config.yaml`, rule: stateRule, windowsOnly: true},
		{name: "junction cd", command: `cmd //c "mklink /J L2 {EB}" && cd L2/y && echo x > config.yaml`, rule: stateRule, windowsOnly: true},
		{name: "junction nested", command: `(cmd //c "mklink /J L3 {EB}"); sh -c 'echo x >> L3/y/config.yaml'`, rule: stateRule, windowsOnly: true},
		{name: "junction wrapped", command: `bash -lc 'cmd //c "mklink /J L4 {EB}"; echo x >> L4/y/config.yaml'`, rule: stateRule, windowsOnly: true},
		{name: "junction renamed", command: `cmd //c "mklink /J L5 {EB}" ; mv L5 L6; echo x >> L6/y/config.yaml`, rule: stateRule, windowsOnly: true},
		{name: "junction hook config", command: `cmd //c "mklink /J L1 {EB}" ; echo x >> L1/y/hooks/.hookcfg`, rule: stateRule, windowsOnly: true},
		{name: "keys twin disk link", command: `echo x >> {E}/x/authorized_keys`, rule: keysRule},
		{name: "keys twin junction", command: `cmd //c "mklink /J L7 {EB}" ; echo x >> L7/x/authorized_keys`, rule: keysRule, windowsOnly: true},
		{name: "new name direct", command: `echo x >> ~/.defenseclaw/p8.txt`, rule: rowParity},
		{name: "new name disk link", command: `echo x >> {E}/y/p7.txt`, rule: rowParity},
		{name: "new name junction", command: `cmd //c "mklink /J L1 {EB}" ; echo x >> L1/y/p1.txt`, rule: rowParity, windowsOnly: true},
		{name: "new name junction cd", command: `cmd //c "mklink /J L2 {EB}" && cd L2/y && echo x > p2.txt`, rule: rowParity, windowsOnly: true},
		{name: "read through the disk link", command: `cat {E}/y/config.yaml`},
		{name: "ordinary junction", command: `cmd //c "mklink /J L8 {EB}\ok" ; echo x >> L8/a.txt`, windowsOnly: true},
		{name: "ordinary write outside", command: `echo x >> {E}/ok/a.txt`},
		{name: "project link", command: `ln -s README.md okl; echo x >> okl`},
		{name: "project write", command: `echo benign > notes.txt; ls`},
	})
}
