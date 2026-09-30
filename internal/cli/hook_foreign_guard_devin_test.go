// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// On Linux and macOS the standalone Devin registration is the
// administrator-owned hook binary in managed mode, so each Devin hook runs
// the foreign-hook guard. A PreToolUse entry a user adds to their own
// ~/.config/devin/config.json, or a project adds to .devin/config.json, that
// could rewrite the tool call is denied at hook time with the file named,
// and `enterprise policy verify --user` (the same evaluation) agrees.
// DefenseClaw's own registration is never foreign.
func TestForeignHookGuardBlocksDevinRewriteEntriesOnTheStandaloneRegistration(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	t.Setenv("XDG_CONFIG_HOME", "")
	policy := enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RoutePerUser, ForeignHooks: config.ForeignHooksRemove, Guard: true}
	fixture.summary.Connectors["devin"] = policy
	previous := connector.DevinHooksPathOverride
	connector.DevinHooksPathOverride = ""
	t.Cleanup(func() { connector.DevinHooksPathOverride = previous })

	userConfig := filepath.Join(fixture.home, ".config", "devin", "config.json")
	setup := connector.SetupOpts{
		DataDir:                filepath.Join(fixture.home, ".defenseclaw"),
		APIAddr:                "127.0.0.1:18970",
		APIToken:               "tok-test",
		ConfigHome:             filepath.Dir(userConfig),
		HookFailMode:           "closed",
		ManagedEnterprise:      true,
		ForeignHookGuardBinary: foreignGuardHookBinary,
	}
	if err := connector.NewDevinConnector().Setup(context.Background(), setup); err != nil {
		t.Fatalf("Devin Setup: %v", err)
	}

	guard := func() hookexec.Options {
		t.Helper()
		payload := `{"hook_event_name":"PreToolUse","cwd":"` + filepath.Join(fixture.project, "src") + `","tool_name":"exec"}`
		var stderr bytes.Buffer
		opts := hookexec.Options{Connector: "devin", ManagedEnterprise: true, Stdin: strings.NewReader(payload), Stderr: &stderr}
		applyEnterpriseForeignHookGuard(&opts)
		return opts
	}
	verify := func() enterprisepolicy.GuardDecision {
		t.Helper()
		return enterprisepolicy.EvaluateForeignHooks(enterprisepolicy.GuardRequest{
			Connector:     "devin",
			Home:          fixture.home,
			AccountHome:   fixture.home,
			WorkingDir:    fixture.project,
			HookBinary:    foreignGuardHookBinary,
			Policy:        policy,
			OwnedCommands: perUserOwnedHookCommands("devin", fixture.home, ""),
		})
	}
	if opts := guard(); opts.ManagedRuntimeFailure != "" {
		t.Fatalf("DefenseClaw's own registration must not be foreign: %q", opts.ManagedRuntimeFailure)
	}
	if decision := verify(); decision.Deny {
		t.Fatalf("policy verify must agree that DefenseClaw's registration is not foreign: %+v", decision)
	}

	rewrite := map[string]any{"matcher": "", "hooks": []any{map[string]any{"type": "command", "command": "./rewrite-command.sh"}}}
	cfgBody, err := json.Marshal(map[string]any{"hooks": map[string]any{"PreToolUse": []any{rewrite}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		path string
		add  func()
	}{
		{
			name: "user config",
			path: userConfig,
			add: func() {
				// The user's entry sits beside DefenseClaw's registration.
				cfg := map[string]any{}
				raw, err := os.ReadFile(userConfig)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(raw, &cfg); err != nil {
					t.Fatal(err)
				}
				hooks, _ := cfg["hooks"].(map[string]any)
				pre, _ := hooks["PreToolUse"].([]any)
				hooks["PreToolUse"] = append([]any{rewrite}, pre...)
				updated, _ := json.Marshal(cfg)
				fixture.write(t, userConfig, string(updated))
			},
		},
		{
			name: "project config",
			path: filepath.Join(fixture.project, ".devin", "config.json"),
			add: func() {
				fixture.write(t, filepath.Join(fixture.project, ".devin", "config.json"), string(cfgBody))
			},
		},
	} {
		restore, err := os.ReadFile(userConfig)
		if err != nil {
			t.Fatal(err)
		}
		tc.add()
		opts := guard()
		if !strings.HasPrefix(opts.ManagedRuntimeFailure, hookexec.ForeignHookBlockedReasonPrefix) || !strings.Contains(opts.ManagedRuntimeFailure, tc.path) {
			t.Fatalf("%s: the Devin hook must deny and name %s: %q", tc.name, tc.path, opts.ManagedRuntimeFailure)
		}
		if decision := verify(); !decision.Deny || !strings.Contains(decision.Reason, tc.path) {
			t.Fatalf("%s: policy verify --user must agree: %+v", tc.name, decision)
		}
		fixture.write(t, userConfig, string(restore))
		if err := os.RemoveAll(filepath.Join(fixture.project, ".devin")); err != nil {
			t.Fatal(err)
		}
	}
}
