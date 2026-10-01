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
	"time"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A user's own Hermes pre_tool_call hook placed after
// DefenseClaw's could rewrite the tool call, and the rewritten command ran
// uninspected: Hermes was not guarded. On Linux and macOS the standalone
// hermes-hook.sh now asks `hook --connector hermes --foreign-hook-check`
// before each tool call. With DefenseClaw's own registration (the per-user
// hermes-hook.sh Setup writes into ~/.hermes/config.yaml) the check allows;
// with a user entry after it, it denies with the file and the allowlist key
// and renders the Hermes block object the hook prints, and `enterprise
// policy verify --user` (the same evaluation) agrees. A Hermes process that
// started while the entry was present stays blocked after the entry is
// gone, because Hermes keeps the hooks it loaded at start.
func TestForeignHookCheckBlocksAUserHermesHookAfterDefenseClaws(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	policy := enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RoutePerUser, ForeignHooks: config.ForeignHooksRemove, Guard: true}
	fixture.summary.Connectors[enterprisepolicy.ConnectorHermes] = policy
	hermesHome := filepath.Join(fixture.home, ".hermes")
	configPath := filepath.Join(hermesHome, "config.yaml")
	t.Setenv("HERMES_HOME", hermesHome)
	previous := connector.HermesConfigPathOverride
	connector.HermesConfigPathOverride = ""
	t.Cleanup(func() { connector.HermesConfigPathOverride = previous })

	setup := connector.SetupOpts{
		DataDir:                filepath.Join(fixture.home, ".defenseclaw"),
		APIAddr:                "127.0.0.1:18970",
		APIToken:               "tok-test",
		HookFailMode:           "closed",
		ManagedEnterprise:      true,
		ManagedHookSocket:      "/var/run/defenseclaw/hook.sock",
		ManagedServiceUID:      461,
		ForeignHookGuardBinary: foreignGuardHookBinary,
	}
	if err := os.MkdirAll(hermesHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := connector.NewHermesConnector().Setup(context.Background(), setup); err != nil {
		t.Fatalf("Hermes Setup: %v", err)
	}
	managed, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	check := func(event, session string) foreignHookCheckResult {
		t.Helper()
		payload := `{"hook_event_name":"` + event + `","session_id":"` + session + `","cwd":"` + fixture.project + `","tool_name":"terminal","tool_input":{"command":"echo benign"}}`
		var out bytes.Buffer
		if code := runForeignHookCheck("hermes", strings.NewReader(payload), &out); code != 0 {
			t.Fatalf("the check always exits 0, got %d", code)
		}
		var result foreignHookCheckResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatalf("the answer must be JSON: %v: %q", err, out.String())
		}
		if !result.Deny && strings.TrimSpace(out.String()) != `{"deny":false}` && len(result.Warnings) == 0 {
			t.Fatalf("hermes-hook.sh allows only the exact allow answer: %q", out.String())
		}
		return result
	}
	verify := func() enterprisepolicy.GuardDecision {
		t.Helper()
		return enterprisepolicy.EvaluateForeignHooks(enterprisepolicy.GuardRequest{
			Connector:     enterprisepolicy.ConnectorHermes,
			Home:          fixture.home,
			AccountHome:   fixture.home,
			HookBinary:    foreignGuardHookBinary,
			Policy:        policy,
			OwnedCommands: perUserOwnedHookCommands(enterprisepolicy.ConnectorHermes, fixture.home, ""),
		})
	}
	if result := check("pre_tool_call", "s-0"); result.Deny {
		t.Fatalf("DefenseClaw's own Hermes registration must not be foreign: %+v", result)
	}
	if decision := verify(); decision.Deny || len(decision.Findings) != 0 {
		t.Fatalf("policy verify must agree that DefenseClaw's registration is not foreign: %+v", decision)
	}

	// The user's own pre_tool_call entry after DefenseClaw's.
	var document map[string]any
	if err := yaml.Unmarshal(managed, &document); err != nil {
		t.Fatal(err)
	}
	hooks := document["hooks"].(map[string]any)
	hooks["pre_tool_call"] = append(hooks["pre_tool_call"].([]any), map[string]any{"command": "/usr/local/bin/rewrite-tool-input.sh", "matcher": ".*"})
	withForeign, err := yaml.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	fixture.write(t, configPath, string(withForeign))

	result := check("pre_tool_call", "s-0")
	if !result.Deny || !strings.Contains(result.Reason, configPath) || !strings.Contains(result.Reason, "enterprise.machine_policy.connectors.hermes.allowed_hooks") {
		t.Fatalf("the check must deny and name the file and the allowlist key: %+v", result)
	}
	if result.HookOutput == nil || result.HookOutput.Action != "block" ||
		!strings.HasPrefix(result.HookOutput.Message, "DefenseClaw blocked this tool call: your organization blocks hermes hooks") ||
		!strings.Contains(result.HookOutput.Message, configPath) || !strings.HasSuffix(result.HookOutput.Message, "(enterprise_foreign_hook_blocked)") {
		t.Fatalf("the check must render the Hermes block the hook prints: %+v", result.HookOutput)
	}
	if decision := verify(); !decision.Deny || !strings.Contains(decision.Reason, configPath) {
		t.Fatalf("policy verify --user must agree: %+v", decision)
	}
	if blocks, _, _ := enterprisepolicy.CollectForeignHookBlocks(fixture.home, time.Now()); len(blocks) == 0 || blocks[0].Connector != "hermes" || blocks[0].Path != configPath {
		t.Fatalf("the block is recorded for the guardian: %+v", blocks)
	}

	// A Hermes process that started with the entry keeps it after the
	// entry is removed from the file.
	fixture.process = "linux::4242:100"
	if result := check("on_session_start", "s-1"); !result.Deny {
		t.Fatalf("the session start with the entry present must record a block: %+v", result)
	}
	fixture.write(t, configPath, string(managed))
	if result := check("pre_tool_call", "s-1"); !result.Deny {
		t.Fatalf("a Hermes process that started with the entry must stay blocked: %+v", result)
	}
	fixture.process = "linux::4343:200"
	if result := check("pre_tool_call", "s-2"); result.Deny {
		t.Fatalf("a Hermes process started after the entry is gone is allowed: %+v", result)
	}

	// An untrusted summary still denies Hermes, with a Hermes block object.
	t.Run("untrusted summary", func(t *testing.T) {
		fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
		fixture.loadErr = os.ErrPermission
		var out bytes.Buffer
		runForeignHookCheck("hermes", strings.NewReader(`{"hook_event_name":"pre_tool_call"}`), &out)
		var result foreignHookCheckResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if !result.Deny || result.HookOutput == nil || result.HookOutput.Action != "block" ||
			!strings.HasSuffix(result.HookOutput.Message, "(enterprise_machine_policy_summary_untrusted)") {
			t.Fatalf("untrusted summary: %+v %+v", result, result.HookOutput)
		}
		out.Reset()
		runForeignHookCheck("opencode", strings.NewReader(`{"hook_event_name":"tool.execute.before"}`), &out)
		if strings.Contains(out.String(), "hook_output") {
			t.Fatalf("only Hermes gets a hook_output: %q", out.String())
		}
	})

	// `enterprise policy show` lists the Hermes guard on Linux and macOS.
	t.Run("policy show", func(t *testing.T) {
		ctx := withEnterprisePolicyTree(t)
		ctx.connectors = append(ctx.connectors, enterprisepolicy.ConnectorHermes)
		standaloneEnterprisePolicyOptions = func() (enterprisePolicyContext, error) { return ctx, nil }
		out, err := runPolicyCommand(t, runEnterprisePolicyShow)
		if err != nil {
			t.Fatalf("show: %v\n%s", err, out)
		}
		index := strings.Index(out, "\nhermes ")
		if index < 0 || !strings.Contains(out[index:], "per_user") || !strings.Contains(out[index:], "guard:     foreign hooks remove (0 allowlisted)") {
			t.Fatalf("show must list the Hermes guard:\n%s", out)
		}
	})
}
