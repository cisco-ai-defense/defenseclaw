// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// outageTableManagedRow is a connector's managed open cells of the gateway
// outage table (docs-site/data/capability-matrix.json).
type outageTableManagedRow struct {
	ID     string `json:"id"`
	Outage struct {
		ManagedOpen        string `json:"managedOpen"`
		ManagedOpenNoGuard string `json:"managedOpenNoGuard"`
	} `json:"outage"`
}

func outageTableManagedRows(t *testing.T) []outageTableManagedRow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs-site", "data", "capability-matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	var matrix struct {
		Connectors []outageTableManagedRow `json:"connectors"`
	}
	if err := json.Unmarshal(raw, &matrix); err != nil {
		t.Fatal(err)
	}
	return matrix.Connectors
}

// outageCellBlocks is whether a managed open cell says an outage call blocks
// on goos, on the default route (machine policy where the connector has it),
// under a policy with managed_hooks_only preserve or not.
func outageCellBlocks(t *testing.T, id, value, goos string, hooksOnlyPreserve bool) bool {
	t.Helper()
	switch value {
	case "blocks":
		return true
	case "runs", "per-user-route-blocks-linux-macos", "per-user-route-blocks":
		// The machine-policy route (the default) follows the mode.
		return false
	case "blocks-linux-macos":
		return goos != "windows"
	case "runs-blocks-with-hooks-only-preserve":
		return hooksOnlyPreserve
	}
	t.Fatalf("%s: unknown managed open value %q", id, value)
	return false
}

// outageGuardCall is the guarded call a connector's managed hook makes: the
// tool event, the payload's session key, and whether the event is bound on
// the command line (Codex, Copilot). The plugins and the standalone Hermes
// hook ask `hook --foreign-hook-check` (check); the managed hooks run the
// hook-time guard and then hookexec (hookTime). The machine-policy OpenCode
// plugin does both.
type outageGuardCall struct {
	event, key       string
	bound            bool
	check, hookTime  bool
	contractID       string
	hookOutputBlocks func(code int, stdout string) bool
}

func outageGuardCallFor(id string) outageGuardCall {
	blocked := func(code int, stdout string) bool {
		return code != 0 || strings.Contains(stdout, "deny") || strings.Contains(stdout, `"block"`)
	}
	call := outageGuardCall{event: "PreToolUse", key: "session_id", hookTime: true, hookOutputBlocks: blocked}
	switch id {
	case "codex":
		call.bound, call.contractID = true, "codex-hooks-v4"
	case "cursor":
		call.event, call.key = "preToolUse", "conversation_id"
	case "copilot":
		call.event, call.key, call.bound = "preToolUse", "sessionId", true
	case "opencode":
		// The machine-policy plugin passes the event on the command line.
		call.event, call.check, call.bound = "tool.execute.before", true, true
	case "amp":
		call.event, call.check, call.hookTime = "tool.call", true, false
	case "hermes":
		call.event, call.check, call.hookTime = "pre_tool_call", true, false
	}
	return call
}

// G-hooks-upg loop round 2 (P2): the gateway outage table said GitHub Copilot
// CLI and OpenCode (and Cursor, Devin and Hermes) run an outage call on a
// managed standalone host whose administrator chose open. With the default
// foreign_hooks: remove the foreign-hook guard asks the gateway for the
// agent session's record before the hook request, and blocks the call when
// the gateway cannot answer, in every fail mode. This makes the full managed
// call of every connector in the table, on each OS's machine policy
// summary, with the administrator's open and a stopped gateway: the guard
// (hook-time, or the check the plugins and the Hermes hook run), then
// hookexec for a guard block. Where the guard blocks, the table's cell must
// say the call blocks and hookexec must give the connector's block; where
// it does not, the cell must equal the foreign_hooks report or allow column,
// where only the hook decides. foreign_hooks report and allow never block
// an outage in the guard, and managed_hooks_only preserve turns it on for
// Claude Code and Codex.
func TestOutageTableManagedOpenMatchesAFullManagedCall(t *testing.T) {
	notRunning := fmt.Errorf("dial hook socket: %w", hookexec.ErrManagedGatewayNotRunning)
	rows := outageTableManagedRows(t)
	ids := []string{}
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	variants := []struct {
		name              string
		foreignHooks      string
		hooksOnlyPreserve bool
		noGuard           bool
	}{
		{name: "default policy"},
		{name: "managed_hooks_only preserve", hooksOnlyPreserve: true},
		{name: "foreign_hooks report", foreignHooks: config.ForeignHooksReport, noGuard: true},
		{name: "foreign_hooks allow", foreignHooks: config.ForeignHooksAllow, noGuard: true},
	}
	guardBlocked := map[string]bool{}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, variant := range variants {
			policies := map[string]config.ResolvedConnectorPolicy{}
			for _, id := range ids {
				policy := config.EnterpriseMachinePolicyConfig{}.PolicyFor(id)
				if variant.foreignHooks != "" {
					policy.ForeignHooks = variant.foreignHooks
				}
				if variant.hooksOnlyPreserve {
					policy.ManagedHooksOnly = config.ManagedHooksOnlyPreserve
				}
				policies[id] = policy
			}
			summary := enterprisepolicy.BuildPublicPolicy(enterprisepolicy.Options{GOOS: goos, HookBinary: foreignGuardHookBinary, Policies: policies}, ids)
			for _, row := range rows {
				if connector.IsProxyConnector(row.ID) {
					continue // no hooks: a proxy connector's requests are blocked while the gateway is down
				}
				t.Run(goos+"/"+variant.name+"/"+row.ID, func(t *testing.T) {
					fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
					fixture.summary = &summary
					fixture.process = "agent-process"
					previousGOOS := hookForeignGuardGOOS
					hookForeignGuardGOOS = goos
					t.Cleanup(func() { hookForeignGuardGOOS = previousGOOS })
					hookForeignGuardExchange = func(string, string, time.Time, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
						return enterprisepolicy.GuardDecision{}, notRunning
					}
					blocked := managedOutageGuardBlocks(t, fixture, row.ID, outageGuardCallFor(row.ID))
					if want := enterprisepolicy.GuardBlocksOutage(row.ID, goos, policies[row.ID]); blocked != want {
						t.Fatalf("the guard blocked the outage call: %v, GuardBlocksOutage says %v", blocked, want)
					}
					if variant.noGuard && blocked {
						t.Fatalf("with %s the guard must leave the outage to the hook", variant.name)
					}
					guardBlocked[goos+"/"+variant.name+"/"+row.ID] = blocked
					column := row.Outage.ManagedOpen
					if variant.noGuard {
						column = row.Outage.ManagedOpenNoGuard
					}
					hookBlocks := outageCellBlocks(t, row.ID, row.Outage.ManagedOpenNoGuard, goos, false)
					if got, want := outageCellBlocks(t, row.ID, column, goos, variant.hooksOnlyPreserve), blocked || hookBlocks; got != want {
						t.Fatalf("the gateway outage table says the call blocks: %v (%q); the managed call: guard blocked %v, the hook blocks %v (%q)",
							got, column, blocked, hookBlocks, row.Outage.ManagedOpenNoGuard)
					}
				})
			}
		}
	}
	// The connectors the finding named are blocked by the default guard.
	for _, key := range []string{"linux/default policy/copilot", "darwin/default policy/opencode", "windows/default policy/opencode", "windows/default policy/copilot"} {
		if !guardBlocked[key] {
			t.Errorf("%s: the default foreign-hook guard must block a managed open outage call", key)
		}
	}
}

// managedOutageGuardBlocks runs id's guarded call with the administrator's
// open and reports whether the foreign-hook guard blocked it. A hook-time
// block is run through hookexec, which must answer with the connector's block
// and the not-running reason; a check denial must carry the reason too.
func managedOutageGuardBlocks(t *testing.T, fixture *foreignGuardFixture, id string, call outageGuardCall) bool {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"hook_event_name": call.event, "cwd": filepath.Join(fixture.project, "src"), call.key: "s-1",
		"tool_name": "Bash", "tool": "bash"})
	if err != nil {
		t.Fatal(err)
	}
	checkDenied, hookDenied := false, false
	if call.check {
		var out bytes.Buffer
		if code := runForeignHookCheck(id, bytes.NewReader(payload), &out); code != 0 {
			t.Fatalf("the foreign-hook check exits 0, got %d", code)
		}
		var result foreignHookCheckResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatalf("check answer: %v: %q", err, out.String())
		}
		if checkDenied = result.Deny; checkDenied && !strings.Contains(result.Reason, hookexec.ManagedGatewayNotRunningReason) {
			t.Fatalf("the check denial must name the stopped gateway: %+v", result)
		}
	}
	if call.hookTime {
		var stdout, stderr bytes.Buffer
		opts := hookexec.Options{
			Connector:         id,
			ManagedEnterprise: true,
			FailMode:          "open",
			Home:              filepath.Join(fixture.home, "managed-data"),
			Stdin:             bytes.NewReader(payload),
			Stdout:            &stdout,
			Stderr:            &stderr,
			HookContractID:    call.contractID,
		}
		if call.bound {
			opts.Event = call.event
		}
		applyEnterpriseForeignHookGuard(&opts)
		if hookDenied = opts.ManagedRuntimeFailure != ""; hookDenied {
			if opts.ManagedRuntimeFailure != hookexec.ManagedGatewayNotRunningReason {
				t.Fatalf("the guard must block with the not-running reason: %q", opts.ManagedRuntimeFailure)
			}
			code := hookexec.Run(context.Background(), opts)
			if !call.hookOutputBlocks(code, stdout.String()) {
				t.Fatalf("hookexec must answer the guard block with the connector's block: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		}
	}
	if call.check && call.hookTime && checkDenied != hookDenied {
		t.Fatalf("the load check (%v) and the hook-time guard (%v) must agree", checkDenied, hookDenied)
	}
	return checkDenied || hookDenied
}
