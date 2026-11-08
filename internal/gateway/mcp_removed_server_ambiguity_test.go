// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const removedSecondDeniedURL = "http://127.0.0.1:28774/mcp"

func writeClaudeServerMap(t *testing.T, home, project string, servers map[string]any) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"projects": map[string]any{filepath.ToSlash(project): map[string]any{"mcpServers": servers}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func wantBlocked(t *testing.T, what string, decision config.AssetPolicyDecision, matched bool) {
	t.Helper()
	if !matched || decision.Action != "block" {
		t.Fatalf("%s: matched=%v decision=%+v, want a block", what, matched, decision)
	}
}

// A call that meets a second denied definition under the name of a server it
// already holds a denied one for keeps both in view: when the config entry is
// gone and the policy in force denies only the one the memory could not keep,
// the live connection stays refused, in every profile, whether the memory is
// full or not and whichever of the policy change and the removal comes first.
// Ordinary servers and other sessions keep their verdicts.
func TestRemovedMCPServerKeepsEveryDeniedDefinitionOfTheCall(t *testing.T) {
	for _, profile := range []string{"default", "managed"} {
		for _, full := range []bool{false, true} {
			for _, removeFirst := range []bool{false, true} {
				name := profile
				if full {
					name += "/memory full"
				}
				if removeFirst {
					name += "/removed before the policy changes"
				}
				t.Run(name, func(t *testing.T) {
					cfg := deniedURLConfig()
					if profile == "managed" {
						cfg = managedURLDenyConfig()
					}
					cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: removedDeniedURL}, {URL: removedSecondDeniedURL}}
					api := &APIServer{scannerCfg: cfg}
					home, project := t.TempDir(), t.TempDir()
					ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
					servers := map[string]any{}
					write := func() { writeClaudeServerMap(t, home, project, servers) }
					if full {
						fillDeniedMCPPartition(t, api, ctx, project, servers, write)
					} else {
						servers["wiki"] = map[string]any{"type": "http", "url": removedDeniedURL}
						write()
						decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
						wantDenyBlock(t, "first denied definition", decision, matched)
					}
					// The same name now points at a second denied endpoint.
					servers["wiki"] = map[string]any{"type": "http", "url": removedSecondDeniedURL}
					write()
					decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
					wantDenyBlock(t, "second denied definition", decision, matched)
					policyChanges := func() {
						// The policy stops denying the first endpoint and keeps
						// denying the second.
						cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: removedSecondDeniedURL}}
					}
					if !removeFirst {
						policyChanges()
						decision, matched = claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
						wantDenyBlock(t, "second definition while configured", decision, matched)
					}
					delete(servers, "wiki")
					write()
					if removeFirst {
						policyChanges()
					}
					decision, matched = claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
					wantBlocked(t, "entry removed", decision, matched)

					// Benign twins: an ordinary server of the session, and another
					// session that never met the name.
					servers["ordinary"] = map[string]any{"type": "http", "url": removedOtherURL}
					write()
					decision, matched = claudeMCPCall(api, ctx, project, "s1", "mcp__ordinary__count_words")
					wantNotBlocked(t, "ordinary server", decision, matched)
					if profile == "default" {
						decision, matched = claudeMCPCall(api, ctx, project, "s2", "mcp__wiki__count_words")
						wantNotBlocked(t, "another session in the default tier", decision, matched)
					}
				})
			}
		}
	}
}

// A server whose entry was edited and then removed has two definitions in its
// session record, and the record cannot say which one the agent holds. Where
// a list decides on where a server points, the call gets the unknown verdict
// (a warning in the default tier, a block in a strict or managed one), never a
// plain allow. A single definition, a policy without lists, and a list that
// does not pin an endpoint keep the allow.
func TestRemovedMCPServerWithSeveralDefinitionsGetsTheUnknownVerdict(t *testing.T) {
	edited := func(t *testing.T, cfg *config.Config, edits int) (config.AssetPolicyDecision, bool) {
		t.Helper()
		api := &APIServer{scannerCfg: cfg}
		home, project := t.TempDir(), t.TempDir()
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
		for _, url := range []string{removedOtherURL, "http://127.0.0.1:28773/mcp"}[:edits] {
			writeClaudeServers(t, home, project, `{"wiki":{"type":"http","url":"`+url+`"}}`)
			decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
			wantNotBlocked(t, "configured "+url, decision, matched)
		}
		writeClaudeServers(t, home, project, `{}`)
		return claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
	}

	decision, matched := edited(t, deniedURLConfig(), 2)
	wantUnknownWarning(t, "default tier", decision, matched)
	decision, matched = edited(t, managedURLDenyConfig(), 2)
	if !matched || decision.Action != "block" || decision.Source != "mcp-definition-unproven" {
		t.Fatalf("managed: matched=%v decision=%+v, want the unknown-definition block", matched, decision)
	}
	strict := deniedURLConfig()
	strict.Guardrail.RulePack = "strict"
	decision, matched = edited(t, strict, 2)
	if !matched || decision.Action != "block" || decision.Source != "mcp-definition-unproven" {
		t.Fatalf("strict: matched=%v decision=%+v, want the unknown-definition block", matched, decision)
	}

	// Benign twins.
	if decision, matched = edited(t, managedURLDenyConfig(), 1); matched {
		t.Fatalf("one definition, complete record: matched=%v decision=%+v, want the plain allow", matched, decision)
	}
	noLists := managedURLDenyConfig()
	noLists.AssetPolicy.MCP.Denied = nil
	if decision, matched = edited(t, noLists, 2); matched {
		t.Fatalf("no lists: matched=%v decision=%+v, want the plain allow", matched, decision)
	}
	nameOnly := managedURLDenyConfig()
	nameOnly.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: "another-server"}}
	if decision, matched = edited(t, nameOnly, 2); matched {
		t.Fatalf("name-only deny of another server: matched=%v decision=%+v, want the plain allow", matched, decision)
	}
}

// The memory records what it could not hold of a name: nothing for the same
// definition seen again, several definitions for an edit, and a dropped denied
// definition when two denied ones meet under one name, in the entries and in
// the lost set; a session that starts again forgets it.
func TestResolvedMCPMemoryRecordsDroppedDefinitions(t *testing.T) {
	now := time.Now()
	first := config.MCPServerEntry{Name: "wiki", URL: removedDeniedURL, Transport: "http"}
	second := config.MCPServerEntry{Name: "wiki", URL: removedSecondDeniedURL, Transport: "http"}
	level := func(m *mcpResolvedDefinitions, at time.Time) mcpAmbiguity {
		return m.ambiguity("claudecode", "/home/a", "s1", "/work", "wiki", at)
	}
	remember := func(m *mcpResolvedDefinitions, entry config.MCPServerEntry, denied bool) {
		m.remember("claudecode", "/home/a", "s1", "/work", "wiki", entry, denied, mcpOneDefinition, now)
	}

	var same mcpResolvedDefinitions
	remember(&same, first, true)
	remember(&same, first, true)
	if got := level(&same, now); got != mcpOneDefinition {
		t.Fatalf("same definition twice: ambiguity %d, want %d", got, mcpOneDefinition)
	}

	var edit mcpResolvedDefinitions
	remember(&edit, first, false)
	remember(&edit, second, false)
	if got := level(&edit, now); got != mcpSeveralDefinitions {
		t.Fatalf("edit: ambiguity %d, want %d", got, mcpSeveralDefinitions)
	}

	var keptDenied mcpResolvedDefinitions
	remember(&keptDenied, first, true)
	remember(&keptDenied, second, false)
	if got := level(&keptDenied, now); got != mcpSeveralDefinitions {
		t.Fatalf("denied kept, ordinary dropped: ambiguity %d, want %d", got, mcpSeveralDefinitions)
	}

	var twoDenied mcpResolvedDefinitions
	remember(&twoDenied, first, true)
	remember(&twoDenied, second, true)
	if got := level(&twoDenied, now); got != mcpDeniedDefinitionDropped {
		t.Fatalf("two denied: ambiguity %d, want %d", got, mcpDeniedDefinitionDropped)
	}
	if got := level(&twoDenied, now.Add(2*mcpResolvedTTL)); got != mcpOneDefinition {
		t.Fatalf("past the TTL: ambiguity %d, want %d", got, mcpOneDefinition)
	}

	var lost mcpResolvedDefinitions
	key := mcpResolvedKey("claudecode", "/home/a", "s1", "/work", "wiki")
	lost.mu.Lock()
	lost.markLostLocked("claudecode", "/home/a", "s1", key, first, mcpOneDefinition, now)
	lost.mu.Unlock()
	if got := level(&lost, now); got != mcpOneDefinition {
		t.Fatalf("one lost definition: ambiguity %d, want %d", got, mcpOneDefinition)
	}
	lost.mu.Lock()
	lost.markLostLocked("claudecode", "/home/a", "s1", key, second, mcpOneDefinition, now)
	lost.mu.Unlock()
	if got := level(&lost, now); got != mcpDeniedDefinitionDropped {
		t.Fatalf("second lost definition: ambiguity %d, want %d", got, mcpDeniedDefinitionDropped)
	}
	if got, held, _ := lost.lostDenied("claudecode", "/home/a", "s1", "/work", "wiki", now); !held || got.URL != removedDeniedURL {
		t.Fatalf("the first lost definition stays held: %+v held=%v", got, held)
	}
	lost.forgetSession("claudecode", "/home/a", "s1")
	if got := level(&lost, now); got != mcpOneDefinition {
		t.Fatalf("after the session started again: ambiguity %d, want %d", got, mcpOneDefinition)
	}
}

// A default deny in observe mode only observes: it must not stand in for the
// verdict on a server whose session record cannot say which definition the
// agent holds. Where a denied rule covers the dropped definition, or the
// deployment is strict or managed, the call is refused whatever the observe
// verdict on the one definition held; the default tier keeps its warning for a
// name found nowhere, and a policy without a deny list keeps the allow.
func TestObservedDefaultDenyDoesNotStandForAnIncompleteSessionRecord(t *testing.T) {
	observeDefaultDeny := func(cfg *config.Config) *config.Config {
		cfg.AssetPolicy.Enabled = true
		cfg.AssetPolicy.Mode = config.AssetPolicyModeObserve
		cfg.AssetPolicy.MCP.Default = "deny"
		return cfg
	}
	session := func(cfg *config.Config) (*APIServer, context.Context, string, string) {
		home, project := t.TempDir(), t.TempDir()
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
		return &APIServer{scannerCfg: cfg}, ctx, home, project
	}

	t.Run("a denied definition dropped from the record", func(t *testing.T) {
		for _, profile := range []string{"default", "managed"} {
			t.Run(profile, func(t *testing.T) {
				cfg := deniedURLConfig()
				if profile == "managed" {
					cfg = managedURLDenyConfig()
				}
				observeDefaultDeny(cfg).AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: removedDeniedURL}, {URL: removedSecondDeniedURL}}
				api, ctx, home, project := session(cfg)
				for _, url := range []string{removedDeniedURL, removedSecondDeniedURL} {
					writeClaudeServers(t, home, project, `{"wiki":{"type":"http","url":"`+url+`"}}`)
					decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
					wantDenyBlock(t, "configured denied definition", decision, matched)
				}
				cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: removedSecondDeniedURL}}
				writeClaudeServers(t, home, project, `{}`)
				decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
				wantBlocked(t, "entry removed", decision, matched)
			})
		}
	})

	t.Run("two ordinary definitions, the dropped one denied later", func(t *testing.T) {
		for _, profile := range []string{"default", "managed"} {
			t.Run(profile, func(t *testing.T) {
				cfg := deniedURLConfig()
				if profile == "managed" {
					cfg = managedURLDenyConfig()
				}
				observeDefaultDeny(cfg).AssetPolicy.MCP.Denied = nil
				api, ctx, home, project := session(cfg)
				for _, url := range []string{removedSecondDeniedURL, removedOtherURL} {
					writeClaudeServers(t, home, project, `{"wiki":{"type":"http","url":"`+url+`"}}`)
					decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
					wantNotBlocked(t, "configured, no deny yet", decision, matched)
				}
				cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: removedSecondDeniedURL}}
				writeClaudeServers(t, home, project, `{}`)
				decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
				if profile == "managed" {
					wantBlocked(t, "entry removed in a managed deployment", decision, matched)
				} else {
					wantNotBlocked(t, "entry removed in the default tier", decision, matched)
				}
			})
		}
	})

	t.Run("a name found nowhere", func(t *testing.T) {
		managed := observeDefaultDeny(managedURLDenyConfig())
		api, ctx, home, project := session(managed)
		writeClaudeServers(t, home, project, `{}`)
		decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__never-seen__count_words")
		wantBlocked(t, "managed", decision, matched)

		// Benign twins: the default tier warns and goes ahead, and a policy
		// without a deny list that pins an endpoint keeps the observe verdict.
		def := observeDefaultDeny(deniedURLConfig())
		api, ctx, home, project = session(def)
		writeClaudeServers(t, home, project, `{}`)
		decision, matched = claudeMCPCall(api, ctx, project, "s1", "mcp__never-seen__count_words")
		wantNotBlocked(t, "default tier", decision, matched)
		noPin := observeDefaultDeny(managedURLDenyConfig())
		noPin.AssetPolicy.MCP.Denied = nil
		api, ctx, home, project = session(noPin)
		writeClaudeServers(t, home, project, `{}`)
		decision, matched = claudeMCPCall(api, ctx, project, "s1", "mcp__never-seen__count_words")
		wantNotBlocked(t, "managed, no deny list", decision, matched)
	})
}
