// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

func TestGAP0602IngressViewBefore(t *testing.T) {
	root := t.TempDir()
	target := sandboxauth.SandboxHome + "/.claude/settings.json"
	host := filepath.Join(root, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(host), 0700); err != nil {
		t.Fatal(err)
	}
	binding := sandboxTestBinding("claudecode")
	binding.Workdir = sandboxauth.Workdir{Mode: sandboxauth.WorkdirMount,
		Mounts: []sandboxauth.Mount{{SandboxPath: sandboxauth.SandboxHome, HostPath: root}}}
	view := sandboxauth.NewFSView(binding, nil)
	ctx := sandboxauth.WithRequest(context.Background(), binding, view)
	for _, file := range []string{gap0433LaptopSettings, "", "{broken", strings.Repeat("x", 65537)} {
		if err := os.WriteFile(host, []byte(file), 0600); err != nil {
			t.Fatal(err)
		}
		got, present := sandboxAgentHookBefore(ctx, target)
		if !present {
			t.Fatal("ingress discarded an available confined before-state")
		}
		if len(file) > 65536 {
			if got != nil {
				t.Fatal("oversized view snapshot accepted")
			}
		} else if got == nil || string(got) != file {
			t.Fatalf("got=%q want=%q", got, file)
		}
	}
	if err := os.Remove(host); err != nil {
		t.Fatal(err)
	}
	if got, present := sandboxAgentHookBefore(ctx, target); !present || got == nil || len(got) != 0 {
		t.Fatal("missing view file must be an exact empty before-state")
	}
	if _, present := sandboxAgentHookBefore(ctx, "/outside/.claude/settings.json"); present {
		t.Fatal("read escaped the ingress view")
	}
	// Copy mode must never borrow a same-named host file.
	binding.Workdir = sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy}
	ctx = sandboxauth.WithRequest(context.Background(), binding, sandboxauth.NewFSView(binding, nil))
	if _, present := sandboxAgentHookBefore(ctx, target); present {
		t.Fatal("copy mode borrowed host state")
	}
}

func TestGAP0602CalloutContextRetainsBefore(t *testing.T) {
	// The ext_proc request builder has only MCP arguments, no actor filesystem.
	// If its caller already has kit facts, evaluation must retain them; it
	// must never use the callout host filesystem to manufacture missing facts.
	api := &APIServer{}
	ctx := api.substrateEvaluationContext(gapNF6Facts(context.Background(), gap0433LaptopSettings),
		registry.Registration{Key: "nf7", Connector: "claudecode"}, sandboxauth.RouteHook)
	got, present := sandboxAgentHookBefore(ctx, sandboxauth.SandboxHome+"/.claude/settings.json")
	if !present || string(got) != gap0433LaptopSettings {
		t.Fatal("callout evaluation lost kit facts")
	}
}

func TestGAP0602WholeJSONSubstringIsAmbiguous(t *testing.T) {
	// A whole JSON old_string is not proof that it is the whole file.
	// Here a benign-looking edit is actually inside a reserved env value.
	old := `{"model":"before"}`
	next := `{"model":"after"}`
	args, _ := json.Marshal(map[string]any{"file_path": "~/.claude/settings.json", "old_string": old, "new_string": next})
	rule, note, _ := sandboxAgentHookConfigChange(context.Background(), trustedActionRequest{
		Connector: "claudecode", Input: actionfacts.Input{Tool: "Edit", Args: args, ActiveHome: sandboxauth.SandboxHome}})
	if rule != agentHookConfigDisableRuleID || !strings.Contains(note, "DefenseClaw could not see the settings file to judge this edit") {
		t.Fatalf("unproven whole-document edit allowed: %s %s", rule, note)
	}
}

func TestGAP0602PatchMoveNeedsSourceContext(t *testing.T) {
	source := "/work/plain.json"
	target := sandboxauth.SandboxHome + "/.claude/settings.json"
	patch := "*** Begin Patch\n*** Update File: " + source + "\n*** Move to: " + target + "\n@@\n-{}\n+{}\n*** End Patch\n"
	args, _ := json.Marshal(map[string]any{"input": patch})
	rule, note, _ := sandboxAgentHookConfigChange(gapNF6Facts(context.Background(), gap0433LaptopSettings), trustedActionRequest{
		Connector: "claudecode", Input: actionfacts.Input{Tool: "apply_patch", Args: args, ActiveHome: sandboxauth.SandboxHome, CWD: "/work"}})
	if rule != agentHookConfigDisableRuleID || !strings.Contains(note, "patch source") {
		t.Fatalf("destination snapshot substituted for unrelated source: rule=%s note=%s", rule, note)
	}
}
