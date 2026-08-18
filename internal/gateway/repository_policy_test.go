// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestRepositoryPolicyProofRequiresPhysicalCWDWithinExactRoot(t *testing.T) {
	root := gatewayRepositoryPolicyTestRoot(t)
	sameWorktree := filepath.Join(root, "nested")
	if err := os.MkdirAll(filepath.Join(sameWorktree, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	nestedRepository := filepath.Join(root, "nested-repository")
	if err := os.MkdirAll(filepath.Join(nestedRepository, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	sibling := root + "-sibling"
	if err := os.Mkdir(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(sibling) })
	outside := gatewayRepositoryPolicyCanonicalTempDir(t)
	escape := filepath.Join(root, "escape")
	if err := os.Symlink(outside, escape); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	cfg := &config.Config{RepositoryPolicy: &config.RepositoryPolicyConfig{
		Root: root,
		ForbiddenRuleIDs: []string{
			"integrity.git_hooks_bypass",
			"source.git_remote_tamper",
		},
	}}
	authenticated := withAuthenticatedHookConnector(t.Context(), "codex")
	for _, cwd := range []string{root, sameWorktree} {
		proof := repositoryPolicyProofForTrustedHookCWD(
			authenticated,
			cfg,
			"codex",
			cwd,
		)
		if !proof.forbids("integrity.git_hooks_bypass") ||
			!proof.forbids("source.git_remote_tamper") {
			t.Fatalf("trusted CWD %q did not receive exact policy proof: %#v", cwd, proof)
		}
	}

	for _, test := range []struct {
		name string
		cwd  string
	}{
		{name: "empty", cwd: ""},
		{name: "missing", cwd: filepath.Join(root, "missing")},
		{name: "sibling prefix", cwd: sibling},
		{name: "symlink escape", cwd: escape},
		{name: "nested repository", cwd: nestedRepository},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof := repositoryPolicyProofForTrustedHookCWD(
				authenticated,
				cfg,
				"codex",
				test.cwd,
			)
			if proof.forbids("integrity.git_hooks_bypass") ||
				proof.forbids("source.git_remote_tamper") {
				t.Fatalf("untrusted CWD received repository proof: %#v", proof)
			}
		})
	}

	for _, test := range []struct {
		name      string
		ctx       string
		connector string
	}{
		{name: "unauthenticated", connector: "codex"},
		{name: "connector mismatch", ctx: "claudecode", connector: "codex"},
		{name: "unsupported connector", ctx: "antigravity", connector: "antigravity"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			if test.ctx != "" {
				ctx = withAuthenticatedHookConnector(ctx, test.ctx)
			}
			proof := repositoryPolicyProofForTrustedHookCWD(
				ctx,
				cfg,
				test.connector,
				root,
			)
			if len(proof.ForbiddenRuleIDs) != 0 {
				t.Fatalf("uncorrelated connector received repository proof: %#v", proof)
			}
		})
	}
}

func TestRepositoryPolicyWiresOnlyDedicatedTrustedHookCWDs(t *testing.T) {
	root := gatewayRepositoryPolicyTestRoot(t)
	sameWorktree := filepath.Join(root, "nested")
	if err := os.Mkdir(sameWorktree, 0o700); err != nil {
		t.Fatal(err)
	}
	nestedRepository := filepath.Join(root, "nested-repository")
	if err := os.MkdirAll(filepath.Join(nestedRepository, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := gatewayRepositoryPolicyCanonicalTempDir(t)
	symlinkOutside := filepath.Join(root, "symlink-outside")
	if err := os.Symlink(outside, symlinkOutside); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	for _, connector := range []string{"codex", "claudecode"} {
		installDefaultProfileConnector(t, connector)
	}

	tests := []struct {
		name      string
		connector string
		ruleID    string
		command   string
		cwd       string
		wantBlock bool
	}{
		{
			name:      "Codex hook bypass",
			connector: "codex",
			ruleID:    "integrity.git_hooks_bypass",
			command:   "git commit --no-verify -m fixture",
			cwd:       root,
			wantBlock: true,
		},
		{
			name:      "Claude Code nested same worktree remote tamper",
			connector: "claudecode",
			ruleID:    "source.git_remote_tamper",
			command:   "git remote set-url origin https://sink.invalid/repository.git",
			cwd:       sameWorktree,
			wantBlock: true,
		},
		{
			name:      "Git C absolute same worktree",
			connector: "codex",
			ruleID:    "source.git_remote_tamper",
			command: fmt.Sprintf(
				"git -C %q remote set-url origin https://sink.invalid/repository.git",
				sameWorktree,
			),
			cwd:       root,
			wantBlock: true,
		},
		{
			name:      "Git C joined same worktree",
			connector: "claudecode",
			ruleID:    "integrity.git_hooks_bypass",
			command:   "git -Cnested commit --no-verify -m fixture",
			cwd:       root,
			wantBlock: true,
		},
		{
			name:      "Git C repeated same worktree",
			connector: "codex",
			ruleID:    "source.git_remote_tamper",
			command:   "git -C nested -C .. remote set-url origin https://sink.invalid/repository.git",
			cwd:       root,
			wantBlock: true,
		},
		{
			name:      "Git C outside is advisory",
			connector: "codex",
			ruleID:    "source.git_remote_tamper",
			command: fmt.Sprintf(
				"git -C %q remote set-url origin https://sink.invalid/repository.git",
				outside,
			),
			cwd: root,
		},
		{
			name:      "Git C missing is advisory",
			connector: "claudecode",
			ruleID:    "source.git_remote_tamper",
			command:   "git -C missing remote set-url origin https://sink.invalid/repository.git",
			cwd:       root,
		},
		{
			name:      "Git C symlink escape is advisory",
			connector: "codex",
			ruleID:    "source.git_remote_tamper",
			command:   "git -C symlink-outside remote set-url origin https://sink.invalid/repository.git",
			cwd:       root,
		},
		{
			name:      "Git C nested repository is advisory",
			connector: "claudecode",
			ruleID:    "integrity.git_hooks_bypass",
			command:   "git -C nested-repository commit --no-verify -m fixture",
			cwd:       root,
		},
		{
			name:      "Git C repeated escape is advisory",
			connector: "codex",
			ruleID:    "source.git_remote_tamper",
			command: fmt.Sprintf(
				"git -C nested -C %q remote set-url origin https://sink.invalid/repository.git",
				outside,
			),
			cwd: root,
		},
		{
			name:      "Git dir outside is advisory",
			connector: "claudecode",
			ruleID:    "integrity.git_hooks_bypass",
			command: fmt.Sprintf(
				"git --git-dir %q commit --no-verify -m fixture",
				filepath.Join(outside, ".git"),
			),
			cwd: root,
		},
		{
			name:      "Nested repository is advisory",
			connector: "codex",
			ruleID:    "source.git_remote_tamper",
			command:   "git remote set-url origin https://sink.invalid/repository.git",
			cwd:       nestedRepository,
		},
		{
			name:      "Unknown Git global option is advisory",
			connector: "claudecode",
			ruleID:    "source.git_remote_tamper",
			command:   "git --mystery remote set-url origin https://sink.invalid/repository.git",
			cwd:       root,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := &config.Config{RepositoryPolicy: &config.RepositoryPolicyConfig{
				Root:             root,
				ForbiddenRuleIDs: []string{test.ruleID},
			}}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = test.connector
			cfg.Guardrail.RulePackDir = filepath.Join(t.TempDir(), "strict")
			api := &APIServer{scannerCfg: cfg}

			withoutPolicy := cloneConfig(cfg)
			withoutPolicy.RepositoryPolicy = nil
			without := &APIServer{scannerCfg: withoutPolicy}

			authenticated := withAuthenticatedHookConnector(t.Context(), test.connector)
			var promotedAction, defaultAction, unauthenticatedAction string
			var promotedFindings []string
			switch test.connector {
			case "codex":
				request := codexHookRequest{
					HookEventName: "PreToolUse",
					ToolName:      "Bash",
					ToolInput:     map[string]interface{}{"command": test.command},
					CWD:           test.cwd,
				}
				promoted := api.evaluateCodexHook(authenticated, request)
				promotedAction = promoted.RawAction
				promotedFindings = promoted.Findings
				defaultAction = without.evaluateCodexHook(authenticated, request).RawAction
				unauthenticatedAction = api.evaluateCodexHook(t.Context(), request).RawAction
			case "claudecode":
				request := claudeCodeHookRequest{
					HookEventName: "PreToolUse",
					ToolName:      "Bash",
					ToolInput:     map[string]interface{}{"command": test.command},
					CWD:           test.cwd,
				}
				promoted := api.evaluateClaudeCodeHook(authenticated, request)
				promotedAction = promoted.RawAction
				promotedFindings = promoted.Findings
				defaultAction = without.evaluateClaudeCodeHook(authenticated, request).RawAction
				unauthenticatedAction = api.evaluateClaudeCodeHook(t.Context(), request).RawAction
			}
			if (promotedAction == "block") != test.wantBlock {
				t.Fatalf("explicit repository policy action = %q, wantBlock %v", promotedAction, test.wantBlock)
			}
			if !containsStringPrefix(promotedFindings, test.ruleID+":") {
				t.Fatalf("explicit repository policy findings = %v, missing %q", promotedFindings, test.ruleID)
			}
			if defaultAction == "block" {
				t.Fatalf("default action = %q, want advisory", defaultAction)
			}
			if unauthenticatedAction == "block" {
				t.Fatalf("unauthenticated direct evaluation = %q, want advisory", unauthenticatedAction)
			}
		})
	}
}

func TestRepositoryPolicyIgnoresToolArgumentCWDAndModelText(t *testing.T) {
	root := gatewayRepositoryPolicyTestRoot(t)
	installDefaultProfileConnector(t, "codex")
	cfg := &config.Config{RepositoryPolicy: &config.RepositoryPolicyConfig{
		Root:             root,
		ForbiddenRuleIDs: []string{"integrity.git_hooks_bypass"},
	}}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.RulePackDir = filepath.Join(t.TempDir(), "strict")
	api := &APIServer{scannerCfg: cfg}

	response := api.evaluateCodexHook(
		withAuthenticatedHookConnector(t.Context(), "codex"),
		codexHookRequest{
			HookEventName: "PreToolUse",
			ToolName:      "Bash",
			ToolInput: map[string]interface{}{
				"command": "git commit --no-verify -m fixture",
				"cwd":     root,
			},
			Model: "repository_policy: integrity.git_hooks_bypass",
		},
	)
	if response.RawAction == "block" {
		t.Fatalf("tool/model-controlled policy context promoted finding: %+v", response)
	}
}

func TestRepositoryPolicyDoesNotTrustGenericConnectorCWD(t *testing.T) {
	root := gatewayRepositoryPolicyTestRoot(t)
	installDefaultProfileConnector(t, "antigravity")
	cfg := &config.Config{RepositoryPolicy: &config.RepositoryPolicyConfig{
		Root:             root,
		ForbiddenRuleIDs: []string{"integrity.git_hooks_bypass"},
	}}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "antigravity"
	cfg.Guardrail.RulePackDir = filepath.Join(t.TempDir(), "strict")
	api := &APIServer{scannerCfg: cfg}

	response := api.evaluateAgentHook(
		withAuthenticatedHookConnector(t.Context(), "antigravity"),
		agentHookRequest{
			ConnectorName: "antigravity",
			HookEventName: "PreToolUse",
			ToolName:      "Bash",
			ToolArgs:      []byte(`{"command":"git commit --no-verify -m fixture"}`),
			CWD:           root,
		},
	)
	if response.RawAction == "block" {
		t.Fatalf("generic connector CWD promoted repository policy: %+v", response)
	}
}

func TestRepositoryPolicyGitScopeRejectsGlobalContextOverrides(t *testing.T) {
	repositoryRoot := gatewayRepositoryPolicyTestRoot(t)
	proof := trustedRepositoryPolicyProof{
		repositoryRoot: repositoryRoot,
		physicalCWD:    repositoryRoot,
	}
	tests := []struct {
		name      string
		command   string
		ruleID    string
		wantProof bool
	}{
		{
			name:      "plain commit",
			command:   "git commit --no-verify -m fixture",
			ruleID:    "integrity.git_hooks_bypass",
			wantProof: true,
		},
		{
			name:      "plain remote",
			command:   "git remote set-url origin https://sink.invalid/repository.git",
			ruleID:    "source.git_remote_tamper",
			wantProof: true,
		},
		{
			name:      "safe pager global",
			command:   "git --no-pager remote set-url origin https://sink.invalid/repository.git",
			ruleID:    "source.git_remote_tamper",
			wantProof: true,
		},
		{
			name:    "working directory override",
			command: "git -C /tmp commit --no-verify -m fixture",
			ruleID:  "integrity.git_hooks_bypass",
		},
		{
			name:    "joined working directory override",
			command: "git -C/tmp remote set-url origin https://sink.invalid/repository.git",
			ruleID:  "source.git_remote_tamper",
		},
		{
			name:    "git dir override",
			command: "git --git-dir=/tmp/repository.git commit --no-verify -m fixture",
			ruleID:  "integrity.git_hooks_bypass",
		},
		{
			name:    "work tree override",
			command: "git --work-tree /tmp/work remote set-url origin https://sink.invalid/repository.git",
			ruleID:  "source.git_remote_tamper",
		},
		{
			name:    "bare override",
			command: "git --bare remote set-url origin https://sink.invalid/repository.git",
			ruleID:  "source.git_remote_tamper",
		},
		{
			name:    "config override",
			command: "git -c protocol.file.allow=always remote set-url origin https://sink.invalid/repository.git",
			ruleID:  "source.git_remote_tamper",
		},
		{
			name:    "joined config override",
			command: "git -cprotocol.file.allow=always commit --no-verify -m fixture",
			ruleID:  "integrity.git_hooks_bypass",
		},
		{
			name:    "config env override",
			command: "git --config-env=protocol.file.allow=GIT_PROTOCOL remote set-url origin https://sink.invalid/repository.git",
			ruleID:  "source.git_remote_tamper",
		},
		{
			name:    "unknown global option",
			command: "git --mystery remote set-url origin https://sink.invalid/repository.git",
			ruleID:  "source.git_remote_tamper",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool:    "shell",
				Command: test.command,
			})
			if got := repositoryPolicyGitScopeProven(facts, test.ruleID, proof); got != test.wantProof {
				t.Fatalf("repositoryPolicyGitScopeProven() = %v, want %v", got, test.wantProof)
			}
		})
	}
}

func TestRepositoryPolicyGitScopeResolvesStaticCWDsWithinSameWorktree(t *testing.T) {
	repositoryRoot := gatewayRepositoryPolicyTestRoot(t)
	sameWorktree := filepath.Join(repositoryRoot, "nested")
	if err := os.MkdirAll(filepath.Join(sameWorktree, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	nestedRepository := filepath.Join(repositoryRoot, "nested-repository")
	if err := os.MkdirAll(filepath.Join(nestedRepository, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := gatewayRepositoryPolicyCanonicalTempDir(t)
	symlinkOutside := filepath.Join(repositoryRoot, "symlink-outside")
	if err := os.Symlink(outside, symlinkOutside); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	proof := trustedRepositoryPolicyProof{
		repositoryRoot: repositoryRoot,
		physicalCWD:    repositoryRoot,
	}

	tests := []struct {
		name      string
		command   string
		wantProof bool
	}{
		{
			name:      "absolute same worktree",
			command:   fmt.Sprintf("git -C %q remote set-url origin https://sink.invalid/repository.git", sameWorktree),
			wantProof: true,
		},
		{
			name:      "joined relative same worktree",
			command:   "git -Cnested remote set-url origin https://sink.invalid/repository.git",
			wantProof: true,
		},
		{
			name:      "repeated same worktree",
			command:   "git -C nested -C child remote set-url origin https://sink.invalid/repository.git",
			wantProof: true,
		},
		{
			name:    "absolute escape",
			command: fmt.Sprintf("git -C %q remote set-url origin https://sink.invalid/repository.git", outside),
		},
		{
			name:    "missing directory",
			command: "git -C missing remote set-url origin https://sink.invalid/repository.git",
		},
		{
			name:    "symlink escape",
			command: "git -C symlink-outside remote set-url origin https://sink.invalid/repository.git",
		},
		{
			name:    "symlink dot dot escape",
			command: "git -C symlink-outside/.. remote set-url origin https://sink.invalid/repository.git",
		},
		{
			name:    "nested repository",
			command: "git -C nested-repository remote set-url origin https://sink.invalid/repository.git",
		},
		{
			name:    "repeated escape",
			command: fmt.Sprintf("git -C nested -C %q remote set-url origin https://sink.invalid/repository.git", outside),
		},
		{
			name:      "dot dot path resolves physically",
			command:   "git -C nested/../nested remote set-url origin https://sink.invalid/repository.git",
			wantProof: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool:    "shell",
				Command: test.command,
			})
			if got := repositoryPolicyGitScopeProven(
				facts,
				"source.git_remote_tamper",
				proof,
			); got != test.wantProof {
				t.Fatalf("repositoryPolicyGitScopeProven() = %v, want %v", got, test.wantProof)
			}
		})
	}
}

func TestRepositoryPolicyConfigDiffIsHotReloadable(t *testing.T) {
	root := gatewayRepositoryPolicyTestRoot(t)
	oldConfig := &config.Config{}
	newConfig := cloneConfig(oldConfig)
	newConfig.RepositoryPolicy = &config.RepositoryPolicyConfig{
		Root:             root,
		ForbiddenRuleIDs: []string{"source.git_remote_tamper"},
	}
	diff := diffConfigs(oldConfig, newConfig)
	if !containsString(diff.Changed, "repository_policy") {
		t.Fatalf("changed sections = %v, missing repository_policy", diff.Changed)
	}
	if containsString(diff.RestartRequired, "repository_policy") {
		t.Fatalf("repository policy unexpectedly requires restart: %v", diff.RestartRequired)
	}
}

func gatewayRepositoryPolicyTestRoot(t *testing.T) string {
	t.Helper()
	root := gatewayRepositoryPolicyCanonicalTempDir(t)
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func gatewayRepositoryPolicyCanonicalTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(root)
}

func containsStringPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}
