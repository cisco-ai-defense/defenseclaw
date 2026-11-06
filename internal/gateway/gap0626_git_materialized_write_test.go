// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestGAP0626GitMaterializedWritePosture(t *testing.T) {
	home, repo := r104ReviewHome(t)
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(repo, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, command   string
		possible        bool
		blockEverywhere bool
	}{
		{"subdirectory pull then project append", `git -C sub pull && echo marker >> future`, true, false},
		{"directory change then pull", `cd project && git -C sub pull && echo marker >> future`, true, false},
		{"checkout then project append", `git -C sub checkout -- future && echo marker >> future`, true, false},
		{"submodule update then project append", `git -C sub submodule update --init && echo marker >> future`, true, false},
		{"clone then project append", `git clone source cloned && echo marker >> cloned/future`, true, false},
		{"exported pull then parent append", `export GIT_WORK_TREE="$HOME"; git -C sub pull && echo marker >> ../future`, true, false},
		{"exported checkout then parent append", `export GIT_WORK_TREE="$HOME"; git -C sub checkout -- future && echo marker >> ../future`, true, false},
		{"auto exported worktree then parent append", `set -a; GIT_WORK_TREE="$HOME"; git -C sub pull && echo marker >> ../future`, true, false},
		{"auto export retained after flag removal", `set -a; GIT_WORK_TREE="$HOME"; set +a; git -C sub pull && echo marker >> ../future`, true, false},
		{"long auto export option", `set -o allexport; GIT_WORK_TREE="$HOME"; git -C sub pull && echo marker >> ../future`, true, false},
		{"auto exported git directory", `set -a; GIT_DIR="$HOME/project/.git"; git -C sub pull && echo marker >> ../future`, true, false},
		{"auto export in nested shell", `bash -lc 'set -a; GIT_WORK_TREE="$HOME"; git -C sub pull && echo marker >> ../future'`, true, false},
		{"auto export in conditional body", `if true; then set -a; GIT_WORK_TREE="$HOME"; git -C sub pull; echo marker >> ../future; fi`, true, false},
		{"removed export then parent append", `export GIT_WORK_TREE="$HOME"; unset GIT_WORK_TREE; git -C sub pull && echo marker >> ../future`, false, false},
		{"removed auto export then parent append", `set -a; GIT_WORK_TREE="$HOME"; export -n GIT_WORK_TREE; git -C sub pull && echo marker >> ../future`, false, false},
		{"auto export after materialization", `git -C sub pull; set -a; GIT_WORK_TREE="$HOME"; echo marker >> ../future`, false, false},
		{"exported read only git then parent append", `export GIT_WORK_TREE="$HOME"; git -C sub show HEAD && echo marker >> ../future`, false, false},
		{"known link after pull", `git -C sub pull && echo marker >> alias`, false, true},
		{"named keys file after pull", `git -C sub pull && echo marker >> ~/.ssh/authorized_keys`, false, true},
		{"project append before pull", `echo marker >> future && git -C sub pull`, false, false},
		{"pull without following write", `git -C sub pull`, false, false},
		{"read only git command then append", `git -C sub show HEAD && echo marker >> future`, false, false},
		{"write outside worktree", `git -C sub pull && echo marker >> ../outside.txt`, false, false},
	}
	for _, profile := range []string{"default", "permissive", "strict", "managed strict"} {
		t.Run(profile, func(t *testing.T) {
			pack := profile
			if profile == "managed strict" {
				pack = "strict"
			}
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
			if profile == "managed strict" {
				cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
				cfg.Enterprise.Profile = managed.ProfileStandalone
			}
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					cwd := repo
					if strings.HasPrefix(tc.command, "cd project") {
						cwd = home
					}
					resp := api.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
						HookEventName: "PreToolUse", SessionID: "gap0626", ToolName: "Bash", CWD: cwd,
						ToolInput: map[string]interface{}{"command": tc.command},
						Payload:   map[string]interface{}{"tool_name": "Bash"},
					})
					want := "allow"
					if tc.blockEverywhere || tc.possible && (profile == "strict" || profile == "managed strict") {
						want = "block"
					} else if tc.possible {
						want = "alert"
					}
					if resp.Action != want {
						t.Fatalf("action=%s findings=%v want=%s", resp.Action, resp.Findings, want)
					}
					joined := strings.Join(resp.Findings, ",")
					if tc.possible && !strings.Contains(joined, "persistence.ssh_authorized_keys_possible:") {
						t.Fatalf("possible write has no finding: %v", resp.Findings)
					}
					if !tc.possible && strings.Contains(joined, "persistence.ssh_authorized_keys_possible:") {
						t.Fatalf("ordinary or named write gained a possible finding: %v", resp.Findings)
					}
					if tc.possible && want == "alert" && !strings.Contains(resp.AdditionalContext, "a HIGH Claude Code hook finding") {
						t.Fatalf("possible write has no visible warning: %+v", resp)
					}
				})
			}
		})
	}
}

func TestGAP0626CodexGitMaterializedWritePosture(t *testing.T) {
	home, repo := r104ReviewHome(t)
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(repo, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ profile, want string }{
		{"default", "alert"}, {"permissive", "alert"}, {"strict", "block"},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "codex"
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), tc.profile)
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			resp := api.evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse", SessionID: "gap0626-codex", ToolName: "exec_command", CWD: repo,
				ToolInput: map[string]interface{}{"cmd": `git -C sub pull && echo marker >> future`},
			})
			if resp.Action != tc.want || !findingStringHasRuleID(resp.Findings, "persistence.ssh_authorized_keys_possible") {
				t.Fatalf("home=%q action=%s findings=%v want=%s", home, resp.Action, resp.Findings, tc.want)
			}
		})
	}
}

func TestGAP0626ArchiveScopeStaysProfileTiered(t *testing.T) {
	home, repo := r104ReviewHome(t)
	if err := os.WriteFile(filepath.Join(repo, "x.tgz"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		profile, command, want string
	}{
		{"default", `cd /tmp && tar -xzf ~/project/x.tgz && mv src src-old`, "allow"},
		{"permissive", `cd /tmp && tar -xzf ~/project/x.tgz && mv src src-old`, "allow"},
		{"strict", `cd /tmp && tar -xzf ~/project/x.tgz && mv src src-old`, "block"},
		{"default", `cd /tmp && tar -xzf ~/project/x.tgz && cp src ~/project/alias`, "block"},
		{"strict", `cd /tmp && tar -xzf ~/project/x.tgz && cp src ~/project/alias`, "block"},
	} {
		t.Run(tc.profile+"/"+tc.command, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), tc.profile)
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			resp := api.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "gap0626-archive", ToolName: "Bash", CWD: repo,
				ToolInput: map[string]interface{}{"command": tc.command},
				Payload:   map[string]interface{}{"tool_name": "Bash"},
			})
			if resp.Action != tc.want {
				t.Fatalf("home=%q action=%s findings=%v want=%s", home, resp.Action, resp.Findings, tc.want)
			}
		})
	}
}

func TestGAP0626PossibleFindingPersists(t *testing.T) {
	_, repo := r104ReviewHome(t)
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
	api := &APIServer{scannerCfg: cfg, logger: logger, health: NewSidecarHealth()}
	resp := api.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
		HookEventName: "PreToolUse", SessionID: "gap0626-audit", ToolName: "Bash", CWD: repo,
		ToolInput: map[string]interface{}{"command": `git pull && echo marker >> future`},
		Payload:   map[string]interface{}{"tool_name": "Bash"},
	})
	if resp.Action != "alert" || !findingStringHasRuleID(resp.Findings, "persistence.ssh_authorized_keys_possible") {
		t.Fatalf("action=%s findings=%v", resp.Action, resp.Findings)
	}
	scans, err := store.ListScanResults(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) == 0 {
		t.Fatalf("scan results = %+v", scans)
	}
	found := false
	for _, scan := range scans {
		rows, err := store.ListScanFindings(scan.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.RuleID.String == "persistence.ssh_authorized_keys_possible" && row.Severity == "HIGH" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("possible finding absent from %d persisted scans", len(scans))
	}
}

func TestGAP0626SecureClientKeepsItsHookResult(t *testing.T) {
	_, repo := r104ReviewHome(t)
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{Profile: managed.ProfileSecureClient}}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	api.SetCiscoInspector(&stubAIDInspector{verdict: &ScanVerdict{Action: "allow", Severity: "NONE", Scanner: "ai-defense"}})
	resp := api.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
		HookEventName: "PreToolUse", SessionID: "gap0626-secure-client", ToolName: "Bash", CWD: repo,
		ToolInput: map[string]interface{}{"command": `git pull && echo marker >> future`},
		Payload:   map[string]interface{}{"tool_name": "Bash"},
	})
	if resp.Action != "allow" || findingStringHasRuleID(resp.Findings, "persistence.ssh_authorized_keys_possible") {
		t.Fatalf("Secure Client action=%s findings=%v", resp.Action, resp.Findings)
	}
}
