// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestGAP236OrdinaryMentionsMoveToStrictProfile(t *testing.T) {
	const home = `C:\Users\review`
	for _, row := range []struct {
		name, command, cwd string
		dialect            actionfacts.Dialect
	}{
		{"GAP-0236", "$t = @'\n.ssh/authorized_k*\n'@; Write-Output $t", home, actionfacts.DialectPowerShell},
		{"GAP-0236 display pipeline", "$t = @'\n.ssh/authorized_k*\n'@; Write-Output $t | Out-String", home, actionfacts.DialectPowerShell},
		{"GAP-0496", `bash -c 'ls -d */* | head -3'`, home, actionfacts.DialectPOSIX},
		{"GAP-0496 spaced", `bash  -c 'ls -d */* | head -3'`, home, actionfacts.DialectPOSIX},
		{"GAP-0496 env", `env bash -c 'ls -d */* | head -3'`, home, actionfacts.DialectPOSIX},
		{"GAP-0496 native form", `bash -c "ls -d */* 2>/dev/null | head -3"`, home, actionfacts.DialectPOSIX},
		{"GAP-0548 quoted option", `t="-t $HOME/.ssh"; cp "$t" a.txt`, home + `\project`, actionfacts.DialectPOSIX},
	} {
		for _, tier := range []string{"default", "permissive", "strict"} {
			for _, managed := range []bool{false, true} {
				t.Run(row.name+"/"+tier+"/"+map[bool]string{false: "user", true: "managed"}[managed], func(t *testing.T) {
					cfg := &config.Config{}
					cfg.Guardrail.Mode = "action"
					cfg.Guardrail.Connector = "codex"
					cfg.Guardrail.RulePack = tier
					if managed {
						cfg.DeploymentMode = "managed_enterprise"
						cfg.Enterprise.Profile = "standalone"
					}
					args, err := json.Marshal(map[string]string{"command": row.command})
					if err != nil {
						t.Fatal(err)
					}
					api := &APIServer{scannerCfg: cfg}
					request := &ToolInspectRequest{Tool: "Bash", Args: args, Direction: "tool_call", Connector: "codex"}
					input := actionfacts.Input{Tool: "Bash", Args: args, Command: row.command, CWD: row.cwd,
						ActiveHome: home, DialectHint: row.dialect}
					verdict := api.inspectTrustedToolPolicyCtx(t.Context(), request, trustedActionRequest{
						Input: input, LegacyText: string(args), Connector: "codex", EnforcementCapable: true,
						ProtectedHomeHook: managed,
					})
					want := "allow"
					if tier == "strict" {
						want = "block"
					}
					if verdict == nil || verdict.Action != want {
						t.Fatalf("verdict = %+v, want %s", verdict, want)
					}
					if tier != "strict" {
						warned := false
						for _, finding := range verdict.DetailedFindings {
							if finding.RuleID == "persistence.ssh_authorized_keys_command" && finding.enforcement == findingEnforcementDetectionOnly {
								warned = true
							}
						}
						if !warned {
							t.Fatal("balanced possible target has no visible finding")
						}
					}
				})
			}
		}
	}
}

func TestGAP0496KnownBashStartupRetainsBlock(t *testing.T) {
	t.Setenv("BASH_ENV", "/tmp/review-startup")
	const home = `C:\Users\review`
	if sshKeyMentionGrade(trustedActionRequest{Input: actionfacts.Input{
		Command: `bash -c 'ls -d */* | head -3'`, CWD: home, ActiveHome: home,
	}}) == hookpaths.PossibleTargetDecision {
		t.Fatal("a known Bash startup file received an ordinary disposition")
	}
}

func TestGAP236ClientProtectedTargetRetainsBlock(t *testing.T) {
	const home = `C:\Users\review`
	command := `bash -c 'ls -d */* | head -3'`
	request := trustedActionRequest{
		Input:                actionfacts.Input{Tool: "Bash", Command: command, CWD: home, ActiveHome: home},
		ResolvedWriteTargets: map[string]string{"project/link": home + `\.ssh\authorized_keys`},
	}
	if sshKeyMentionGrade(request) != hookpaths.ProtectedTargetDecision {
		t.Fatal("client-proved protected target received an ordinary disposition")
	}
	request.ResolvedWriteTargets = map[string]string{hookpaths.ActionDecisionKey: hookpaths.ProtectedTargetDecision}
	if sshKeyMentionGrade(request) != hookpaths.ProtectedTargetDecision {
		t.Fatal("client decision received an ordinary disposition")
	}
}
