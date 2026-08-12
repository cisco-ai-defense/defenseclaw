// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func requireNativePOSIXArtifactHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("native Windows paths do not have one authoritative POSIX shell mapping")
	}
}

func TestPromotedArtifactFindingsBlocksOnlyAuthoritativeFinalBytes(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "artifact-promotion-test"
	installDefaultProfileConnector(t, connectorName)
	dir := t.TempDir()
	tests := []struct {
		name        string
		body        string
		wantRule    string
		enforceable bool
	}{
		{name: "destructive", body: "#!/bin/sh\nrm -rf /\n", wantRule: "CMD-RM-RF", enforceable: true},
		{name: "benign", body: "#!/bin/sh\nprintf '%s\\n' build-complete\n"},
		{
			name: "control flow remains detection only",
			body: "#!/bin/sh\nfalse && rm -rf /\n", wantRule: "CMD-RM-RF",
		},
		{
			name: "exit makes later command unreachable",
			body: "#!/bin/sh\nexit 0\nrm -rf /\n", wantRule: "CMD-RM-RF",
		},
		{
			name: "exec makes later command unreachable",
			body: "#!/bin/sh\nexec true\nrm -rf /\n", wantRule: "CMD-RM-RF",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, test.name+".sh")
			if err := os.WriteFile(path, []byte(test.body), 0o700); err != nil {
				t.Fatal(err)
			}
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool: "shell", Command: fmt.Sprintf("bash %q", path), CWD: dir,
			})
			findings := promotedArtifactFindings(t.Context(), agentHookRequest{
				ConnectorName: connectorName,
			}, facts, true)
			var matched *RuleFinding
			for index := range findings {
				if findings[index].RuleID == test.wantRule {
					matched = &findings[index]
					break
				}
			}
			if test.wantRule == "" {
				if len(findings) != 0 {
					t.Fatalf("benign final bytes produced findings: %v", FindingStrings(findings))
				}
				return
			}
			if matched == nil {
				t.Fatalf("missing %s: %v facts=%+v", test.wantRule, FindingStrings(findings), facts)
			}
			if got := matched.contributesToEnforcement(); got != test.enforceable {
				t.Fatalf(
					"enforceable=%t want %t: %+v outer=%+v projected=%+v",
					got,
					test.enforceable,
					*matched,
					facts,
					facts.EnforcementProjection(),
				)
			}
		})
	}
}

func TestPromotedArtifactHonorsPOSIXNoExecScriptMode(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "artifact-noexec-script-test"
	installDefaultProfileConnector(t, connectorName)
	home := trustedSameHostHome()
	if home == "" {
		t.Skip("same-host home unavailable")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "runner-cleanup.sh")
	statePath := filepath.Join(
		home,
		".defenseclaw",
		"quarantine",
		"skills",
		"e2e-stale",
	)
	body := fmt.Sprintf("#!/bin/sh\nrm -rf -- %q\n", statePath)
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name        string
		invocation  string
		enforceable bool
	}{
		{name: "bash short noexec", invocation: "bash -n"},
		{name: "bash named noexec", invocation: "bash -o noexec"},
		{name: "sh noexec", invocation: "sh -n"},
		{name: "dash noexec", invocation: "dash -n"},
		{name: "bash verbose noexec", invocation: "bash -nv"},
		{name: "bash final verbose noexec", invocation: "bash +v -nv"},
		{name: "bash named verbose noexec", invocation: "bash -o noexec -o verbose"},
		{name: "bash long verbose noexec", invocation: "bash --verbose -n"},
		{name: "sh verbose noexec", invocation: "sh -nv"},
		{name: "dash verbose noexec", invocation: "dash -nv"},
		{name: "bash verbose disabled", invocation: "bash -nv +v"},
		{name: "bash named verbose disabled", invocation: "bash -o noexec -o verbose +o verbose"},
		{name: "sh verbose disabled", invocation: "sh -nv +v"},
		{name: "dash verbose disabled", invocation: "dash -nv +v"},
		{name: "bash short noexec re-enabled", invocation: "bash -n +n", enforceable: true},
		{name: "bash named noexec re-enabled", invocation: "bash -o noexec +o noexec", enforceable: true},
		{name: "sh noexec re-enabled", invocation: "sh -n +n", enforceable: true},
		{name: "dash noexec re-enabled", invocation: "dash -n +n", enforceable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool:    "shell",
				Command: fmt.Sprintf("%s %q", test.invocation, path),
				CWD:     dir,
			})
			findings := promotedArtifactFindings(t.Context(), agentHookRequest{
				ConnectorName: connectorName,
			}, facts, true)
			matched := findingWithID(findings, "tamper.detector_state_write")
			if !test.enforceable {
				if len(findings) != 0 {
					t.Fatalf(
						"no-exec script produced findings: %v facts=%+v",
						FindingStrings(findings),
						facts,
					)
				}
				return
			}
			if matched == nil || !matched.contributesToEnforcement() {
				t.Fatalf(
					"re-enabled script lost enforceable tamper finding: %v facts=%+v",
					FindingStrings(findings),
					facts,
				)
			}
		})
	}
}

func TestPOSIXNoExecArtifactPipelineRetainsFinding(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "artifact-noexec-pipeline-test"
	installDefaultProfileConnector(t, connectorName)
	home := trustedSameHostHome()
	if home == "" {
		t.Skip("same-host home unavailable")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bad\nprintf SAFE_FILENAME_MARKER\n#")
	statePath := filepath.Join(
		home, ".defenseclaw", "quarantine", "skills", "e2e-stale",
	)
	if err := os.WriteFile(
		path,
		[]byte(fmt.Sprintf("#!/bin/sh\nrm -rf -- %q\n(\n", statePath)),
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		format string
	}{
		{name: "bash", format: "bash -n '%s' 2>/dev/stdout | bash"},
		{name: "bash verbose", format: "bash -nv '%s' 2>/dev/stdout | bash"},
		{name: "sh", format: "sh -n '%s' 2>/dev/stdout | bash"},
		{name: "dash verbose", format: "dash -nv '%s' 2>/dev/stdout | bash"},
		{name: "env bash", format: "env bash -n '%s' 2>/dev/stdout | bash"},
		{name: "command sh", format: "command -- sh -n '%s' 2>/dev/stdout | bash"},
		{name: "exec dash", format: "exec dash -n '%s' 2>/dev/stdout | bash"},
		{name: "subshell", format: "(bash -n '%s') 2>/dev/stdout | bash"},
		{name: "block", format: "{ bash -n '%s'; } 2>/dev/stdout | bash"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := fmt.Sprintf(test.format, path)
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool: "shell", Command: command, CWD: dir, ActiveHome: home,
			})
			findings := promotedArtifactFindings(t.Context(), agentHookRequest{
				ConnectorName: connectorName,
			}, facts, true)
			matched := findingWithID(findings, "tamper.detector_state_write")
			if matched == nil {
				t.Fatalf("no-exec pipeline lost tamper finding: %v facts=%+v", FindingStrings(findings), facts)
			}
			if matched.contributesToEnforcement() {
				t.Fatalf("pipeline artifact unexpectedly became enforceable: %+v", *matched)
			}
		})
	}
}

func TestPOSIXNoExecCommandPipelineRetainsFinding(t *testing.T) {
	const connectorName = "noexec-command-pipeline-test"
	installDefaultProfileConnector(t, connectorName)
	for _, test := range []struct {
		name    string
		command string
	}{
		{name: "bash", command: `bash -n -c 'rm -rf /' 2>&1 | bash`},
		{name: "bash verbose", command: `bash -nv -c 'rm -rf /' 2>&1 | bash`},
		{name: "env bash", command: `env bash -n -c 'rm -rf /' 2>&1 | bash`},
		{name: "command sh", command: `command -- sh -n -c 'rm -rf /' 2>&1 | bash`},
		{name: "exec dash", command: `exec dash -n -c 'rm -rf /' 2>&1 | bash`},
	} {
		t.Run(test.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]string{"command": test.command})
			if err != nil {
				t.Fatal(err)
			}
			for _, input := range []actionfacts.Input{
				{Tool: "shell", Command: test.command, CWD: "/repo"},
				{Tool: "Bash", Args: args, CWD: "/repo"},
			} {
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: test.command, Connector: connectorName,
					EnforcementCapable: true,
				})
				if findingWithID(findings, "CMD-RM-RF") == nil {
					t.Fatalf("no-exec command pipeline lost finding: %v", FindingStrings(findings))
				}
			}
		})
	}
}

func TestPOSIXNoExecScriptRedirectRetainsStateMutationDetection(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "artifact-noexec-redirect-test"
	installDefaultProfileConnector(t, connectorName)
	home := trustedSameHostHome()
	if home == "" {
		t.Skip("same-host home unavailable")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "runner-cleanup.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf safe\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(
		home,
		".defenseclaw",
		"quarantine",
		"skills",
		"redirected-output",
	)
	command := fmt.Sprintf("bash -n %q > %q", script, target)
	input := actionfacts.Input{
		Tool: "shell", Command: command, CWD: dir, ActiveHome: home,
	}
	facts := actionfacts.Analyze(input)
	sawScriptExecute := false
	sawTargetWrite := false
	for _, path := range facts.Paths {
		sawScriptExecute = sawScriptExecute || path.Access == actionfacts.PathAccessExecute &&
			semanticPathValue(path) == canonicalSemanticPath(script)
		sawTargetWrite = sawTargetWrite || path.Access == actionfacts.PathAccessWrite &&
			semanticPathValue(path) == canonicalSemanticPath(target)
	}
	if facts.Parse.Status != actionfacts.StatusPartial || facts.Authoritative() ||
		!sawScriptExecute || !sawTargetWrite {
		t.Fatalf("no-exec redirect facts=%+v", facts)
	}
	if findings := promotedArtifactFindings(
		t.Context(),
		agentHookRequest{ConnectorName: connectorName},
		facts,
		true,
	); len(findings) != 0 {
		t.Fatalf("safe redirected script produced artifact findings: %v", FindingStrings(findings))
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: command, Connector: connectorName,
		EnforcementCapable: true,
	})
	matched := findingWithID(findings, "tamper.detector_state_write")
	if matched == nil || matched.contributesToEnforcement() {
		t.Fatalf("redirect lost fallback tamper finding: %v", FindingStrings(findings))
	}
}

func TestReadPromotedArtifactRejectsPathIndirection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ordinary users cannot reliably create a Windows symlink fixture")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.sh")
	link := filepath.Join(dir, "link.sh")
	if err := os.WriteFile(target, []byte("#!/bin/sh\nrm -rf /\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if body, _, ok := readPromotedArtifact(link, actionfacts.DialectPOSIX); ok || len(body) != 0 {
		t.Fatal("symlinked artifact became enforcement input")
	}
}

func TestReadPromotedArtifactRequiresExecuteBitOnlyForDirectPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not use POSIX execute permission bits")
	}
	path := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nrm -rf /\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := readPromotedArtifact(path, actionfacts.DialectNone); ok {
		t.Fatal("non-executable direct path was promoted")
	}
	if _, dialect, ok := readPromotedArtifact(
		path,
		actionfacts.DialectPOSIX,
	); !ok || dialect != actionfacts.DialectPOSIX {
		t.Fatal("explicit interpreter lost readable non-executable script")
	}
}

func TestPromotedArtifactUsesInvocationWorkingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX working-directory semantics")
	}
	const connectorName = "artifact-cwd-test"
	installDefaultProfileConnector(t, connectorName)
	file, err := os.CreateTemp("/tmp", "defenseclaw-artifact-cwd-*.sh")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	t.Cleanup(func() { _ = os.Remove(path) })
	if _, err := file.WriteString("#!/bin/sh\nrm -rf ..\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name        string
		cwd         string
		enforceable bool
	}{
		{name: "caller in tmp", cwd: "/tmp", enforceable: true},
		{name: "caller in project", cwd: "/tmp/project", enforceable: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := actionfacts.Analyze(actionfacts.Input{
				Tool: "shell", Command: fmt.Sprintf("bash %q", path), CWD: test.cwd,
			})
			findings := promotedArtifactFindings(t.Context(), agentHookRequest{
				ConnectorName: connectorName,
			}, facts, true)
			got := false
			for _, finding := range findings {
				got = got || finding.RuleID == "CMD-RM-RF" && finding.contributesToEnforcement()
			}
			if got != test.enforceable {
				t.Fatalf("enforceable=%t want %t findings=%v", got, test.enforceable, FindingStrings(findings))
			}
		})
	}
}

func TestPromotedArtifactShebangDialectRequiresExactInterpreter(t *testing.T) {
	tests := []struct {
		line string
		want actionfacts.Dialect
	}{
		{line: "#!/bin/sh", want: actionfacts.DialectPOSIX},
		{line: "#!/usr/bin/bash", want: actionfacts.DialectPOSIX},
		{line: "#!/usr/bin/env bash", want: actionfacts.DialectPOSIX},
		{line: "#!/usr/local/bin/pwsh", want: actionfacts.DialectPowerShell},
		{line: "#!/usr/bin/env pwsh", want: actionfacts.DialectPowerShell},
		{line: "#!/usr/bin/shadow", want: actionfacts.DialectNone},
		{line: "#!/usr/bin/env bashful", want: actionfacts.DialectNone},
		{line: "#!/opt/notpowershell", want: actionfacts.DialectNone},
		{line: "#!/usr/bin/env -S bash", want: actionfacts.DialectNone},
		{line: "#!/bin/sh -e", want: actionfacts.DialectNone},
		{line: "#!sh", want: actionfacts.DialectNone},
		{line: "  #!/bin/sh", want: actionfacts.DialectNone},
		{line: "#!/bin/sh\r", want: actionfacts.DialectNone},
	}
	for _, test := range tests {
		t.Run(test.line, func(t *testing.T) {
			if got := promotedArtifactShebangDialect([]byte(test.line + "\n")); got != test.want {
				t.Fatalf("dialect=%q want %q", got, test.want)
			}
		})
	}
}

func TestExperimentalArtifactPromotionRequiresReviewedStructuredRoute(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	installDefaultProfileConnector(t, "claudecode")
	path := filepath.Join(t.TempDir(), "assembled.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nrm -rf /\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool: "shell", Command: fmt.Sprintf("bash %q", path), CWD: filepath.Dir(path),
	})
	capture := &toolChainHookCapture{}
	capture.recordTrustedAction(facts, nil)
	req := agentHookRequest{
		ConnectorName:           "claudecode",
		HookEventName:           "PreToolUse",
		SuppressCorrelationEmit: true,
		toolChain:               capture,
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
	api := &APIServer{scannerCfg: cfg}
	profile := api.hookProfileForConnector("claudecode")
	original := agentHookResponse{
		Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action",
	}

	got := api.safeApplyExperimentalArtifactPromotion(
		t.Context(), profile, req, original, 0,
	)
	if got.Action != guardrailActionBlock {
		t.Fatalf("reviewed pre-tool route action=%q findings=%v", got.Action, got.RuleIDs)
	}

	unknown := req
	unknown.HookEventName = "pretooluse"
	if got := api.safeApplyExperimentalArtifactPromotion(
		t.Context(), profile, unknown, original, 0,
	); got.Action != original.Action || len(got.RuleIDs) != 0 {
		t.Fatalf("undeclared event entered artifact path: %+v", got)
	}

	unreviewed := profile
	unreviewed.ToolCallLifecycle = connector.ToolCallLifecycleContract{}
	if got := api.safeApplyExperimentalArtifactPromotion(
		t.Context(), unreviewed, req, original, 0,
	); got.Action != original.Action || len(got.RuleIDs) != 0 {
		t.Fatalf("unreviewed contract entered artifact path: %+v", got)
	}
}

func TestPromotedArtifactOuterControlFlowIsDetectionOnly(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "artifact-outer-control-test"
	installDefaultProfileConnector(t, connectorName)
	path := filepath.Join(t.TempDir(), "destructive.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nrm -rf /\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		fmt.Sprintf("false && bash %q", path),
		fmt.Sprintf("true || bash %q", path),
	} {
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "shell", Command: command})
		findings := promotedArtifactFindings(t.Context(), agentHookRequest{
			ConnectorName: connectorName,
		}, facts, true)
		var matched *RuleFinding
		for index := range findings {
			if findings[index].RuleID == "CMD-RM-RF" {
				matched = &findings[index]
				break
			}
		}
		if matched == nil {
			t.Fatalf("outer control flow lost detection for %q", command)
		}
		if matched.contributesToEnforcement() {
			t.Fatalf("outer control flow became enforceable for %q: %+v", command, *matched)
		}
	}
}

func TestPromotedArtifactFactsParticipateInToolChains(t *testing.T) {
	requireNativePOSIXArtifactHost(t)
	const connectorName = "artifact-chain-test"
	installDefaultProfileConnector(t, connectorName)
	dir := t.TempDir()
	for _, test := range []struct {
		name string
		body string
		step int
	}{
		{name: "predecessor", body: "#!/bin/sh\nsudo -l\n", step: 1},
		{name: "terminal", body: "#!/bin/sh\nsudo -u root /bin/sh\n", step: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, test.name+".sh")
			if err := os.WriteFile(path, []byte(test.body), 0o700); err != nil {
				t.Fatal(err)
			}
			outer := actionfacts.Analyze(actionfacts.Input{
				Tool: "shell", Command: fmt.Sprintf("bash %q", path), CWD: dir,
			})
			capture := &toolChainHookCapture{}
			capture.recordTrustedAction(outer, nil)
			req := agentHookRequest{
				ConnectorName: connectorName,
				toolChain:     capture,
			}
			_ = promotedArtifactFindings(t.Context(), req, outer, true)
			projection, _ := projectAgentHookToolChains(
				req,
				connector.ToolCallLifecycleContract{},
			)
			assertToolChainStep(
				t,
				projection,
				guardrail.ToolChainPrivilegeDiscoveryThenElevation,
				test.step,
				true,
			)
		})
	}
}

func TestPromotedWindowsArtifactFactsParticipateInToolChains(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-native artifact integration")
	}
	const connectorName = "windows-artifact-chain-test"
	installDefaultProfileConnector(t, connectorName)
	home := trustedSameHostHome()
	if home == "" {
		t.Skip("Windows home directory unavailable")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "credential-read.ps1")
	credentialPath := filepath.Join(home, ".aws", "credentials")
	body := "Get-Content '" + strings.ReplaceAll(credentialPath, "'", "''") + "'\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	quotedPath := strings.ReplaceAll(path, "'", "''")
	outer := actionfacts.Analyze(actionfacts.Input{
		Tool:        "powershell",
		Command:     "& '" + quotedPath + "'",
		CWD:         dir,
		DialectHint: actionfacts.DialectPowerShell,
	})
	capture := &toolChainHookCapture{}
	capture.recordTrustedAction(outer, nil)
	req := agentHookRequest{
		ConnectorName: connectorName,
		toolChain:     capture,
	}
	_ = promotedArtifactFindings(t.Context(), req, outer, true)
	projection, _ := projectAgentHookToolChains(
		req,
		connector.ToolCallLifecycleContract{},
	)
	assertToolChainStep(
		t,
		projection,
		guardrail.ToolChainSecretReadThenEgress,
		1,
		false,
	)
}

func TestPromotedWindowsArtifactTrailingLineEndingEnforcement(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-native artifact integration")
	}
	const connectorName = "windows-artifact-enforcement-test"
	installDefaultProfileConnector(t, connectorName)
	dir := t.TempDir()
	for _, test := range []struct {
		name        string
		body        string
		wantRule    string
		enforceable bool
	}{
		{
			name: "destructive CRLF", body: "Remove-Item -Recurse -Force C:\\\r\n",
			wantRule: "CMD-RM-RF", enforceable: true,
		},
		{
			name:     "runtime bypass CRLF",
			body:     "codex exec --dangerously-bypass-approvals-and-sandbox\r\n",
			wantRule: "exec.agent_runtime_bypass_flags", enforceable: true,
		},
		{
			name:     "straight-line interior CRLF is enforceable",
			body:     "Write-Output ready\r\nRemove-Item -Recurse -Force C:\\\r\n",
			wantRule: "CMD-RM-RF", enforceable: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, test.name+".ps1")
			if err := os.WriteFile(path, []byte(test.body), 0o600); err != nil {
				t.Fatal(err)
			}
			quotedPath := strings.ReplaceAll(path, "'", "''")
			outer := actionfacts.Analyze(actionfacts.Input{
				Tool: "powershell", Command: "powershell -NoProfile -File '" + quotedPath + "'",
				CWD: dir, DialectHint: actionfacts.DialectPowerShell,
			})
			findings := promotedArtifactFindings(
				t.Context(),
				agentHookRequest{ConnectorName: connectorName},
				outer,
				true,
			)
			var matched *RuleFinding
			for index := range findings {
				if findings[index].RuleID == test.wantRule {
					matched = &findings[index]
					break
				}
			}
			if matched == nil {
				t.Fatalf("missing %s: %v outer=%+v", test.wantRule, FindingStrings(findings), outer)
			}
			if got := matched.contributesToEnforcement(); got != test.enforceable {
				t.Fatalf("enforceable=%t want %t: %+v", got, test.enforceable, *matched)
			}
		})
	}
}

func TestPromotedWindowsCMDAndBATFinalBytes(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-native artifact integration")
	}
	const connectorName = "claudecode"
	installDefaultProfileConnector(t, connectorName)
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connectorName
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
	api := &APIServer{scannerCfg: cfg}
	profile := api.hookProfileForConnector(connectorName)
	original := agentHookResponse{
		Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action",
	}

	for _, extension := range []string{".cmd", ".bat"} {
		t.Run(strings.TrimPrefix(extension, "."), func(t *testing.T) {
			for _, test := range []struct {
				name      string
				body      string
				wantBlock bool
			}{
				{
					name: "destructive", body: "rmdir /s /q C:\\\r\n",
					wantBlock: true,
				},
				{
					name: "quoted benign control",
					body: "echo \"rmdir /s /q C:\\\"\r\n",
				},
			} {
				t.Run(test.name, func(t *testing.T) {
					path := filepath.Join(dir, test.name+extension)
					if err := os.WriteFile(path, []byte(test.body), 0o600); err != nil {
						t.Fatal(err)
					}
					outer := actionfacts.Analyze(actionfacts.Input{
						Tool: "cmd", Command: `"` + path + `"`, CWD: dir,
						DialectHint: actionfacts.DialectCMD,
					})
					findings := promotedArtifactFindings(
						t.Context(),
						agentHookRequest{ConnectorName: connectorName},
						outer,
						true,
					)
					if test.wantBlock {
						if len(findings) != 1 || findings[0].RuleID != "CMD-RM-RF" ||
							!findings[0].contributesToEnforcement() {
							t.Fatalf("destructive final bytes findings=%+v outer=%+v", findings, outer)
						}
					} else if len(findings) != 0 {
						t.Fatalf("quoted final bytes produced findings: %v", FindingStrings(findings))
					}

					capture := &toolChainHookCapture{}
					capture.recordTrustedAction(outer, nil)
					req := agentHookRequest{
						ConnectorName:           connectorName,
						HookEventName:           "PreToolUse",
						SuppressCorrelationEmit: true,
						toolChain:               capture,
					}
					got := api.safeApplyExperimentalArtifactPromotion(
						t.Context(), profile, req, original, 0,
					)
					wantAction, wantRawAction := original.Action, original.RawAction
					if test.wantBlock {
						wantAction, wantRawAction = guardrailActionBlock, guardrailActionBlock
					}
					if got.Action != wantAction || got.RawAction != wantRawAction {
						t.Fatalf(
							"action/raw=%q/%q want %q/%q findings=%v outer=%+v",
							got.Action, got.RawAction, wantAction, wantRawAction,
							got.Findings, outer,
						)
					}
				})
			}
		})
	}
}

func TestPromotedArtifactDirectSuffixDoesNotInventInterpreter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-directly-executable.ps1")
	if err := os.WriteFile(
		path,
		[]byte(`Remove-Item -Recurse -Force C:\`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	facts := actionfacts.Facts{
		Parse: actionfacts.ParseResult{
			Status:  actionfacts.StatusComplete,
			Dialect: actionfacts.DialectPOSIX,
		},
		Commands: []actionfacts.CommandFact{{
			ID: 1, Kind: actionfacts.CommandKindProcess,
			Dialect: actionfacts.DialectPOSIX, Effect: actionfacts.EffectExecute,
			Program: path, Executable: path, Argv: []string{path}, ArgvComplete: true,
		}},
		Paths: []actionfacts.PathFact{{
			CommandID: 1, Access: actionfacts.PathAccessExecute,
			Flavor: actionfacts.PathFlavorPOSIX, Value: path,
			Normalized: path, Resolved: path, Absolute: true,
		}},
	}
	if findings := promotedArtifactFindings(
		t.Context(),
		agentHookRequest{ConnectorName: "artifact-direct-suffix-test"},
		facts,
		true,
	); len(findings) != 0 {
		t.Fatalf("suffix-only direct path produced findings: %v", FindingStrings(findings))
	}
}

func TestPromotedArtifactDialectRequiresAmbientWindowsShellAuthority(t *testing.T) {
	tests := []struct {
		name    string
		command actionfacts.CommandFact
		path    actionfacts.PathFact
		want    actionfacts.Dialect
		ok      bool
	}{
		{
			name: "PowerShell dot source",
			command: actionfacts.CommandFact{
				Program: ".", Dialect: actionfacts.DialectPowerShell,
			},
			path: actionfacts.PathFact{
				Access: actionfacts.PathAccessRead, Normalized: `C:\work\task.ps1`,
			},
			want: actionfacts.DialectPowerShell, ok: true,
		},
		{
			name: "POSIX dot source",
			command: actionfacts.CommandFact{
				Program: ".", Dialect: actionfacts.DialectPOSIX,
			},
			path: actionfacts.PathFact{
				Access: actionfacts.PathAccessRead, Normalized: "/tmp/task.sh",
			},
			want: actionfacts.DialectPOSIX, ok: true,
		},
		{
			name: "PowerShell direct script",
			command: actionfacts.CommandFact{
				Program: `C:\work\task.ps1`, Dialect: actionfacts.DialectPowerShell,
			},
			path: actionfacts.PathFact{
				Access: actionfacts.PathAccessExecute, Normalized: `C:\work\task.ps1`,
			},
			want: actionfacts.DialectPowerShell, ok: true,
		},
		{
			name: "CMD direct script",
			command: actionfacts.CommandFact{
				Program: `C:\work\task.cmd`, Dialect: actionfacts.DialectCMD,
			},
			path: actionfacts.PathFact{
				Access: actionfacts.PathAccessExecute, Normalized: `C:\work\task.cmd`,
			},
			want: actionfacts.DialectCMD, ok: true,
		},
		{
			name: "POSIX suffix alone",
			command: actionfacts.CommandFact{
				Program: "/tmp/task.ps1", Dialect: actionfacts.DialectPOSIX,
			},
			path: actionfacts.PathFact{
				Access: actionfacts.PathAccessExecute, Normalized: "/tmp/task.ps1",
			},
			want: actionfacts.DialectNone, ok: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := promotedArtifactDialect(test.command, test.path)
			if got != test.want || ok != test.ok {
				t.Fatalf("dialect/ok=%q/%t want %q/%t", got, ok, test.want, test.ok)
			}
		})
	}
}
