// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The five shell-recall effect rules are detection evidence. Each is a
// code-owned proof with an inert catalog pattern, and each is alert-only: no
// pack may turn one into a block, however the call is classified.
var shellRecallEffectRuleIDs = []string{
	"exec.escaped_binary_write",
	"account.literal_password_change_via_stdin",
	"exec.download_then_run_fetched_file",
	"source_control.clone_then_run_or_adhoc_push",
	"exec.inline_code_network_and_exec",
}

func shellRecallFixtureCommand(t *testing.T, fixture, caseSuffix string) string {
	t.Helper()
	_, selfPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	file, err := os.Open(filepath.Join(filepath.Dir(selfPath), "..", "..", "benchmarks", "fixtures", fixture))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for scanner.Scan() {
		var row struct {
			ID      string `json:"id"`
			Payload struct {
				Events []struct {
					Command string `json:"command"`
				} `json:"events"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(row.ID, caseSuffix) {
			continue
		}
		var commands []string
		for _, event := range row.Payload.Events {
			commands = append(commands, event.Command)
		}
		return strings.Join(commands, "; ")
	}
	t.Fatalf("fixture case %s not found in %s", caseSuffix, fixture)
	return ""
}

func TestShellRecallEffectRulesAreAlertOnlyAndNeverBlock(t *testing.T) {
	for _, id := range shellRecallEffectRuleIDs {
		contract, ok := exactFallbackContracts[id]
		if !ok || !contract.alertOnly || !contract.codeOwnedDetection || !contract.requiresExactDetectionProof ||
			contract.detectionOnly || contract.proves == nil || contract.boundedSubgraphProves == nil {
			t.Fatalf("%s contract posture = %+v, want code-owned alert-only exact proof", id, contract)
		}
	}
	const connector = "shell-recall-effects-test"
	installDefaultProfileConnector(t, connector)
	commands := map[string]string{
		// the shared download-then-execute fixture, fetch and run as one action
		"exec.download_then_run_fetched_file": shellRecallFixtureCommand(t, "download-execute-chain-v1.jsonl", "/public-ip-absolute"),
		// placeholders: reserved example hosts only
		"exec.escaped_binary_write":                   `printf '` + strings.Repeat(`\x41`, 40) + `' >> /tmp/f`,
		"account.literal_password_change_via_stdin":   `echo -e "user\nsecret\nsecret" | passwd | bash`,
		"source_control.clone_then_run_or_adhoc_push": `git push user@example.org:o/r main`,
		"exec.inline_code_network_and_exec":           `python3 -c "import urllib.request,subprocess; subprocess.call(['id']); urllib.request.urlopen('https://example.org/x')"`,
	}
	if len(commands) != len(shellRecallEffectRuleIDs) {
		t.Fatalf("commands cover %d of %d rules", len(commands), len(shellRecallEffectRuleIDs))
	}
	for _, pack := range []string{"default", "permissive", "strict"} {
		for _, id := range shellRecallEffectRuleIDs {
			t.Run(pack+"/"+id, func(t *testing.T) {
				args, err := json.Marshal(map[string]string{"command": commands[id]})
				if err != nil {
					t.Fatal(err)
				}
				cfg := &config.Config{}
				cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
				verdict := (&APIServer{scannerCfg: cfg}).inspectTrustedToolPolicyCtx(
					t.Context(),
					&ToolInspectRequest{Tool: "Bash", Args: args, Direction: "tool_call", Connector: connector},
					trustedActionRequest{
						Input:      actionfacts.Input{Tool: "Bash", Args: args, CWD: "/repo"},
						LegacyText: string(args), Connector: connector, EnforcementCapable: true,
					},
				)
				finding := findingWithID(verdict.DetailedFindings, id)
				// permissive keeps the MEDIUM source-control rule below its alert floor
				if finding == nil && !(pack == "permissive" && id == "source_control.clone_then_run_or_adhoc_push") {
					t.Fatalf("%s: rule did not fire; verdict=%+v", pack, verdict)
				}
				if finding != nil && (finding.contributesToEnforcement() || !finding.contributesToAlertOnly()) {
					t.Fatalf("%s: finding is not alert-only: %+v", pack, *finding)
				}
				if verdict.Action == guardrailActionBlock {
					t.Fatalf("%s: verdict blocked: %+v", pack, verdict)
				}
			})
		}
	}
}
