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

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestRulePackValidateWireProtocol(t *testing.T) {
	previousDir, previousJSON := rulePackValidateDir, rulePackValidateJSON
	previousOutput := rulePackValidateCmd.OutOrStdout()
	t.Cleanup(func() {
		rulePackValidateDir, rulePackValidateJSON = previousDir, previousJSON
		rulePackValidateCmd.SetOut(previousOutput)
	})

	rulePackValidateDir = shippedRulePackForCLITest(t, "default")
	rulePackValidateJSON = true
	output := &strings.Builder{}
	rulePackValidateCmd.SetOut(output)
	if err := rulePackValidateCmd.RunE(rulePackValidateCmd, nil); err != nil {
		t.Fatal(err)
	}

	var response rulePackWireResponse
	if err := json.Unmarshal([]byte(output.String()), &response); err != nil {
		t.Fatal(err)
	}
	if response.WireVersion != rulePackWireVersion ||
		response.Kind != "validation" ||
		!response.Valid ||
		response.Summary == nil ||
		response.Summary.RuleFileCount == 0 ||
		response.Summary.RuleCount == 0 ||
		len(response.Summary.Digest) != 64 ||
		response.Error != nil {
		t.Fatalf("unexpected validation response: %+v", response)
	}
}

func TestRulePackValidateWarnsWhenToolCallPatternCannotBlock(t *testing.T) {
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	const rule = "version: 1\ncategory: acme\nrules:\n  - id: ACME-TEST\n    tool_call_only: true\n    pattern: 'marker'\n    title: Marker\n    severity: HIGH\n    confidence: 0.9\n    tags: [test]\n"
	if err := os.WriteFile(filepath.Join(directory, "rules", "acme.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	previousDir, previousJSON := rulePackValidateDir, rulePackValidateJSON
	previousOutput := rulePackValidateCmd.OutOrStdout()
	t.Cleanup(func() {
		rulePackValidateDir, rulePackValidateJSON = previousDir, previousJSON
		rulePackValidateCmd.SetOut(previousOutput)
	})
	rulePackValidateDir, rulePackValidateJSON = directory, false
	output := &strings.Builder{}
	rulePackValidateCmd.SetOut(output)
	if err := rulePackValidateCmd.RunE(rulePackValidateCmd, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "warning: 1 enabled tool_call_only rules have no expression") {
		t.Fatalf("missing detection-only warning: %s", output)
	}
}

func TestRulePackValidateFailureIsStructuredAndValueSafe(t *testing.T) {
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	const secretLikeSeverity = "private-secret-like-severity"
	raw := `version: 1
category: command
rules:
  - id: TEST-COMMAND
    pattern: '\btrue\b'
    title: Test command
    severity: ` + secretLikeSeverity + `
    confidence: 0.9
    tags: [test]
`
	if err := os.WriteFile(filepath.Join(directory, "rules", "commands.yaml"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	previousDir, previousJSON := rulePackValidateDir, rulePackValidateJSON
	previousOutput := rulePackValidateCmd.OutOrStdout()
	t.Cleanup(func() {
		rulePackValidateDir, rulePackValidateJSON = previousDir, previousJSON
		rulePackValidateCmd.SetOut(previousOutput)
	})

	rulePackValidateDir = directory
	rulePackValidateJSON = true
	output := &strings.Builder{}
	rulePackValidateCmd.SetOut(output)
	err := rulePackValidateCmd.RunE(rulePackValidateCmd, nil)
	if err == nil {
		t.Fatal("rulepack validate accepted an invalid severity")
	}
	if strings.Contains(err.Error(), secretLikeSeverity) || strings.Contains(output.String(), secretLikeSeverity) {
		t.Fatalf("validation diagnostic leaked rejected value: err=%v output=%s", err, output)
	}

	var response rulePackWireResponse
	if decodeErr := json.Unmarshal([]byte(output.String()), &response); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if response.WireVersion != rulePackWireVersion ||
		response.Kind != "validation_error" ||
		response.Valid ||
		response.Error == nil ||
		response.Error.Code == "" ||
		response.Error.Path == "" ||
		response.Error.Reason == "" ||
		response.Summary != nil {
		t.Fatalf("unexpected validation failure: %+v", response)
	}
}

func TestRulePackMachineCommandBypassesRuntimeInitialization(t *testing.T) {
	previousConfig, previousStore, previousLog := cfg, auditStore, auditLog
	cfg, auditStore, auditLog = nil, nil, nil
	t.Cleanup(func() {
		cfg, auditStore, auditLog = previousConfig, previousStore, previousLog
	})
	if rulePackCmd.PersistentPreRunE == nil || rulePackCmd.PersistentPostRun == nil {
		t.Fatal("rulepack helper must override root runtime hooks")
	}
	if err := rulePackCmd.PersistentPreRunE(rulePackCmd, nil); err != nil {
		t.Fatal(err)
	}
	if cfg != nil || auditStore != nil || auditLog != nil {
		t.Fatal("offline rulepack helper initialized runtime state")
	}
}

func TestRulePackDiagnosticRejectsUnsafeExportedErrorFields(t *testing.T) {
	diagnostic := rulePackDiagnostic(errors.New("unstructured secret-like failure"))
	if diagnostic.Path != "$" ||
		diagnostic.Code != "rulepack_invalid" ||
		diagnostic.Reason != "rule pack could not be validated safely" {
		t.Fatalf("unexpected fallback diagnostic: %+v", diagnostic)
	}

	diagnostic = rulePackDiagnostic(&guardrail.RulePackError{
		Path:   "rules/\nsecret.yaml",
		Code:   "Not-Safe",
		Reason: "unsafe\rreason",
	})
	if diagnostic.Path != "$" ||
		diagnostic.Code != "rulepack_invalid" ||
		diagnostic.Reason != "rule pack could not be validated safely" {
		t.Fatalf("unsafe diagnostic fields were not rejected: %+v", diagnostic)
	}
}

func shippedRulePackForCLITest(t *testing.T, profile string) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve rulepack test source path")
	}
	return filepath.Join(filepath.Dir(source), "..", "..", "policies", "guardrail", profile)
}

// The validator is the rule-pack check enterprise hosts have (they ship no
// defenseclaw CLI), so it is listed in help.
func TestRulePackValidateIsAVisibleCommand(t *testing.T) {
	command, _, err := rootCmd.Find([]string{"rulepack", "validate"})
	if err != nil || command != rulePackValidateCmd {
		t.Fatalf("rulepack validate is not registered: %v", err)
	}
	for current := command; current != nil && current != rootCmd; current = current.Parent() {
		if current.Hidden {
			t.Fatalf("%q is hidden from help", current.CommandPath())
		}
	}
	if rulePackValidateCmd.Flags().Lookup("dir") == nil || rulePackValidateCmd.Flags().Lookup("json") == nil {
		t.Fatal("rulepack validate lost its --dir or --json flag")
	}
}

// GAP-1274: a pack the service account cannot read is not "valid" with exit 0
// in text mode; --json keeps its validity-only contract.
func TestRulePackValidateFailsWhenTheGatewayCannotLoadThePack(t *testing.T) {
	previousDir, previousJSON := rulePackValidateDir, rulePackValidateJSON
	previousOutput, previousProblem := rulePackValidateCmd.OutOrStdout(), rulePackServiceReadProblemFn
	previousErr := rulePackValidateCmd.ErrOrStderr()
	t.Cleanup(func() {
		rulePackValidateDir, rulePackValidateJSON = previousDir, previousJSON
		rulePackValidateCmd.SetOut(previousOutput)
		rulePackValidateCmd.SetErr(previousErr)
		rulePackServiceReadProblemFn = previousProblem
	})
	rulePackServiceReadProblemFn = func(context.Context, string) string { return "the folder is 0700" }
	rulePackValidateDir = shippedRulePackForCLITest(t, "default")

	rulePackValidateJSON = false
	output := &strings.Builder{}
	rulePackValidateCmd.SetOut(output)
	rulePackValidateCmd.SetErr(&strings.Builder{})
	err := rulePackValidateCmd.RunE(rulePackValidateCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "the gateway cannot load this pack: the folder is 0700") {
		t.Fatalf("text mode err = %v", err)
	}
	if strings.Contains(output.String(), "valid rule pack:") || !strings.Contains(output.String(), "syntax is valid") {
		t.Fatalf("text mode output = %q", output.String())
	}

	rulePackValidateJSON = true
	output.Reset()
	if err := rulePackValidateCmd.RunE(rulePackValidateCmd, nil); err != nil {
		t.Fatalf("json mode err = %v", err)
	}
}

// GAP-1405: a missing --dir is named in the text output and the error, not
// reported "at .".
func TestRulePackValidateMissingDirNamesTheDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nonexistent-rs3")
	previousDir, previousJSON := rulePackValidateDir, rulePackValidateJSON
	previousOutput := rulePackValidateCmd.OutOrStdout()
	t.Cleanup(func() {
		rulePackValidateDir, rulePackValidateJSON = previousDir, previousJSON
		rulePackValidateCmd.SetOut(previousOutput)
	})
	rulePackValidateDir = missing
	rulePackValidateJSON = false
	output := &strings.Builder{}
	rulePackValidateCmd.SetOut(output)
	err := rulePackValidateCmd.RunE(rulePackValidateCmd, nil)
	if err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("error = %v, want it to name %s", err, missing)
	}
	if !strings.Contains(output.String(), "at "+missing+":") {
		t.Fatalf("text output does not name the directory:\n%s", output)
	}
}

func TestRulePackValidateSecureClientTextMatchesMain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("config_version: 8\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: secure_client\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_CONFIG", path)
	summary := guardrail.RulePackSummary{RuleFileCount: 2, RuleCount: 3, Digest: strings.Repeat("a", 64)}
	output := &strings.Builder{}
	if err := writeRulePackValidation(output, rulePackWireResponse{Valid: true, Summary: &summary}, false); err != nil {
		t.Fatal(err)
	}
	want := "valid rule pack: 2 files, 3 rules, digest " + strings.Repeat("a", 64) + "\n"
	if output.String() != want {
		t.Fatalf("Secure Client validation = %q, want %q", output.String(), want)
	}
}
