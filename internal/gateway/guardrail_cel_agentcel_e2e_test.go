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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

// TestGuardrailPortableCELAgentCELE2E is an opt-in exhaustive process-boundary
// check. It consumes only an AgentCEL binary and its public bare-document CEL
// CLI; DefenseClaw does not import the AgentCEL module. Every shipped rule
// instance is loaded as a separate .cel file, and every authoritative,
// projectable CEL-targeted corpus case is compared with native typed
// evaluation.
func TestGuardrailPortableCELAgentCELE2E(t *testing.T) {
	agentCEL := os.Getenv("AGENTCEL_BIN")
	if agentCEL == "" {
		t.Skip("set AGENTCEL_BIN to an AgentCEL binary with bare document CEL support")
	}
	if info, err := os.Stat(agentCEL); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("AGENTCEL_BIN is not a regular file: %v", err)
	}

	_, rules := loadShippedGuardrailCELRules(t)
	if len(rules) == 0 {
		t.Fatal("shipped guardrail CEL inventory is empty")
	}

	directory := t.TempDir()
	rulesDirectory := filepath.Join(directory, "rules")
	if err := os.Mkdir(rulesDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	syntheticIDs := make([]string, len(rules))
	for index, rule := range rules {
		syntheticIDs[index] = fmt.Sprintf("defenseclaw_%03d", index)
		rulePath := filepath.Join(rulesDirectory, syntheticIDs[index]+".cel")
		if err := os.WriteFile(rulePath, []byte(rule.portable.Expression()+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(directory, "agentcel.yaml")
	configuration := fmt.Sprintf(
		"version: v1\nrequire_certified: false\nrules:\n  paths:\n    - %q\n  required: true\n",
		rulesDirectory,
	)
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}

	validate := exec.CommandContext(
		t.Context(), agentCEL, "validate", "--config", configPath, "--format", "json",
	)
	validationJSON, err := validate.Output()
	if err != nil {
		t.Fatalf("AgentCEL validate: %v", err)
	}
	var validation struct {
		Valid     bool `json:"valid"`
		RuleCount int  `json:"rule_count"`
	}
	if err := json.Unmarshal(validationJSON, &validation); err != nil {
		t.Fatalf("decode AgentCEL validation: %v; output=%s", err, validationJSON)
	}
	if !validation.Valid || validation.RuleCount != len(rules) {
		t.Fatalf("AgentCEL validation = %#v, want %d valid rules", validation, len(rules))
	}

	shippedRuleIDs := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		shippedRuleIDs[rule.id] = struct{}{}
	}

	corpus := readSecurityCorpus[toolCallCorpusCase](t, actionFactsSecurityCorpus)
	applicableCases := 0
	evaluations := 0
	for _, corpusCase := range corpus {
		if _, targeted := shippedRuleIDs[corpusCase.RuleID]; !targeted {
			continue
		}
		facts := actionfacts.Analyze(toolCallCorpusActionFactsInput(corpusCase))
		if !facts.Authoritative() {
			continue
		}
		projection, projectionCode := semantic.Project(facts)
		if projectionCode != semantic.ProjectionOK {
			continue
		}
		document, err := semantic.PortableDocument(projection)
		if err != nil {
			t.Fatalf("portable document case=%q: %v", corpusCase.ID, err)
		}
		documentJSON, err := json.Marshal(document)
		if err != nil {
			t.Fatalf("marshal portable document case=%q: %v", corpusCase.ID, err)
		}

		expected := make(map[string]struct{})
		for index, rule := range rules {
			result, code := rule.program.EvalBool(t.Context(), projection)
			if code != semantic.EvalOK {
				t.Fatalf("native evaluation profile=%q rule=%q case=%q: %s", rule.profile, rule.id, corpusCase.ID, code)
			}
			if result.Matched {
				expected[syntheticIDs[index]] = struct{}{}
			}
		}

		result, exitCode, stderr := scanAgentCELDocument(t, agentCEL, configPath, documentJSON)
		wantExitCode := 0
		if len(expected) != 0 {
			wantExitCode = 1
		}
		if exitCode != wantExitCode || !result.Authoritative || result.Matched != (len(expected) != 0) {
			t.Fatalf(
				"AgentCEL case=%q exit=%d result=%#v stderr=%s; want exit=%d matches=%d",
				corpusCase.ID, exitCode, result, stderr, wantExitCode, len(expected),
			)
		}
		actual := make(map[string]struct{}, len(result.Matches))
		for _, match := range result.Matches {
			if _, duplicate := actual[match.RuleID]; duplicate {
				t.Fatalf("AgentCEL case=%q repeated match %q", corpusCase.ID, match.RuleID)
			}
			actual[match.RuleID] = struct{}{}
		}
		if len(actual) != len(expected) {
			t.Fatalf("AgentCEL case=%q returned %d matches, want %d", corpusCase.ID, len(actual), len(expected))
		}
		for id := range expected {
			if _, ok := actual[id]; !ok {
				t.Fatalf("AgentCEL case=%q omitted expected match %q", corpusCase.ID, id)
			}
		}
		applicableCases++
		evaluations += len(rules)
	}
	if applicableCases != 180 || evaluations != len(rules)*applicableCases {
		t.Fatalf(
			"AgentCEL corpus coverage cases=%d evaluations=%d, want cases=180 evaluations=%d",
			applicableCases, evaluations, len(rules)*180,
		)
	}
	t.Logf(
		"AgentCEL bare-document process matrix: rule_instances=%d applicable_cases=%d evaluations=%d",
		len(rules), applicableCases, evaluations,
	)
}

type agentCELScanResult struct {
	Matched       bool `json:"matched"`
	Authoritative bool `json:"authoritative"`
	Matches       []struct {
		RuleID string `json:"rule_id"`
	} `json:"matches"`
}

func scanAgentCELDocument(
	t *testing.T,
	agentCEL string,
	configPath string,
	documentJSON []byte,
) (agentCELScanResult, int, string) {
	t.Helper()
	command := exec.CommandContext(
		t.Context(),
		agentCEL,
		"scan",
		"--config", configPath,
		"--format", "json",
		"--input-kind", "document",
		"-",
	)
	command.Stdin = bytes.NewReader(documentJSON)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			t.Fatalf("run AgentCEL: %v", runErr)
		}
		exitCode = exitErr.ExitCode()
	}
	var result agentCELScanResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode AgentCEL output: %v; stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	return result, exitCode, stderr.String()
}
