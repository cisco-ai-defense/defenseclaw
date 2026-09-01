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

	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

// TestGuardrailPortableCELAgentCELE2E is an opt-in process-boundary check. It
// intentionally consumes only an AgentCEL binary and its public bare-document
// CEL CLI; DefenseClaw does not import the AgentCEL module.
func TestGuardrailPortableCELAgentCELE2E(t *testing.T) {
	agentCEL := os.Getenv("AGENTCEL_BIN")
	if agentCEL == "" {
		t.Skip("set AGENTCEL_BIN to an AgentCEL binary with bare document CEL support")
	}
	if info, err := os.Stat(agentCEL); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("AGENTCEL_BIN is not a regular file: %v", err)
	}

	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	expression := `f.commands.exists(c, c.id == 9007199254740993 && ` +
		`defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_DELETE in c.operations)`
	portable, code := compiler.CompilePortable(expression)
	if code != semantic.CompileOK || portable == nil {
		t.Fatalf("CompilePortable() = (%v, %q)", portable, code)
	}
	document, err := semantic.PortableDocument(&semanticpb.Facts{
		Commands: []*semanticpb.CommandFact{{
			Id:         9007199254740993,
			Operations: []semanticpb.OperationKind{semanticpb.OperationKind_OPERATION_KIND_DELETE},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	documentJSON, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	directory := t.TempDir()
	rulePath := filepath.Join(directory, "defenseclaw_actionfacts.cel")
	if err := os.WriteFile(rulePath, []byte(portable.Expression()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "agentcel.yaml")
	configuration := fmt.Sprintf(
		"version: v1\nrequire_certified: false\nrules:\n  paths:\n    - %q\n  required: true\n",
		rulePath,
	)
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}

	command := exec.CommandContext(
		t.Context(),
		agentCEL,
		"scan",
		"--config", configPath,
		"--format", "json",
		"--input-kind", "document",
		"--rule", "defenseclaw_actionfacts",
		"-",
	)
	command.Stdin = bytes.NewReader(documentJSON)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	var exitErr *exec.ExitError
	if runErr == nil || !errors.As(runErr, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("AgentCEL exit err=%v stdout=%s stderr=%s", runErr, stdout.String(), stderr.String())
	}
	var result struct {
		Matched       bool `json:"matched"`
		Authoritative bool `json:"authoritative"`
		Matches       []struct {
			RuleID string `json:"rule_id"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode AgentCEL output: %v; stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if !result.Matched || !result.Authoritative || len(result.Matches) != 1 ||
		result.Matches[0].RuleID != "defenseclaw_actionfacts" {
		t.Fatalf("unexpected AgentCEL result: %#v; stderr=%s", result, stderr.String())
	}
}
