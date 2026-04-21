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

package tui

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestGuardrailWizardFields_InheritFromUnifiedLLM asserts the wizard
// pre-fills judge.{model,provider,api_key_env,api_base} from the
// unified top-level “llm:“ block when the judge block is empty, AND
// that these inherited pre-fills are marked as Defaults (not just
// Values). Equal Value/Default means buildWizardArgs will skip the
// flag on submit — see TestBuildWizardArgs_GuardrailInheritsWhenUntouched
// for the submit side of this contract.
func TestGuardrailWizardFields_InheritFromUnifiedLLM(t *testing.T) {
	cfg := &config.Config{}
	cfg.LLM.Provider = "anthropic"
	cfg.LLM.Model = "claude-3-5-sonnet-20241022"
	cfg.LLM.APIKeyEnv = "DEFENSECLAW_LLM_KEY"
	cfg.LLM.BaseURL = "https://api.anthropic.com"

	p := &SetupPanel{cfg: cfg}
	fields := p.guardrailWizardFields()

	want := map[string]struct {
		value  string
		defVal string
	}{
		"Provider":     {"anthropic", "anthropic"},
		"Model":        {"claude-3-5-sonnet-20241022", "claude-3-5-sonnet-20241022"},
		"API Key Env":  {"DEFENSECLAW_LLM_KEY", "DEFENSECLAW_LLM_KEY"},
		"API Base URL": {"https://api.anthropic.com", "https://api.anthropic.com"},
	}

	// The judge section is the third "section" divider; collect the
	// four fields that immediately follow it.
	inJudge := false
	seen := map[string]bool{}
	for _, f := range fields {
		if f.Kind == "section" {
			inJudge = f.Label == "LLM Judge"
			continue
		}
		if !inJudge {
			continue
		}
		exp, ok := want[f.Label]
		if !ok {
			continue
		}
		seen[f.Label] = true
		if f.Value != exp.value {
			t.Errorf("judge.%s Value = %q, want %q (inherited from cfg.llm)",
				f.Label, f.Value, exp.value)
		}
		if f.Default != exp.defVal {
			t.Errorf("judge.%s Default = %q, want %q — without this, submitting "+
				"unchanged values writes explicit gc.judge.* overrides instead "+
				"of inheriting at runtime via resolve_llm",
				f.Label, f.Default, exp.defVal)
		}
	}
	for label := range want {
		if !seen[label] {
			t.Errorf("expected to find judge field %q in wizard, got fields %+v",
				label, fields)
		}
	}
}

// TestGuardrailWizardFields_NoInheritWhenJudgeCustomised asserts that
// operator-set judge fields are NOT overridden by the unified-llm
// pre-fill logic. This guards against a regression where the pre-fill
// accidentally clobbered explicit per-judge overrides.
func TestGuardrailWizardFields_NoInheritWhenJudgeCustomised(t *testing.T) {
	cfg := &config.Config{}
	cfg.LLM.Provider = "anthropic"
	cfg.LLM.Model = "claude-3-5-sonnet-20241022"
	cfg.LLM.APIKeyEnv = "DEFENSECLAW_LLM_KEY"

	// Operator has explicitly customised the judge.
	cfg.Guardrail.Judge.Model = "openai/gpt-4o-mini"
	cfg.Guardrail.Judge.APIKeyEnv = "JUDGE_SPECIFIC_KEY"

	p := &SetupPanel{cfg: cfg}
	fields := p.guardrailWizardFields()

	inJudge := false
	for _, f := range fields {
		if f.Kind == "section" {
			inJudge = f.Label == "LLM Judge"
			continue
		}
		if !inJudge {
			continue
		}
		switch f.Label {
		case "Provider":
			if f.Value != "openai" {
				t.Errorf("judge Provider = %q, want %q (extracted from customised judge.model)", f.Value, "openai")
			}
		case "Model":
			if f.Value != "gpt-4o-mini" {
				t.Errorf("judge Model = %q, want %q (extracted from customised judge.model)", f.Value, "gpt-4o-mini")
			}
		case "API Key Env":
			if f.Value != "JUDGE_SPECIFIC_KEY" {
				t.Errorf("judge API Key Env = %q, want %q (customised — must not inherit from cfg.llm)", f.Value, "JUDGE_SPECIFIC_KEY")
			}
		}
	}
}

// TestBuildWizardArgs_GuardrailInheritsWhenUntouched is the submit-side
// of the pre-fill contract: when the operator opens the wizard with
// unified-LLM-backed judge defaults and hits Enter without editing, we
// must NOT send --judge-model / --judge-api-key-env / --judge-api-base
// flags. Otherwise the non-interactive CLI path writes them verbatim
// into gc.judge.* and the judge stops tracking later edits to cfg.llm.*.
func TestBuildWizardArgs_GuardrailInheritsWhenUntouched(t *testing.T) {
	cfg := &config.Config{}
	cfg.LLM.Provider = "anthropic"
	cfg.LLM.Model = "claude-3-5-sonnet-20241022"
	cfg.LLM.APIKeyEnv = "DEFENSECLAW_LLM_KEY"
	cfg.LLM.BaseURL = "https://api.anthropic.com"

	p := &SetupPanel{
		cfg:           cfg,
		wizRunIdx:     wizardGuardrail,
		wizFormFields: (&SetupPanel{cfg: cfg}).guardrailWizardFields(),
	}
	args := p.buildWizardArgs(wizardGuardrail)
	joined := strings.Join(args, " ")

	for _, flag := range []string{"--judge-model", "--judge-api-key-env", "--judge-api-base"} {
		if strings.Contains(joined, flag) {
			t.Errorf("buildWizardArgs unexpectedly included %s when user accepted inherited defaults — "+
				"this breaks true inherit semantics (gc.judge.* gets written verbatim instead of "+
				"resolving through cfg.llm.* at runtime).\n  full args: %v",
				flag, args)
		}
	}
}

// TestBuildWizardArgs_GuardrailSendsJudgeModelWhenChanged asserts the
// positive path: when the operator actually edits the judge model, we
// do send the combined provider/model flag, and the provider prefix is
// preserved even if the operator left Provider alone.
func TestBuildWizardArgs_GuardrailSendsJudgeModelWhenChanged(t *testing.T) {
	cfg := &config.Config{}
	cfg.LLM.Provider = "anthropic"
	cfg.LLM.Model = "claude-3-5-sonnet-20241022"
	cfg.LLM.APIKeyEnv = "DEFENSECLAW_LLM_KEY"

	p := &SetupPanel{cfg: cfg}
	p.wizRunIdx = wizardGuardrail
	p.wizFormFields = p.guardrailWizardFields()

	// Simulate the operator editing the Model field.
	for i := range p.wizFormFields {
		if p.wizFormFields[i].Flag == "--judge-model" {
			p.wizFormFields[i].Value = "claude-3-5-haiku-20241022"
		}
	}

	args := p.buildWizardArgs(wizardGuardrail)
	joined := strings.Join(args, " ")

	wantModel := "anthropic/claude-3-5-haiku-20241022"
	if !strings.Contains(joined, "--judge-model "+wantModel) {
		t.Errorf("expected --judge-model %s in args (combined provider/model), got %v",
			wantModel, args)
	}
}
