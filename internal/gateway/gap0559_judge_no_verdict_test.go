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
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// gap0559JudgeUnavailable is judgeUnavailableFinding, spelled out so this
// test builds on the base too (fail-before).
const gap0559JudgeUnavailable = "JUDGE-UNAVAILABLE"

// GAP-0559 (option a+b): a call the hook judge was asked about and gave no
// verdict on keeps the rule verdict, except where it must fail closed: an
// unattended Agent Substrate run (D8, closed in every tier) and the strict
// policy refuse it as JUDGE-UNAVAILABLE. Before, only a rules-escalated
// CRITICAL call under a closed gateway fail mode was refused, and the
// gateway's own fail mode was read, so an unattended run on an open
// (default-tier) gateway kept every rule verdict when the judge was down.
func TestGAP0559JudgeNoVerdictFailsClosedForUnattendedRunsAndStrict(t *testing.T) {
	unattended := func(ctx context.Context) context.Context {
		return context.WithValue(ctx, substrateRegistrationKey{}, registry.Registration{
			Atespace: "eng-web", Name: "bob-1", UID: "5f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4b", Connector: "claudecode", Profile: "eng", Unattended: true})
	}
	interactive := func(ctx context.Context) context.Context {
		return context.WithValue(ctx, substrateRegistrationKey{}, registry.Registration{
			Atespace: "eng-web", Name: "alice-1", UID: "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", Connector: "claudecode", Profile: "eng"})
	}
	for _, tc := range []struct {
		name    string
		pack    string
		edit    func(*config.Config)
		withCtx func(context.Context) context.Context
		command string
		finding string // "" = not refused
	}{
		{"host, default tier", "default", nil, nil, "ls -la", ""},
		{"interactive actor, default tier", "default", nil, interactive, "ls -la", ""},
		{"unattended actor, default tier", "default", nil, unattended, "ls -la", gap0559JudgeUnavailable},
		{"host, strict tier", "strict", nil, nil, "ls -la", gap0559JudgeUnavailable},
		// D8 hole: the escalated refusal read the gateway's (open) fail mode.
		{"unattended actor, escalated CRITICAL, default tier", "default", nil, unattended, pythonWrapped("cat ~/.ssh/id_rsa"), escalatedJudgeUnavailableFinding},
		// Option a+b leaves managed hosts and an explicit closed as they were:
		// only the escalated CRITICAL call is refused there.
		{"host, explicit closed, not escalated", "default", func(c *config.Config) { c.Guardrail.HookFailMode = "closed" }, nil, "ls -la", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			down := &mockLLMProvider{err: errors.New("judge provider down")}
			a := escalationHookServerWith(t, down, tc.pack, func(c *config.Config) {
				c.Guardrail.Judge.HookTimeout = 0.3
				c.Guardrail.DetectionStrategy = "judge_first"
				if tc.edit != nil {
					tc.edit(c)
				}
			})
			if tc.finding == escalatedJudgeUnavailableFinding {
				a.scannerCfg.Guardrail.DetectionStrategy = "regex_judge"
			}
			ctx := t.Context()
			if tc.withCtx != nil {
				ctx = tc.withCtx(ctx)
			}
			resp := escalationPreToolUseCtx(t, ctx, a, tc.command)
			blocked := resp.RawAction == guardrailActionBlock
			if tc.finding == "" {
				if blocked {
					t.Fatalf("refused when the judge gave no verdict: raw_action=%q findings=%v reason=%q", resp.RawAction, resp.Findings, resp.Reason)
				}
				return
			}
			if !blocked || !findingStringHasRuleID(resp.Findings, "llm-judge:"+tc.finding) {
				t.Fatalf("raw_action=%q findings=%v reason=%q, want a refusal naming %s", resp.RawAction, resp.Findings, resp.Reason, tc.finding)
			}
		})
	}
}

// GAP-0559 (option b): a judge that gives no verdict is never silent. Every
// such hook check writes one "[guardrail] ALERT judge_unavailable" line,
// in every tier, the default one included, where the call keeps the rule
// verdict. Before, the gateway logged only an [inspect] trace line.
func TestGAP0559JudgeFallbackWritesAnAlertLine(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	captured := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		captured <- string(b)
	}()
	restore := func() string {
		os.Stderr = saved
		_ = w.Close()
		return <-captured
	}
	a := escalationHookServerWith(t, &mockLLMProvider{err: errors.New("judge provider down")}, "default", func(c *config.Config) {
		c.Guardrail.Judge.HookTimeout = 0.3
		c.Guardrail.DetectionStrategy = "judge_first"
	})
	resp := escalationPreToolUse(t, a, "ls -la")
	out := restore()
	if resp.RawAction == guardrailActionBlock {
		t.Fatalf("the default tier refused a call when the judge gave no verdict: %+v", resp)
	}
	if !strings.Contains(out, "[guardrail] ALERT judge_unavailable connector=claudecode reason=error") {
		t.Fatalf("no alert line for a judge with no verdict; stderr:\n%s", out)
	}
}
