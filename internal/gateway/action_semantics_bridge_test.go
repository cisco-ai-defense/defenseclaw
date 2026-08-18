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
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/asrruntime"
)

type bridgeTestRuntime struct {
	pins         asrruntime.Pins
	canAuthorize bool
	calls        []asrruntime.NormalizedInvocation
	evaluate     func(asrruntime.NormalizedInvocation) asrruntime.Result
}

func (r *bridgeTestRuntime) Evaluate(invocation asrruntime.NormalizedInvocation) asrruntime.Result {
	r.calls = append(r.calls, invocation)
	if r.evaluate != nil {
		return r.evaluate(invocation)
	}
	return asrruntime.Result{
		CallID:        invocation.CallID,
		Status:        asrruntime.StatusComplete,
		Pins:          r.pins,
		Authoritative: r.canAuthorize,
	}
}

func (r *bridgeTestRuntime) Pins() asrruntime.Pins { return r.pins }
func (r *bridgeTestRuntime) CanAuthorize() bool    { return r.canAuthorize }

func TestActionSemanticsBridgeEvaluatesEveryProjectableNodeExactlyOnce(t *testing.T) {
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool:        "shell",
		Command:     `sh -c 'printf x | tee /tmp/output'`,
		CWD:         "/repo",
		ActiveHome:  "/home/runner",
		DialectHint: actionfacts.DialectPOSIX,
	})
	runtime := &bridgeTestRuntime{}
	report := evaluateActionSemanticsNodes(
		facts,
		bridgeTestPOSIXContext(),
		runtime,
	)

	projectable := make(map[int64]actionfacts.ASRCommandCandidate)
	for _, candidate := range report.Projection.Candidates {
		if candidate.Projectable {
			projectable[candidate.CommandID] = candidate
		}
	}
	if len(projectable) == 0 || len(runtime.calls) != len(projectable) ||
		len(report.Evaluations) != len(projectable) {
		t.Fatalf(
			"projectable=%d calls=%d evaluations=%d report=%#v",
			len(projectable),
			len(runtime.calls),
			len(report.Evaluations),
			report,
		)
	}
	seen := make(map[int64]int, len(runtime.calls))
	for _, call := range runtime.calls {
		commandID, err := strconv.ParseInt(call.CallID, 10, 64)
		if err != nil {
			t.Fatalf("call ID %q: %v", call.CallID, err)
		}
		candidate, ok := projectable[commandID]
		if !ok {
			t.Fatalf("call for non-projectable command %d", commandID)
		}
		seen[commandID]++
		if call.Program != candidate.Program ||
			call.Surface != actionSemanticsSurface(candidate.Surface) ||
			!call.ArgvComplete ||
			call.Profile != string(actionfacts.ASRProfileUniversalLinux) ||
			call.Context == nil || call.Context.CWD != facts.CWD ||
			call.Context.ActiveHome != facts.ActiveHome {
			t.Fatalf("call=%#v candidate=%#v", call, candidate)
		}
	}
	for commandID, count := range seen {
		if count != 1 {
			t.Fatalf("command %d evaluated %d times", commandID, count)
		}
	}
}

func TestActionSemanticsBridgeKeepsPartialOuterNodesShadowOnly(t *testing.T) {
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool:        "shell",
		Command:     `false && rm -rf /tmp/victim`,
		CWD:         "/repo",
		DialectHint: actionfacts.DialectPOSIX,
	})
	if facts.Authoritative() {
		t.Fatalf("test requires partial outer facts: %#v", facts)
	}
	runtime := &bridgeTestRuntime{canAuthorize: true}
	report := evaluateActionSemanticsNodes(facts, bridgeTestPOSIXContext(), runtime)
	if len(report.Evaluations) == 0 || len(runtime.calls) != len(report.Evaluations) {
		t.Fatalf("partial outer nodes were not evaluated: %#v", report)
	}
	for _, evaluation := range report.Evaluations {
		if evaluation.CandidateAuthoritative || evaluation.Authoritative {
			t.Fatalf("partial outer result became authoritative: %#v", evaluation)
		}
	}
}

func TestActionSemanticsBridgeRequiresCompleteCorrelatedPinnedParity(t *testing.T) {
	pins := asrruntime.Pins{
		SchemaVersion:          "1",
		CatalogVersion:         "catalog",
		CatalogDigest:          "digest",
		EvaluatorABI:           "abi",
		SemanticContractDigest: "contract",
		ConformanceDigest:      "conformance",
	}
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool: "exec",
		Argv: []string{"rm", "-f", "/tmp/cache"},
	})
	context := actionfacts.ASRProjectionContext{
		Platform:   actionfacts.ASRPlatformLinux,
		Profile:    actionfacts.ASRProfileUniversalLinux,
		Provenance: actionfacts.ASRCommandProvenanceStructuredArgv,
	}

	tests := []struct {
		name        string
		status      asrruntime.Status
		callID      string
		resultPins  asrruntime.Pins
		resultAuth  bool
		runtimeAuth bool
		wantAuth    bool
	}{
		{name: "complete exact parity", status: asrruntime.StatusComplete, resultPins: pins, resultAuth: true, runtimeAuth: true, wantAuth: true},
		{name: "partial", status: asrruntime.StatusPartial, resultPins: pins, resultAuth: true, runtimeAuth: true},
		{name: "invalid", status: asrruntime.StatusInvalid, resultPins: pins, resultAuth: true, runtimeAuth: true},
		{name: "unsupported", status: asrruntime.StatusUnsupported, resultPins: pins, resultAuth: true, runtimeAuth: true},
		{name: "runtime error", status: asrruntime.StatusError, resultPins: pins, resultAuth: true, runtimeAuth: true},
		{name: "call ID mismatch", status: asrruntime.StatusComplete, callID: "other", resultPins: pins, resultAuth: true, runtimeAuth: true},
		{name: "pin mismatch", status: asrruntime.StatusComplete, resultPins: asrruntime.Pins{CatalogDigest: "other"}, resultAuth: true, runtimeAuth: true},
		{name: "result refuses authority", status: asrruntime.StatusComplete, resultPins: pins, runtimeAuth: true},
		{name: "runtime parity disabled", status: asrruntime.StatusComplete, resultPins: pins, resultAuth: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := &bridgeTestRuntime{pins: pins, canAuthorize: test.runtimeAuth}
			runtime.evaluate = func(invocation asrruntime.NormalizedInvocation) asrruntime.Result {
				callID := test.callID
				if callID == "" {
					callID = invocation.CallID
				}
				return asrruntime.Result{
					CallID:        callID,
					Status:        test.status,
					Pins:          test.resultPins,
					Authoritative: test.resultAuth,
				}
			}
			report := evaluateActionSemanticsNodes(facts, context, runtime)
			if len(report.Evaluations) != 1 ||
				report.Evaluations[0].Authoritative != test.wantAuth {
				t.Fatalf("report=%#v", report)
			}
		})
	}
}

func TestDispatchRunsActionSemanticsBeforePartialFallback(t *testing.T) {
	context := bridgeTestPOSIXContext()
	runtime := &bridgeTestRuntime{}
	var observed actionSemanticsBridgeReport
	dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: actionfacts.Input{
			Tool:        "shell",
			Command:     `false && rm -rf /tmp/victim`,
			DialectHint: actionfacts.DialectPOSIX,
		},
		LegacyText:            `false && rm -rf /tmp/victim`,
		EnforcementCapable:    true,
		ASRContext:            &context,
		asrRuntime:            runtime,
		recordActionSemantics: func(report actionSemanticsBridgeReport) { observed = report },
	})
	if len(runtime.calls) == 0 || len(observed.Evaluations) != len(runtime.calls) {
		t.Fatalf("ASR was skipped before partial fallback: calls=%d report=%#v", len(runtime.calls), observed)
	}
	for _, evaluation := range observed.Evaluations {
		if evaluation.Authoritative {
			t.Fatalf("partial dispatch result became authoritative: %#v", evaluation)
		}
	}
}

func TestEmbeddedActionSemanticsRuntimeRemainsShadowOnly(t *testing.T) {
	runtime, err := loadEmbeddedActionSemanticsRuntime()
	if err != nil {
		t.Fatalf("load embedded runtime: %v", err)
	}
	if runtime == nil || runtime.CanAuthorize() {
		t.Fatalf("bootstrap runtime authority=%t", runtime != nil && runtime.CanAuthorize())
	}
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool: "exec",
		Argv: []string{"rm", "-f", "/tmp/cache"},
	})
	report := evaluateActionSemanticsNodes(
		facts,
		actionfacts.ASRProjectionContext{
			Platform:   actionfacts.ASRPlatformLinux,
			Profile:    actionfacts.ASRProfileUniversalLinux,
			Provenance: actionfacts.ASRCommandProvenanceStructuredArgv,
		},
		runtime,
	)
	if len(report.Evaluations) != 1 || report.Evaluations[0].Authoritative {
		t.Fatalf("report=%#v", report)
	}
}

func bridgeTestPOSIXContext() actionfacts.ASRProjectionContext {
	return actionfacts.ASRProjectionContext{
		Platform:   actionfacts.ASRPlatformLinux,
		Profile:    actionfacts.ASRProfileUniversalLinux,
		Provenance: actionfacts.ASRCommandProvenanceActionFactsStaticPOSIX,
	}
}
