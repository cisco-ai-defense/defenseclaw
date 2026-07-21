// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltinCorrelationProfilesAreVersionedAndValid(t *testing.T) {
	reg := NewDefaultRegistry()
	if got := len(reg.Names()); got != 13 {
		t.Fatalf("builtin count=%d want 13", got)
	}
	for _, name := range reg.Names() {
		name := name
		t.Run(name, func(t *testing.T) {
			conn, ok := reg.Get(name)
			if !ok {
				t.Fatal("connector missing from registry")
			}
			provider, ok := conn.(CorrelationSpecProvider)
			if !ok {
				t.Fatalf("%s does not implement CorrelationSpecProvider", name)
			}
			spec := provider.CorrelationSpec(SetupOpts{})
			if spec.ProfileVersion == "" || spec.ProfileVersion == CorrelationProfileExplicitV1 {
				t.Fatalf("profile version=%q want built-in version", spec.ProfileVersion)
			}
			if spec.Connector != name {
				t.Fatalf("connector=%q want %q", spec.Connector, name)
			}
			if err := spec.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestCorrelationContractSourcesAndFixturesAreImmutable(t *testing.T) {
	specs := []CorrelationSpec{ExplicitCanonicalCorrelationSpec("plugin-example")}
	for _, name := range NewDefaultRegistry().Names() {
		specs = append(specs, DefaultCorrelationSpec(name))
	}
	for _, spec := range specs {
		t.Run(spec.Connector, func(t *testing.T) {
			if err := spec.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			for _, source := range spec.ContractSources {
				for _, fixture := range source.Fixtures {
					path := filepath.Join("..", "..", "..", filepath.FromSlash(fixture.Path))
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatalf("read fixture %s: %v", fixture.ID, err)
					}
					// Git may materialize text fixtures with CRLF on Windows even
					// though their reviewed Git blobs are LF. Canonicalize only that
					// checkout-level transformation; a lone CR or any content change
					// still fails the immutable digest check.
					withoutCRLF := bytes.ReplaceAll(raw, []byte("\r\n"), nil)
					if bytes.ContainsRune(withoutCRLF, '\r') {
						t.Fatalf("fixture %s contains a non-CRLF carriage return", fixture.ID)
					}
					canonical := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
					digest := sha256.Sum256(canonical)
					if got := "sha256:" + hex.EncodeToString(digest[:]); got != fixture.SHA256 {
						t.Fatalf("fixture %s digest=%s want %s", fixture.ID, got, fixture.SHA256)
					}
				}
			}
		})
	}
}

func TestCorrelationAuthorityRequiresExactFieldEvidence(t *testing.T) {
	spec := DefaultCorrelationSpec("codex")
	generic, ok := spec.NativeOTLPValue(map[string]interface{}{
		"gen_ai.tool.call.id": "generic-call",
	}, CorrelationTargetTool)
	if !ok {
		t.Fatal("generic GenAI tool ID was not retained as typed evidence")
	}
	if spec.IsAuthoritativeValue(CorrelationSurfaceNativeOTLP, generic) {
		t.Fatal("generic GenAI alias inherited Codex call_id authority")
	}
	if _, proven := spec.MirrorProofForValue(CorrelationSurfaceNativeOTLP, generic); proven {
		t.Fatal("generic GenAI alias inherited Codex call_id mirror proof")
	}

	broken := spec
	broken.FieldEvidence = append([]CorrelationFieldEvidence(nil), spec.FieldEvidence...)
	for index := range broken.FieldEvidence {
		if broken.FieldEvidence[index].Path == "call_id" {
			broken.FieldEvidence[index].FixtureID = "missing-fixture"
		}
	}
	if err := broken.Validate(); err == nil || !strings.Contains(err.Error(), "fixture") {
		t.Fatalf("profile with missing evidence fixture validated: %v", err)
	}
}

func TestHookProfilesCarryResolvedCorrelationVersion(t *testing.T) {
	reg := NewDefaultRegistry()
	for _, name := range []string{"codex", "claudecode", "hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity", "opencode", "omnigent"} {
		conn, _ := reg.Get(name)
		profile := conn.(HookProfileProvider).HookProfile(SetupOpts{})
		if profile.Correlation.ProfileVersion == "" || profile.Correlation.ProfileVersion == CorrelationProfileExplicitV1 {
			t.Errorf("%s correlation version=%q", name, profile.Correlation.ProfileVersion)
		}
		if profile.Correlation.HookContractID != profile.ContractID {
			t.Errorf("%s correlation contract=%q hook contract=%q", name, profile.Correlation.HookContractID, profile.ContractID)
		}
	}
}

func TestCorrelationProfileVersionGateFailsClosed(t *testing.T) {
	spec := NewCodexConnector().CorrelationSpec(SetupOpts{HookContractID: "codex-hooks-v999"})
	if spec.ProfileVersion != CorrelationProfileExplicitV1 {
		t.Fatalf("profile=%q want explicit fail-closed profile", spec.ProfileVersion)
	}
	if _, ok := spec.HookValue(map[string]interface{}{"thread_id": "thread-guessed"}, CorrelationTargetSession); ok {
		t.Fatal("incompatible contract accepted vendor thread alias")
	}
	if got, ok := spec.HookValue(map[string]interface{}{"session_id": "session-explicit"}, CorrelationTargetSession); !ok || got.Value != "session-explicit" {
		t.Fatalf("exact canonical field=(%+v,%v)", got, ok)
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("fail-closed profile invalid: %v", err)
	}
}

func TestCodexCorrelationProfileSupportsExactReviewedHookContracts(t *testing.T) {
	tests := []struct {
		contractID        string
		wantSubagentStart bool
	}{
		{contractID: "codex-hooks-v1"},
		{contractID: "codex-hooks-v2"},
		{contractID: "codex-hooks-v3", wantSubagentStart: true},
	}
	for _, tc := range tests {
		t.Run(tc.contractID, func(t *testing.T) {
			spec, ok := CorrelationSpecForConnector("codex", tc.contractID)
			if !ok {
				t.Fatal("reviewed Codex contract rejected")
			}
			if spec.HookContractID != tc.contractID {
				t.Fatalf("correlation contract=%q want %q", spec.HookContractID, tc.contractID)
			}
			if err := spec.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			got, ok := spec.LifecycleForEvent("SubagentStart")
			if tc.wantSubagentStart {
				if !ok || got != CorrelationLifecycleSubagentStart {
					t.Fatalf("SubagentStart lifecycle=(%q,%v)", got, ok)
				}
			} else if ok {
				t.Fatalf("older contract unexpectedly maps SubagentStart to %q", got)
			}
		})
	}

	if _, ok := CorrelationSpecForConnector("codex", "codex-hooks-v999"); ok {
		t.Fatal("unreviewed future Codex contract accepted")
	}
}

func TestUnknownCorrelationProfileDoesNotGuessVendorAliases(t *testing.T) {
	spec := ExplicitCanonicalCorrelationSpec("plugin-example")
	if !spec.AllowsReceiptTarget(CorrelationTargetSourceEvent) {
		t.Fatal("explicit canonical source_event_id lacks exact replay protection")
	}
	payload := map[string]interface{}{
		"conversation_id": "conversation-1", "task_id": "task-1",
		"execution_id": "execution-1", "generation_id": "generation-1",
		"step_id": "step-1", "tool_use_id": "tool-1",
	}
	for _, target := range []CorrelationTarget{CorrelationTargetSession, CorrelationTargetTurn, CorrelationTargetTool, CorrelationTargetExecution, CorrelationTargetStep} {
		if got, ok := spec.HookValue(payload, target); ok {
			t.Errorf("target %s guessed %+v", target, got)
		}
	}
}

func TestAntigravityStepIsNeverTurn(t *testing.T) {
	spec := NewAntigravityConnector().CorrelationSpec(SetupOpts{})
	payload := map[string]interface{}{"conversationId": "conv-1", "stepIdx": float64(21), "invocationNum": float64(7)}
	if got, ok := spec.HookValue(payload, CorrelationTargetSession); !ok || got.Value != "conv-1" {
		t.Fatalf("session=(%+v,%v)", got, ok)
	}
	if got, ok := spec.HookValue(payload, CorrelationTargetStep); !ok || got.Value != "21" || got.IDKind != "trajectory_step" {
		t.Fatalf("step=(%+v,%v)", got, ok)
	}
	if got, ok := spec.HookValue(payload, CorrelationTargetTurn); ok {
		t.Fatalf("stepIdx became turn: %+v", got)
	}
	if got, ok := spec.HookValue(payload, CorrelationTargetExecution); !ok || got.Value != "7" {
		t.Fatalf("invocation=(%+v,%v)", got, ok)
	}
}

func TestConnectorScopedTurnMappingsDoNotCrossKinds(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]interface{}
		want    string
	}{
		{name: "cursor", payload: map[string]interface{}{"generation_id": "generation-7"}, want: "generation-7"},
		{name: "windsurf", payload: map[string]interface{}{"execution_id": "execution-9"}, want: "execution-9"},
		{name: "zeptoclaw", payload: map[string]interface{}{"provider_request_id": "provider-1"}, want: ""},
		{name: "antigravity", payload: map[string]interface{}{"stepIdx": 9}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := DefaultCorrelationSpec(tc.name)
			got, _ := spec.HookValue(tc.payload, CorrelationTargetTurn)
			if got.Value != tc.want {
				t.Fatalf("turn=%q want %q", got.Value, tc.want)
			}
		})
	}
}

func TestHermesNestedIdentityBindingsAreDeclared(t *testing.T) {
	spec := NewHermesConnector().CorrelationSpec(SetupOpts{})
	payload := map[string]interface{}{"extra": map[string]interface{}{
		"session_id": "session-1", "parent_session_id": "parent-1", "child_session_id": "child-1",
		"child_subagent_id": "agent-child", "tool_call_id": "call-1", "api_request_id": "hermes-operation-1",
	}}
	assert := func(target CorrelationTarget, want string) CorrelationValue {
		t.Helper()
		got, ok := spec.HookValue(payload, target)
		if !ok || got.Value != want {
			t.Fatalf("%s=(%+v,%v) want %q", target, got, ok, want)
		}
		return got
	}
	assert(CorrelationTargetSession, "session-1")
	assert(CorrelationTargetParentSession, "parent-1")
	assert(CorrelationTargetChildSession, "child-1")
	assert(CorrelationTargetChildAgent, "agent-child")
	assert(CorrelationTargetTool, "call-1")
	operation := assert(CorrelationTargetExecution, "hermes-operation-1")
	if operation.IDKind != "observer_api_operation" {
		t.Fatalf("api request kind=%q", operation.IDKind)
	}
	if _, ok := spec.HookValue(payload, CorrelationTargetModelRequest); ok {
		t.Fatal("Hermes api_request_id was mislabeled as an upstream model/provider request")
	}
}

func TestSemanticEventIDAcceptsOnlyExactCanonicalKey(t *testing.T) {
	spec := NewCodexConnector().CorrelationSpec(SetupOpts{})
	for _, key := range []string{"semantic_event_id", "event_id", "record_id"} {
		if got, ok := spec.HookValue(map[string]interface{}{key: "event-1"}, CorrelationTargetSemanticEvent); ok {
			t.Errorf("alias %q produced semantic event %+v", key, got)
		}
	}
	got, ok := spec.HookValue(map[string]interface{}{"defenseclaw.semantic_event.id": "semantic-1"}, CorrelationTargetSemanticEvent)
	if !ok || got.Value != "semantic-1" || got.Namespace != "defenseclaw" || got.IDKind != "semantic_event" {
		t.Fatalf("canonical semantic event=(%+v,%v)", got, ok)
	}
}

func TestNativeTelemetryRegistryIsExplicit(t *testing.T) {
	wants := map[string]NativeTelemetryStability{
		"openclaw": NativeTelemetryNone, "zeptoclaw": NativeTelemetryNone,
		"codex": NativeTelemetryStable, "claudecode": NativeTelemetryBeta,
		"hermes": NativeTelemetryNone, "cursor": NativeTelemetryNone, "windsurf": NativeTelemetryNone,
		"geminicli": NativeTelemetryStable, "copilot": NativeTelemetryStable,
		"openhands": NativeTelemetryNone, "antigravity": NativeTelemetryNone,
		"opencode": NativeTelemetryNone, "omnigent": NativeTelemetryExperimental,
	}
	for name, want := range wants {
		spec := DefaultCorrelationSpec(name)
		if spec.NativeTelemetry.Stability != want {
			t.Errorf("%s stability=%q want %q", name, spec.NativeTelemetry.Stability, want)
		}
		if want != NativeTelemetryNone {
			if len(spec.NativeTelemetry.Signals) == 0 {
				t.Errorf("%s native registry incomplete: %+v", name, spec.NativeTelemetry)
			}
			foundSurface := false
			for _, surface := range spec.Surfaces {
				foundSurface = foundSurface || surface == CorrelationSurfaceNativeOTLP
			}
			if !foundSurface {
				t.Errorf("%s native-capable but surfaces=%v", name, spec.Surfaces)
			}
		}
	}
}

func TestEveryDeclaredCorrelationSurfaceHasReviewedBindings(t *testing.T) {
	for _, name := range NewDefaultRegistry().Names() {
		spec := DefaultCorrelationSpec(name)
		if err := spec.Validate(); err != nil {
			t.Fatalf("%s profile invalid: %v", name, err)
		}
		for _, surface := range spec.Surfaces {
			var count int
			switch surface {
			case CorrelationSurfaceHook:
				count = len(spec.HookBindings)
			case CorrelationSurfaceProxy:
				count = len(spec.ProxyBindings)
			case CorrelationSurfaceStream:
				count = len(spec.StreamBindings)
			case CorrelationSurfaceNativeOTLP:
				count = len(spec.NativeOTLPBindings)
			}
			if count == 0 {
				t.Errorf("%s declares %s without bindings", name, surface)
			}
		}
	}
	for _, name := range []string{"openhands", "opencode"} {
		for _, surface := range DefaultCorrelationSpec(name).Surfaces {
			if surface == CorrelationSurfaceStream {
				t.Errorf("%s advertises an event stream without a production adapter", name)
			}
		}
	}
}

func TestCrossRailMirrorIDsAreNativeAuthoritative(t *testing.T) {
	for _, name := range NewDefaultRegistry().Names() {
		spec := DefaultCorrelationSpec(name)
		for _, target := range spec.MirrorIdentityTargets {
			if !spec.NativeTelemetry.IsAuthoritative(target) {
				t.Errorf("%s mirror target %s is not native-authoritative", name, target)
			}
		}
		if err := spec.Validate(); err != nil {
			t.Errorf("%s correlation profile invalid: %v", name, err)
		}
	}
}

func TestNativeAuthorityMustCoverCrossRailProof(t *testing.T) {
	spec := DefaultCorrelationSpec("codex")
	spec.NativeTelemetry.AuthoritativeFields = nil
	if err := spec.Validate(); err == nil {
		t.Fatalf("profile without authoritative tool/item mirror proof validated: %v", err)
	}
}

func TestNativeNoneCannotDeclareAuthority(t *testing.T) {
	spec := DefaultCorrelationSpec("cursor")
	spec.NativeTelemetry.AuthoritativeFields = []CorrelationTarget{CorrelationTargetSession}
	if err := spec.Validate(); err == nil {
		t.Fatalf("native-none profile accepted authority: %v", err)
	}
}

func TestTurnBindingsNeverUseForbiddenGenericKinds(t *testing.T) {
	for _, name := range NewDefaultRegistry().Names() {
		spec := DefaultCorrelationSpec(name)
		for _, binding := range spec.HookBindings {
			if binding.Target != CorrelationTargetTurn {
				continue
			}
			for _, path := range binding.Paths {
				lower := strings.ToLower(path)
				if strings.Contains(lower, "tool_call") || strings.Contains(lower, "tool_use") || strings.Contains(lower, "stepidx") || strings.Contains(lower, "step_id") {
					t.Errorf("%s turn binding includes forbidden path %q", name, path)
				}
			}
		}
	}
}

func TestCorrelationRegistryRetainsAllTypedNativeIdentifiers(t *testing.T) {
	spec := DefaultCorrelationSpec("codex")
	values := spec.NativeOTLPValues(map[string]interface{}{
		"thread.id":                      "thread-1",
		"turn.id":                        "turn-1",
		"gen_ai.conversation.id":         "conversation-1",
		"gen_ai.response.id":             "response-1",
		"defenseclaw.model.response.id":  "response-2",
		"gen_ai.tool.call.id":            "tool-1",
		"defenseclaw.tool.invocation.id": "tool-2",
		"defenseclaw.semantic_event.id":  "semantic-1",
	})
	wants := map[string]bool{
		"thread:thread-1": false, "turn:turn-1": false,
		"session:conversation-1":    false,
		"model_response:response-1": false, "model_response:response-2": false,
		"tool_invocation:tool-1": false, "tool_invocation:tool-2": false,
		"semantic_event:semantic-1": false,
	}
	for _, value := range values {
		key := value.IDKind + ":" + value.Value
		if _, ok := wants[key]; ok {
			wants[key] = true
		}
	}
	for key, found := range wants {
		if !found {
			t.Errorf("missing typed native identifier %s from %+v", key, values)
		}
	}
}

func TestHookLifecycleBindingsUseOnlyReviewedContractEvents(t *testing.T) {
	for _, name := range []string{
		"codex", "claudecode", "hermes", "cursor", "windsurf", "geminicli",
		"copilot", "openhands", "antigravity", "opencode", "omnigent",
	} {
		t.Run(name, func(t *testing.T) {
			spec := DefaultCorrelationSpec(name)
			resolution := ResolveHookContract(name, "")
			declared := make(map[string]bool, len(resolution.Contract.Events))
			for _, event := range resolution.Contract.Events {
				declared[event] = true
			}
			for _, lifecycle := range spec.Lifecycle {
				for _, event := range lifecycle.Events {
					if !declared[event] {
						t.Errorf("%s maps undeclared event %q", lifecycle.Lifecycle, event)
					}
				}
			}
		})
	}
}

func TestConnectorLifecycleSemantics(t *testing.T) {
	cases := []struct {
		connector string
		event     string
		want      CorrelationLifecycle
	}{
		{"codex", "UserPromptSubmit", CorrelationLifecycleTurnStart},
		{"claudecode", "PostToolUseFailure", CorrelationLifecycleToolEnd},
		{"hermes", "pre_llm_call", CorrelationLifecycleTurnStart},
		{"cursor", "beforeSubmitPrompt", CorrelationLifecycleTurnStart},
		{"windsurf", "post_cascade_response", CorrelationLifecycleTurnEnd},
		{"geminicli", "BeforeTool", CorrelationLifecycleToolStart},
		{"copilot", "userPromptSubmitted", CorrelationLifecycleTurnStart},
		{"openhands", "user_prompt_submit", CorrelationLifecycleTurnStart},
		{"antigravity", "PostInvocation", CorrelationLifecycleTurnEnd},
		{"opencode", "tool.execute.after", CorrelationLifecycleToolEnd},
		{"omnigent", "AfterAgentResponse", CorrelationLifecycleTurnEnd},
	}
	for _, tc := range cases {
		t.Run(tc.connector+"/"+tc.event, func(t *testing.T) {
			got, ok := DefaultCorrelationSpec(tc.connector).LifecycleForEvent(tc.event)
			if !ok || got != tc.want {
				t.Fatalf("lifecycle=(%q,%v) want %q", got, ok, tc.want)
			}
		})
	}
}

func TestNativeRegistryNeverRecognizesNonStandardGenAIRequestID(t *testing.T) {
	for _, name := range NewDefaultRegistry().Names() {
		spec := DefaultCorrelationSpec(name)
		if got, ok := spec.NativeOTLPValue(map[string]interface{}{"gen_ai.request.id": "not-standard"}, CorrelationTargetModelRequest); ok {
			t.Errorf("%s accepted non-standard gen_ai.request.id as %+v", name, got)
		}
	}
}

func TestAllBuiltinCorrelationProfilesUseConnectorExactIDs(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]interface{}
		wants   map[CorrelationTarget]string
	}{
		{"openclaw", map[string]interface{}{"sessionKey": "s", "messageId": "m", "runId": "r", "callId": "c"}, map[CorrelationTarget]string{CorrelationTargetSession: "s", CorrelationTargetMessage: "m", CorrelationTargetExecution: "r", CorrelationTargetTool: "c"}},
		{"zeptoclaw", map[string]interface{}{"provider_request_id": "rq", "provider_response_id": "rs", "provider_tool_call_id": "tc"}, map[CorrelationTarget]string{CorrelationTargetModelRequest: "rq", CorrelationTargetModelResponse: "rs", CorrelationTargetTool: "tc"}},
		{"codex", map[string]interface{}{"thread_id": "th", "session_id": "s", "turn_id": "t", "item_id": "i", "tool_use_id": "tc"}, map[CorrelationTarget]string{CorrelationTargetThread: "th", CorrelationTargetSession: "s", CorrelationTargetTurn: "t", CorrelationTargetSourceEvent: "i", CorrelationTargetTool: "tc"}},
		{"claudecode", map[string]interface{}{"session_id": "s", "prompt_id": "p", "tool_use_id": "tc"}, map[CorrelationTarget]string{CorrelationTargetSession: "s", CorrelationTargetTurn: "p", CorrelationTargetTool: "tc"}},
		{"hermes", map[string]interface{}{"extra": map[string]interface{}{"session_id": "s", "turn_id": "t", "event_id": "e", "tool_call_id": "tc"}}, map[CorrelationTarget]string{CorrelationTargetSession: "s", CorrelationTargetTurn: "t", CorrelationTargetSourceEvent: "e", CorrelationTargetTool: "tc"}},
		{"cursor", map[string]interface{}{"conversation_id": "s", "generation_id": "t", "messageId": "m", "tool_use_id": "tc"}, map[CorrelationTarget]string{CorrelationTargetSession: "s", CorrelationTargetTurn: "t", CorrelationTargetSourceEvent: "m", CorrelationTargetTool: "tc"}},
		{"windsurf", map[string]interface{}{"trajectory_id": "s", "execution_id": "t", "stepIndex": 3, "tool_call_id": "tc"}, map[CorrelationTarget]string{CorrelationTargetSession: "s", CorrelationTargetTurn: "t", CorrelationTargetExecution: "t", CorrelationTargetSourceSeq: "3", CorrelationTargetTool: "tc"}},
		{"geminicli", map[string]interface{}{"session_id": "s", "prompt_id": "p", "response_id": "rs"}, map[CorrelationTarget]string{CorrelationTargetSession: "s", CorrelationTargetTurn: "p", CorrelationTargetModelResponse: "rs"}},
		{"copilot", map[string]interface{}{"sessionId": "s"}, map[CorrelationTarget]string{CorrelationTargetSession: "s"}},
		{"openhands", map[string]interface{}{"conversation_id": "s", "message_id": "t", "event_id": "e", "tool_call_id": "tc", "llm_response_id": "rs"}, map[CorrelationTarget]string{CorrelationTargetSession: "s", CorrelationTargetTurn: "t", CorrelationTargetSourceEvent: "e", CorrelationTargetTool: "tc", CorrelationTargetModelResponse: "rs"}},
		{"antigravity", map[string]interface{}{"conversationId": "s", "stepIdx": 4, "invocationNum": 8, "toolCall": map[string]interface{}{"id": "tc"}}, map[CorrelationTarget]string{CorrelationTargetSession: "s", CorrelationTargetStep: "4", CorrelationTargetExecution: "8", CorrelationTargetTool: "tc"}},
		{"opencode", map[string]interface{}{"session_id": "s", "parentID": "ps", "messageId": "t", "part_id": "e", "callID": "tc"}, map[CorrelationTarget]string{CorrelationTargetSession: "s", CorrelationTargetParentSession: "ps", CorrelationTargetTurn: "t", CorrelationTargetSourceEvent: "e", CorrelationTargetTool: "tc"}},
		{"omnigent", map[string]interface{}{"conversation_id": "s", "root_conversation_id": "rs", "response_id": "t", "item_id": "e", "call_id": "tc"}, map[CorrelationTarget]string{CorrelationTargetSession: "s", CorrelationTargetRootSession: "rs", CorrelationTargetTurn: "t", CorrelationTargetSourceEvent: "e", CorrelationTargetTool: "tc"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := DefaultCorrelationSpec(tc.name)
			for target, want := range tc.wants {
				got, ok := spec.HookValue(tc.payload, target)
				if !ok || got.Value != want || got.Namespace != tc.name || got.IDKind == "" || got.Origin != CorrelationOriginReported {
					t.Errorf("target %s=(%+v,%v), want reported %q in %s namespace", target, got, ok, want, tc.name)
				}
			}
		})
	}
}

func TestNativeAndHookBindingSurfacesDoNotLeakAliases(t *testing.T) {
	spec := DefaultCorrelationSpec("codex")
	for _, key := range []string{"conversation.id", "gen_ai.conversation.id", "gen_ai.response.id", "thread.id", "turn.id"} {
		if got, ok := spec.HookValue(map[string]interface{}{key: "native-only"}, CorrelationTargetSession); ok {
			t.Errorf("native-only alias %q leaked into hook session mapping: %+v", key, got)
		}
	}
	if got, ok := spec.NativeOTLPValue(map[string]interface{}{"conversation.id": "native-session"}, CorrelationTargetSession); !ok || got.Value != "native-session" {
		t.Fatalf("Codex native conversation.id=(%+v,%v)", got, ok)
	}
}

func TestMembershipIDsCannotBeDeclaredAsMirrorProof(t *testing.T) {
	for _, name := range NewDefaultRegistry().Names() {
		spec := DefaultCorrelationSpec(name)
		for _, target := range spec.MirrorIdentityTargets {
			switch target {
			case CorrelationTargetSession, CorrelationTargetThread, CorrelationTargetTurn,
				CorrelationTargetAgent, CorrelationTargetExecution, CorrelationTargetStep:
				t.Errorf("%s declares membership target %s as mirror proof", name, target)
			}
		}
	}
}

func TestSourceProvenCrossRailMirrorIDsShareOneTypedKind(t *testing.T) {
	tests := []struct {
		name      string
		target    CorrelationTarget
		hookKey   string
		nativeKey string
	}{
		{"codex/tool", CorrelationTargetTool, "tool_use_id", "call_id"},
		{"claudecode/tool", CorrelationTargetTool, "tool_use_id", "gen_ai.tool.call.id"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			connectorName := strings.Split(tc.name, "/")[0]
			spec := DefaultCorrelationSpec(connectorName)
			if !spec.AllowsMirrorTarget(tc.target) {
				t.Fatalf("documented mirror target %s is not enabled", tc.target)
			}
			hook, hookOK := spec.HookValue(map[string]interface{}{tc.hookKey: "same-id"}, tc.target)
			native, nativeOK := spec.NativeOTLPValue(map[string]interface{}{tc.nativeKey: "same-id"}, tc.target)
			if !hookOK || !nativeOK {
				t.Fatalf("missing cross-rail binding hook=(%+v,%v) native=(%+v,%v)", hook, hookOK, native, nativeOK)
			}
			if hook.Namespace != native.Namespace || hook.IDKind != native.IDKind {
				t.Fatalf("typed kind mismatch hook=%s/%s native=%s/%s", hook.Namespace, hook.IDKind, native.Namespace, native.IDKind)
			}
			hookProof, hookProven := spec.MirrorProofForValue(CorrelationSurfaceHook, hook)
			nativeProof, nativeProven := spec.MirrorProofForValue(CorrelationSurfaceNativeOTLP, native)
			if !hookProven || !nativeProven || hookProof != nativeProof ||
				!spec.IsAuthoritativeValue(CorrelationSurfaceNativeOTLP, native) {
				t.Fatalf("field proof hook=(%q,%v) native=(%q,%v) authority=%v",
					hookProof, hookProven, nativeProof, nativeProven,
					spec.IsAuthoritativeValue(CorrelationSurfaceNativeOTLP, native))
			}
		})
	}
}

func TestOpenClawNativeTelemetryFailsClosedWithoutReviewedExporter(t *testing.T) {
	spec := DefaultCorrelationSpec("openclaw")
	if spec.NativeTelemetry.Stability != NativeTelemetryNone || len(spec.NativeOTLPBindings) != 0 ||
		len(spec.MirrorIdentityTargets) != 0 {
		t.Fatalf("OpenClaw advertises unreviewed native telemetry: %+v mirrors=%v",
			spec.NativeTelemetry, spec.MirrorIdentityTargets)
	}
}

func TestCopilotDocumentedHookAndNativeIDsStayOnTheirRails(t *testing.T) {
	spec := DefaultCorrelationSpec("copilot")
	hook := map[string]interface{}{
		"sessionId":      "session-1",
		"interaction_id": "untrusted-hook-interaction",
		"tool_use_id":    "untrusted-hook-tool",
	}
	if session, ok := spec.HookValue(hook, CorrelationTargetSession); !ok || session.Value != "session-1" {
		t.Fatalf("documented Copilot hook session=(%+v,%v)", session, ok)
	}
	for _, target := range []CorrelationTarget{CorrelationTargetMessage, CorrelationTargetModelRequest, CorrelationTargetTool} {
		if value, ok := spec.HookValue(hook, target); ok {
			t.Errorf("undocumented Copilot hook identity populated %s: %+v", target, value)
		}
	}

	native, ok := spec.NativeOTLPValue(map[string]interface{}{"github.copilot.interaction_id": "interaction-1"}, CorrelationTargetModelRequest)
	if !ok || native.Value != "interaction-1" || native.IDKind != "interaction" {
		t.Fatalf("Copilot native interaction=(%+v,%v)", native, ok)
	}
	if message, found := spec.NativeOTLPValue(map[string]interface{}{"github.copilot.interaction_id": "interaction-1"}, CorrelationTargetMessage); found {
		t.Fatalf("Copilot interaction was mislabeled as a message: %+v", message)
	}
	if spec.NativeTelemetry.IsAuthoritative(CorrelationTargetModelRequest) {
		t.Fatal("Copilot native interaction gained cross-rail authority without paired field proof")
	}
	if len(spec.MirrorIdentityTargets) != 0 {
		t.Fatalf("Copilot undocumented hook/native mirrors remain enabled: %v", spec.MirrorIdentityTargets)
	}
}

func TestClaudeDocumentedHookIDsAndCorrelationVersionFloor(t *testing.T) {
	spec := DefaultCorrelationSpec("claudecode")
	if spec.MinAgentVersion != "2.1.196" {
		t.Fatalf("Claude correlation min version=%q want 2.1.196", spec.MinAgentVersion)
	}
	payload := map[string]interface{}{
		"session_id":  "session-1",
		"prompt_id":   "prompt-1",
		"tool_use_id": "tool-1",
	}
	for target, want := range map[CorrelationTarget]string{
		CorrelationTargetSession: "session-1",
		CorrelationTargetTurn:    "prompt-1",
		CorrelationTargetTool:    "tool-1",
	} {
		value, ok := spec.HookValue(payload, target)
		if !ok || value.Value != want {
			t.Errorf("Claude documented %s=(%+v,%v) want %q", target, value, ok, want)
		}
	}
	for _, tc := range []struct {
		key    string
		target CorrelationTarget
	}{
		{"turnId", CorrelationTargetTurn},
		{"promptId", CorrelationTargetTurn},
		{"client_request_id", CorrelationTargetModelRequest},
		{"request_id", CorrelationTargetModelResponse},
		{"response_id", CorrelationTargetModelResponse},
	} {
		if value, ok := spec.HookValue(map[string]interface{}{tc.key: "undocumented"}, tc.target); ok {
			t.Errorf("undocumented Claude hook alias %q populated %s: %+v", tc.key, tc.target, value)
		}
	}
	if !spec.AllowsMirrorTarget(CorrelationTargetTool) || spec.AllowsMirrorTarget(CorrelationTargetModelResponse) {
		t.Fatalf("Claude mirror targets=%v want tool only", spec.MirrorIdentityTargets)
	}
}

func TestGeminiNativeToolCallUsesDocumentedUnderscoreSpelling(t *testing.T) {
	spec := DefaultCorrelationSpec("geminicli")
	tool, ok := spec.NativeOTLPValue(map[string]interface{}{"gen_ai.tool.call_id": "gemini-call-1"}, CorrelationTargetTool)
	if !ok || tool.Value != "gemini-call-1" || tool.Path != "gen_ai.tool.call_id" || tool.IDKind != "tool_invocation" {
		t.Fatalf("Gemini native tool=(%+v,%v)", tool, ok)
	}
	if value, found := spec.HookValue(map[string]interface{}{"toolCallId": "not-documented"}, CorrelationTargetTool); found {
		t.Fatalf("undocumented Gemini hook toolCallId was accepted: %+v", value)
	}
	if spec.AllowsMirrorTarget(CorrelationTargetTool) {
		t.Fatal("Gemini hook/native tool mirror is enabled without a shared documented hook ID")
	}
}

func TestCodexUndocumentedLineageAndResponseAliasesFailClosed(t *testing.T) {
	spec := DefaultCorrelationSpec("codex")
	for _, tc := range []struct {
		key    string
		target CorrelationTarget
	}{
		{"agentId", CorrelationTargetAgent},
		{"parentAgentId", CorrelationTargetParentAgent},
		{"subagent_id", CorrelationTargetChildAgent},
		{"response_id", CorrelationTargetModelResponse},
	} {
		if value, ok := spec.HookValue(map[string]interface{}{tc.key: "undocumented"}, tc.target); ok {
			t.Errorf("undocumented Codex hook alias %q populated %s: %+v", tc.key, tc.target, value)
		}
	}
	if spec.Allows(CorrelationInferenceSubagentIdentity) {
		t.Fatal("Codex subagent identity inference remains enabled without parent/depth evidence")
	}
	if !spec.Allows(CorrelationInferenceUniqueActivePromptBoundary) {
		t.Fatal("Codex native OTLP cannot attach to one durable active prompt boundary")
	}
	if spec.Allows(CorrelationInferencePromptBoundaryTurn) {
		t.Fatal("Codex native prompt-boundary attachment must not authorize minting a hook turn")
	}
	if spec.Completeness.AgentLifecycle != CorrelationCompletenessPartial || spec.Completeness.Model != CorrelationCompletenessPartial {
		t.Fatalf("Codex completeness overclaims hook evidence: %+v", spec.Completeness)
	}
	if spec.AllowsMirrorTarget(CorrelationTargetModelResponse) || !spec.AllowsMirrorTarget(CorrelationTargetTool) {
		t.Fatalf("Codex mirror targets=%v want tool only", spec.MirrorIdentityTargets)
	}
	native, ok := spec.NativeOTLPValue(map[string]interface{}{"gen_ai.response.id": "native-response-1"}, CorrelationTargetModelResponse)
	if !ok || native.Value != "native-response-1" {
		t.Fatalf("Codex native response evidence=(%+v,%v)", native, ok)
	}
}

func TestClaudeNativeRequestAndResponseIDsStayDistinct(t *testing.T) {
	spec := DefaultCorrelationSpec("claudecode")
	values := spec.NativeOTLPValues(map[string]interface{}{
		"request_id":         "provider-response-1",
		"client_request_id":  "client-request-1",
		"gen_ai.response.id": "provider-response-1",
	})
	if err := ValidateCorrelationValues(values); err != nil {
		t.Fatalf("documented Claude request/response aliases conflicted: %v", err)
	}
	wants := map[string]string{
		string(CorrelationTargetModelRequest):  "client-request-1",
		string(CorrelationTargetModelResponse): "provider-response-1",
	}
	for target, want := range wants {
		found := false
		for _, value := range values {
			if string(value.Target) == target && value.Value == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing Claude %s=%q from %+v", target, want, values)
		}
	}
}

func TestOpenHandsActionIDNeverAliasesProviderToolInvocation(t *testing.T) {
	spec := DefaultCorrelationSpec("openhands")
	action, ok := spec.HookValue(map[string]interface{}{"action_id": "shared"}, CorrelationTargetAction)
	if !ok || action.IDKind != "action" {
		t.Fatalf("action binding=(%+v,%v)", action, ok)
	}
	if tool, found := spec.HookValue(map[string]interface{}{"action_id": "shared"}, CorrelationTargetTool); found {
		t.Fatalf("action ID populated tool invocation: %+v", tool)
	}
	tool, ok := spec.HookValue(map[string]interface{}{"tool_call_id": "shared"}, CorrelationTargetTool)
	if !ok || tool.IDKind != "tool_invocation" {
		t.Fatalf("hook tool binding=(%+v,%v)", tool, ok)
	}
	if action.Target == tool.Target || action.IDKind == tool.IDKind {
		t.Fatal("OpenHands action_id was made equivalent to tool invocation")
	}
	if spec.NativeTelemetry.Stability != NativeTelemetryNone {
		t.Fatal("OpenHands advertises a native exporter that is not installed")
	}
}

func TestCorrelationAliasConflictsAreTypedAndFailClosed(t *testing.T) {
	codex := DefaultCorrelationSpec("codex")
	conflicting := codex.HookValues(map[string]interface{}{
		"session_id": "session-a",
		"sessionId":  "session-b",
	})
	if err := ValidateCorrelationValues(conflicting); err == nil {
		t.Fatal("conflicting aliases of one typed Codex session were accepted")
	}

	openhands := DefaultCorrelationSpec("openhands")
	independent := openhands.HookValues(map[string]interface{}{
		"action_id":    "shared-provider-value",
		"tool_call_id": "shared-provider-value",
	})
	if err := ValidateCorrelationValues(independent); err != nil {
		t.Fatalf("independent action and tool identities were treated as aliases: %v", err)
	}
}

func TestCorrelationProviderIDsArePreservedExactlyOrRejected(t *testing.T) {
	spec := DefaultCorrelationSpec("codex")
	exact := "provider:turn/with.Mixed_Case-01"
	values := spec.HookValues(map[string]interface{}{"turn_id": exact})
	if err := ValidateCorrelationValues(values); err != nil {
		t.Fatalf("exact provider ID rejected: %v", err)
	}
	if len(values) == 0 || values[len(values)-1].Value != exact {
		t.Fatalf("provider ID was rewritten: %+v", values)
	}

	for name, value := range map[string]string{
		"leading-space":  " padded",
		"trailing-space": "padded ",
		"control":        "turn\nother",
		"oversized":      strings.Repeat("x", maxCorrelationProviderIDBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			invalid := spec.HookValues(map[string]interface{}{"turn_id": value})
			if err := ValidateCorrelationValues(invalid); err == nil {
				t.Fatalf("invalid provider ID %q was accepted", name)
			}
		})
	}
}

func TestProviderTypedBindingsOverrideCanonicalFallbacks(t *testing.T) {
	claude := DefaultCorrelationSpec("claudecode")
	payload := map[string]interface{}{
		"turn_id":   "fallback-turn",
		"prompt_id": "provider-prompt",
	}
	hook, ok := claude.HookValue(payload, CorrelationTargetTurn)
	if !ok || hook.Value != "provider-prompt" || hook.IDKind != "prompt" {
		t.Fatalf("Claude hook prompt preference=(%+v,%v)", hook, ok)
	}
	native, ok := claude.NativeOTLPValue(map[string]interface{}{"prompt.id": "provider-prompt"}, CorrelationTargetTurn)
	if !ok || native.IDKind != hook.IDKind || native.Namespace != hook.Namespace {
		t.Fatalf("Claude cross-rail prompt typing hook=%+v native=(%+v,%v)", hook, native, ok)
	}
	if err := ValidateCorrelationValues(claude.HookValues(payload)); err != nil {
		t.Fatalf("distinct typed turn and prompt evidence conflicted: %v", err)
	}

	antigravity := DefaultCorrelationSpec("antigravity")
	tool, ok := antigravity.HookValue(map[string]interface{}{"tool_call_id": "call-1"}, CorrelationTargetTool)
	if !ok || tool.IDKind != "tool_call" {
		t.Fatalf("Antigravity provider tool kind=(%+v,%v)", tool, ok)
	}
}
