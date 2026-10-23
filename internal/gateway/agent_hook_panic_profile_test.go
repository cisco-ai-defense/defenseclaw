// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func panicTestProfiles(t *testing.T, api *APIServer) map[string]connector.HookProfile {
	t.Helper()
	profiles := map[string]connector.HookProfile{}
	for _, name := range sharedDefaultRegistry().Names() {
		if _, ok := api.hookProfileProvider(name); !ok {
			continue
		}
		profile := api.hookProfileForConnector(name)
		if len(profile.SupportedEvents) == 0 {
			if name != "kiro" {
				t.Fatalf("registered hook profile %s has no events", name)
			}
			// Host Kiro installs two surfaces without a versioned host contract.
			profile.SupportedEvents = []string{"UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"}
		}
		profiles[name] = profile
	}
	if len(profiles) < 10 {
		t.Fatalf("registered hook profiles=%d, want the complete hook registry", len(profiles))
	}
	for _, name := range []string{"claudecode", "codex", "copilot", "cursor", "devin", "antigravity", "hermes", "opencode", "kiro", "amp"} {
		if _, ok := profiles[name]; !ok {
			t.Fatalf("registered hook profile %s is missing", name)
		}
	}
	return profiles
}

func panicTestEvent(profile connector.HookProfile, blockable bool) string {
	prefer := ""
	for _, event := range profile.SupportedEvents {
		action, _ := mapHookActionForProfile("block", "action", event, profile.Capabilities, profile, nil)
		if (action == "block") != blockable {
			continue
		}
		if strings.EqualFold(event, "PreToolUse") || strings.EqualFold(event, "pre_tool_call") || strings.EqualFold(event, "tool.call") {
			return event
		}
		if prefer == "" || strings.Contains(strings.ToLower(event), "post") {
			prefer = event
		}
	}
	return prefer
}

func panicTestLifecycleEvent(profile connector.HookProfile) string {
	for _, event := range profile.SupportedEvents {
		if strings.Contains(strings.ToLower(event), "post") {
			return event
		}
	}
	for _, event := range profile.SupportedEvents {
		lower := strings.ToLower(event)
		if strings.Contains(lower, "session") || strings.Contains(lower, "stop") || strings.Contains(lower, "agent.end") {
			return event
		}
	}
	return ""
}

func injectPanicForProfile(t *testing.T, name string) {
	t.Helper()
	previous, had := hookProfileRuntimes[name]
	hookProfileRuntimes[name] = func(profile connector.HookProfile) hookProfileRuntime {
		runtime := defaultHookProfileRuntime(profile)
		runtime.Evaluate = func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}) agentHookResponse {
			panic("injected evaluator error")
		}
		return runtime
	}
	t.Cleanup(func() {
		if had {
			hookProfileRuntimes[name] = previous
		} else {
			delete(hookProfileRuntimes, name)
		}
	})
}

func panicTestPayload(name, event, cwd string) (map[string]interface{}, string) {
	if name == "antigravity" {
		return map[string]interface{}{
			"conversationId": "panic-test", "stepIdx": 1, "workspacePaths": []string{cwd},
			"toolCall": map[string]interface{}{"name": "run_command", "args": map[string]interface{}{"Cwd": cwd, "CommandLine": "echo done"}},
		}, event
	}
	if name == "copilot" {
		return map[string]interface{}{
			"sessionId": "panic-test", "timestamp": float64(1), "cwd": cwd,
			"toolName": "bash", "toolArgs": `{"command":"echo done"}`,
		}, event
	}
	return map[string]interface{}{
		"hook_event_name": event, "session_id": "panic-test", "cwd": cwd,
		"tool_name": "Bash", "tool_input": map[string]interface{}{"command": "echo done"},
		"tool_args": map[string]interface{}{"command": "echo done"},
	}, ""
}

func postPanicTestHook(t *testing.T, api *APIServer, name, event string) (map[string]interface{}, agentHookRequest) {
	t.Helper()
	payload, registeredEvent := panicTestPayload(name, event, t.TempDir())
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	profile := api.hookProfileForConnector(name)
	decoded := normalizeAgentHookRequestWithRawProfileEvent(name, payload, body, profile, registeredEvent, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+name+"/hook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	switch name {
	case "codex":
		setTestCodexHookBinding(req, event, defaultTestCodexHookContract)
	case "copilot":
		req.Header.Set("X-DefenseClaw-Copilot-Event", event)
	case "antigravity":
		req.Header.Set("X-DefenseClaw-Antigravity-Event", event)
	}
	w := httptest.NewRecorder()
	api.handleAgentHook(name).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s/%s status=%d body=%s", name, event, w.Code, w.Body.String())
	}
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response, decoded
}

func normalizedPanicOutput(value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		if len(v) == 0 {
			return nil
		}
		out := map[string]interface{}{}
		for key, item := range v {
			out[key] = normalizedPanicOutput(item)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(v))
		for index, item := range v {
			out[index] = normalizedPanicOutput(item)
		}
		return out
	case []map[string]interface{}:
		out := make([]interface{}, len(v))
		for index, item := range v {
			out[index] = normalizedPanicOutput(item)
		}
		return out
	case string:
		if len(v) > 32 || strings.HasPrefix(v, "<redacted ") {
			return "<reason>"
		}
	}
	return value
}

func panicTestOutput(name string, response map[string]interface{}) interface{} {
	switch name {
	case "claudecode":
		return response["claude_code_output"]
	case "codex":
		return response["codex_output"]
	default:
		return response["hook_output"]
	}
}

func panicWireDenies(value interface{}) bool {
	object, ok := value.(map[string]interface{})
	if !ok {
		return false
	}
	for key, item := range object {
		if key == "continue" && item == false {
			return true
		}
		if key == "permissionDecision" || key == "permission" || key == "decision" || key == "behavior" {
			if item == "deny" || item == "block" {
				return true
			}
		}
		if panicWireDenies(item) {
			return true
		}
	}
	return false
}

func TestRecoveredHookFailModeByDeployment(t *testing.T) {
	var nilConfig *config.Config
	if got := nilConfig.EffectiveActionHookFailModeForConnector("hermes"); got != "closed" {
		t.Fatalf("nil config action fail mode=%q, want closed", got)
	}
	api := &APIServer{}
	profiles := panicTestProfiles(t, api)
	for name, profile := range profiles {
		event := panicTestEvent(profile, true)
		if event == "" {
			t.Fatalf("%s has no blockable event", name)
		}
		for _, deployment := range []struct{ name, mode, profile string }{
			{"oss", "", ""},
			{"standalone", managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone},
			{"secure_client", managed.DeploymentModeManagedEnterprise, managed.ProfileSecureClient},
		} {
			for _, failMode := range []string{"", "open", "closed"} {
				for _, mode := range []string{"action", "observe"} {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", name, deployment.name, failMode, mode), func(t *testing.T) {
						injectPanicForProfile(t, name)
						store, logger := testStoreAndLogger(t)
						cfg := &config.Config{}
						cfg.DeploymentMode, cfg.Enterprise.Profile = deployment.mode, deployment.profile
						cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode, cfg.Guardrail.Connector = mode, failMode, name
						server := &APIServer{scannerCfg: cfg, store: store, logger: logger}
						response, _ := postPanicTestHook(t, server, name, event)
						want, wantMode := "block", "action"
						reason := "a closed failed check blocks in every mode"
						if deployment.name == "secure_client" && failMode == "closed" {
							reason = "an explicit closed wins under Secure Client too"
						} else if deployment.name == "secure_client" {
							want, wantMode, reason = "allow", mode, "Secure Client's unset or open fail mode allows recovered errors"
						} else if deployment.name == "standalone" && failMode == "open" {
							reason = "the administrator's open applies to outages, not recovered evaluator errors"
						} else if failMode == "open" && name != "cursor" {
							want, wantMode, reason = "allow", mode, "explicit open is effective for this connector"
						} else if failMode == "open" && name == "cursor" {
							reason = "the cursor accessor keeps this connector closed"
						}
						wantWouldBlock := want == "allow"
						if response["action"] != want || response["raw_action"] != "block" || response["would_block"] != wantWouldBlock || response["mode"] != wantMode {
							t.Fatalf("%s: response=%v, want %s/block/%v/%s", reason, response, want, wantWouldBlock, wantMode)
						}
						row := soleHookDecisionForTest(t, store)
						if row.Structured["result"] != "panic" {
							t.Fatalf("%s: audit result=%v, want panic", reason, row.Structured["result"])
						}
					})
				}
			}
		}
	}
}

func TestRecoveredHookVerdictUsesRegisteredProfiles(t *testing.T) {
	api := &APIServer{}
	profiles := panicTestProfiles(t, api)
	for name, profile := range profiles {
		if panicTestEvent(profile, false) == "" {
			t.Logf("%s declares no supported event outside its block surface", name)
		}
		for _, tc := range []struct{ kind, event string }{
			{"blockable", panicTestEvent(profile, true)},
			{"nonblockable", panicTestEvent(profile, false)},
			{"lifecycle", panicTestLifecycleEvent(profile)},
		} {
			if tc.event == "" {
				if tc.kind == "nonblockable" {
					continue
				}
				t.Fatalf("%s has no valid %s event", name, tc.kind)
			}
			t.Run(name+"/"+tc.kind+"/"+tc.event, func(t *testing.T) {
				injectPanicForProfile(t, name)
				store, logger := testStoreAndLogger(t)
				cfg := &config.Config{}
				cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode, cfg.Guardrail.Connector = "action", "closed", name
				server := &APIServer{scannerCfg: cfg, store: store, logger: logger}
				response, req := postPanicTestHook(t, server, name, tc.event)
				output := panicTestOutput(name, response)
				if hookexec.LifecycleEvent(name, tc.event) && !terminalLifecycleEvent(name, tc.event) {
					wire, _ := output.(map[string]interface{})
					if response["action"] != "allow" || response["raw_action"] != "block" || response["would_block"] != true || lifecycleAnswerRepeats(wire) {
						t.Fatalf("lifecycle panic response=%v, want a neutral allow", response)
					}
					if row := soleHookDecisionForTest(t, store); row.Structured["result"] != "panic" {
						t.Fatalf("audit result=%v, want one panic row", row.Structured["result"])
					}
					return
				}
				// The closed answer is the event's native control: a block
				// where the hook can carry one, else the advisory allow.
				want := panicNativeActionOracle(name, tc.event, profile)
				wantWouldBlock := want == "allow"
				if response["action"] != want || response["raw_action"] != "block" || response["would_block"] != wantWouldBlock || response["mode"] != "action" {
					t.Fatalf("panic response=%v, want %s/action would_block=%v", response, want, wantWouldBlock)
				}
				expected := agentHookResponseForProfile(profile, req, want, "block", "WARN", "comparison reason for recovered hook evaluation error", nil, "action", wantWouldBlock, profile.Capabilities)
				switch {
				case terminalLifecycleEvent(name, tc.event):
					if wire, ok := output.(map[string]interface{}); !ok || wire["continue"] != false || wire["stopReason"] == "" {
						t.Fatalf("Claude lifecycle panic output=%v, want terminal closed failure", output)
					}
				default:
					if got, want := normalizedPanicOutput(output), normalizedPanicOutput(expected.HookOutput); !reflect.DeepEqual(got, want) {
						t.Fatalf("hook output=%v, normal verdict output=%v", got, want)
					}
				}
				if want == "block" {
					denies := panicWireDenies(panicTestOutput(name, response))
					if name == "amp" {
						denies = response["action"] == "block"
					}
					if !denies {
						t.Fatalf("%s/%s block has no dialect denial: %v", name, tc.event, response)
					}
				}
				row := soleHookDecisionForTest(t, store)
				if row.Structured["result"] != "panic" {
					t.Fatalf("audit result=%v, want one panic row", row.Structured["result"])
				}
			})
		}
	}
}

type panickingResponderConnector struct {
	connector.Connector
	provider connector.HookProfileProvider
	panicked *bool
}

func (c panickingResponderConnector) HookProfile(opts connector.SetupOpts) connector.HookProfile {
	profile := c.provider.HookProfile(opts)
	profile.Respond = func(connector.HookRespondInput) connector.HookRespondOutput {
		*c.panicked = true
		panic("injected native response shaper panic")
	}
	return profile
}

func TestHookPanicResponseNativeFallbackAfterResponderPanic(t *testing.T) {
	for _, tc := range []struct{ name, event string }{
		{"antigravity", "PreToolUse"},
		{"antigravity", "Stop"},
		{"kiro", "PreToolUse"},
	} {
		t.Run(tc.name+"/"+tc.event, func(t *testing.T) {
			name := tc.name
			original, ok := sharedDefaultRegistry().Get(name)
			if !ok {
				t.Fatalf("missing registered %s connector", name)
			}
			provider, ok := original.(connector.HookProfileProvider)
			if !ok {
				t.Fatalf("%s has no hook profile", name)
			}
			panicked := false
			registry := connector.NewRegistry()
			registry.RegisterBuiltin(panickingResponderConnector{
				Connector: original, provider: provider, panicked: &panicked,
			})
			cfg := config.DefaultConfig()
			cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
			cfg.Enterprise.Profile = managed.ProfileSecureClient
			cfg.Guardrail.Mode = "observe"
			cfg.Guardrail.HookFailMode = "closed"
			api := &APIServer{scannerCfg: cfg, connectorRegistry: registry}
			req := agentHookRequest{ConnectorName: name, HookEventName: tc.event}
			resp := api.hookPanicResponse(t.Context(), name, req, nil, nil)
			if hookexec.LifecycleEvent(name, tc.event) {
				// The lifecycle answer survives a second responder panic
				// without turning into a veto that repeats the hook.
				if !panicked || resp.Action != "allow" || !resp.WouldBlock || lifecycleAnswerRepeats(resp.HookOutput) {
					t.Fatalf("%s responder panic response=%+v, panicked=%t", name, resp, panicked)
				}
				return
			}
			if !panicked || resp.Action != "block" || resp.Mode != "action" || resp.WouldBlock ||
				!panicWireDenies(resp.HookOutput) {
				t.Fatalf("%s responder panic response=%+v, panicked=%t", name, resp, panicked)
			}
		})
	}
}
