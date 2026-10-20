// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

// Every built-in contract that reaches Cisco AI Defense names its events per
// surface and the encoding they are sent in, and the derived declaration agrees
// with the runtime classification it comes from.
func TestBuiltinContractsDeclareAIDSurfaces(t *testing.T) {
	checked := 0
	for name, contracts := range builtinHookContracts {
		for _, contract := range contracts {
			if len(contract.AIDSurfaces) == 0 {
				continue
			}
			checked++
			if contract.AIDWireVersion != AIDWireVersionChatToolCalls {
				t.Errorf("%s/%s aid_wire_version=%q want %q",
					name, contract.ContractID, contract.AIDWireVersion, AIDWireVersionChatToolCalls)
			}
			events := make(map[string]bool, len(contract.Events))
			for _, event := range contract.Events {
				events[canonicalHookEvent(event)] = true
			}
			for _, surface := range contract.AIDSurfaces {
				if surface == AIDSurfaceEventContent {
					continue
				}
				declared := contract.AIDSurfaceEvents[surface]
				if len(declared) == 0 {
					t.Errorf("%s declares aid surface %q with no events", contract.ContractID, surface)
				}
				for _, event := range declared {
					if !events[canonicalHookEvent(event)] {
						t.Errorf("%s aid_surface_events[%q] names %q, which is not in events",
							contract.ContractID, surface, event)
					}
				}
			}
			checkAIDSurfaceClassification(t, contract.ContractID, contract.Events,
				contract.AIDSurfaces, contract.AIDSurfaceEvents)
			if routed := intersectEvents(contract.Routing().StructuredActionEvents, contract.Events); len(routed) > 0 &&
				!sameStrings(contract.AIDSurfaceEvents[AIDSurfaceToolCall], routed) {
				t.Errorf("%s aid_surface_events[tool_call]=%v, want the routed %v",
					contract.ContractID, contract.AIDSurfaceEvents[AIDSurfaceToolCall], routed)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no built-in contract reaching AID was checked")
	}
}

// A contract that declares no AID surface gets no events and no wire version,
// so the send path treats it as undeclared.
func TestAIDDeclarationAbsentWithoutSurfaces(t *testing.T) {
	contract := HookContract{Connector: "x", ContractID: "x-v1", Events: []string{"PreToolUse"}}
	if got := aidSurfaceEventsFor(contract); got != nil {
		t.Fatalf("aidSurfaceEventsFor=%v want nil", got)
	}
	fillAIDDeclaration(&contract)
	if contract.AIDWireVersion != "" || contract.AIDSurfaceEvents != nil {
		t.Fatalf("undeclared contract got wire=%q events=%v", contract.AIDWireVersion, contract.AIDSurfaceEvents)
	}
}

// checkAIDSurfaceClassification holds a declaration to the runtime
// classification the derived ones come from: prompt and tool_result list
// exactly the events the canonical spellings select, and a tool_call event is
// neither a prompt nor a result.
func checkAIDSurfaceClassification(
	t *testing.T,
	label string,
	events, surfaces []string,
	declared map[string][]string,
) {
	t.Helper()
	carried := make(map[string]bool, len(surfaces))
	for _, surface := range surfaces {
		carried[surface] = true
	}
	for surface, canonical := range map[string]map[string]bool{
		AIDSurfacePrompt:     aidPromptSurfaceEvents,
		AIDSurfaceToolResult: aidToolResultSurfaceEvents,
	} {
		if !carried[surface] {
			continue
		}
		if want := filterEvents(events, canonical); !sameStrings(declared[surface], want) {
			t.Errorf("%s aid_surface_events[%q]=%v, want %v", label, surface, declared[surface], want)
		}
	}
	for _, event := range declared[AIDSurfaceToolCall] {
		key := canonicalHookEvent(event)
		if aidPromptSurfaceEvents[key] || aidToolResultSurfaceEvents[key] {
			t.Errorf("%s aid_surface_events[tool_call] names %q, a prompt or result event", label, event)
		}
	}
}

// The send path carries a tool call only for a profile whose contract declares
// the tool_call surface in the implemented encoding.
func TestHookProfileCarriesAIDToolCall(t *testing.T) {
	for _, test := range []struct {
		name    string
		profile HookProfile
		want    bool
	}{
		{"declared", HookProfile{AIDSurfaces: []string{"tool_call"}, AIDWireVersion: AIDWireVersionChatToolCalls}, true},
		{"no contract", HookProfile{Name: "claudecode"}, false},
		{"surface without wire version", HookProfile{AIDSurfaces: []string{"tool_call"}}, false},
		{"other wire version", HookProfile{AIDSurfaces: []string{"tool_call"}, AIDWireVersion: "chat-tool-calls-v2"}, false},
		{"wire version without tool_call", HookProfile{AIDSurfaces: []string{"prompt"}, AIDWireVersion: AIDWireVersionChatToolCalls}, false},
	} {
		if got := HookProfileCarriesAIDToolCall(test.profile); got != test.want {
			t.Errorf("%s: got %v want %v", test.name, got, test.want)
		}
	}
	for name := range builtinHookContracts {
		for _, contract := range KnownHookContracts(name) {
			profile := HookProfile{AIDSurfaces: contract.AIDSurfaces, AIDWireVersion: contract.AIDWireVersion}
			if HookProfileAIDSurfaceEnabled(profile, AIDSurfaceToolCall) && !HookProfileCarriesAIDToolCall(profile) {
				t.Errorf("%s declares tool_call but would not carry it", contract.ContractID)
			}
		}
	}
}

// Every declared tool-call shape belongs to a real contract that sends tool
// calls, names a tool once, and uses the closed surface vocabulary; a shell
// tool names the argument that holds its command.
func TestAIDToolCallShapesDeclareRealContracts(t *testing.T) {
	contracts := map[string]HookContract{}
	for name := range builtinHookContracts {
		for _, contract := range KnownHookContracts(name) {
			contracts[contract.ContractID] = contract
		}
	}
	for contractID, shapes := range aidToolCallShapesByContract {
		contract, ok := contracts[contractID]
		if !ok {
			t.Errorf("aidToolCallShapesByContract names unknown contract %q", contractID)
			continue
		}
		profile := HookProfile{AIDSurfaces: contract.AIDSurfaces, AIDWireVersion: contract.AIDWireVersion}
		if !HookProfileCarriesAIDToolCall(profile) {
			t.Errorf("%s declares tool-call shapes but does not carry tool calls", contractID)
		}
		if !sameStrings(shapeTools(contract.AIDToolCallShapes), shapeTools(shapes)) {
			t.Errorf("%s AIDToolCallShapes=%v, want %v", contractID, contract.AIDToolCallShapes, shapes)
		}
		seen := map[string]bool{}
		for _, shape := range shapes {
			if shape.Tool == "" || seen[shape.Tool] {
				t.Errorf("%s shape tool %q is blank or repeated", contractID, shape.Tool)
			}
			seen[shape.Tool] = true
			if !validToolSurface(shape.Surface) {
				t.Errorf("%s/%s surface %q is not a ToolSurface", contractID, shape.Tool, shape.Surface)
			}
			if shape.Surface == ToolSurfaceShell && shape.CommandArg == "" {
				t.Errorf("%s/%s is a shell tool with no command_arg", contractID, shape.Tool)
			}
			if got, ok := contract.AIDToolCallShapeFor(shape.Tool); !ok || got != shape {
				t.Errorf("%s AIDToolCallShapeFor(%q)=%+v,%v", contractID, shape.Tool, got, ok)
			}
		}
	}
}

func shapeTools(shapes []AIDToolCallShape) []string {
	out := make([]string, 0, len(shapes))
	for _, shape := range shapes {
		out = append(out, shape.Tool+"|"+string(shape.Surface)+"|"+shape.CommandArg)
	}
	return out
}
