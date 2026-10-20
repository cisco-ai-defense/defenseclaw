// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The registry's AID surface declaration has to describe what the hook lane
// actually does with each event, or it documents rather than governs. For every
// contract event, the runtime classification and the declaration must agree.
func TestAIDSurfaceEventsMatchRuntimeClassification(t *testing.T) {
	registry := connector.NewDefaultRegistry()
	for _, name := range registry.Names() {
		for _, contract := range connector.KnownHookContracts(name) {
			declared := func(surface string, event string) bool {
				for _, candidate := range contract.AIDSurfaceEvents[surface] {
					if candidate == event {
						return true
					}
				}
				return false
			}
			carries := func(surface string) bool {
				for _, candidate := range contract.AIDSurfaces {
					if candidate == surface {
						return true
					}
				}
				return false
			}
			for _, event := range contract.Events {
				t.Run(contract.ContractID+"/"+event, func(t *testing.T) {
					if carries(connector.AIDSurfacePrompt) {
						if got, want := declared(connector.AIDSurfacePrompt, event), isPromptLikeEvent(event); got != want {
							t.Errorf("prompt surface declared=%v, runtime=%v", got, want)
						}
					}
					if carries(connector.AIDSurfaceToolResult) {
						if got, want := declared(connector.AIDSurfaceToolResult, event), isResultLikeEvent(event); got != want {
							t.Errorf("tool_result surface declared=%v, runtime=%v", got, want)
						}
					}
					if carries(connector.AIDSurfaceToolCall) {
						routed := contract.ToolCallLifecycle.RouteForEvent(event) == connector.ToolEventRouteStructuredAction
						if got := declared(connector.AIDSurfaceToolCall, event); got != routed {
							t.Errorf("tool_call surface declared=%v, routed=%v", got, routed)
						}
					}
				})
			}
		}
	}
}

// The registry's prompt and tool_result spellings are exactly the ones the
// runtime switches accept. Read from the source, so a spelling added to either
// switch without the registry, or left in the registry after the switch drops
// it, fails here even when no contract declares it yet.
func TestAIDSurfaceEventListsMatchRuntime(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "agent_hook.go", nil, 0)
	if err != nil {
		t.Fatalf("parse agent_hook.go: %v", err)
	}
	caseStrings := func(name string) []string {
		var out []string
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != name {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				clause, ok := n.(*ast.CaseClause)
				if !ok {
					return true
				}
				for _, expr := range clause.List {
					lit, ok := expr.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					value, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatalf("%s case %s: %v", name, lit.Value, err)
					}
					out = append(out, value)
				}
				return false
			})
		}
		if len(out) == 0 {
			t.Fatalf("no case strings found in %s; the switch moved", name)
		}
		sort.Strings(out)
		return out
	}
	for surface, fn := range map[string]string{
		connector.AIDSurfacePrompt:     "isPromptLikeEvent",
		connector.AIDSurfaceToolResult: "isResultLikeEvent",
	} {
		registry := connector.AIDSurfaceEventSpellings(surface)
		sort.Strings(registry)
		if runtime := caseStrings(fn); !reflect.DeepEqual(registry, runtime) {
			t.Errorf("%s spellings drifted from %s:\nregistry=%v\nruntime=%v", surface, fn, registry, runtime)
		}
	}
}

// Every contract that sends anything to AID names the encoding it sends.
func TestAIDWireVersionDeclaredForEveryAIDSurface(t *testing.T) {
	registry := connector.NewDefaultRegistry()
	for _, name := range registry.Names() {
		for _, contract := range connector.KnownHookContracts(name) {
			if len(contract.AIDSurfaces) == 0 {
				continue
			}
			if contract.AIDWireVersion != connector.AIDWireVersionChatToolCalls {
				t.Errorf("%s aid_wire_version=%q want %q",
					contract.ContractID, contract.AIDWireVersion, connector.AIDWireVersionChatToolCalls)
			}
		}
	}
}
