// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// The MCP mapper's caps, registered with the bound-rule property test
// (TestBoundRuleEveryLaneCap): past each cap the call carries the limit finding
// naming the cap, at least the unknown tier of the pack, and what was read
// before the cap still decides.
func init() {
	registerBoundedLane(
		boundedLaneCap{lane: "s7/nonshell mcp-twins", cap: bounded.Paths, limit: maxNonShellPathTwins,
			gen: nonShellPathsCall, seen: nonShellSeenCall},
		boundedLaneCap{lane: "s7/nonshell mcp-array", cap: bounded.Items, limit: 512,
			gen: nonShellFillCall(func(size int) any { return nonShellList(size, "a") }), seen: nonShellSeenCall},
		boundedLaneCap{lane: "s7/nonshell mcp-depth", cap: bounded.Depth, limit: 16,
			gen: nonShellFillCall(nonShellNest), seen: nonShellSeenCall},
		boundedLaneCap{lane: "s7/nonshell mcp-effects", cap: bounded.Effects, limit: 256,
			gen: nonShellFillCall(nonShellURLs), seen: nonShellSeenCall},
		boundedLaneCap{lane: "s7/nonshell mcp-nodes", cap: bounded.Nodes, limit: 1 << 16,
			gen: nonShellFillCall(nonShellKeys), seen: nonShellSeenCall},
		boundedLaneCap{lane: "s7/nonshell mcp-json-string", cap: bounded.Depth, limit: 4,
			gen: nonShellJSONStringCall, seen: nonShellSeenCall},
		boundedLaneCap{lane: "s7/nonshell mcp-string-bytes", cap: bounded.Bytes, limit: 1 << 20,
			gen: nonShellFillCall(nonShellBigString), seen: nonShellSeenCall},
		boundedLaneCap{lane: "s7/nonshell mcp-path-bytes", cap: bounded.Bytes, limit: 32 << 10,
			gen: nonShellLongPathCall, seen: nonShellSeenCall},
	)
}

const nonShellSeenPath = "/home/u/.ssh/id_rsa" // fixture of nonshell_tools_test.go

func nonShellSeenCall() boundedLaneCall {
	return boundedLaneCall{tool: "mcp__acme__read_file", input: map[string]any{"path": nonShellSeenPath}}
}

func nonShellList(n int, v any) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// nonShellFillCall builds {"path": <seen, when the shape asks>, "zz_fill": fill(size)}.
// The seen path sorts before the fill key, so it is read before the cap.
func nonShellFillCall(fill func(size int) any) func(int, boundedShape) (boundedLaneCall, bool) {
	return func(size int, shape boundedShape) (boundedLaneCall, bool) {
		if shape.nested || shape.multi || shape.seenAfter {
			return boundedLaneCall{}, false
		}
		input := map[string]any{"zz_fill": fill(size)}
		if shape.seen {
			input["path"] = nonShellSeenPath
		}
		return boundedLaneCall{tool: "mcp__acme__label", input: input}, true
	}
}

// nonShellNest is size levels of objects around a benign leaf.
func nonShellNest(size int) any {
	var cur any = "leaf"
	for i := 0; i < size-1; i++ {
		cur = map[string]any{"n": cur}
	}
	return cur
}

// nonShellURLs is size request objects, one effect each, none a collector.
func nonShellURLs(size int) any {
	out := make([]any, size)
	for i := range out {
		out[i] = map[string]any{"url": "https://api.example.com/v1/x"}
	}
	return out
}

// nonShellKeys is an object that holds size values in all (the call object and
// this one count two): size-2 scalar keys.
func nonShellKeys(size int) any {
	out := make(map[string]any, size)
	for i := 0; i < size-2; i++ {
		out["k"+itoaNS(i)] = 1
	}
	return out
}

// nonShellBigString is one string of size bytes.
func nonShellBigString(size int) any { return strings.Repeat("a", size) }

func itoaNS(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// nonShellPathsCall reads size benign paths, with the seen path first.
func nonShellPathsCall(size int, shape boundedShape) (boundedLaneCall, bool) {
	if shape.nested || shape.multi || shape.seenAfter {
		return boundedLaneCall{}, false
	}
	var paths []any
	if shape.seen {
		paths = append(paths, nonShellSeenPath)
	}
	for i := 0; i < size; i++ {
		paths = append(paths, "/repo/docs/f"+itoaNS(i)+".md")
	}
	return boundedLaneCall{tool: "mcp__filesystem__read_multiple_files", input: map[string]any{"paths": paths}}, true
}

// nonShellJSONStringCall wraps a request in size JSON strings, as a proxy tool does.
func nonShellJSONStringCall(size int, shape boundedShape) (boundedLaneCall, bool) {
	if shape.nested || shape.multi || shape.seenAfter {
		return boundedLaneCall{}, false
	}
	var inner any = map[string]any{"note": "ok"}
	if shape.seen {
		inner = map[string]any{"path": nonShellSeenPath}
	}
	for i := 0; i < size; i++ {
		raw, _ := jsonMarshalNS(inner)
		inner = map[string]any{"arguments": string(raw)}
	}
	return boundedLaneCall{tool: "mcp__proxy__call_tool", input: inner.(map[string]any)}, true
}

// nonShellLongPathCall is a benign path padded to size bytes (the seen shape pads the seen path).
func nonShellLongPathCall(size int, shape boundedShape) (boundedLaneCall, bool) {
	if shape.nested || shape.multi || shape.seenAfter {
		return boundedLaneCall{}, false
	}
	prefix := "/repo/"
	tail := "f.md"
	if shape.seen {
		prefix, tail = "/home/u/", ".ssh/id_rsa"
	}
	rem := max(0, size-len(prefix)-len(tail))
	pad := strings.Repeat("./", rem/2)
	if rem%2 == 1 {
		pad += "/"
	}
	return boundedLaneCall{tool: "mcp__acme__read_file", input: map[string]any{"path": prefix + pad + tail}}, true
}

func jsonMarshalNS(v any) ([]byte, error) { return json.Marshal(v) }
