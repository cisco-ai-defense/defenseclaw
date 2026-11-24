// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"github.com/defenseclaw/defenseclaw/internal/paymentcard"
	"regexp"
	"strings"
	"testing"
)

func gap2166ChatDelta(choice int, field, value string) string {
	return gap1265Raw + "data: " + streamTailJSON(map[string]any{
		"choices": []any{map[string]any{"index": choice, "delta": map[string]any{field: value}}},
	}) + "\n\n"
}

func gap2166Rows(t *testing.T, path, tier, pack string, managed bool) []gap1265Row {
	t.Helper()
	card := gap1091Group(gap1091Card(t, "4", 16), " ", 4, 4, 4, 4)
	bad := card[:len(card)-1] + string("0123456789"[(int(card[len(card)-1]-'0')+1)%10])
	key := gap0429Label("gh", "p_") + gap0429Random(t, gap0429Alnum, 36)
	lead := retestFiller(2048)[:2048] + " VALUE: "
	type split struct {
		name, left, right, full string
		block                   bool
	}
	values := []split{
		{"card", card[:10], card[10:], card, true},
		{"token", key[:7], key[7:], key, true},
		{"invalid-luhn", bad[:10], bad[10:], bad, false},
	}
	var rows []gap1265Row
	// A complete answer-lane card is the positive control in every tier.
	var whole []string
	switch path {
	case "passthrough/anthropic":
		whole = []string{gap2162AnthropicDelta(0, "text_delta", lead+card+" done.\n")}
	case "passthrough/openai-responses":
		whole = []string{gap2162Event("response.output_text.delta", map[string]any{"output_index": 0, "delta": lead + card + " done.\n"})}
	default:
		whole = []string{gap2166ChatDelta(0, "content", lead+card+" done.\n")}
	}
	rows = append(rows, gap1265Row{name: "card-one-lane", tier: tier, pack: pack, managed: managed,
		pieces: whole, wantBlocked: true,
		secret: gap0429Secret{name: "card", class: "control", text: "VALUE: " + card, body: len("VALUE: "), end: len("VALUE: ") + len(card)}})
	for _, v := range values {
		var pieces []string
		switch path {
		case "passthrough/anthropic":
			pieces = []string{
				gap2162AnthropicDelta(0, "thinking_delta", lead+v.left),
				gap2162AnthropicStop(0),
				gap2162AnthropicStart(1, map[string]any{"type": "text", "text": ""}),
				gap2162AnthropicDelta(1, "text_delta", v.right+" done.\n"),
			}
		case "passthrough/openai-responses":
			pieces = []string{
				gap2162Event("response.reasoning_text.delta", map[string]any{"output_index": 0, "delta": lead + v.left}),
				gap2162Event("response.output_text.delta", map[string]any{"output_index": 1, "delta": v.right + " done.\n"}),
			}
		default:
			pieces = []string{
				gap2166ChatDelta(0, "reasoning_content", lead+v.left),
				gap2166ChatDelta(0, "content", v.right+" done.\n"),
			}
		}
		s := gap0429Secret{name: v.name, class: "boundary", text: "VALUE: " + v.full, body: len("VALUE: "), end: len("VALUE: ") + len(v.full)}
		rows = append(rows, gap1265Row{name: v.name, tier: tier, pack: pack, managed: managed,
			pieces: pieces, secret: s, wantBlocked: v.block})
	}
	if path == "passthrough/openai-chat" {
		rows = append(rows, gap1265Row{name: "two-choices", tier: tier, pack: pack, managed: managed,
			pieces: []string{
				gap2166ChatDelta(0, "reasoning_content", lead+card[:10]),
				gap2166ChatDelta(1, "content", card[10:]+" done.\n"),
			}})
		rows = append(rows, gap1265Row{name: "tool-input", tier: tier, pack: pack, managed: managed,
			pieces: []string{
				gap2166ChatDelta(0, "reasoning_content", lead+card[:10]),
				gap1265Raw + "data: " + streamTailJSON(map[string]any{
					"choices": []any{map[string]any{"index": 0, "delta": map[string]any{
						"tool_calls": []any{map[string]any{"index": 0, "type": "function",
							"function": map[string]any{"name": "Read", "arguments": streamTailJSON(map[string]any{"partial": card[10:]})}}},
					}}},
				}) + "\n\n",
				gap2166ChatDelta(0, "content", "safe answer.\n"),
			}})
	}
	if path == "passthrough/openai-responses" {
		rows = append(rows, gap1265Row{name: "summary-part", tier: tier, pack: pack, managed: managed,
			pieces: []string{
				gap2162Event("response.reasoning_summary_text.delta", map[string]any{"output_index": 0, "summary_index": 0, "delta": lead + card[:10]}),
				gap2162Event("response.output_text.delta", map[string]any{"output_index": 1, "delta": card[10:] + " done.\n"}),
			}})
	}
	// A label in reasoning and a value arriving in two answer chunks must
	// hold the first value bytes until the existing secret rule decides it.
	bearer := gap0429Random(t, gap0429Alnum, 40)
	var bearerPieces []string
	switch path {
	case "passthrough/anthropic":
		bearerPieces = []string{
			gap2162AnthropicDelta(0, "thinking_delta", lead+"Authorization: Bearer "),
			gap2162AnthropicStop(0),
			gap2162AnthropicStart(1, map[string]any{"type": "text", "text": ""}),
			gap2162AnthropicDelta(1, "text_delta", bearer[:8]),
			gap2162AnthropicDelta(1, "text_delta", bearer[8:]+" done.\n"),
		}
	case "passthrough/openai-responses":
		bearerPieces = []string{
			gap2162Event("response.reasoning_text.delta", map[string]any{"output_index": 0, "delta": lead + "Authorization: Bearer "}),
			gap2162Event("response.output_text.delta", map[string]any{"output_index": 1, "delta": bearer[:8]}),
			gap2162Event("response.output_text.delta", map[string]any{"output_index": 1, "delta": bearer[8:] + " done.\n"}),
		}
	default:
		bearerPieces = []string{
			gap2166ChatDelta(0, "reasoning_content", lead+"Authorization: Bearer "),
			gap2166ChatDelta(0, "content", bearer[:8]),
			gap2166ChatDelta(0, "content", bearer[8:]+" done.\n"),
		}
	}
	rows = append(rows, gap1265Row{name: "bearer-separator", tier: tier, pack: pack, managed: managed,
		pieces: bearerPieces, at: len(bearerPieces) - 1, pause: gap2162Pause, wantBlocked: false,
		secret: gap0429Secret{name: "bearer", class: "boundary", text: "Bearer " + bearer, body: len("Bearer "), end: len("Bearer ") + len(bearer)}})
	return rows
}

// GAP-2166: only a reasoning-to-answer boundary in one choice may form a match.
func TestGAP2166ReasoningAnswerBoundaryStream(t *testing.T) {
	paths := gap0429PathsNamed(t, "passthrough/anthropic", "passthrough/openai-chat", "passthrough/openai-responses")
	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			var rows []gap1265Row
			for _, tier := range streamTailTiers {
				if hookAnswerRaceBuild && !tier.blocks {
					continue
				}
				rows = append(rows, gap2166Rows(t, path.name, tier.name, tier.pack, tier.managed)...)
			}
			results, _ := gap1265Serve(t, path, rows)
			for i, row := range rows {
				res := results[i]
				name := row.tier + "/" + row.name
				if row.wantBlocked {
					if !res.blocked {
						t.Errorf("%s: split value was not blocked", name)
					}
					if n := gap0429Released(res.snapRaw, row.secret); n > 0 {
						t.Errorf("%s: %d value bytes reached client before verdict", name, n)
					}
					if n := gap0429Released(res.bodyRaw, row.secret); n > 0 {
						t.Errorf("%s: %d blocked value bytes reached client", name, n)
					}
				} else if row.name == "bearer-separator" {
					if n := gap0429Released(res.snapRaw, row.secret); n > 0 {
						t.Errorf("%s: %d bearer value bytes reached client before verdict", name, n)
					}
				} else if res.blocked {
					t.Errorf("%s: benign boundary was blocked", name)
				}
			}
		})
	}
}

// The regex can cross a newline, but the shared card validator rejects
// mixed separators. This pins the GAP-2166 failure below regex matching.
func TestGAP2166GroupedNewlineProbe(t *testing.T) {
	card := gap1091Group(gap1091Card(t, "4", 16), " ", 4, 4, 4, 4)
	split := card[:10] + "\n" + card[10:]
	if !validPaymentCardCandidate(card) {
		t.Fatal("synthetic Visa card fixture is not valid")
	}
	if !regexp.MustCompile(`[\s-]`).MatchString("\n") {
		t.Fatal("card regex separator did not accept a line feed")
	}
	if !paymentcard.Grouped(card) || paymentcard.Grouped(split) {
		t.Fatal("the shared card grouping validator did not reject mixed separators")
	}
	if validPaymentCardCandidate(split) {
		t.Fatal("a mixed space/newline card unexpectedly passed grouping")
	}
}

// GAP-2170: a short answer between two reasoning parts must leave the
// reasoning's open run held until its later part decides it.
func TestGAP2170InterleavedReasoningRunHeld(t *testing.T) {
	paths := gap0429PathsNamed(t, "passthrough/anthropic", "passthrough/openai-chat", "passthrough/openai-responses")
	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			var rows []gap1265Row
			for _, tier := range streamTailTiers {
				if hookAnswerRaceBuild && !tier.blocks {
					continue
				}
				card := gap1091Group(gap1091Card(t, "4", 16), " ", 4, 4, 4, 4)
				lead := retestFiller(2048)[:2048] + " VALUE: "
				first, rest := card[:10], card[10:]
				var pieces []string
				switch path.name {
				case "passthrough/anthropic":
					pieces = []string{
						gap2162AnthropicDelta(0, "thinking_delta", lead+first),
						gap2162AnthropicStop(0),
						gap2162AnthropicStart(1, map[string]any{"type": "text", "text": ""}),
						gap2162AnthropicDelta(1, "text_delta", "checking. "),
						gap2162AnthropicStop(1),
						gap2162AnthropicStart(2, map[string]any{"type": "thinking", "thinking": ""}),
						gap2162AnthropicDelta(2, "thinking_delta", rest+" done.\n"),
					}
				case "passthrough/openai-responses":
					pieces = []string{
						gap2162Event("response.reasoning_text.delta", map[string]any{"output_index": 0, "delta": lead + first}),
						gap2162Event("response.output_text.delta", map[string]any{"output_index": 1, "delta": "checking. "}),
						gap2162Event("response.reasoning_text.delta", map[string]any{"output_index": 0, "delta": rest + " done.\n"}),
					}
				default:
					pieces = []string{
						gap2166ChatDelta(0, "reasoning_content", lead+first),
						gap2166ChatDelta(0, "content", "checking. "),
						gap2166ChatDelta(0, "reasoning_content", rest+" done.\n"),
					}
				}
				rows = append(rows, gap1265Row{name: "card-across-reasoning", tier: tier.name, pack: tier.pack, managed: tier.managed,
					pieces: pieces, at: len(pieces) - 1, pause: gap2162Pause, wantBlocked: true,
					secret: gap0429Secret{name: "card", class: "boundary", text: "VALUE: " + card, body: len("VALUE: "), end: len("VALUE: ") + len(card)}})
			}
			results, _ := gap1265Serve(t, path, rows)
			for i, row := range rows {
				res := results[i]
				if !res.blocked {
					t.Errorf("%s: complete card was not blocked", row.tier)
				}
				before := gap0429Released(res.snapRaw, row.secret)
				final := gap0429Released(res.bodyRaw, row.secret)
				t.Logf("%s: before=%d final=%d blocked=%v", row.tier, before, final, res.blocked)
				if before > 0 {
					t.Errorf("%s: %d card bytes reached client before verdict", row.tier, before)
				}
				if final > 0 {
					t.Errorf("%s: %d blocked card bytes reached client", row.tier, final)
				}
			}
		})
	}
}

func TestGAP2166CheckViewBoundaries(t *testing.T) {
	var r responseText
	r.Add(reasoningPiece(0, "prefix gh"))
	r.Add(answerPiece(0, "p_suffix"))
	if got := r.String(); got != "prefix gh\np_suffix" {
		t.Fatalf("canonical text changed: %q", got)
	}
	if got := r.CheckText(); got != "prefix gh\np_suffix\n\x00\nprefix ghp_suffix" {
		t.Fatalf("mid-token boundary missing: %q", got)
	}
	var choices responseText
	choices.Add(reasoningPiece(0, "left"))
	choices.Add(answerPiece(1, "right"))
	if choices.CheckText() != choices.String() {
		t.Fatal("joined two choices")
	}
	var tools responseText
	tools.Add(toolInputPiece(0, 0, "left"))
	tools.Add(answerPiece(0, "right"))
	if tools.CheckText() != tools.String() {
		t.Fatal("joined tool input to answer")
	}
	var summary responseText
	summary.Add(summaryPiece(0, 0, "left"))
	summary.Add(answerPiece(0, "right"))
	if summary.CheckText() != summary.String() {
		t.Fatal("joined Responses summary to answer")
	}
	var buffered responseText
	buffered.Add(answerPiece(0, "right"))
	buffered.Add(reasoningPiece(0, "left "))
	if buffered.CheckText() != buffered.String() {
		t.Fatal("stream joined answer before reasoning")
	}
	if got := buffered.CheckTextNonStream(); got != "right\nleft \n\x00\nleft right" {
		t.Fatalf("buffered reasoning-to-answer view: %q", got)
	}
	var newline responseText
	newline.Add(reasoningPiece(0, "left\n"))
	newline.Add(answerPiece(0, "right"))
	if got := newline.CheckText(); got != "left\n\nright\n\x00\nleft right" {
		t.Fatalf("newline boundary: %q", got)
	}
}

func TestGAP2166BufferedChatCheckText(t *testing.T) {
	card := gap1091Group(gap1091Card(t, "4", 16), " ", 4, 4, 4, 4)
	body := []byte(streamTailJSON(map[string]any{
		"choices": []any{map[string]any{"index": 0, "message": map[string]any{
			"content": card[10:], "reasoning_content": "VALUE: " + card[:10],
		}}},
	}))
	canonical, _ := extractRawForwardCompletion(body, false)
	check := extractRawForwardCheckCompletion(body)
	if !strings.Contains(check, "VALUE: "+card) || strings.Contains(canonical, "VALUE: "+card) {
		t.Fatal("buffered raw-forward check view did not preserve canonical separation")
	}
	native := passthroughReplyCheckText(body, "openai", nil)
	if !strings.Contains(native, "VALUE: "+card) {
		t.Fatal("buffered passthrough chat check missed the boundary")
	}
	responses := []byte(streamTailJSON(map[string]any{
		"output": []any{
			map[string]any{"type": "reasoning", "summary": []any{map[string]any{"text": "VALUE: " + card[:10]}}},
			map[string]any{"type": "message", "content": []any{map[string]any{"type": "output_text", "text": card[10:]}}},
		},
	}))
	if got := extractPassthroughResponseCheckContent(responses, "openai"); strings.Contains(got, "VALUE: "+card) {
		t.Fatal("Responses summary was joined to the answer")
	}
	var canonicalSummary responseText
	canonicalSummary.Add(summaryPiece(0, 0, "summary"))
	canonicalSummary.Add(reasoningPiece(0, "reasoning"))
	if canonicalSummary.String() != "summaryreasoning" {
		t.Fatal("summary marker changed canonical output")
	}
}

func TestGAP2166ControlVerdictsAreNone(t *testing.T) {
	card := gap1091Group(gap1091Card(t, "4", 16), " ", 4, 4, 4, 4)
	bad := card[:len(card)-1] + string("0123456789"[(int(card[len(card)-1]-'0')+1)%10])
	cases := map[string][]responsePiece{
		"invalid-luhn": {reasoningPiece(0, "VALUE: "+bad[:10]), answerPiece(0, bad[10:])},
		"two-choices":  {reasoningPiece(0, "VALUE: "+card[:10]), answerPiece(1, card[10:])},
		"tool-input":   {toolInputPiece(0, 0, "VALUE: "+card[:10]), answerPiece(0, card[10:])},
		"summary-part": {summaryPiece(0, 0, "VALUE: "+card[:10]), answerPiece(0, card[10:])},
	}
	inspector := retestInspector()
	for name, pieces := range cases {
		t.Run(name, func(t *testing.T) {
			var acc responseText
			acc.AddAll(pieces)
			check := acc.CheckText()
			verdict := inspector.Inspect(context.Background(), "completion", check,
				[]ChatMessage{{Role: "assistant", Content: check}}, "gpt-4", "action")
			if verdict == nil || verdict.Severity != "NONE" || verdict.Action != "allow" {
				t.Fatalf("control verdict changed: %+v", verdict)
			}
		})
	}
	var whole responseText
	whole.Add(answerPiece(0, "VALUE: "+card))
	check := whole.CheckText()
	verdict := inspector.Inspect(context.Background(), "completion", check,
		[]ChatMessage{{Role: "assistant", Content: check}}, "gpt-4", "action")
	if verdict == nil || verdict.Severity != "CRITICAL" || verdict.Action != "block" {
		t.Fatalf("whole card control weakened: %+v", verdict)
	}
}
