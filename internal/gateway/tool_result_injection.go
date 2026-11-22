// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// Structural prompt-injection checks for tool output (rel-1-0-10 GAP-0171).
//
// A tool result is data: a file, a web page, an email, an API response. What
// makes it an injection is not its words but who it talks to. Ordinary data
// addresses people ("please send me the report", "make sure to book early");
// an injection addresses the agent that reads it, about the agent's own
// instructions or role. These checks therefore pair two structures and never
// fire on a phrase alone:
//
//   - an addressee: the text calls the AI agent by role or model name, in the
//     vocative ("to you, the assistant", "dear AI", "note to the agent"; not
//     "docs for agents", which is about agents, not to one), refers to the agent's own instructions or task ("your
//     previous instructions", "the task the user gave you"), or opens a new
//     chat role inside the data (chat-template role tokens, a closing tool
//     result tag, a "system message" header);
//   - a directive aimed at that reader: a second-person modal ("you must"),
//     "please <action>", "do the following", or a clause that starts with an
//     action verb.
//
// The one exception is a directive to discard the reader's own instructions
// ("ignore your previous ..."): that clause is both parts at once, whatever
// noun ends it, misspelled or not.
//
// These checks run only on the tool_result surface. In a user prompt the user
// addresses the assistant and gives it orders by design; there the same
// structures are the normal case.

const (
	toolResultRuleDiscard   = "TOOLRESULT-DISCARD-INSTRUCTIONS"
	toolResultRuleAddressed = "TOOLRESULT-AGENT-DIRECTIVE"
	toolResultRuleRole      = "TOOLRESULT-ROLE-SWITCH"
	toolResultRuleTask      = "TOOLRESULT-TASK-DIRECTIVE"
)

// toolResultInjectionTags marks every finding of these checks; the
// prompt-injection tag is what the tool-result disposition keys on.
var toolResultInjectionTags = []string{"prompt-injection", "indirect-injection", "tool-result"}

// toolResultAI is the reader an injection names: an AI agent by role or by a
// model family name.
const toolResultAI = `(?:ai|a\.i\.|assistant|agent|llm|language\s+model|chat\s?bot|bot|model|copilot|gpt-?\d[\w.-]*|chatgpt|claude|gemini|llama|mistral)`

var (
	toolResultDiscardRe = lazyregexp.New(`(?i)\b(?:ignore|disregard|forget|override|abandon|discard)\s+(?:all\s+(?:of\s+)?)?your\s+(?:previous|prior|earlier|original|initial|above|current|existing|old)\s+[a-z]{4,}`)

	// toolResultAddresseeRe: the data names the AI agent as its reader, or
	// refers to the agent's own instructions or task.
	toolResultAddresseeRe = lazyregexp.New(`(?i)` +
		`\b(?:dear|hey|hello|hi|attention)\s*,?\s+(?:the\s+|an?\s+|this\s+|any\s+|all\s+)?` + toolResultAI + `s?\b` +
		`|\bto\s+you\s*,\s*(?:the\s+|an?\s+|my\s+)?` + toolResultAI + `\b` +
		`|\byou\s*,\s*(?:the\s+|an?\s+|my\s+)?` + toolResultAI + `\s*[,.!:]` +
		`|\b(?:note|message|instructions?|notice)\s+to\s+(?:the\s+|any\s+|all\s+)?` + toolResultAI + `s?\b` +
		`|\byour\s+(?:previous|prior|original|initial|earlier|above)\s+(?:instructions?|tasks?|prompts?|directives?|guidelines|rules|goals?|objectives?)\b` +
		`|\bthe\s+(?:task|instructions?|request)\s+(?:that\s+|which\s+)?(?:i|the\s+user|we|they|he|she)\s+(?:gave|assigned|asked|sent|set)\s+(?:to\s+)?you\b` +
		`|\b(?:before|after)\s+you\s+(?:can\s+|could\s+)?(?:solve|complete|finish|continue|proceed\s+with|answer|respond\s+to|do|start|work\s+on)\s+(?:the|your|this|that|my)\s+(?:original\s+|actual\s+|main\s+)?(?:task|request|question|job|instructions?)\b`)

	// toolResultRoleRe: a new chat role opened inside the data.
	toolResultRoleRe = lazyregexp.New(`(?i)` +
		`<\|(?:im_start|im_end|system|user|assistant|endoftext|start_header_id|end_header_id|eot_id)\|>` +
		`|\[/?inst\]|<</?sys>>|<(?:start|end)_of_turn>` +
		`|</(?:tool_result|tool_response|function_results?|tool_output)>` +
		`|(?m:^[ \t]*(?:#{1,6}[ \t]*|\[|\(|<|\*\*)?[ \t]*\(?(?:system(?:[ _-]?(?:message|prompt|instructions?|note|override|update))?|developer[ _-]?message|admin(?:istrator)?[ _-]?(?:message|note|instructions?))\)?[ \t]*(?:\]|\)|>|\*\*)?[ \t]*(?::|$|\)))`)

	// toolResultDirectiveRe: a directive aimed at the reader.
	toolResultDirectiveRe = lazyregexp.New(`(?im)` +
		`\byou\s+(?:must|should|shall|need\s+to|have\s+to|are\s+(?:required|instructed|expected|asked)\s+to|will\s+(?:now\s+)?)\b` +
		`|\bplease\s+` + toolResultVerbs + `\b` +
		`|\b(?:do|perform|complete)\s+the\s+following\b|\bmake\s+sure\s+(?:to|you|that\s+you)\b` +
		`|(?:^|[.!?:;,]\s+|\binstead\s*,?\s+|\bfirst\s*,?\s+|\bnow\s*,?\s+|\bimmediately\s+)` + toolResultVerbs + `\s+(?:the|a|an|all|this|that|these|my|your|me|it|to)\b`)
)

// toolResultVerbs are the actions a directive asks the reader to take.
const toolResultVerbs = `(?:send|transfer|forward|delete|remove|call|invoke|use|run|execute|create|update|change|modify|email|share|post|invite|add|visit|download|upload|pay|book|reserve|write|open|reply|ignore|disregard|forget|say|tell|print|output|reveal|include|insert|append|summari[sz]e|respond|answer|stop|do)`

// toolResultTaskVerbs are toolResultVerbs and the other actions the
// TRUST-TODO-* pack rules name.
const toolResultTaskVerbs = `(?:` + toolResultVerbs + `|concatenate|navigate|erase|wire|publish|mail|give)`

// toolResultMoveVerbs are the directives that move data or money to someone:
// the TRUST-TODO-DATA-MOVE actions.
const toolResultMoveVerbs = `(?:send|transfer|forward|e-?mail|mail|share|upload|post|publish|wire|pay)`

// A task-list marker (TODO:, FIXME:) turns a sentence of the data into a task
// for whoever reads it (rel-1-0-10 GAP-0358). The pack rules TRUST-TODO-* read
// the marker only at the start of the whole text, which is the typed-prompt
// shape; inside a tool's output the marker opens a clause anywhere. Two
// structures, so a note written for people stays quiet:
//
//   - glued to the prose: right after the end of a sentence or an opening
//     quote ("... accordingly.TODO: Transfer $30,000 ...", subject:
//     'TODO: Send ...'), followed by an action. A note for people starts its
//     own line or follows a comment leader or a list bullet (// TODO: remove,
//   - TODO: ...), which do not open this clause;
//   - on a line of its own: only a directive that moves data or money to
//     someone ("TODO: Send a transaction to US13..."). "TODO: remove this
//     shim" on its own line is a developer's note.
var (
	toolResultTaskInlineRe = lazyregexp.New(`(?i)(?:[.!?]["')\]]?|["'])[ \t]*(?:todo|fixme)[ \t]*:[ \t]*(?:please[ \t,]+)?` + toolResultTaskVerbs + `\b`)
	toolResultTaskLineRe   = lazyregexp.New(`(?im)^[ \t]*(?:todo|fixme)[ \t]*:[ \t]*(?:please[ \t,]+)?` + toolResultMoveVerbs + `\b`)
)

const (
	// toolResultInjectionMaxScan bounds the text the checks read; text past
	// it is a truncated input under the bound rule (bounded.Bytes).
	toolResultInjectionMaxScan = 256 << 10
	// toolResultDirectiveWindow is how far after an addressee the directive
	// may start (and a short lead before it, for "Please, assistant, ...").
	toolResultDirectiveWindow = 300
	toolResultDirectiveLead   = 80
	// toolResultMaxAnchors bounds the addressee/role matches examined; more is
	// a truncated input (bounded.Items).
	toolResultMaxAnchors = 64
)

// toolResultInjectionFindings runs the structural checks over text, the
// tool-result view (escapes decoded, confusables folded). At most one finding
// per rule. The caps it hit come back as a CapSet (ONE BOUND RULE,
// rel-1-0-10:GAP-0639): what was read before them still decides, and the
// caller adds the evaluation-limit finding, so a cut output is never a silent
// allow.
func toolResultInjectionFindings(text string) ([]RuleFinding, bounded.CapSet) {
	if strings.TrimSpace(text) == "" {
		return nil, bounded.CapSet{}
	}
	var cut bounded.Truncated
	if !cut.Within(bounded.Bytes, len(text), toolResultInjectionMaxScan) {
		text = utf8SafePrefix(text, toolResultInjectionMaxScan)
	}
	var out []RuleFinding
	if loc := toolResultDiscardRe.Regexp().FindStringIndex(text); loc != nil {
		out = append(out, toolResultFinding(toolResultRuleDiscard, "Tool output tells the agent to discard its instructions", text, loc[0], loc[1]))
	}
	if loc, ok := toolResultAnchoredDirective(&cut, toolResultAddresseeRe, text); ok {
		out = append(out, toolResultFinding(toolResultRuleAddressed, "Tool output gives the agent an instruction", text, loc[0], loc[1]))
	}
	if loc, ok := toolResultAnchoredDirective(&cut, toolResultRoleRe, text); ok {
		out = append(out, toolResultFinding(toolResultRuleRole, "Tool output opens a chat role and gives an instruction", text, loc[0], loc[1]))
	}
	if loc := toolResultTaskInlineRe.Regexp().FindStringIndex(text); loc != nil {
		out = append(out, toolResultFinding(toolResultRuleTask, "Tool output turns a task-list marker into an instruction for the agent", text, loc[0], loc[1]))
	} else if loc := toolResultTaskLineRe.Regexp().FindStringIndex(text); loc != nil {
		out = append(out, toolResultFinding(toolResultRuleTask, "Tool output turns a task-list marker into an instruction for the agent", text, loc[0], loc[1]))
	}
	return out, cut.Set()
}

// toolResultAnchoredDirective finds the first anchor match of re that a
// directive follows within the window, and returns the span from the anchor
// to the end of the directive.
func toolResultAnchoredDirective(cut *bounded.Truncated, re *lazyregexp.Regexp, text string) ([2]int, bool) {
	anchors := re.Regexp().FindAllStringIndex(text, toolResultMaxAnchors+1)
	if !cut.Within(bounded.Items, len(anchors), toolResultMaxAnchors) {
		anchors = anchors[:toolResultMaxAnchors]
	}
	directive := toolResultDirectiveRe.Regexp()
	for _, a := range anchors {
		lo := max(0, a[0]-toolResultDirectiveLead)
		hi := min(len(text), a[1]+toolResultDirectiveWindow)
		if d := directive.FindStringIndex(text[lo:hi]); d != nil {
			return [2]int{a[0], max(a[1], lo+d[1])}, true
		}
	}
	return [2]int{}, false
}

func toolResultFinding(id, title, text string, start, end int) RuleFinding {
	return RuleFinding{
		RuleID:     id,
		Title:      title,
		Severity:   "HIGH",
		Confidence: 0.8,
		Evidence:   sanitizeEvidence(text[start:min(end, start+80)]),
		Tags:       toolResultInjectionTags,
		LineNumber: lineNumberAtOffset(text, start),
	}
}
