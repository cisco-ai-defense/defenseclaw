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
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// The tool judge's context packet (S7 TASKS B): next to the call text the
// judge gets what DefenseClaw's own parser proves the call does (its
// effects and resolved targets), what this session did earlier to those
// targets, and the rules that sent the call to the judge. Without it the
// judge read vocabulary: a plain read of a key file came back as a
// Sensitive Data Access signal, a scoped rm -f as Destructive Commands and
// a local script run by path as hidden execution (Gemma 4 31B on the S7
// corpora, BENCH-gemma4.md).
//
// The packet is derived from the same untrusted call text, so every value
// in it is bounded and stripped of control characters and block tags; only
// its structure comes from the gateway.

const (
	maxJudgePacketTargets      = 12
	maxJudgePacketNetwork      = 6
	maxJudgePacketPrograms     = 8
	maxJudgePacketValueBytes   = 200
	maxJudgePacketHistoryLines = 8
	maxJudgePacketRules        = 8
	// maxJudgeTargetHistory bounds the per-session target history; the
	// oldest entries go first.
	maxJudgeTargetHistory = 128
)

// judgeTarget is one resolved path effect of a call.
type judgeTarget struct {
	access string
	path   string
}

// judgeCallEffects is the parser's account of one tool call.
type judgeCallEffects struct {
	modeled  bool   // the parser found programs, targets or network actions
	parse    string // actionfacts parse status
	complete bool   // parse complete, authoritative, no command with an uncertain effect
	programs []string
	targets  []judgeTarget
	network  []string
}

// judgeTargetSeen is what a session did to one target earlier.
type judgeTargetSeen struct {
	ordinal  int
	accesses []string
}

func toolJudgeCallEffects(ctx context.Context, toolName, args string) judgeCallEffects {
	in := actionfacts.Input{Tool: toolName, ActiveHome: hookActiveHome(ctx)}
	trimmed := strings.TrimSpace(args)
	if json.Valid([]byte(trimmed)) {
		in.Args = json.RawMessage(trimmed)
	} else {
		in.Command = trimmed
	}
	facts := actionfacts.Analyze(in)
	out := judgeCallEffects{parse: string(facts.Parse.Status)}
	if facts.Parse.Status == actionfacts.StatusNotApplicable || facts.Parse.Status == "" {
		return out
	}
	out.complete = facts.Parse.Status == actionfacts.StatusComplete && facts.Authoritative()
	seenProgram := map[string]bool{}
	for _, command := range facts.Commands {
		if command.Effect == actionfacts.EffectUncertain {
			out.complete = false
		}
		program := judgePacketValue(command.Program)
		if program == "" || seenProgram[program] || len(out.programs) >= maxJudgePacketPrograms {
			continue
		}
		seenProgram[program] = true
		out.programs = append(out.programs, program)
	}
	seenTarget := map[judgeTarget]bool{}
	for _, path := range facts.OperandPaths() {
		access := judgePacketAccess(path.Access)
		if access == "" {
			continue
		}
		value := path.Resolved
		if value == "" {
			value = path.Normalized
		}
		if value == "" {
			value = path.Value
		}
		target := judgeTarget{access: access, path: judgePacketValue(value)}
		if target.path == "" || seenTarget[target] {
			continue
		}
		if len(out.targets) >= maxJudgePacketTargets {
			out.complete = false
			break
		}
		seenTarget[target] = true
		out.targets = append(out.targets, target)
	}
	for _, network := range facts.Network {
		if len(out.network) >= maxJudgePacketNetwork {
			out.complete = false
			break
		}
		host := network.NormalizedHost
		if host == "" {
			host = network.Host
		}
		line := string(network.Action)
		if endpoint := judgePacketValue(strings.TrimSuffix(network.Scheme+"://"+host, "://")); endpoint != "" {
			line += " " + endpoint
		}
		if network.Port > 0 {
			line += fmt.Sprintf(":%d", network.Port)
		}
		if network.Scope != "" {
			line += " (" + string(network.Scope) + ")"
		}
		out.network = append(out.network, line)
	}
	// A tool the parser does not model (MCP and application tools) comes
	// back partial with no facts: the call text is all there is.
	out.modeled = len(out.programs)+len(out.targets)+len(out.network) > 0
	return out
}

// judgePacketAccess maps a parser path access to the packet's verbs; a
// metadata look is not an effect the judge needs.
func judgePacketAccess(access actionfacts.PathAccess) string {
	switch access {
	case actionfacts.PathAccessRead, actionfacts.PathAccessList, actionfacts.PathAccessWrite,
		actionfacts.PathAccessDelete, actionfacts.PathAccessExecute, actionfacts.PathAccessConnect:
		return string(access)
	case actionfacts.PathAccessAppend:
		return string(actionfacts.PathAccessWrite)
	}
	return ""
}

// judgePacketValue bounds one value taken from the call: no control
// characters (a newline would forge a packet line), no block tags.
func judgePacketValue(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, value)
	return neutralizeToolJudgeDelimiters(utf8SafePrefix(strings.TrimSpace(value), maxJudgePacketValueBytes))
}

// render writes the CALL_EFFECTS block; nothing when the parser found no
// effect to report.
func (e judgeCallEffects) render(b *strings.Builder) {
	if !e.modeled {
		return
	}
	state := "partial"
	if e.complete {
		state = "complete"
	}
	fmt.Fprintf(b, "\n<CALL_EFFECTS parse=%q coverage=%q>\n", e.parse, state)
	if len(e.programs) > 0 {
		b.WriteString("programs: " + strings.Join(e.programs, ", ") + "\n")
	}
	byAccess := map[string][]string{}
	for _, target := range e.targets {
		byAccess[target.access] = append(byAccess[target.access], target.path)
	}
	for _, access := range []string{"read", "list", "write", "delete", "execute", "connect"} {
		if paths := byAccess[access]; len(paths) > 0 {
			b.WriteString(access + ": " + strings.Join(paths, ", ") + "\n")
		}
	}
	if len(e.network) > 0 {
		b.WriteString("network: " + strings.Join(e.network, "; ") + "\n")
	} else {
		b.WriteString("network: none\n")
	}
	b.WriteString("</CALL_EFFECTS>")
}

// recordJudgeTargets renders what the session did earlier to this call's
// targets, then adds this call's effects to the session history.
func recordJudgeTargets(b *strings.Builder, history map[string]judgeTargetSeen, ordinal int, effects judgeCallEffects) {
	var lines []string
	for _, target := range effects.targets {
		if seen, ok := history[target.path]; ok && len(lines) < maxJudgePacketHistoryLines {
			lines = append(lines, fmt.Sprintf("%s: %s (call %d of this session)", target.path, strings.Join(seen.accesses, ", "), seen.ordinal))
		}
	}
	if len(lines) > 0 {
		sort.Strings(lines)
		b.WriteString("\n<TARGET_HISTORY>\n" + strings.Join(lines, "\n") + "\n</TARGET_HISTORY>")
	}
	for _, target := range effects.targets {
		seen := history[target.path]
		seen.ordinal = ordinal
		if !slices.Contains(seen.accesses, target.access) {
			seen.accesses = append(seen.accesses, target.access)
		}
		history[target.path] = seen
	}
	for len(history) > maxJudgeTargetHistory {
		oldest, oldestOrdinal := "", int(^uint(0)>>1)
		for path, seen := range history {
			if seen.ordinal < oldestOrdinal || (seen.ordinal == oldestOrdinal && path < oldest) {
				oldest, oldestOrdinal = path, seen.ordinal
			}
		}
		delete(history, oldest)
	}
}

type judgeFlaggingRulesKey struct{}

// withJudgeFlaggingRules hands the judge the rule findings that sent the
// call to it (rule id and severity; both are the gateway's own).
func withJudgeFlaggingRules(ctx context.Context, current *ToolInspectVerdict) context.Context {
	if current == nil || len(current.DetailedFindings) == 0 {
		return ctx
	}
	var rules []string
	seen := map[string]bool{}
	for _, finding := range current.DetailedFindings {
		line := judgePacketValue(finding.RuleID)
		if finding.Severity != "" {
			line += " (" + judgePacketValue(strings.ToUpper(finding.Severity)) + ")"
		}
		if line == "" || seen[line] || len(rules) >= maxJudgePacketRules {
			continue
		}
		seen[line] = true
		rules = append(rules, line)
	}
	if len(rules) == 0 {
		return ctx
	}
	return context.WithValue(ctx, judgeFlaggingRulesKey{}, rules)
}

func renderJudgeFlaggingRules(ctx context.Context, b *strings.Builder) {
	rules, _ := ctx.Value(judgeFlaggingRulesKey{}).([]string)
	if len(rules) == 0 {
		return
	}
	b.WriteString("\n<FLAGGING_RULES>\n" + strings.Join(rules, "\n") + "\n</FLAGGING_RULES>")
}

// judgeReadOnlyPrograms only read what their operands name and print to
// stdout. A program that can write, send, run another program or print the
// environment (find -exec/-delete, sort -o, tee, env, printenv, git, curl,
// any interpreter) is not here.
var judgeReadOnlyPrograms = map[string]bool{
	"cat": true, "head": true, "tail": true, "ls": true, "grep": true, "egrep": true, "fgrep": true, "rg": true,
	"wc": true, "stat": true, "file": true, "pwd": true, "tree": true, "du": true, "df": true, "nl": true,
	"realpath": true, "readlink": true, "basename": true, "dirname": true, "echo": true, "printf": true, "true": true,
}

// hookJudgeSkipsProvenReadOnly reports a tool call the rules did not flag
// and the parser proves only reads (S7 TASKS B: ask the judge about the
// calls the rules leave open, not about reads): the parse is complete and
// authoritative, every command is a read-only program (a pipe between them
// included; a file tool is decided by its typed paths), every path effect is a
// read, list or metadata look, and there is no network action. Such a
// call cannot change, run or send anything; the judge could at most ask for
// review of a read, and a later call that sends what was read still meets
// it, because the read is kept in the session history (TARGET_HISTORY).
func hookJudgeSkipsProvenReadOnly(ctx context.Context, toolName, args string, current *ToolInspectVerdict) bool {
	if rulesFlagged(current) {
		return false
	}
	in := actionfacts.Input{Tool: toolName, ActiveHome: hookActiveHome(ctx)}
	trimmed := strings.TrimSpace(args)
	if !json.Valid([]byte(trimmed)) {
		return false
	}
	in.Args = json.RawMessage(trimmed)
	facts := actionfacts.Analyze(in)
	if len(facts.Network) > 0 || !facts.Authoritative() {
		return false
	}
	fileTool := actionfacts.PathTool(toolName)
	if fileTool && len(facts.Paths) == 0 || !fileTool && len(facts.Commands) == 0 {
		return false
	}
	for _, command := range facts.Commands {
		if fileTool {
			// A file tool's typed arguments name what it touches; the path
			// effects below decide.
			break
		}
		if command.Kind != actionfacts.CommandKindProcess || command.Effect == actionfacts.EffectUncertain ||
			command.ControlFlowUncertain || !judgeReadOnlyPrograms[command.Program] {
			return false
		}
	}
	for _, path := range facts.Paths {
		switch path.Access {
		case actionfacts.PathAccessRead, actionfacts.PathAccessList, actionfacts.PathAccessMetadata:
		default:
			return false
		}
	}
	return true
}
