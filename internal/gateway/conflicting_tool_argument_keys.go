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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const (
	// conflictingToolArgumentsRuleID is the conservative finding of a shell
	// or file-write tool call whose arguments name one field more than once.
	conflictingToolArgumentsRuleID = "TOOL-ARGS-CONFLICT"
	conflictingToolArgumentsTitle  = "Conflicting tool arguments: more than one key names the same argument, so the call cannot be verified"
	// maxConflictingToolArgumentCandidates bounds the single-key calls one
	// call is judged as.
	maxConflictingToolArgumentCandidates = 16
)

// conflictingToolArgumentSource is the argument object of a tool call as
// the call carried it, before a connector projection took arguments out of
// it (agentHookTrustedActionArgs, connector.TrustedShellArgs), and that
// projection. The conflict check reads this object, so a second key for an
// argument the projection takes out still names the same field, and every
// candidate is projected the same way before it is judged (GAP-0678).
type conflictingToolArgumentSource struct {
	raw     json.RawMessage
	project func(json.RawMessage) actionfacts.Input
}

// conflictingToolArgumentCandidate is the call with each conflicting field
// named once: raw as the tool call would carry it, input as the trusted
// action parser reads it.
type conflictingToolArgumentCandidate struct {
	input actionfacts.Input
	raw   json.RawMessage
}

// conflictingToolArguments is a tool call whose analysis is ambiguous or
// partial because more than one of its argument keys names the same field
// (GAP-0678).
type conflictingToolArguments struct {
	// candidates are the call with each such field named once, for every
	// key and value it was given.
	candidates []conflictingToolArgumentCandidate
	// shellOrWrite is set when a candidate is a complete shell or
	// file-write call.
	shellOrWrite bool
}

// toolArgument is one member of a tool call's argument object.
type toolArgument struct {
	key   string
	value json.RawMessage
}

// toolArgumentGroup is the members of an argument object that name one
// field: its distinct keys, its distinct values, and its distinct members.
type toolArgumentGroup struct {
	keys    []string
	values  []json.RawMessage
	members []toolArgument
}

// conflictingToolArgumentKeys reports a tool call whose argument object
// names one field more than once: keys equal but for letter case (command
// and Command, workdir and Workdir), two keys ActionFacts reads as the same
// field (command and cmd or script, file_path and path, cwd and workdir), or
// a reviewed key repeated with another value ({"command":"a","command":"b"};
// a JSON decoder keeps one of them, and which one depends on the runtime).
// ActionFacts folds those keys onto one field (ambiguous: conflicting
// sources or a duplicate JSON key) or, in a closed argument contract, reads
// the second key as an unknown one (partial). Such a call cannot be
// verified. The object is read as the tool call carried it, before a
// connector projection (request.conflictSource).
func conflictingToolArgumentKeys(request trustedActionRequest, facts actionfacts.Facts) (conflictingToolArguments, bool) {
	input := request.Input
	if !conflictingToolArgumentStatus(facts.Parse) || input.Command != "" || len(input.Argv) != 0 {
		return conflictingToolArguments{}, false
	}
	raw := input.Args
	project := func(args json.RawMessage) actionfacts.Input {
		candidate := input
		candidate.Args = args
		return candidate
	}
	if source := request.conflictSource; source != nil && len(source.raw) > 0 && source.project != nil {
		raw, project = source.raw, source.project
	}
	members, ok := topLevelToolArguments(raw)
	if !ok {
		return conflictingToolArguments{}, false
	}
	// A wrapper object names the call's own fields only where ActionFacts
	// reads it so for this tool; a closed shell contract reads it as an
	// unknown key.
	foldsWrappers := actionfacts.Analyze(project(json.RawMessage(`{"input":{"command":"true"}}`))).Authoritative()
	choices, conflicted, repeated := toolArgumentChoices(members, 0, foldsWrappers)
	if !conflicted && !repeated {
		return conflictingToolArguments{}, false
	}
	// Two spellings of one argument with the same value name one action:
	// each candidate is still judged, but the call is no conflict (GAP-0696).
	competing := conflicted && !toolArgumentSpellingsAgree(members)

	var result conflictingToolArguments
	complete := false
	seen := make(map[string]struct{}, len(choices))
	for _, choice := range choices {
		raw, ok := encodeToolArguments(choice)
		if !ok {
			continue
		}
		if _, duplicate := seen[string(raw)]; duplicate {
			continue
		}
		seen[string(raw)] = struct{}{}
		candidate := conflictingToolArgumentCandidate{input: project(raw), raw: raw}
		result.candidates = append(result.candidates, candidate)
		analysis := actionfacts.Analyze(candidate.input)
		if !analysis.Authoritative() {
			continue
		}
		complete = true
		// A complete analysis of a command argument is an execution tool:
		// ActionFacts reads command text only for one. Only keys or values
		// that disagree leave the call unverifiable; a key repeated with
		// the value it already has, or an unreviewed key given twice, is
		// judged as the one call it is.
		if competing && ((len(analysis.Commands) > 0 && hasCommandArgument(candidate.input.Args)) ||
			slices.ContainsFunc(analysis.Paths, writeClassPathFact)) {
			result.shellOrWrite = true
		}
	}
	if !complete && competing && toolArgumentCommandsCompete(members) &&
		(trustedBashExecutionTool(input.Tool) || trustedPowerShellExecutionTool(input.Tool)) &&
		!connector.IsShellTool(request.Connector, input.Tool) {
		// Two different commands on a shell tool, next to a key no
		// candidate's contract knows: no candidate is complete, but there
		// is still no one command to verify. A connector's own shell tool
		// takes TOOL-ARGS-UNVERIFIED for it (inspectSandboxShellToolPolicyCtx);
		// any other shell tool name was judged detection-only
		// (rel-1-0-6:GAP-0132). Each candidate is still judged.
		result.shellOrWrite = true
		return result, true
	}
	return result, complete
}

// toolArgumentCommandsCompete reports an argument object whose command keys
// (command, cmd, script, ...) hold more than one command, compared as
// toolArgumentSpellingsAgree compares values.
func toolArgumentCommandsCompete(members []toolArgument) bool {
	for _, group := range groupToolArguments(members) {
		if field, _ := conflictingToolArgumentField(group.keys[0]); field != "command" || len(group.values) < 2 {
			continue
		}
		first, ok := normalizedToolArgumentValue(group.values[0])
		for _, value := range group.values[1:] {
			next, nextOK := normalizedToolArgumentValue(value)
			if !ok || !nextOK || !bytes.Equal(first, next) {
				return true
			}
		}
	}
	return false
}

// toolArgumentSpellingsAgree reports an argument object in which every
// field named by more than one key is named with one value, compared as
// the JSON value it decodes to (command and cmd, command and Command, cwd
// and workdir, all with the same value). Whichever spelling a reader takes,
// the call is the same action, so it is judged as that call and not as a
// conflict (GAP-0696). A wrapper object (input, parameters, request, an
// args object) is never read so: its fields can cross the object's own,
// and that stays a conflict.
func toolArgumentSpellingsAgree(members []toolArgument) bool {
	for _, member := range members {
		if toolArgumentWrapper(member.key, member.value) {
			return false
		}
	}
	for _, group := range groupToolArguments(members) {
		if len(group.values) < 2 {
			continue
		}
		first, ok := normalizedToolArgumentValue(group.values[0])
		if !ok {
			return false
		}
		for _, value := range group.values[1:] {
			next, ok := normalizedToolArgumentValue(value)
			if !ok || !bytes.Equal(first, next) {
				return false
			}
		}
	}
	return true
}

// normalizedToolArgumentValue is a scalar JSON value as a reader decodes
// it, encoded one way (string escapes). An object or array keeps its
// compact form: a repeated key inside it must not fold two values into one.
func normalizedToolArgumentValue(raw json.RawMessage) ([]byte, bool) {
	if len(raw) > 0 && (raw[0] == '{' || raw[0] == '[') {
		return raw, true
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, false
	}
	return out.Bytes(), true
}

// maxNestedToolArgumentDepth bounds the wrapper objects (input, parameters,
// request) inside one another that the conflict check expands.
const maxNestedToolArgumentDepth = 4

// toolArgumentChoices is every way to name each field of an argument object
// once: each key of a field with each of its values. A wrapper object
// ActionFacts reads the fields of (input, parameters, request) is expanded
// the same way, so a field named twice inside it is judged as each of its
// candidates too. conflicted reports a field that more than one key or
// value names; repeated reports a member the object (or a wrapper in it)
// gives more than once, which ActionFacts reads as a duplicate JSON key. A
// field named both by the object's own keys and inside a wrapper in it, or
// in two wrappers, is a conflict too (splitWrappedFieldConflicts) when
// foldsWrappers says ActionFacts reads wrappers as the call's own fields.
func toolArgumentChoices(members []toolArgument, depth int, foldsWrappers bool) (choices []map[string]json.RawMessage, conflicted, repeated bool) {
	expanded := make([]toolArgument, 0, len(members))
	for _, member := range members {
		field, _ := conflictingToolArgumentField(member.key)
		if field != "nested" || depth >= maxNestedToolArgumentDepth || len(member.value) == 0 || member.value[0] != '{' {
			expanded = append(expanded, member)
			continue
		}
		nested, ok := topLevelToolArguments(member.value)
		if !ok {
			expanded = append(expanded, member)
			continue
		}
		inner, innerConflicted, innerRepeated := toolArgumentChoices(nested, depth+1, foldsWrappers)
		if !innerConflicted && !innerRepeated {
			expanded = append(expanded, member)
			continue
		}
		conflicted = conflicted || innerConflicted
		repeated = repeated || innerRepeated
		for _, choice := range inner {
			value, ok := encodeToolArguments(choice)
			if !ok {
				continue
			}
			expanded = append(expanded, toolArgument{key: member.key, value: value})
		}
	}

	groups := groupToolArguments(expanded)
	shared := make(map[string]json.RawMessage, len(expanded))
	var conflicting []*toolArgumentGroup
	kept := 0
	for _, group := range groups {
		kept += len(group.members)
		if len(group.members) == 1 {
			shared[group.keys[0]] = group.values[0]
			continue
		}
		conflicting = append(conflicting, group)
	}
	repeated = repeated || kept < len(expanded)
	conflicted = conflicted || len(conflicting) > 0

	// Each field is named by each of its keys with each of its values, so a
	// value is judged under the key the reviewed contract reads.
	choices = []map[string]json.RawMessage{shared}
	total := 1
	for _, group := range conflicting {
		total *= len(group.keys) * len(group.values)
		if total > maxConflictingToolArgumentCandidates {
			break
		}
	}
	if total <= maxConflictingToolArgumentCandidates {
		for _, group := range conflicting {
			next := make([]map[string]json.RawMessage, 0, len(choices)*len(group.keys)*len(group.values))
			for _, choice := range choices {
				for _, key := range group.keys {
					for _, value := range group.values {
						next = append(next, withArgument(choice, key, value))
					}
				}
			}
			choices = next
		}
		if !foldsWrappers {
			return choices, conflicted, repeated
		}
		choices, crossed := splitWrappedFieldConflicts(choices)
		return choices, conflicted || crossed, repeated
	}
	// Too many fields to try every pairing: each key keeps its own value.
	widest := 0
	for _, group := range conflicting {
		widest = max(widest, len(group.members))
	}
	next := make([]map[string]json.RawMessage, 0, widest)
	for index := range widest {
		choice := shared
		for _, group := range conflicting {
			member := group.members[min(index, len(group.members)-1)]
			choice = withArgument(choice, member.key, member.value)
		}
		next = append(next, choice)
	}
	if !foldsWrappers {
		return next, conflicted, repeated
	}
	next, crossed := splitWrappedFieldConflicts(next)
	return next, conflicted || crossed, repeated
}

// toolArgumentWrapper reports a member whose object value ActionFacts reads
// the fields of as the call's own (input, parameters, request, or an args
// object).
func toolArgumentWrapper(key string, value json.RawMessage) bool {
	field, _ := conflictingToolArgumentField(key)
	return (field == "nested" || field == "args") && len(value) > 0 && value[0] == '{'
}

// splitWrappedFieldConflicts judges a field a choice names in more than one
// place, with its own keys and inside a wrapper object
// ({"command":a,"input":{"command":b}}) or in two wrappers, which ActionFacts
// folds onto one field, as each of them: one choice per place, with the
// field taken out everywhere else. crossed reports such a field.
func splitWrappedFieldConflicts(choices []map[string]json.RawMessage) (out []map[string]json.RawMessage, crossed bool) {
	out = make([]map[string]json.RawMessage, 0, len(choices))
	for _, choice := range choices {
		sources := wrappedFieldSources(choice)
		var fields []string
		total := 1
		for _, field := range slices.Sorted(maps.Keys(sources)) {
			if len(sources[field]) > 1 {
				fields = append(fields, field)
				total *= len(sources[field])
			}
		}
		if len(fields) == 0 {
			out = append(out, choice)
			continue
		}
		crossed = true
		variants := []map[string]json.RawMessage{choice}
		if len(choices)*total <= maxConflictingToolArgumentCandidates {
			for _, field := range fields {
				next := make([]map[string]json.RawMessage, 0, len(variants)*len(sources[field]))
				for _, variant := range variants {
					for _, source := range sources[field] {
						next = append(next, keepToolArgumentFieldSource(variant, field, source))
					}
				}
				variants = next
			}
		} else {
			// Too many places to try every pairing: the n-th choice keeps
			// each field's n-th place.
			widest := 0
			for _, field := range fields {
				widest = max(widest, len(sources[field]))
			}
			variants = make([]map[string]json.RawMessage, 0, widest)
			for index := range widest {
				variant := choice
				for _, field := range fields {
					places := sources[field]
					variant = keepToolArgumentFieldSource(variant, field, places[min(index, len(places)-1)])
				}
				variants = append(variants, variant)
			}
		}
		out = append(out, variants...)
	}
	return out, crossed
}

// wrappedFieldSources maps each reviewed field a choice names to the places
// that name it: "" for its own keys, else each wrapper key whose object (or
// a wrapper inside it) names it.
func wrappedFieldSources(choice map[string]json.RawMessage) map[string][]string {
	sources := map[string][]string{}
	add := func(field, source string) {
		if !slices.Contains(sources[field], source) {
			sources[field] = append(sources[field], source)
		}
	}
	for _, key := range slices.Sorted(maps.Keys(choice)) {
		value := choice[key]
		if toolArgumentWrapper(key, value) {
			for _, field := range slices.Sorted(maps.Keys(wrappedToolArgumentFields(value, 0))) {
				add(field, key)
			}
			continue
		}
		if field, reviewed := conflictingToolArgumentField(key); reviewed && field != "nested" {
			add(field, "")
		}
	}
	return sources
}

// wrappedToolArgumentFields is the reviewed fields a wrapper object names,
// directly or in the wrappers inside it.
func wrappedToolArgumentFields(value json.RawMessage, depth int) map[string]struct{} {
	fields := map[string]struct{}{}
	members, ok := topLevelToolArguments(value)
	if !ok {
		return fields
	}
	for _, member := range members {
		if toolArgumentWrapper(member.key, member.value) {
			if depth < maxNestedToolArgumentDepth {
				maps.Copy(fields, wrappedToolArgumentFields(member.value, depth+1))
			}
			continue
		}
		if field, reviewed := conflictingToolArgumentField(member.key); reviewed && field != "nested" {
			fields[field] = struct{}{}
		}
	}
	return fields
}

// keepToolArgumentFieldSource is choice with field named only at source
// (wrappedFieldSources): taken out of the choice's own keys unless source
// is "", and out of every wrapper but source. A wrapper left empty goes.
func keepToolArgumentFieldSource(choice map[string]json.RawMessage, field, source string) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(choice))
	for key, value := range choice {
		if toolArgumentWrapper(key, value) {
			if key != source {
				stripped, ok := withoutWrappedToolArgumentField(value, field, 0)
				if ok && stripped == nil {
					continue
				}
				if ok {
					value = stripped
				}
			}
			out[key] = value
			continue
		}
		if name, reviewed := conflictingToolArgumentField(key); reviewed && name == field && source != "" {
			continue
		}
		out[key] = value
	}
	return out
}

// withoutWrappedToolArgumentField is a wrapper object without the keys that
// name field, in it and in the wrappers inside it; nil when nothing is
// left, and false when it cannot be read.
func withoutWrappedToolArgumentField(value json.RawMessage, field string, depth int) (json.RawMessage, bool) {
	members, ok := topLevelToolArguments(value)
	if !ok {
		return nil, false
	}
	object := make(map[string]json.RawMessage, len(members))
	for _, member := range members {
		if toolArgumentWrapper(member.key, member.value) && depth < maxNestedToolArgumentDepth {
			stripped, ok := withoutWrappedToolArgumentField(member.value, field, depth+1)
			switch {
			case !ok:
				object[member.key] = member.value
			case stripped != nil:
				object[member.key] = stripped
			}
			continue
		}
		if name, reviewed := conflictingToolArgumentField(member.key); reviewed && name == field {
			continue
		}
		object[member.key] = member.value
	}
	if len(object) == 0 {
		return nil, true
	}
	return encodeToolArguments(object)
}

// conflictingToolArgumentStatus is the analysis a second key for a field
// leaves: ambiguous (conflicting sources, a duplicate JSON key) or partial
// (a closed contract reads the second key as an unknown one). Whether the
// keys caused it is decided on the candidates.
func conflictingToolArgumentStatus(parse actionfacts.ParseResult) bool {
	return parse.Status == actionfacts.StatusAmbiguous || parse.Status == actionfacts.StatusPartial
}

// topLevelToolArguments is every member of a JSON object, in order,
// repeated keys included, with compact values.
func topLevelToolArguments(raw json.RawMessage) ([]toolArgument, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if opening, err := decoder.Token(); err != nil || opening != json.Delim('{') {
		return nil, false
	}
	var members []toolArgument
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, false
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, false
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, value); err != nil {
			return nil, false
		}
		members = append(members, toolArgument{key: key, value: compact.Bytes()})
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	return members, true
}

// groupToolArguments groups an argument object's members by the field they
// name (conflictingToolArgumentField), in order. A repeated key the field
// table does not review keeps only its last value; a member repeated with
// the same value counts once.
func groupToolArguments(members []toolArgument) []*toolArgumentGroup {
	last := make(map[string]int, len(members))
	for index, member := range members {
		last[member.key] = index
	}
	byField := make(map[string]*toolArgumentGroup, len(members))
	var groups []*toolArgumentGroup
	for index, member := range members {
		field, reviewed := conflictingToolArgumentField(member.key)
		if !reviewed && last[member.key] != index {
			continue
		}
		group := byField[field]
		if group == nil {
			group = &toolArgumentGroup{}
			byField[field] = group
			groups = append(groups, group)
		}
		if slices.ContainsFunc(group.members, func(existing toolArgument) bool {
			return existing.key == member.key && bytes.Equal(existing.value, member.value)
		}) {
			continue
		}
		group.members = append(group.members, member)
		if !slices.Contains(group.keys, member.key) {
			group.keys = append(group.keys, member.key)
		}
		if !slices.ContainsFunc(group.values, func(value json.RawMessage) bool { return bytes.Equal(value, member.value) }) {
			group.values = append(group.values, member.value)
		}
	}
	return groups
}

// hasCommandArgument reports an argument object with a key ActionFacts
// reads as a command (command and its aliases, or argv), directly or in a
// wrapper object it reads the fields of (input, parameters, request).
func hasCommandArgument(args json.RawMessage) bool {
	return hasCommandArgumentAt(args, 0)
}

func hasCommandArgumentAt(args json.RawMessage, depth int) bool {
	members, ok := topLevelToolArguments(args)
	if !ok {
		return false
	}
	for _, member := range members {
		if toolArgumentWrapper(member.key, member.value) {
			if depth < maxNestedToolArgumentDepth && hasCommandArgumentAt(member.value, depth+1) {
				return true
			}
			continue
		}
		if field, _ := conflictingToolArgumentField(member.key); field == "command" || field == "argv" {
			return true
		}
	}
	return false
}

// conflictingToolArgumentField is the field an argument key names for the
// conflict check, and whether ActionFacts reviews it. It mirrors
// actionfacts canonicalInputFieldName (keys equal but for letter case, and
// the aliases it folds onto one field), plus the edit tools' text keys. Any
// other key names its lower-case form.
func conflictingToolArgumentField(key string) (string, bool) {
	field := strings.ToLower(key)
	switch field {
	case "command", "cmd", "script",
		"rawcommand", "raw_command", "raw-command",
		"shellcommand", "shell_command", "shell-command",
		"commandline", "command_line", "command-line":
		return "command", true
	case "argv", "commandargv", "command_argv", "command-argv":
		return "argv", true
	case "cwd", "workdir", "work_dir", "work-dir",
		"workingdirectory", "working_directory", "working-directory":
		return "cwd", true
	case "path", "filepath", "file_path", "file-path":
		return "path", true
	case "url", "uri", "endpoint":
		return "url", true
	case "method", "httpmethod", "http_method", "http-method":
		return "method", true
	case "input", "parameters", "request":
		return "nested", true
	case "old_string", "oldstring", "old-string", "old_str":
		return "old_string", true
	case "new_string", "newstring", "new-string", "new_str":
		return "new_string", true
	case "replace_all", "replaceall", "replace-all":
		return "replace_all", true
	case "args", "source", "destination", "target",
		"body", "data", "payload", "content", "headers", "edits":
		return field, true
	}
	return field, false
}

// encodeToolArguments encodes a candidate argument object as a tool call
// carries it (no HTML escaping, so the text fallback reads the same text).
func encodeToolArguments(object map[string]json.RawMessage) (json.RawMessage, bool) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(object); err != nil {
		return nil, false
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), true
}

func withArgument(base map[string]json.RawMessage, key string, value json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(base)+1)
	for name, existing := range base {
		out[name] = existing
	}
	out[key] = value
	return out
}

func writeClassPathFact(path actionfacts.PathFact) bool {
	switch path.Access {
	case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete:
		return true
	}
	return false
}

// dispatchConflictingToolArguments judges a call with conflicting argument
// keys as each of its candidates, so a dangerous value under either key
// gets its own rule finding. A shell or file-write call also takes a
// conservative CRITICAL finding: the call itself cannot be verified, so it
// never falls through to allow. Like every finding, it only blocks where the
// call is enforcement-capable (observe mode records would_block).
func dispatchConflictingToolArguments(
	parent context.Context,
	request trustedActionRequest,
	conflict conflictingToolArguments,
) []RuleFinding {
	var findings []RuleFinding
	for _, candidate := range conflict.candidates {
		single := request
		single.Input = candidate.input
		single.LegacyText = string(candidate.raw)
		single.conflictSource = nil
		single.record, single.recordTelemetry = nil, nil
		findings = append(findings, dispatchTrustedAction(parent, single)...)
	}
	findings = deduplicateTrustedActionFindings(findings)
	if !conflict.shellOrWrite {
		return findings
	}
	enforcement := findingEnforcementAllowed
	if !request.EnforcementCapable {
		enforcement = findingEnforcementDetectionOnly
	}
	return append(findings, RuleFinding{
		RuleID:      conflictingToolArgumentsRuleID,
		Title:       conflictingToolArgumentsTitle,
		Severity:    "CRITICAL",
		Confidence:  1,
		Tags:        []string{"tool-arguments"},
		LineNumber:  1,
		enforcement: enforcement,
	})
}
