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
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
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
	shared := make(map[string]json.RawMessage, len(members))
	var conflicting []*toolArgumentGroup
	for _, group := range groupToolArguments(members) {
		if len(group.members) == 1 {
			shared[group.keys[0]] = group.values[0]
			continue
		}
		conflicting = append(conflicting, group)
	}
	if len(conflicting) == 0 {
		return conflictingToolArguments{}, false
	}

	// Each field is named by each of its keys with each of its values, so a
	// value is judged under the key the reviewed contract reads.
	choices := []map[string]json.RawMessage{shared}
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
	} else {
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
		choices = next
	}

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
		// ActionFacts reads command text only for one.
		if (len(analysis.Commands) > 0 && hasCommandArgument(candidate.input.Args)) ||
			slices.ContainsFunc(analysis.Paths, writeClassPathFact) {
			result.shellOrWrite = true
		}
	}
	return result, complete
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
// reads as a command (command and its aliases, or argv).
func hasCommandArgument(args json.RawMessage) bool {
	members, ok := topLevelToolArguments(args)
	if !ok {
		return false
	}
	for _, member := range members {
		switch field, _ := conflictingToolArgumentField(member.key); field {
		case "command", "argv":
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
