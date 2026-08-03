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

package actionfacts

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

type extractedInput struct {
	command      string
	argv         []string
	cwd          string
	paths        []extractedScalar
	patchChanges []patchPathChange
	patchMove    bool
	patchSet     bool
	urls         []string
	method       string
	payload      []extractedPayload
	status       ParseStatus
	issues       []IssueCode
}

type extractedScalar struct {
	key   string
	value string
}

type extractedPayload struct {
	key      string
	nonEmpty bool
}

func (out extractedInput) singlePathArgument(allowedKeys ...string) (extractedScalar, bool) {
	if out.status != StatusComplete || len(out.paths) != 1 {
		return extractedScalar{}, false
	}
	path := out.paths[0]
	for _, allowed := range allowedKeys {
		if path.key == allowed {
			return path, true
		}
	}
	return extractedScalar{}, false
}

func (out extractedInput) sourceDestinationArguments() (
	source string,
	destination string,
	ok bool,
) {
	if out.status != StatusComplete || len(out.paths) != 2 {
		return "", "", false
	}
	for _, path := range out.paths {
		switch path.key {
		case "source":
			if source != "" {
				return "", "", false
			}
			source = path.value
		case "destination":
			if destination != "" {
				return "", "", false
			}
			destination = path.value
		default:
			return "", "", false
		}
	}
	if source == "" || destination == "" {
		return "", "", false
	}
	return source, destination, true
}

const maxArgsProjectionDepth = 2

func extractArgs(raw json.RawMessage) extractedInput {
	return extractArgsAtSchema(raw, 0, false)
}

func extractArgsForTool(raw json.RawMessage, tool string) extractedInput {
	return extractArgsAtSchema(raw, 0, isApplyPatchTool(tool))
}

func extractArgsAt(raw json.RawMessage, projectionDepth int) extractedInput {
	return extractArgsAtSchema(raw, projectionDepth, false)
}

func extractArgsAtSchema(
	raw json.RawMessage,
	projectionDepth int,
	patchSchema bool,
) extractedInput {
	if projectionDepth > maxArgsProjectionDepth {
		return extractedInput{status: StatusLimitExceeded, issues: []IssueCode{IssueDepthLimit}}
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return extractedInput{status: StatusNotApplicable}
	}
	if len(raw) > maxArgsJSONBytes {
		return extractedInput{status: StatusLimitExceeded, issues: []IssueCode{IssueInputLimit}}
	}
	if !utf8.Valid(raw) {
		return extractedInput{status: StatusInvalid, issues: []IssueCode{IssueInvalidUTF8}}
	}
	stringLimit := maxCommandBytes
	if patchSchema {
		stringLimit = maxArgsJSONBytes
	}
	if issue := validateJSONWithStringLimit(raw, stringLimit); issue != "" {
		status := StatusInvalid
		if issue == IssueDuplicateJSONKey {
			status = StatusAmbiguous
		} else if issue == IssueInputLimit || issue == IssueDepthLimit {
			status = StatusLimitExceeded
		}
		return extractedInput{status: status, issues: []IssueCode{issue}}
	}

	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return extractedInput{status: StatusInvalid, issues: []IssueCode{IssueInvalidJSON}}
	}
	return extractJSONValue(value, projectionDepth, true, patchSchema)
}

func extractJSONValue(
	value any,
	projectionDepth int,
	malformedJSONIsCommand bool,
	patchSchema bool,
) extractedInput {
	switch value := value.(type) {
	case string:
		if issue := validateCommandText(value); issue != "" {
			return extractedInput{
				status: statusForInputIssue(issue),
				issues: []IssueCode{issue},
			}
		}
		trimmed := strings.TrimSpace(value)
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			if projectionDepth >= maxArgsProjectionDepth {
				return extractedInput{
					status: StatusLimitExceeded,
					issues: []IssueCode{IssueDepthLimit},
				}
			}
			nested := extractArgsAtSchema(
				json.RawMessage(trimmed),
				projectionDepth+1,
				patchSchema,
			)
			if !malformedJSONIsCommand ||
				nested.status != StatusInvalid ||
				!containsIssue(nested.issues, IssueInvalidJSON) {
				return nested
			}
		}
		return extractedInput{command: value, status: StatusComplete}
	case []any:
		argv, issue := stringArray(value)
		if issue != "" {
			status := StatusInvalid
			if issue == IssueInputLimit {
				status = StatusLimitExceeded
			}
			return extractedInput{status: status, issues: []IssueCode{issue}}
		}
		return extractedInput{argv: argv, status: StatusComplete}
	case map[string]any:
		return extractJSONObject(value, projectionDepth, patchSchema)
	case nil:
		return extractedInput{status: StatusNotApplicable}
	default:
		return extractedInput{status: StatusUnsupported, issues: []IssueCode{IssueUnsupportedConstruct}}
	}
}

func extractJSONObject(
	object map[string]any,
	projectionDepth int,
	patchSchema bool,
) extractedInput {
	out := extractedInput{status: StatusNotApplicable}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if strings.IndexByte(key, 0) >= 0 {
			out.mergeProblem(StatusInvalid, IssueInvalidSyntax)
			continue
		}
		value := object[key]
		if patchSchema && isPatchInputField(key) {
			text, ok := value.(string)
			if !ok {
				out.mergeProblem(StatusInvalid, IssueInvalidJSON)
				continue
			}
			appendExtractedPatch(&out, text)
			continue
		}
		field, known := canonicalInputFieldName(key)
		if !known {
			// ActionFacts uses closed schemas. Silently ignoring an unfamiliar
			// field could turn an action-bearing request into a false complete
			// parse and incorrectly suppress its legacy detector.
			out.mergeProblem(StatusPartial, IssueUnknownOperandGrammar)
			continue
		}
		switch field {
		case "command":
			switch value := value.(type) {
			case string:
				if issue := validateCommandText(value); issue != "" {
					out.mergeProblem(statusForInputIssue(issue), issue)
					continue
				}
				if out.command != "" && out.command != value {
					out.mergeProblem(StatusAmbiguous, IssueConflictingSources)
					continue
				}
				out.command = value
				out.markApplicable()
			case []any:
				argv, issue := stringArray(value)
				if issue != "" {
					out.mergeProblem(statusForInputIssue(issue), issue)
					continue
				}
				mergeExtractedArgv(&out, argv)
			default:
				out.mergeProblem(StatusInvalid, IssueInvalidJSON)
			}
		case "argv":
			array, ok := value.([]any)
			if !ok {
				out.mergeProblem(StatusInvalid, IssueInvalidJSON)
				continue
			}
			argv, issue := stringArray(array)
			if issue != "" {
				out.mergeProblem(statusForInputIssue(issue), issue)
				continue
			}
			mergeExtractedArgv(&out, argv)
		case "args":
			switch value := value.(type) {
			case []any:
				argv, issue := stringArray(value)
				if issue != "" {
					out.mergeProblem(statusForInputIssue(issue), issue)
					continue
				}
				mergeExtractedArgv(&out, argv)
			case string, map[string]any:
				mergeNestedExtractedValue(&out, value, projectionDepth, patchSchema)
			default:
				out.mergeProblem(StatusInvalid, IssueInvalidJSON)
			}
		case "cwd":
			text, ok := value.(string)
			if !ok {
				out.mergeProblem(StatusInvalid, IssueInvalidJSON)
				continue
			}
			if strings.TrimSpace(text) == "" {
				out.mergeProblem(StatusInvalid, IssueInvalidSyntax)
				continue
			}
			if len(text) > maxScalarBytes {
				out.mergeProblem(StatusLimitExceeded, IssueInputLimit)
				continue
			}
			if strings.IndexByte(text, 0) >= 0 {
				out.mergeProblem(StatusInvalid, IssueInvalidSyntax)
				continue
			}
			if out.cwd != "" && out.cwd != text {
				out.mergeProblem(StatusAmbiguous, IssueConflictingSources)
				continue
			}
			out.cwd = text
		case "path", "source", "destination", "target":
			if patchSchema {
				out.mergeProblem(StatusAmbiguous, IssueConflictingSources)
				continue
			}
			text, ok := value.(string)
			if !ok {
				out.mergeProblem(StatusInvalid, IssueInvalidJSON)
				continue
			}
			if strings.TrimSpace(text) == "" {
				out.mergeProblem(StatusInvalid, IssueInvalidSyntax)
				continue
			}
			if len(text) > maxScalarBytes {
				out.mergeProblem(StatusLimitExceeded, IssueInputLimit)
				continue
			}
			if strings.IndexByte(text, 0) >= 0 {
				out.mergeProblem(StatusInvalid, IssueInvalidSyntax)
				continue
			}
			if (field == "target" || field == "source" ||
				field == "destination") &&
				looksLikeHTTPURL(text) {
				if !appendExtractedURL(&out, text) {
					continue
				}
				out.markApplicable()
				continue
			}
			if appendExtractedPath(&out, field, text) {
				out.markApplicable()
			}
		case "url":
			text, ok := value.(string)
			if !ok {
				out.mergeProblem(StatusInvalid, IssueInvalidJSON)
				continue
			}
			if strings.TrimSpace(text) == "" {
				out.mergeProblem(StatusInvalid, IssueInvalidSyntax)
				continue
			}
			if len(text) > maxScalarBytes {
				out.mergeProblem(StatusLimitExceeded, IssueInputLimit)
				continue
			}
			if strings.IndexByte(text, 0) >= 0 {
				out.mergeProblem(StatusInvalid, IssueInvalidSyntax)
				continue
			}
			if appendExtractedURL(&out, text) {
				out.markApplicable()
			}
		case "method":
			text, ok := value.(string)
			if !ok || strings.TrimSpace(text) == "" ||
				strings.TrimSpace(text) != text {
				out.mergeProblem(StatusInvalid, IssueInvalidSyntax)
				continue
			}
			if len(text) > maxScalarBytes {
				out.mergeProblem(StatusLimitExceeded, IssueInputLimit)
				continue
			}
			if strings.IndexByte(text, 0) >= 0 {
				out.mergeProblem(StatusInvalid, IssueInvalidSyntax)
				continue
			}
			if out.method != "" && !strings.EqualFold(out.method, text) {
				out.mergeProblem(StatusAmbiguous, IssueConflictingSources)
				continue
			}
			out.method = text
			out.markApplicable()
		case "body", "data", "payload", "content", "headers":
			// Payload values are deliberately not retained in Facts. The JSON
			// validator has already bounded their size and depth. Retain only
			// the field kind and whether it contains outbound bytes.
			if appendExtractedPayload(
				&out,
				field,
				nonEmptyPayload(value),
			) {
				out.markApplicable()
			}
		case "nested":
			mergeNestedExtractedValue(&out, value, projectionDepth, patchSchema)
		}
	}
	return out
}

func canonicalInputFieldName(value string) (string, bool) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", false
	}
	name := strings.ToLower(value)
	switch name {
	case "command", "cmd", "script",
		"rawcommand", "raw_command", "raw-command",
		"shellcommand", "shell_command", "shell-command",
		"commandline", "command_line", "command-line":
		return "command", true
	case "argv", "commandargv", "command_argv", "command-argv":
		return "argv", true
	case "args":
		return "args", true
	case "cwd", "workdir", "work_dir", "work-dir",
		"workingdirectory", "working_directory", "working-directory":
		return "cwd", true
	case "path", "filepath", "file_path", "file-path":
		return "path", true
	case "source", "destination", "target":
		return name, true
	case "url", "uri", "endpoint":
		return "url", true
	case "method", "httpmethod", "http_method", "http-method":
		return "method", true
	case "body", "data", "payload", "content", "headers":
		return name, true
	case "input", "parameters", "request":
		return "nested", true
	default:
		return "", false
	}
}

func nonEmptyPayload(value any) bool {
	switch value := value.(type) {
	case nil:
		return false
	case string:
		return value != ""
	case []any:
		return len(value) > 0
	case map[string]any:
		return len(value) > 0
	default:
		// JSON booleans and numbers have a non-empty wire representation.
		return true
	}
}

func mergeNestedExtractedValue(
	out *extractedInput,
	value any,
	projectionDepth int,
	patchSchema bool,
) {
	if projectionDepth >= maxArgsProjectionDepth {
		out.mergeProblem(StatusLimitExceeded, IssueDepthLimit)
		return
	}
	switch value.(type) {
	case string, []any, map[string]any:
		out.merge(extractJSONValue(value, projectionDepth+1, false, patchSchema))
	default:
		out.mergeProblem(StatusInvalid, IssueInvalidJSON)
	}
}

func mergeExtractedArgv(out *extractedInput, argv []string) {
	if len(out.argv) > 0 && !equalStrings(out.argv, argv) {
		out.mergeProblem(StatusAmbiguous, IssueConflictingSources)
		return
	}
	out.argv = cloneSlice(argv)
	out.markApplicable()
}

func statusForInputIssue(issue IssueCode) ParseStatus {
	if issue == IssueInputLimit || issue == IssueDepthLimit {
		return StatusLimitExceeded
	}
	return StatusInvalid
}

func looksLikeHTTPURL(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func appendExtractedURL(out *extractedInput, value string) bool {
	if _, ok := networkURLFact(0, value, NetworkConnect); !ok {
		out.mergeProblem(StatusPartial, IssueUnknownOperandGrammar)
		return false
	}
	for _, existing := range out.urls {
		if existing == value {
			return true
		}
	}
	if len(out.urls) > 0 {
		out.mergeProblem(StatusAmbiguous, IssueConflictingSources)
		return false
	}
	out.urls = append(out.urls, value)
	return true
}

func appendExtractedPath(out *extractedInput, key, value string) bool {
	for _, existing := range out.paths {
		if existing.key != key {
			continue
		}
		if existing.value == value {
			return true
		}
		out.mergeProblem(StatusAmbiguous, IssueConflictingSources)
		return false
	}
	out.paths = append(out.paths, extractedScalar{key: key, value: value})
	return true
}

func appendExtractedPayload(
	out *extractedInput,
	key string,
	nonEmpty bool,
) bool {
	for _, existing := range out.payload {
		if existing.key != key {
			continue
		}
		// Payload bytes are intentionally not retained, so two aliases for the
		// same field cannot be proven equal after extraction.
		out.mergeProblem(StatusAmbiguous, IssueConflictingSources)
		return false
	}
	out.payload = append(out.payload, extractedPayload{
		key:      key,
		nonEmpty: nonEmpty,
	})
	return true
}

func validateJSON(raw []byte) IssueCode {
	return validateJSONWithStringLimit(raw, maxCommandBytes)
}

func validateJSONWithStringLimit(raw []byte, maxStringBytes int) IssueCode {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	members := 0
	if issue := consumeJSONValue(decoder, 0, &members, maxStringBytes); issue != "" {
		return issue
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return IssueInvalidJSON
	}
	return ""
}

func consumeJSONValue(
	decoder *json.Decoder,
	depth int,
	members *int,
	maxStringBytes int,
) IssueCode {
	if depth > maxJSONDepth {
		return IssueDepthLimit
	}
	token, err := decoder.Token()
	if err != nil {
		return IssueInvalidJSON
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return IssueInvalidJSON
				}
				key, ok := keyToken.(string)
				if !ok {
					return IssueInvalidJSON
				}
				if len(key) > maxScalarBytes {
					return IssueInputLimit
				}
				if _, exists := seen[key]; exists {
					return IssueDuplicateJSONKey
				}
				seen[key] = struct{}{}
				*members++
				if *members > maxJSONMembers {
					return IssueInputLimit
				}
				if issue := consumeJSONValue(
					decoder,
					depth+1,
					members,
					maxStringBytes,
				); issue != "" {
					return issue
				}
			}
			if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
				return IssueInvalidJSON
			}
		case '[':
			for decoder.More() {
				*members++
				if *members > maxJSONMembers {
					return IssueInputLimit
				}
				if issue := consumeJSONValue(
					decoder,
					depth+1,
					members,
					maxStringBytes,
				); issue != "" {
					return issue
				}
			}
			if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
				return IssueInvalidJSON
			}
		default:
			return IssueInvalidJSON
		}
	case string:
		if len(token) > maxStringBytes {
			return IssueInputLimit
		}
	}
	return ""
}

func stringArray(values []any) ([]string, IssueCode) {
	if len(values) == 0 || len(values) > maxArgvItems {
		if len(values) > maxArgvItems {
			return nil, IssueInputLimit
		}
		return nil, IssueInvalidJSON
	}
	argv := make([]string, len(values))
	total := 0
	for i, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, IssueInvalidJSON
		}
		if len(text) > maxScalarBytes {
			return nil, IssueInputLimit
		}
		if strings.IndexByte(text, 0) >= 0 {
			return nil, IssueInvalidSyntax
		}
		total += len(text)
		if total > maxArgvBytes {
			return nil, IssueInputLimit
		}
		argv[i] = text
	}
	return argv, ""
}

func (out *extractedInput) markApplicable() {
	if out.status == StatusNotApplicable || out.status == "" {
		out.status = StatusComplete
	}
}

func (out *extractedInput) mergeProblem(status ParseStatus, issue IssueCode) {
	out.status = mergeParseStatus(out.status, status, out.hasFacts())
	if !containsIssue(out.issues, issue) && len(out.issues) < maxIssues {
		out.issues = append(out.issues, issue)
	}
}

func (out *extractedInput) merge(other extractedInput) {
	if other.command != "" {
		if out.command != "" && out.command != other.command {
			out.mergeProblem(StatusAmbiguous, IssueConflictingSources)
		} else {
			out.command = other.command
		}
	}
	if len(other.argv) > 0 {
		if len(out.argv) > 0 && !equalStrings(out.argv, other.argv) {
			out.mergeProblem(StatusAmbiguous, IssueConflictingSources)
		} else {
			out.argv = cloneSlice(other.argv)
		}
	}
	if other.cwd != "" {
		if out.cwd != "" && out.cwd != other.cwd {
			out.mergeProblem(StatusAmbiguous, IssueConflictingSources)
		} else {
			out.cwd = other.cwd
		}
	}
	if other.patchSet {
		if out.patchSet {
			out.mergeProblem(StatusAmbiguous, IssueConflictingSources)
		} else {
			out.patchSet = true
			out.patchMove = other.patchMove
			out.patchChanges = cloneSlice(other.patchChanges)
		}
	}
	if other.method != "" {
		if out.method != "" && !strings.EqualFold(out.method, other.method) {
			out.mergeProblem(StatusAmbiguous, IssueConflictingSources)
		} else {
			out.method = other.method
		}
	}
	for _, path := range other.paths {
		appendExtractedPath(out, path.key, path.value)
	}
	for _, rawURL := range other.urls {
		appendExtractedURL(out, rawURL)
	}
	for _, payload := range other.payload {
		appendExtractedPayload(out, payload.key, payload.nonEmpty)
	}
	for _, issue := range other.issues {
		if !containsIssue(out.issues, issue) && len(out.issues) < maxIssues {
			out.issues = append(out.issues, issue)
		}
	}
	out.status = mergeParseStatus(out.status, other.status, out.hasFacts())
}

func (out extractedInput) hasFacts() bool {
	return out.command != "" || len(out.argv) > 0 || len(out.paths) > 0 ||
		len(out.patchChanges) > 0 ||
		len(out.urls) > 0 || out.method != "" || len(out.payload) > 0
}

func containsIssue(issues []IssueCode, want IssueCode) bool {
	for _, issue := range issues {
		if issue == want {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
