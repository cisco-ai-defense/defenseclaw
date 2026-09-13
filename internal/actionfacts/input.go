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
	"math"
	"sort"
	"strconv"
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
	policyBypass bool
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
	if exactTerminalKeystrokesTool(tool) {
		return extractExactTerminalKeystrokesArgs(raw)
	}
	if strings.EqualFold(tool, "shell") && exactEndpointProcessMetadataInput(raw) != "" {
		// Closed Sysmon process metadata may accompany an explicit shell command.
		// It contributes only an opaque lineage identity; it is not command text.
		return extractedInput{status: StatusComplete}
	}
	if usesClosedCodingAgentArgumentSchema(raw, tool) {
		return extractClosedCodingAgentArgs(raw, tool)
	}
	if tool == "secretsdump" || tool == "hashcat_crack" || tool == "kerberoast" {
		if _, ok := exactStructuredDirectoryCredentialAcquisition(Input{Tool: tool, Args: raw}); ok {
			return extractedInput{status: StatusComplete}
		}
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	if exactShellExecutionTool(tool) || usesClosedShellExecutionArgumentSchema(raw, tool) {
		return extractExactShellExecutionArgs(raw)
	}
	if strings.EqualFold(tool, "persist") {
		return extractExactPersistenceArgs(raw)
	}
	if tool == "cloud_metadata" {
		if _, _, ok := exactCloudMetadataInput(raw); ok {
			// The reviewed metadata recognizer owns this closed schema. Provider
			// paths remain private and are never projected as filesystem paths.
			return extractedInput{status: StatusComplete}
		}
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	if tool == "aws.cloudtrail_event" {
		if _, ok := exactCloudAuditSecurityOperationInput(raw); ok || exactCloudAuditResourceMutationInput(tool, raw) != nil {
			// The reviewed CloudTrail recognizer owns this closed, post-action
			// schema. Cloud values remain private and never become generic argv.
			return extractedInput{status: StatusComplete}
		}
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	if tool == "azure.activity_event" || tool == "gcp.audit_event" {
		if exactCloudAuditResourceMutationInput(tool, raw) != nil {
			return extractedInput{status: StatusComplete}
		}
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	if tool == "windows.event" {
		if _, ok := exactEndpointSecurityControlMutationInput(raw); ok {
			return extractedInput{status: StatusComplete}
		}
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	if tool == "credential_extract" {
		if _, ok := exactStructuredCredentialReadInput(raw); ok {
			return extractedInput{status: StatusComplete}
		}
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	if tool == "get_file_by_id" || tool == "send_email" ||
		tool == "append_to_file" || tool == "share_file" ||
		(tool == "delete_file" && structuredResourceMutationSchemaSelected(raw)) {
		if exactStructuredResourceArtifactInput(tool, raw) {
			// The resource/artifact lineage recognizer owns these closed schemas.
			// Identifiers and message content remain private and never become
			// generic command, path, payload, or network facts.
			return extractedInput{status: StatusComplete}
		}
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	if tool == "port_forward" {
		if _, ok := exactStructuredPortForwardInput(raw); ok {
			return extractedInput{status: StatusComplete}
		}
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	if tool == "sql_query" {
		if _, _, _, ok := exactSQLQueryArgs(raw); ok {
			// sql_query is a closed structured schema. The query remains private
			// to the reviewed SQL recognizers and is never reinterpreted as a
			// shell command or projected into CEL-visible argv.
			return extractedInput{status: StatusComplete}
		}
	}
	if strings.EqualFold(tool, "kubectl") {
		if exactKubernetesCronJobInputSchema(raw) || exactKubernetesPodRunInputSchema(raw) ||
			exactKubernetesCronJobReverseShellInputSchema(raw) {
			// The reviewed CronJob recognizer owns this closed structured
			// schema. Patch bytes remain private to it and are not projected
			// into the generic command classifier.
			return extractedInput{status: StatusComplete}
		}
		command, namespace, ok := exactStructuredKubectlInput(raw)
		if !ok {
			return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
		}
		prefix := "kubectl "
		if namespace != "" {
			prefix = "kubectl --namespace=" + namespace + " "
		}
		return extractedInput{command: prefix + command, status: StatusComplete}
	}
	if strings.EqualFold(tool, "aws_cli") {
		// aws_cli is an execution-capable schema only for the closed IAM
		// productions owned by cloud_iam_principal.go. Never feed an unrelated
		// provider command through generic command-field extraction.
		return extractExactAWSCLIArgs(raw)
	}
	return extractArgsAtSchema(raw, 0, isApplyPatchTool(tool))
}

// exactTerminalKeystrokesTool identifies the one reviewed terminal-control
// schema currently used by Terminal Wrench trajectories. Keystrokes are not a
// generic command alias: an arbitrary tool carrying the same field remains
// opaque input.
func exactTerminalKeystrokesTool(tool string) bool {
	return strings.EqualFold(tool, "bash_command")
}

// extractExactTerminalKeystrokesArgs accepts one submitted, literal POSIX
// command. A single trailing Enter is part of the envelope and is removed
// before parsing. Multi-line, compound, dynamic, redirected, piped, wrapped,
// or interactive input remains partial so it cannot mint authoritative facts.
func extractExactTerminalKeystrokesArgs(raw json.RawMessage) extractedInput {
	object, problem := exactJSONObject(raw)
	if problem.status != "" {
		return problem
	}
	value, ok := object["keystrokes"]
	if !ok {
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	keystrokes, ok := value.(string)
	if !ok || validateCommandText(keystrokes) != "" {
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	for key, metadata := range object {
		switch key {
		case "keystrokes":
		case "duration":
			number, valid := metadata.(json.Number)
			if !valid {
				return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
			}
			duration, err := strconv.ParseFloat(number.String(), 64)
			if err != nil || math.IsInf(duration, 0) || math.IsNaN(duration) || duration < 0 {
				return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
			}
		default:
			return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
		}
	}
	command := ""
	switch {
	case strings.HasSuffix(keystrokes, "\r\n"):
		command = strings.TrimSuffix(keystrokes, "\r\n")
	case strings.HasSuffix(keystrokes, "\n"):
		command = strings.TrimSuffix(keystrokes, "\n")
	default:
		// Without a literal Enter, the terminal input has not been submitted.
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	if strings.ContainsAny(command, "\r\n") || containsTerminalControlInput(command) ||
		!exactSingleStaticPOSIXCommand(command) {
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnsupportedConstruct}}
	}
	return extractedInput{command: command, status: StatusComplete}
}

func containsTerminalControlInput(source string) bool {
	for _, character := range source {
		if character == '\t' {
			continue
		}
		if character < ' ' || character == 0x7f {
			return true
		}
	}
	return false
}

func exactSingleStaticPOSIXCommand(source string) bool {
	parsed := parsePOSIX(source, 1, 0)
	classifyOutput(&parsed)
	enforceAnalyzeAuthority(&parsed)
	statusAccepted := parsed.status == StatusComplete ||
		(parsed.status == StatusPartial && len(parsed.issues) == 1 &&
			parsed.issues[0] == IssueUnknownOperandGrammar)
	if !statusAccepted || len(parsed.commands) != 1 {
		return false
	}
	command := parsed.commands[0]
	// POSIX parser internals use the zero value for process commands; the
	// public Facts clone normalizes it to CommandKindProcess.
	if command.Kind == "" {
		command.Kind = CommandKindProcess
	}
	return exactUnconditionalTopLevelCommand(command) && command.ArgvComplete &&
		staticArguments(command.Arguments)
}

func usesClosedCodingAgentArgumentSchema(raw json.RawMessage, tool string) bool {
	object, problem := exactJSONObject(raw)
	if problem.status != "" {
		return false
	}
	hasAny := func(keys ...string) bool {
		for _, key := range keys {
			if _, ok := object[key]; ok {
				return true
			}
		}
		return false
	}
	switch strings.ToLower(tool) {
	case "read":
		return hasAny("limit", "offset", "pages")
	case "edit":
		return hasAny("old_string", "new_string", "replace_all")
	case "grep", "glob":
		return hasAny("pattern")
	case "webfetch":
		return hasAny("prompt")
	case "search_code":
		return hasAny("root", "pattern", "max_results")
	case "notebookedit":
		return hasAny("notebook_path", "new_source", "edit_mode")
	default:
		return false
	}
}

// extractClosedCodingAgentArgs projects the reviewed argument contracts used
// by common coding-agent file and web tools. Pagination, presentation, and
// search selectors are validated but do not become executable content.
func extractClosedCodingAgentArgs(raw json.RawMessage, tool string) extractedInput {
	object, problem := exactJSONObject(raw)
	if problem.status != "" {
		return problem
	}
	out := extractedInput{status: StatusComplete}
	allowed := map[string]func(string, any) bool{}
	require := map[string]bool{}
	stringField := func(key string, value any) bool {
		text, ok := value.(string)
		if !ok || validateScalar(text, maxScalarBytes) != "" || strings.TrimSpace(text) == "" {
			return false
		}
		canonical := key
		if key == "file_path" || key == "root" || key == "notebook_path" {
			canonical = "path"
		}
		return appendExtractedPath(&out, canonical, text)
	}
	metadataString := func(_ string, value any) bool {
		text, ok := value.(string)
		return ok && validateScalar(text, maxScalarBytes) == ""
	}
	literalText := func(_ string, value any) bool {
		_, ok := value.(string)
		return ok
	}
	nonNegativeInteger := func(_ string, value any) bool {
		number, ok := value.(json.Number)
		if !ok || strings.ContainsAny(number.String(), ".eE") {
			return false
		}
		parsed, err := strconv.ParseInt(number.String(), 10, 64)
		return err == nil && parsed >= 0
	}
	boolean := func(_ string, value any) bool {
		_, ok := value.(bool)
		return ok
	}

	switch strings.ToLower(tool) {
	case "read":
		allowed["file_path"] = stringField
		allowed["limit"] = nonNegativeInteger
		allowed["offset"] = nonNegativeInteger
		allowed["pages"] = metadataString
		require["file_path"] = true
	case "edit":
		allowed["file_path"] = stringField
		allowed["old_string"] = literalText
		allowed["new_string"] = func(_ string, value any) bool {
			text, ok := value.(string)
			if ok {
				out.payload = append(out.payload, extractedPayload{key: "content", nonEmpty: text != ""})
			}
			return ok
		}
		allowed["replace_all"] = boolean
		require["file_path"], require["old_string"], require["new_string"] = true, true, true
	case "grep":
		allowed["pattern"] = metadataString
		allowed["path"] = stringField
		allowed["file_path"] = stringField
		for _, key := range []string{"output_mode", "glob", "type"} {
			allowed[key] = metadataString
		}
		for _, key := range []string{"context", "head_limit"} {
			allowed[key] = nonNegativeInteger
		}
		allowed["-n"], allowed["-i"] = boolean, boolean
		require["pattern"] = true
	case "glob":
		allowed["pattern"] = metadataString
		allowed["path"] = stringField
		require["pattern"] = true
	case "webfetch":
		allowed["url"] = func(_ string, value any) bool {
			text, ok := value.(string)
			return ok && appendExtractedURL(&out, text)
		}
		allowed["prompt"] = metadataString
		require["url"], require["prompt"] = true, true
	case "search_code":
		allowed["root"] = stringField
		allowed["pattern"] = metadataString
		allowed["glob"] = metadataString
		allowed["max_results"] = nonNegativeInteger
		require["root"], require["pattern"] = true, true
	case "notebookedit":
		allowed["notebook_path"] = stringField
		allowed["cell_id"] = metadataString
		allowed["cell_type"] = metadataString
		allowed["edit_mode"] = metadataString
		allowed["new_source"] = func(_ string, value any) bool {
			text, ok := value.(string)
			if ok {
				out.payload = append(out.payload, extractedPayload{key: "content", nonEmpty: text != ""})
			}
			return ok
		}
		for _, key := range []string{"notebook_path", "cell_id", "cell_type", "edit_mode", "new_source"} {
			require[key] = true
		}
	}
	for key, value := range object {
		validator, ok := allowed[key]
		if !ok || !validator(key, value) {
			return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
		}
		delete(require, key)
	}
	if len(require) != 0 {
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	return out
}

func exactJSONObject(raw json.RawMessage) (map[string]any, extractedInput) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, extractedInput{status: StatusNotApplicable}
	}
	if len(raw) > maxArgsJSONBytes {
		return nil, extractedInput{status: StatusLimitExceeded, issues: []IssueCode{IssueInputLimit}}
	}
	if !utf8.Valid(raw) {
		return nil, extractedInput{status: StatusInvalid, issues: []IssueCode{IssueInvalidUTF8}}
	}
	if issue := validateJSONWithStringLimit(raw, maxCommandBytes); issue != "" {
		return nil, extractedInput{status: statusForStructuredJSONIssue(issue), issues: []IssueCode{issue}}
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, extractedInput{status: StatusInvalid, issues: []IssueCode{IssueInvalidJSON}}
	}
	return object, extractedInput{}
}

func exactShellExecutionTool(tool string) bool {
	switch strings.ToLower(tool) {
	case "bash", "powershell":
		return true
	default:
		return false
	}
}

func usesClosedShellExecutionArgumentSchema(raw json.RawMessage, tool string) bool {
	if !strings.EqualFold(tool, "shell") {
		return false
	}
	object, problem := exactJSONObject(raw)
	if problem.status != "" {
		return false
	}
	for _, key := range []string{"description", "timeout", "run_in_background", "dangerouslyDisableSandbox"} {
		if _, ok := object[key]; ok {
			return true
		}
	}
	return false
}

// extractExactShellExecutionArgs accepts the closed argument contract used by
// common coding-agent Bash and PowerShell tools. Descriptions and timeout
// controls are metadata, not nested executable text. Unknown fields remain
// partial, and an explicit sandbox disable is retained only as a value-free
// policy-bypass bit for the command projection.
func extractExactShellExecutionArgs(raw json.RawMessage) extractedInput {
	if len(bytes.TrimSpace(raw)) == 0 {
		return extractedInput{status: StatusNotApplicable}
	}
	if len(raw) > maxArgsJSONBytes {
		return extractedInput{status: StatusLimitExceeded, issues: []IssueCode{IssueInputLimit}}
	}
	if !utf8.Valid(raw) {
		return extractedInput{status: StatusInvalid, issues: []IssueCode{IssueInvalidUTF8}}
	}
	if issue := validateJSONWithStringLimit(raw, maxCommandBytes); issue != "" {
		return extractedInput{status: statusForStructuredJSONIssue(issue), issues: []IssueCode{issue}}
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		return extractedInput{status: StatusInvalid, issues: []IssueCode{IssueInvalidJSON}}
	}
	commandValue, ok := object["command"]
	if !ok {
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	out := extractedInput{status: StatusComplete}
	switch command := commandValue.(type) {
	case string:
		if command == "" || validateCommandText(command) != "" {
			return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
		}
		out.command = command
	case []any:
		if len(command) == 0 {
			return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
		}
		out.argv = make([]string, 0, len(command))
		for _, item := range command {
			argument, valid := item.(string)
			if !valid {
				return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
			}
			out.argv = append(out.argv, argument)
		}
		if validateArgv(out.argv) != "" {
			return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
		}
	default:
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	for key, value := range object {
		switch key {
		case "command":
		case "cwd":
			cwd, valid := value.(string)
			if !valid || strings.TrimSpace(cwd) == "" || validateScalar(cwd, maxScalarBytes) != "" {
				return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
			}
			out.cwd = cwd
		case "description":
			description, valid := value.(string)
			if !valid || validateScalar(description, maxScalarBytes) != "" {
				return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
			}
		case "timeout":
			number, valid := value.(json.Number)
			if !valid {
				return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
			}
			timeout, err := strconv.ParseFloat(number.String(), 64)
			if err != nil || math.IsInf(timeout, 0) || math.IsNaN(timeout) || timeout <= 0 {
				return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
			}
		case "run_in_background":
			if _, valid := value.(bool); !valid {
				return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
			}
		case "dangerouslyDisableSandbox":
			disabled, valid := value.(bool)
			if !valid {
				return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
			}
			out.policyBypass = disabled
		default:
			return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
		}
	}
	return out
}

func statusForStructuredJSONIssue(issue IssueCode) ParseStatus {
	if issue == IssueDuplicateJSONKey {
		return StatusAmbiguous
	}
	return statusForInputIssue(issue)
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
