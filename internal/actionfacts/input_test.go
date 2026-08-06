// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestExtractArgsSupportedShapes(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		command string
		argv    []string
		cwd     string
	}{
		{name: "object command", raw: `{"command":"echo ok","cwd":"/repo"}`, command: "echo ok", cwd: "/repo"},
		{name: "camel aliases", raw: `{"rawCommand":"id","workingDirectory":"/tmp"}`, command: "id", cwd: "/tmp"},
		{name: "top level string", raw: `"printf safe"`, command: "printf safe"},
		{name: "string wrapped object", raw: `"{\"cmd\":\"whoami\"}"`, command: "whoami"},
		{name: "top level argv", raw: `["cat","/etc/passwd"]`, argv: []string{"cat", "/etc/passwd"}},
		{name: "command array", raw: `{"command":["cat","/etc/passwd"]}`, argv: []string{"cat", "/etc/passwd"}},
		{name: "nested parameters", raw: `{"parameters":{"commandArgv":["rm","-rf","/tmp/x"]}}`, argv: []string{"rm", "-rf", "/tmp/x"}},
		{name: "object args wrapper", raw: `{"args":{"command":"whoami"}}`, command: "whoami"},
		{name: "string args wrapper", raw: `{"args":"{\"command\":\"id\"}"}`, command: "id"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := extractArgs(json.RawMessage(test.raw))
			if got.status != StatusComplete {
				t.Fatalf("status = %s issues=%v", got.status, got.issues)
			}
			if got.command != test.command || !equalStrings(got.argv, test.argv) || got.cwd != test.cwd {
				t.Fatalf("extracted = command:%q argv:%v cwd:%q", got.command, got.argv, got.cwd)
			}
		})
	}
}

func TestExtractArgsUsesOnlyExplicitFieldAliases(t *testing.T) {
	tests := []struct {
		name    string
		raw     json.RawMessage
		command string
		argv    []string
		cwd     string
		path    string
		method  string
	}{
		{
			name:    "snake command",
			raw:     json.RawMessage(`{"raw_command":"id"}`),
			command: "id",
		},
		{
			name:    "hyphen command",
			raw:     json.RawMessage(`{"shell-command":"id"}`),
			command: "id",
		},
		{
			name: "snake argv",
			raw:  json.RawMessage(`{"command_argv":["id"]}`),
			argv: []string{"id"},
		},
		{
			name: "hyphen argv",
			raw:  json.RawMessage(`{"command-argv":["id"]}`),
			argv: []string{"id"},
		},
		{
			name:    "snake cwd",
			raw:     json.RawMessage(`{"command":"id","working_directory":"/repo"}`),
			command: "id",
			cwd:     "/repo",
		},
		{
			name:    "hyphen cwd",
			raw:     json.RawMessage(`{"command":"id","working-directory":"/repo"}`),
			command: "id",
			cwd:     "/repo",
		},
		{
			name: "snake path",
			raw:  json.RawMessage(`{"file_path":"/tmp/input"}`),
			path: "/tmp/input",
		},
		{
			name: "hyphen path",
			raw:  json.RawMessage(`{"file-path":"/tmp/input"}`),
			path: "/tmp/input",
		},
		{
			name:   "snake method",
			raw:    json.RawMessage(`{"http_method":"POST"}`),
			method: "POST",
		},
		{
			name:   "hyphen method",
			raw:    json.RawMessage(`{"http-method":"POST"}`),
			method: "POST",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := extractArgs(test.raw)
			if got.status != StatusComplete ||
				got.command != test.command ||
				!equalStrings(got.argv, test.argv) ||
				got.cwd != test.cwd ||
				got.method != test.method {
				t.Fatalf("extracted = %#v", got)
			}
			if test.path == "" {
				if len(got.paths) != 0 {
					t.Fatalf("paths = %#v", got.paths)
				}
				return
			}
			if len(got.paths) != 1 ||
				got.paths[0].key != "path" ||
				got.paths[0].value != test.path {
				t.Fatalf("paths = %#v", got.paths)
			}
		})
	}
}

func TestExtractArgsRejectsInventedPunctuationAliasesWithoutLeakingValues(
	t *testing.T,
) {
	const private = "DO-NOT-RETAIN-UNKNOWN-VALUE"
	for _, test := range []struct {
		name string
		raw  json.RawMessage
	}{
		{name: "dotted path", raw: json.RawMessage(`{"p.a.t.h":"` + private + `"}`)},
		{name: "dashed path", raw: json.RawMessage(`{"p-a-t-h":"` + private + `"}`)},
		{name: "underscored path", raw: json.RawMessage(`{"p_a_t_h":"` + private + `"}`)},
		{name: "dotted command", raw: json.RawMessage(`{"c.o.m.m.a.n.d":"` + private + `"}`)},
		{name: "split command", raw: json.RawMessage(`{"co-mmand":"` + private + `"}`)},
		{name: "dotted URL", raw: json.RawMessage(`{"u.r.l":"https://` + private + `.example"}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			extracted := extractArgs(test.raw)
			if extracted.status != StatusPartial ||
				!containsIssue(
					extracted.issues,
					IssueUnknownOperandGrammar,
				) ||
				extracted.hasFacts() {
				t.Fatalf("unknown alias extracted facts: %#v", extracted)
			}
			for _, issue := range extracted.issues {
				if strings.Contains(string(issue), private) {
					t.Fatalf("issue leaked private input: %q", issue)
				}
			}
		})
	}
}

func TestExtractArgsSemanticAliasDuplicatesDeduplicateOrConflict(t *testing.T) {
	identical := extractArgs(json.RawMessage(
		`{"path":"/tmp/input","Path":"/tmp/input"}`,
	))
	if identical.status != StatusComplete ||
		len(identical.paths) != 1 ||
		identical.paths[0].key != "path" ||
		identical.paths[0].value != "/tmp/input" {
		t.Fatalf("identical aliases = %#v", identical)
	}

	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"path":"/tmp/one","Path":"/tmp/two"}`),
		json.RawMessage(
			`{"input":{"path":"/tmp/one"},"Input":{"path":"/tmp/two"}}`,
		),
		json.RawMessage(`{"body":"one","Body":"two"}`),
	} {
		conflicting := extractArgs(raw)
		if conflicting.status != StatusAmbiguous ||
			!containsIssue(
				conflicting.issues,
				IssueConflictingSources,
			) {
			t.Fatalf("raw=%s conflicting aliases = %#v", raw, conflicting)
		}
	}
}

func TestExtractArgsRejectsDuplicateAndConflictingSources(t *testing.T) {
	duplicate := extractArgs(json.RawMessage(`{"command":"id","command":"whoami"}`))
	if duplicate.status != StatusAmbiguous || !containsIssue(duplicate.issues, IssueDuplicateJSONKey) {
		t.Fatalf("duplicate result = status:%s issues:%v", duplicate.status, duplicate.issues)
	}

	conflict := extractArgs(json.RawMessage(`{"command":"id","rawCommand":"whoami"}`))
	if conflict.status != StatusAmbiguous || !containsIssue(conflict.issues, IssueConflictingSources) {
		t.Fatalf("conflict result = status:%s issues:%v", conflict.status, conflict.issues)
	}
}

func TestExtractArgsSchemaKeysRejectOuterWhitespace(t *testing.T) {
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{" command ":"id"}`),
		json.RawMessage(`{" path ":"/etc/shadow"}`),
		json.RawMessage(`{" url ":"https://sink.example"}`),
	} {
		extracted := extractArgs(raw)
		if extracted.status != StatusPartial ||
			!containsIssue(
				extracted.issues,
				IssueUnknownOperandGrammar,
			) ||
			extracted.command != "" ||
			len(extracted.argv) != 0 ||
			len(extracted.paths) != 0 ||
			len(extracted.urls) != 0 {
			t.Fatalf("raw=%s extracted=%#v", raw, extracted)
		}
	}
}

func TestExtractArgsURLAliasesConflictOrDeduplicate(t *testing.T) {
	conflicting := []json.RawMessage{
		json.RawMessage(
			`{"url":"https://one.example","endpoint":"https://two.example"}`,
		),
		json.RawMessage(
			`{"url":"https://one.example","request":{"uri":"https://two.example"}}`,
		),
	}
	for _, raw := range conflicting {
		extracted := extractArgs(raw)
		if extracted.status != StatusAmbiguous ||
			!containsIssue(
				extracted.issues,
				IssueConflictingSources,
			) {
			t.Fatalf("raw=%s extracted=%#v", raw, extracted)
		}
	}

	identical := extractArgs(json.RawMessage(
		`{"url":"https://same.example","endpoint":"https://same.example"}`,
	))
	if identical.status != StatusComplete ||
		len(identical.urls) != 1 ||
		identical.urls[0] != "https://same.example" {
		t.Fatalf("identical aliases = %#v", identical)
	}
}

func TestAppendExtractedURLFindsAnyExistingMatchBeforeConflict(t *testing.T) {
	extracted := extractedInput{
		status: StatusComplete,
		urls: []string{
			"https://first.example",
			"https://matching.example",
		},
	}
	if !appendExtractedURL(&extracted, "https://matching.example") ||
		extracted.status != StatusComplete ||
		containsIssue(extracted.issues, IssueConflictingSources) ||
		len(extracted.urls) != 2 {
		t.Fatalf("matching URL was treated as conflicting: %#v", extracted)
	}

	if appendExtractedURL(&extracted, "https://different.example") ||
		extracted.status != StatusAmbiguous ||
		!containsIssue(extracted.issues, IssueConflictingSources) ||
		len(extracted.urls) != 2 {
		t.Fatalf("different URL was not treated as conflicting: %#v", extracted)
	}
}

func TestExtractArgsBoundsAndTypeFailures(t *testing.T) {
	oversizedRaw := manyJSONStringValues(5, maxCommandBytes)
	if len(oversizedRaw) <= maxArgsJSONBytes ||
		validateJSON(oversizedRaw) != "" {
		t.Fatalf(
			"raw-byte-limit precondition failed: bytes=%d issue=%q",
			len(oversizedRaw),
			validateJSON(oversizedRaw),
		)
	}
	tests := []struct {
		name   string
		raw    json.RawMessage
		status ParseStatus
		issue  IssueCode
	}{
		{name: "malformed", raw: json.RawMessage(`{"command":`), status: StatusInvalid, issue: IssueInvalidJSON},
		{name: "non string argv", raw: json.RawMessage(`{"argv":["id",7]}`), status: StatusInvalid, issue: IssueInvalidJSON},
		{name: "scalar limit", raw: json.RawMessage(`{"command":"` + strings.Repeat("a", maxCommandBytes+1) + `"}`), status: StatusLimitExceeded, issue: IssueInputLimit},
		{name: "path scalar limit", raw: json.RawMessage(`{"path":"` + strings.Repeat("a", maxScalarBytes+1) + `"}`), status: StatusLimitExceeded, issue: IssueInputLimit},
		{name: "argv count", raw: manyArgvJSON(maxArgvItems + 1), status: StatusLimitExceeded, issue: IssueInputLimit},
		{name: "empty command", raw: json.RawMessage(`{"command":""}`), status: StatusInvalid, issue: IssueInvalidSyntax},
		{name: "empty path", raw: json.RawMessage(`{"path":""}`), status: StatusInvalid, issue: IssueInvalidSyntax},
		{name: "NUL command", raw: json.RawMessage(`{"command":"id\u0000safe"}`), status: StatusInvalid, issue: IssueInvalidSyntax},
		{name: "NUL argv", raw: json.RawMessage(`{"argv":["cat","/etc/shadow\u0000safe"]}`), status: StatusInvalid, issue: IssueInvalidSyntax},
		{name: "NUL CWD", raw: json.RawMessage(`{"cwd":"C:\\repo\u0000safe"}`), status: StatusInvalid, issue: IssueInvalidSyntax},
		{name: "NUL path", raw: json.RawMessage(`{"path":"/etc/shadow\u0000safe"}`), status: StatusInvalid, issue: IssueInvalidSyntax},
		{name: "NUL URL", raw: json.RawMessage(`{"url":"https://sink.example/\u0000safe"}`), status: StatusInvalid, issue: IssueInvalidSyntax},
		{name: "NUL schema key", raw: json.RawMessage(`{"comm\u0000and":"id"}`), status: StatusInvalid, issue: IssueInvalidSyntax},
		{name: "NUL nested schema key", raw: json.RawMessage(`{"parameters":{"comm\u0000and":"id"}}`), status: StatusInvalid, issue: IssueInvalidSyntax},
		{name: "wrong path type", raw: json.RawMessage(`{"path":["/etc/passwd"]}`), status: StatusInvalid, issue: IssueInvalidJSON},
		{name: "wrong args type", raw: json.RawMessage(`{"args":7}`), status: StatusInvalid, issue: IssueInvalidJSON},
		{name: "malformed URL", raw: json.RawMessage(`{"url":"https://"}`), status: StatusPartial, issue: IssueUnknownOperandGrammar},
		{
			name:   "JSON byte limit",
			raw:    oversizedRaw,
			status: StatusLimitExceeded,
			issue:  IssueInputLimit,
		},
		{
			name: "JSON structural depth",
			raw: json.RawMessage(
				strings.Repeat("[", maxJSONDepth+2) +
					"0" +
					strings.Repeat("]", maxJSONDepth+2),
			),
			status: StatusLimitExceeded,
			issue:  IssueDepthLimit,
		},
		{
			name:   "JSON member limit",
			raw:    manyJSONMembers(maxJSONMembers + 1),
			status: StatusLimitExceeded,
			issue:  IssueInputLimit,
		},
		{
			name:   "nested projection depth",
			raw:    json.RawMessage(`{"input":{"request":{"parameters":{"command":"id"}}}}`),
			status: StatusLimitExceeded,
			issue:  IssueDepthLimit,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := extractArgs(test.raw)
			if got.status != test.status || !containsIssue(got.issues, test.issue) {
				t.Fatalf("result = status:%s issues:%v", got.status, got.issues)
			}
		})
	}
}

func manyJSONStringValues(count, valueBytes int) json.RawMessage {
	var builder strings.Builder
	builder.WriteString(`{"body":[`)
	for i := 0; i < count; i++ {
		if i > 0 {
			builder.WriteByte(',')
		}
		builder.WriteByte('"')
		builder.WriteString(strings.Repeat("a", valueBytes))
		builder.WriteByte('"')
	}
	builder.WriteString(`]}`)
	return json.RawMessage(builder.String())
}

func manyJSONMembers(count int) json.RawMessage {
	var builder strings.Builder
	builder.WriteByte('{')
	for i := 0; i < count; i++ {
		if i > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(`"field`)
		builder.WriteString(strconv.Itoa(i))
		builder.WriteString(`":null`)
	}
	builder.WriteByte('}')
	return json.RawMessage(builder.String())
}

func TestExtractArgsRecursivelyDecodesBoundedJSONStrings(t *testing.T) {
	allowed := extractArgs(json.RawMessage(
		`{"input":"{\"command\":[\"cat\",\"/etc/passwd\"]}"}`,
	))
	if allowed.status != StatusComplete ||
		!equalStrings(allowed.argv, []string{"cat", "/etc/passwd"}) {
		t.Fatalf("allowed result = %#v", allowed)
	}

	tooDeep := extractArgs(json.RawMessage(
		`{"input":"{\"request\":{\"command\":\"id\"}}"}`,
	))
	if tooDeep.status != StatusLimitExceeded ||
		!containsIssue(tooDeep.issues, IssueDepthLimit) {
		t.Fatalf("too-deep result = %#v", tooDeep)
	}
}

func TestExtractArgsClassifiesHTTPSRoleAliasesAsURL(t *testing.T) {
	for _, key := range []string{"target", "source", "destination"} {
		extracted := extractArgs(json.RawMessage(
			`{"` + key + `":"https://docs.example/page"}`,
		))
		if extracted.status != StatusComplete || len(extracted.paths) != 0 ||
			len(extracted.urls) != 1 ||
			extracted.urls[0] != "https://docs.example/page" {
			t.Fatalf("%s extracted = %#v", key, extracted)
		}
	}

	filesystem := extractArgs(json.RawMessage(
		`{"path":"https://docs.example/page"}`,
	))
	if filesystem.status != StatusComplete ||
		len(filesystem.paths) != 1 ||
		filesystem.paths[0].key != "path" ||
		filesystem.paths[0].value != "https://docs.example/page" ||
		len(filesystem.urls) != 0 {
		t.Fatalf("explicit filesystem path = %#v", filesystem)
	}

	malformed := extractArgs(json.RawMessage(`{"target":"https://"}`))
	if malformed.status == StatusComplete ||
		!containsIssue(malformed.issues, IssueUnknownOperandGrammar) {
		t.Fatalf("malformed target = %#v", malformed)
	}
}

func TestExtractArgsSourcePreservesURLAndFilesystemRoles(t *testing.T) {
	remote := extractArgs(json.RawMessage(
		`{"source":"https://source.example/archive","destination":"/tmp/archive"}`,
	))
	if remote.status != StatusComplete ||
		len(remote.urls) != 1 ||
		remote.urls[0] != "https://source.example/archive" ||
		len(remote.paths) != 1 ||
		remote.paths[0].key != "destination" ||
		remote.paths[0].value != "/tmp/archive" {
		t.Fatalf("remote source = %#v", remote)
	}
	if source, destination, ok := remote.sourceDestinationArguments(); ok {
		t.Fatalf(
			"URL source became a path transfer: source=%q destination=%q",
			source,
			destination,
		)
	}

	local := extractArgs(json.RawMessage(
		`{"source":"/tmp/input","destination":"/tmp/output"}`,
	))
	source, destination, ok := local.sourceDestinationArguments()
	if !ok || source != "/tmp/input" || destination != "/tmp/output" ||
		len(local.urls) != 0 {
		t.Fatalf(
			"local transfer = source:%q destination:%q ok:%v extracted:%#v",
			source,
			destination,
			ok,
			local,
		)
	}
}

func TestExtractArgsAllowsNULInOpaquePayloadContent(t *testing.T) {
	for _, raw := range []json.RawMessage{
		json.RawMessage(
			`{"url":"https://sink.example/upload","method":"POST","body":"\u0000"}`,
		),
		json.RawMessage(
			`{"url":"https://sink.example/upload","method":"POST","body":{"\u0000":"value"}}`,
		),
		json.RawMessage(
			`{"url":"https://sink.example/upload","method":"POST","headers":{"x\u0000trace":"value"}}`,
		),
	} {
		extracted := extractArgs(raw)
		if extracted.status != StatusComplete ||
			len(extracted.payload) != 1 ||
			!extracted.payload[0].nonEmpty {
			t.Fatalf("raw=%s extracted=%#v", raw, extracted)
		}
	}
}

func TestExtractedPathSchemaHelpersPreserveRolesAndCardinality(t *testing.T) {
	input := extractArgs(json.RawMessage(`{"source":"/tmp/input"}`))
	if path, ok := input.singlePathArgument("path", "filepath", "target", "source"); !ok || path.key != "source" || path.value != "/tmp/input" {
		t.Fatalf("single input path = %#v, ok=%v", path, ok)
	}
	if _, ok := input.singlePathArgument("path", "filepath", "target", "destination"); ok {
		t.Fatal("source path matched an output-only schema")
	}

	transfer := extractArgs(json.RawMessage(
		`{"destination":"/tmp/output","source":"/tmp/input"}`,
	))
	source, destination, ok := transfer.sourceDestinationArguments()
	if !ok || source != "/tmp/input" || destination != "/tmp/output" {
		t.Fatalf(
			"source/destination = %q/%q, ok=%v, paths=%#v",
			source,
			destination,
			ok,
			transfer.paths,
		)
	}

	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"source":"/tmp/input"}`),
		json.RawMessage(`{"destination":"/tmp/output"}`),
		json.RawMessage(`{"path":"/tmp/input","destination":"/tmp/output"}`),
		json.RawMessage(
			`{"source":"/tmp/input","s-o-u-r-c-e":"/tmp/other","destination":"/tmp/output"}`,
		),
	} {
		extracted := extractArgs(raw)
		if source, destination, ok := extracted.sourceDestinationArguments(); ok {
			t.Fatalf(
				"invalid transfer schema produced %q/%q from %s",
				source,
				destination,
				raw,
			)
		}
	}
}

func manyArgvJSON(count int) json.RawMessage {
	values := make([]string, count)
	for i := range values {
		values[i] = "x"
	}
	body, _ := json.Marshal(map[string]any{"argv": values})
	return body
}
