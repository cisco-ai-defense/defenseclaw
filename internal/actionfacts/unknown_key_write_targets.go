// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
)

// UnknownKeyWriteTargetViews returns the write targets of a native
// file-write tool call (write, edit, multiedit or create) whose arguments
// carry keys outside the tool's reviewed schema. Such a call stays partial,
// as every call with unknown keys does. Its target key is still one of the
// reviewed ones, and the harness writes the file it names, so each target
// key the call names (filePath, file_path or path) is analyzed as the
// target of the same tool in its reviewed shape, with one-byte text. Each
// returned view is complete and names one written path.
//
// A view proves only which file the call writes: callers count a rule match
// on it and never a non-match. It reports nothing for any other call: a
// complete, limit-exceeded or malformed parse, a call with command text, or
// a target that is not a bounded, non-empty string.
func UnknownKeyWriteTargetViews(input Input, facts Facts) []Facts {
	if facts.Parse.Status != StatusPartial || len(facts.Parse.Issues) == 0 ||
		input.Command != "" || len(input.Argv) != 0 {
		return nil
	}
	for _, issue := range facts.Parse.Issues {
		if issue != IssueUnknownOperandGrammar {
			return nil
		}
	}
	shape, ok := unknownKeyWriteToolShape(input.Tool)
	if !ok {
		return nil
	}
	object, problem := exactJSONObject(input.Args)
	if problem.status != "" {
		return nil
	}
	var views []Facts
	for _, key := range []string{"filePath", "file_path", "path"} {
		target, ok := object[key].(string)
		if !ok || strings.TrimSpace(target) == "" || strings.IndexByte(target, 0) >= 0 ||
			validateScalar(target, maxScalarBytes) != "" {
			continue
		}
		reviewed, err := json.Marshal(shape(target))
		if err != nil {
			continue
		}
		reduced := input
		reduced.Args = reviewed
		view := Analyze(reduced)
		if view.Authoritative() && factsWriteAPath(view) {
			views = append(views, view)
		}
	}
	return views
}

// unknownKeyWriteToolShape is the reviewed argument object of a write-class
// native tool for one target.
func unknownKeyWriteToolShape(tool string) (func(string) map[string]any, bool) {
	switch strings.ToLower(tool) {
	case "write":
		return func(target string) map[string]any {
			return map[string]any{"file_path": target, "content": "x"}
		}, true
	case "edit":
		return func(target string) map[string]any {
			return map[string]any{"file_path": target, "old_string": "x", "new_string": "x"}
		}, true
	case "multiedit", "multi_edit", "multi-edit":
		return func(target string) map[string]any {
			return map[string]any{"file_path": target, "edits": []any{map[string]any{"old_string": "x", "new_string": "x"}}}
		}, true
	case "create":
		return func(target string) map[string]any {
			return map[string]any{"path": target, "file_text": "x"}
		}, true
	default:
		return nil, false
	}
}

func factsWriteAPath(facts Facts) bool {
	for _, path := range facts.Paths {
		if path.Access == PathAccessWrite || path.Access == PathAccessAppend {
			return true
		}
	}
	return false
}
