// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"
)

// UnknownKeyWriteTargetViews returns the write targets of a native
// file-write tool call (write, edit, multiedit or create) whose arguments
// carry keys outside the tool's reviewed schema. Such a call stays partial,
// as every call with unknown keys does. Its target key is still one of the
// reviewed ones, and the harness writes the file it names, so each target
// key the call names (filePath, file_path or path) is analyzed as the
// target of the same tool in its reviewed shape, with one-byte text. A key
// outside the schema whose value is a rooted path is read the same way
// (unknownKeyTargetKeys). Each returned view is complete and names one
// written path.
//
// A view proves only which file the call writes: callers count a rule match
// on it and never a non-match. It reports nothing for any other call: a
// complete, limit-exceeded or malformed parse, a call with command text, or
// a target that is not a bounded, non-empty string.
func UnknownKeyWriteTargetViews(input Input, facts Facts) []Facts {
	var views []Facts
	for _, reviewed := range UnknownKeyWriteTargetCalls(input, facts) {
		reduced := input
		reduced.Args = reviewed
		view := Analyze(reduced)
		if view.Authoritative() && factsWriteAPath(view) {
			views = append(views, view)
		}
	}
	return views
}

// UnknownKeyWriteTargetCalls returns, for a call UnknownKeyWriteTargetViews
// reads, the reviewed arguments of the same tool for each target the call
// names: one object per target key, with one-byte text. A caller judges each
// as the call that writes that one file.
func UnknownKeyWriteTargetCalls(input Input, facts Facts) []json.RawMessage {
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
	var calls []json.RawMessage
	for _, key := range unknownKeyTargetKeys(object) {
		target, ok := object[key].(string)
		if !ok || strings.TrimSpace(target) == "" || strings.IndexByte(target, 0) >= 0 ||
			validateScalar(target, maxScalarBytes) != "" {
			continue
		}
		reviewed, err := json.Marshal(shape(target))
		if err != nil {
			continue
		}
		calls = append(calls, reviewed)
	}
	return calls
}

// maxUnknownKeyPathTargets bounds the unreviewed keys of one call that are
// read as a path.
const maxUnknownKeyPathTargets = 8

// unknownKeyDirectoryKeys are the argument names that carry a directory to
// run in or search, not a file to write.
var unknownKeyDirectoryKeys = map[string]bool{
	"cwd": true, "workdir": true, "work_dir": true, "workingdirectory": true,
	"working_directory": true, "root": true, "directory": true, "dir": true,
	"basedir": true, "base_dir": true, "base_path": true, "basepath": true,
}

// unknownKeyTargetKeys lists the keys of a native write call that name a
// file it may write: the reviewed target keys (filePath, file_path, path)
// and, after them in key order, any other key whose string value is a
// rooted path (absolute, home, drive, UNC or device-namespace) other than
// the directory keys. The harness writes only the file its reviewed key
// names, but a key outside the schema that names a file is read as another
// target, so a call cannot carry the file it writes in a key the walk does
// not know (rel-1-0-6:GAP-0729 review 6).
func unknownKeyTargetKeys(object map[string]any) []string {
	keys := []string{"filePath", "file_path", "path"}
	var extra []string
	for key, value := range object {
		text, ok := value.(string)
		if !ok || slices.Contains(keys, key) || unknownKeyDirectoryKeys[strings.ToLower(key)] || !rootedPathText(text) {
			continue
		}
		extra = append(extra, key)
	}
	sort.Strings(extra)
	return append(keys, extra[:min(len(extra), maxUnknownKeyPathTargets)]...)
}

// rootedPathText reports text that starts as an absolute path of either
// platform: /, \\, ~/, a drive letter and a separator.
func rootedPathText(text string) bool {
	text = strings.TrimSpace(text)
	switch {
	case strings.HasPrefix(text, "/"), strings.HasPrefix(text, `\\`), strings.HasPrefix(text, "~/"), strings.HasPrefix(text, `~\`):
		return true
	}
	return len(text) >= 3 && isASCIILetter(text[0]) && text[1] == ':' && (text[2] == '\\' || text[2] == '/')
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
