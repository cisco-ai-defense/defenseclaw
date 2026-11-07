// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"path"
	"path/filepath"
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
// outside the schema that holds a path that can reach DefenseClaw's
// protected files is read the same way (unknownKeyTargets). Each returned
// view is complete and names one written path.
//
// A view proves only which file the call writes: callers count a rule match
// on it and never a non-match. It reports nothing for any other call: a
// complete, limit-exceeded or malformed parse, a call with command text, or
// a target that is not a bounded, non-empty string.
func UnknownKeyWriteTargetViews(input Input, facts Facts) []Facts {
	var views []Facts
	for _, call := range unknownKeyTargets(input, facts, false) {
		reduced := input
		reduced.Args = call
		view := Analyze(reduced)
		if view.Authoritative() && factsWriteAPath(view) {
			views = append(views, view)
		}
	}
	return views
}

// UnknownKeyProtectedStateCalls returns, for a call UnknownKeyWriteTargetViews
// reads, the reviewed arguments of the same tool for each target that can
// reach DefenseClaw's own state or the machine policy files it publishes
// (protectedStateReach): one object per target key, with one-byte text. A
// caller judges each as the call that writes that one file and counts its
// state-write verdict only. A call whose targets are all ordinary files
// returns nothing, so it costs no second evaluation.
func UnknownKeyProtectedStateCalls(input Input, facts Facts) []json.RawMessage {
	return unknownKeyTargets(input, facts, true)
}

// unknownKeyTargets lists the reviewed arguments of a native write call
// with keys outside the tool's schema, one per target: the reviewed target
// keys (filePath, file_path, path) and, after them in key order, any other
// key whose string value can reach protected state, except the keys that
// carry a directory, a description or the text the call writes
// (unknownKeyPayloadKey). The harness writes only the file its reviewed key
// names, but a key the walk does not know that names protected state is read
// as another target, so a call cannot carry that file in a key of its own
// choosing (rel-1-0-6:GAP-0729). With stateOnly the reviewed keys are listed
// only when they can reach protected state as well.
func unknownKeyTargets(input Input, facts Facts, stateOnly bool) []json.RawMessage {
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
	keys := []string{"filePath", "file_path", "path"}
	reviewed := len(keys)
	var extra []string
	for key, value := range object {
		if _, isText := value.(string); isText && !slices.Contains(keys, key) && !unknownKeyPayloadKey(key) {
			extra = append(extra, key)
		}
	}
	sort.Strings(extra)
	reach := protectedStateReach{cwd: input.CWD, linked: map[string]bool{}}
	seen := map[string]bool{}
	var calls []json.RawMessage
	for i, key := range append(keys, extra...) {
		target, ok := object[key].(string)
		if !ok || strings.TrimSpace(target) == "" || strings.IndexByte(target, 0) >= 0 ||
			validateScalar(target, maxScalarBytes) != "" || seen[target] {
			continue
		}
		// A relative path of another key is read from the working directory.
		resolved := reach.absolute(target)
		if (stateOnly || i >= reviewed) && !reach.mayReach(resolved) {
			continue
		}
		seen[target] = true
		if i >= reviewed {
			target = resolved
		}
		call, err := json.Marshal(shape(target))
		if err != nil {
			continue
		}
		calls = append(calls, call)
	}
	return calls
}

// unknownKeyPayloadKey reports an argument name that carries a directory to
// run in or search, a description, or the text a call writes or looks for,
// none of which is a file the harness writes: a file whose text, or whose
// description, mentions a path is an ordinary write.
func unknownKeyPayloadKey(key string) bool {
	name := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(key))
	return unknownKeyPayloadNames[name]
}

var unknownKeyPayloadNames = map[string]bool{
	// directories
	"cwd": true, "workdir": true, "workingdirectory": true, "root": true, "directory": true,
	"dir": true, "basedir": true, "basepath": true,
	// descriptions
	"description": true, "desc": true, "note": true, "notes": true, "comment": true, "comments": true,
	"title": true, "summary": true, "message": true, "msg": true, "reason": true, "label": true,
	"explanation": true, "rationale": true, "instructions": true, "instruction": true,
	"prompt": true, "purpose": true,
	// written or searched text
	"content": true, "contents": true, "text": true, "filetext": true, "newstring": true,
	"oldstring": true, "newstr": true, "oldstr": true, "data": true, "body": true, "patch": true,
	"diff": true, "query": true, "pattern": true, "replacement": true,
}

// protectedStateReach decides, from the text of a path and a bounded look
// at the links on it, whether a native write call's target can reach
// DefenseClaw's state tree or a machine policy file of an agent. It keeps an
// ordinary file from costing a second evaluation.
type protectedStateReach struct {
	cwd    string
	linked map[string]bool
}

// mayReach reports a target whose spelling names the state tree
// (defenseclaw, in any case or separator, through ~, $HOME or %USERPROFILE%),
// a machine policy directory (Windows administrative shares and 8.3 names
// included), a tilde-prefix or 8.3 name that can spell either, a relative
// path under a directory that does, or a path with a link on it that may
// lead there.
func (r *protectedStateReach) mayReach(text string) bool {
	slashed := strings.ReplaceAll(text, `\`, "/")
	lower := strings.ToLower(slashed)
	if strings.Contains(lower, "defenseclaw") || strings.Contains(strings.TrimPrefix(lower, "~/"), "~") ||
		ManagedAgentSettingsPath(path.Clean(slashed)) || WindowsManagedAgentSettingsPath(text) {
		return true
	}
	return strings.HasPrefix(slashed, "/") && r.linkOnPath(path.Clean(slashed))
}

// absolute joins a relative path to the working directory, with the
// separator of the directory's own syntax.
func (r *protectedStateReach) absolute(target string) string {
	text := strings.TrimSpace(target)
	if rootedPathText(text) || strings.HasPrefix(text, "~") || r.cwd == "" {
		return text
	}
	if rootedPathText(r.cwd) && !strings.HasPrefix(r.cwd, "/") {
		return strings.TrimRight(r.cwd, `/\`) + `\` + text
	}
	return strings.TrimRight(r.cwd, "/") + "/" + text
}

// linkOnPath reports a link on the path, or on the nearest part of it that
// exists, once per directory of a call.
func (r *protectedStateReach) linkOnPath(clean string) bool {
	for current := clean; ; current = path.Dir(current) {
		if linked, seen := r.linked[current]; seen {
			return linked
		}
		if real, err := filepath.EvalSymlinks(current); err == nil {
			r.linked[current] = real != current
			return r.linked[current]
		}
		if current == "/" || current == "." {
			return false
		}
	}
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
