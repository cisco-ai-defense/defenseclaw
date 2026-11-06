// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"
	"sort"
	"strings"
)

// A file-tool call (a read, write, edit, multiedit, notebook edit, create,
// patch or search tool) whose arguments carry a key outside the tool's
// reviewed schema parses partial, as every call with an unknown key does,
// and a partial parse is never authoritative: no path rule judged the file
// the call names, so one extra key such as "description" hid a write to
// DefenseClaw's own state, a credential file or an SSH key from every rule
// in every profile (gas-ux-r1 GAP-0076; GAP-0655 had closed it for the
// authorized_keys rule only). An unknown key must never hide a known path,
// and it must not become a place to hide one either:
//
//   - The call without its unknown keys (the reduced call) is the call the
//     harness runs: its reviewed keys keep their values, the text included.
//   - Every path-shaped string the unknown keys hold (at any depth up to
//     maxUnknownKeyValueDepth) is judged as the target of the same tool:
//     the reduced call with its target replaced, or, where the reduced call
//     is not complete, the tool's reviewed shape for that target.
//   - Each target a reviewed target key names is judged the same way when
//     the reduced call is not complete (a mixed dialect, a non-string or
//     repeated target).
//
// The twins prove only which file the call reads or writes: callers count
// a rule match on them and never a non-match. Past maxUnknownKeyTargets
// candidates the call cannot be read whole (UnknownKeyTwins reports
// overflow) and callers fail closed for a write tool.

const (
	// maxUnknownKeyTargets bounds the targets one call is judged as.
	maxUnknownKeyTargets = 16
	// maxUnknownKeyValueDepth bounds the objects and arrays inside an
	// unknown key that are searched for path-shaped strings.
	maxUnknownKeyValueDepth = 4
)

// UnknownKeyTwin is one reading of a file-tool call with unknown keys: its
// arguments and their complete analysis, which names at least one path.
type UnknownKeyTwin struct {
	Args  json.RawMessage
	Facts Facts
}

// UnknownKeyTwins returns the readings of a file-tool call whose parse is
// partial only because of argument keys outside its reviewed schema, and
// whether the call holds more candidate targets than are judged
// (maxUnknownKeyTargets). It reports nothing for any other call: a
// complete, ambiguous, limit-exceeded or malformed parse, a call with
// command text or argv, or a tool that names no file.
func UnknownKeyTwins(input Input, facts Facts) ([]UnknownKeyTwin, bool) {
	// A patch tool reads a path-named key as a second source of its
	// targets (ambiguous); its harness reads only the patch.
	patch := isApplyPatchTool(input.Tool)
	if (facts.Parse.Status != StatusPartial && (!patch || facts.Parse.Status != StatusAmbiguous)) ||
		len(facts.Parse.Issues) == 0 || input.Command != "" || len(input.Argv) != 0 ||
		!unknownKeyFileTool(input.Tool) {
		return nil, false
	}
	for _, issue := range facts.Parse.Issues {
		if issue != IssueUnknownOperandGrammar && (!patch || issue != IssueConflictingSources) {
			return nil, false
		}
	}
	object, problem := exactJSONObject(input.Args)
	if problem.status != "" {
		return nil, false
	}
	reduced := make(map[string]any, len(object))
	var unknown []string
	for _, key := range slices.Sorted(maps.Keys(object)) {
		if reviewedFileToolArgumentKey(input.Tool, key) {
			reduced[key] = object[key]
		} else {
			unknown = append(unknown, key)
		}
	}

	var twins []UnknownKeyTwin
	seen := map[string]bool{}
	add := func(args map[string]any) bool {
		raw, err := json.Marshal(args)
		if err != nil || seen[string(raw)] {
			return false
		}
		seen[string(raw)] = true
		view := input
		view.Args = raw
		analyzed := Analyze(view)
		if !analyzed.Authoritative() || len(analyzed.Paths) == 0 {
			return false
		}
		twins = append(twins, UnknownKeyTwin{Args: raw, Facts: analyzed})
		return true
	}
	reducedComplete := len(unknown) != 0 && len(reduced) != 0 && add(reduced)

	var candidates []string
	collect := func(value any) {
		appendPathShapedStrings(&candidates, value, 0)
	}
	if !reducedComplete {
		// The call cannot be read in its reviewed shape: every target it
		// may name is judged, the reviewed target keys first.
		for _, key := range unknownKeyTargetKeys {
			if value, ok := object[key]; ok {
				collect(value)
			}
		}
		for _, key := range slices.Sorted(maps.Keys(reduced)) {
			if !slices.Contains(unknownKeyTargetKeys, key) && !fileToolTextKeys[key] {
				collect(reduced[key])
			}
		}
	}
	for _, key := range unknown {
		collect(object[key])
	}
	overflow := false
	if len(candidates) > maxUnknownKeyTargets {
		candidates, overflow = candidates[:maxUnknownKeyTargets], true
	}
	for _, target := range candidates {
		if reducedComplete {
			if retargeted, ok := retargetFileToolArgs(input.Tool, reduced, target); ok && add(retargeted) {
				continue
			}
		}
		add(unknownKeyFileToolShape(input.Tool, target))
	}
	return twins, overflow
}

// UnknownKeyWriteTargetViews returns the complete analyses of the readings
// of a file-tool call with unknown keys (UnknownKeyTwins) that write,
// append to or delete a path. The hook client lists their targets, so the
// gateway judges the same files the user's hook resolved.
func UnknownKeyWriteTargetViews(input Input, facts Facts) []Facts {
	twins, _ := UnknownKeyTwins(input, facts)
	var views []Facts
	for _, twin := range twins {
		if factsMutateAPath(twin.Facts) {
			views = append(views, twin.Facts)
		}
	}
	return views
}

// UnknownKeyWriteOverflow reports a write-class file-tool call with unknown
// keys that holds more candidate targets than UnknownKeyTwins judges: the
// files it may write cannot all be read, so callers fail closed.
func UnknownKeyWriteOverflow(input Input, facts Facts) bool {
	if !StructuredWriteTool(input.Tool) && !isApplyPatchTool(input.Tool) {
		return false
	}
	_, overflow := UnknownKeyTwins(input, facts)
	return overflow
}

// PathShapedArgumentValues returns the path-shaped strings an argument
// value holds, at any depth up to maxUnknownKeyValueDepth, once each, and
// whether it holds more than maxUnknownKeyTargets of them (only that many
// are returned). A connector projection that keeps only its harness's
// reviewed keys judges these values of the keys it leaves out as targets
// too, as UnknownKeyTwins does.
func PathShapedArgumentValues(raw json.RawMessage) ([]string, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return nil, false
	}
	var values []string
	appendPathShapedStrings(&values, value, 0)
	if len(values) > maxUnknownKeyTargets {
		return values[:maxUnknownKeyTargets], true
	}
	return values, false
}

// unknownKeyFileTool reports a tool whose reviewed arguments name a file:
// a path tool of lookupToolArgumentSemantics or the apply_patch envelope.
func unknownKeyFileTool(tool string) bool {
	if isApplyPatchTool(tool) {
		return true
	}
	semantics, known := lookupToolArgumentSemantics(tool)
	return known && semantics.acceptsPaths && !semantics.acceptsURLs
}

// unknownKeyTargetKeys are the reviewed keys that name a file-tool call's
// target, in the order their readings are judged.
var unknownKeyTargetKeys = []string{"filePath", "file_path", "path", "notebook_path", "root"}

// closedFileToolArgumentKeys are the keys the closed coding-agent file-tool
// schemas review (extractClosedCodingAgentArgs) and the patch fields.
var closedFileToolArgumentKeys = map[string]bool{
	"filePath": true, "file_path": true, "path": true, "notebook_path": true, "root": true,
	"content": true, "old_string": true, "new_string": true, "replace_all": true,
	"oldString": true, "newString": true, "replaceAll": true, "old_str": true, "new_str": true,
	"file_text": true, "edits": true, "new_source": true, "cell_id": true, "cell_type": true,
	"edit_mode": true, "limit": true, "offset": true, "pages": true, "pattern": true, "glob": true,
	"type": true, "output_mode": true, "context": true, "head_limit": true, "-n": true, "-i": true,
	"max_results": true, "patch": true, "patchText": true, "patch_text": true,
}

// fileToolTextKeys are the reviewed keys whose value is text the tool
// writes or matches, never a target.
var fileToolTextKeys = map[string]bool{
	"content": true, "old_string": true, "new_string": true, "oldString": true, "newString": true,
	"old_str": true, "new_str": true, "file_text": true, "new_source": true, "edits": true,
	"pattern": true, "glob": true, "patch": true, "patchText": true, "patch_text": true, "command": true,
}

// reviewedFileToolArgumentKey reports a key some reviewed schema of tool
// reads: for a patch tool its patch fields and working directory, for any
// other a closed schema's key or a generic field name
// (canonicalInputFieldName). Every other key is unknown to every schema.
func reviewedFileToolArgumentKey(tool, key string) bool {
	field, known := canonicalInputFieldName(key)
	if isApplyPatchTool(tool) {
		return isPatchInputField(key) || key == "input" || field == "cwd"
	}
	return closedFileToolArgumentKeys[key] || known
}

// appendPathShapedStrings appends every path-shaped string in value
// (pathShapedArgumentValue), searching objects and arrays to
// maxUnknownKeyValueDepth, once each, in a stable order. It stops one past
// maxUnknownKeyTargets: the caller reports the overflow.
func appendPathShapedStrings(out *[]string, value any, depth int) {
	if len(*out) > maxUnknownKeyTargets {
		return
	}
	switch value := value.(type) {
	case string:
		if pathShapedArgumentValue(value) && !slices.Contains(*out, value) {
			*out = append(*out, value)
		}
	case []any:
		if depth >= maxUnknownKeyValueDepth {
			return
		}
		for _, item := range value {
			appendPathShapedStrings(out, item, depth+1)
		}
	case map[string]any:
		if depth >= maxUnknownKeyValueDepth {
			return
		}
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			appendPathShapedStrings(out, value[key], depth+1)
		}
	}
}

// pathShapedArgumentValue reports a string that can name a file: bounded,
// on one line, not a URL, and spelled as a path (a separator, or a leading
// ~, . or variable sign). Free text such as a description has spaces and
// no such spelling, so it is not judged as a target; when it is, the
// reading names an ordinary file and no path rule matches.
func pathShapedArgumentValue(value string) bool {
	if strings.TrimSpace(value) == "" || validateScalar(value, maxScalarBytes) != "" ||
		strings.ContainsAny(value, "\r\n") || strings.Contains(value, "://") {
		return false
	}
	return strings.ContainsAny(value, `/\`) || strings.HasPrefix(value, "~") ||
		strings.HasPrefix(value, ".") || strings.HasPrefix(value, "$") || strings.HasPrefix(value, "%")
}

// retargetFileToolArgs returns the reduced arguments of a file-tool call
// with its target replaced by target: the value of its reviewed target key,
// or, for a patch tool, its patch replaced by one that adds target.
func retargetFileToolArgs(tool string, reduced map[string]any, target string) (map[string]any, bool) {
	out := make(map[string]any, len(reduced))
	for key, value := range reduced {
		out[key] = value
	}
	if isApplyPatchTool(tool) {
		for _, key := range []string{"command", "patch", "patchText", "patch_text", "input"} {
			if _, ok := out[key].(string); ok {
				out[key] = unknownKeyTargetPatch(target)
				return out, true
			}
		}
		return nil, false
	}
	for _, key := range unknownKeyTargetKeys {
		if _, ok := out[key]; ok {
			out[key] = target
			return out, true
		}
	}
	return nil, false
}

func unknownKeyTargetPatch(target string) string {
	return "*** Begin Patch\n*** Add File: " + target + "\n+x\n*** End Patch\n"
}

// unknownKeyFileToolShape is the reviewed argument object of the file tool
// for one target, with one-byte text.
func unknownKeyFileToolShape(tool, target string) map[string]any {
	if isApplyPatchTool(tool) {
		return map[string]any{"command": unknownKeyTargetPatch(target)}
	}
	switch strings.ToLower(tool) {
	case "write":
		return map[string]any{"file_path": target, "content": "x"}
	case "edit":
		return map[string]any{"file_path": target, "old_string": "x", "new_string": "x"}
	case "multiedit", "multi_edit", "multi-edit":
		return map[string]any{"file_path": target, "edits": []any{map[string]any{"old_string": "x", "new_string": "x"}}}
	case "create":
		return map[string]any{"path": target, "file_text": "x"}
	case "notebookedit":
		return map[string]any{"notebook_path": target, "new_source": "x", "cell_id": "x", "cell_type": "code", "edit_mode": "replace"}
	case "read":
		return map[string]any{"file_path": target}
	case "grep", "glob":
		return map[string]any{"pattern": "x", "path": target}
	case "search_code":
		return map[string]any{"root": target, "pattern": "x"}
	}
	if semantics, _ := lookupToolArgumentSemantics(tool); semantics.acceptsContent {
		return map[string]any{"path": target, "content": "x"}
	}
	return map[string]any{"path": target}
}
