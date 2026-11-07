// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"maps"
	"path"
	"slices"
	"sort"
	"strings"
)

// A file-tool call (a read, write, edit, multiedit, notebook edit, create,
// patch or search tool) whose arguments carry a key outside the tool's
// reviewed schema can lose authority or be parsed as a different kind of
// call by the generic parser. Then no path rule judges the file the tool
// handles, so one extra key hid a write to
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
// candidates or past the nesting bound, the remaining target is Possible
// grade. Named readings still win.

const (
	// maxUnknownKeyTargets bounds the targets one call is judged as.
	maxUnknownKeyTargets = 16
	// maxUnknownKeyValueDepth bounds the objects and arrays inside an
	// unknown key that are searched for path-shaped strings.
	maxUnknownKeyValueDepth = 4
)

// UnknownKeyTwin is one additive reading of a file-tool call with extra keys.
type UnknownKeyTwin struct {
	Args  json.RawMessage
	Facts Facts
}

// UnknownKeyTwins returns the reviewed and alternate readings of a file-tool
// call with extra argument keys, plus whether the target count or depth
// bound was exceeded. The full parse status does not gate these readings.
func UnknownKeyTwins(input Input, facts Facts) ([]UnknownKeyTwin, bool) {
	_ = facts
	if input.Command != "" || len(input.Argv) != 0 || !unknownKeyFileTool(input.Tool) ||
		len(input.Args) == 0 {
		return nil, false
	}
	// Most file calls have only their tool's reviewed keys. Check those keys
	// before the bounded value parser, which otherwise scans the JSON again
	// even though no alternate reading can exist. A patch envelope needs its
	// values to select the reviewed field, so it takes the full path below.
	if !isApplyPatchTool(input.Tool) {
		var rawFields map[string]json.RawMessage
		if json.Unmarshal(input.Args, &rawFields) == nil && rawFields != nil {
			keys := make(map[string]any, len(rawFields))
			for key := range rawFields {
				keys[key] = nil
			}
			onlyReviewed := true
			for key := range rawFields {
				if !reviewedFileToolArgumentKey(input.Tool, key, keys) {
					onlyReviewed = false
					break
				}
			}
			if onlyReviewed {
				return nil, false
			}
		}
	}
	if validateJSONWithStringLimit(input.Args, len(input.Args)) != "" {
		return nil, false
	}
	// An oversized extra value does not make the reviewed target disappear.
	decoder := json.NewDecoder(bytes.NewReader(input.Args))
	decoder.UseNumber()
	var object map[string]any
	if decoder.Decode(&object) != nil || object == nil {
		return nil, false
	}
	reduced := make(map[string]any, len(object))
	var unknown []string
	for _, key := range slices.Sorted(maps.Keys(object)) {
		if reviewedFileToolArgumentKey(input.Tool, key, object) {
			reduced[key] = object[key]
		} else {
			unknown = append(unknown, key)
		}
	}

	if len(unknown) == 0 {
		return nil, false
	}
	// A large reviewed payload remains the existing over-limit case. The
	// extra field may be large; only the reduced call must fit the parser.
	reducedRaw, err := json.Marshal(reduced)
	if err != nil || len(reducedRaw) > maxArgsJSONBytes || validateJSONWithStringLimit(reducedRaw, maxCommandBytes) != "" {
		return nil, false
	}
	var twins []UnknownKeyTwin
	seen := map[string]bool{}
	add := func(args map[string]any) bool {
		raw, err := json.Marshal(args)
		if err != nil {
			return false
		}
		if complete, exists := seen[string(raw)]; exists {
			return complete
		}
		view := input
		view.Args = raw
		analyzed := Analyze(view)
		complete := analyzed.Authoritative() && len(analyzed.Paths) > 0
		seen[string(raw)] = complete
		twins = append(twins, UnknownKeyTwin{Args: raw, Facts: analyzed})
		return complete
	}
	reducedComplete := len(reduced) != 0 && add(reduced)
	if reducedComplete && !isApplyPatchTool(input.Tool) {
		for _, key := range unknownKeyTargetKeys {
			if raw, ok := reduced[key].(string); ok {
				if target := KnownExtraKeyPath(raw, input.ActiveHome); target != raw {
					placed := maps.Clone(reduced)
					placed[key] = target
					add(placed)
				}
			}
		}
	}

	var candidates []string
	overflow := false
	collect := func(value any) {
		appendPathShapedStrings(&candidates, value, 0, &overflow)
	}
	// More than one target field can be two dialect readings. Keep every
	// named value regardless of which field the reduction selected.
	targetFields := 0
	for _, key := range unknownKeyTargetKeys {
		if _, ok := object[key]; ok {
			targetFields++
		}
	}
	if targetFields > 1 {
		for _, key := range unknownKeyTargetKeys {
			if value, ok := object[key].(string); ok {
				collect(value)
			}
		}
	}
	if !reducedComplete {
		// The call cannot be read in its reviewed shape: every target it
		// may name is judged, the reviewed target keys first.
		for _, key := range unknownKeyTargetKeys {
			if value, ok := object[key].(string); ok {
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
		if _, isString := object[key].(string); isString && DescriptiveArgumentKey(key) {
			continue
		}
		collect(object[key])
	}
	if len(candidates) > maxUnknownKeyTargets {
		candidates, overflow = candidates[:maxUnknownKeyTargets], true
	}
	for _, target := range candidates {
		target = KnownExtraKeyPath(target, input.ActiveHome)
		if reducedComplete {
			if retargeted, ok := retargetFileToolArgs(input.Tool, reduced, target); ok && add(retargeted) {
				continue
			}
		}
		add(unknownKeyFileToolShape(input.Tool, target))
	}
	return twins, overflow
}

// Values in extra keys use the same known home as the reviewed call. In
// particular, patch envelopes do not expand shell spelling by themselves.
func KnownExtraKeyPath(target, home string) string {
	if home == "" {
		return target
	}
	for _, prefix := range []string{"~/", "$HOME/", "${HOME}/"} {
		if strings.HasPrefix(target, prefix) {
			// Agent paths use the connector dialect, not the gateway host:
			// ActiveHome is a slash path (/home/u) or a drive path (C:\Users\u),
			// and both join with slashes. filepath.Join turned "/sandbox" into
			// \sandbox on a Windows gateway, which then resolved under the cwd.
			if normalized, ok := normalizeActiveHome(home); ok {
				home = normalized
			}
			rest := strings.TrimPrefix(target, prefix)
			if strings.HasPrefix(home, "//") { // a UNC home keeps its leading slashes
				return strings.TrimRight(home, "/") + "/" + rest
			}
			return path.Join(home, rest)
		}
	}
	return target
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
// files it may write cannot all be read. The gateway grades this Possible.
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
	overflow := false
	appendPathShapedStrings(&values, value, 0, &overflow)
	if len(values) > maxUnknownKeyTargets {
		return values[:maxUnknownKeyTargets], true
	}
	return values, overflow
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

// reviewedFileToolArgumentKey follows the file tool's own argument contract.
// A generic parser field such as cwd, command or input is not thereby a
// reviewed field of Write, Edit or Read.
func reviewedFileToolArgumentKey(tool, key string, object map[string]any) bool {
	if isApplyPatchTool(tool) {
		for _, candidate := range []string{"patchText", "patch_text", "patch", "command", "input"} {
			if _, ok := object[candidate]; ok && (isPatchInputField(candidate) || isPatchEnvelopeField(candidate, object[candidate])) {
				return key == candidate
			}
		}
		return false
	}
	pathKey := ""
	for _, candidate := range []string{"file_path", "filePath", "path"} {
		if _, ok := object[candidate]; ok {
			pathKey = candidate
			break
		}
	}
	switch strings.ToLower(tool) {
	case "read", "readfile", "read_file", "read-file":
		return key == pathKey || slices.Contains([]string{"limit", "offset", "pages"}, key)
	case "write", "writefile", "write_file", "write-file", "fs_write", "fs.write_file", "fs.write":
		return key == pathKey || key == "content" || key == "file_text"
	case "edit", "editfile", "edit_file", "edit-file":
		edit := codingAgentEditDialect(object)
		if strings.EqualFold(tool, "edit") {
			return key == edit.path || key == edit.old || key == edit.new || key == edit.all
		}
		return key == pathKey || slices.Contains([]string{"old_string", "new_string", "replace_all", "oldString", "newString", "replaceAll", "old_str", "new_str"}, key)
	case "multiedit", "multi_edit", "multi-edit":
		return key == pathKey || key == "edits"
	case "notebookedit", "notebook_edit", "notebook-edit":
		return slices.Contains([]string{"notebook_path", "new_source", "cell_id", "cell_type", "edit_mode"}, key)
	case "create", "createfile", "create_file", "create-file":
		return key == pathKey || key == "file_text" || key == "content"
	case "grep", "glob", "search_code":
		return closedFileToolArgumentKeys[key]
	default:
		return slices.Contains(unknownKeyTargetKeys, key) || fileToolTextKeys[key]
	}
}

// appendPathShapedStrings appends every path-shaped string in value
// (pathShapedArgumentValue), searching objects and arrays to
// maxUnknownKeyValueDepth, once each, in a stable order. It stops one past
// maxUnknownKeyTargets: the caller reports the overflow.
func appendPathShapedStrings(out *[]string, value any, depth int, overflow *bool) {
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
			if len(value) > 0 {
				*overflow = true
			}
			return
		}
		for _, item := range value {
			appendPathShapedStrings(out, item, depth+1, overflow)
		}
	case map[string]any:
		if depth >= maxUnknownKeyValueDepth {
			if len(value) > 0 {
				*overflow = true
			}
			return
		}
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if _, isString := value[key].(string); isString && DescriptiveArgumentKey(key) {
				continue
			}
			appendPathShapedStrings(out, value[key], depth+1, overflow)
		}
	}
}

// descriptiveKeyWords are the words of an argument key that names prose
// about the call: what it is for, a note or a comment. The harness reads
// such a key as text, never as a place to write.
var descriptiveKeyWords = map[string]bool{
	"description": true, "desc": true, "descr": true, "note": true, "notes": true,
	"detail": true, "details": true, "annotation": true, "annotations": true,
	"comment": true, "comments": true, "context": true, "info": true, "information": true,
	"reason": true, "rationale": true, "summary": true, "explanation": true, "title": true,
	"label": true, "purpose": true, "message": true, "msg": true, "remark": true,
	"remarks": true, "memo": true, "hint": true, "caption": true, "justification": true,
	"intent": true, "doc": true, "docs": true, "documentation": true,
}

// targetKeyWords are the words that make a key a place a tool can write or
// read, whatever else the key says: description_file or note_path is judged
// as a target.
var targetKeyWords = map[string]bool{
	"path": true, "paths": true, "file": true, "files": true, "filename": true, "filepath": true,
	"dir": true, "dirs": true, "directory": true, "folder": true, "target": true, "targets": true,
	"dest": true, "destination": true, "destinations": true, "output": true, "out": true,
	"to": true, "into": true, "location": true, "uri": true, "url": true, "root": true,
	"cwd": true, "home": true, "source": true, "src": true, "from": true, "name": true,
	"save": true, "write": true,
}

// DescriptiveArgumentKey reports an argument key whose words are prose about
// the call (description, note, details, context, ...) and none of whose
// words names a place (path, file, destination, ...). A string under such a
// key is text: the value is not a target of the tool, whatever it spells
// (rel-1-0-6:GAP-0729 review 9 M1). Any other unknown key keeps being
// judged, and so does a descriptive key that holds an object or an array.
func DescriptiveArgumentKey(key string) bool {
	descriptive := false
	for _, word := range argumentKeyWords(key) {
		if targetKeyWords[word] {
			return false
		}
		descriptive = descriptive || descriptiveKeyWords[word]
	}
	return descriptive
}

// argumentKeyWords splits a key into lower-case words at separators
// and camel-case humps (fileDescription, extra_note, Annotation-text).
func argumentKeyWords(key string) []string {
	var words []string
	start := 0
	for i := 1; i <= len(key); i++ {
		if i < len(key) {
			prev, cur := key[i-1], key[i]
			boundary := !isASCIIAlphanumeric(cur) || !isASCIIAlphanumeric(prev) ||
				(prev >= 'a' && prev <= 'z' && cur >= 'A' && cur <= 'Z')
			if !boundary {
				continue
			}
		}
		if word := strings.ToLower(strings.Trim(key[start:i], "_-. ")); word != "" {
			words = append(words, word)
		}
		start = i
	}
	return words
}

func isASCIIAlphanumeric(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
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
