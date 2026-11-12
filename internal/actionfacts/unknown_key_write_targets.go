// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"maps"
	"path"
	"slices"
	"strings"
	"unicode"
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
//     is not complete, the tool's reviewed shape for that target. A string
//     under a key that names a place (path, file, target, destination,
//     output, ... at any depth, destinationArgumentKey) is judged by every
//     rule. Any other string (metadata, commentary, description, ...) is
//     judged for DefenseClaw's own state only, which blocks in every
//     profile whatever the key is called; it is text for every other
//     protected class, and the managed agent settings files of the vendors
//     are such a class (rel-1-0-6:GAP-0729).
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
	// SelfProtectionOnly marks the reading of a string under a key that
	// names no place: callers count only the findings that protect
	// DefenseClaw's own state from it.
	SelfProtectionOnly bool
}

// ArgumentTarget is a path-shaped string in the arguments of a call and
// whether a key that names a place (destinationArgumentKey) holds it.
type ArgumentTarget struct {
	Value       string
	Destination bool
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
	type reading struct {
		index    int
		complete bool
	}
	seen := map[string]reading{}
	add := func(args map[string]any, selfOnly bool) bool {
		raw, err := json.Marshal(args)
		if err != nil {
			return false
		}
		if prior, exists := seen[string(raw)]; exists {
			if !selfOnly {
				twins[prior.index].SelfProtectionOnly = false
			}
			return prior.complete
		}
		view := input
		view.Args = raw
		analyzed := Analyze(view)
		complete := analyzed.Authoritative() && len(analyzed.Paths) > 0
		seen[string(raw)] = reading{len(twins), complete}
		twins = append(twins, UnknownKeyTwin{Args: raw, Facts: analyzed, SelfProtectionOnly: selfOnly})
		return complete
	}
	reducedComplete := len(reduced) != 0 && add(reduced, false)
	if reducedComplete && !isApplyPatchTool(input.Tool) {
		for _, key := range unknownKeyTargetKeys {
			if raw, ok := reduced[key].(string); ok {
				if target := KnownExtraKeyPath(raw, input.ActiveHome); target != raw {
					placed := maps.Clone(reduced)
					placed[key] = target
					add(placed, false)
				}
			}
		}
	}

	var collected targetCollector
	collect := func(value any) {
		appendPathShapedStrings(&collected, value, 0, true)
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
		appendPathShapedStrings(&collected, object[key], 0, destinationArgumentKey(key))
	}
	candidates, overflow := collected.result()
	for _, candidate := range candidates {
		selfOnly := !candidate.Destination
		target := KnownExtraKeyPath(candidate.Value, input.ActiveHome)
		if reducedComplete {
			if retargeted, ok := retargetFileToolArgs(input.Tool, reduced, target); ok && add(retargeted, selfOnly) {
				continue
			}
		}
		add(unknownKeyFileToolShape(input.Tool, target), selfOnly)
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
func UnknownKeyWriteTargetViews(input Input, facts Facts) []UnknownKeyTwin {
	twins, _ := UnknownKeyTwins(input, facts)
	var views []UnknownKeyTwin
	for _, twin := range twins {
		if factsMutateAPath(twin.Facts) {
			views = append(views, twin)
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

// PathShapedArgumentValues returns the path-shaped strings the value of an
// unknown argument key holds, at any depth up to maxUnknownKeyValueDepth,
// once each, and whether it holds more than maxUnknownKeyTargets of them
// (only that many of each kind are returned). A connector projection that
// keeps only its harness's reviewed keys judges these values of the keys it
// leaves out as targets too, as UnknownKeyTwins does: those under a key
// that names a place by every rule, the others for DefenseClaw's own state.
func PathShapedArgumentValues(key string, raw json.RawMessage) ([]ArgumentTarget, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return nil, false
	}
	var collected targetCollector
	appendPathShapedStrings(&collected, value, 0, destinationArgumentKey(key))
	return collected.result()
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

// targetCollector gathers the path-shaped strings of argument values: at
// most one past maxUnknownKeyTargets of each kind (under a key that names a
// place, and others), so that a long run of one kind never hides the other.
type targetCollector struct {
	out                  []ArgumentTarget
	destinations, others int
	overflow             bool
}

func (c *targetCollector) add(value string, destination bool) {
	if i := slices.IndexFunc(c.out, func(target ArgumentTarget) bool { return target.Value == value }); i >= 0 {
		if destination && !c.out[i].Destination {
			c.out[i].Destination = true
			c.destinations, c.others = c.destinations+1, c.others-1
		}
		return
	}
	if destination {
		if c.destinations > maxUnknownKeyTargets {
			return
		}
		c.destinations++
	} else {
		// The vendor machine-policy files are a protected class of their
		// own: a string that only mentions one is text (GAP-0729).
		if c.others > maxUnknownKeyTargets || ManagedAgentSettingsPath(value, true) || WindowsManagedAgentSettingsPath(value) {
			return
		}
		c.others++
	}
	c.out = append(c.out, ArgumentTarget{Value: value, Destination: destination})
}

func (c *targetCollector) full() bool {
	return c.destinations > maxUnknownKeyTargets && c.others > maxUnknownKeyTargets
}

// result lists the targets under a key that names a place first, then the
// others, each kind cut at maxUnknownKeyTargets (overflow is then true).
func (c *targetCollector) result() ([]ArgumentTarget, bool) {
	var places, others []ArgumentTarget
	for _, target := range c.out {
		if target.Destination {
			places = append(places, target)
		} else {
			others = append(others, target)
		}
	}
	overflow := c.overflow
	if len(places) > maxUnknownKeyTargets {
		places, overflow = places[:maxUnknownKeyTargets], true
	}
	if len(others) > maxUnknownKeyTargets {
		others, overflow = others[:maxUnknownKeyTargets], true
	}
	return append(places, others...), overflow
}

// appendPathShapedStrings adds every path-shaped string in value
// (pathShapedArgumentValue) to the collector, searching objects and arrays
// to maxUnknownKeyValueDepth, in a stable order. destination is true when
// the key that holds value, or one above it, names a place.
func appendPathShapedStrings(c *targetCollector, value any, depth int, destination bool) {
	if c.full() {
		return
	}
	switch value := value.(type) {
	case string:
		if pathShapedArgumentValue(value) {
			c.add(value, destination)
		}
	case []any:
		if depth >= maxUnknownKeyValueDepth {
			if len(value) > 0 {
				c.overflow = true
			}
			return
		}
		for _, item := range value {
			appendPathShapedStrings(c, item, depth+1, destination)
		}
	case map[string]any:
		if depth >= maxUnknownKeyValueDepth {
			if len(value) > 0 {
				c.overflow = true
			}
			return
		}
		for _, key := range slices.Sorted(maps.Keys(value)) {
			appendPathShapedStrings(c, value[key], depth+1, destination || destinationArgumentKey(key))
		}
	}
}

// destinationWords are the words of an argument key that name where a call
// writes: the owner's list for the extra keys of a file tool.
var destinationWords = []string{
	"path", "file", "filename", "target", "destination", "dest", "output", "out", "to", "location",
}

// destinationArgumentKey reports a key with a word that names a place
// (path, file, filename, target, destination, dest, output, out, to,
// location), singular or plural, alone or joined to another place word
// (filepath, outputfile), split at separators, digits and camel-case
// humps: file_path, targetFile, destinations. A key that only holds text
// about the call (metadata, commentary, description, notes) names no place.
func destinationArgumentKey(key string) bool {
	var word []rune
	flush := func() bool {
		defer func() { word = word[:0] }()
		return len(word) > 0 && destinationWord(strings.ToLower(string(word)))
	}
	var previous rune
	for _, r := range key {
		switch {
		case !unicode.IsLetter(r):
			if flush() {
				return true
			}
		case unicode.IsUpper(r) && unicode.IsLower(previous):
			if flush() {
				return true
			}
			word = append(word, r)
		default:
			word = append(word, r)
		}
		previous = r
	}
	return flush()
}

// destinationWord reports a lower-case word that is a place word, its
// plural, or made only of place words.
func destinationWord(word string) bool {
	if word == "" {
		return false
	}
	if len(word) > 3 {
		if singular, ok := strings.CutSuffix(word, "s"); ok && destinationWord(singular) {
			return true
		}
	}
	for _, place := range destinationWords {
		if rest, ok := strings.CutPrefix(word, place); ok && (rest == "" || destinationWord(rest)) {
			return true
		}
	}
	return false
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
