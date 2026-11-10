// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hermesargs"
)

// hermesReplaceEditArgs is the Claude Code edit call {file_path, old_string,
// new_string, replace_all} the gateway judges a Hermes patch call in replace
// mode as (connector.HermesTrustedWriteViews), so the hook client lists and
// resolves the same target it lists for write_file (rel-1-0-2 GAP-0680). ok
// is false for any other call: a V4A patch (mode "patch", read by
// hermesV4APatchTargets) or arguments outside that contract keep the reading
// of the call as written.
func hermesReplaceEditArgs(args json.RawMessage) (json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(args, &fields) != nil || fields == nil {
		return nil, false
	}
	str := func(key string) (string, bool) {
		var value string
		raw, present := fields[key]
		return value, present && json.Unmarshal(raw, &value) == nil
	}
	if raw, present := fields["mode"]; present && strings.TrimSpace(string(raw)) != "null" {
		if mode, ok := str("mode"); !ok || mode != "replace" {
			return nil, false
		}
	}
	path, pathOK := str("path")
	oldText, oldOK := str("old_string")
	newText, newOK := str("new_string")
	if !pathOK || path == "" || !oldOK || !newOK {
		return nil, false
	}
	edit := map[string]any{"file_path": path, "old_string": oldText, "new_string": newText}
	if raw, present := fields["replace_all"]; present && strings.TrimSpace(string(raw)) != "null" {
		var all bool
		if json.Unmarshal(raw, &all) != nil {
			return nil, false
		}
		edit["replace_all"] = all
	}
	encoded, err := json.Marshal(edit)
	return encoded, err == nil
}

// hermesV4AMaxTargets is connector.HermesMaxPatchTargets: a V4A patch that
// names more files is judged as one whose targets are unknown.
const hermesV4AMaxTargets = 256

// hermesV4APatchTargets lists the files a Hermes V4A patch (mode "patch")
// changes, as the gateway judges them (connector.HermesTrustedWriteViews:
// one native file write or delete per Update, Add, Delete and Move header,
// read by hermesargs.V4ATargets), each placed in cwd and home and resolved
// under the patch-target rule as apply_patch targets are (patchTargetPaths).
// v4a is false for any call that is not in V4A mode. ok is false for a V4A
// call whose targets are unknown: repeated keys, a body Hermes would refuse,
// a target that cannot be placed or resolved, or more than
// hermesV4AMaxTargets files.
func hermesV4APatchTargets(args json.RawMessage, cwd, home string) (paths []string, v4a, ok bool) {
	fields, unique := hermesUniqueFields(args)
	var mode string
	if raw, present := fields["mode"]; !present || json.Unmarshal(raw, &mode) != nil || mode != "patch" {
		return nil, false, false
	}
	if !unique {
		return nil, true, false
	}
	var body string
	if json.Unmarshal(fields["patch"], &body) != nil || body == "" {
		return nil, true, false
	}
	if raw, present := fields["path"]; present && strings.TrimSpace(string(raw)) != "null" {
		var path string
		if json.Unmarshal(raw, &path) != nil || !hermesargs.PlainPath(path) {
			return nil, true, false
		}
	}
	targets, parsed := hermesargs.V4ATargets(body)
	if !parsed || len(targets) > hermesV4AMaxTargets {
		return nil, true, false
	}
	for _, target := range targets {
		if !hermesargs.PlainPath(target.Path) {
			return nil, true, false
		}
		placed, known := patchTargetPaths(target.Path, cwd, home, patchResolved)
		if !known {
			return nil, true, false
		}
		paths = append(paths, placed...)
	}
	return paths, true, true
}

// hermesUniqueFields decodes a top-level argument object as Hermes reads it
// (a repeated key keeps its last value). unique is false when a key repeats,
// which the gateway refuses to guess at; fields is nil when args is not
// exactly one JSON object.
func hermesUniqueFields(args json.RawMessage) (fields map[string]json.RawMessage, unique bool) {
	dec := json.NewDecoder(bytes.NewReader(args))
	if start, err := dec.Token(); err != nil || start != json.Delim('{') {
		return nil, false
	}
	fields = make(map[string]json.RawMessage)
	unique = true
	for dec.More() {
		key, err := dec.Token()
		name, isName := key.(string)
		if err != nil || !isName {
			return nil, false
		}
		var raw json.RawMessage
		if dec.Decode(&raw) != nil {
			return nil, false
		}
		if _, repeated := fields[name]; repeated {
			unique = false
		}
		fields[name] = raw
	}
	if end, err := dec.Token(); err != nil || end != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return fields, unique
}
