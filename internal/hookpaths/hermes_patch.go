// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hermespatch"
)

// hermesReplaceEditArgs is the Claude Code edit call {file_path, old_string,
// new_string, replace_all} the gateway judges a Hermes patch call in replace
// mode as (connector.HermesTrustedWriteViews), so the hook client lists and
// resolves the same target it lists for write_file (rel-1-0-2 GAP-0680). ok
// is false for any other call: a V4A patch (mode "patch") or arguments
// outside that contract keep the reading of the call as written.
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

// hermesV4APatchTargets reads the same headers that the gateway judges and
// places every changed file in the hook's target walk. A malformed argument
// object leaves the write targets unverified.
func hermesV4APatchTargets(args json.RawMessage, cwd, home string) ([]string, bool) {
	dec := json.NewDecoder(bytes.NewReader(args))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string]json.RawMessage)
	for dec.More() {
		key, err := dec.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, false
		}
		var raw json.RawMessage
		if dec.Decode(&raw) != nil {
			return nil, false
		}
		fields[name] = raw
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return nil, false
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, false
	}
	var mode, body string
	if json.Unmarshal(fields["mode"], &mode) != nil || mode != "patch" ||
		json.Unmarshal(fields["patch"], &body) != nil || body == "" {
		return nil, false
	}
	if raw, present := fields["path"]; present && strings.TrimSpace(string(raw)) != "null" {
		var path string
		if json.Unmarshal(raw, &path) != nil || !hermespatch.PlainPath(path) {
			return nil, false
		}
	}
	targets, parsed := hermespatch.Targets(body)
	if !parsed || len(targets) > 256 {
		return nil, false
	}
	paths := make([]string, 0, len(targets))
	for _, target := range targets {
		if !hermespatch.PlainPath(target.Path) {
			return nil, false
		}
		placed, ok := patchTargetPaths(target.Path, cwd, home, false)
		if !ok {
			return nil, false
		}
		paths = append(paths, placed...)
	}
	return paths, true
}
