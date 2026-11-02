// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"strings"
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

// hermesV4AApplyPatchArgs gives the hook client the standard V4A envelope
// as an apply_patch call. Its target reader resolves each directive before
// the managed gateway loses access to the user's home. An envelope outside
// that reader's contract remains unproved and gets no ordinary-path claim.
func hermesV4AApplyPatchArgs(args json.RawMessage) (json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(args, &fields) != nil || fields == nil {
		return nil, false
	}
	var mode, patch string
	if raw, present := fields["mode"]; present {
		if json.Unmarshal(raw, &mode) != nil || mode != "patch" {
			return nil, false
		}
	} else if len(fields) != 1 {
		// A lone V4A body without mode defaults to replace in Hermes,
		// which rejects it. The gateway still checks its named paths.
		return nil, false
	}
	if json.Unmarshal(fields["patch"], &patch) != nil || patch == "" {
		return nil, false
	}
	encoded, err := json.Marshal(map[string]string{"patch": patch})
	return encoded, err == nil
}
