// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package copilotargs

import (
	"encoding/json"
	"slices"
)

// writeMetadata is, per Copilot CLI write tool, the display-only metadata
// field it sends (a description on edit, a file mode on create) and the
// reviewed fields beside it. Neither metadata field can name a target.
var writeMetadata = map[string]struct {
	metadata string
	reviewed []string
}{
	"edit":   {"description", []string{"path", "old_str", "new_str"}},
	"create": {"mode", []string{"path", "file_text"}},
}

// WriteArgsWithoutMetadata returns the arguments of a Copilot CLI edit or
// create call (tool is the judged name, LocalActionTool of the call's) with
// its metadata field removed, and true, when the call carries that field
// and otherwise only reviewed fields. Any other call reports false: an
// unknown field keeps the call's arguments, and so its partial analysis.
//
// The gateway judges a Copilot call on these arguments and the hook's
// write-target resolver (hookpaths) describes the same call, so a metadata
// field never leaves one side with a target the other cannot see.
func WriteArgsWithoutMetadata(tool string, args json.RawMessage) (json.RawMessage, bool) {
	shape, ok := writeMetadata[tool]
	if !ok {
		return nil, false
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(args, &object) != nil {
		return nil, false
	}
	if _, present := object[shape.metadata]; !present {
		return nil, false
	}
	delete(object, shape.metadata)
	for key := range object {
		if !slices.Contains(shape.reviewed, key) {
			return nil, false
		}
	}
	clean, err := json.Marshal(object)
	return clean, err == nil
}
