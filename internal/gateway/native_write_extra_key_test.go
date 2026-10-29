// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

// nativeWriteExtraKeyCalls are native write tools whose arguments carry one
// key outside the tool's reviewed schema. The harness still writes the file
// the target key names, so each is judged by that target like the reviewed
// call (GAP-0655).
func nativeWriteExtraKeyCalls() []nativeWriteCall {
	return []nativeWriteCall{
		{"opencode", "edit", func(p string) map[string]any {
			return map[string]any{"path": p, "oldString": "# base", "newString": "# base\n# k", "description": "add a line"}
		}},
		{"opencode", "write", func(p string) map[string]any {
			return map[string]any{"path": p, "content": "# k\n", "description": "add a line"}
		}},
		{"copilot", "edit", func(p string) map[string]any {
			return map[string]any{"path": p, "old_str": "# base", "new_str": "# base\n# k", "description": "add a line"}
		}},
		{"copilot", "create", func(p string) map[string]any {
			return map[string]any{"path": p, "file_text": "# k\n", "mode": "0600"}
		}},
	}
}

// nativeWriteTableCalls is every row of the host and sandbox tables.
func nativeWriteTableCalls() []nativeWriteCall {
	return append(nativeWriteCalls(), nativeWriteExtraKeyCalls()...)
}
