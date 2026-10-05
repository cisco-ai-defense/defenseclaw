// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import "fmt"

// toolBatchToolName is the tool name of the record the gateway makes for a
// Claude Code PostToolBatch (claudeCodeToolBatchName in the gateway).
const toolBatchToolName = "tool_batch"

// classifyToolBatchCallIdentifiers classes the call list of a Claude Code
// tool_batch span as identifiers. Its arguments are not tool input: the
// gateway builds them from the calls of the batch as
// {"tool_calls":[{"tool_name":..., "tool_use_id":...}]}, the same values the
// span of each call carries as gen_ai.tool.name and gen_ai.tool.call.id. As
// content, the content redaction profile replaced them with tokens while the
// span of the call kept its name in clear (GAP-2558). Only a local claudecode
// span named tool_batch qualifies, and only those two string members.
func classifyToolBatchCallIdentifiers(classes map[string]FieldClass, attributes map[string]any, connector string) {
	if connector != "claudecode" || attributes["gen_ai.tool.name"] != toolBatchToolName {
		return
	}
	arguments, _ := attributes["gen_ai.tool.call.arguments"].(map[string]any)
	calls, _ := arguments["tool_calls"].([]any)
	for index, candidate := range calls {
		call, _ := candidate.(map[string]any)
		for _, key := range []string{"tool_name", "tool_use_id"} {
			pointer := fmt.Sprintf("/gen_ai.tool.call.arguments/tool_calls/%d/%s", index, key)
			if _, isString := call[key].(string); isString && classes[pointer] == FieldClassContent {
				classes[pointer] = FieldClassIdentifier
			}
		}
	}
}
