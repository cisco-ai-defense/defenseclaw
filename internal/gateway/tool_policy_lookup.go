// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"strings"
)

const toolPolicyLookupErrorFinding = "POLICY-LOOKUP-ERROR"

func toolPolicyLookupErrorReason(check, tool, connector string, err error) string {
	check = strings.TrimSpace(check)
	if check == "" {
		check = "policy"
	}
	tool = strings.TrimSpace(tool)
	if tool == "" {
		tool = "<unknown>"
	}
	connector = strings.ToLower(strings.TrimSpace(connector))
	if connector == "" {
		connector = "global"
	}
	return fmt.Sprintf("tool %s lookup failed for %q on connector %q; blocking fail-closed: %v",
		check, tool, connector, err)
}

func logToolPolicyLookupError(surface, check, tool, connector string, err error) string {
	reason := toolPolicyLookupErrorReason(check, tool, connector, err)
	surface = strings.TrimSpace(surface)
	if surface == "" {
		surface = "gateway"
	}
	fmt.Fprintf(os.Stderr, "[%s] BLOCKED tool call: %s\n", surface, reason)
	return reason
}

func toolPolicyLookupErrorVerdict(surface, check, tool, connector string, err error) *ToolInspectVerdict {
	return &ToolInspectVerdict{
		Action:     "block",
		Severity:   "HIGH",
		Confidence: 1.0,
		Reason:     logToolPolicyLookupError(surface, check, tool, connector, err),
		Findings:   []string{toolPolicyLookupErrorFinding},
	}
}
