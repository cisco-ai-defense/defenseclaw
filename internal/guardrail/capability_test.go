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

package guardrail

import "testing"

func TestClassifyToolName(t *testing.T) {
	cases := []struct {
		name string
		want ToolCapabilityClass
	}{
		{"read_file", CapReadFS},
		{"fs.read_file", CapReadFS},
		{"write_file", CapWriteFS},
		{"apply_patch", CapWriteFS},
		{"run_shell", CapExecShell},
		{"bash", CapExecShell},
		{"shell.run", CapExecShell},
		{"execute_command", CapExecShell},
		{"my_tool_shell", CapExecShell},
		{"fetch", CapNetworkFetch},
		{"http_request", CapNetworkFetch},
		{"http.get", CapNetworkFetch},
		{"send_email", CapSendMessage},
		{"post_webhook", CapSendMessage},
		{"RUN_SHELL", CapExecShell},
		{"unknown_tool", CapUnknown},
		{"", CapUnknown},
	}
	for _, c := range cases {
		got := ClassifyToolName(c.name)
		if got != c.want {
			t.Errorf("ClassifyToolName(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}
