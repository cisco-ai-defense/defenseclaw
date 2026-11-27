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

package attest

import "testing"

// GAP-0632: a bare MCP command that the kit finds through a link is read
// by what runs: a link of the folder (a folder PATH entry) is the
// folder's, and a runner reached under another name is a runner, so a
// folder program it is given is not an installed program's data.
func TestGAP0632BareCommandThroughALink(t *testing.T) {
	type row struct {
		cmd   string
		args  []string
		files []AttachedFile
	}
	const hitRole = "mcp_command_path_hit" // RoleCommandPathHit
	unknown := map[string]row{
		"folder link to an installed python": {"mcp-x", []string{"tools/srv.py"}, []AttachedFile{
			{Role: RoleCommandPath, Path: "mcp-x", Content: []byte("/usr/bin/python3")},
			{Role: hitRole, Path: "mcp-x", Content: []byte("/work/repo/bin/mcp-x")}}},
		"link to python, no PATH entry reported (older kit)": {"mcp-x", []string{"tools/srv.py"}, []AttachedFile{
			{Role: RoleCommandPath, Path: "mcp-x", Content: []byte("/usr/bin/python3.12")}}},
		"link to node": {"srv", []string{"./index.js"}, []AttachedFile{
			{Role: RoleCommandPath, Path: "srv", Content: []byte("/usr/bin/node")}}},
		"folder link to an installed program": {"mcp-y", nil, []AttachedFile{
			{Role: RoleCommandPath, Path: "mcp-y", Content: []byte("/usr/local/bin/mcp-server-git")},
			{Role: hitRole, Path: "mcp-y", Content: []byte("/work/repo/node_modules/.bin/mcp-y")}}},
	}
	for name, r := range unknown {
		if d := repoServerDecision(t, r.cmd, r.args, nil, r.files...); !d.Unavailable {
			t.Errorf("%s: %+v, want unscanned (the fail mode decides)", name, d)
		}
	}
	known := map[string]row{
		"installed link outside the folder": {"mcp-server-git", []string{"--repository", "."}, []AttachedFile{
			{Role: RoleCommandPath, Path: "mcp-server-git", Content: []byte("/opt/mcp/bin/mcp-server-git")},
			{Role: hitRole, Path: "mcp-server-git", Content: []byte("/usr/local/bin/mcp-server-git")}}},
		"link to python given an installed program": {"mcp-x", []string{"/usr/local/lib/mcp/srv.py"}, []AttachedFile{
			{Role: RoleCommandPath, Path: "mcp-x", Content: []byte("/usr/bin/python3")}}},
		"bare python3 to python3.12, module absent": {"python3", []string{"-m", "mcp_server_time"}, []AttachedFile{
			{Role: RoleCommandPath, Path: "python3", Content: []byte("/usr/bin/python3.12")},
			{Role: hitRole, Path: "python3", Content: []byte("/usr/bin/python3")},
			{Role: RoleMCPModuleAbsent, Path: "mcp_server_time"}}},
	}
	for name, r := range known {
		if d := repoServerDecision(t, r.cmd, r.args, nil, r.files...); d.Unavailable {
			t.Errorf("%s: %+v, want decided by the config rules", name, d)
		}
	}
}
