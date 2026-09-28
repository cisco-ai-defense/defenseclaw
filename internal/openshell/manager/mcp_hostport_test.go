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

package manager

import (
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// A localhost MCP server was left behind as "runs on this machine, which
// the sandbox cannot reach" on the same banner that said --host-port opened
// its port. A loopback HTTP server on an accepted host port comes along,
// pointed at host.openshell.internal; for another port the reason names the
// --host-port that brings it.
func TestImportMCPServersOverHostPorts(t *testing.T) {
	servers, skipped, _ := importMCPServers("claudecode", []config.MCPServerEntry{
		{Name: "local", URL: "http://localhost:38830/mcp?x=1", Transport: "http"},
		{Name: "loop", URL: "http://127.0.0.1:38831/mcp"},
		{Name: "tls", URL: "https://localhost:38830/mcp"},
		{Name: "lan", URL: "http://10.0.0.5:38830/mcp"},
	}, nil, []int{38830})
	if len(servers) != 1 || servers[0].Name != "local" || servers[0].URL != "http://host.openshell.internal:38830/mcp?x=1" {
		t.Fatalf("imported = %+v", servers)
	}
	reasons := map[string]string{}
	for _, s := range skipped {
		reasons[s.Name] = s.Reason
	}
	if !strings.HasSuffix(reasons["loop"], "run the sandbox with --host-port 38831 to bring it along") ||
		!strings.Contains(reasons["tls"], "HTTPS") || reasons["lan"] != localMCPUnreachable {
		t.Fatalf("left behind = %v", reasons)
	}
	if port, ok := hostPortOfMCP(servers[0].URL); !ok || port != 38830 {
		t.Fatalf("hostPortOfMCP = %d, %v", port, ok)
	}
}

// The banner says the server comes along and how it connects.
func TestCreateBringsLocalMCPOverAHostPort(t *testing.T) {
	e := newEnv(t, nil)
	withMCP(e, &fakeMCP{entries: []config.MCPServerEntry{{Name: "r2g-local", URL: "http://localhost:38830/mcp", Transport: "http"}}})
	sb := e.create(sandboxapi.CreateRequest{Name: "mcphp", HostPorts: []int{38830}})
	if sb.MCP == nil || !slices.Contains(sb.MCP.Imported, "r2g-local") || len(sb.MCP.LeftBehind) != 0 {
		t.Fatalf("mcp = %+v", sb.MCP)
	}
	var noted bool
	for _, w := range sb.Warnings {
		noted = noted || strings.Contains(w, "r2g-local reaches port 38830 on this machine as host.openshell.internal:38830")
	}
	if !noted {
		t.Fatalf("warnings = %q", sb.Warnings)
	}
}
