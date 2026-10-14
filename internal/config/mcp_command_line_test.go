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

package config

import "testing"

func TestCodexWholeTableOverrideMergesExistingServer(t *testing.T) {
	base := []MCPServerEntry{{Name: "approved", URL: "https://approved.example/mcp"}}
	entries, touched, exclusive, err := applyCodexMCPOverrides(base, []string{
		`mcp_servers={added={url="https://added.example/mcp"}}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if exclusive || touched["approved"] {
		t.Fatalf("whole-table override hid the configured server: exclusive=%v touched=%v", exclusive, touched)
	}
	approved, found := lookupMCPToolServer("codex", entries, "approved")
	if !found || approved.URL != base[0].URL {
		t.Fatalf("configured server after override = %+v, found=%v", approved, found)
	}
	if added, found := lookupMCPToolServer("codex", entries, "added"); !found || added.URL != "https://added.example/mcp" {
		t.Fatalf("added server = %+v, found=%v", added, found)
	}
}
