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

package sandboxcli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// The start banner says how many of the user's MCP servers came along and
// how many the organization blocked (GAP-0475).
func TestMCPBannerCountsWhatTheOrganizationLeftOut(t *testing.T) {
	for _, tc := range []struct {
		in   *sandboxapi.MCPSummary
		want string
	}{
		{nil, ""},
		{&sandboxapi.MCPSummary{}, ""},
		{&sandboxapi.MCPSummary{Imported: []string{"ok-srv"}, LeftBehind: []sandboxapi.MCPLeftBehind{{Name: "off", Reason: "disabled"}}}, "ok-srv ✓"},
		{&sandboxapi.MCPSummary{Imported: []string{"ok-srv", "user-srv"}, LeftBehind: []sandboxapi.MCPLeftBehind{
			{Name: "blocked-srv", Reason: "blocked by your organization", Code: sandboxapi.MCPCodeOrganizationBlock}}},
			"ok-srv ✓ · user-srv ✓ (2 of your servers included; 1 blocked by your organization)"},
		{&sandboxapi.MCPSummary{LeftBehind: []sandboxapi.MCPLeftBehind{
			{Name: "blocked-srv", Code: sandboxapi.MCPCodeOrganizationBlock}, {Name: "asset-srv", Code: sandboxapi.MCPCodeAssetPolicy}}},
			"0 of your servers included; 1 blocked by your organization; 1 left out by your organization's asset policy"},
	} {
		if got := mcpBannerText(tc.in); got != tc.want {
			t.Errorf("mcpBannerText(%+v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
