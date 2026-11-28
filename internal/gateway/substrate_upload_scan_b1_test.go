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

//go:build !windows

package gateway

import (
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// B1 S9a: the launcher settings carry substrate.launcher.upload_scan, read
// live (hold_back is the admin-off switch), with defaults when unset.
func TestB1LauncherSettingsReportUploadScan(t *testing.T) {
	up := config.SubstrateUploadScanConfig{SecretAction: "hold_back", MaxFileBytes: 1 << 20}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.UploadScan = func() config.SubstrateUploadScanConfig { return up } })
	rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/launcher", "p-alice", "")
	if b := rec.Body.String(); rec.Code != http.StatusOK || !strings.Contains(b, `"secret_action":"hold_back"`) || !strings.Contains(b, `"max_file_bytes":1048576`) {
		t.Fatalf("admin hold_back not reported: %d %s", rec.Code, b)
	}
	g := newSubstrateFixture(t)
	rec = g.do(t, g.admin, http.MethodGet, "/api/v1/substrate/launcher", "p-alice", "")
	if b := rec.Body.String(); !strings.Contains(b, `"secret_action":"replace"`) || !strings.Contains(b, `"time_budget":"2m0s"`) || !strings.Contains(b, `"placeholder_form":"token"`) {
		t.Fatalf("defaults not reported: %s", b)
	}
}
