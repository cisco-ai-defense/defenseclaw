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

package sandboxcli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

func TestDoctorNamesTheUsersManualStopForALegacyGuest(t *testing.T) {
	ta := newTestApp(t, "")
	sb := sampleSandbox("kept")
	sb.Phase, sb.OldSupervisor = "ready", true
	ta.daemon.add(sb)
	row := ta.runDoctor(bg).Get(CheckIDLegacySandbox)
	if row == nil || row.Status != openshell.StatusFail || row.Fix == nil ||
		!strings.Contains(row.Detail, "legacy sandbox running, not protected by the 1.0.4 egress policy") ||
		!strings.Contains(row.Fix.Summary, "defenseclaw sandbox stop kept") {
		t.Fatalf("legacy doctor row = %+v", row)
	}
}
