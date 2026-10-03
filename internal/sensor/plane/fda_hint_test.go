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

package plane

import (
	"strings"
	"testing"
)

func TestFullDiskAccessHintNamesTheManagedSensorHelper(t *testing.T) {
	helper := "/opt/cisco/defenseclaw/bin/defenseclaw-sensor-helper"
	got := fullDiskAccessHint(helper)
	if !strings.Contains(got, helper) || !strings.Contains(got, "PPPC") {
		t.Fatalf("managed hint = %q", got)
	}
	got = fullDiskAccessHint("/Users/dev/.local/bin/defenseclaw-gateway")
	if !strings.Contains(got, "launches the gateway") || strings.Contains(got, "PPPC") {
		t.Fatalf("per-user hint = %q", got)
	}
}
