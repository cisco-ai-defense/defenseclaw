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

package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// B5.4 S3: substrate.skills.scan.enabled: false is the admin-off switch. No
// scan runs and the gateway's fail mode decides (managed installs refuse new
// skills), read on every scan so a config reload applies at once.
func TestB54ScanOffIsTheFailMode(t *testing.T) {
	on := false
	s := runtimeSkillScanner{enabled: func() bool { return on }}
	_, _, err := s.ScanSkillFolder(context.Background(), "x", "/sandbox/.claude/skills/x", nil)
	if !errors.Is(err, gateway.ErrSubstrateSkillScannerUnavailable) {
		t.Fatalf("scan off: %v", err)
	}
}
