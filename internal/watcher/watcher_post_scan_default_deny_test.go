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

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// reloadingScanner runs onScan as a config reload during the scan would.
type reloadingScanner struct {
	countingScanner
	onScan func()
}

func (s *reloadingScanner) Scan(ctx context.Context, target string) (*scanner.ScanResult, error) {
	s.onScan()
	return s.countingScanner.Scan(ctx, target)
}

// GAP-1155: a default deny switched on while a skill was being scanned
// refuses the clean skill, as it would have before the scan.
func TestDefaultDenyActivatedDuringTheScanRefusesTheSkill(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil)
	denying := *cfg
	denying.AssetPolicy = config.DefaultAssetPolicy()
	denying.AssetPolicy.Enabled = true
	denying.AssetPolicy.Mode = config.AssetPolicyModeAction
	denying.AssetPolicy.Skill.Default = "deny"
	var reloaded atomic.Bool
	w.admissionPolicySource = func() AdmissionPolicySnapshot {
		if reloaded.Load() {
			return AdmissionPolicySnapshot{Config: &denying}
		}
		return AdmissionPolicySnapshot{Config: cfg}
	}
	w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &reloadingScanner{countingScanner: countingScanner{name: "skill-scanner"}, onScan: func() { reloaded.Store(true) }}
	}
	path := filepath.Join(skillDir, "late-deny")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	res := w.runAdmission(context.Background(), InstallEvent{Type: InstallSkill, Name: "late-deny", Path: path, Timestamp: time.Now()})
	if res.Verdict != VerdictBlocked {
		t.Fatalf("result %+v, want the default deny that became active during the scan to block", res)
	}
}
