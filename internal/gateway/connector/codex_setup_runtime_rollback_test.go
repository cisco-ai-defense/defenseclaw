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

package connector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// A failed Codex Setup puts the gateway helper record back as found: a new
// record goes, an existing one keeps its bytes (GAP-1736).
func TestCodexSetupRuntimeRollbackCoversTheGatewayHelperRecord(t *testing.T) {
	for _, tc := range []struct {
		name   string
		before []byte
	}{
		{name: "absent before setup"},
		{name: "present before setup", before: []byte("/home/u/.local/bin/defenseclaw-gateway\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := filepath.Join(testenv.PrivateTempDir(t), "defenseclaw")
			hookDir := filepath.Join(dataDir, "hooks")
			if err := os.MkdirAll(hookDir, 0o700); err != nil {
				t.Fatal(err)
			}
			record := filepath.Join(hookDir, ".gateway-helper")
			if tc.before != nil {
				if err := os.WriteFile(record, tc.before, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			opts := SetupOpts{DataDir: dataDir}
			snapshot, err := snapshotCodexSetupRuntime(opts, NewCodexConnector())
			if err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			if err := os.WriteFile(record, []byte("/elsewhere/defenseclaw-gateway\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := restoreCodexSetupRuntime(snapshot); err != nil {
				t.Fatalf("restore: %v", err)
			}
			after, err := os.ReadFile(record)
			if tc.before == nil {
				if !os.IsNotExist(err) {
					t.Fatalf("failed Setup left a new gateway helper record (%v): %q", err, after)
				}
				return
			}
			if err != nil || string(after) != string(tc.before) {
				t.Fatalf("gateway helper record after rollback = %q, %v; want %q", after, err, tc.before)
			}
		})
	}
}
