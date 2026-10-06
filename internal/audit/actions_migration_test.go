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

package audit

import (
	"context"
	"path/filepath"
	"testing"
)

// TestOperatorAdmissionRowsAndClear: only operator install rows are
// migration input, and clearing them keeps the journal (quarantine).
func TestOperatorAdmissionRowsAndClear(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ name, value, reason string }{
		{"operator-block", "block", "manually blocked"},
		{"operator-allow", "allow", "vetted"},
		{"scan-block", "block", "auto-block: watch detected HIGH findings (scanner=skill-scanner)"},
	} {
		if err := store.SetActionField("skill", row.name, "install", row.value, row.reason); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SetActionField("skill", "operator-block", "file", "quarantine", "manually blocked"); err != nil {
		t.Fatal(err)
	}

	rows, err := store.OperatorAdmissionRows()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].TargetName != "operator-allow" || rows[1].TargetName != "operator-block" {
		t.Fatalf("operator rows = %+v", rows)
	}
	if err := store.ClearInstallActions(context.Background(), []string{rows[0].ID, rows[1].ID}); err != nil {
		t.Fatal(err)
	}
	if left, _ := store.OperatorAdmissionRows(); len(left) != 0 {
		t.Fatalf("rows left after clear: %+v", left)
	}
	if entry, _ := store.GetAction("skill", "operator-block"); entry == nil || entry.Actions.File != "quarantine" || entry.Actions.Install != "" {
		t.Fatalf("journal row = %+v, want the quarantine kept and install cleared", entry)
	}
	if entry, _ := store.GetAction("skill", "operator-allow"); entry != nil {
		t.Fatalf("empty row kept: %+v", entry)
	}
}
