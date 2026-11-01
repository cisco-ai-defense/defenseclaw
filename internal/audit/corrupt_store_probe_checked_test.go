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
	"bytes"
	"io"
	"path/filepath"
	"testing"
)

// rel-1-0-6 GAP-0332: the start ran quick_check over the whole store twice,
// in the read-only probe and again on the writable connection. The probe now
// reports a check that read the store and found it intact, and only a start
// without one checks again.
func TestReadOnlyProbeReportsAnIntactStoreAsChecked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	probe, err := readOnlyAuditStoreProbe(path, &bytes.Buffer{})
	if err != nil || !probe.checked {
		t.Fatalf("probe of an intact store = %+v, %v; want checked", probe, err)
	}
	missing, err := readOnlyAuditStoreProbe(filepath.Join(t.TempDir(), "absent.db"), &bytes.Buffer{})
	if err != nil || missing.checked {
		t.Fatalf("probe of a missing store = %+v, %v; want not checked", missing, err)
	}
	reopened, err := OpenDaemonStore(path, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	_ = reopened.Close()
}

func TestReadOnlyProbeOfACorruptStoreIsNotChecked(t *testing.T) {
	path := corruptColdJournalFixture(t)
	probe, err := readOnlyAuditStoreProbe(path, &bytes.Buffer{})
	if !isSQLiteCorrupt(err) || probe.checked {
		t.Fatalf("probe of a corrupt store = %+v, %v; want corrupt, not checked", probe, err)
	}
}

// A start whose probe did not check the store (skipped, inconclusive, or a
// store rebuilt after it) still runs the writable connection's quick_check.
func TestAStartWithoutACheckedProbeChecksTheStore(t *testing.T) {
	original := probeExistingAuditStore
	t.Cleanup(func() { probeExistingAuditStore = original })
	probeExistingAuditStore = func(string, io.Writer) (auditStoreProbe, error) { return auditStoreProbe{}, nil }
	path := corruptColdJournalFixture(t)
	var warning bytes.Buffer
	store, err := OpenDaemonStore(path, &warning)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	if !bytes.Contains(warning.Bytes(), []byte("corrupt")) {
		t.Fatalf("a start without a checked probe did not find the corrupt store; warning %q", warning.String())
	}
}
