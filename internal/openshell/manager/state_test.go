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

package manager

import (
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// loadRecord reads one sandbox's record from disk.
func loadRecord(t *testing.T, e *harnessEnv, name string) *record {
	t.Helper()
	recs, errs := e.m.records.loadAll()
	if len(errs) > 0 {
		t.Fatalf("load records: %v", errs)
	}
	for _, r := range recs {
		if r.Name == name {
			return r
		}
	}
	return nil
}

// TestRecordSavesNeverGoBack pins that concurrent writers of a sandbox
// record leave the newest state on disk. The first write stalls right
// before it reaches the file while a second writer changes the record and
// saves it; a write that took its copy before the change must not land
// last.
func TestRecordSavesNeverGoBack(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "savebox"})
	e.m.mu.Lock()
	b := e.m.boxes["savebox"]
	e.m.mu.Unlock()
	stalled, second := make(chan struct{}), make(chan struct{})
	var writes atomic.Int32
	e.m.records.beforeWrite = func(string) {
		if writes.Add(1) == 1 {
			close(stalled)
			select {
			case <-second:
			case <-time.After(300 * time.Millisecond):
			}
		}
	}
	first := make(chan error, 1)
	go func() { first <- e.m.saveCursor(b, "v1:old") }()
	<-stalled
	go func() {
		if err := e.m.saveCursor(b, "v1:new"); err != nil {
			t.Error(err)
		}
		close(second)
	}()
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	<-second
	got := loadRecord(t, e, "savebox")
	if got == nil {
		t.Fatal("the record is gone")
	}
	if got.Cursor != "v1:new" {
		t.Fatalf("record on disk has cursor %q, want the newest, v1:new", got.Cursor)
	}
}

// TestSaveAfterRemoveKeepsTheRecordGone pins that a write racing the
// removal of a deleted sandbox's record cannot bring the record back.
func TestSaveAfterRemoveKeepsTheRecordGone(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "gonebox"})
	e.m.mu.Lock()
	b := e.m.boxes["gonebox"]
	e.m.mu.Unlock()
	if err := e.m.removeRecord(b); err != nil {
		t.Fatal(err)
	}
	if err := e.m.saveCursor(b, "v1:late"); err != nil {
		t.Fatal(err)
	}
	p, _ := e.m.records.path("gonebox")
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("the removed record is back: %v", err)
	}
}
