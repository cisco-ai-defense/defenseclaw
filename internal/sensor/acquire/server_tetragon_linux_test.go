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

//go:build linux

package acquire

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

type queuedFeed struct {
	batches chan plane.KernelBatch
	once    sync.Once
	done    chan struct{}
}

func (f *queuedFeed) Recv() (plane.KernelBatch, error) {
	select {
	case batch := <-f.batches:
		return batch, nil
	case <-f.done:
		return plane.KernelBatch{}, errors.New("closed")
	}
}
func (f *queuedFeed) Backend() plane.Backend {
	return plane.Backend{Kind: plane.BackendTetragon, Version: "v1.7.1", Socket: "/var/run/tetragon/tetragon.sock"}
}
func (f *queuedFeed) Close() error { f.once.Do(func() { close(f.done) }); return nil }

// TestHelperServesTetragonWhenConfigured: with a Tetragon mode the helper's
// event stream is the Tetragon source (here a queued feed), and the
// gateway sees its events and backend through the broker unchanged.
func TestHelperServesTetragonWhenConfigured(t *testing.T) {
	feed := &queuedFeed{batches: make(chan plane.KernelBatch, 8), done: make(chan struct{})}
	dials := 0
	var mu sync.Mutex
	helper := serveStub(t, ServerConfig{Tetragon: &TetragonConfig{Mode: "consume",
		Dial: func(context.Context) (plane.KernelFeed, error) {
			mu.Lock()
			defer mu.Unlock()
			dials++
			return feed, nil
		}}}, stubAcquirer{newStubSource(plane.Coverage{Mechanism: "must not be used"})})
	source := helper.PlaneSource([]string{"/etc"})
	if err := source.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	coverage := source.Coverage()
	if coverage.Backend == nil || coverage.Backend.Kind != plane.BackendTetragon || coverage.Backend.Mode != "consume" ||
		coverage.Backend.Version != "v1.7.1" {
		t.Fatalf("coverage %+v", coverage)
	}
	uid := 1001
	feed.batches <- plane.KernelBatch{Events: []plane.Event{{
		Kind: plane.KindExec, PID: 72425, Name: "2.1.292", Exe: "/home/dcr-std1/.local/share/claude/versions/2.1.292",
		UID: &uid, ExecID: "e1", ParentExecID: "e0", Source: plane.SourceTetragon,
	}}}
	select {
	case event := <-source.Events():
		if event.Exe == "" || event.UID == nil || *event.UID != 1001 || event.ExecID != "e1" || event.Source != plane.SourceTetragon {
			t.Fatalf("event %+v", event)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event through the broker")
	}
	mu.Lock()
	defer mu.Unlock()
	if dials != 1 {
		t.Fatalf("%d dials", dials)
	}
}
