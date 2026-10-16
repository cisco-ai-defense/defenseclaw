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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// observeFeed is a Tetragon session whose listing already holds
// DefenseClaw's observe policy, enabled, as on a host in steady state.
type observeFeed struct {
	once sync.Once
	done chan struct{}
}

func (f *observeFeed) Recv() (plane.KernelBatch, error) {
	<-f.done
	return plane.KernelBatch{}, errors.New("closed")
}
func (f *observeFeed) Backend() plane.Backend {
	return plane.Backend{Kind: plane.BackendTetragon, Version: "v1.7.1", Socket: "/var/run/tetragon/tetragon.sock",
		Policies: []plane.BackendPolicy{{Name: "defenseclaw-observe-45a62214", Mode: "monitor_only", State: "enabled"}}}
}
func (f *observeFeed) Close() error { f.once.Do(func() { close(f.done) }); return nil }

// #1240 (tetragon-pr:GAP-0123): on a managed host whose users are enrolled
// through vendor machine policy only (no home for fanotify), every gateway
// subscription after the observe policy loaded got a first frame without
// the file half, and no later frame ever corrected it: /health stayed
// degraded with "file events need DefenseClaw's observe policy" while the
// backend listed that policy enabled. The subscriber now sees the observe
// policy as the file half on the stream, long before the hand-off interval.
func TestEventStreamNamesALoadedObservePolicyWithNoHomeEnrolled(t *testing.T) {
	shortCoverageInterval(t, 50*time.Millisecond)
	helper := serveStub(t, ServerConfig{Tetragon: &TetragonConfig{Mode: "observe",
		Dial: func(context.Context) (plane.KernelFeed, error) {
			return &observeFeed{done: make(chan struct{})}, nil
		},
		OwnObservePolicy: func(name string) bool { return name == "defenseclaw-observe-45a62214" },
	}}, stubAcquirer{newStubSource(plane.Coverage{Mechanism: "must not be used"})})
	source := helper.PlaneSource(nil)
	if err := source.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	// Well inside the default 30 s hand-off interval and the 2 s refresh.
	deadline := time.Now().Add(1500 * time.Millisecond)
	for !source.Coverage().Complete() {
		if time.Now().After(deadline) {
			t.Fatalf("the stream kept the partial coverage: %+v", source.Coverage())
		}
		time.Sleep(10 * time.Millisecond)
	}
	coverage := source.Coverage()
	if !strings.Contains(coverage.Mechanism, "file opens from the DefenseClaw observe policy") || len(coverage.Limitations) != 0 {
		t.Fatalf("coverage %+v", coverage)
	}
}
