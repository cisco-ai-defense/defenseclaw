// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package processutil

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeThread struct {
	id       uint32
	previous uint32
	unopened bool
	err      error
}

func fakeThreadOps(snapshots [][]fakeThread) (capturedThreadOps, *[]uint32) {
	var resumed []uint32
	clock := time.Unix(0, 0)
	call := 0
	byID := map[uint32]fakeThread{}
	return capturedThreadOps{
		threads: func(uint32) ([]uint32, error) {
			index := call
			if index >= len(snapshots) {
				index = len(snapshots) - 1
			}
			call++
			ids := make([]uint32, 0, len(snapshots[index]))
			for _, thread := range snapshots[index] {
				byID[thread.id] = thread
				ids = append(ids, thread.id)
			}
			return ids, nil
		},
		resume: func(id uint32) (uint32, bool, error) {
			thread := byID[id]
			if thread.unopened {
				return 0, false, nil
			}
			resumed = append(resumed, id)
			return thread.previous, true, thread.err
		},
		now:   func() time.Time { return clock },
		sleep: func(delay time.Duration) { clock = clock.Add(delay) },
	}, &resumed
}

func TestResumeCapturedProcessAcceptsEndpointSuspendCount(t *testing.T) {
	for _, previous := range []uint32{1, 2, 5} {
		ops, resumed := fakeThreadOps([][]fakeThread{{{id: 7, previous: previous}}})
		if err := resumeCapturedProcessWithOps(42, ops); err != nil {
			t.Fatalf("previous suspend count %d: %v", previous, err)
		}
		if len(*resumed) != 1 || (*resumed)[0] != 7 {
			t.Fatalf("previous suspend count %d: resumed %v, want exactly [7]", previous, *resumed)
		}
	}
}

func TestResumeCapturedProcessSkipsRunningInjectedThreads(t *testing.T) {
	ops, resumed := fakeThreadOps([][]fakeThread{{
		{id: 3, previous: 0},
		{id: 4, unopened: true},
		{id: 5, previous: 1},
		{id: 6, previous: 1},
	}})
	if err := resumeCapturedProcessWithOps(42, ops); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got := *resumed; len(got) != 2 || got[0] != 3 || got[1] != 5 {
		t.Fatalf("resumed %v, want the running thread probed and then only the first suspended one", got)
	}
}

func TestResumeCapturedProcessAcceptsAlreadyRunningProcess(t *testing.T) {
	ops, _ := fakeThreadOps([][]fakeThread{{{id: 3, previous: 0}, {id: 4, previous: 0}}})
	if err := resumeCapturedProcessWithOps(42, ops); err != nil {
		t.Fatalf("every thread already running must not fail the launch: %v", err)
	}
}

func TestResumeCapturedProcessWaitsForPrimaryThread(t *testing.T) {
	ops, resumed := fakeThreadOps([][]fakeThread{{}, {}, {{id: 9, previous: 1}}})
	if err := resumeCapturedProcessWithOps(42, ops); err != nil {
		t.Fatalf("resume after the thread appears: %v", err)
	}
	if len(*resumed) != 1 {
		t.Fatalf("resumed %v, want one thread", *resumed)
	}
}

func TestResumeCapturedProcessRefusals(t *testing.T) {
	ops, _ := fakeThreadOps([][]fakeThread{{}})
	if err := resumeCapturedProcessWithOps(42, ops); err == nil ||
		!strings.Contains(err.Error(), "was not visible") {
		t.Fatalf("no thread error = %v", err)
	}
	failure := errors.New("resume denied")
	ops, _ = fakeThreadOps([][]fakeThread{{{id: 1, previous: 1, err: failure}}})
	if err := resumeCapturedProcessWithOps(42, ops); !errors.Is(err, failure) {
		t.Fatalf("resume error = %v, want %v", err, failure)
	}
	ops, _ = fakeThreadOps([][]fakeThread{{{id: 1, unopened: true}}})
	if err := resumeCapturedProcessWithOps(42, ops); err == nil {
		t.Fatal("a primary thread that never opens must fail once the wait is over")
	}
}
