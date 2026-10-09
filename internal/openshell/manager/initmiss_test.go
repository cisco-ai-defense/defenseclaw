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

//go:build !windows

package manager

import (
	"testing"
	"time"
)

// GAP-0100 (TS r5): an idle sandbox recorded its init (pid 1) ending and
// starting again when one complete sample lacked it. pid 1 of the sandbox's
// pid namespace ends only with the sandbox (and endProcessTree), so a sample
// without it does not end it; a new init (another start) still replaces it.
func TestProcessTreeKeepsTheSandboxInitWhenASampleMissesIt(t *testing.T) {
	tree := newProcTree()
	t0 := time.Now()
	tree.merge(sampleOf("1 0 10 openshell-sandbox", "42 1 20 claude"), t0, t0, false)
	t1 := t0.Add(5 * time.Second)
	if started, exited := tree.merge(sampleOf("42 1 20 claude"), t1, t1, false); len(started) != 0 || len(exited) != 0 {
		t.Fatalf("a sample without pid 1: started %+v exited %+v", started, exited)
	}
	t2 := t1.Add(5 * time.Second)
	if started, exited := tree.merge(sampleOf("1 0 10 openshell-sandbox", "42 1 20 claude"), t2, t2, false); len(started) != 0 || len(exited) != 0 {
		t.Fatalf("pid 1 again: started %+v exited %+v", started, exited)
	}
	t3 := t2.Add(5 * time.Second)
	started, exited := tree.merge(sampleOf("1 0 99 openshell-sandbox"), t3, t3, false)
	if len(started) != 1 || started[0].PID != 1 || len(exited) != 2 {
		t.Fatalf("a new init: started %+v exited %+v, want the old init and claude ended", started, exited)
	}
}
