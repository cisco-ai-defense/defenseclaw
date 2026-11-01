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

package sensor

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

// GAP-1400: two would-block writes of one tactic are two hits on the one
// activity; an observation and a weaker outcome do not add hits.
func TestActivityCountsKernelHitsOfItsOutcome(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	write := func(path string, outcome plane.KernelOutcome, control string) plane.Event {
		return plane.Event{Kind: plane.KindFileWrite, PID: 1201, Path: path, ExecID: "sh", UID: uidp(1001),
			Source: plane.SourceTetragon, Policy: "defenseclaw-controls-burnin-2a3b4c5d", Outcome: outcome,
			Control: control, At: base}
	}
	script := []plane.Event{
		{Kind: plane.KindExec, PID: 1200, PPID: 1, Name: "2.1.292", Exe: claudeExe, ExecID: "root", UID: uidp(1001), At: base},
		{Kind: plane.KindExec, PID: 1201, PPID: 1200, Name: "sh", Exe: "/usr/bin/sh", ExecID: "sh",
			ParentExecID: "root", UID: uidp(1001), At: base},
		write("/home/dev/.bashrc", plane.OutcomeObserved, ""),
		write("/home/dev/.bashrc", plane.OutcomeWouldBlock, "kernel.persistence_write"),
		write("/home/dev/.profile", plane.OutcomeWouldBlock, "kernel.persistence_write"),
		write("/home/dev/.profile", plane.OutcomeObserved, ""),
	}
	host := newHost(newFake(fullCoverage(), script...))
	drainAll(t, host, len(script))
	findings := host.harvest(base.Add(time.Minute), 1)
	if len(findings) != 1 {
		t.Fatalf("got %d findings", len(findings))
	}
	for _, activity := range findings[0].Activities {
		if activity.Tactic != tactics.Persistence {
			continue
		}
		if activity.Outcome != plane.OutcomeWouldBlock || activity.Control != "kernel.persistence_write" || activity.Hits != 2 {
			t.Fatalf("persistence activity = %+v, want would_block kernel.persistence_write with 2 hits", activity)
		}
		return
	}
	t.Fatalf("no persistence activity in %+v", findings[0].Activities)
}
