// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package agentchain

import (
	"testing"
	"time"
)

func TestReseedWindowDoesNotAliasDifferentImage(t *testing.T) {
	start := int64(1_760_000_000) * int64(time.Second)
	for _, next := range []ExecObservation{
		{PID: 200, PPID: 50, Name: "bash", Exe: "/usr/bin/bash", ExecID: "next", StartNS: start + int64(5*time.Millisecond)},
		{PID: 200, PPID: 50, Name: "2.1.292", Exe: "/home/dev/.local/share/claude/versions/2.1.292", Cmdline: "changed argv", ExecID: "next", StartNS: start + int64(5*time.Millisecond)},
	} {
		tracker := NewTracker()
		tracker.ObserveExecEvent(ExecObservation{PID: 200, PPID: 50, Name: "2.1.292",
			Exe: "/home/dev/.local/share/claude/versions/2.1.292", Cmdline: "claude", ExecID: "first", StartNS: start})
		tracker.ObserveExecEvent(next)
		if lineage, ok := tracker.Lineage(200, "next"); ok && lineage.Root.ExecID == "first" {
			t.Fatalf("a changed image inherited the agent root through aliasing: %+v", lineage)
		}
	}
}
