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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// fastFlush shortens the refusal fold and the flush for a test.
func fastFlush(t *testing.T) {
	t.Helper()
	window, interval := blockCoalesceWindow, sinkFlushInterval
	blockCoalesceWindow, sinkFlushInterval = 100*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { blockCoalesceWindow, sinkFlushInterval = window, interval })
}

func egressRecords(e *harnessEnv, sandbox string, match func(audit.SandboxEgressEvent) bool) int {
	e.tel.mu.Lock()
	defer e.tel.mu.Unlock()
	n := 0
	for _, r := range e.tel.egress {
		if r.Sandbox.Name == sandbox && (match == nil || match(r)) {
			n++
		}
	}
	return n
}

func feedEvents(e *harnessEnv, sandbox string, match func(sandboxapi.ActivityEvent) bool) int {
	n := 0
	for _, ev := range e.m.ActivitySince(0, sandbox) {
		if match(ev) {
			n++
		}
	}
	return n
}

func blockedEvent(sandbox, host string) egress.Event {
	return egress.Event{Kind: egress.EventBlocked, Time: time.Now(), SandboxName: sandbox, Method: "CONNECT",
		Host: host, Port: 443, Category: "webhook_catcher", Source: egress.SourceFeed, Reason: "exfil destination"}
}

// TestRepeatedRefusalsAreFolded pins that one sandbox refused the same
// request thousands of times puts one record into the shared queue and one
// for the repeats, naming their count, and that its large-upload finding
// and another sandbox's refusal still get through.
func TestRepeatedRefusalsAreFolded(t *testing.T) {
	fastFlush(t)
	e := newEnv(t, nil)
	e.run()
	a := e.create(sandboxapi.CreateRequest{Name: "floodbox"})
	b := e.create(sandboxapi.CreateRequest{Name: "quietbox", Project: e.otherProject("quietbox")})
	sink := e.m.EgressSink()
	for range 10000 {
		sink.EgressEvent(blockedEvent(a.Name, "flood.example"))
	}
	sink.EgressEvent(egress.Event{Kind: egress.EventLargeUpload, Time: time.Now(), SandboxName: a.Name, Host: "files.example.net", BytesUp: 30 << 20})
	sink.EgressEvent(blockedEvent(b.Name, "other.example"))
	eventually(t, "the other sandbox's refusal and the finding", func() bool {
		e.tel.mu.Lock()
		findings := len(e.tel.findings)
		e.tel.mu.Unlock()
		return findings == 1 && egressRecords(e, b.Name, nil) == 1
	})
	eventually(t, "the folded repeats", func() bool {
		return egressRecords(e, a.Name, func(r audit.SandboxEgressEvent) bool { return strings.Contains(r.Reason, "9998 more like it") }) == 1
	})
	if n := egressRecords(e, a.Name, nil); n != 2 {
		t.Fatalf("%d egress records for 10000 identical refusals, want 2", n)
	}
	if n := feedEvents(e, a.Name, func(ev sandboxapi.ActivityEvent) bool { return ev.Kind == sandboxapi.ActivityEgressBlocked }); n != 2 {
		t.Fatalf("%d feed events for 10000 identical refusals, want 2", n)
	}
}

// TestDistinctRefusalsArePacedPerSandbox pins that a sandbox refused for
// thousands of distinct destinations is paced on its own: the other
// sandbox's refusal is recorded and shown, and the feed tells how many of
// the flood it held back.
func TestDistinctRefusalsArePacedPerSandbox(t *testing.T) {
	fastFlush(t)
	e := newEnv(t, nil)
	e.run()
	a := e.create(sandboxapi.CreateRequest{Name: "manyhosts"})
	b := e.create(sandboxapi.CreateRequest{Name: "onehost", Project: e.otherProject("onehost")})
	sink := e.m.EgressSink()
	for i := range 5000 {
		sink.EgressEvent(blockedEvent(a.Name, fmt.Sprintf("h%d.flood.example", i)))
	}
	sink.EgressEvent(blockedEvent(b.Name, "other.example"))
	eventually(t, "the other sandbox's refusal on the feed", func() bool {
		return feedEvents(e, b.Name, func(ev sandboxapi.ActivityEvent) bool {
			return ev.Kind == sandboxapi.ActivityEgressBlocked && ev.Host == "other.example"
		}) == 1
	})
	eventually(t, "the held-back count on the feed", func() bool {
		return feedEvents(e, a.Name, func(ev sandboxapi.ActivityEvent) bool { return ev.Reason == "flood" }) >= 1
	})
	if n := egressRecords(e, a.Name, nil); n > 2*blockedBurst {
		t.Fatalf("%d egress records for 5000 refusals in a burst, want the sandbox paced", n)
	}
	shown := feedEvents(e, a.Name, func(ev sandboxapi.ActivityEvent) bool { return ev.Host != "" })
	if shown > 2*feedBurst {
		t.Fatalf("%d feed events for 5000 refusals in a burst, want the sandbox paced", shown)
	}
}

// TestLargeUploadSurvivesAFullQueue pins that a large-upload finding the
// full queue cannot take is kept, and recorded once the queue drains.
func TestLargeUploadSurvivesAFullQueue(t *testing.T) {
	fastFlush(t)
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "fullq"})
	sink := e.m.EgressSink()
	for range egressSinkBuffer + 10 {
		sink.EgressEvent(egress.Event{Kind: egress.EventClosed, Time: time.Now(), SandboxName: sb.Name, Host: "a.example", Port: 443})
	}
	sink.EgressEvent(egress.Event{Kind: egress.EventLargeUpload, Time: time.Now(), SandboxName: sb.Name, Host: "files.example.net", BytesUp: 30 << 20})
	e.run()
	eventually(t, "the finding", func() bool {
		e.tel.mu.Lock()
		defer e.tel.mu.Unlock()
		return len(e.tel.findings) == 1
	})
}
