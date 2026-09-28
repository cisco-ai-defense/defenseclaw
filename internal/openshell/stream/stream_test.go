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

package stream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
)

// step is one scripted server action on a WatchSandbox call.
type step struct {
	send  *pb.SandboxStreamEvent
	err   error // end the call with this status
	block bool  // hold the call open until the client goes away
}

// fakeGateway serves WatchSandbox from per-call scripts over bufconn and
// records every request.
type fakeGateway struct {
	pb.UnimplementedOpenShellServer
	mu       sync.Mutex
	scripts  [][]step
	requests []*pb.WatchSandboxRequest
}

func (g *fakeGateway) WatchSandbox(req *pb.WatchSandboxRequest, srv grpc.ServerStreamingServer[pb.SandboxStreamEvent]) error {
	g.mu.Lock()
	g.requests = append(g.requests, req)
	var script []step
	if len(g.scripts) > 0 {
		script, g.scripts = g.scripts[0], g.scripts[1:]
	}
	g.mu.Unlock()
	if script == nil {
		<-srv.Context().Done()
		return srv.Context().Err()
	}
	for _, s := range script {
		switch {
		case s.send != nil:
			if err := srv.Send(s.send); err != nil {
				return err
			}
		case s.err != nil:
			return s.err
		case s.block:
			<-srv.Context().Done()
			return srv.Context().Err()
		}
	}
	return nil
}

func (g *fakeGateway) request(i int) *pb.WatchSandboxRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.requests[i]
}

func (g *fakeGateway) calls() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.requests)
}

func startGateway(t *testing.T, scripts ...[]step) (*fakeGateway, *grpc.ClientConn) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	g := &fakeGateway{scripts: scripts}
	srv := grpc.NewServer()
	pb.RegisterOpenShellServer(srv, g)
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
	})
	return g, conn
}

const space = "v1:fb559785-1a34-469a-b195-25f8781ae985:"

func cur(space string, n int) string { return fmt.Sprintf("%s%020d", space, n) }

func ocsfLine(cursor, msg string) *pb.SandboxStreamEvent {
	return &pb.SandboxStreamEvent{Cursor: cursor, Payload: &pb.SandboxStreamEvent_Log{Log: &pb.SandboxLogLine{
		SandboxId: "48cdacc8", EventTime: timestamppb.New(time.Unix(1700000000, 0)), Level: "OCSF", Target: "ocsf",
		Message: msg, Source: "sandbox"}}}
}

func statusEvent(phase pb.SandboxPhase) *pb.SandboxStreamEvent {
	exit := int32(0)
	return &pb.SandboxStreamEvent{Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "48cdacc8", Name: "d-watch"},
		Status: &pb.SandboxStatus{Phase: phase, CurrentPolicyVersion: 3, ExitCode: &exit,
			Conditions:             []*pb.SandboxCondition{{Type: "ConfigurationReady", Status: "True", Reason: "ConfigurationAccepted"}},
			ConfigurationAdmission: &pb.SandboxConfigurationAdmission{State: pb.ConfigurationAdmissionState_CONFIGURATION_ADMISSION_STATE_ACCEPTED}},
	}}}
}

type recorder struct {
	mu     sync.Mutex
	events []Event
	saved  []string
	sleeps []time.Duration
}

func (r *recorder) handle(ev Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recorder) kinds() []Kind {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Kind, len(r.events))
	for i, ev := range r.events {
		out[i] = ev.Kind
	}
	return out
}

func (r *recorder) ofKind(k Kind) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Event
	for _, ev := range r.events {
		if ev.Kind == k {
			out = append(out, ev)
		}
	}
	return out
}

func newWatcher(t *testing.T, conn grpc.ClientConnInterface, rec *recorder, cfg Config) *Watcher {
	t.Helper()
	cfg.Conn = conn
	if cfg.Sandbox == "" {
		cfg.Sandbox = "d-watch"
	}
	cfg.SaveCursor = func(c string) error {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.saved = append(rec.saved, c)
		return nil
	}
	w, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w.sleep = func(ctx context.Context, d time.Duration) error {
		rec.mu.Lock()
		rec.sleeps = append(rec.sleeps, d)
		rec.mu.Unlock()
		return ctx.Err()
	}
	return w
}

// runUntil runs the watcher until stop reports true, then cancels it.
func runUntil(t *testing.T, w *Watcher, rec *recorder, stop func() bool) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx, rec.handle) }()
	deadline := time.After(10 * time.Second)
	for !stop() {
		select {
		case err := <-done:
			return err
		case <-deadline:
			t.Fatalf("watcher did not reach the expected state; events: %v", rec.kinds())
		case <-time.After(2 * time.Millisecond):
		}
	}
	cancel()
	return <-done
}

func TestWatchDeliversTypedEvents(t *testing.T) {
	g, conn := startGateway(t, []step{
		{send: statusEvent(pb.SandboxPhase_SANDBOX_PHASE_READY)},
		{send: ocsfLine(cur(space, 30), "NET:OPEN [INFO] ALLOWED /usr/bin/curl(0) -> host.openshell.internal:18999 [policy:_provider_spike_hooks_1 engine:opa]")},
		{send: ocsfLine(cur(space, 37), "HTTP:POST [MED] DENIED POST http://api.github.com:443/zen [policy:spike_extra engine:l7] [reason:L7_REQUEST deny POST api.github.com:443/zen reason=POST /zen not permitted by policy]")},
		{send: &pb.SandboxStreamEvent{Cursor: cur(space, 38), Payload: &pb.SandboxStreamEvent_Log{Log: &pb.SandboxLogLine{Level: "INFO", Target: "openshell_sandbox", Message: "plain line"}}}},
		{send: &pb.SandboxStreamEvent{Cursor: cur(space, 39), Payload: &pb.SandboxStreamEvent_Event{Event: &pb.PlatformEvent{
			Source: "docker", Type: "Normal", Reason: "Started", Message: "container started", Metadata: map[string]string{"container": "abc"}}}}},
		{send: &pb.SandboxStreamEvent{Payload: &pb.SandboxStreamEvent_DraftPolicyUpdate{DraftPolicyUpdate: &pb.DraftPolicyUpdate{
			DraftVersion: 4, NewChunks: 1, TotalPending: 2, Summary: "evil.example.net:443"}}}},
		{send: &pb.SandboxStreamEvent{Payload: &pb.SandboxStreamEvent_Warning{Warning: &pb.SandboxStreamWarning{Message: "dropped 12 log lines: receiver lagged"}}}},
		{block: true},
	})
	rec := &recorder{}
	w := newWatcher(t, conn, rec, Config{TailLines: 50, EventTail: 10})
	err := runUntil(t, w, rec, func() bool { return len(rec.ofKind(KindWarning)) == 1 })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v", err)
	}

	req := g.request(0)
	if req.GetSandbox() != "d-watch" || req.GetWorkspaceScope().GetWorkspace() != "default" || !req.GetFollowStatus() ||
		!req.GetFollowLogs() || !req.GetFollowEvents() || req.GetResumeAfterCursor() != "" || req.GetLogTailLines() != 50 ||
		req.GetEventTail() != 10 || len(req.GetLogSources()) != 1 || req.GetLogSources()[0] != "sandbox" {
		t.Fatalf("request = %v", req)
	}
	want := []Kind{KindConnected, KindStatus, KindLog, KindLog, KindLog, KindPlatform, KindDraft, KindWarning}
	if got := rec.kinds(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("kinds = %v, want %v", got, want)
	}
	st := rec.ofKind(KindStatus)[0].Status
	if st.Name != "d-watch" || st.Phase != openshell.PhaseReady || st.PolicyVersion != 3 || st.Admission != openshell.AdmissionAccepted ||
		st.ExitCode == nil || len(st.Conditions) != 1 {
		t.Fatalf("status = %+v", st)
	}
	logs := rec.ofKind(KindLog)
	if logs[0].Log.OCSF == nil || logs[0].Log.OCSF.Class != ocsf.ClassNetwork || logs[0].Log.OCSF.Binary != "/usr/bin/curl" ||
		logs[0].Cursor != cur(space, 30) || !logs[0].Time.Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("ocsf log = %+v / %+v", logs[0], logs[0].Log.OCSF)
	}
	if !logs[1].Log.OCSF.Denied() || logs[1].Log.OCSF.Reason == "" {
		t.Fatalf("denied http = %+v", logs[1].Log.OCSF)
	}
	if logs[2].Log.OCSF != nil || logs[2].Log.Source != "gateway" {
		t.Fatalf("plain line = %+v", logs[2].Log)
	}
	if p := rec.ofKind(KindPlatform)[0].Platform; p.Reason != "Started" || p.Metadata["container"] != "abc" {
		t.Fatalf("platform = %+v", p)
	}
	if d := rec.ofKind(KindDraft)[0].Draft; d.TotalPending != 2 || d.NewChunks != 1 {
		t.Fatalf("draft = %+v", d)
	}
	if w.Cursor() != cur(space, 39) {
		t.Fatalf("cursor = %q", w.Cursor())
	}
	if last := rec.saved[len(rec.saved)-1]; last != cur(space, 39) {
		t.Fatalf("saved = %v", rec.saved)
	}
}

func TestWatchResumesAfterTransportFailure(t *testing.T) {
	g, conn := startGateway(t,
		[]step{
			{send: ocsfLine(cur(space, 1), "SSH:LISTEN [INFO]")},
			{send: ocsfLine(cur(space, 2), "NET:LISTEN [INFO] 127.0.0.1:3128")},
			{err: status.Error(codes.Unavailable, "gateway restarting")},
		},
		[]step{{err: status.Error(codes.Unavailable, "connection refused")}},
		[]step{
			{send: ocsfLine(cur(space, 3), "SSH:OPEN [INFO] ALLOWED")},
			{block: true},
		},
	)
	rec := &recorder{}
	w := newWatcher(t, conn, rec, Config{TailLines: 20, Backoff: Backoff{Initial: 100 * time.Millisecond, Max: time.Second, Multiplier: 2}})
	_ = runUntil(t, w, rec, func() bool { return len(rec.ofKind(KindLog)) == 3 })

	if g.request(1).GetResumeAfterCursor() != cur(space, 2) || g.request(1).GetLogTailLines() != 0 {
		t.Fatalf("resume request = %v", g.request(1))
	}
	if g.request(2).GetResumeAfterCursor() != cur(space, 2) {
		t.Fatalf("second resume request = %v", g.request(2))
	}
	conns := rec.ofKind(KindConnected)
	if len(conns) != 2 || conns[0].Connection.Resumed || !conns[1].Connection.Resumed || conns[1].Connection.Cursor != cur(space, 2) {
		t.Fatalf("connected events = %+v %+v", conns[0].Connection, conns[len(conns)-1].Connection)
	}
	disc := rec.ofKind(KindDisconnected)
	if len(disc) != 2 || status.Code(disc[0].Connection.Err) != codes.Unavailable {
		t.Fatalf("disconnects = %+v", disc)
	}
	// The first failure followed a healthy stream: initial delay. The
	// second failed without delivering anything: doubled.
	if fmt.Sprint(rec.sleeps) != fmt.Sprint([]time.Duration{100 * time.Millisecond, 200 * time.Millisecond}) {
		t.Fatalf("backoff = %v", rec.sleeps)
	}
	// The throttle lets the first cursor through; the disconnect flushes
	// the second before the reconnect.
	if fmt.Sprint(rec.saved) != fmt.Sprint([]string{cur(space, 1), cur(space, 2), cur(space, 3)}) {
		t.Fatalf("saved cursors = %v", rec.saved)
	}
}

func TestWatchOutOfRangeResubscribesWithoutCursorAndReportsGap(t *testing.T) {
	newSpace := "v1:0a1b2c3d-0000-4000-8000-000000000000:"
	g, conn := startGateway(t,
		[]step{{err: status.Error(codes.OutOfRange, "cursor predates the buffer")}},
		[]step{
			{send: ocsfLine(cur(newSpace, 1), "LIFECYCLE:START [INFO] openshell-sandbox success")},
			{block: true},
		},
	)
	rec := &recorder{}
	persisted := cur(space, 99)
	w := newWatcher(t, conn, rec, Config{Cursor: persisted, TailLines: 200})
	_ = runUntil(t, w, rec, func() bool { return len(rec.ofKind(KindLog)) == 1 })

	if g.request(0).GetResumeAfterCursor() != persisted {
		t.Fatalf("first request = %v", g.request(0))
	}
	if g.request(1).GetResumeAfterCursor() != "" || g.request(1).GetLogTailLines() != 200 {
		t.Fatalf("resubscribe request = %v", g.request(1))
	}
	gaps := rec.ofKind(KindGap)
	if len(gaps) != 1 || gaps[0].Gap.Reason != GapCursorOutOfRange || gaps[0].Gap.LostCursor != persisted {
		t.Fatalf("gaps = %+v", gaps)
	}
	if len(rec.sleeps) != 0 {
		t.Fatalf("a gap must resubscribe immediately, slept %v", rec.sleeps)
	}
	if rec.saved[0] != "" || rec.saved[len(rec.saved)-1] != cur(newSpace, 1) {
		t.Fatalf("saved = %q", rec.saved)
	}
	if w.Cursor() != cur(newSpace, 1) {
		t.Fatalf("cursor = %q", w.Cursor())
	}
}

func TestWatchRejectedCursorIsAGapButBadRequestIsTerminal(t *testing.T) {
	_, conn := startGateway(t,
		[]step{{err: status.Error(codes.InvalidArgument, "cursor was not issued by this gateway")}},
		[]step{{err: status.Error(codes.InvalidArgument, "bad selector")}},
	)
	rec := &recorder{}
	w := newWatcher(t, conn, rec, Config{Cursor: "v1:foreign:00000000000000000001"})
	err := w.Run(context.Background(), rec.handle)
	if status.Code(errors.Unwrap(err)) != codes.InvalidArgument {
		t.Fatalf("Run = %v", err)
	}
	if gaps := rec.ofKind(KindGap); len(gaps) != 1 || gaps[0].Gap.Reason != GapCursorRejected {
		t.Fatalf("gaps = %+v", gaps)
	}
}

func TestWatchOutOfRangeWithoutCursorBacksOff(t *testing.T) {
	g, conn := startGateway(t,
		[]step{{err: status.Error(codes.OutOfRange, "odd")}},
		[]step{{send: ocsfLine(cur(space, 1), "SSH:LISTEN [INFO]")}, {block: true}},
	)
	rec := &recorder{}
	w := newWatcher(t, conn, rec, Config{})
	_ = runUntil(t, w, rec, func() bool { return len(rec.ofKind(KindLog)) == 1 })
	if len(rec.ofKind(KindGap)) != 0 || len(rec.sleeps) != 1 || g.calls() != 2 {
		t.Fatalf("gaps %v sleeps %v calls %d", rec.ofKind(KindGap), rec.sleeps, g.calls())
	}
}

func TestWatchDropsReplayedDuplicates(t *testing.T) {
	newSpace := "v1:11111111-2222-4333-8444-555555555555:"
	_, conn := startGateway(t,
		[]step{
			{send: ocsfLine(cur(space, 7), "SSH:LISTEN [INFO]")},
			{send: ocsfLine(cur(space, 8), "SSH:OPEN [INFO] ALLOWED")},
			{err: status.Error(codes.OutOfRange, "trimmed")},
		},
		[]step{
			// A tail replay after the gap repeats the last line.
			{send: ocsfLine(cur(space, 8), "SSH:OPEN [INFO] ALLOWED")},
			{send: ocsfLine(cur(newSpace, 1), "NET:LISTEN [INFO] 127.0.0.1:3128")},
			{block: true},
		},
	)
	rec := &recorder{}
	w := newWatcher(t, conn, rec, Config{})
	_ = runUntil(t, w, rec, func() bool { return len(rec.ofKind(KindLog)) >= 3 })
	logs := rec.ofKind(KindLog)
	if len(logs) != 3 || logs[2].Cursor != cur(newSpace, 1) {
		t.Fatalf("logs = %+v", logs)
	}
}

func TestWatchTerminalErrors(t *testing.T) {
	for _, tc := range []struct {
		code codes.Code
		want error
	}{
		{codes.NotFound, ErrSandboxNotFound},
		{codes.PermissionDenied, nil},
		{codes.Unauthenticated, nil},
		{codes.Unimplemented, nil},
	} {
		t.Run(tc.code.String(), func(t *testing.T) {
			_, conn := startGateway(t, []step{{err: status.Error(tc.code, "no")}})
			rec := &recorder{}
			w := newWatcher(t, conn, rec, Config{})
			err := w.Run(context.Background(), rec.handle)
			if err == nil {
				t.Fatal("Run returned nil")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("Run = %v, want %v", err, tc.want)
			}
			if tc.want == nil && status.Code(errors.Unwrap(err)) != tc.code {
				t.Fatalf("Run = %v", err)
			}
			if len(rec.sleeps) != 0 {
				t.Fatalf("terminal error backed off: %v", rec.sleeps)
			}
		})
	}
}

// TestWatchEndsWhenItsConnectionIsClosed pins that a watch whose gateway
// connection is closed under it (the manager dropped the connection) ends,
// instead of resubscribing on the dead connection for good.
func TestWatchEndsWhenItsConnectionIsClosed(t *testing.T) {
	g, conn := startGateway(t, []step{{send: statusEvent(pb.SandboxPhase_SANDBOX_PHASE_READY)}, {block: true}})
	rec := &recorder{}
	w := newWatcher(t, conn, rec, Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx, rec.handle) }()
	deadline := time.After(5 * time.Second)
	for len(rec.ofKind(KindStatus)) == 0 {
		select {
		case <-deadline:
			t.Fatalf("no status event; events: %v", rec.kinds())
		case <-time.After(2 * time.Millisecond):
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		t.Fatalf("the watch kept retrying on a closed connection (%d subscriptions, %d backoffs)", g.calls(), len(rec.sleeps))
	}
	if ctx.Err() != nil || status.Code(errors.Unwrap(err)) != codes.Canceled {
		t.Fatalf("Run = %v, want the closed connection's error", err)
	}
	if n := len(rec.sleeps); n > 1 {
		t.Fatalf("the watch backed off %d times on a closed connection", n)
	}
}

func TestWatchBackoffGrowsAndCaps(t *testing.T) {
	var scripts [][]step
	for i := 0; i < 6; i++ {
		scripts = append(scripts, []step{{err: status.Error(codes.Unavailable, "down")}})
	}
	scripts = append(scripts, []step{{send: ocsfLine(cur(space, 1), "SSH:LISTEN [INFO]")}, {err: status.Error(codes.Unavailable, "down")}})
	scripts = append(scripts, []step{{block: true}})
	_, conn := startGateway(t, scripts...)
	rec := &recorder{}
	w := newWatcher(t, conn, rec, Config{Backoff: Backoff{Initial: time.Second, Max: 8 * time.Second, Multiplier: 2}})
	_ = runUntil(t, w, rec, func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return len(rec.sleeps) == 7
	})
	want := []time.Duration{1, 2, 4, 8, 8, 8, 1}
	for i := range want {
		want[i] *= time.Second
	}
	if fmt.Sprint(rec.sleeps) != fmt.Sprint(want) {
		t.Fatalf("backoff = %v, want %v", rec.sleeps, want)
	}
}

func TestWatchJitterStaysWithinBounds(t *testing.T) {
	w := &Watcher{cfg: Config{Backoff: Backoff{Initial: time.Second, Max: time.Second, Multiplier: 1, Jitter: 0.5}}}
	for i := 0; i < 200; i++ {
		if d := w.jitter(time.Second); d < 500*time.Millisecond || d > time.Second {
			t.Fatalf("jittered delay %s out of bounds", d)
		}
	}
}

func TestWatchCursorSaveFailureIsReportedNotFatal(t *testing.T) {
	_, conn := startGateway(t, []step{
		{send: ocsfLine(cur(space, 1), "SSH:LISTEN [INFO]")},
		{send: ocsfLine(cur(space, 2), "SSH:OPEN [INFO] ALLOWED")},
		{block: true},
	})
	rec := &recorder{}
	w, err := New(Config{Conn: conn, Sandbox: "d-watch", SaveInterval: time.Nanosecond,
		SaveCursor: func(string) error { return errors.New("disk full") }})
	if err != nil {
		t.Fatal(err)
	}
	_ = runUntil(t, w, rec, func() bool { return len(rec.ofKind(KindLog)) == 2 })
	warn := rec.ofKind(KindWarning)
	if len(warn) == 0 || !warn[0].Warning.Local {
		t.Fatalf("warnings = %+v", warn)
	}
}

func TestNewValidates(t *testing.T) {
	_, conn := startGateway(t)
	for _, cfg := range []Config{{Sandbox: "ok"}, {Conn: conn}, {Conn: conn, Sandbox: "Bad Name"}} {
		if _, err := New(cfg); err == nil {
			t.Fatalf("New(%+v) accepted", cfg)
		}
	}
	w, err := New(Config{Conn: conn, Sandbox: "ok", Follow: Follow{Logs: true}})
	if err != nil {
		t.Fatal(err)
	}
	if req := w.request(); req.GetFollowStatus() || !req.GetFollowLogs() || req.GetFollowEvents() {
		t.Fatalf("follow selection lost: %v", req)
	}
	if err := w.Run(context.Background(), nil); err == nil {
		t.Fatal("nil handler accepted")
	}
}
