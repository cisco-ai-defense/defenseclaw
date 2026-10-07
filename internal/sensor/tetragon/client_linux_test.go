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

package tetragon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// fakeTetragon is FineGuidanceSensors on a real unix socket: the trust
// checks need SO_PEERCRED, which an in-memory connection does not carry.
// Every RPC it serves is recorded, and it implements all of them, so a call
// the client's allowlist should have stopped shows up as served.
type fakeTetragon struct {
	pb.UnimplementedFineGuidanceSensorsServer

	dir, socket, info string
	server            *grpc.Server

	mu       sync.Mutex
	version  string
	noInfo   bool
	policies []*pb.TracingPolicyStatus
	served   []string
	events   chan *pb.GetEventsResponse
	requests []*pb.GetEventsRequest
	added    []string
}

// myTrust lets the tests stand in for root.
func myTrust() *trustPolicy { return &trustPolicy{ownerUID: os.Getuid(), peerUID: os.Getuid()} }

func newFakeTetragon(t *testing.T, version string) *fakeTetragon {
	t.Helper()
	// A short path: sun_path is 108 bytes.
	dir, err := os.MkdirTemp("", "tg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	fake := &fakeTetragon{
		dir: dir, socket: filepath.Join(dir, "tetragon.sock"), info: filepath.Join(dir, "tetragon-info.json"),
		version: version, events: make(chan *pb.GetEventsResponse, 64),
	}
	fake.writeInfo(t, "unix://"+fake.socket, os.Getpid())
	fake.start(t)
	return fake
}

func (f *fakeTetragon) writeInfo(t *testing.T, address string, pid int) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"server_address": address, "metrics_address": "", "pid": pid, "export_fname": "/var/log/tetragon/tetragon.log",
	})
	if err := os.WriteFile(f.info, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.info, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *fakeTetragon) start(t *testing.T) {
	t.Helper()
	_ = os.Remove(f.socket)
	listener, err := net.Listen("unix", f.socket)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	if err := os.Chmod(f.socket, 0o660); err != nil {
		t.Fatal(err)
	}
	f.server = grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			f.record(info.FullMethod)
			return handler(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			f.record(info.FullMethod)
			return handler(srv, ss)
		}),
	)
	pb.RegisterFineGuidanceSensorsServer(f.server, f)
	server := f.server
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
}

// restart stops the server (ending every stream) and serves again.
func (f *fakeTetragon) restart(t *testing.T) {
	t.Helper()
	f.server.Stop()
	f.mu.Lock()
	f.events = make(chan *pb.GetEventsResponse, 64)
	f.mu.Unlock()
	f.start(t)
}

func (f *fakeTetragon) record(method string) {
	f.mu.Lock()
	f.served = append(f.served, method)
	f.mu.Unlock()
}

func (f *fakeTetragon) servedMethods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	set := map[string]bool{}
	for _, method := range f.served {
		set[method] = true
	}
	out := make([]string, 0, len(set))
	for method := range set {
		out = append(out, method)
	}
	sort.Strings(out)
	f.served = nil
	return out
}

func (f *fakeTetragon) GetVersion(context.Context, *pb.GetVersionRequest) (*pb.GetVersionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &pb.GetVersionResponse{Version: f.version}, nil
}

func (f *fakeTetragon) GetInfo(context.Context, *pb.GetInfoRequest) (*pb.GetInfoResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.noInfo {
		return nil, status.Error(codes.Unimplemented, "method GetInfo not implemented")
	}
	keep, _ := anypb.New(wrapperspb.Bool(false))
	server, _ := anypb.New(wrapperspb.String("unix:///var/run/tetragon/tetragon.sock"))
	return &pb.GetInfoResponse{
		Version: f.version,
		Probes:  []*pb.GetInfoResponse_Probe{{Name: "lsm", Enabled: wrapperspb.Bool(true)}, {Name: "override", Enabled: wrapperspb.Bool(false)}},
		Conf:    []*pb.GetInfoResponse_ConfVal{{Key: "keep-sensors-on-exit", Value: keep}, {Key: "server-address", Value: server}},
	}, nil
}

func (f *fakeTetragon) GetEvents(request *pb.GetEventsRequest, stream pb.FineGuidanceSensors_GetEventsServer) error {
	f.mu.Lock()
	f.requests = append(f.requests, request)
	events := f.events
	f.mu.Unlock()
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case event, ok := <-events:
			if !ok {
				return nil
			}
			if err := stream.Send(event); err != nil {
				return err
			}
		}
	}
}

func (f *fakeTetragon) ListTracingPolicies(context.Context, *pb.ListTracingPoliciesRequest) (*pb.ListTracingPoliciesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &pb.ListTracingPoliciesResponse{Policies: f.policies}, nil
}

func (f *fakeTetragon) AddTracingPolicy(_ context.Context, request *pb.AddTracingPolicyRequest) (*pb.AddTracingPolicyResponse, error) {
	f.mu.Lock()
	f.added = append(f.added, request.GetYaml())
	f.mu.Unlock()
	return &pb.AddTracingPolicyResponse{}, nil
}

func (f *fakeTetragon) DeleteTracingPolicy(context.Context, *pb.DeleteTracingPolicyRequest) (*pb.DeleteTracingPolicyResponse, error) {
	return &pb.DeleteTracingPolicyResponse{}, nil
}

func (f *fakeTetragon) ConfigureTracingPolicy(context.Context, *pb.ConfigureTracingPolicyRequest) (*pb.ConfigureTracingPolicyResponse, error) {
	return &pb.ConfigureTracingPolicyResponse{}, nil
}

func (f *fakeTetragon) SetDebug(context.Context, *pb.SetDebugRequest) (*pb.SetDebugResponse, error) {
	return &pb.SetDebugResponse{}, nil
}

func (f *fakeTetragon) RuntimeHook(context.Context, *pb.RuntimeHookRequest) (*pb.RuntimeHookResponse, error) {
	return &pb.RuntimeHookResponse{}, nil
}

func (f *fakeTetragon) dial(t *testing.T, scope Scope, trust *trustPolicy) (*Client, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := Dial(ctx, DialOptions{InfoPath: f.info, Scope: scope, trust: trust})
	if client != nil {
		t.Cleanup(func() { _ = client.Close() })
	}
	return client, err
}

func wantReason(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("dial succeeded, want %s", code)
	}
	if got := ReasonCode(err); got != code {
		t.Fatalf("reason %s (%v), want %s", got, err, code)
	}
	if !strings.HasPrefix(err.Error(), code+": ") {
		t.Fatalf("error %q does not start with its reason code", err)
	}
}

func TestDialRefusesUntrustedEndpoints(t *testing.T) {
	t.Run("no info file", func(t *testing.T) {
		_, err := Dial(context.Background(), DialOptions{InfoPath: filepath.Join(t.TempDir(), "absent.json"), Scope: ScopeConsume, trust: myTrust()})
		wantReason(t, err, ReasonUnavailable)
	})
	t.Run("socket missing", func(t *testing.T) {
		fake := newFakeTetragon(t, "v1.7.1")
		fake.writeInfo(t, "unix://"+filepath.Join(fake.dir, "gone.sock"), os.Getpid())
		_, err := fake.dial(t, ScopeConsume, myTrust())
		wantReason(t, err, ReasonUnavailable)
	})
	t.Run("TCP address is never dialled", func(t *testing.T) {
		fake := newFakeTetragon(t, "v1.7.1")
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("no loopback TCP: %v", err)
		}
		defer listener.Close()
		accepted := make(chan struct{}, 1)
		go func() {
			if conn, err := listener.Accept(); err == nil {
				accepted <- struct{}{}
				_ = conn.Close()
			}
		}()
		for _, address := range []string{listener.Addr().String(), "localhost:54321", "dns:///" + listener.Addr().String(), "unix:relative.sock"} {
			fake.writeInfo(t, address, os.Getpid())
			_, err := fake.dial(t, ScopeConsume, myTrust())
			wantReason(t, err, ReasonTCPAPI)
		}
		select {
		case <-accepted:
			t.Fatal("the client connected to a TCP address")
		case <-time.After(200 * time.Millisecond):
		}
	})
	t.Run("info file not root's", func(t *testing.T) {
		fake := newFakeTetragon(t, "v1.7.1")
		_, err := fake.dial(t, ScopeConsume, &trustPolicy{ownerUID: os.Getuid() + 1, peerUID: os.Getuid()})
		wantReason(t, err, ReasonUntrusted)
	})
	t.Run("info file group-writable", func(t *testing.T) {
		fake := newFakeTetragon(t, "v1.7.1")
		if err := os.Chmod(fake.info, 0o664); err != nil {
			t.Fatal(err)
		}
		_, err := fake.dial(t, ScopeConsume, myTrust())
		wantReason(t, err, ReasonUntrusted)
	})
	t.Run("info file is a link", func(t *testing.T) {
		fake := newFakeTetragon(t, "v1.7.1")
		link := filepath.Join(fake.dir, "link.json")
		if err := os.Symlink(fake.info, link); err != nil {
			t.Fatal(err)
		}
		_, err := Dial(context.Background(), DialOptions{InfoPath: link, Scope: ScopeConsume, trust: myTrust()})
		wantReason(t, err, ReasonUntrusted)
	})
	t.Run("socket directory world-writable", func(t *testing.T) {
		fake := newFakeTetragon(t, "v1.7.1")
		if err := os.Chmod(fake.dir, 0o777); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(fake.dir, 0o750)
		_, err := fake.dial(t, ScopeConsume, myTrust())
		wantReason(t, err, ReasonUntrusted)
	})
	t.Run("socket world-writable", func(t *testing.T) {
		fake := newFakeTetragon(t, "v1.7.1")
		if err := os.Chmod(fake.socket, 0o666); err != nil {
			t.Fatal(err)
		}
		_, err := fake.dial(t, ScopeConsume, myTrust())
		wantReason(t, err, ReasonUntrusted)
	})
	t.Run("not a socket", func(t *testing.T) {
		fake := newFakeTetragon(t, "v1.7.1")
		plain := filepath.Join(fake.dir, "plain")
		if err := os.WriteFile(plain, nil, 0o640); err != nil {
			t.Fatal(err)
		}
		fake.writeInfo(t, "unix://"+plain, os.Getpid())
		_, err := fake.dial(t, ScopeConsume, myTrust())
		wantReason(t, err, ReasonUntrusted)
	})
	t.Run("wrong peer uid", func(t *testing.T) {
		fake := newFakeTetragon(t, "v1.7.1")
		_, err := fake.dial(t, ScopeConsume, &trustPolicy{ownerUID: os.Getuid(), peerUID: os.Getuid() + 1})
		wantReason(t, err, ReasonUntrusted)
	})
	t.Run("restart: the info file names another pid", func(t *testing.T) {
		fake := newFakeTetragon(t, "v1.7.1")
		fake.writeInfo(t, "unix://"+fake.socket, os.Getpid()+1)
		_, err := fake.dial(t, ScopeConsume, myTrust())
		wantReason(t, err, ReasonUntrusted)
	})
	t.Run("root trust refuses a test-owned endpoint", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("running as root")
		}
		fake := newFakeTetragon(t, "v1.7.1")
		_, err := fake.dial(t, ScopeConsume, nil)
		wantReason(t, err, ReasonUntrusted)
	})
}

func TestDialChecksTheVersionWindow(t *testing.T) {
	for version, want := range map[string]Support{
		"v1.7.1":       {Consume: true, Observe: true, Enforce: true},
		"v1.7.0-dirty": {Consume: true, Observe: true, Enforce: true},
		"v1.6.0":       {Consume: true},
	} {
		fake := newFakeTetragon(t, version)
		fake.mu.Lock()
		fake.noInfo = strings.HasPrefix(version, "v1.6")
		fake.mu.Unlock()
		client, err := fake.dial(t, ScopeConsume, myTrust())
		if err != nil {
			t.Fatalf("%s: %v", version, err)
		}
		if got := SupportFor(client.Version()); got != want {
			t.Fatalf("%s: support %+v, want %+v", version, got, want)
		}
		info, err := client.GetInfo(context.Background())
		if fake.noInfo {
			if status.Code(err) != codes.Unimplemented {
				t.Fatalf("1.6 GetInfo: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if keep, known := info.KeepSensorsOnExit(); keep || !known {
			t.Fatalf("keep-sensors-on-exit %v known %v", keep, known)
		}
		if lsm, known := info.Probe("lsm"); !lsm || !known {
			t.Fatalf("lsm probe %v %v", lsm, known)
		}
		if info.Conf["server-address"] != "unix:///var/run/tetragon/tetragon.sock" {
			t.Fatalf("conf %v", info.Conf)
		}
	}
	for _, version := range []string{"v1.5.2", "v2.0.0", "garbage"} {
		fake := newFakeTetragon(t, version)
		_, err := fake.dial(t, ScopeConsume, myTrust())
		wantReason(t, err, ReasonUnsupportedVersion)
	}
	if keep, known := (ServerInfo{}).KeepSensorsOnExit(); !keep || known {
		t.Fatal("an unreadable conf must count as keep-sensors-on-exit set")
	}
}

// TestRPCAllowlistPerScope pins the per-mode RPC allowlist (spec 3.2): every
// scope calls every method, and the fake server, which implements them all,
// must have served exactly the allowed set.
func TestRPCAllowlistPerScope(t *testing.T) {
	want := map[Scope][]string{
		ScopeConsume: {
			"/tetragon.FineGuidanceSensors/GetEvents", "/tetragon.FineGuidanceSensors/GetInfo",
			"/tetragon.FineGuidanceSensors/GetVersion", "/tetragon.FineGuidanceSensors/ListTracingPolicies",
		},
		ScopePolicy: {
			"/tetragon.FineGuidanceSensors/AddTracingPolicy", "/tetragon.FineGuidanceSensors/ConfigureTracingPolicy",
			"/tetragon.FineGuidanceSensors/DeleteTracingPolicy", "/tetragon.FineGuidanceSensors/GetEvents",
			"/tetragon.FineGuidanceSensors/GetInfo", "/tetragon.FineGuidanceSensors/GetVersion",
			"/tetragon.FineGuidanceSensors/ListTracingPolicies",
		},
		ScopeCleanup: {
			"/tetragon.FineGuidanceSensors/DeleteTracingPolicy", "/tetragon.FineGuidanceSensors/ListTracingPolicies",
		},
	}
	for scope, allowed := range want {
		if got := AllowedMethods(scope); !reflect.DeepEqual(got, allowed) {
			t.Fatalf("%s allowlist %v, want %v", scope, got, allowed)
		}
		fake := newFakeTetragon(t, "v1.7.1")
		close(fake.events)
		client, err := fake.dial(t, scope, myTrust())
		if err != nil {
			t.Fatalf("%s: %v", scope, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		raw := pb.NewFineGuidanceSensorsClient(client.conn)
		name := "defenseclaw-controls-0a1b2c3d"
		document := "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: " + name + "\nspec: {}\n"
		results := map[string]error{}
		_, results["GetVersion"] = raw.GetVersion(ctx, &pb.GetVersionRequest{})
		_, results["GetInfo"] = client.GetInfo(ctx)
		if stream, err := client.Events(ctx, EventsRequest()); err != nil {
			results["GetEvents"] = err
		} else {
			_, err := stream.Recv()
			if status.Code(err) == codes.PermissionDenied {
				results["GetEvents"] = err
			}
		}
		_, results["ListTracingPolicies"] = client.ListPolicies(ctx)
		_, results["AddTracingPolicy"] = client.AddPolicy(ctx, []byte(document))
		results["DeleteTracingPolicy"] = client.DeletePolicy(ctx, name)
		results["ConfigureTracingPolicy"] = client.ConfigurePolicy(ctx, name, pb.TracingPolicyMode_TP_MODE_MONITOR, nil)
		// Never allowed, in any scope.
		_, results["SetDebug"] = raw.SetDebug(ctx, &pb.SetDebugRequest{})
		_, results["RuntimeHook"] = raw.RuntimeHook(ctx, &pb.RuntimeHookRequest{})
		cancel()

		served := fake.servedMethods()
		if !reflect.DeepEqual(served, allowed) {
			t.Fatalf("%s: the server served %v, want exactly %v", scope, served, allowed)
		}
		for method, err := range results {
			full := "/tetragon.FineGuidanceSensors/" + method
			if scope.Allows(full) {
				if err != nil {
					t.Fatalf("%s: allowed %s failed: %v", scope, method, err)
				}
			} else if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("%s: %s was not refused locally: %v", scope, method, err)
			}
		}
	}
	if _, ok := ScopeForMode("off"); ok {
		t.Fatal("mode off has a session scope")
	}
	for mode, want := range map[string]Scope{"consume": ScopeConsume, "observe": ScopePolicy, "enforce": ScopePolicy} {
		if got, ok := ScopeForMode(mode); !ok || got != want {
			t.Fatalf("mode %s: scope %s", mode, got)
		}
	}
}

func TestPolicyWritesAreLimitedToDefenseClawNames(t *testing.T) {
	fake := newFakeTetragon(t, "v1.7.1")
	client, err := fake.dial(t, ScopePolicy, myTrust())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, name := range []string{"dc-tg2-file-sensitive", "defenseclaw-foo", "defenseclaw-controls-XYZ", "defenseclaw-controls-0a1b2c3d4"} {
		if err := client.DeletePolicy(ctx, name); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("delete %q: %v", name, err)
		}
		if err := client.ConfigurePolicy(ctx, name, pb.TracingPolicyMode_TP_MODE_ENFORCE, nil); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("configure %q: %v", name, err)
		}
	}
	good := "defenseclaw-observe-89abcdef"
	for document, code := range map[string]codes.Code{
		"kind: TracingPolicy\nmetadata:\n  name: someone-else\n":                                 codes.PermissionDenied,
		"kind: TracingPolicy\nmetadata:\n  name: defenseclaw-observe-89abcdef0\n":                codes.PermissionDenied,
		"kind: TracingPolicyNamespaced\nmetadata:\n  name: " + good + "\n  namespace: default\n": codes.InvalidArgument,
		"kind: TracingPolicy\nmetadata:\n  name: " + good + "\n  namespace: default\n":           codes.InvalidArgument,
		"{not yaml": codes.InvalidArgument,
	} {
		if _, err := client.AddPolicy(ctx, []byte(document)); status.Code(err) != code {
			t.Fatalf("add %q: %v, want %s", document, err, code)
		}
	}
	if name, err := client.AddPolicy(ctx, []byte("kind: TracingPolicy\nmetadata:\n  name: "+good+"\n")); err != nil || name != good {
		t.Fatalf("add: %q %v", name, err)
	}
	fake.mu.Lock()
	added := len(fake.added)
	fake.mu.Unlock()
	if added != 1 {
		t.Fatalf("server saw %d adds", added)
	}
}

func TestEventsRequestShape(t *testing.T) {
	request := EventsRequest()
	if len(request.GetAllowList()) != 1 || len(request.GetDenyList()) != 0 || request.GetAggregationOptions() != nil {
		t.Fatalf("filters %+v", request)
	}
	allow := request.GetAllowList()[0]
	if !reflect.DeepEqual(allow.GetEventSet(), EventTypes) || len(allow.GetPolicyNames()) != 0 || len(allow.GetCelExpression()) != 0 {
		t.Fatalf("allow list %+v", allow)
	}
	field := request.GetFieldFilters()
	if len(field) != 1 || field[0].GetAction() != pb.FieldFilterAction_EXCLUDE {
		t.Fatalf("field filters %+v", field)
	}
	paths := field[0].GetFields().GetPaths()
	for _, required := range []string{"ancestors", "process.environment_variables", "process.cap", "process.ns", "process.pod", "parent.environment_variables"} {
		found := false
		for _, path := range paths {
			found = found || path == required
		}
		if !found {
			t.Fatalf("field filter does not drop %s: %v", required, paths)
		}
	}
	for _, path := range paths {
		if path == "process.binary_properties" || path == "process.arguments" {
			t.Fatalf("field filter drops %s, which the mapper needs", path)
		}
	}
}

// TestFeedStreamsLossSignalsAndEnds drives a dialled feed: the request the
// server sees, mapped events, throttle and rate-limit signals, DefenseClaw's
// own policies only in the backend, and the stream ending.
func TestFeedStreamsLossSignalsAndEnds(t *testing.T) {
	fake := newFakeTetragon(t, "v1.7.1")
	fake.policies = []*pb.TracingPolicyStatus{
		{Name: "defenseclaw-observe-89abcdef", State: pb.TracingPolicyState_TP_STATE_ENABLED, Mode: pb.TracingPolicyMode_TP_MODE_MONITOR},
		{Name: "defenseclaw-controls-0a1b2c3d", State: pb.TracingPolicyState_TP_STATE_ENABLED, Mode: pb.TracingPolicyMode_TP_MODE_ENFORCE},
		{Name: "dc-tg2-file-sensitive", State: pb.TracingPolicyState_TP_STATE_ENABLED},
	}
	dial := NewDialer(DialerConfig{InfoPath: fake.info, Homes: []string{fixtureHome}, trust: myTrust()})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	feed, err := dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer feed.Close()

	backend := feed.Backend()
	if backend.Kind != plane.BackendTetragon || backend.Version != "v1.7.1" || backend.Socket != fake.socket || backend.LossKnown {
		t.Fatalf("backend %+v", backend)
	}
	if len(backend.Policies) != 2 || backend.Policies[0].Name != "defenseclaw-controls-0a1b2c3d" ||
		backend.Policies[0].Mode != "enforce" || backend.Policies[1].State != "enabled" {
		t.Fatalf("policies %+v", backend.Policies)
	}

	for _, response := range loadFixture(t, "tg2-session.jsonl") {
		fake.events <- response
	}
	var execs, blocked, throttles int
	var dropped int64
	// 26 records; the customer policy's event and the hook's four tool
	// execs and exits map to nothing and are not returned.
	for received := 0; received < 21; received++ {
		batch, err := feed.Recv()
		if err != nil {
			t.Fatalf("after %d batches: %v", received, err)
		}
		dropped += batch.Dropped
		if batch.ThrottleStart {
			throttles++
		}
		for _, event := range batch.Events {
			if event.Kind == plane.KindExec {
				execs++
			}
			if event.Outcome == plane.OutcomeBlocked {
				blocked++
			}
		}
	}
	if execs == 0 || blocked != 1 || throttles != 1 || dropped != 7 {
		t.Fatalf("execs %d blocked %d throttles %d dropped %d", execs, blocked, throttles, dropped)
	}
	fake.mu.Lock()
	requests := fake.requests
	fake.mu.Unlock()
	if len(requests) != 1 || !reflect.DeepEqual(requests[0].GetAllowList()[0].GetEventSet(), EventTypes) {
		t.Fatalf("server saw %d requests", len(requests))
	}
	served := fake.servedMethods()
	for _, method := range served {
		if !ScopeConsume.Allows(method) {
			t.Fatalf("the event session called %s", method)
		}
	}

	// Tetragon restarts: the stream ends, and a new dial reaches it again.
	fake.restart(t)
	if _, err := feed.Recv(); err == nil {
		t.Fatal("the stream outlived the server")
	}
	again, err := dial(ctx)
	if err != nil {
		t.Fatalf("redial after the restart: %v", err)
	}
	_ = again.Close()
	// A restarted Tetragon has a new pid: a dial that reads the new info
	// file must check against it, and an old pid is refused.
	fake.writeInfo(t, "unix://"+fake.socket, os.Getpid()+7)
	if _, err := dial(ctx); ReasonCode(err) != ReasonUntrusted {
		t.Fatalf("pid change: %v", err)
	}
}

func TestReasonCodeOfAnUnknownError(t *testing.T) {
	if ReasonCode(errors.New("x")) != ReasonUnavailable {
		t.Fatal("unknown errors are tetragon_unavailable")
	}
}
