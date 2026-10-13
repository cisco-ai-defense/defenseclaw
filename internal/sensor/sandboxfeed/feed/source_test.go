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

package feed

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tetragon"
	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// fakeStream replays responses, then ends.
type fakeStream struct {
	responses []*pb.GetEventsResponse
	end       error
	hold      chan struct{}
}

func (f *fakeStream) Recv() (*pb.GetEventsResponse, error) {
	if len(f.responses) == 0 {
		if f.hold != nil {
			<-f.hold
		}
		return nil, f.end
	}
	r := f.responses[0]
	f.responses = f.responses[1:]
	return r, nil
}

// The hub delivers each reader its own uid's frames and every reader the
// status frames; a reader that falls behind loses frames, counted for it.
func TestHubFiltersByOwner(t *testing.T) {
	hub := NewHub(nil)
	mine, theirs := hub.Subscribe(1000), hub.Subscribe(1001)
	defer mine.Close()
	defer theirs.Close()
	hub.Publish(Item{Owner: 1000, Frame: sandboxfeed.Frame{Kind: sandboxfeed.FrameExec, ExecID: "a"}})
	hub.SetTetragon(sandboxfeed.TetragonConnected, "")
	if f := <-mine.Frames(); f.ExecID != "a" {
		t.Fatalf("mine = %+v", f)
	}
	if f := <-mine.Frames(); f.Kind != sandboxfeed.FrameStatus || f.Tetragon != sandboxfeed.TetragonConnected {
		t.Fatalf("mine status = %+v", f)
	}
	if f := <-theirs.Frames(); f.Kind != sandboxfeed.FrameStatus {
		t.Fatalf("theirs got %+v, want only the status", f)
	}
	select {
	case f := <-theirs.Frames():
		t.Fatalf("another uid's frame reached 1001: %+v", f)
	default:
	}
	// The same state again is no news.
	hub.SetTetragon(sandboxfeed.TetragonConnected, "")
	if len(mine.Frames()) != 0 {
		t.Fatal("an unchanged state was sent")
	}
	for range subscriptionBuffer + 5 {
		hub.Publish(Item{Owner: 1001, Frame: sandboxfeed.Frame{Kind: sandboxfeed.FrameExec}})
	}
	if dropped := theirs.TakeDropped(); dropped != 5 {
		t.Fatalf("dropped = %d", dropped)
	}
	if mine.TakeDropped() != 0 {
		t.Fatal("a reader lost frames that were not its own")
	}
}

// The source maps the stream into the hub, says when Tetragon goes away and
// comes back, and passes the loss signals on.
func TestSourceFollowsTetragon(t *testing.T) {
	hub := NewHub(nil)
	sub := hub.Subscribe(1000)
	defer sub.Close()
	shell := proc{pid: 4200, ktime: 5e9, docker: workload, binary: "/bin/bash", args: "-l"}
	opens := 0
	var mu sync.Mutex
	hold := make(chan struct{})
	source := &Source{
		Mapper: NewMapper(MapperConfig{Containers: testContainers()}), Hub: hub, Logger: quietLogger(),
		Open: func(context.Context) (EventStream, func(), error) {
			mu.Lock()
			defer mu.Unlock()
			opens++
			switch opens {
			case 1:
				return nil, nil, &tetragon.Error{Code: tetragon.ReasonTCPAPI, Detail: "localhost:54321"}
			case 2:
				return &fakeStream{responses: []*pb.GetEventsResponse{
					execOf(shell),
					{Event: &pb.GetEventsResponse_ProcessThrottle{ProcessThrottle: &pb.ProcessThrottle{Type: pb.ThrottleType_THROTTLE_START}}},
					{Event: &pb.GetEventsResponse_RateLimitInfo{RateLimitInfo: &pb.RateLimitInfo{NumberOfDroppedProcessEvents: 7}}},
				}, end: io.EOF}, func() {}, nil
			}
			return &fakeStream{hold: hold, end: io.EOF}, func() {}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { source.Run(ctx); close(done) }()

	var got []sandboxfeed.Frame
	deadline := time.After(20 * time.Second)
	for !slices.ContainsFunc(got, func(f sandboxfeed.Frame) bool { return f.Dropped == 7 }) {
		select {
		case f := <-sub.Frames():
			got = append(got, f)
		case <-deadline:
			t.Fatalf("frames so far: %+v", got)
		}
	}
	want := []func(sandboxfeed.Frame) bool{
		func(f sandboxfeed.Frame) bool {
			return f.Kind == sandboxfeed.FrameStatus && f.Tetragon == sandboxfeed.TetragonUnavailable && f.Reason == tetragon.ReasonTCPAPI
		},
		func(f sandboxfeed.Frame) bool {
			return f.Kind == sandboxfeed.FrameStatus && f.Tetragon == sandboxfeed.TetragonConnected
		},
		func(f sandboxfeed.Frame) bool { return f.Kind == sandboxfeed.FrameExec && f.HostPID == 4200 },
		func(f sandboxfeed.Frame) bool { return f.Kind == sandboxfeed.FrameStatus && f.Dropped == 1 },
		func(f sandboxfeed.Frame) bool { return f.Kind == sandboxfeed.FrameStatus && f.Dropped == 7 },
	}
	if len(got) != len(want) {
		t.Fatalf("frames = %+v", got)
	}
	for i, ok := range want {
		if !ok(got[i]) {
			t.Fatalf("frame %d = %+v (all %+v)", i, got[i], got)
		}
	}
	// The stream ended: unavailable, then the next session.
	select {
	case f := <-sub.Frames():
		if f.Tetragon != sandboxfeed.TetragonUnavailable {
			t.Fatalf("after the end = %+v", f)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the end of the stream was not reported")
	}
	cancel()
	close(hold)
	<-done
}

// The feed's request: container execs and exits only, and the loss signals;
// the fields it does not use are dropped by Tetragon.
func TestRequestAsksForContainerExecsOnly(t *testing.T) {
	request := Request()
	if len(request.GetAllowList()) != 2 {
		t.Fatalf("allow list = %+v", request.GetAllowList())
	}
	execs, losses := request.GetAllowList()[0], request.GetAllowList()[1]
	if !slices.Equal(execs.GetEventSet(), []pb.EventType{pb.EventType_PROCESS_EXEC, pb.EventType_PROCESS_EXIT}) ||
		!slices.Equal(execs.GetContainerId(), []string{".+"}) {
		t.Fatalf("exec filter = %+v", execs)
	}
	if !slices.Equal(losses.GetEventSet(), []pb.EventType{pb.EventType_PROCESS_THROTTLE, pb.EventType_RATE_LIMIT_INFO}) {
		t.Fatalf("loss filter = %+v", losses)
	}
	excluded := request.GetFieldFilters()[0].GetFields().GetPaths()
	for _, field := range []string{"ancestors", "process.environment_variables", "parent.environment_variables", "process.cap", "parent.arguments"} {
		if !slices.Contains(excluded, field) {
			t.Errorf("%s is not dropped", field)
		}
	}
	if request.GetFieldFilters()[0].GetAction() != pb.FieldFilterAction_EXCLUDE {
		t.Fatal("the field filter does not exclude")
	}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
