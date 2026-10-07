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
	"fmt"
	"log/slog"
	"os"
	"time"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tetragon"
	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// The feed's Tetragon request: the exec and exit of container processes
// (Tetragon's container_id filter, so host processes never reach the feed)
// and the two loss signals. Ancestors, environment variables, capabilities,
// namespaces, credentials, pod data and binary properties are dropped by
// Tetragon before sending, and so are the parent's arguments and folder.
var (
	feedEventTypes = []pb.EventType{pb.EventType_PROCESS_EXEC, pb.EventType_PROCESS_EXIT}
	lossEventTypes = []pb.EventType{pb.EventType_PROCESS_THROTTLE, pb.EventType_RATE_LIMIT_INFO}
	feedExcluded   = []string{
		"ancestors",
		"process.environment_variables", "process.cap", "process.ns", "process.process_credentials",
		"process.pod", "process.binary_properties",
		"parent.environment_variables", "parent.cap", "parent.ns", "parent.process_credentials",
		"parent.pod", "parent.binary_properties", "parent.arguments", "parent.cwd",
	}
)

// Request is the feed's GetEvents request. It is built here and carries no
// filter a caller could widen.
func Request() *pb.GetEventsRequest {
	return &pb.GetEventsRequest{
		AllowList: []*pb.Filter{
			{EventSet: append([]pb.EventType(nil), feedEventTypes...), ContainerId: []string{".+"}},
			{EventSet: append([]pb.EventType(nil), lossEventTypes...)},
		},
		FieldFilters: []*pb.FieldFilter{{
			EventSet: append([]pb.EventType(nil), feedEventTypes...),
			Fields:   &fieldmaskpb.FieldMask{Paths: append([]string(nil), feedExcluded...)},
			Action:   pb.FieldFilterAction_EXCLUDE,
		}},
	}
}

// EventStream is an open GetEvents stream.
type EventStream interface {
	Recv() (*pb.GetEventsResponse, error)
}

// Opener opens a Tetragon event stream; close ends it.
type Opener func(ctx context.Context) (stream EventStream, close func(), err error)

// OpenTetragon is the production Opener: a consume-scoped session (the
// version and the event stream; never a policy call) to the root-owned unix
// socket Tetragon's info file names, checked as the managed helper checks
// it.
func OpenTetragon(ctx context.Context) (EventStream, func(), error) {
	client, err := tetragon.Dial(ctx, tetragon.DialOptions{Scope: tetragon.ScopeConsume})
	if err != nil {
		return nil, nil, err
	}
	streamCtx, cancel := context.WithCancel(ctx)
	stream, err := client.Events(streamCtx, Request())
	if err != nil {
		cancel()
		_ = client.Close()
		return nil, nil, fmt.Errorf("%s: GetEvents: %w", tetragon.ReasonUnavailable, err)
	}
	return stream, func() { cancel(); _ = client.Close() }, nil
}

// Source pumps Tetragon's stream through the Mapper into the Hub, falling
// silent (and saying so in status frames) while Tetragon is down.
type Source struct {
	Mapper *Mapper
	Hub    *Hub
	// Open defaults to OpenTetragon.
	Open   Opener
	Logger *slog.Logger
	Now    func() time.Time
	// SummaryEvery paces the supervisor summaries (default one minute).
	SummaryEvery time.Duration

	loggedAt time.Time
}

// countersEvery paces the counters' log line.
const countersEvery = 10 * time.Minute

// Redial pacing while Tetragon is down.
const (
	redialFirst = 2 * time.Second
	redialMax   = time.Minute
)

// Run serves until ctx ends.
func (s *Source) Run(ctx context.Context) {
	if s.Open == nil {
		s.Open = OpenTetragon
	}
	if s.Logger == nil {
		s.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.SummaryEvery <= 0 {
		s.SummaryEvery = time.Minute
	}
	wait := redialFirst
	for ctx.Err() == nil {
		stream, closeStream, err := s.Open(ctx)
		if err != nil {
			reason := tetragon.ReasonCode(err)
			if state, previous := s.Hub.Tetragon(); state != sandboxfeed.TetragonUnavailable || previous != reason {
				s.Logger.Warn("sandbox kernel feed: Tetragon is not available; retrying", "reason", reason, "error", err)
			}
			s.Hub.SetTetragon(sandboxfeed.TetragonUnavailable, reason)
			if !sleep(ctx, wait) {
				return
			}
			wait = min(2*wait, redialMax)
			continue
		}
		wait = redialFirst
		s.Hub.SetTetragon(sandboxfeed.TetragonConnected, "")
		s.Logger.Info("sandbox kernel feed: reading Tetragon's exec stream")
		err = s.pump(ctx, stream)
		closeStream()
		if ctx.Err() != nil {
			return
		}
		s.Logger.Warn("sandbox kernel feed: Tetragon's stream ended; redialling", "error", err)
		s.Hub.SetTetragon(sandboxfeed.TetragonUnavailable, tetragon.ReasonUnavailable)
		if !sleep(ctx, redialFirst) {
			return
		}
	}
}

// pump reads one stream until it ends.
func (s *Source) pump(ctx context.Context, stream EventStream) error {
	type received struct {
		response *pb.GetEventsResponse
		err      error
	}
	responses := make(chan received, 256)
	go func() {
		for {
			response, err := stream.Recv()
			select {
			case responses <- received{response, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	ticker := time.NewTicker(s.SummaryEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.flush()
		case r := <-responses:
			if r.err != nil {
				s.flush()
				return r.err
			}
			s.handle(ctx, r.response)
		}
	}
}

func (s *Source) handle(ctx context.Context, response *pb.GetEventsResponse) {
	switch event := response.GetEvent().(type) {
	case *pb.GetEventsResponse_ProcessThrottle:
		if event.ProcessThrottle.GetType() == pb.ThrottleType_THROTTLE_START {
			s.Hub.Lost(1)
		}
		return
	case *pb.GetEventsResponse_RateLimitInfo:
		s.Hub.Lost(int64(event.RateLimitInfo.GetNumberOfDroppedProcessEvents()))
		return
	}
	for _, item := range s.Mapper.Map(ctx, response) {
		s.Hub.Publish(item)
	}
}

// flush sends the supervisor summaries and, every ten minutes, logs the
// counters (the in-sandbox pid capture rate is pinned / execs).
func (s *Source) flush() {
	now := s.Now()
	for _, item := range s.Mapper.Summaries(now) {
		s.Hub.Publish(item)
	}
	if now.Sub(s.loggedAt) < countersEvery {
		return
	}
	s.loggedAt = now
	stats := s.Mapper.Stats()
	s.Logger.Info("sandbox kernel feed counters", "execs", stats.Execs, "pinned", stats.Pinned, "reused", stats.Reused,
		"supervisor_execs", stats.Supervisor, "runtime_execs", stats.Runtime, "other_execs", stats.Other, "readers", s.Hub.Subscribers())
}

func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
