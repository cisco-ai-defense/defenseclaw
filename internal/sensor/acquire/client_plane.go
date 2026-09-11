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

package acquire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// helperPlaneSource is Plane C delivered over the broker.
//
// It holds one long-lived connection: the helper writes a coverage frame,
// then events until either side goes away. Reconnection is deliberately not
// automatic -- a dropped privileged stream is a coverage change the operator
// should see reported, not one this layer papers over.
type helperPlaneSource struct {
	helper *Helper
	buffer *plane.Buffer

	mu       sync.Mutex
	coverage plane.Coverage
	conn     net.Conn
	closed   bool
	wg       sync.WaitGroup
}

// Start opens the subscription and reads the coverage frame.
func (s *helperPlaneSource) Start(ctx context.Context) error {
	conn, err := s.helper.dialer(ctx)
	if err != nil {
		return err
	}
	if err := writeFrame(conn, Request{
		Version: protocolVersion, Op: OpEvents,
	}, requestDeadline); err != nil {
		_ = conn.Close()
		return err
	}
	var header Response
	if err := readFrame(conn, &header, responseDeadline); err != nil {
		_ = conn.Close()
		return fmt.Errorf("acquire: read event stream header: %w", err)
	}
	if header.Error != "" {
		_ = conn.Close()
		return fmt.Errorf("acquire: helper refused the event stream: %s", header.Error)
	}
	var frame eventStreamFrame
	if err := json.Unmarshal(header.Body, &frame); err != nil || frame.Coverage == nil {
		_ = conn.Close()
		return errors.New("acquire: helper opened an event stream without stating its coverage")
	}

	s.mu.Lock()
	s.conn = conn
	s.coverage = decodeCoverage(*frame.Coverage)
	s.mu.Unlock()

	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.drain(ctx, conn) }()
	return nil
}

// drain reads event frames until the stream ends.
func (s *helperPlaneSource) drain(ctx context.Context, conn net.Conn) {
	defer s.buffer.Close()
	for {
		if ctx.Err() != nil {
			return
		}
		var response Response
		// No read deadline: a quiet host legitimately produces no events for
		// a long time, and treating silence as failure would drop a working
		// stream precisely when there is nothing to report.
		_ = conn.SetReadDeadline(time.Time{})
		if err := readFrame(conn, &response, 0); err != nil {
			return
		}
		if response.Error != "" {
			return
		}
		var frame eventStreamFrame
		if err := json.Unmarshal(response.Body, &frame); err != nil || frame.Event == nil {
			continue
		}
		s.buffer.Push(decodeEvent(*frame.Event))
	}
}

// Events is the delivery channel.
func (s *helperPlaneSource) Events() <-chan plane.Event { return s.buffer.Events() }

// Coverage reports what the helper said it was delivering, annotated so an
// operator can see the acquisition ran out of process.
func (s *helperPlaneSource) Coverage() plane.Coverage {
	s.mu.Lock()
	defer s.mu.Unlock()
	coverage := s.coverage
	if coverage.Mechanism != "" {
		coverage.Mechanism += " (via the sensor helper)"
	}
	return coverage
}

// Close ends the subscription.
func (s *helperPlaneSource) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	conn := s.conn
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	s.wg.Wait()
	return nil
}
