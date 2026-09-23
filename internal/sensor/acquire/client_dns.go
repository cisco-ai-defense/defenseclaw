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

	"github.com/defenseclaw/defenseclaw/internal/sensor/dnscapture"
)

// brokeredCapturer receives observed DNS answers from the helper.
//
// Without this a brokered deployment could never report full coverage: a
// peer named from the answer the host actually resolved is a direct
// observation, and one named from a PTR record is a guess made by whoever
// controls the address. Leaving that unbrokered would have meant a managed
// install permanently one line short of complete, for a capability the
// helper already holds.
type brokeredCapturer struct {
	helper *Helper

	mu        sync.Mutex
	mechanism string
	conn      net.Conn
	closed    bool
	wg        sync.WaitGroup
}

// Start opens the subscription and reads the mechanism header.
func (c *brokeredCapturer) Start(ctx context.Context, cache *dnscapture.Cache) error {
	conn, err := c.helper.dialer(ctx)
	if err != nil {
		return err
	}
	if err := writeFrame(conn, Request{
		Version: protocolVersion, Op: OpDNS,
	}, requestDeadline); err != nil {
		_ = conn.Close()
		return err
	}
	var header Response
	if err := readFrame(conn, &header, responseDeadline); err != nil {
		_ = conn.Close()
		return fmt.Errorf("acquire: read dns stream header: %w", err)
	}
	if header.Error != "" {
		_ = conn.Close()
		return fmt.Errorf("acquire: helper refused dns capture: %s", header.Error)
	}
	var frame dnsStreamFrame
	if err := json.Unmarshal(header.Body, &frame); err != nil || frame.Mechanism == "" {
		_ = conn.Close()
		return errors.New("acquire: helper opened a dns stream without naming its mechanism")
	}

	c.mu.Lock()
	c.conn = conn
	c.mechanism = frame.Mechanism + " (via the sensor helper)"
	c.mu.Unlock()

	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.drain(ctx, conn, cache) }()
	return nil
}

func (c *brokeredCapturer) drain(ctx context.Context, conn net.Conn, cache *dnscapture.Cache) {
	for {
		if ctx.Err() != nil {
			return
		}
		var response Response
		// A host that resolves nothing for a while is normal, so silence is
		// not a failure and carries no deadline.
		_ = conn.SetReadDeadline(time.Time{})
		if err := readFrame(conn, &response, 0); err != nil {
			return
		}
		if response.Error != "" {
			return
		}
		var frame dnsStreamFrame
		if err := json.Unmarshal(response.Body, &frame); err != nil {
			continue
		}
		if frame.Address != "" && frame.Hostname != "" {
			cache.Record(frame.Address, frame.Hostname)
		}
	}
}

// Mechanism names what is capturing, annotated so an operator can see the
// observation happened out of process.
func (c *brokeredCapturer) Mechanism() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mechanism == "" {
		return "sensor helper (not started)"
	}
	return c.mechanism
}

// Close ends the subscription.
func (c *brokeredCapturer) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	c.wg.Wait()
	return nil
}
