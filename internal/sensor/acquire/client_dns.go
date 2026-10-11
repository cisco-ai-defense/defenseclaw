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
	// stop is closed by Close, so a wait between two subscriptions ends at
	// once instead of holding Close for the backoff.
	stop chan struct{}
	wg   sync.WaitGroup
}

// Start opens the subscription and reads the mechanism header.
func (c *brokeredCapturer) Start(ctx context.Context, cache *dnscapture.Cache) error {
	conn, mechanism, err := c.subscribe(ctx)
	if err != nil {
		return err
	}
	if !c.adopt(conn, mechanism) {
		_ = conn.Close()
		return errors.New("acquire: dns capture closed while starting")
	}
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.follow(ctx, conn, cache) }()
	return nil
}

// subscribe dials the helper and reads the dns stream header.
func (c *brokeredCapturer) subscribe(ctx context.Context) (net.Conn, string, error) {
	conn, err := c.helper.dialer(ctx)
	if err != nil {
		return nil, "", err
	}
	defer context.AfterFunc(ctx, func() { _ = conn.Close() })()
	if err := writeFrame(conn, Request{
		Version: protocolVersion, Op: OpDNS,
	}, requestDeadline); err != nil {
		_ = conn.Close()
		return nil, "", err
	}
	var header Response
	if err := readFrame(conn, &header, responseDeadline); err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("acquire: read dns stream header: %w", err)
	}
	if header.Error != "" {
		_ = conn.Close()
		return nil, "", fmt.Errorf("acquire: helper refused dns capture: %s", header.Error)
	}
	var frame dnsStreamFrame
	if err := json.Unmarshal(header.Body, &frame); err != nil || frame.Mechanism == "" {
		_ = conn.Close()
		return nil, "", errors.New("acquire: helper opened a dns stream without naming its mechanism")
	}
	return conn, frame.Mechanism + " (via the sensor helper)", nil
}

// adopt makes conn the subscription Close ends; false once Close has run.
func (c *brokeredCapturer) adopt(conn net.Conn, mechanism string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	if c.stop == nil {
		c.stop = make(chan struct{})
	}
	c.conn = conn
	c.mechanism = mechanism
	return true
}

// Bounds of the wait between two subscriptions after the helper's dns stream
// ended.
const (
	dnsResubscribeMin = time.Second
	dnsResubscribeMax = 30 * time.Second
)

// follow drains the subscription and, when the helper ends it (it restarts
// on every package upgrade and config push), subscribes again with a capped
// backoff until Close. A one-shot stream left the capture reporting itself
// running while it recorded nothing until the gateway restarted (GAP-1418).
func (c *brokeredCapturer) follow(ctx context.Context, conn net.Conn, cache *dnscapture.Cache) {
	c.mu.Lock()
	stop := c.stop
	c.mu.Unlock()
	backoff := dnsResubscribeMin
	for {
		c.drain(ctx, conn, cache)
		_ = conn.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-time.After(backoff):
			}
			backoff = min(2*backoff, dnsResubscribeMax)
			next, mechanism, err := c.subscribe(ctx)
			if err != nil {
				continue
			}
			if !c.adopt(next, mechanism) {
				_ = next.Close()
				return
			}
			conn, backoff = next, dnsResubscribeMin
			break
		}
	}
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
	if c.stop != nil {
		close(c.stop)
	}
	c.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	c.wg.Wait()
	return nil
}
