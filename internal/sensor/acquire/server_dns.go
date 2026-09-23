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
	"net"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/dnscapture"
)

// dnsStreamFrame is one frame on an OpDNS subscription: the mechanism
// header, then observed answers.
type dnsStreamFrame struct {
	Mechanism string `json:"mechanism,omitempty"`
	Address   string `json:"address,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
}

// serveDNS streams observed DNS answers.
//
// Naming a peer from the answer this host actually resolved is a direct
// observation; naming it from a PTR record is a guess made by whoever
// controls the address. The difference is worth a privileged socket, and
// without brokering it a sandboxed gateway could never report full
// coverage no matter how much else the helper supplied.
//
// Only the address-to-hostname pair crosses. The helper is observing every
// DNS answer on the host, and the client has no business seeing queries it
// did not need -- so the projection is exactly what peer naming consumes.
func (s *Server) serveDNS(ctx context.Context, conn net.Conn, request Request) {
	capturer := dnscapture.New()
	cache := dnscapture.NewCache()
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := capturer.Start(streamCtx, cache); err != nil {
		_ = writeFrame(conn, Response{
			Version: protocolVersion, Op: request.Op, Error: err.Error(),
		}, responseDeadline)
		return
	}
	defer capturer.Close()

	header, err := json.Marshal(dnsStreamFrame{Mechanism: capturer.Mechanism()})
	if err != nil {
		return
	}
	if err := writeFrame(conn, Response{
		Version: protocolVersion, Op: request.Op, Body: header,
	}, responseDeadline); err != nil {
		return
	}

	go func() {
		var scratch [1]byte
		_ = conn.SetReadDeadline(time.Time{})
		_, _ = conn.Read(scratch[:])
		cancel()
	}()

	// The capturer writes into a cache rather than exposing a channel, so
	// the stream is a differential poll of that cache. A tick is cheap and
	// peer naming is not latency-critical: a name that arrives one second
	// after the connection is still the name.
	ticker := time.NewTicker(dnsStreamInterval)
	defer ticker.Stop()
	sent := make(map[string]string, 256)
	for {
		select {
		case <-streamCtx.Done():
			return
		case <-ticker.C:
			for address, hostname := range cache.Entries() {
				if previous, ok := sent[address]; ok && previous == hostname {
					continue
				}
				body, err := json.Marshal(dnsStreamFrame{
					Address: address, Hostname: hostname,
				})
				if err != nil {
					continue
				}
				if err := writeFrame(conn, Response{
					Version: protocolVersion, Op: request.Op, Body: body,
				}, responseDeadline); err != nil {
					return
				}
				sent[address] = hostname
				if len(sent) > dnsStreamMemory {
					// Bounded: the helper must not grow a map for every
					// address the host ever resolved.
					sent = map[string]string{address: hostname}
				}
			}
		}
	}
}

// dnsStreamInterval is how often observed answers are forwarded.
const dnsStreamInterval = time.Second

// dnsStreamMemory bounds what the stream remembers having sent.
const dnsStreamMemory = 8192
