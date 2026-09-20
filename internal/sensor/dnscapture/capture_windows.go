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

//go:build windows

package dnscapture

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dnsChannel is the DNS client's operational channel. Event 3008 records a
// completed query with the answers the resolver returned.
//
// This rather than a raw packet capture: Windows has no AF_PACKET, npcap is a
// third-party driver the sensor will not require, and the DNS client already
// publishes exactly the fact needed -- the name and the addresses it resolved
// to -- with no protocol parsing and no risk of capturing anything else.
const (
	dnsChannel      = "Microsoft-Windows-DNS-Client/Operational"
	dnsQueryEventID = 3008
	pollInterval    = 2 * time.Second
)

var dnsQuery = fmt.Sprintf("*[System[(EventID=%d)]]", dnsQueryEventID)

var (
	modWevtapi    = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = modWevtapi.NewProc("EvtQuery")
	procEvtNext   = modWevtapi.NewProc("EvtNext")
	procEvtRender = modWevtapi.NewProc("EvtRender")
	procEvtClose  = modWevtapi.NewProc("EvtClose")
	procEvtSeek   = modWevtapi.NewProc("EvtSeek")
)

const (
	evtQueryChannelPath   = 0x1
	evtQueryForwardDir    = 0x100
	evtRenderEventXML     = 1
	evtSeekRelativeToLast = 0x2
)

type windowsCapturer struct {
	handle windows.Handle
	mu     sync.Mutex
	closed bool
	stop   chan struct{}
	wg     sync.WaitGroup
}

// New returns the Windows DNS capturer.
func New() Capturer { return &windowsCapturer{stop: make(chan struct{})} }

func (c *windowsCapturer) Mechanism() string {
	return "Microsoft-Windows-DNS-Client/Operational (event 3008)"
}

func (c *windowsCapturer) Start(ctx context.Context, cache *Cache) error {
	handle, err := openDNSQuery()
	if err != nil {
		return fmt.Errorf("dnscapture: %s unreadable: %w "+
			"(enable the channel with: wevtutil sl %s /e:true)", dnsChannel, err, dnsChannel)
	}
	// Skip the backlog. Replaying yesterday's resolutions would attribute
	// addresses that have since been reassigned.
	_, _, _ = procEvtSeek.Call(uintptr(handle), 0, 0, 0, evtSeekRelativeToLast)
	c.handle = handle

	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.drain(ctx, cache) }()
	go func() { <-ctx.Done(); _ = c.Close() }()
	return nil
}

func (c *windowsCapturer) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.stop)
	c.mu.Unlock()
	c.wg.Wait()
	return nil
}

func openDNSQuery() (windows.Handle, error) {
	channel, err := windows.UTF16PtrFromString(dnsChannel)
	if err != nil {
		return 0, err
	}
	query, err := windows.UTF16PtrFromString(dnsQuery)
	if err != nil {
		return 0, err
	}
	handle, _, callErr := procEvtQuery.Call(
		0, uintptr(unsafe.Pointer(channel)), uintptr(unsafe.Pointer(query)),
		uintptr(evtQueryChannelPath|evtQueryForwardDir),
	)
	if handle == 0 {
		return 0, callErr
	}
	return windows.Handle(handle), nil
}

func (c *windowsCapturer) drain(ctx context.Context, cache *Cache) {
	defer procEvtClose.Call(uintptr(c.handle))
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stop:
			return
		case <-ticker.C:
		}
		for {
			events, ok := nextEvents(c.handle, 32, 100)
			if !ok || len(events) == 0 {
				break
			}
			for _, raw := range events {
				for _, found := range decodeDNSClientEvent(raw) {
					cache.Record(found.address, found.name)
				}
			}
		}
	}
}

func nextEvents(handle windows.Handle, count, timeoutMS int) ([]string, bool) {
	handles := make([]windows.Handle, count)
	var returned uint32
	ret, _, _ := procEvtNext.Call(
		uintptr(handle), uintptr(count), uintptr(unsafe.Pointer(&handles[0])),
		uintptr(timeoutMS), 0, uintptr(unsafe.Pointer(&returned)),
	)
	if ret == 0 {
		return nil, false
	}
	rendered := make([]string, 0, returned)
	for index := 0; index < int(returned); index++ {
		if text, err := renderEvent(handles[index]); err == nil {
			rendered = append(rendered, text)
		}
		procEvtClose.Call(uintptr(handles[index]))
	}
	return rendered, true
}

func renderEvent(event windows.Handle) (string, error) {
	var used, properties uint32
	procEvtRender.Call(0, uintptr(event), evtRenderEventXML, 0, 0,
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&properties)))
	if used == 0 {
		return "", fmt.Errorf("dnscapture: EvtRender reported a zero-length event")
	}
	buffer := make([]uint16, (used/2)+1)
	ret, _, callErr := procEvtRender.Call(
		0, uintptr(event), evtRenderEventXML, uintptr(used),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&properties)),
	)
	if ret == 0 {
		return "", callErr
	}
	return windows.UTF16ToString(buffer), nil
}

type dnsRecord struct {
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

func (r dnsRecord) field(name string) string {
	for _, entry := range r.Data {
		if strings.EqualFold(entry.Name, name) {
			return entry.Value
		}
	}
	return ""
}

// decodeDNSClientEvent extracts the answers from one event 3008.
//
// QueryResults is a ';'-separated list whose entries are either bare addresses
// or "type::address" pairs, and it can carry CNAME targets alongside the
// addresses. Only entries that parse as an IP are recorded, so a CNAME chain
// contributes its addresses and nothing that is not one.
func decodeDNSClientEvent(raw string) []answer {
	var record dnsRecord
	if err := xml.Unmarshal([]byte(raw), &record); err != nil {
		return nil
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(record.field("QueryName")), "."))
	if name == "" {
		return nil
	}
	results := make([]answer, 0, 4)
	for _, part := range strings.Split(record.field("QueryResults"), ";") {
		candidate := strings.TrimSpace(part)
		if candidate == "" {
			continue
		}
		if index := strings.LastIndex(candidate, "::"); index >= 0 {
			candidate = strings.TrimSpace(candidate[index+2:])
		}
		if parsed := net.ParseIP(candidate); parsed != nil {
			results = append(results, answer{name: name, address: parsed.String()})
		}
	}
	return results
}
