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

//go:build linux

package dnscapture

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

// ethPAll is ETH_P_ALL in network byte order, the protocol an AF_PACKET socket
// binds to in order to see every frame.
const ethPAll = 0x0003

// linuxCapturer reads DNS answers off an AF_PACKET socket.
//
// AF_PACKET rather than shelling out to tcpdump: a privileged service spawning
// a packet sniffer as a subprocess is a worse shape than opening the socket
// itself, and it removes a runtime dependency the sensor would otherwise have
// to detect and report on.
//
// An attached BPF filter narrows delivery to UDP port 53 in the kernel, so an
// idle host costs nothing and a busy one does not copy every frame to
// userspace.
type linuxCapturer struct {
	fd     int
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// New returns the Linux DNS capturer.
func New() Capturer { return &linuxCapturer{fd: -1} }

func (c *linuxCapturer) Mechanism() string { return "AF_PACKET with a UDP/53 BPF filter" }

func (c *linuxCapturer) Start(ctx context.Context, cache *Cache) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(hostToNetworkShort(ethPAll)))
	if err != nil {
		return fmt.Errorf("dnscapture: AF_PACKET socket: %w "+
			"(packet capture needs CAP_NET_RAW; run the gateway elevated or disable dns_capture)", err)
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, dnsFilter()); err != nil {
		// Without the filter every frame on the host reaches userspace. That
		// is a cost the operator did not agree to, so refuse rather than
		// silently capturing everything.
		_ = unix.Close(fd)
		return fmt.Errorf("dnscapture: attach BPF filter: %w", err)
	}
	c.fd = fd
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.read(ctx, cache) }()
	go func() { <-ctx.Done(); _ = c.Close() }()
	return nil
}

func (c *linuxCapturer) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	fd := c.fd
	c.fd = -1
	c.mu.Unlock()
	if fd >= 0 {
		_ = unix.Close(fd)
	}
	c.wg.Wait()
	return nil
}

func (c *linuxCapturer) read(ctx context.Context, cache *Cache) {
	buffer := make([]byte, 65536)
	for {
		if ctx.Err() != nil {
			return
		}
		c.mu.Lock()
		fd := c.fd
		c.mu.Unlock()
		if fd < 0 {
			return
		}
		read, _, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}
		for _, found := range decodeEthernetDNS(buffer[:read]) {
			cache.Record(found.address, found.name)
		}
	}
}

// dnsFilter is a classic BPF program selecting UDP source port 53 over IPv4 or
// IPv6, which is where answers come from.
//
// Written out rather than generated because it is short, fixed, and its
// correctness is easier to review as instructions than as a compiler.
func dnsFilter() *unix.SockFprog {
	const (
		ldAbsH = unix.BPF_LD | unix.BPF_H | unix.BPF_ABS
		ldAbsB = unix.BPF_LD | unix.BPF_B | unix.BPF_ABS
		jeqK   = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		retK   = unix.BPF_RET | unix.BPF_K
	)
	instructions := []unix.SockFilter{
		// Ethernet type at offset 12.
		{Code: ldAbsH, K: 12},
		{Code: jeqK, Jt: 0, Jf: 5, K: 0x0800}, // IPv4 -> continue, else try IPv6
		// IPv4: protocol at 23 must be UDP, source port at 34 must be 53.
		{Code: ldAbsB, K: 23},
		{Code: jeqK, Jt: 0, Jf: 8, K: 17},
		{Code: ldAbsH, K: 34},
		{Code: jeqK, Jt: 5, Jf: 6, K: 53},
		// IPv6: next header at 20 must be UDP, source port at 54 must be 53.
		{Code: jeqK, Jt: 0, Jf: 5, K: 0x86DD},
		{Code: ldAbsB, K: 20},
		{Code: jeqK, Jt: 0, Jf: 3, K: 17},
		{Code: ldAbsH, K: 54},
		{Code: jeqK, Jt: 0, Jf: 1, K: 53},
		{Code: retK, K: 65535},
		{Code: retK, K: 0},
	}
	return &unix.SockFprog{
		Len:    uint16(len(instructions)),
		Filter: &instructions[0],
	}
}

func hostToNetworkShort(value uint16) uint16 {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], value)
	return binary.LittleEndian.Uint16(raw[:])
}

// decodeEthernetDNS strips the link, network, and transport headers and hands
// the payload to the DNS decoder. Every length is checked because the frame is
// attacker-influenced.
func decodeEthernetDNS(frame []byte) []answer {
	const ethernetHeader = 14
	if len(frame) < ethernetHeader {
		return nil
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	payload := frame[ethernetHeader:]

	switch etherType {
	case 0x0800: // IPv4
		if len(payload) < 20 {
			return nil
		}
		headerLen := int(payload[0]&0x0F) * 4
		if headerLen < 20 || len(payload) < headerLen+8 || payload[9] != 17 {
			return nil
		}
		return decodeUDP(payload[headerLen:])
	case 0x86DD: // IPv6
		if len(payload) < 40 || payload[6] != 17 {
			return nil
		}
		return decodeUDP(payload[40:])
	}
	return nil
}

func decodeUDP(segment []byte) []answer {
	const udpHeader = 8
	if len(segment) < udpHeader {
		return nil
	}
	if binary.BigEndian.Uint16(segment[0:2]) != 53 {
		return nil
	}
	return decodeAnswers(segment[udpHeader:])
}
