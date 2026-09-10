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

//go:build darwin

package dnscapture

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// maxBPFDevices is how many /dev/bpfN nodes to try. macOS creates them on
// demand up to a limit; another capture holding the low ones is ordinary.
const maxBPFDevices = 64

// darwinCapturer reads DNS answers from a BPF device.
//
// /dev/bpf rather than shelling out to tcpdump: tcpdump is itself a BPF
// consumer, and a privileged service spawning a sniffer as a subprocess is a
// worse shape than opening the device. It also removes a runtime dependency
// the sensor would otherwise have to detect and report on.
type darwinCapturer struct {
	fd         int
	bufferSize int
	device     string
	mu         sync.Mutex
	closed     bool
	wg         sync.WaitGroup
}

// New returns the macOS DNS capturer.
func New() Capturer { return &darwinCapturer{fd: -1} }

func (c *darwinCapturer) Mechanism() string {
	if c.device != "" {
		return "BPF (" + c.device + ") with a UDP/53 filter"
	}
	return "BPF with a UDP/53 filter"
}

func (c *darwinCapturer) Start(ctx context.Context, cache *Cache) error {
	iface := defaultInterface()
	if iface == "" {
		return fmt.Errorf("dnscapture: no non-loopback interface is up")
	}
	fd, device, err := openBPF()
	if err != nil {
		return fmt.Errorf("dnscapture: %w "+
			"(BPF devices are root-owned; run the gateway elevated or disable dns_capture)", err)
	}
	c.fd, c.device = fd, device

	if err := c.configure(iface); err != nil {
		_ = unix.Close(fd)
		c.fd = -1
		return err
	}
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.read(ctx, cache) }()
	go func() { <-ctx.Done(); _ = c.Close() }()
	return nil
}

func openBPF() (int, string, error) {
	var lastErr error
	for index := 0; index < maxBPFDevices; index++ {
		device := "/dev/bpf" + strconv.Itoa(index)
		fd, err := unix.Open(device, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			return fd, device, nil
		}
		lastErr = err
		if err != unix.EBUSY {
			// A permission failure will repeat on every node, so stop rather
			// than making 64 identical syscalls.
			if err == unix.EACCES || err == unix.EPERM {
				break
			}
		}
	}
	return -1, "", fmt.Errorf("no BPF device could be opened: %w", lastErr)
}

func (c *darwinCapturer) configure(iface string) error {
	// The buffer size must be set before the interface is bound.
	bufferSize := 1 << 20
	if err := ioctlInt(c.fd, unix.BIOCSBLEN, &bufferSize); err != nil {
		return fmt.Errorf("dnscapture: BIOCSBLEN: %w", err)
	}
	c.bufferSize = bufferSize

	var request ifreq
	copy(request.Name[:], iface)
	if err := ioctlPtr(c.fd, unix.BIOCSETIF, unsafe.Pointer(&request)); err != nil {
		return fmt.Errorf("dnscapture: BIOCSETIF %s: %w", iface, err)
	}
	// Immediate mode: deliver each packet rather than waiting for the buffer
	// to fill, so a name is cached before the connection using it is polled.
	enable := 1
	if err := ioctlInt(c.fd, unix.BIOCIMMEDIATE, &enable); err != nil {
		return fmt.Errorf("dnscapture: BIOCIMMEDIATE: %w", err)
	}
	// Read-only: this must never be able to inject a frame.
	seeSent := 0
	_ = ioctlInt(c.fd, unix.BIOCSSEESENT, &seeSent)

	if err := c.attachFilter(); err != nil {
		return err
	}
	return nil
}

// attachFilter narrows delivery to UDP source port 53 in the kernel. Without
// it every frame on the interface is copied to userspace, which is a cost the
// operator did not agree to.
func (c *darwinCapturer) attachFilter() error {
	instructions := bpfProgram()
	program := struct {
		Len    uint32
		_      [4]byte
		Filter *unix.BpfInsn
	}{Len: uint32(len(instructions)), Filter: &instructions[0]}
	if err := ioctlPtr(c.fd, unix.BIOCSETF, unsafe.Pointer(&program)); err != nil {
		return fmt.Errorf("dnscapture: BIOCSETF: %w", err)
	}
	return nil
}

func bpfProgram() []unix.BpfInsn {
	const (
		ldAbsH = unix.BPF_LD | unix.BPF_H | unix.BPF_ABS
		ldAbsB = unix.BPF_LD | unix.BPF_B | unix.BPF_ABS
		jeqK   = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		retK   = unix.BPF_RET | unix.BPF_K
	)
	return []unix.BpfInsn{
		{Code: ldAbsH, K: 12},
		// IPv4? On a miss, jump to the IPv6 ethertype test at index 6, not
		// past it. Jf counts instructions *after* the next one, so this is
		// 6-(1+1)=4; the earlier 5 landed on the IPv6 next-header load and
		// skipped the ethertype check, letting any non-IP frame through
		// whenever byte 20 happened to be 17 and bytes 54-55 happened to be
		// port 53.
		{Code: jeqK, Jt: 0, Jf: 4, K: 0x0800},
		{Code: ldAbsB, K: 23},
		{Code: jeqK, Jt: 0, Jf: 8, K: 17},
		{Code: ldAbsH, K: 34},
		{Code: jeqK, Jt: 5, Jf: 6, K: 53},
		{Code: jeqK, Jt: 0, Jf: 5, K: 0x86DD},
		{Code: ldAbsB, K: 20},
		{Code: jeqK, Jt: 0, Jf: 3, K: 17},
		{Code: ldAbsH, K: 54},
		{Code: jeqK, Jt: 0, Jf: 1, K: 53},
		{Code: retK, K: 65535},
		{Code: retK, K: 0},
	}
}

type ifreq struct {
	Name [16]byte
	_    [16]byte
}

func ioctlInt(fd int, request uint, value *int) error {
	return ioctlPtr(fd, request, unsafe.Pointer(value))
}

func ioctlPtr(fd int, request uint, argument unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(argument))
	if errno != 0 {
		return errno
	}
	return nil
}

func (c *darwinCapturer) Close() error {
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

func (c *darwinCapturer) read(ctx context.Context, cache *Cache) {
	buffer := make([]byte, c.bufferSize)
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
		read, err := unix.Read(fd, buffer)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}
		for _, found := range decodeBPFBuffer(buffer[:read]) {
			cache.Record(found.address, found.name)
		}
	}
}

// bpfHdrLen is sizeof(struct bpf_hdr) on 64-bit Darwin: two 8-byte timeval
// halves, caplen, datalen, and a 2-byte header length with padding.
const bpfHdrLen = 20

// decodeBPFBuffer walks the packet records in one BPF read. A single read
// returns several packets, each preceded by a header and padded to a
// word boundary.
func decodeBPFBuffer(data []byte) []answer {
	results := make([]answer, 0, 4)
	offset := 0
	for offset+bpfHdrLen <= len(data) {
		capLen := int(binary.LittleEndian.Uint32(data[offset+8:]))
		headerLen := int(binary.LittleEndian.Uint16(data[offset+16:]))
		if headerLen < bpfHdrLen || capLen < 0 {
			return results
		}
		start := offset + headerLen
		end := start + capLen
		if end > len(data) {
			return results
		}
		results = append(results, decodeEthernetDNS(data[start:end])...)
		// BPF_WORDALIGN
		offset = (start + capLen + 3) &^ 3
		if offset <= start {
			return results
		}
	}
	return results
}

// decodeEthernetDNS strips the link, network, and transport headers.
func decodeEthernetDNS(frame []byte) []answer {
	const ethernetHeader = 14
	if len(frame) < ethernetHeader {
		return nil
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	payload := frame[ethernetHeader:]
	switch etherType {
	case 0x0800:
		if len(payload) < 20 {
			return nil
		}
		headerLen := int(payload[0]&0x0F) * 4
		if headerLen < 20 || len(payload) < headerLen+8 || payload[9] != 17 {
			return nil
		}
		return decodeUDP(payload[headerLen:])
	case 0x86DD:
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

// defaultInterface picks the first non-loopback interface that is up and has
// an address.
//
// BPF binds to one interface, so this is a real choice rather than a detail: a
// host with a VPN and a physical NIC resolves DNS over whichever the route
// picks, and binding the wrong one captures nothing. Preferring the first
// up-with-address interface matches what the routing table would use in the
// common case; an operator on a multi-homed host who needs another one
// disables dns_capture and relies on catalog attribution.
func defaultInterface() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, candidate := range interfaces {
		if candidate.Flags&net.FlagUp == 0 || candidate.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := candidate.Addrs()
		if err != nil || len(addresses) == 0 {
			continue
		}
		return candidate.Name
	}
	return ""
}
