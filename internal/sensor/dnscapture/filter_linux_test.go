// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package dnscapture

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// runFilter interprets the classic-BPF program against one frame and returns
// the accepted byte count.
//
// Reading jump offsets by eye is exactly how the bug this covers survived
// review: Jf counts instructions after the next one, so an off-by-one lands
// on a plausible-looking instruction rather than erroring. Execute it instead.
func runFilter(t *testing.T, program []unix.SockFilter, frame []byte) uint32 {
	t.Helper()
	load := func(offset uint32, width int) (uint32, bool) {
		if int(offset)+width > len(frame) {
			// The kernel drops the packet on an out-of-range load.
			return 0, false
		}
		switch width {
		case 1:
			return uint32(frame[offset]), true
		case 2:
			return uint32(frame[offset])<<8 | uint32(frame[offset+1]), true
		default:
			t.Fatalf("unsupported load width %d", width)
			return 0, false
		}
	}

	var accumulator uint32
	for pc := 0; pc < len(program); {
		if pc >= len(program) {
			t.Fatal("program counter ran past the end of the filter")
		}
		instruction := program[pc]
		switch instruction.Code {
		case unix.BPF_LD | unix.BPF_H | unix.BPF_ABS:
			value, ok := load(instruction.K, 2)
			if !ok {
				return 0
			}
			accumulator = value
			pc++
		case unix.BPF_LD | unix.BPF_B | unix.BPF_ABS:
			value, ok := load(instruction.K, 1)
			if !ok {
				return 0
			}
			accumulator = value
			pc++
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if accumulator == instruction.K {
				pc += 1 + int(instruction.Jt)
			} else {
				pc += 1 + int(instruction.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return instruction.K
		default:
			t.Fatalf("unhandled BPF opcode %#x at %d", instruction.Code, pc)
		}
	}
	t.Fatal("filter fell off the end without returning")
	return 0
}

func filterProgram(t *testing.T) []unix.SockFilter {
	t.Helper()
	program := dnsFilter()
	return unsafe.Slice(program.Filter, int(program.Len))
}

// frame builds an Ethernet frame with the given ethertype and the bytes that
// matter to the filter placed at the offsets it reads.
func frame(ethertype uint16, set map[int]byte) []byte {
	buffer := make([]byte, 64)
	buffer[12] = byte(ethertype >> 8)
	buffer[13] = byte(ethertype)
	for offset, value := range set {
		buffer[offset] = value
	}
	return buffer
}

// TestDNSFilterRejectsNonIPFramesThatLookLikeDNS is the regression this exists
// for. The IPv4 miss jumped past the IPv6 ethertype test to the IPv6
// next-header load, so any frame at all -- ARP, VLAN, anything -- was accepted
// whenever byte 20 held 17 and bytes 54-55 held 53. Those bytes carry no such
// meaning outside an IPv6 header, so arbitrary link-layer traffic reached a
// DNS parser.
func TestDNSFilterRejectsNonIPFramesThatLookLikeDNS(t *testing.T) {
	program := filterProgram(t)

	const (
		ipv4 = 0x0800
		ipv6 = 0x86DD
		arp  = 0x0806
		udp  = 17
	)
	dnsPortAt := func(offset int) map[int]byte {
		return map[int]byte{offset: 0, offset + 1: 53}
	}
	merge := func(maps ...map[int]byte) map[int]byte {
		out := map[int]byte{}
		for _, m := range maps {
			for k, v := range m {
				out[k] = v
			}
		}
		return out
	}

	for _, test := range []struct {
		name  string
		frame []byte
		want  bool
	}{
		{
			name:  "IPv4 UDP from port 53 is a DNS answer",
			frame: frame(ipv4, merge(map[int]byte{23: udp}, dnsPortAt(34))),
			want:  true,
		},
		{
			name:  "IPv6 UDP from port 53 is a DNS answer",
			frame: frame(ipv6, merge(map[int]byte{20: udp}, dnsPortAt(54))),
			want:  true,
		},
		{
			name:  "ARP carrying the IPv6 byte pattern must not be accepted",
			frame: frame(arp, merge(map[int]byte{20: udp}, dnsPortAt(54))),
			want:  false,
		},
		{
			name:  "an unknown ethertype with the IPv6 byte pattern must not be accepted",
			frame: frame(0x1234, merge(map[int]byte{20: udp}, dnsPortAt(54))),
			want:  false,
		},
		{
			name:  "IPv4 TCP from port 53 is not a DNS datagram",
			frame: frame(ipv4, merge(map[int]byte{23: 6}, dnsPortAt(34))),
			want:  false,
		},
		{
			name:  "IPv4 UDP from another port is not an answer",
			frame: frame(ipv4, merge(map[int]byte{23: udp}, map[int]byte{34: 0x1F, 35: 0x90})),
			want:  false,
		},
		{
			name:  "IPv6 with a non-UDP next header",
			frame: frame(ipv6, merge(map[int]byte{20: 6}, dnsPortAt(54))),
			want:  false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			accepted := runFilter(t, program, test.frame) > 0
			if accepted != test.want {
				t.Fatalf("accepted = %v, want %v", accepted, test.want)
			}
		})
	}
}

// TestDNSFilterJumpsStayInsideTheProgram guards the whole program against the
// class of error the ethertype jump was: a target that is a valid index but
// the wrong instruction is invisible, while one past the end is a load error.
func TestDNSFilterJumpsStayInsideTheProgram(t *testing.T) {
	program := filterProgram(t)
	for index, instruction := range program {
		if instruction.Code != unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K {
			continue
		}
		for name, offset := range map[string]uint8{"Jt": instruction.Jt, "Jf": instruction.Jf} {
			target := index + 1 + int(offset)
			if target >= len(program) {
				t.Errorf("instruction %d %s jumps to %d, past the %d-instruction program",
					index, name, target, len(program))
			}
		}
	}
}
