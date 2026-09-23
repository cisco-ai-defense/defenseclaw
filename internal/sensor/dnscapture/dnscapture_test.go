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

package dnscapture

import (
	"strings"
	"testing"
	"time"
)

// buildResponse assembles a DNS response with one question and the given
// answers, so the decoder is exercised against real wire bytes rather than a
// mock.
func buildResponse(question string, answers []answer, compress bool) []byte {
	packet := []byte{
		0x12, 0x34, // id
		0x81, 0x80, // response, recursion available, rcode 0
		0x00, 0x01, // qdcount
		0x00, 0x00, // ancount, filled below
		0x00, 0x00, 0x00, 0x00,
	}
	packet[6] = byte(len(answers) >> 8)
	packet[7] = byte(len(answers))

	questionOffset := len(packet)
	packet = append(packet, encodeName(question)...)
	packet = append(packet, 0x00, 0x01, 0x00, 0x01) // type A, class IN

	for _, entry := range answers {
		if compress {
			packet = append(packet, 0xC0, byte(questionOffset))
		} else {
			packet = append(packet, encodeName(entry.name)...)
		}
		if strings.Contains(entry.address, ":") {
			packet = append(packet, 0x00, 0x1C) // AAAA
		} else {
			packet = append(packet, 0x00, 0x01) // A
		}
		packet = append(packet, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C) // class, ttl
		raw := encodeAddress(entry.address)
		packet = append(packet, byte(len(raw)>>8), byte(len(raw)))
		packet = append(packet, raw...)
	}
	return packet
}

func encodeName(name string) []byte {
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0x00)
}

func encodeAddress(address string) []byte {
	if strings.Contains(address, ":") {
		return make([]byte, 16) // ::, sufficient for the length checks under test
	}
	out := make([]byte, 4)
	parts := strings.Split(address, ".")
	for index := 0; index < 4 && index < len(parts); index++ {
		value := 0
		for _, digit := range parts[index] {
			value = value*10 + int(digit-'0')
		}
		out[index] = byte(value)
	}
	return out
}

func TestDecodeAnswersReadsAAndAAAARecords(t *testing.T) {
	t.Parallel()
	payload := buildResponse("api.anthropic.com", []answer{
		{name: "api.anthropic.com", address: "104.18.0.1"},
		{name: "api.anthropic.com", address: "::"},
	}, false)
	got := decodeAnswers(payload)
	if len(got) != 2 {
		t.Fatalf("decoded %d answers, want 2: %+v", len(got), got)
	}
	if got[0].name != "api.anthropic.com" || got[0].address != "104.18.0.1" {
		t.Fatalf("first answer = %+v", got[0])
	}
	if got[1].address != "::" {
		t.Fatalf("IPv6 answer = %+v, want the canonical net.IP rendering", got[1])
	}
}

// TestDecodeFollowsCompressionPointers pins that the common wire form -- a
// pointer back to the question name -- resolves, since almost every real
// response uses it.
func TestDecodeFollowsCompressionPointers(t *testing.T) {
	t.Parallel()
	payload := buildResponse("api.openai.com", []answer{
		{name: "api.openai.com", address: "1.2.3.4"},
	}, true)
	got := decodeAnswers(payload)
	if len(got) != 1 || got[0].name != "api.openai.com" || got[0].address != "1.2.3.4" {
		t.Fatalf("decoded %+v", got)
	}
}

// TestDecodeIsTotalOnHostileInput is the property that matters most: the
// payload is attacker-influenced, so every malformed shape must yield nothing
// rather than panic or loop.
func TestDecodeIsTotalOnHostileInput(t *testing.T) {
	t.Parallel()
	valid := buildResponse("a.example", []answer{{name: "a.example", address: "9.9.9.9"}}, false)

	cases := map[string][]byte{
		"empty":                  {},
		"header only":            valid[:12],
		"truncated mid-name":     valid[:14],
		"truncated mid-answer":   valid[:len(valid)-2],
		"a query not a response": append([]byte{0x12, 0x34, 0x00, 0x00}, valid[4:]...),
		"self-referential pointer": {
			0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
			0xC0, 0x0C, // points at itself
			0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 1, 2, 3, 4,
		},
		"absurd answer count": {
			0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
		},
		"rdlength past the end": {
			0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x7F, 0xFF,
		},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			done := make(chan int, 1)
			go func() { done <- len(decodeAnswers(payload)) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("decodeAnswers did not terminate")
			}
		})
	}
}

func TestCacheExpiresRatherThanHoldingForever(t *testing.T) {
	t.Parallel()
	// An address held forever would eventually attribute an unrelated peer to
	// a provider, which is worse than not naming it.
	now := time.Unix(1_760_000_000, 0)
	cache := NewCache()
	cache.now = func() time.Time { return now }
	cache.Record("104.18.0.1", "API.Anthropic.COM.")

	hostname, ok := cache.Lookup("104.18.0.1")
	if !ok || hostname != "api.anthropic.com" {
		t.Fatalf("Lookup = %q, %t; the name should be normalised", hostname, ok)
	}
	now = now.Add(entryTTL + time.Second)
	if _, ok := cache.Lookup("104.18.0.1"); ok {
		t.Fatal("an expired entry was still served")
	}
}

func TestCacheIgnoresEmptyInput(t *testing.T) {
	t.Parallel()
	cache := NewCache()
	cache.Record("", "example.com")
	cache.Record("1.2.3.4", "")
	if cache.Observed() != 0 {
		t.Fatalf("Observed = %d, want 0", cache.Observed())
	}
}

func TestCacheIsBounded(t *testing.T) {
	t.Parallel()
	cache := NewCache()
	for index := 0; index < maxEntries+500; index++ {
		cache.Record("10.0."+itoa(byte(index/256))+"."+itoa(byte(index%256)), "host.example")
	}
	cache.mu.RLock()
	size := len(cache.entries)
	cache.mu.RUnlock()
	if size > maxEntries {
		t.Fatalf("cache holds %d entries, above the %d bound", size, maxEntries)
	}
}

func TestIPv6RenderingMatchesCanonicalForm(t *testing.T) {
	t.Parallel()
	// The rendering must match net.IP.String() or a lookup by the socket
	// table's address will miss.
	for _, test := range []struct {
		raw  []byte
		want string
	}{
		{make([]byte, 16), "::"},
		{[]byte{0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "2606:4700::1"},
		{[]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55},
			"fe80::211:22ff:fe33:4455"},
	} {
		if got := ipv6String(test.raw); got != test.want {
			t.Errorf("ipv6String = %q, want %q", got, test.want)
		}
	}
}
