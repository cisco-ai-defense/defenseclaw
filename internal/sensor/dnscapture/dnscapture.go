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

// Package dnscapture observes DNS answers so an egress peer is named from what
// the host actually resolved rather than inferred from its address.
//
// # Why this outranks reverse DNS
//
// A PTR record is controlled by whoever owns the address and frequently names
// infrastructure rather than the service; a catalog address index can be stale
// or shared. A captured answer is a direct observation of the name that
// produced the address the process then connected to, which is why it is
// weighted at full confidence and the other two are not.
//
// # What it does not do
//
// It reads only DNS answer sections: names and the addresses they resolved to.
// It parses no other protocol, retains no payload, and never associates a
// query with a process -- the pairing to a pid happens later, by address, in
// the egress plane.
package dnscapture

import (
	"context"
	"strings"
	"sync"
	"time"
)

// entryTTL bounds how long a captured answer is trusted.
//
// Provider addresses are shared and reassigned. A name held forever would
// eventually attribute an unrelated peer to a provider, which is worse than
// not naming it at all.
const entryTTL = 30 * time.Minute

// maxEntries bounds the table so a host resolving many names cannot grow it
// without limit.
const maxEntries = 8192

type entry struct {
	hostname string
	expires  time.Time
}

// readWakeInterval is how often a blocked packet read surfaces to re-check
// whether the capture is still wanted.
//
// Closing a capture descriptor does not reliably interrupt a goroutine
// already blocked reading it, so without this a quiet host -- no DNS traffic
// for a while, which is ordinary -- leaves Close waiting on a reader that
// never returns. Short enough that shutdown is prompt, long enough that the
// wakeups cost nothing.
const readWakeInterval = 2 * time.Second

// Cache maps an observed address to the name that resolved to it.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]entry
	now     func() time.Time
	// observed counts answers recorded, so an operator can tell a capture that
	// is running-but-silent from one that is working.
	observed int64
}

// NewCache returns an empty cache.
func NewCache() *Cache {
	return &Cache{entries: make(map[string]entry, 256), now: time.Now}
}

// Record stores one answer.
func (c *Cache) Record(address, hostname string) {
	address = strings.TrimSpace(address)
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	if address == "" || hostname == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= maxEntries {
		// Drop everything rather than evicting one. The cache is an
		// attribution aid, not state anything depends on, and a full clear is
		// bounded work where an LRU would be a structure to maintain for no
		// correctness gain.
		c.entries = make(map[string]entry, 256)
	}
	c.entries[address] = entry{hostname: hostname, expires: c.now().Add(entryTTL)}
	c.observed++
}

// Lookup returns the captured name for an address.
func (c *Cache) Lookup(address string) (string, bool) {
	c.mu.RLock()
	found, ok := c.entries[address]
	c.mu.RUnlock()
	if !ok || c.now().After(found.expires) {
		return "", false
	}
	return found.hostname, true
}

// Entries returns a copy of the unexpired address-to-hostname pairs.
//
// A copy, not the map: the caller iterates while capture keeps writing, and
// handing out the live map would race. Expired entries are skipped rather
// than deleted, leaving eviction to Record where the bound already lives.
func (c *Cache) Entries() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := c.now()
	out := make(map[string]string, len(c.entries))
	for address, found := range c.entries {
		if now.After(found.expires) {
			continue
		}
		out[address] = found.hostname
	}
	return out
}

// Observed is how many answers have been recorded.
func (c *Cache) Observed() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.observed
}

// Capturer is one platform's DNS observation.
type Capturer interface {
	// Start begins capture. An error names what the operator has to change.
	Start(ctx context.Context, cache *Cache) error
	// Mechanism names what is capturing, for the coverage report.
	Mechanism() string
	// Close stops capture.
	Close() error
}

// answer is one decoded DNS answer record.
type answer struct {
	name    string
	address string
}

// decodeAnswers extracts A and AAAA answers from a DNS response payload.
//
// Written against the wire format rather than a library because the sensor
// takes no third-party dependency for this, and because the parse must be
// total: a malformed or hostile packet has to yield nothing rather than panic
// or loop. Every offset is bounds-checked and pointer chasing is depth-capped.
func decodeAnswers(payload []byte) []answer {
	const headerLen = 12
	if len(payload) < headerLen {
		return nil
	}
	flags := uint16(payload[2])<<8 | uint16(payload[3])
	if flags&0x8000 == 0 {
		return nil // a query, not a response
	}
	if flags&0x000F != 0 {
		return nil // non-zero rcode: no usable answers
	}
	questions := int(uint16(payload[4])<<8 | uint16(payload[5]))
	answers := int(uint16(payload[6])<<8 | uint16(payload[7]))
	if answers <= 0 || answers > 64 {
		return nil
	}

	offset := headerLen
	for index := 0; index < questions; index++ {
		next, ok := skipName(payload, offset)
		if !ok || next+4 > len(payload) {
			return nil
		}
		offset = next + 4
	}

	results := make([]answer, 0, answers)
	// owner tracks the most recent decoded name so a CNAME chain attributes
	// its final address back to the name the process actually asked for.
	for index := 0; index < answers; index++ {
		name, next, ok := readName(payload, offset, 0)
		if !ok {
			return results
		}
		if next+10 > len(payload) {
			return results
		}
		recordType := uint16(payload[next])<<8 | uint16(payload[next+1])
		dataLen := int(uint16(payload[next+8])<<8 | uint16(payload[next+9]))
		dataStart := next + 10
		if dataLen < 0 || dataStart+dataLen > len(payload) {
			return results
		}
		switch recordType {
		case 1: // A
			if dataLen == 4 {
				results = append(results, answer{name: name, address: ipv4String(payload[dataStart : dataStart+4])})
			}
		case 28: // AAAA
			if dataLen == 16 {
				results = append(results, answer{name: name, address: ipv6String(payload[dataStart : dataStart+16])})
			}
		}
		offset = dataStart + dataLen
	}
	return results
}

// maxPointerDepth caps compression-pointer chasing. A packet can point at
// itself, and an uncapped decoder would spin forever on one hostile datagram.
const maxPointerDepth = 16

// maxNameBytes is the wire limit on a domain name (RFC 1035 s2.3.4). The
// depth cap alone does not bound the decoded name: sixteen levels of pointer,
// each contributing labels, can assemble a name of many kilobytes out of one
// 64KB frame. That string is cached per address and travels into telemetry
// fields the redaction profiles class as content, so an unbounded name is an
// amplification vector rather than merely a malformed one. A name over the
// limit cannot be legitimate, so it is refused rather than truncated.
const maxNameBytes = 255

// maxLabelBytes is the wire limit on a single label (RFC 1035 s2.3.4). The
// two high bits of a length byte are the label type: 00 is a literal label
// and 11 is a compression pointer. 01 and 10 are reserved and have never been
// assigned, so a decoder that treats them as literal lengths is accepting a
// packet no resolver would emit.
const maxLabelBytes = 63

func readName(payload []byte, offset, depth int) (string, int, bool) {
	if depth > maxPointerDepth {
		return "", 0, false
	}
	var builder strings.Builder
	cursor := offset
	afterPointer := -1
	for {
		if cursor >= len(payload) {
			return "", 0, false
		}
		length := int(payload[cursor])
		if length == 0 {
			cursor++
			break
		}
		if length&0xC0 == 0xC0 {
			if cursor+1 >= len(payload) {
				return "", 0, false
			}
			target := (length&0x3F)<<8 | int(payload[cursor+1])
			if afterPointer < 0 {
				afterPointer = cursor + 2
			}
			suffix, _, ok := readName(payload, target, depth+1)
			if !ok {
				return "", 0, false
			}
			if suffix != "" {
				if builder.Len()+1+len(suffix) > maxNameBytes {
					return "", 0, false
				}
				if builder.Len() > 0 {
					builder.WriteByte('.')
				}
				builder.WriteString(suffix)
			}
			cursor = afterPointer
			return strings.ToLower(builder.String()), cursor, true
		}
		if length > maxLabelBytes {
			// A reserved label type (01 or 10). Not a length.
			return "", 0, false
		}
		if cursor+1+length > len(payload) {
			return "", 0, false
		}
		if builder.Len()+1+length > maxNameBytes {
			return "", 0, false
		}
		if builder.Len() > 0 {
			builder.WriteByte('.')
		}
		builder.Write(payload[cursor+1 : cursor+1+length])
		cursor += 1 + length
	}
	if afterPointer >= 0 {
		cursor = afterPointer
	}
	return strings.ToLower(builder.String()), cursor, true
}

func skipName(payload []byte, offset int) (int, bool) {
	cursor := offset
	for {
		if cursor >= len(payload) {
			return 0, false
		}
		length := int(payload[cursor])
		if length == 0 {
			return cursor + 1, true
		}
		if length&0xC0 == 0xC0 {
			// The pointer is two bytes; the second must be present, or the
			// returned offset would name a position past the payload.
			if cursor+1 >= len(payload) {
				return 0, false
			}
			return cursor + 2, true
		}
		if length > maxLabelBytes {
			// A reserved label type (01 or 10). Skipping it as a length
			// would desynchronise the walk against the record that follows.
			return 0, false
		}
		cursor += 1 + length
	}
}

func ipv4String(raw []byte) string {
	return itoa(raw[0]) + "." + itoa(raw[1]) + "." + itoa(raw[2]) + "." + itoa(raw[3])
}

func itoa(value byte) string {
	switch {
	case value >= 100:
		return string([]byte{'0' + value/100, '0' + (value/10)%10, '0' + value%10})
	case value >= 10:
		return string([]byte{'0' + value/10, '0' + value%10})
	default:
		return string([]byte{'0' + value})
	}
}

const hexDigits = "0123456789abcdef"

// ipv6String renders the canonical net.IP form so a captured address is
// directly comparable to what the socket table reports.
func ipv6String(raw []byte) string {
	groups := make([]string, 8)
	for index := 0; index < 8; index++ {
		high, low := raw[index*2], raw[index*2+1]
		value := uint16(high)<<8 | uint16(low)
		if value == 0 {
			groups[index] = "0"
			continue
		}
		digits := []byte{
			hexDigits[(value>>12)&0xF], hexDigits[(value>>8)&0xF],
			hexDigits[(value>>4)&0xF], hexDigits[value&0xF],
		}
		trimmed := strings.TrimLeft(string(digits), "0")
		if trimmed == "" {
			trimmed = "0"
		}
		groups[index] = trimmed
	}
	return collapseZeroRun(groups)
}

// collapseZeroRun applies RFC 5952 :: compression to the longest zero run, so
// the rendering matches net.IP.String() and lookups by address hit.
func collapseZeroRun(groups []string) string {
	bestStart, bestLen, start, length := -1, 0, -1, 0
	for index := 0; index <= len(groups); index++ {
		if index < len(groups) && groups[index] == "0" {
			if start < 0 {
				start = index
			}
			length++
			continue
		}
		if length > bestLen {
			bestStart, bestLen = start, length
		}
		start, length = -1, 0
	}
	if bestLen < 2 {
		return strings.Join(groups, ":")
	}
	head := strings.Join(groups[:bestStart], ":")
	tail := strings.Join(groups[bestStart+bestLen:], ":")
	return head + "::" + tail
}
