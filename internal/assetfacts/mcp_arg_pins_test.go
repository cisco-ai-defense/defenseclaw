// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// A claim that does not fit pins every argument up to maxPinArgs, not only the
// first maxArgs, and keeps them through another pass of the codec; the header
// still fits.
func TestMCPPinsCoverArgumentsPastTheFactBound(t *testing.T) {
	digest := "ab"
	for len(digest) < 64 {
		digest += "ab"
	}
	args := make([]string, maxPinArgs+100)
	for i := range args {
		args[i] = fmt.Sprintf("--argument-%d", i)
	}
	for _, count := range []int{maxArgs + 8, maxPinArgs, len(args)} {
		value := Encode(Facts{MCP: &MCPServer{Name: "notes", Command: "node", Args: args[:count], ProjectScope: true, Digest: digest}})
		facts, ok := Decode(value)
		if !ok || facts.MCP == nil || facts.MCP.Pins == nil {
			t.Fatalf("%d arguments: facts = %+v, want the pins", count, facts.MCP)
		}
		again, _ := Decode(Encode(facts))
		for _, pins := range []*MCPPins{facts.MCP.Pins, again.MCP.Pins} {
			want := min(count, maxPinArgs)
			if pins == nil || pins.ArgCount != count || len(pins.Args) != want {
				t.Fatalf("%d arguments: pins = %+v, want %d digests and the count", count, pins, want)
			}
			for _, i := range []int{0, maxArgs - 1, maxArgs, want - 1} {
				if pins.Args[i] != PinArgSum(args[i]) {
					t.Errorf("%d arguments: pin %d = %q, want the digest of %q", count, i, pins.Args[i], args[i])
				}
			}
		}
	}
}

// Arguments past the full digests are pinned by a digest as wide as the full
// ones, up to the bound, and survive another pass of the codec; the count is
// stated as is, past the bound, so an exact deny of a very long list is never
// ruled out by it.
func TestMCPPinsTailCoversArgumentsPastTheFullDigests(t *testing.T) {
	args := make([]string, maxPinArgs+maxTailPins+10)
	for i := range args {
		args[i] = fmt.Sprintf("--argument-%d", i)
	}
	server := &MCPServer{Name: "notes", Command: "node", Args: args, ProjectScope: true, Digest: strings.Repeat("ab", 32)}
	facts, ok := Decode(Encode(Facts{MCP: server}))
	if !ok || facts.MCP == nil || facts.MCP.Pins == nil {
		t.Fatalf("no pins: %+v", facts.MCP)
	}
	again, _ := Decode(Encode(facts))
	for _, pins := range []*MCPPins{facts.MCP.Pins, again.MCP.Pins} {
		tail := pins.TailBytes()
		if pins == nil || pins.ArgCount != len(args) || len(pins.Args) != maxPinArgs || len(tail) != maxTailPins*pinTailDigestLen {
			t.Fatalf("pins = %d count, %d digests, %d tail bytes", pins.ArgCount, len(pins.Args), len(tail))
		}
		for _, i := range []int{maxPinArgs, maxPinArgs + 1, maxPinArgs + maxTailPins - 1} {
			if !bytes.Equal(TailDigestAt(tail, i-maxPinArgs), PinTailDigest(args[i])) {
				t.Errorf("tail digest %d does not digest %q", i, args[i])
			}
		}
		if TailDigestAt(tail, maxTailPins) != nil || TailDigestAt(tail, -1) != nil {
			t.Error("a tail digest was returned past the ones the claim holds")
		}
	}
	over := make([]string, maxPinArgs+maxTailPins+1)
	for i := range over {
		over[i] = "--same"
	}
	big, _ := Decode(Encode(Facts{MCP: &MCPServer{Name: "notes", Command: "node", Args: over, ProjectScope: true, Digest: strings.Repeat("ab", 32)}}))
	if big.MCP == nil || big.MCP.Pins == nil || big.MCP.Pins.ArgCount != len(over) {
		t.Fatalf("the argument count was changed: %+v", big.MCP)
	}
}

// The allocation-free comparisons agree with the digests the claim holds.
func TestPinMatchesAgreeWithTheDigests(t *testing.T) {
	for _, value := range []string{"", "--same", "  padded  ", "café", strings.Repeat("x", 300)} {
		if !PinArgMatches(value, PinArgSum(value)) || PinArgMatches(value+"!", PinArgSum(value)) {
			t.Errorf("PinArgMatches disagrees with PinArgSum for %q", value)
		}
		if !PinTailMatches(value, PinTailDigest(value)) || PinTailMatches(value+"!", PinTailDigest(value)) {
			t.Errorf("PinTailMatches disagrees with PinTailDigest for %q", value)
		}
	}
	if PinArgMatches("a", "short") || PinTailMatches("a", nil) {
		t.Error("a malformed held digest matched")
	}
}
