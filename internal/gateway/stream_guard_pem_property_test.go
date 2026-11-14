// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"math/rand"
	"strings"
	"testing"
)

// pemPropertyPieces are the shapes a private-key tracker has to get right:
// header and footer lines of key and non-key labels, half lines, escaped
// line ends, prose. Keys come from the rule fixtures (syntheticPrivateKeyPEM).
func pemPropertyPieces(key string) []string {
	return []string{
		"-----BEGIN " + "CERTIFICATE" + "-----\n",
		"-----END " + "CERTIFICATE" + "-----\n",
		"-----END " + "RSA PRIVATE KEY" + "-----\n",
		"-----END " + "EC PRIVATE KEY" + "-----\n",
		"-----BEGIN " + "RSA PRIVATE KEY" + "-----\n",
		"-----BEGIN ",
		"-----END ",
		"-----",
		"X-----\n",
		"MIIBodyLineNotReal\n",
		`\n`,
		"\n",
		streamGuardFiller(90),
		strings.Repeat("-", 40),
		key,
	}
}

// TestStreamGuardPEMTrackerIsLinearOnAnyInput: for random inputs built from
// key and non-key BEGIN and END lines, half lines and prose, pushed in
// random chunk sizes, the guard always finishes and the private-key tracker
// searches a number of bytes linear in the text (rel-1-0-10:GAP-0428: an END
// line of another label inside an open block looped forever). The bound is a
// work count, not wall-clock time.
func TestStreamGuardPEMTrackerIsLinearOnAnyInput(t *testing.T) {
	check, _ := streamGuardTestCheck()
	key := syntheticPrivateKeyPEM("RSA PRIVATE KEY") + "\n"
	pieces := pemPropertyPieces(key)
	rng := rand.New(rand.NewSource(20261114))
	for trial := 0; trial < 300; trial++ {
		var b strings.Builder
		for b.Len() < 2000+rng.Intn(20000) {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		text := b.String()
		guard := newCompletionStreamGuard(check, 1+rng.Intn(600))
		pushes := 0
		blocked := false
		for _, chunk := range streamChunks(rng, text, 1+rng.Intn(5000)) {
			pushes++
			if _, v := guard.Push(chunk, []byte(chunk)); v != nil {
				blocked = true
				break
			}
		}
		if !blocked {
			guard.Finish()
		}
		if limit := 4*len(text) + (pemMaxHeaderLine+8)*2*pushes; guard.pemWork > limit {
			t.Fatalf("trial %d: the tracker searched %d bytes for %d bytes of text in %d pushes (limit %d)",
				trial, guard.pemWork, len(text), pushes, limit)
		}
	}
}

// TestStreamGuardKeyIsHeldWhateverPrecedesIt: a real private key preceded by
// a decoy (a non-key BEGIN line split at a push boundary, a foreign END line,
// a non-key block, an unclosed key header of another label) is never
// released in part, for provider-sized pushes: 1 and 24 bytes (token
// streams), 512 and 1,500 bytes (Gemini and Bedrock frames), 4 KiB (a
// passthrough read) (rel-1-0-10:GAP-0429).
func TestStreamGuardKeyIsHeldWhateverPrecedesIt(t *testing.T) {
	check, _ := streamGuardTestCheck()
	key := syntheticPrivateKeyPEM("RSA PRIVATE KEY") + "\n"
	if v := check("k\n" + key); v == nil || v.Action != guardrailActionBlock {
		t.Fatalf("the key fixture is not blocked whole: %+v", v)
	}
	bodyStart := strings.IndexByte(key, '\n') + 1
	body := key[bodyStart:strings.LastIndex(key, "-----END")]
	decoys := map[string]string{
		"none":                "",
		"non-key begin line":  "-----BEGIN " + "X" + "-----\n",
		"foreign end line":    "-----END " + "CERTIFICATE" + "-----\n",
		"non-key block":       "-----BEGIN " + "CERTIFICATE" + "-----\nMIIBodyLineNotReal\n-----END " + "CERTIFICATE" + "-----\n",
		"open key of another": "-----BEGIN " + "EC PRIVATE KEY" + "-----\nMIIBodyLineNotReal\n",
		"two foreign footers": "-----END " + "CERTIFICATE" + "-----\n-----END " + "X" + "-----\n",
		"half begin, no line": "-----BEGIN ",
		"dashes":              strings.Repeat("-", 30) + "\n",
	}
	for name, decoy := range decoys {
		for _, size := range []int{1, 24, 512, 1500, 4096} {
			for shift := 0; shift < 3; shift++ {
				text := streamGuardFiller(600+shift*37) + "\n" + decoy + key + streamGuardFiller(400)
				guard := newCompletionStreamGuard(check, streamGuardScanEvery)
				var out strings.Builder
				blocked := false
				for off := 0; off < len(text); off += size {
					chunk := text[off:min(off+size, len(text))]
					units, v := guard.Push(chunk, []byte(chunk))
					for _, u := range units {
						out.Write(u)
					}
					if v != nil {
						blocked = true
						break
					}
				}
				if !blocked {
					units, v := guard.Finish()
					blocked = v != nil
					for _, u := range units {
						out.Write(u)
					}
				}
				released := 0
				for _, line := range strings.Split(body, "\n") {
					if len(line) > 8 && strings.Contains(out.String(), line) {
						released += len(line)
					}
				}
				if released > 0 || !blocked {
					t.Fatalf("decoy %q, %d-byte pushes, shift %d: blocked=%v, %d key-body bytes released",
						name, size, shift, blocked, released)
				}
			}
		}
	}
}
