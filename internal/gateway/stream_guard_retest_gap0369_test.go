// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
	"time"
)

// GAP-0369 (s7/response review round 1): the s7/response stream guard held
// everything after an unclosed private-key BEGIN line (up to 64 KiB) and
// widened every check to read from that line, 9x the CPU of the same stream
// without it. Rel never took that guard; its open-secret reader
// (stream_secret_hold.go, rel-1-0-10:GAP-0429) holds an open BEGIN line only
// until a line no PEM body has, and advances over new text only. The repro
// here is the gap's: a 61 KB benign reply in 24-byte pieces, with and without
// a BEGIN line near the start. The hold must stay within the BEGIN line and
// one piece, the client must get the whole reply on the /llm proxy and on the
// passthrough stream, and the line must cost no more on /llm than the same
// words in prose. (Its words "PRIVATE KEY" wake the SEC-SECRET-ASSIGN regex,
// which then reads the whole reply at every mid-stream check, as it does for
// any reply that says "private key", "token" or "password": that whole-reply
// cost is not the PEM hold's.)
func TestRetestGAP0369OpenPEMHeaderHoldAndCost(t *testing.T) {
	key := syntheticPrivateKeyPEM("RSA PRIVATE KEY")
	header := key[:strings.IndexByte(key, '\n')+1]
	filler := retestFiller(61 << 10)
	const lead = "Here is the layout of the file:\n"
	const mention = "We rotate the PRIVATE KEY of the build server every month.\n"

	// maxHeld is the longest run of text the open-secret reader keeps open
	// while the reply arrives in 24-byte pieces.
	maxHeld := func(text string) int {
		var r responseText
		longest, from := 0, -1
		for _, p := range retestPieces(text, 24) {
			r.Add(answerPiece(0, p))
			if !r.OpenSecret().open {
				from = -1
				continue
			}
			if from < 0 {
				from = r.Len() - len(p)
			}
			longest = max(longest, r.Len()-from)
		}
		return longest
	}
	base, got := maxHeld(lead+filler), maxHeld(lead+header+filler)
	if limit := base + len(header) + 2*24; got > limit {
		t.Errorf("an unclosed BEGIN line held %d bytes of text open (without it %d, limit %d)", got, base, limit)
	}
	t.Logf("longest open run: %d bytes with the BEGIN line, %d without", got, base)

	// The streams: 12 KB of the same reply (the cost grows with the square of
	// the length on both, so a shorter reply shows the same ratio).
	keyText := lead + header + retestFiller(12<<10)
	mentionText := lead + mention + retestFiller(12<<10)
	llm := func(text string) string { return retestLLM(t, retestPieces(text, 24)) }
	var writes []string
	for _, p := range retestPieces(keyText, 24) {
		writes = append(writes, retestOAIFrame(p))
	}
	if got := streamedContent(retestPassthrough(t, append(writes, "data: [DONE]\n\n"))); got != keyText {
		t.Fatalf("passthrough: the client got %d of %d text bytes (blocked or held)", len(got), len(keyText))
	}
	cost := map[string]time.Duration{}
	for i := 0; i < 2; i++ {
		for kind, text := range map[string]string{"header": keyText, "mention": mentionText} {
			start := time.Now()
			out := llm(text)
			d := time.Since(start)
			if c, ok := cost[kind]; !ok || d < c {
				cost[kind] = d
			}
			if got := streamedContent(out); got != text {
				t.Fatalf("llm %s: the client got %d of %d text bytes (blocked or held)", kind, len(got), len(text))
			}
		}
	}
	t.Logf("llm (best of 2): %v with the BEGIN line, %v with the words in prose", cost["header"], cost["mention"])
	if cost["header"] > cost["mention"]*3/2+100*time.Millisecond {
		t.Errorf("llm: the stream with an unclosed BEGIN line cost %v, with the same words in prose %v (more than 1.5x)", cost["header"], cost["mention"])
	}
}
