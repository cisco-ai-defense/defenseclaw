// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"math/rand"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

// The incremental mid-stream scan (rel-1-0-10:GAP-0515) decides like the
// whole-text rescan of rel. Every text case of the regex security suite
// (completion and prompt cases, attacks and benign controls) is placed at
// the head, in the middle or at the tail (in turn) of benign prose of
// 6 KiB (past the 4 KiB overlap, so windows leave text out), cut into random
// chunks, and replayed through the guard's checkpoints (a scan
// once 500 more bytes of text arrived). At every checkpoint up to the first
// block, the class the guard acts on (block, confirm, other) of the window
// scan (streamScanWindow) equals that of the whole-text scan, so the stream
// is cut at the same byte. The whole-text checks at the end of the stream
// are unchanged.
func TestStreamScanIncrementalMatchesWholeText(t *testing.T) {
	f, err := os.Open("testdata/security_suite/regex/corpus.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var texts []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		var c struct {
			Direction string `json:"direction"`
			Content   string `json:"content"`
		}
		if json.Unmarshal([]byte(line), &c) != nil || c.Content == "" {
			continue
		}
		if c.Direction == "completion" || c.Direction == "prompt" {
			texts = append(texts, c.Content)
		}
	}
	if len(texts) < 100 {
		t.Fatalf("only %d text cases read", len(texts))
	}
	insp := NewGuardrailInspector("local", nil, nil)
	ctx := context.Background()
	class := func(s string) string {
		v := insp.InspectMidStream(ctx, "completion", s, []ChatMessage{{Role: "assistant", Content: s}}, "m", "action")
		switch {
		case v != nil && v.Severity != "NONE" && v.Action == "block":
			return "block"
		case v != nil && v.Action == "confirm":
			return "confirm"
		}
		return "other"
	}
	const prose = "The service reads its settings, starts the workers and logs each request it serves. "
	filler := func(n int) string { return strings.Repeat(prose, n/len(prose)+1)[:n] }
	rng := rand.New(rand.NewSource(515))
	blocks, checks := 0, 0
	for i, body := range texts {
		half := filler(6 << 10 / 2)
		placed := []string{body + "\n\n" + filler(6<<10), half + "\n\n" + body + "\n\n" + half, filler(6<<10) + "\n\n" + body}
		text := placed[i%3]
		// the checkpoints of one random chunking
		var points []int
		last, n := 0, 0
		for n < len(text) {
			n = min(n+1+rng.Intn(600), len(text))
			for n < len(text) && !utf8.RuneStart(text[n]) {
				n++
			}
			if n-last >= 500 {
				points = append(points, n)
				last = n
			}
		}
		prev := 0
		for _, p := range points {
			whole, inc := class(text[:p]), class(streamScanWindow(text[:p], prev))
			prev = p
			checks++
			if whole != inc {
				t.Fatalf("case %d at byte %d of %d: whole-text scan %s, incremental scan %s", i, p, len(text), whole, inc)
			}
			if whole == "block" {
				blocks++
				break
			}
		}
	}
	if blocks == 0 {
		t.Fatal("no case blocked: the test would prove nothing")
	}
	t.Logf("%d text cases, %d checkpoints compared, %d streams cut", len(texts), checks, blocks)
}
