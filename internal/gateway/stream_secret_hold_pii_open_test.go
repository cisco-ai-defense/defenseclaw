// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The PII open shape of the stream hold (rel-1-0-10:GAP-1091,
// stream_secret_hold.go streamPIIRules).

// TestStreamPIIOpenHoldsEveryPrefix: every prefix of a card number or an SSN
// from its first digit is open, the whole value followed by a word is not,
// and digits inside a word or a run longer than any match are not held.
func TestStreamPIIOpenHoldsEveryPrefix(t *testing.T) {
	for _, v := range gap1091Values(t) {
		text := v.text + " is the value."
		var r responseText
		for i := 1; i <= len(text); i++ {
			r.Add(answerPiece(0, text[i-1:i]))
			want := i > v.body && i <= v.end+1 // the separator after it may start more digits
			if got := r.OpenSecret().open; got != want {
				t.Fatalf("%s: after %d bytes (%q) open=%v, want %v", v.name, i, text[max(0, i-24):i], got, want)
			}
		}
	}
	for _, c := range []struct{ name, text string }{
		{"digits-in-a-word", "build abc123"},
		{"number-then-word", "it took 12 seconds"},
		{"long-run", "id " + strings.Repeat("7", 40)},
	} {
		var r responseText
		r.Add(answerPiece(0, c.text))
		if r.OpenSecret().open {
			t.Errorf("%s: %q is held", c.name, c.text)
		}
	}
	// A zero-width character between digits (removed by the normalized
	// check) and a UTF-8 sequence cut after a digit keep the run open.
	for _, text := range []string{"is 4111\u200b11", "is 4111\xc2", "is 4111 1111"} {
		var r responseText
		r.Add(answerPiece(0, text))
		if !r.OpenSecret().open {
			t.Errorf("%q is not held", text)
		}
	}
}

// TestStreamPIIOpenCoversBlockingPIIRules: every card number and SSN rule of
// the shipped packs has the PII open shape (streamPIIRules).
func TestStreamPIIOpenCoversBlockingPIIRules(t *testing.T) {
	covered := map[string]bool{}
	for _, r := range streamPIIRules {
		for _, id := range r.rules {
			covered[id] = true
		}
	}
	var files []string
	for _, glob := range []string{
		filepath.Join("..", "..", "policies", "guardrail", "*", "rules", "enterprise-data.yaml"),
		filepath.Join("..", "..", "policies", "guardrail-use-cases", "*", "rules", "enterprise-data.yaml"),
	} {
		m, err := filepath.Glob(glob)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) < 4 {
		t.Fatalf("enterprise-data rule files: %d", len(files))
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Rules []struct {
				ID   string   `yaml:"id"`
				Tags []string `yaml:"tags"`
			} `yaml:"rules"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, r := range doc.Rules {
			card := false
			for _, tag := range r.Tags {
				card = card || tag == "pci"
			}
			if (card || strings.HasPrefix(r.ID, "ENT-BULK-SSN")) && !covered[r.ID] {
				t.Errorf("%s: card or SSN rule %s has no open shape in streamPIIRules", f, r.ID)
			}
		}
	}
}
