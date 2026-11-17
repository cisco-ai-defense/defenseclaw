// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// spliceZeroWidth puts sep after every n-th rune of s.
func spliceZeroWidth(s, sep string, n int) string {
	var b strings.Builder
	i := 0
	for _, r := range s {
		b.WriteRune(r)
		i++
		if i%n == 0 {
			b.WriteString(sep)
		}
	}
	return b.String()
}

// invisibleSeparators is one row per class of character that renders as
// nothing (rel-1-0-10:GAP-1076), with every code point of the class that a
// splice could use.
var invisibleSeparators = []struct {
	class string
	runes []rune
}{
	{"zero-width space, joiners, word joiner, BOM (Cf)", []rune{0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}},
	{"soft hyphen, Arabic letter mark, Mongolian vowel separator (Cf)", []rune{0x00AD, 0x061C, 0x180E}},
	{"bidi marks, embeddings and isolates (Cf)", []rune{0x200E, 0x200F, 0x202A, 0x202C, 0x202E, 0x2066, 0x2069}},
	{"invisible operators and deprecated format controls (Cf)", []rune{0x2061, 0x2062, 0x2063, 0x2064, 0x206A, 0x206F}},
	{"interlinear annotation and shorthand format controls (Cf)", []rune{0xFFF9, 0xFFFB, 0x1BCA0, 0x1BCA3}},
	{"tag characters (Cf)", []rune{0xE0001, 0xE0020, 0xE0041, 0xE007F}},
	{"Hangul fillers", []rune{0x115F, 0x1160, 0x3164, 0xFFA0}},
	{"Khmer inherent vowels, combining grapheme joiner", []rune{0x17B4, 0x17B5, 0x034F}},
	{"variation selectors, Mongolian free variation selectors", []rune{0xFE00, 0xFE0F, 0xE0100, 0xE01EF, 0x180B, 0x180D, 0x180F}},
}

// TestSecretRulesSeeThroughInvisibleSeparators (rel-1-0-10:GAP-0210,
// GAP-1076): a secret rule fixture (rules_test.go) with an invisible character
// spliced in every 7 runes is still found by its rule, on the request side
// (the hook prompt check and the proxy prompt scan), on a tool result, and on
// the response side (a completion, whole and streamed), in every shipped pack.
// The default pack reads every fixture with every code point; permissive and
// strict read two fixtures with every code point. The text the checks get is
// never changed: only the copy the secret rules read is folded.
func TestSecretRulesSeeThroughInvisibleSeparators(t *testing.T) {
	var all []secretRuleFixture
	for _, fx := range secretRuleTruePositives() {
		if !strings.Contains(fx.input, "-----BEGIN") { // a PEM block is validated line by line (secretshape)
			all = append(all, fx)
		}
	}
	api := &APIServer{scannerCfg: &config.Config{}}
	insp := gap0210Inspector()
	checked := 0
	for _, profile := range gap0210Packs {
		ctx := gap0210PackContext(t, profile)
		fixtures := all
		if profile != "default" {
			fixtures = nil
			for _, fx := range all {
				if fx.wantID == "SEC-HF-TOKEN" || fx.wantID == "SEC-GITHUB-TOKEN" {
					fixtures = append(fixtures, fx)
				}
			}
		}
		for _, sep := range invisibleSeparators {
			for _, r := range sep.runes {
				for _, fx := range fixtures {
					text := spliceZeroWidth(fx.input, string(r), 7)
					checked++
					where := fmt.Sprintf("%s %s with U+%04X (%s) every 7 runes", profile, fx.name, r, sep.class)
					sides := map[string][]string{
						"request: hook prompt":  api.inspectMessageContent(ctx, claudeCodeContentInspectRequest(text, "prompt")).Findings,
						"request: proxy prompt": insp.Inspect(ctx, "prompt", text, nil, "model", "action").Findings,
						"tool result":           api.inspectMessageContent(ctx, claudeCodeContentInspectRequest(text, "tool_result")).Findings,
						"response: completion":  insp.Inspect(ctx, "completion", text, nil, "model", "action").Findings,
					}
					var streamed []string
					for _, v := range gap0210Stream(ctx, insp, gap0210Turn(text, "tail")) {
						streamed = append(streamed, v.Findings...)
					}
					sides["response: streamed"] = streamed
					for side, findings := range sides {
						if !gap0210HasRule(findings, fx.wantID) {
							t.Errorf("%s: %s misses %s (%v)", where, side, fx.wantID, findings)
						}
					}
				}
			}
		}
	}
	if checked < 900 {
		t.Fatalf("checked %d spliced fixtures, want the whole table (>= 900)", checked)
	}
}

// The fold reads every code point of the table as nothing and leaves ASCII
// text as it is (no copy) and visible non-ASCII text unchanged.
func TestCredentialVisibleText(t *testing.T) {
	for _, sep := range invisibleSeparators {
		for _, r := range sep.runes {
			if got := credentialVisibleText("ab" + string(r) + "cd"); got != "abcd" {
				t.Errorf("U+%04X (%s): %q, want abcd", r, sep.class, got)
			}
		}
	}
	for _, text := range []string{"plain ascii = 1", "café 中文 مرحبا naïve"} {
		if got := credentialVisibleText(text); got != text {
			t.Errorf("%q changed to %q", text, got)
		}
	}
}
