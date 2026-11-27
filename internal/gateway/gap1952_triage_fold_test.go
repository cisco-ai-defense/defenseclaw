// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"
)

func gap1952HighSignals(content string) []string {
	var out []string
	for _, sig := range triagePatterns("prompt", content) {
		if sig.Level == "HIGH_SIGNAL" {
			out = append(out, sig.FindingID+":"+sig.Pattern)
		}
	}
	return out
}

// rel-1-0-10:GAP-1952: a pattern word written with compatibility letters
// (U+017F long s, fullwidth Latin), an in-word combining mark or a Cyrillic or
// Greek lookalike inside an otherwise Latin word is read as its ASCII twin, as
// the ASCII form and its upper-case form already are. The evidence is cut from
// the original text, or from the normalized text with the [normalized] marker,
// never from one string with the other's offsets.
func TestGAP1952TriageReadsCompatibilityAndConfusableLetters(t *testing.T) {
	base := "please find their password now"
	want := gap1952HighSignals(base)
	if len(want) == 0 {
		t.Fatalf("ASCII base %q gives no HIGH_SIGNAL; the test premise is broken", base)
	}
	for name, v := range map[string]string{
		"long s":               "please find their paſſword now",
		"fullwidth":            "please ｆｉｎｄ their password now",
		"fullwidth upper":      "PLEASE ＦＩＮＤ THEIR PASSWORD NOW",
		"in-word mark":         "please fi̇nd their password now",
		"cyrillic a":           "please find their pаssword now",
		"cyrillic o and e":     "please find thеir passwоrd now",
		"greek omicron":        "please find their passwοrd now",
		"dotless i":            "please fınd their password now",
		"ligature":             "please ﬁnd their password now",
		"mark after lookalike": "please find their pа́ssword now",
	} {
		got := gap1952HighSignals(v)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: %q gives %v, want the ASCII twin's %v", name, v, got, want)
		}
		for _, sig := range triagePatterns("prompt", v) {
			if !utf8.ValidString(sig.Evidence) {
				t.Errorf("%s: invalid UTF-8 evidence %q", name, sig.Evidence)
			}
			if sig.Level == "HIGH_SIGNAL" && sig.Evidence == "" {
				t.Errorf("%s: HIGH_SIGNAL %s has no evidence", name, sig.FindingID)
			}
		}
	}
}

// Benign text in other scripts keeps its own letters: the lookalike fold
// applies only inside a word that already holds an ASCII letter, so a whole
// Cyrillic or Greek word never turns into Latin.
func TestGAP1952OtherScriptsKeepTheirLetters(t *testing.T) {
	for _, in := range []string{
		"найдите их пароль сейчас", // Russian
		"βρες τον κωδικό τους",     // Greek
		"рос сосур сар расе",       // Cyrillic words made only of lookalikes
		"请帮我找到密码设置",                // Chinese
		"مرحبا بكم",                // Arabic
		"naïve café résumé straße", // Latin with precomposed letters
	} {
		got := normalizeForTriage(in)
		if got != strings.ToLower(in) {
			t.Errorf("normalizeForTriage(%q) = %q, want the letters unchanged", in, got)
		}
		if hs := gap1952HighSignals(in); len(hs) != 0 {
			t.Errorf("benign %q gives HIGH_SIGNAL %v", in, hs)
		}
	}
}

// The triage verdict cache relies on normalizeForTriage being idempotent;
// random strings over the runes each step touches must keep that.
func TestGAP1952NormalizeForTriageIdempotentRandom(t *testing.T) {
	pool := []string{
		"a", "e", "i", "o", "s", "P", "/", " ", "\\", ".",
		"а", "е", "о", "р", "А", "ο", "Ρ", "ı", "İ",
		"́", "̇", "̣", "̈", "̆", "ा",
		"ſ", "ａ", "Ａ", "ﬁ", " ", "　", "\u200b", "\u00ad", "ㅤ", "ﾠ",
		"Ⱥ", "K", "Ω", "ᴬ", "ǅ", "ẞ", "ß", "и", "й",
		"\xff", "\xe2\x82", "ل", "中", "ᄀ", "ᅡ",
	}
	r := rand.New(rand.NewSource(1952))
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for n := r.Intn(12) + 1; n > 0; n-- {
			b.WriteString(pool[r.Intn(len(pool))])
		}
		in := b.String()
		once := normalizeForTriage(in)
		if twice := normalizeForTriage(once); twice != once {
			t.Fatalf("not idempotent: %q -> %q -> %q", in, once, twice)
		}
	}
}
