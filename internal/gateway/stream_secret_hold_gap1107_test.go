// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// streamTokenOpen is the alternatives of streamTokenOpenAlts joined into one
// end-anchored expression: the reference streamTokenOpenStart must equal. The
// stream paths do not run it (substrate-1:GAP-1107).
var streamTokenOpen = regexp.MustCompile(`(?:` + strings.Join(streamTokenOpenAlts(), "|") + `)$`)

// substrate-1:GAP-1107: the start of the open token or digit run that
// streamTokenOpenStart finds, alternative by alternative behind their
// literals, is the start the joined streamTokenOpen finds, for tails made of
// every rule's open prefix, token bytes, separators, case folds and runes
// beyond ASCII, at every cut.
func TestGAP1107TokenOpenStartIsTheJoinedMatch(t *testing.T) {
	// The open prefixes, split so no literal here is a whole token.
	prefixes := []string{
		"AK" + "IA", "AS" + "IA", "s" + "k-", "r" + "k_", "gh" + "p_", "gh" + "s_", "github" + "_pat_", "glp" + "at-",
		"AI" + "za", "xo" + "xb-", "https://hooks.slack.com/" + "services/", "https://discord.com/api/" + "webhooks/",
		"https://discordapp.com/api/" + "webhooks/", "ey" + "J", "postgres" + "://", "redis" + "://u", "Bea" + "rer ",
		"bearer\t", "pass" + "word=", "PASSWD: ", "pwd2 := ", "passphrase\"=", "sec" + "ret: ", "api_" + "key is ",
		"private-key=", "credentials(", "token,", "signing_key=>", "S" + "G.", "S" + "K", "np" + "m_", "h" + "f_",
		"py" + "pi-", "4111 ", "1234-", "123-45-", "9", "0\u200b", "5–",
	}
	bodies := []string{
		"A1b2C3", "0000", "zz", "_-", "+/=", ".", "!@#", "K", "ſ", "é", "�", "",
		" ", "  ", "\t", "\n", ",", ";", "\"", "'", "\\", "`", "(", ")", "=", ":", "-", "x", "the ", "Is ",
	}
	rng := rand.New(rand.NewSource(1107))
	rounds := 400
	if hookAnswerRaceBuild {
		rounds = 40 // the race detector runs the automata about 15 times slower
	}
	checked := 0
	for round := 0; round < rounds; round++ {
		var b strings.Builder
		for b.Len() < 360 {
			if rng.Intn(3) == 0 {
				b.WriteString(prefixes[rng.Intn(len(prefixes))])
			}
			b.WriteString(bodies[rng.Intn(len(bodies))])
			if rng.Intn(4) == 0 {
				b.WriteString(strings.Repeat("Q7", rng.Intn(20)))
			}
		}
		text := b.String()
		for cut := 0; cut <= len(text); cut += 1 + rng.Intn(7) {
			tail := text[:cut]
			if len(tail) > streamSecretTail {
				tail = tail[len(tail)-streamSecretTail:]
			}
			want := -1
			if loc := streamTokenOpen.FindStringIndex(tail); loc != nil {
				want = loc[0]
			}
			if got := streamTokenOpenStart(tail); got != want {
				t.Fatalf("tail %q: start %d, the joined expression %d", tail, got, want)
			}
			checked++
		}
	}
	t.Logf("%d tails", checked)
}
