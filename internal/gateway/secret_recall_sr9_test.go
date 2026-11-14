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

// GAP-0665: the path rule weighs a value by its letters and digits, not by its
// pieces, and counts only word-shaped pieces of three letters or more as
// words. A short secret padded with short pieces between slashes is still a
// secret. Every value is generated at run time from a seeded generator.

const (
	sr9Alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	sr9Hex   = "0123456789abcdef"
	sr9Std   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	sr9URL   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	sr9Az    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_~.-"
)

// sr9Words are words of five letters or fewer, the padding a person puts in a
// path (long enough to trip the name rule on their own, which is a different
// rule); sr9Short are the one to three letter pieces (a, go, src).
var (
	sr9Words = []string{"with", "from", "into", "over", "about", "after", "prod", "keys", "deploy", "backup", "tests", "shared", "home", "user", "data", "cache", "logs", "build", "docs", "guide", "notes", "index", "files", "check"}
	sr9Three = []string{"the", "and", "for", "src", "lib", "bin", "app", "api", "web", "net", "log", "doc", "tmp", "etc", "var", "usr", "key", "cfg"}
	sr9Short = []string{"a", "b", "c", "d", "e", "f", "go", "src", "lib", "bin", "app", "api", "web", "net", "db", "ui"}
)

func sr9Pick(r *rand.Rand, pool []string, k int) []string {
	out := make([]string, 0, k)
	for i := 0; i < k; i++ {
		out = append(out, pool[r.Intn(len(pool))])
	}
	return out
}

// sr9Secret draws a secret that is accepted on its own: the padded value must
// give the same decision.
func sr9Secret(r *rand.Rand, alphabet string, n int) string {
	for {
		if s := randomString(r, alphabet, n); secretAssignmentRejection(s) == "" {
			return s
		}
	}
}

// sr9Surround puts the secret pieces among the padding, in the middle of it.
func sr9Surround(r *rand.Rand, pad []string, secret ...string) string {
	at := r.Intn(len(pad) + 1)
	all := append([]string{}, pad[:at]...)
	all = append(all, secret...)
	all = append(all, pad[at:]...)
	return strings.Join(all, "/")
}

func sr9Chunks(r *rand.Rand, v string, lo, hi int) []string {
	var out []string
	for len(v) > 0 {
		n := min(lo+r.Intn(hi-lo+1), len(v))
		out = append(out, v[:n])
		v = v[n:]
	}
	return out
}

// The four owner cases (GAP-0536) keep their reason: path. The rows are
// synthetic and have the masked shape of the benchmark cases
// at/codex/45e4f2aa59c7db2b/470, ef1a51b64fc57645/509, c3196c0df80b17c3/1611
// and 92da3b7143c1eebb/w432 (letters and digit groups in the same places).
func TestSecretRecallSR9OwnerCasesStayPaths(t *testing.T) {
	for id, path := range map[string]string{
		"470":  "a/main/tests/un-it/go/c102-ab34-56d7e89f0/cmd/integration/security/key_tests.py",
		"509":  "a/modules/one/tm-1234ab5c-sessions.XkTBa9/review/fix/documentation/references_guide.md",
		"1611": "migrate/modules/versions/a1b2c3d4e5f6_create_audit_log_for_every_changes.py-28-",
		"w432": "a/main/tests/un-it/go/c102-X91/cmd/utils/test_files_rotate_integration.py",
	} {
		if got := secretAssignmentRejection(path); got != "path" {
			t.Errorf("case %s: rejection %q, want path", id, got)
		}
	}
}

// Padding that is short pieces, not words, never makes a path: single letters
// weigh no word, and the id characters of the secret stay over a quarter of
// the value. 2000 seeded draws per class, every one accepted (a draw that the
// name rule rejects is drawn again, and at most one in twenty may be).
func TestSecretRecallSR9PaddedSecretsAreAccepted(t *testing.T) {
	r := rand.New(rand.NewSource(665))
	const n = 2000
	for label, gen := range map[string]func() string{
		"a/b/c/d/e/f + alnum16": func() string {
			return "a/b/c/d/e/f/" + sr9Secret(r, sr9Alnum, 16)
		},
		"a/b/c/d/e/f/g/h + 2 x alnum16": func() string {
			return "a/b/c/d/e/f/g/h/" + sr9Secret(r, sr9Alnum, 16) + "/" + sr9Secret(r, sr9Alnum, 16)
		},
		"12 one-letter pieces + alnum40 in 3 chunks": func() string {
			return "a/b/c/d/e/f/g/h/i/j/k/l/" + strings.Join(sr9Chunks(r, sr9Secret(r, sr9Alnum, 40), 13, 14), "/")
		},
		"6-12 short pieces + alnum12": func() string {
			return sr9Surround(r, sr9Pick(r, sr9Short, 6+r.Intn(7)), sr9Secret(r, sr9Alnum, 12))
		},
		"6 three-letter words + alnum16": func() string {
			return sr9Surround(r, sr9Pick(r, sr9Three, 6), sr9Secret(r, sr9Alnum, 16))
		},
		"6 three-letter words + azure storage key 40": func() string {
			return sr9Surround(r, sr9Pick(r, sr9Three, 6), sr9Secret(r, sr9Az, 40))
		},
		"hex40 in chunks 8-16 + 1-3 short pieces per chunk": func() string {
			chunks := sr9Chunks(r, sr9Secret(r, sr9Hex, 40), 8, 16)
			var parts []string
			for _, c := range chunks {
				parts = append(parts, sr9Pick(r, sr9Three, 1+r.Intn(3))...)
				parts = append(parts, c)
			}
			return strings.Join(parts, "/")
		},
		"gcp key AIza + 6 three-letter words": func() string {
			return sr9Surround(r, sr9Pick(r, sr9Three, 6), "AIza"+sr9Secret(r, sr9URL, 35))
		},
	} {
		// n draws; a draw that the name or words rule rejects (the secret's
		// own letters run in word-shaped stretches) is another rule's
		// decision, identical without the padding, and is drawn again.
		accepted, other := 0, 0
		for accepted < n && other < n {
			switch why := secretAssignmentRejection(gen()); why {
			case "":
				accepted++
			case "path":
				t.Fatalf("%s: draw %d read as a path", label, accepted+other)
			default:
				other++
			}
		}
		if accepted != n || other > n/20 {
			t.Errorf("%s: accepted %d of %d, %d rejected by another rule", label, accepted, n, other)
		}
	}
}

// A secret with five-letter padding words is never read as a path (the name or
// words rule may still call a value that is mostly words a name, which is a
// separate rule): the ids are 16 or more characters against at most 30 letters
// of padding, so they stay over a quarter of the value.
func TestSecretRecallSR9WordPaddedSecretsAreNotPaths(t *testing.T) {
	r := rand.New(rand.NewSource(2665))
	const n = 2000
	for label, gen := range map[string]func() string{
		"6 words + alnum16":              func() string { return sr9Surround(r, sr9Pick(r, sr9Words, 6), sr9Secret(r, sr9Alnum, 16)) },
		"6 words + azure storage key 40": func() string { return sr9Surround(r, sr9Pick(r, sr9Words, 6), sr9Secret(r, sr9Az, 40)) },
		"6 words + aws secret 40":        func() string { return sr9Surround(r, sr9Pick(r, sr9Words, 6), sr9Secret(r, sr9Alnum, 40)) },
		"6-12 short pieces + alnum40 in 3 chunks": func() string {
			return sr9Surround(r, sr9Pick(r, sr9Short, 6+r.Intn(7)), strings.Join(sr9Chunks(r, sr9Secret(r, sr9Alnum, 40), 13, 14), "/"))
		},
	} {
		paths := 0
		for i := 0; i < n; i++ {
			if secretAssignmentRejection(gen()) == "path" {
				paths++
			}
		}
		if paths != 0 {
			t.Errorf("%s: %d of %d draws were read as a path", label, paths, n)
		}
	}
}

// The natural secret formats stay secrets: none of 2000 seeded draws is read
// as a path, and none is rejected for any reason (GAP-0452 accept rates are
// checked by the review tests; this class is the path rule alone).
func TestSecretRecallSR9NaturalSecretsAreNotPaths(t *testing.T) {
	r := rand.New(rand.NewSource(1665))
	const n = 2000
	jwtHead := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	for label, gen := range map[string]func() string{
		"base64 12 bytes":        func() string { return randomBase64(r, 12, false) },
		"base64 24 bytes":        func() string { return randomBase64(r, 24, false) },
		"base64 32 bytes":        func() string { return randomBase64(r, 32, false) },
		"base64 48 bytes":        func() string { return randomBase64(r, 48, false) },
		"base64 90 bytes":        func() string { return randomBase64(r, 90, false) },
		"aws secret 40":          func() string { return randomString(r, sr9Std, 40) },
		"azure storage key 88":   func() string { return randomBase64(r, 64, false) },
		"azure sas signature 44": func() string { return randomBase64(r, 32, false) },
		"gcp service account":    func() string { return randomString(r, sr9Std, 64) },
		"jwt":                    func() string { return jwtHead + "." + randomBase64(r, 24, true) + "." + randomBase64(r, 32, true) },
	} {
		paths := 0
		for i := 0; i < n; i++ {
			v := gen()
			if strings.Contains(v, "/") && secretAssignmentPathShaped(v) {
				paths++
			}
		}
		if paths != 0 {
			t.Errorf("%s: %d of %d draws were read as a path", label, paths, n)
		}
	}
}
