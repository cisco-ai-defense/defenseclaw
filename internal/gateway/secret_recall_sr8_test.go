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

// GAP-0536: a long relative path with one or two id-like pieces is a path.
// The rows are synthetic and have the shape of the three benchmark cases
// (at/codex/45e4f2aa59c7db2b/470, ef1a51b64fc57645/509, c3196c0df80b17c3/1611):
// ten to fifteen components of words and file names, with a short git hash, a
// temporary-directory suffix or a migration revision among them.
func TestSecretRecallSR8LongRelativePathsWithAnIDPieceArePaths(t *testing.T) {
	for id, path := range map[string]string{
		"470":  "a/test/cases/un-it/go/c102-ab34-56d7e89f0/cmd/integration/security/key_tests.py",
		"509":  "a/modules/one/tm-1234ab5c-sessions.XkTBa9/review/fix/documentation/references_guide.md",
		"1611": "migrate/modules/versions/a1b2c3d4e5f6_create_audit_log_for_every_changes.py-28-",
	} {
		if got := secretAssignmentRejection(path); got == "" {
			t.Errorf("case %s: a relative path was accepted as a secret", id)
		}
	}
}

// What is not a path stays a value: too few components, too few words, too
// many ids, an id piece longer than 16 characters, or an empty component.
func TestSecretRecallSR8PathShapeStaysNarrow(t *testing.T) {
	for label, value := range map[string]string{
		"three components":  "keys/prod/deploy_aa11bb22cc33dd",
		"one word per id":   "aa1bb2cc3d4e/x9k2m7q4p1w8/Zq4Rt8Lm2Xv/ab3kqm7p9x2w",
		"id longer than 16": "srv/data/backups/archive/monthly/reports/summary/x9k2m7q4p1w8a5b3c7d9e1",
		"empty component":   "srv/data/backups//archive/monthly/reports/summary/x9k2m7q4p1w8",
		"too many ids":      "srv/data/backups/archive/monthly/reports/aa1b2c3d4e5f/x9k2m7q4p1w8/summary",
	} {
		if secretAssignmentPathShaped(value) {
			t.Errorf("%s: read as a path", label)
		}
	}
}

// Random secrets that hold slashes are not paths: the rule must not read a
// base64 value, an AWS-style key or a forced-slash key as a path, in any of
// 2000 draws, and a value that was accepted before stays accepted.
func TestSecretRecallSR8SecretsWithSlashesAreNotPaths(t *testing.T) {
	const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	r := rand.New(rand.NewSource(536))
	const n = 2000
	// force puts k slashes at random places of v, at least one apart.
	force := func(v string, k int) string {
		b := []byte(v)
		for placed := 0; placed < k; {
			i := 1 + r.Intn(len(b)-2)
			if b[i] != '/' && b[i-1] != '/' && b[i+1] != '/' {
				b[i] = '/'
				placed++
			}
		}
		return string(b)
	}
	for label, gen := range map[string]func() string{
		"base64 32 bytes":          func() string { return randomString(r, base64Alphabet, 43) + "=" },
		"base64 48 bytes":          func() string { return randomString(r, base64Alphabet, 64) },
		"base64 32 bytes 3 slash":  func() string { return force(randomString(r, base64Alphabet, 43)+"=", 3) },
		"base64 64 bytes 5 slash":  func() string { return force(randomString(r, base64Alphabet, 86), 5) },
		"base64url 32 bytes 3 /":   func() string { return force(randomString(r, base64URLAlphabet, 43), 3) },
		"base64url 48 bytes 5 /":   func() string { return force(randomString(r, base64URLAlphabet, 64), 5) },
		"aws secret 40 with 4 /":   func() string { return force(randomString(r, base64Alphabet, 40), 4) },
		"lower+digit 40 with 4 /":  func() string { return force(randomString(r, lowerDigitAlphabet, 40), 4) },
		"lower+digit 60 with 5 /":  func() string { return force(randomString(r, lowerDigitAlphabet, 60), 5) },
		"words, id, id, words key": func() string { return "keys/prod/deploy/" + randomString(r, base64Alphabet, 30) },
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
