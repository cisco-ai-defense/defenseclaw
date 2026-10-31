// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"testing"
)

// TestBraceWriterOperandsOntoKeysBlockManagedLikePerUser is rel-1-0-6
// GAP-0228: a writer whose target operand is a brace word that bash
// expands to the authorized_keys file (tee ~/.ssh/authorized_key{s,x})
// was allowed by a managed gateway, which cannot search the home and sees
// only the targets the hook client lists, while the per-user gateway
// blocked it; dd of= with a brace word, and a dd with a second of=, were
// allowed in both. The brace operands of tee, sed -i, truncate and dd are
// now listed as the fixed words bash makes of them, and dd reads every
// of=. Both connectors block managed and per-user; brace writes into
// project files stay allowed. A brace redirect target is an ambiguous
// redirect in bash (nothing is written), and rsync with a brace that only
// names the keys file as a source copies nothing onto it.
func TestBraceWriterOperandsOntoKeysBlockManagedLikePerUser(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	blocked := []string{
		"tee ../.ssh/authorized_key{s,x} < ../.ssh/id.pub",
		"tee ~/.ssh/authorized_key{s,x} < ../.ssh/id.pub",
		"tee -a ../.ssh/authorized_key{r..t} < ../.ssh/id.pub",
		"tee keylink{,.x} < ../.ssh/id.pub",
		"sed -i s/a/b/ ../.ssh/authorized_key{s,x}",
		"truncate -s0 ../.ssh/authorized_key{s,x}",
		"truncate -s0 keylink{,.x}",
		"dd if=../.ssh/id.pub of=../.ssh/authorized_key{x,s}",
		"dd if=../.ssh/id.pub of=~/.ssh/authorized_key{x,s}",
		"dd if=../.ssh/id.pub of=ordinary/a of=../.ssh/authorized_keys",
		"dd if=README.md of=keylink{,.x}",
		// The plain and already-read forms stay blocked.
		"tee ../.ssh/authorized_keys < ../.ssh/id.pub",
		"cp {../.ssh/id.pub,../.ssh/authorized_keys}",
		"install {../.ssh/id.pub,../.ssh/authorized_keys}",
		"mv {../.ssh/id.pub,../.ssh/authorized_keys}",
		"ln -sf {../ordinary/a,../.ssh/authorized_keys}",
	}
	allowed := []string{
		"tee ordinary/{a,b}.txt < README.md",
		"sed -i s/a/b/ ordinary/{a,b}.txt",
		"truncate -s 0 ordinary/{a,b}",
		"dd if=README.md of=ordinary/{a,b}",
		"dd if=README.md of=ordinary/a",
		"echo k >> ../.ssh/authorized_key{s,x}",
		"rsync ../.ssh/id.pub ../.ssh/authorized_key{s,}",
	}
	check := func(command, want string) {
		payload := f.payload(t, command)
		header := f.clientHeader(t, payload)
		for _, call := range everyMode(command, payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			if call.verdict, call.body = f.serve(call); call.verdict != want {
				t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
			}
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range blocked {
		check(command, "block")
	}
	for _, command := range allowed {
		check(command, "allow")
	}
}
