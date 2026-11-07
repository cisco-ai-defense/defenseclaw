// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"testing"
)

// TestGAP0409DynamicRedirectOntoKeysLinkAlertsEveryMode is rel-1-0-2
// GAP-0409 (sweep 7 and 8, managed RHEL corpus c and d): an append onto
// a project link to the keys file whose redirect target is a variable set
// by eval, a ${f:-default} after an unset inside an if, or a command
// substitution was allowed by a managed gateway (it cannot see the link and
// reads the hook client's concrete-write fact), on both connectors. The
// client's value tracker now reads $(echo word), drops the names a
// compound statement assigns or unsets, and reads an eval of static
// name=value words, so all four cells answer the protected-file alert (a
// block in the strict pack); the ordinary-file twins stay allowed.
func TestGAP0409DynamicRedirectOntoKeysLinkAlertsEveryMode(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	alerted := []string{
		`f=other; eval f=keylink; echo dccert-block-marker >> "$f"`,
		`f=report.txt; if true; then unset f; fi; echo dccert-block-marker >> ${f:-keylink}`,
		`f=$(echo keylink); echo dccert-block-marker >> "$f"`,
		`read f <<< keylink; echo dccert-block-marker >> "$f"`,
		`f=keylink; echo dccert-block-marker >> "$f"`,
		`f=keylink; echo dccert-block-marker >> ${f}`,
		`echo dccert-block-marker >> keylink`,
	}
	allowed := []string{
		`f=report.txt; if true; then unset f; fi; echo ok >> ${f:-notes2.txt}`,
		`f=$(echo notes3.txt); echo ok >> "$f"`,
		`f=$(echo report.txt); echo ok >> "$f"`,
		`read f <<< notes4.txt; echo ok >> "$f"`,
		`f=notes5.txt; echo ok >> "$f"`,
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
				t.Errorf("%s: verdict %s, want %s; body %.160s", call.name, call.verdict, want, call.body)
			}
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range alerted {
		check(command, "alert")
	}
	for _, command := range allowed {
		check(command, "allow")
	}
}
