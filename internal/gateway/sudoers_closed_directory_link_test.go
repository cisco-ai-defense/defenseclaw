// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows create POSIX symlinks.

//go:build !windows

package gateway

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// closedDirectoryEvidence rewrites the hook client evidence of a Write through
// grant-link the way a client answers when a directory on the way of the link
// is closed to the user (/etc/sudoers.d is mode 0750 root): the operand has no
// physical answer and the file the link text leads to is listed instead.
func closedDirectoryEvidence(t *testing.T, linkText string) func(*testing.T, string) string {
	return func(t *testing.T, evidence string) string {
		t.Helper()
		targets, ok := hookpaths.Decode(evidence)
		if !ok {
			t.Fatalf("hook evidence %q is not readable", evidence)
		}
		for key := range targets {
			if filepath.Base(key) == "grant-link" && strings.HasPrefix(key, "/") {
				targets[key] = ""
				targets[hookpaths.LinkTextFactPrefix+key] = linkText
			}
		}
		encoded, err := json.Marshal(targets)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
}

func withClosedDirectoryEvidence(t *testing.T, linkText string) {
	t.Helper()
	sudoersEvidenceRewrite = closedDirectoryEvidence(t, linkText)
	t.Cleanup(func() { sudoersEvidenceRewrite = nil })
}

// TestFileToolWriteOfAGrantThroughALinkIntoAClosedSudoersDirectoryIsBlocked: the
// user cannot open /etc/sudoers.d, so the hook client has no physical answer
// for a project link into it; the link text names the drop-in, and the grant
// is refused like the direct write in every profile.
func TestFileToolWriteOfAGrantThroughALinkIntoAClosedSudoersDirectoryIsBlocked(t *testing.T) {
	hostLinksEtc(t, false)
	withClosedDirectoryEvidence(t, "/etc/sudoers.d/r109ops")
	for spelling, spell := range sudoersLinkSpellings {
		for _, profile := range []string{"default", "permissive", "strict"} {
			for _, managed := range []bool{false, true} {
				t.Run(spelling+"/"+profile+"/"+map[bool]string{false: "per-user", true: "managed"}[managed], func(t *testing.T) {
					row := sudoersLinkSpelledRow(t, "/etc/sudoers.d/r109ops", "r109yem5 ALL=(ALL) NOPASSWD: ALL\n", spell)
					blocked, _, body := postSudoersHook(t, row, profile, managed)
					if !blocked || !strings.Contains(body, sudoersGrantRuleID) {
						t.Fatalf("blocked = %t, want a block naming %s: %.600s", blocked, sudoersGrantRuleID, body)
					}
				})
			}
		}
	}
}

// TestFileToolWriteThroughALinkIntoAClosedDirectoryElsewhereIsAllowed is the
// benign twin: a closed directory whose link text leads to an ordinary file
// never names the grant rule, and the balanced profiles allow it.
func TestFileToolWriteThroughALinkIntoAClosedDirectoryElsewhereIsAllowed(t *testing.T) {
	hostLinksEtc(t, false)
	for _, profile := range []string{"default", "permissive"} {
		t.Run(profile, func(t *testing.T) {
			withClosedDirectoryEvidence(t, "/srv/closed/notes.txt")
			row := sudoersLinkSpelledRow(t, "/srv/closed/notes.txt", "r109yem5 ALL=(ALL) NOPASSWD: ALL\n", sudoersLinkSpellings["direct"])
			blocked, _, body := postSudoersHook(t, row, profile, false)
			if blocked || strings.Contains(body, sudoersGrantRuleID) {
				t.Fatalf("blocked = %t, names the grant rule = %t, want neither: %.600s", blocked, strings.Contains(body, sudoersGrantRuleID), body)
			}
		})
	}
}
