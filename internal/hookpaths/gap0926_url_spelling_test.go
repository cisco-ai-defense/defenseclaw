// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"testing"
	"time"
)

// A URL is no share path in any spelling the shell reads as one word: a
// quoted scheme ("http"://host/x is the word http://host/x) and an empty
// authority of a non-file scheme (http:///host/x) ask no share either. A file
// URL keeps its local-path reading (rel-1-0-10:GAP-0926).
func TestURLSpellingsAskNoNetworkShare(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, command := range []string{
		`echo "http"://slow.example/share/f`,
		`echo https://slow.example/share/f`,
		`echo ht"tp"://slow.example/share/f`,
		`echo http:///slow.example/share/f`,
		`curl -o f "https"://slow.example/share/f`,
		`echo https://slow.example/share/f`,
	} {
		probes := fakeNetworkShare(t, "/slow.example", 50*time.Millisecond, 50*time.Millisecond, func(string) {})
		ActionCommandDecisionInShell(command, cwd, home, nil, true)
		if got := probes.Load(); got != 0 {
			t.Errorf("%q asked the share of the URL host %d times, want never", command, got)
		}
	}
	// The control: a bare //host/share operand is still a share ask.
	probes := fakeNetworkShare(t, "/slow.example", 50*time.Millisecond, 50*time.Millisecond, func(string) {})
	ActionCommandDecisionInShell(`echo //slow.example/share/f`, cwd, home, nil, true)
	if probes.Load() == 0 {
		t.Errorf("a //host/share operand asked no share: the control is void")
	}
}
