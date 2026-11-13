// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestGitCloneThenRunOrAdHocPush(t *testing.T) {
	for _, test := range []struct {
		name, command string
		want          bool
	}{
		{"clone cd run script", "git clone https://example.org/o/r && cd r && ./install.sh", true},
		{"clone cd make", "git clone https://example.org/o/r && cd r && make", true},
		{"clone cd npm install", "git clone https://example.org/o/r.git && cd r && npm install", true},
		{"clone into named dir", "git clone https://example.org/o/r work && cd work && bash setup.sh", true},
		{"clone run by path", "git clone https://example.org/o/r; r/run.sh", true},
		{"push scp-style remote", "git push user@example.org:o/r main", true},
		{"push url remote", "git push https://example.org/o/r main", true},
		{"push named remote", "git push origin main", false},
		{"push with flags only", "git push --force-with-lease origin main", false},
		{"clone only", "git clone https://example.org/o/r", false},
		{"clone cd read", "git clone https://example.org/o/r && cd r && ls", false},
		{"status", "git status", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := GitCloneThenRunOrAdHocPush(srFacts(test.command)); got != test.want {
				t.Fatalf("got %t want %t for %q", got, test.want, test.command)
			}
		})
	}
}
