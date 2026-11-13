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
		{"clone cd make then run the built program", "git clone https://example.org/o/r && cd r && make && ./r", true},
		{"clone cd make is ordinary build work", "git clone https://example.org/o/r && cd r && make", false},
		{"clone cd make test", "git clone https://example.org/o/r && cd r && make test", false},
		{"clone cd npm install", "git clone https://example.org/o/r.git && cd r && npm install", false},
		{"clone cd npm start", "git clone https://example.org/o/r && cd r && npm install && npm start", false},
		{"clone cd go test", "git clone https://example.org/o/r && cd r && go test ./...", false},
		{"clone cd pip install", "git clone https://example.org/o/r && cd r && pip install -e .", false},
		{"clone into named dir", "git clone https://example.org/o/r work && cd work && bash setup.sh", true},
		{"clone run by path", "git clone https://example.org/o/r; r/run.sh", true},
		{"push scp-style remote", "git push user@example.org:o/r main", true},
		{"push url to bare public ip", "git push https://203.0.113.9/o/r main", true},
		{"push ssh url on an unknown host", "git push ssh://git@example.org/o/r.git main", true},
		{"push scp-style to a self-hosted server", "git push git@git.example.org:team/r.git main", true},
		{"push ssh url to the same self-hosted server", "git push ssh://git@git.example.org/team/r.git main", true},
		{"push ssh url on a forge", "git push ssh://git@github.com/o/r.git main", false},
		{"push ssh url on the forge port-443 host", "git push ssh://git@ssh.github.com:443/o/r.git main", false},
		{"push https remote on a named host", "git push https://git.example.org/team/r.git main", false},
		{"push fork url on a forge", "git push https://github.com/o/fork.git HEAD:b", false},
		{"push scp-style remote on a forge", "git push git@github.com:o/r.git main", false},
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
