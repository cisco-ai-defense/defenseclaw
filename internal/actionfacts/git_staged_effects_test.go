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
		// SHREV2-09: the scp form without a user
		{"push scp-style without a user", "git push git.example.org:team/r.git main", true},
		{"push scp-style without a user to a forge", "git push github.com:o/r.git main", false},
		{"push a relative path", "git push ./backup/r.git main", false},
		// SHREV2-10: option values, and a remote the action defines itself
		{"push option value before the remote", "git push -o ci.skip git@git.example.org:o/r main", true},
		{"push option value before a named remote", "git push -o ci.skip origin main", false},
		{"push --push-option value before the remote", "git push --push-option=x --push-option y git@git.example.org:o/r main", true},
		{"push with --repo", "git push --repo=git@git.example.org:o/r main", true},
		{"push with --repo and a separate value", "git push --repo git@git.example.org:o/r main", true},
		{"remote added then pushed by name", "git remote add up git@git.example.org:o/r.git && git push up main", true},
		{"remote url reset then pushed by name", "git remote set-url origin ssh://git@git.example.org/o/r && git push origin main", true},
		{"remote added on a forge then pushed", "git remote add up git@github.com:o/r.git && git push up main", false},
		{"remote url given with -c then pushed by name", "git -c remote.up.url=ssh://git@git.example.org/o/r push up main", true},
		{"remote pushurl given with -c", "git -c remote.up.pushurl=git@git.example.org:o/r push up main", true},
		// the clone is left by a later cd elsewhere
		{"run after leaving the clone", "git clone https://example.org/o/r && cd r && cd .. && run.sh", false},
		{"run after cd into a subdirectory of the clone", "git clone https://example.org/o/r && cd r && cd sub && ./run.sh", true},
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
