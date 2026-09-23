// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactTemporarySetuidExecutable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{name: "tmp direct", command: `chmod 4755 /tmp/helper`, want: true},
		{name: "var tmp sudo", command: `sudo chmod 04755 /var/tmp/.helper`, want: true},
		{name: "shared memory separator", command: `chmod -- 4700 /dev/shm/agent`, want: true},
		{name: "root defaulting su script", command: `/usr/bin/su -c 'id; cp /bin/bash /tmp/.helper; chmod 4755 /tmp/.helper'`, want: true},
		{name: "setgid only", command: `chmod 2755 /tmp/helper`},
		{name: "setuid without execute", command: `chmod 4644 /tmp/helper`},
		{name: "ordinary executable", command: `chmod 0755 /tmp/helper`},
		{name: "non temporary", command: `chmod 4755 /usr/local/bin/helper`},
		{name: "multiple targets", command: `chmod 4755 /tmp/a /tmp/b`},
		{name: "dynamic target", command: `chmod 4755 "$TARGET"`},
		{name: "recursive", command: `chmod -R 4755 /tmp/tree`},
		{name: "conditional", command: `test -f /tmp/helper && chmod 4755 /tmp/helper`},
		{name: "redirect", command: `chmod 4755 /tmp/helper 2>/dev/null`},
		{name: "unsupported wrapper", command: `env chmod 4755 /tmp/helper`},
		{name: "non root su user", command: `su alice -c 'chmod 4755 /tmp/helper'`},
		{name: "conditional su child", command: `su -c 'test -f /tmp/helper && chmod 4755 /tmp/helper'`},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "shell", Command: test.command, DialectHint: DialectPOSIX})
			if got := ExactTemporarySetuidExecutable(facts); got != test.want {
				t.Fatalf("ExactTemporarySetuidExecutable() = %v, want %v; facts=%#v", got, test.want, facts)
			}
		})
	}
}
