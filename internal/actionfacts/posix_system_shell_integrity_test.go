// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactPOSIXSystemShellReplacement(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{name: "Terminal Wrench copy", command: "cp /bin/bash /bin/dash\n", want: true},
		{name: "conditional replacement abstains", command: "mv /bin/dash /bin/dash.orig && cp /bin/bash /bin/dash\n"},
		{name: "symlink retarget abstains", command: "ln -sf /bin/bash /bin/sh\n"},
		{name: "ordinary shell copy", command: "cp /bin/bash /tmp/bash\n"},
		{name: "dash backup", command: "cp /bin/dash /bin/dash.real\n"},
		{name: "restore dash", command: "cp /bin/dash.real /bin/dash\n"},
		{name: "relative source", command: "cp ./bash /bin/dash\n"},
		{name: "dynamic target", command: "cp /bin/bash \"$TARGET\"\n"},
		{name: "different backup", command: "mv /bin/dash /tmp/dash && cp /bin/bash /bin/dash\n"},
		{name: "condition unrelated", command: "test -f /tmp/flag && cp /bin/bash /bin/dash\n"},
		{name: "pipeline", command: "cp /bin/bash /bin/dash | cat\n"},
		{name: "wrapper", command: "sudo cp /bin/bash /bin/dash\n"},
		{name: "force option on copy", command: "cp -f /bin/bash /bin/dash\n"},
		{name: "link option", command: "ln -s /bin/bash /bin/dash\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "bash_command", Command: test.command,
				CWD: "/app", DialectHint: DialectPOSIX,
			})
			if got := ExactPOSIXSystemShellReplacement(facts); got != test.want {
				t.Fatalf("proof=%t want=%t facts=%#v", got, test.want, facts)
			}
		})
	}
}
