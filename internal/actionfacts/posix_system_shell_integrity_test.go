// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

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

func TestExactPOSIXSystemInterpreterWrapper(t *testing.T) {
	const wrapper = "if [ ! -e /usr/bin/python3.12.real ]; then mv /usr/bin/python3.12 /usr/bin/python3.12.real; fi\n" +
		"cat >/usr/bin/.python3.12.wrap <<'EOF'\n" +
		"#!/bin/sh.real\n" +
		"PYTHONPATH=/opt/pyspoof${PYTHONPATH:+:$PYTHONPATH}\n" +
		"export PYTHONPATH\n" +
		"exec /usr/bin/python3.12.real \"$@\"\n" +
		"EOF\n" +
		"chmod 0755 /usr/bin/.python3.12.wrap\n" +
		"mv -f /usr/bin/.python3.12.wrap /usr/bin/python3.12\n"

	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{name: "Terminal Wrench versioned Python wrapper", command: wrapper, want: true},
		{name: "project-local wrapper", command: strings.ReplaceAll(wrapper, "/usr/bin/", "/app/")},
		{name: "unversioned interpreter", command: strings.ReplaceAll(wrapper, "python3.12", "python3")},
		{name: "dynamic injected path", command: strings.Replace(wrapper, "/opt/pyspoof", "$SPOOF", 1)},
		{name: "missing backup", command: strings.Replace(wrapper, "if [ ! -e /usr/bin/python3.12.real ]; then mv /usr/bin/python3.12 /usr/bin/python3.12.real; fi\n", "", 1)},
		{name: "different backup", command: strings.Replace(wrapper, "/usr/bin/python3.12.real; fi", "/tmp/python3.12.real; fi", 1)},
		{name: "different delegate", command: strings.Replace(wrapper, "exec /usr/bin/python3.12.real", "exec /tmp/python3.12.real", 1)},
		{name: "conditional replacement", command: strings.Replace(wrapper, "mv -f /usr/bin/.python3.12.wrap /usr/bin/python3.12", "test -e /tmp/flag && mv -f /usr/bin/.python3.12.wrap /usr/bin/python3.12", 1)},
		{name: "extra wrapper command", command: strings.Replace(wrapper, "export PYTHONPATH\n", "export PYTHONPATH\nid\n", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "bash_command", Command: test.command, CWD: "/app", DialectHint: DialectPOSIX})
			if got := ExactPOSIXSystemInterpreterWrapper(facts); got != test.want {
				t.Fatalf("proof=%t want=%t parse=%s facts=%#v", got, test.want, facts.Parse.Status, facts)
			}
		})
	}
}
