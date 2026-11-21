// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"
)

// The triple slash of a scheme is a URL spelling only where the share check
// reads it as a share (a Windows host, rel-1-0-10:GAP-0926). On a POSIX host
// host:///abs/path is the local /abs/path, so it stays a mention as it is at
// rel (rel-1-0-10:GAP-1665), and a one-letter scheme is a drive letter, no
// URL, on every host (C:///Users/u/f, rel-1-0-10:GAP-1661).
func TestGAP1665TripleSlashIsAURLOnlyWhereItReadsAsAShare(t *testing.T) {
	previous := networkShareRootOf
	t.Cleanup(func() { networkShareRootOf = previous })
	for _, row := range []struct {
		text             string
		share, posixHost bool // want, with the token read as a share / as a local path
	}{
		{`scp x.json localhost:///home/u/.ssh/authorized_keys`, true, false},
		{`rsync x.json u@localhost:///home/u/.ssh/authorized_keys`, true, false},
		{`echo http:///slow.example/share/f`, true, false},
		{`echo "http":///slow.example/share/f`, true, false},
		{`echo file:///home/u/.ssh/authorized_keys`, false, false},
		{`echo FILE:///home/u/.ssh/authorized_keys`, false, false},
		{`cp x.json C:///Users/u/.ssh/authorized_keys`, false, false},
		{`cp x.json "C":///Users/u/.ssh/authorized_keys`, false, false},
		{`cp x.json c:///Users/u/.ssh/authorized_keys`, false, false},
		// The double slash keeps its reading.
		{`echo http://slow.example/share/f`, true, false},
		{`echo C://slow.example/share/f`, true, false},
	} {
		start := strings.Index(row.text, "//")
		token := row.text[start:]
		for _, host := range []struct {
			name  string
			share bool
			want  bool
		}{{"share", true, row.share}, {"posix", false, row.posixHost}} {
			read := host.share
			networkShareRootOf = func(string) string {
				if read {
					return "//slow.example/share"
				}
				return ""
			}
			if got := actionURLAuthorityToken(row.text, start, token); got != host.want {
				t.Errorf("%s host %q: URL authority %v, want %v", host.name, row.text, got, host.want)
			}
		}
	}
}
