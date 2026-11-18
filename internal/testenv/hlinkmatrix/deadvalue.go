// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hlinkmatrix

// DeadValueRow is one dead-value proof row (rel-1-0-6 GAP-0431): a variable
// holds the protected link name, is rebound to an ordinary file, and the
// write uses the rebound value. ProvedSafe is the client proof's answer with
// no shell startup in the environment.
type DeadValueRow struct {
	ID, Command string
	ProvedSafe  bool
}

// DeadValueRows are the rows of the dead-value proof tests, shared by the
// hookpaths proof test and the gateway four-cell tests.
func DeadValueRows() []DeadValueRow {
	return []DeadValueRow{
		{"ordinary-redirect", `f=keylink; f=a.txt; echo m >> "$f"`, true},
		{"quoted-install", `f=keylink; f=a.txt; install b.txt "$f"`, true},
		{"quoted-rsync", `f=keylink; f=a.txt; rsync b.txt "$f"`, true},
		{"rebound-home", `HOME=/tmp/project; f=~/keylink; echo m >> "$f"`, false},
		{"directory-stack-tilde", `f=~+/keylink; echo m >> "$f"`, false},
		{"unquoted-install", `f=keylink; f=a.txt; install b.txt $f`, false},
		{"unquoted-rsync", `f=keylink; f=a.txt; rsync b.txt $f`, false},
	}
}
