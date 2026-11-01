// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// A numeric group with no known local name may be an unnamed passwd primary
// gid. Its presence alone does not prove a directory source (r103 GAP-0149).
func TestMatchedGroupSourceDoesNotInventADirectoryForNumericGIDs(t *testing.T) {
	// The unnamed primary gid of a local passwd account is local; for any
	// other account its source is unknown, so it is omitted.
	for directory, want := range map[useridentity.Directory]string{
		useridentity.DirectoryLocal: "local", useridentity.DirectoryActiveDirectory: "", "": "",
	} {
		subject := &profileSubject{Directory: directory, Groups: []string{"29998"}}
		if got := matchedGroupSource(nil, subject, "29998"); got != want {
			t.Fatalf("directory=%q: numeric gid source = %q, want %q", directory, got, want)
		}
	}
	if got := matchedGroupSource(nil, &profileSubject{localAccount: true, Groups: []string{"29998"}}, "29998"); got != "local" {
		t.Fatalf("local account numeric gid source = %q, want local", got)
	}
	if got := matchedGroupSource(nil, &profileSubject{Groups: []string{`CORP\29998`}}, "29998"); got != "directory" {
		t.Fatalf("qualified numeric name source = %q, want directory", got)
	}
}
