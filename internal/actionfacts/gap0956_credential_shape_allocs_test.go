// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// TestGAP0956CredentialShapeBuildsNoString: MatchCredentialFileShape runs on
// every path of every placed reading of a copy-mode call; the folder and
// suffix strings it built for each table row were most of the allocations
// of a long call (substrate-1 GAP-0956). A path that names no credentials
// file is matched with no allocation, and folderIndex gives the answer of
// the concatenated form.
func TestGAP0956CredentialShapeBuildsNoString(t *testing.T) {
	for _, value := range []string{"/home/sandbox/s0/s1/f5", "touch", "/tmp/out.txt"} {
		if allocs := testing.AllocsPerRun(50, func() { MatchCredentialFileShape(value) }); allocs != 0 {
			t.Errorf("MatchCredentialFileShape(%q) allocates %.0f times", value, allocs)
		}
	}
	concat := func(value, folder string) int {
		if strings.HasPrefix(value, folder+"/") {
			return 0
		}
		if index := strings.Index(value, "/"+folder+"/"); index >= 0 {
			return index + 1
		}
		return -1
	}
	values := []string{"", "/", "//", "a", ".aws", ".aws/", ".aws/credentials", "/home/u/.aws/credentials",
		"/home/u/x.aws/credentials", "/home/u/.aws", "/home/u/.awsx/.aws/c", ".aws/.aws/c", "a//b", "/a/.ssh/.ssh/id",
		"/.ssh", ".ssh.ssh/x", "x/.ssh/", "/a/b/c/.config/gcloud/x", ".config/gcloud"}
	for _, value := range values {
		for _, folder := range []string{"", ".aws", ".ssh", ".config/gcloud", "a", "b"} {
			if got, want := folderIndex(value, folder), concat(value, folder); got != want {
				t.Errorf("folderIndex(%q, %q) = %d, want %d", value, folder, got, want)
			}
			if got, want := hasPathSuffix(value, folder), strings.HasSuffix(value, "/"+folder); got != want {
				t.Errorf("hasPathSuffix(%q, %q) = %v, want %v", value, folder, got, want)
			}
		}
	}
}
