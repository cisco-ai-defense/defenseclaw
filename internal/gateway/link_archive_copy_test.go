// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestR107ArchiveCopyOfACommandLinkIsTheSameLink: cp -a (or -P, -d) of a
// link the command makes copies the link itself, so an append to the copy
// of a link to a project file is the ordinary write the plain copy is, per
// user and managed (rel-1-0-6:GAP-0259). The same copy of a link to the keys
// file still writes the keys file.
func TestR107ArchiveCopyOfACommandLinkIsTheSameLink(t *testing.T) {
	r106Reader2Check(t, []r106Reader2Row{
		{"plain archive copy then append", "project", `cp --archive README.md notes9.txt && echo k >> notes9.txt`, "allow"},
		{"archive copy of a made link then append", "project", `ln -s README.md rl1 && cp --archive rl1 notes9.txt && echo k >> notes9.txt`, "allow"},
		{"cp -a of a made link then append", "project", `ln -s README.md rl2 && cp -a rl2 copy2 && echo k >> copy2`, "allow"},
		{"cp -a -t of a made link then append", "project", `ln -s README.md rl5 && mkdir -p out5 && cp -a -t out5 rl5 && echo k >> out5/rl5`, "allow"},
		{"cp -P of a made ln -sr link then append", "project", `ln -sr README.md rr6 && cp -P rr6 nr6 && echo k >> nr6`, "allow"},
		{"cp -d of a made link then append", "project", `ln -s a.txt rl7 && cp -d rl7 n7 && echo k >> n7`, "allow"},
		{"link to the keys file then write", "project", `ln -sfn ../.ssh/authorized_keys plink && echo k >> plink`, "block"},
		{"link to the keys file, cp -a it, write the copy", "project", `ln -sfn ../.ssh/authorized_keys plink && cp -a plink pcopy && echo k >> pcopy`, "block"},
	})
}
