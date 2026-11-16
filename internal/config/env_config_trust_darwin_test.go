// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package config

import (
	"os"
	"testing"
)

func TestJudgeEnvConfigMetadataDarwin(t *testing.T) {
	admin := func(uid uint32) bool { return uid == 501 }
	cases := []struct {
		name      string
		uid, gid  uint32
		perm      os.FileMode
		links     uint64
		drift     bool
		untrusted bool
	}{
		{name: "canonical", perm: 0o644, links: 1},
		{name: "tighter", perm: 0o600, links: 1},
		{name: "administrator owner", uid: 501, perm: 0o644, links: 1, drift: true},
		{name: "wheel group write", perm: 0o664, links: 1, drift: true},
		{name: "admin group write", gid: 80, perm: 0o664, links: 1, drift: true},
		{name: "staff group write", gid: 20, perm: 0o664, links: 1, drift: true, untrusted: true},
		{name: "other write", perm: 0o646, links: 1, drift: true, untrusted: true},
		{name: "standard user owner", uid: 502, perm: 0o644, links: 1, drift: true, untrusted: true},
		{name: "hard link", perm: 0o644, links: 2, drift: true, untrusted: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drift, untrusted := judgeEnvConfigMetadata(tc.uid, tc.gid, tc.perm, tc.links, admin)
			if (len(drift) > 0) != tc.drift || untrusted != tc.untrusted {
				t.Fatalf("drift %v untrusted %v; want drift %v untrusted %v", drift, untrusted, tc.drift, tc.untrusted)
			}
		})
	}
}
