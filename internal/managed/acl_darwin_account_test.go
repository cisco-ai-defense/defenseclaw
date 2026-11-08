// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import "testing"

// The account rule refuses what the strict rule refuses, except an entry for a
// principal that can change the path anyway (GAP-0053 REVIEW-7 MF1).
func TestJudgeDarwinACLOutputForAccount(t *testing.T) {
	cases := []struct {
		name    string
		acl     string
		account string
		refused bool
	}{
		{name: "no ACL", acl: ""},
		{name: "root write on a folder", acl: " 0: user:root allow add_file,delete_child\n"},
		{name: "wheel write", acl: " 0: group:wheel allow write,delete_child\n"},
		{name: "admin inherited write", acl: " 0: group:admin inherited allow write,file_inherit,directory_inherit\n"},
		{name: "the account itself", acl: " 0: user:Alice allow add_file,delete_child\n", account: "alice"},
		{name: "read entry for everyone", acl: " 0: group:everyone allow read,readattr\n"},
		{name: "deny entry for everyone", acl: " 0: group:everyone deny write,delete\n"},
		{name: "everyone write", acl: " 0: group:everyone allow write\n", refused: true},
		{name: "everyone add_file", acl: " 0: group:everyone allow add_file,delete_child\n", account: "alice", refused: true},
		{name: "staff write", acl: " 0: group:staff allow write\n", refused: true},
		{name: "another account", acl: " 0: user:bob allow write,append\n", account: "alice", refused: true},
		{name: "another account when the name is unknown", acl: " 0: user:alice allow write\n", refused: true},
		{name: "inherit-only write", acl: " 0: group:everyone allow add_file,file_inherit,only_inherit\n", refused: true},
		{
			name:    "trusted entry does not hide an untrusted one",
			acl:     " 0: user:root allow write\n 1: group:everyone allow write\n",
			refused: true,
		},
		{name: "unparsable entry", acl: " 0: user:root allow\n", refused: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := JudgeDarwinACLOutputForAccount("/home/alice/.config/opencode", []byte(tc.acl), tc.account)
			if (err != nil) != tc.refused {
				t.Fatalf("verdict = %v, want refused=%v", err, tc.refused)
			}
		})
	}
}
