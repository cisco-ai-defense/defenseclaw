// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"reflect"
	"testing"
)

func TestJudgeDarwinACLOutput(t *testing.T) {
	const listing = "-rw-r-----+ 1 root  wheel  12 Nov  2 10:00 /opt/x/config.yaml\n"
	cases := []struct {
		name               string
		acl                string
		wantVerdict        bool
		wantUntrusted      []string
		wantInheritOnly    []string
		wantEntries        int
		wantMalformedError bool
	}{
		{name: "no ACL", acl: "", wantEntries: 0},
		{name: "read entry", acl: " 0: group:everyone allow read,readattr,readextattr,readsecurity\n", wantEntries: 1},
		{name: "deny entry", acl: " 0: group:everyone deny write,delete\n", wantEntries: 1},
		{name: "root write", acl: " 0: user:root allow write,append\n", wantEntries: 1},
		{name: "wheel write", acl: " 0: group:wheel allow write,delete_child\n", wantEntries: 1},
		{name: "admin inherited write", acl: " 0: group:admin inherited allow write,file_inherit,directory_inherit\n", wantEntries: 1},
		{
			name: "everyone write", acl: " 0: group:everyone allow write\n",
			wantVerdict: true, wantUntrusted: []string{"group:everyone"}, wantEntries: 1,
		},
		{
			name: "user inherited write", acl: " 0: user:alice inherited allow add_file,file_inherit\n",
			wantVerdict: true, wantUntrusted: []string{"user:alice"}, wantEntries: 1,
		},
		{
			name: "inherit-only write", acl: " 0: group:everyone allow add_file,file_inherit,only_inherit\n",
			wantInheritOnly: []string{"group:everyone"}, wantEntries: 1,
		},
		{
			name: "mixed", acl: " 0: group:admin allow write\n 1: group:staff allow chown\n 2: user:bob allow read\n",
			wantVerdict: true, wantUntrusted: []string{"group:staff"}, wantEntries: 3,
		},
		{name: "malformed", acl: " 0: group:everyone allow\n", wantMalformedError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output := []byte(listing + tc.acl)
			entries, err := parseDarwinACLEntries("/opt/x/config.yaml", output)
			if tc.wantMalformedError {
				if err == nil {
					t.Fatal("parse succeeded, want malformed error")
				}
				if verdictErr := JudgeDarwinACLOutput("/opt/x/config.yaml", output); verdictErr == nil || isTrustVerdict(verdictErr) {
					t.Fatalf("JudgeDarwinACLOutput = %v, want a plain (non-verdict) error", verdictErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			judgement := judgeDarwinACLEntries(entries)
			if judgement.Entries != tc.wantEntries {
				t.Fatalf("entries = %d, want %d", judgement.Entries, tc.wantEntries)
			}
			if !reflect.DeepEqual(judgement.UntrustedWriters, tc.wantUntrusted) {
				t.Fatalf("untrusted = %v, want %v", judgement.UntrustedWriters, tc.wantUntrusted)
			}
			if !reflect.DeepEqual(judgement.InheritOnlyWriters, tc.wantInheritOnly) {
				t.Fatalf("inherit-only = %v, want %v", judgement.InheritOnlyWriters, tc.wantInheritOnly)
			}
			verdict := JudgeDarwinACLOutput("/opt/x/config.yaml", output)
			if tc.wantVerdict != (verdict != nil) {
				t.Fatalf("verdict = %v, want verdict %v", verdict, tc.wantVerdict)
			}
			if verdict != nil && !isTrustVerdict(verdict) {
				t.Fatalf("verdict %v is not a trust verdict", verdict)
			}
		})
	}
}

func TestJudgeDarwinACLOutputIgnoresPathnameText(t *testing.T) {
	output := []byte("drwx------  2 user  staff  64 Nov  2 10:00 /tmp/path allow write\n")
	if err := JudgeDarwinACLOutput("/tmp/path allow write", output); err != nil {
		t.Fatalf("pathname text was mistaken for an ACL entry: %v", err)
	}
}
