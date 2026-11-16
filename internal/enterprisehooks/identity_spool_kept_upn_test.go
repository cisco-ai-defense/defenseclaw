// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// W19 review (loop round 1): a Windows record keeps its last known UPN for
// profile matching (GAP-0129, GAP-0284) and dates it as kept, so the gateway
// can leave it out of agent identity rows. The mark changes no UPN,
// principal or source.
func TestMarkWindowsKeptUPN(t *testing.T) {
	const sid, other = "S-1-5-21-111111111-222222222-333333333-4001", "S-1-5-21-111111111-222222222-333333333-4002"
	t0 := time.Date(2026, 10, 23, 1, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	verified := IdentitySpoolRecord{Key: sid, UpdatedAt: t0, UPNSource: UPNSourceTranslateName,
		Facts: useridentity.DirectoryFacts{UPN: "alice@corp.example", Principal: "alice@corp.example"}}
	keptAt := func(at time.Time) IdentitySpoolRecord {
		r := verified
		r.UPNKeptSince = at
		return r
	}
	pass := func(key, upn string) IdentitySpoolRecord {
		return IdentitySpoolRecord{Key: key, UpdatedAt: t1, UPNSource: UPNSourceTranslateName,
			Facts: useridentity.DirectoryFacts{UPN: upn, Principal: upn}}
	}
	for _, tc := range []struct {
		name             string
		record, previous IdentitySpoolRecord
		kept             bool
		want             time.Time
	}{
		{"a verified UPN is current", pass(sid, "alice@corp.example"), verified, false, time.Time{}},
		{"a verified UPN ends an earlier kept one", pass(sid, "alice@corp.example"), keptAt(t0), false, time.Time{}},
		{"a renamed UPN is current", pass(sid, "renamed@corp.example"), keptAt(t0), false, time.Time{}},
		{"the first kept pass", pass(sid, "alice@corp.example"), verified, true, t1},
		{"still kept", pass(sid, "alice@corp.example"), keptAt(t0), true, t0},
		{"still kept, other casing", pass(sid, "Alice@corp.example"), keptAt(t0), true, t0},
		{"another kept UPN", pass(sid, "older@corp.example"), keptAt(t0), true, t1},
		{"another account", pass(other, "alice@corp.example"), keptAt(t0), true, t1},
		{"a previous mark after this pass", pass(sid, "alice@corp.example"), keptAt(t1.Add(time.Minute)), true, t1},
		{"no UPN to keep", pass(sid, ""), keptAt(t0), true, time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := MarkWindowsKeptUPN(tc.record, tc.previous, tc.kept)
			if !got.UPNKeptSince.Equal(tc.want) || got.UPNKept() != !tc.want.IsZero() {
				t.Fatalf("kept since %v (kept %t); want %v", got.UPNKeptSince, got.UPNKept(), tc.want)
			}
			if got.Facts.UPN != tc.record.Facts.UPN || got.Facts.Principal != tc.record.Facts.Principal ||
				got.UPNSource != tc.record.UPNSource || got.Key != tc.record.Key || !got.UpdatedAt.Equal(tc.record.UpdatedAt) {
				t.Fatalf("record = %+v; the mark changed what profile matching reads", got)
			}
		})
	}
}

// A kept mark survives the spool file, which the gateway and a 1.0.3
// guardian (whose record has the same upn_kept_since field) both read.
func TestIdentitySpoolRecordUPNKept(t *testing.T) {
	const sid = "S-1-5-21-111111111-222222222-333333333-4001"
	at := time.Date(2026, 10, 23, 1, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		record IdentitySpoolRecord
		want   bool
	}{
		{"verified", IdentitySpoolRecord{UPNSource: UPNSourceTranslateName, Facts: useridentity.DirectoryFacts{UPN: "a@corp.example"}}, false},
		{"Windows kept", IdentitySpoolRecord{UPNSource: UPNSourceTranslateName, UPNKeptSince: at,
			Facts: useridentity.DirectoryFacts{UPN: "a@corp.example"}}, true},
		{"InfoPipe kept", IdentitySpoolRecord{UPNSource: UPNSourceInfoPipeKept, UPNKeptSince: at,
			Facts: useridentity.DirectoryFacts{UPN: "a@corp.example"}}, true},
		{"InfoPipe kept by an older build", IdentitySpoolRecord{UPNSource: UPNSourceInfoPipeKept,
			Facts: useridentity.DirectoryFacts{UPN: "a@corp.example"}}, true},
		{"no UPN", IdentitySpoolRecord{UPNKeptSince: at}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := tc.record
			record.Version, record.Key, record.UpdatedAt = IdentitySpoolRecordVersion, sid, at
			data, err := MarshalIdentitySpoolRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseIdentitySpoolRecord(data, sid)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.UPNKept() != tc.want || !parsed.UPNKeptSince.Equal(tc.record.UPNKeptSince) {
				t.Fatalf("parsed = %+v, kept %t; want kept %t", parsed, parsed.UPNKept(), tc.want)
			}
		})
	}
}
