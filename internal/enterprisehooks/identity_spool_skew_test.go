// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// identitySpoolRecord103 is the record as the gateways and guardians of
// 0.8.10 to 1.0.3 decode it: these fields only, unknown fields refused, the
// first JSON value of the file only (ParseIdentitySpoolRecord at fc6794381d).
type identitySpoolRecord103 struct {
	Version         int                         `json:"version"`
	Key             string                      `json:"key"`
	User            string                      `json:"user,omitempty"`
	UpdatedAt       time.Time                   `json:"updated_at"`
	UPNSource       string                      `json:"upn_source,omitempty"`
	UPNKeptSince    time.Time                   `json:"upn_kept_since,omitzero"`
	SSSDDomain      string                      `json:"sssd_domain,omitempty"`
	AccountDomain   string                      `json:"account_domain,omitempty"`
	Facts           useridentity.DirectoryFacts `json:"facts"`
	ConnectorEmails map[string]string           `json:"connector_emails,omitempty"`
}

func parseIdentitySpoolRecord103(data []byte) (identitySpoolRecord103, error) {
	var record identitySpoolRecord103
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&record)
	return record, err
}

// W2B-G-enum review loop 5: the guardian wrote account_sid in the record
// object, which a 1.0.3 gateway still running beside it (during the package
// upgrade, or after a rollback) refused as an unknown field. The SSSD user
// whose UPN only the record holds then fell from a UPN assignment to the
// default profile. The SID now goes in an extension after the record
// object, which those builds do not read, and the record object is what
// they decode.
func TestIdentitySpoolRecordWithASIDStaysReadableByAnOlderGateway(t *testing.T) {
	record := IdentitySpoolRecord{Key: "94401601", User: "dcad-alice", SSSDDomain: "dclab.test", UpdatedAt: time.Now().UTC().Truncate(time.Second),
		UPNSource: UPNSourceInfoPipe, AccountSID: "S-1-5-21-1-2-3-1601",
		Facts: useridentity.DirectoryFacts{UPN: "alice.alt@alt.dclab.test", Principal: "alice.alt@alt.dclab.test", Source: useridentity.SourceSSSDInfoPipe}}
	data, err := MarshalIdentitySpoolRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	old, err := parseIdentitySpoolRecord103(data)
	if err != nil {
		t.Fatalf("a 1.0.3 gateway refuses the record: %v\n%s", err, data)
	}
	if old.Facts.UPN != record.Facts.UPN || old.Key != record.Key || old.User != record.User {
		t.Fatalf("a 1.0.3 gateway reads %+v, want the record's UPN", old)
	}
	got, err := ParseIdentitySpoolRecord(data, record.Key)
	if err != nil || got.AccountSID != record.AccountSID || got.Facts.UPN != record.Facts.UPN {
		t.Fatalf("this build reads %+v (%v), want the SID and the UPN", got, err)
	}
	// A record without a SID is the record object alone, as before.
	record.AccountSID = ""
	plain, err := MarshalIdentitySpoolRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "\n") || strings.Contains(string(plain), "account_sid") {
		t.Fatalf("a record without a SID carries an extension: %s", plain)
	}
	if got, err := ParseIdentitySpoolRecord(plain, record.Key); err != nil || got.AccountSID != "" {
		t.Fatalf("a record a 1.0.3 guardian wrote: %+v (%v)", got, err)
	}
	// A later build may add facts to the extension; anything after it, or
	// an extension that is not an object, is refused.
	later := append(append([]byte(nil), plain...), []byte("\n"+`{"account_sid":"S-1-5-21-1-2-3-1601","future_fact":1}`)...)
	if got, err := ParseIdentitySpoolRecord(later, record.Key); err != nil || got.AccountSID != "S-1-5-21-1-2-3-1601" {
		t.Fatalf("an extension with a later fact: %+v (%v)", got, err)
	}
	for _, bad := range []string{`{"account_sid":"S-1-5-21-1"} {"account_sid":"S-1-5-21-2"}`, `"S-1-5-21-1"`, `{"account_sid":`} {
		if _, err := ParseIdentitySpoolRecord(append(append([]byte(nil), plain...), []byte("\n"+bad)...), record.Key); err == nil {
			t.Errorf("extension %s was accepted", bad)
		}
	}
	// The record object still refuses unknown fields, so the SID in it
	// (what the first 1.0.4 builds wrote) is not trusted silently either.
	inline := strings.Replace(string(plain), `"key":`, `"account_sid":"S-1-5-21-1-2-3-1601","key":`, 1)
	if _, err := ParseIdentitySpoolRecord([]byte(inline), record.Key); err == nil {
		t.Error("a SID inside the record object was accepted")
	}
}
