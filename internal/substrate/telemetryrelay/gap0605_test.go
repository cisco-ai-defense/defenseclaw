// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetryrelay

import (
	"context"
	"strings"
	"testing"
)

// substrate-1:GAP-0605 (review 3). An egress record no registration
// matches kept the atespace and actor name the callout posted (trimmed and
// cut to 512 bytes) and the gateway exported them, though the callout only
// ever reads names that are SPIFFE path segments. The leader now keeps an
// unregistered record only when both names pass registry.ValidName, the
// check the callout applies to the SPIFFE ID; any other name is dropped.
func TestGAP0605UnregisteredEgressRecordsNeedWellFormedNames(t *testing.T) {
	s := &Store{Registrations: fakeRegs{}}
	_, _ = s.PostEgress(context.Background(), PostRequest{Records: []Record{
		{Kind: KindEgress, Atespace: "eng-web", Actor: "job-1", Host: "kept.example.com", Decision: "block"},
		{Kind: KindEgress, Atespace: "eng-web/../admin", Actor: "job-1", Host: "a.example.com", Decision: "block"},
		{Kind: KindEgress, Atespace: "eng-web", Actor: "job 1 forged=1", Host: "b.example.com", Decision: "block"},
		{Kind: KindEgress, Atespace: "eng-web", Actor: strings.Repeat("a", 300), Host: "c.example.com", Decision: "block"},
		{Kind: KindEgress, Atespace: "-eng", Actor: "job-1", Host: "d.example.com", Decision: "block"},
	}})
	out, _ := s.Take(context.Background(), TakeRequest{})
	if len(out.Records) != 1 || out.Records[0].Host != "kept.example.com" || !out.Records[0].Unregistered {
		t.Fatalf("kept %+v, want only the record with well-formed names, marked unregistered", out.Records)
	}
}
