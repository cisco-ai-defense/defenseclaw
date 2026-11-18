// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetryrelay

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"
)

// drain takes from s until it is empty and returns every record and the
// sum of Dropped.
func drain(t *testing.T, s *Store) ([]Record, int64) {
	t.Helper()
	var all []Record
	var dropped int64
	for i := 0; i < 100000; i++ {
		out, err := s.Take(context.Background(), TakeRequest{})
		if err != nil {
			t.Fatal(err)
		}
		dropped += out.Dropped
		if len(out.Records) == 0 {
			return all, dropped
		}
		all = append(all, out.Records...)
	}
	t.Fatal("the queue never emptied")
	return nil, 0
}

// GAP-0580: a record's text fields were kept at any length, so one callout
// post (up to a 4 MiB body) could hold megabytes per record in the
// leader's memory. They are cut to 512 bytes, at a character boundary.
func TestGAP0580TextFieldsAreCutAtACharacterBoundary(t *testing.T) {
	s := &Store{}
	long := strings.Repeat("é", 1<<20) // 2 MiB of two-byte characters
	s.Add(Record{Kind: KindEgress, Host: "pypi.org" + long, Path: "/" + long, Reason: long, Category: long, Actor: "alice-1" + long},
		Record{Kind: KindLifecycle, Lifecycle: "crashed", Actor: long, Template: long})
	recs, _ := drain(t, s)
	if len(recs) != 2 {
		t.Fatalf("got %d records", len(recs))
	}
	for _, r := range recs {
		for name, v := range map[string]string{"host": r.Host, "path": r.Path, "reason": r.Reason, "category": r.Category, "actor": r.Actor, "template": r.Template} {
			if len(v) > 512 {
				t.Errorf("%s %s is %d bytes, over 512", r.Kind, name, len(v))
			}
			if !utf8.ValidString(v) {
				t.Errorf("%s %s was cut inside a character", r.Kind, name)
			}
		}
	}
}

// GAP-0580: one shared queue dropped the oldest record of any kind, so a
// burst of egress decisions pushed out lifecycle crashed and deleted
// records and the controller's counts.
func TestGAP0580EgressDoesNotEvictLifecycleOrCounts(t *testing.T) {
	s := &Store{MaxQueue: 4}
	s.Add(Record{Kind: KindLifecycle, Lifecycle: "crashed", Actor: "alice-1"},
		Record{Kind: KindCount, Metric: MetricIdleSuspends, Value: 1},
		Record{Kind: KindLifecycle, Lifecycle: "deleted", Actor: "alice-1"})
	for i := 0; i < 100; i++ {
		s.Add(Record{Kind: KindEgress, Host: "pypi.org", Decision: "allow"})
	}
	recs, dropped := drain(t, s)
	var crashed, deleted, counts, egress int
	for _, r := range recs {
		switch {
		case r.Kind == KindLifecycle && r.Lifecycle == "crashed":
			crashed++
		case r.Kind == KindLifecycle && r.Lifecycle == "deleted":
			deleted++
		case r.Kind == KindCount:
			counts++
		case r.Kind == KindEgress:
			egress++
		}
	}
	if crashed != 1 || deleted != 1 || counts != 1 {
		t.Fatalf("egress pushed out lifecycle records or counts: crashed %d deleted %d counts %d (egress %d, dropped %d)", crashed, deleted, counts, egress, dropped)
	}
	if egress == 0 || dropped == 0 {
		t.Fatalf("egress %d dropped %d: the egress bound did not apply", egress, dropped)
	}
}

// GAP-0580: the queue was bounded by record count only (50,000), not in
// bytes. Now each queue holds at most 16 MiB.
func TestGAP0580QueueIsBoundedInBytes(t *testing.T) {
	s := &Store{}
	f := strings.Repeat("x", 600)
	for i := 0; i < 20000; i++ {
		s.Add(Record{Kind: KindEgress, Atespace: f, Actor: f, UID: f, Profile: f, Host: f, Path: f, Reason: f, Category: f})
	}
	recs, dropped := drain(t, s)
	var text int64
	for _, r := range recs {
		text += int64(len(r.Atespace) + len(r.Actor) + len(r.UID) + len(r.Profile) + len(r.Host) + len(r.Path) + len(r.Reason) + len(r.Category))
	}
	if text > 16<<20 {
		t.Fatalf("the queue held %d MiB of text (%d records), over 16 MiB", text>>20, len(recs))
	}
	if dropped == 0 {
		t.Fatal("nothing was dropped past the byte bound")
	}
}
