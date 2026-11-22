// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetryrelay

import (
	"context"
	"testing"
)

func TestStoreHandsEachRecordOnceAndKeepsTheNewestGauge(t *testing.T) {
	s := &Store{MaxQueue: 2}
	s.Add(
		Record{Kind: KindEgress, Host: "a"},
		Record{Kind: KindCount, Metric: MetricIdleSuspends, Value: 1},
		Record{Kind: KindCount, Metric: "made_up", Value: 1},             // unknown metric: dropped
		Record{Kind: KindCount, Metric: MetricPolicyConflicts, Value: 0}, // no increment: dropped
		Record{Kind: KindGauge, Metric: MetricUnattestedTemplates, Value: 4},
		Record{Kind: "other"},
		Record{Kind: KindLifecycle, Actor: "x"},
		Record{Kind: KindEgress, Host: "b"},
		Record{Kind: KindEgress, Host: "c"}, // over the egress bound: the oldest egress record goes
	)
	out, _ := s.Take(context.Background(), TakeRequest{Max: 2})
	if len(out.Records) != 2 || out.Records[0].Kind != KindCount || out.Records[1].Kind != KindLifecycle || out.Dropped != 1 || out.Gauges[MetricUnattestedTemplates] != 4 {
		t.Fatalf("first take %+v", out)
	}
	out, _ = s.Take(context.Background(), TakeRequest{})
	if len(out.Records) != 2 || out.Records[0].Host != "b" || out.Records[1].Host != "c" || out.Dropped != 0 || out.Gauges[MetricUnattestedTemplates] != 4 {
		t.Fatalf("second take %+v", out)
	}
	out, _ = s.Take(context.Background(), TakeRequest{})
	if len(out.Records) != 0 {
		t.Fatalf("a record was handed on twice: %+v", out)
	}
}

func TestPosterKeepsOnlyTheNewestGaugeValue(t *testing.T) {
	p := &Poster{}
	p.Add(Record{Kind: KindGauge, Metric: MetricUnattestedTemplates, Value: 1}, Record{Kind: KindEgress, Host: "h"},
		Record{Kind: KindGauge, Metric: MetricUnattestedTemplates, Value: 2})
	if pending := p.Pending(); len(pending) != 2 || pending[1].Value != 2 {
		t.Fatalf("pending %+v", pending)
	}
}

func TestEachPosterMethodTakesOnlyItsKinds(t *testing.T) {
	s := &Store{}
	all := PostRequest{Records: []Record{
		{Kind: KindEgress, Host: "h", Decision: "allow"}, {Kind: KindCount, Metric: MetricIdleSuspends, Value: 1},
		{Kind: KindLifecycle, Actor: "forged"}, {Kind: KindGauge, Metric: MetricUnattestedTemplates, Value: 2},
	}}
	_, _ = s.PostEgress(context.Background(), all)
	out, _ := s.Take(context.Background(), TakeRequest{})
	if len(out.Records) != 1 || out.Records[0].Kind != KindEgress || len(out.Gauges) != 0 {
		t.Fatalf("egress post kept %+v", out)
	}
	_, _ = s.PostCounts(context.Background(), all)
	out, _ = s.Take(context.Background(), TakeRequest{})
	if len(out.Records) != 1 || out.Records[0].Kind != KindCount || out.Gauges[MetricUnattestedTemplates] != 2 {
		t.Fatalf("counts post kept %+v", out)
	}
}
