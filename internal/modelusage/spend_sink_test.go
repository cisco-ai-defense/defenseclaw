package modelusage

import (
	"testing"
	"time"
)

type recordingSink struct {
	keys []string
	usd  float64
	n    int
}

func (r *recordingSink) Charge(keys []string, usd float64, _ time.Time) {
	r.keys, r.usd, r.n = keys, usd, r.n+1
}

type idSink struct {
	recordingSink
	id string
}

func (s *idSink) ChargeCall(id string, keys []string, usd float64, at time.Time) {
	s.id = id
	s.Charge(keys, usd, at)
}

func TestChargeBudgetsComputedElseReportedAgentCostOnly(t *testing.T) {
	e := NewEngine()
	sink := &recordingSink{}
	e.SetSpendSink(sink)
	computed, reported := 0.25, 9.0
	keys := []string{"user:d:*:1001"}
	agent := CallFacts{CallRole: RoleAgent, ChargeKeys: keys}
	e.chargeBudgets(agent, Record{Cost: Cost{USD: &computed, Basis: BasisComputed}})
	if sink.n != 1 || sink.usd != 0.25 || sink.keys[0] != keys[0] {
		t.Fatalf("computed agent cost: %+v", sink)
	}
	e.chargeBudgets(agent, Record{Cost: Cost{USD: &reported, Basis: BasisReported, ComputedUSD: &computed}})
	if sink.n != 2 || sink.usd != 0.25 {
		t.Fatalf("when both are known the computed cost is charged: %+v", sink)
	}
	e.chargeBudgets(agent, Record{Cost: Cost{USD: &reported, Basis: BasisReported}})
	if sink.n != 3 || sink.usd != 9 {
		t.Fatalf("with no computed cost the reported one is charged: %+v", sink)
	}
	e.chargeBudgets(agent, Record{})
	e.chargeBudgets(CallFacts{CallRole: "judge", ChargeKeys: keys}, Record{Cost: Cost{USD: &computed, Basis: BasisComputed}})
	e.chargeBudgets(CallFacts{CallRole: RoleAgent}, Record{Cost: Cost{USD: &computed, Basis: BasisComputed}})
	if sink.n != 3 {
		t.Fatalf("unknown cost, judge calls and keyless calls charge nothing, never 0: %+v", sink)
	}
}

func TestChargeBudgetsUsesTheCallIDWhenTheSinkWantsIt(t *testing.T) {
	e := NewEngine()
	sink := &idSink{}
	e.SetSpendSink(sink)
	usd := 1.5
	e.chargeBudgets(CallFacts{RequestID: "req-9", CallRole: RoleAgent, ChargeKeys: []string{"k"}}, Record{Cost: Cost{USD: &usd, Basis: BasisComputed}})
	if sink.id != "req-9" || sink.n != 1 || sink.usd != 1.5 {
		t.Fatalf("%+v", sink)
	}
}

func TestNoSpendSinkIsFree(t *testing.T) {
	usd := 1.0
	e := NewEngine()
	e.chargeBudgets(CallFacts{CallRole: RoleAgent, ChargeKeys: []string{"k"}}, Record{Cost: Cost{USD: &usd, Basis: BasisComputed}})
	var nilEngine *Engine
	nilEngine.chargeBudgets(CallFacts{}, Record{})
	nilEngine.SetSpendSink(nil)
}
