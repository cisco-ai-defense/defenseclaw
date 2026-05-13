package behavioralrisk

import (
	"context"
	"testing"
	"time"
)

func TestAnalyzerScoresBurst(t *testing.T) {
	a := NewAnalyzer(StaticBaseline{DefaultRPM: 1})
	now := time.Unix(1000, 0)
	var got Result
	for i := 0; i < 5; i++ {
		got = a.Analyze(context.Background(), Event{AgentID: "agent-a", TaskID: "task", ResourceID: "database:customers", Domain: "customer_pii", Timestamp: now.Add(time.Duration(i) * time.Millisecond)})
	}
	if got.Score == 0 || !got.ShouldAlert {
		t.Fatalf("expected non-zero alert score, got %+v", got)
	}
}

func TestAnalyzerDetectsSequenceAndCrossDomain(t *testing.T) {
	a := NewAnalyzer(StaticBaseline{DefaultRPM: 1000})
	now := time.Unix(1000, 0)
	a.Analyze(context.Background(), Event{AgentID: "agent-a", TaskID: "task", ResourceID: "DESCRIBE", Domain: "internal", Timestamp: now})
	a.Analyze(context.Background(), Event{AgentID: "agent-a", TaskID: "task", ResourceID: "SELECT * FROM customers", Domain: "customer_pii", Timestamp: now.Add(time.Millisecond)})
	got := a.Analyze(context.Background(), Event{AgentID: "agent-a", TaskID: "task", ResourceID: "HTTP POST external", Domain: "finance", Timestamp: now.Add(2 * time.Millisecond)})
	if got.Score < 45 || !got.ShouldAlert {
		t.Fatalf("expected sequence/cross-domain alert, got %+v", got)
	}
}
