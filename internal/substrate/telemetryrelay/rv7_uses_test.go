package telemetryrelay

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// RV7-2 (GAP-0803): one actor that calls many distinct hosts keeps only
// its own newest hosts and never pushes out another actor's last use.
func TestRV7UsesFloodKeepsOtherActors(t *testing.T) {
	ctx := context.Background()
	s := &Store{}
	now := time.Now().UTC()
	rec := func(uid, host string, at time.Time) Record {
		return Record{Kind: KindEgress, Atespace: "eng", Actor: "a-" + uid, UID: uid, Host: host, Decision: "allow", At: at}
	}
	if _, err := s.PostEgress(ctx, PostRequest{Records: []Record{rec("victim", "github.com", now.Add(-time.Minute))}}); err != nil {
		t.Fatal(err)
	}
	var flood []Record
	for i := range DefaultMaxHostUses + 1 {
		flood = append(flood, rec("attacker", fmt.Sprintf("h%d.example.com", i), now.Add(-time.Duration(DefaultMaxHostUses+1-i)*time.Millisecond)))
		if len(flood) == 500 {
			if _, err := s.PostEgress(ctx, PostRequest{Records: flood}); err != nil {
				t.Fatal(err)
			}
			flood = nil
		}
	}
	if _, err := s.PostEgress(ctx, PostRequest{Records: flood}); err != nil {
		t.Fatal(err)
	}
	v, _ := s.HostUses(ctx, HostUsesRequest{Actors: []ActorRef{{Atespace: "eng", UID: "victim"}}})
	if len(v.Uses) != 1 || v.Uses[0].Host != "github.com" {
		t.Errorf("victim uses after the flood = %+v, want github.com", v.Uses)
	}
	a, _ := s.HostUses(ctx, HostUsesRequest{Actors: []ActorRef{{Atespace: "eng", UID: "attacker"}}})
	if len(a.Uses) != DefaultMaxHostUsesPerActor || a.Uses[0].Host != fmt.Sprintf("h%d.example.com", DefaultMaxHostUses) {
		t.Errorf("attacker keeps %d uses (newest %+v), want its newest %d", len(a.Uses), a.Uses[:1], DefaultMaxHostUsesPerActor)
	}
	if s.useCount != 1+DefaultMaxHostUsesPerActor {
		t.Errorf("useCount = %d, want %d", s.useCount, 1+DefaultMaxHostUsesPerActor)
	}
}

// RV7-3: a person with more than 256 agents reads all their uses.
func TestRV7UseReaderBatches(t *testing.T) {
	s := &Store{}
	now := time.Now().UTC()
	var recs []Record
	var actors []ActorRef
	for i := range 300 {
		uid := fmt.Sprintf("u%03d", i)
		recs = append(recs, Record{Kind: KindEgress, Atespace: "eng", Actor: "a-" + uid, UID: uid, Host: "github.com", Decision: "allow", At: now})
		actors = append(actors, ActorRef{Atespace: "eng", UID: uid})
	}
	if _, err := s.PostEgress(context.Background(), PostRequest{Records: recs}); err != nil {
		t.Fatal(err)
	}
	got, err := (&UseReader{Leader: relayLeader(t, s)}).HostUses(context.Background(), actors)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 300 {
		t.Errorf("uses for 300 actors = %d, want 300", len(got))
	}
}
