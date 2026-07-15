package axis

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestBrokerFailClosedAndIdempotency(t *testing.T) {
	db, e := sql.Open("sqlite", ":memory:")
	if e != nil {
		t.Fatal(e)
	}
	b := NewBroker(db, map[string]string{})
	b.LocalJudge = false
	if e = b.Init(); e != nil {
		t.Fatal(e)
	}
	r := AuthorizationRequest{ProtocolVersion: ProtocolVersion, ExecutionID: "e1", SessionID: "s1", CallID: "c1", ToolClass: ToolRead, Workspace: "/missing", Invocation: Invocation{Program: "true"}}
	d, _ := requestDigest(r)
	r.RequestDigest = d
	o := b.Authorize(context.Background(), r)
	if o.Decision != "deny" {
		t.Fatal("unavailable lane allowed")
	}
	b.LocalJudge = true
	b.Registry = map[string]string{"/tmp": "/tmp"}
	r.ExecutionID = "e2"
	r.SessionID = "s2"
	r.CallID = "c2"
	r.Workspace = "/tmp"
	r.RelativeCWD = "."
	d, _ = requestDigest(r)
	r.RequestDigest = d
	o = b.Authorize(context.Background(), r)
	if o.Decision != "allow" {
		t.Fatalf("authorize: %+v", o)
	}
	o = b.Authorize(context.Background(), r)
	if o.Decision != "allow" {
		t.Fatal("idempotent replay denied")
	}
	time.Sleep(time.Millisecond)
}
