// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetryrelay

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// relayLeader is a leader serving s over HTTP, and a client of it.
func relayLeader(t *testing.T, s *Store) *leader.Client {
	t.Helper()
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, s)
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	return &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: 200 * time.Millisecond}
}

// escaped is an egress record whose text encoding/json writes six times as
// long: '&' is &.
func escaped(i int) Record {
	amp := strings.Repeat("&", MaxFieldBytes)
	return Record{Kind: KindEgress, Atespace: "eng-web", Actor: "alice-1", Host: amp, Path: "/" + amp[1:], Reason: amp,
		Category: amp, Decision: "block", Profile: string(rune('a' + i%26))}
}

// GAP-0580 (review 2): the byte bound counted raw text, but encoding/json
// writes < > & and control characters as 6-byte escapes, so the bound
// under-counted a record's size on the wire.
func TestGAP0580RecordSizeBoundsItsJSON(t *testing.T) {
	ctl := string([]byte{0x01, 0x1f, 0x7f}) + "  \"\\\n\t"
	cases := map[string]string{
		"ampersands": strings.Repeat("&", MaxFieldBytes),
		"angles":     strings.Repeat("<>", MaxFieldBytes/2),
		"control":    strings.Repeat(ctl, 40),
		"invalid":    strings.Repeat("\xff\xfe", MaxFieldBytes/2),
		"plain":      "x",
	}
	at := time.Date(2026, 11, 18, 1, 2, 3, 123456789, time.FixedZone("x", -(9*3600+30*60)))
	for name, v := range cases {
		// Every field set: each string to v, each flag true, the value to
		// its longest, so a field recordSize does not count shows here.
		var r Record
		rv := reflect.ValueOf(&r).Elem()
		for i := 0; i < rv.NumField(); i++ {
			switch f := rv.Field(i); f.Kind() {
			case reflect.String:
				f.SetString(v)
			case reflect.Bool:
				f.SetBool(true)
			case reflect.Int64:
				f.SetInt(math.MinInt64)
			}
		}
		r.At = at
		r = cutRecord(r)
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if got := recordSize(r); int64(len(raw)) > got {
			t.Errorf("%s: recordSize %d, but the record is %d JSON bytes", name, got, len(raw))
		}
	}
}

// GAP-0580 (review 2): a take of records whose text escapes (512-byte
// '/&&&...' paths) was about 1 MiB by the raw count and several MiB of JSON,
// over the 4 MiB a leader client reads, so the take failed and its records
// were lost. Each take is now bounded by the JSON size.
func TestGAP0580TakeAnswerFitsTheLeaderReadLimit(t *testing.T) {
	s := &Store{}
	const n = 1000
	for i := 0; i < n; i++ {
		s.Add(escaped(i))
	}
	client := relayLeader(t, s)
	got := 0
	taker := &Taker{Leader: client, Record: func(_ context.Context, out TakeResponse) { got += len(out.Records) }}
	for i := 0; i < 100 && got < n; i++ {
		if err := taker.TakeOnce(context.Background()); err != nil {
			t.Fatalf("take %d after %d records: %v", i, got, err)
		}
	}
	if got != n {
		t.Fatalf("took %d records, want %d", got, n)
	}
}

// GAP-0580 (review 2): Poster.Flush sent up to 2,000 records with no byte
// bound, so a batch of escaping records was over the leader's 4 MiB request
// limit and was refused. Each batch is now about 1 MiB of JSON at most.
func TestGAP0580PosterBatchesStayUnderTheLeaderRequestLimit(t *testing.T) {
	s := &Store{}
	p := &Poster{Leader: relayLeader(t, s), Method: MethodPostEgress}
	const n = 1000
	for i := 0; i < n; i++ {
		p.Add(escaped(i))
	}
	for i := 0; i < 100 && len(p.Pending()) > 0; i++ {
		if err := p.Flush(context.Background()); err != nil {
			t.Fatalf("flush %d with %d pending: %v", i, len(p.Pending()), err)
		}
	}
	recs, dropped := drain(t, s)
	if len(recs) != n || dropped != 0 {
		t.Fatalf("the leader got %d records (dropped %d), want %d", len(recs), dropped, n)
	}
}

// GAP-0580 (review 2): a batch the leader refused (bad_request, as for a
// body over its limit) was put back at the front of the queue, so every
// later flush sent it again and the poster never sent anything else. A
// refused batch is dropped; one that failed otherwise is kept.
func TestGAP0580ARefusedBatchDoesNotWedgeThePoster(t *testing.T) {
	var mu sync.Mutex
	var sent [][]string
	answer := http.StatusRequestEntityTooLarge
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req leader.Request
		var in PostRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil || json.Unmarshal(req.Body, &in) != nil {
			t.Error("the post does not decode")
		}
		hosts := []string{}
		for _, rec := range in.Records {
			hosts = append(hosts, rec.Host)
		}
		mu.Lock()
		sent = append(sent, hosts)
		code := answer
		mu.Unlock()
		w.WriteHeader(code)
		switch code {
		case http.StatusRequestEntityTooLarge:
			_, _ = w.Write([]byte(`{"error":{"code":"bad_request","message":"body too large"}}`))
		case http.StatusInternalServerError:
			_, _ = w.Write([]byte(`{"error":{"code":"internal","message":"store failed"}}`))
		default:
			_, _ = w.Write([]byte(`{"body":{}}`))
		}
	}))
	t.Cleanup(hs.Close)
	p := &Poster{Leader: &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: 200 * time.Millisecond}, Method: MethodPostEgress}
	p.Add(Record{Kind: KindEgress, Host: "a"}, Record{Kind: KindEgress, Host: "b"})
	if err := p.Flush(context.Background()); err == nil {
		t.Fatal("a refused batch flushed without an error")
	}
	if pending := p.Pending(); len(pending) != 0 {
		t.Fatalf("the refused batch is still pending: %+v", pending)
	}
	mu.Lock()
	answer = http.StatusInternalServerError
	mu.Unlock()
	p.Add(Record{Kind: KindEgress, Host: "c"})
	if err := p.Flush(context.Background()); err == nil {
		t.Fatal("a failed flush returned no error")
	}
	if pending := p.Pending(); len(pending) != 1 || pending[0].Host != "c" {
		t.Fatalf("a batch that failed without a refusal was not kept: %+v", pending)
	}
	mu.Lock()
	answer = http.StatusOK
	mu.Unlock()
	p.Add(Record{Kind: KindEgress, Host: "d"})
	if err := p.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 3 || strings.Join(sent[2], ",") != "c,d" {
		t.Fatalf("posts %v, want [a b] [c] [c d]", sent)
	}
}
