// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package budgetstore

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

func testKeys(t *testing.T, fill byte) Keys {
	t.Helper()
	k, err := DeriveKeys(bytes.Repeat([]byte{fill}, SecretBytes))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// serve starts an HTTPS store and returns a client trusting its certificate.
func serve(t *testing.T, keys Keys) (*Client, *Store, *httptest.Server) {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv := httptest.NewTLSServer(&Handler{Store: store, Keys: serverKeys(t, keys)})
	t.Cleanup(srv.Close)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	client, err := NewClient(srv.URL, keys, caPEM, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return client, store, srv
}

func TestPushAndTotalsAcrossWriters(t *testing.T) {
	keys := testKeys(t, 1)
	client, _, _ := serve(t, keys)
	ctx := context.Background()
	today := time.Now().UTC().Format(time.DateOnly)
	key := "user:daily:*:ak1:1:0123456789abcdef0123456789abcdef"
	group := "group:eng:" + keys.SubjectHash(`DCLAB\eng`)
	if err := client.Push(ctx, "dev1-a", []routingadmin.SeedRow{{Day: today, Key: key, USD: 2}, {Day: today, Key: group, USD: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := client.Push(ctx, "dev1-a", []routingadmin.SeedRow{{Day: today, Key: key, USD: 3}}); err != nil { // absolute
		t.Fatal(err)
	}
	if err := client.Push(ctx, "dev2-b", []routingadmin.SeedRow{{Day: today, Key: key, USD: 4}}); err != nil {
		t.Fatal(err)
	}
	since := time.Now().AddDate(0, 0, -7)
	rows, err := client.Totals(ctx, "dev2-b", since, []string{key, group})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, r := range rows {
		got[r.Key] += r.USD
	}
	if got[key] != 3 || got[group] != 1 {
		t.Fatalf("other writers only, absolute totals: %v", got)
	}
	rows, _ = client.Totals(ctx, "dev3-c", since, []string{key})
	if len(rows) != 1 || rows[0].USD != 7 {
		t.Fatalf("a new writer sees both devices: %+v", rows)
	}
}

func post(t *testing.T, srv *httptest.Server, keys Keys, path string, body []byte, at time.Time) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(body))
	req.Header.Set(HeaderTime, strconv.FormatInt(at.Unix(), 10))
	req.Header.Set(HeaderSignature, keys.Sign(http.MethodPost, path, at, body))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var e ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&e)
	return resp.StatusCode, e.Error
}

func TestAuthFailuresAndReplayAreRefused(t *testing.T) {
	keys := testKeys(t, 1)
	_, _, srv := serve(t, keys)
	today := time.Now().UTC().Format(time.DateOnly)
	body, _ := json.Marshal(PushRequest{Epoch: "e1", Seq: 5, Rows: []Row{{Day: today, Key: "connector:c:codex", USD: 1}}})
	if code, _ := post(t, srv, keys, PathPush, body, time.Now()); code != http.StatusOK {
		t.Fatalf("signed push: %d", code)
	}
	if code, reason := post(t, srv, keys, PathPush, body, time.Now()); code != http.StatusConflict || reason != "replayed" {
		t.Fatalf("replay: %d %s", code, reason)
	}
	if code, reason := post(t, srv, testKeys(t, 2), PathPush, body, time.Now()); code != http.StatusUnauthorized || reason != "unauthorized" {
		t.Fatalf("another tenant secret: %d %s", code, reason)
	}
	if code, reason := post(t, srv, keys, PathPush, body, time.Now().Add(-10*time.Minute)); code != http.StatusUnauthorized || reason != "unauthorized" {
		t.Fatalf("old request: %d %s", code, reason)
	}
	bad, _ := json.Marshal(PushRequest{Epoch: "e2", Seq: 1, Rows: []Row{{Day: today, Key: "user:Alice Smith", USD: 1}}})
	if code, _ := post(t, srv, keys, PathPush, bad, time.Now()); code != http.StatusBadRequest {
		t.Fatalf("a key that is not a charge key: %d", code)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+PathPush, bytes.NewReader(body))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned: %d", resp.StatusCode)
	}
}

func TestClientRefusesPlaintextAndUntrustedCertificates(t *testing.T) {
	keys := testKeys(t, 1)
	for _, raw := range []string{"http://store:8443", "https://user:pw@store", "https://store/path", "https://store?x=1", "store:8443"} {
		if _, err := NewClient(raw, keys, nil, time.Second); err == nil {
			t.Fatalf("%s must be refused", raw)
		}
	}
	_, _, srv := serve(t, keys)
	untrusted, err := NewClient(srv.URL, keys, nil, 2*time.Second) // system roots only
	if err != nil {
		t.Fatal(err)
	}
	if err := untrusted.Push(context.Background(), "e1", []routingadmin.SeedRow{{Day: "2026-11-12", Key: "connector:c:codex", USD: 1}}); err == nil {
		t.Fatal("a certificate no trusted CA signed must fail")
	}
}

func TestStoreFileHoldsNoNames(t *testing.T) {
	keys := testKeys(t, 1)
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(&Handler{Store: store, Keys: serverKeys(t, keys)})
	defer srv.Close()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	client, _ := NewClient(srv.URL, keys, caPEM, 5*time.Second)
	today := time.Now().UTC().Format(time.DateOnly)
	names := []string{`DCLAB\eng`, "alice@dclab.test"}
	if err := client.Push(context.Background(), "e1", []routingadmin.SeedRow{
		{Day: today, Key: "group:eng:" + keys.SubjectHash(names[0]), USD: 1},
		{Day: today, Key: "user:named:=" + keys.SubjectHash(names[1]), USD: 1},
	}); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	for _, f := range []string{"store.db", "store.db-wal"} {
		data, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			continue
		}
		for _, name := range []string{"eng", "alice", "dclab"} {
			if bytes.Contains(bytes.ToLower(data), []byte(`dclab\`+name)) || bytes.Contains(bytes.ToLower(data), []byte(name+"@")) {
				t.Fatalf("%s holds %q", f, name)
			}
		}
	}
	if keys.SubjectHash(names[0]) == testKeys(t, 2).SubjectHash(names[0]) {
		t.Fatal("the subject hash must depend on the tenant secret")
	}
}

func TestPruneDropsOldDays(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	old := time.Now().UTC().AddDate(0, 0, -RetentionDays-1).Format(time.DateOnly)
	ctx := context.Background()
	if err := store.Push(ctx, PushRequest{Epoch: "e1", Seq: 1, Rows: []Row{{Day: old, Key: "connector:c:codex", USD: 1}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _ := store.Totals(ctx, TotalsRequest{Epoch: "e2", Since: "2000-01-01", Keys: []string{"connector:c:codex"}})
	if len(rows) != 0 {
		t.Fatalf("pruned: %+v", rows)
	}
}

func TestRateLimiter(t *testing.T) {
	limit := RateLimiter(2)
	if !limit("a") || !limit("a") || limit("a") || !limit("b") {
		t.Fatal("two per minute per host")
	}
}

// serverKeys are the store's keys: the auth key only.
func serverKeys(t *testing.T, device Keys) Keys {
	t.Helper()
	k, err := AuthKeys(device.AuthKey())
	if err != nil {
		t.Fatal(err)
	}
	if k.SubjectHash("x") != "" {
		t.Fatal("the store must not hold the subject key")
	}
	return k
}

func TestClientRefusesAnUnsignedOrRewrittenAnswer(t *testing.T) {
	keys := testKeys(t, 1)
	store, err := OpenStore(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	inner := &Handler{Store: store, Keys: serverKeys(t, keys)}
	rewrite := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		inner.ServeHTTP(rec, r)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(bytes.Replace(rec.Body.Bytes(), []byte(`"rows":null`), []byte(`"rows":[{"day":"2026-11-12","key":"connector:c:codex","usd":9999}]`), 1))
	})
	srv := httptest.NewTLSServer(rewrite)
	defer srv.Close()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	client, _ := NewClient(srv.URL, keys, caPEM, 5*time.Second)
	if _, err := client.Totals(context.Background(), "e1", time.Now().AddDate(0, 0, -1), []string{"connector:c:codex"}); err == nil {
		t.Fatal("a rewritten answer must be refused")
	}
}

func TestPushRefusesDaysOutsideTheWindow(t *testing.T) {
	now := time.Now()
	for _, day := range []string{"9999-12-31", now.AddDate(0, 0, -RetentionDays-2).Format(time.DateOnly)} {
		req := PushRequest{Epoch: "e1", Seq: 1, Rows: []Row{{Day: day, Key: "connector:c:codex", USD: 1}}}
		if req.validate(now) == nil {
			t.Fatalf("%s must be refused", day)
		}
	}
	if (PushRequest{Epoch: "e1", Seq: 1 << 63}).validate(now) == nil {
		t.Fatal("a sequence above 2^63-1 must be refused")
	}
}

func TestClientKeyGroupsIPv6ByPrefix(t *testing.T) {
	if clientKey("[2001:db8:1:2:aaaa::1]:443") != clientKey("[2001:db8:1:2:bbbb::9]:443") {
		t.Fatal("one /64 is one client")
	}
	if clientKey("192.0.2.1:443") != "192.0.2.1" {
		t.Fatal("IPv4 by address")
	}
}

func TestIdleWritersArePrunedButTheirSpendStays(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	today := time.Now().UTC().Format(time.DateOnly)
	if err := store.Push(ctx, PushRequest{Epoch: "e1", Seq: 1, Rows: []Row{{Day: today, Key: "connector:c:codex", USD: 2}}}); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return time.Now().Add(WriterIdle + time.Minute) }
	if err := store.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	var writers int
	_ = store.db.QueryRow(`SELECT COUNT(*) FROM writers`).Scan(&writers)
	rows, _ := store.Totals(ctx, TotalsRequest{Epoch: "e2", Since: today, Keys: []string{"connector:c:codex"}})
	if writers != 0 || len(rows) != 1 || rows[0].USD != 2 {
		t.Fatalf("writers %d rows %+v", writers, rows)
	}
}
