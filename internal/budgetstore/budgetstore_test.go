// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package budgetstore

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

const (
	aliceSID = "S-1-5-21-1-2-3-1001"
	bobUPN   = "bob@dclab.test"
	engGroup = `DCLAB\eng`
)

var testBudgets = []config.RoutingBudget{
	{ID: "daily", Scope: "user", Subject: "*", Period: "day", LimitUSD: 10},
	{ID: "eng", Scope: "group", Subject: engGroup, Period: "day", LimitUSD: 5},
	{ID: "codex", Scope: "connector", Subject: "codex", Period: "day", LimitUSD: 50},
}

func subjectKey(t *testing.T, fill byte) SubjectKey {
	t.Helper()
	k, err := NewSubjectKey(bytes.Repeat([]byte{fill}, SecretBytes))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type fixture struct {
	t       *testing.T
	store   *Store
	srv     *httptest.Server
	caPEM   []byte
	subject SubjectKey
	dir     string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	store.SetBudgets(map[string]Budget{"eng": {LimitUSD: 5, Period: "day"}, "codex": {LimitUSD: 50, Period: "day"}})
	srv := httptest.NewTLSServer(&Handler{Store: store})
	t.Cleanup(srv.Close)
	return &fixture{t: t, store: store, srv: srv, subject: subjectKey(t, 1), dir: dir,
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})}
}

// device issues and registers one device and returns its credential and client.
func (f *fixture) device(users, groups []string, capUSD float64) (Credential, *Client) {
	f.t.Helper()
	cred, rec, err := Issue(f.subject, IssueInput{Budgets: testBudgets, Users: users, Groups: groups, CapUSD: capUSD})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.store.AddDevice(context.Background(), rec, false); err != nil {
		f.t.Fatal(err)
	}
	key, err := cred.Key()
	if err != nil {
		f.t.Fatal(err)
	}
	client, err := NewClient(f.srv.URL, key, f.caPEM, 5*time.Second)
	if err != nil {
		f.t.Fatal(err)
	}
	return cred, client
}

func userKey(c Credential, budget string, i int) string {
	return "user:" + budget + ":*:" + c.Users[i].ID
}

func groupKey(c Credential) string {
	for _, fleet := range c.Keys {
		if strings.HasPrefix(fleet, "group:eng:") {
			return fleet
		}
	}
	return ""
}

func today() string { return time.Now().UTC().Format(time.DateOnly) }

func sum(rows []routingadmin.SeedRow) map[string]float64 {
	out := map[string]float64{}
	for _, r := range rows {
		out[r.Key] += r.USD
	}
	return out
}

func TestOneUserAcrossDevicesSeesOtherWritersOnly(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	credA, a := f.device([]string{aliceSID}, nil, 0)
	credB, b := f.device([]string{aliceSID, bobUPN}, nil, 0)
	alice := userKey(credA, "daily", 0)
	if alice != userKey(credB, "daily", 0) {
		t.Fatal("one user has one fleet id on every device")
	}
	if err := a.Push(ctx, "ea", []routingadmin.SeedRow{{Day: today(), Key: alice, USD: 2}}); err != nil {
		t.Fatal(err)
	}
	if err := a.Push(ctx, "ea", []routingadmin.SeedRow{{Day: today(), Key: alice, USD: 3}}); err != nil { // absolute
		t.Fatal(err)
	}
	if err := b.Push(ctx, "eb", []routingadmin.SeedRow{{Day: today(), Key: alice, USD: 4}}); err != nil {
		t.Fatal(err)
	}
	since := time.Now().AddDate(0, 0, -7)
	rows, err := a.Totals(ctx, "ea", since, []string{alice})
	if err != nil {
		t.Fatal(err)
	}
	if got := sum(rows); got[alice] != 4 {
		t.Fatalf("device A sees device B's spend only: %v", got)
	}
	rows, _ = b.Totals(ctx, "eb2", since, []string{alice})
	if got := sum(rows); got[alice] != 7 {
		t.Fatalf("a restarted writer sees both: %v", got)
	}
}

// A3-FORGE: a device cannot add spend to a user or group it was not issued.
func TestForgedAddIsRefused(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, a := f.device([]string{aliceSID}, nil, 0)
	credB, _ := f.device([]string{bobUPN}, []string{engGroup}, 0)
	for _, key := range []string{userKey(credB, "daily", 0), groupKey(credB)} {
		err := a.Push(ctx, "ea", []routingadmin.SeedRow{{Day: today(), Key: key, USD: 100}})
		if err == nil || !strings.Contains(err.Error(), "does not name") {
			t.Fatalf("forged add of %s: %v", key, err)
		}
	}
	var n int
	_ = f.store.db.QueryRow(`SELECT COUNT(*) FROM spend`).Scan(&n)
	if n != 0 {
		t.Fatalf("a refused push stores nothing: %d rows", n)
	}
}

// A3-XREAD: a device cannot read another user's spend.
func TestCrossUserReadIsRefused(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, a := f.device([]string{aliceSID}, nil, 0)
	credB, b := f.device([]string{bobUPN}, nil, 0)
	bob := userKey(credB, "daily", 0)
	if err := b.Push(ctx, "eb", []routingadmin.SeedRow{{Day: today(), Key: bob, USD: 3}}); err != nil {
		t.Fatal(err)
	}
	_, err := a.Totals(ctx, "ea", time.Now().AddDate(0, 0, -1), []string{bob})
	if err == nil || !strings.Contains(err.Error(), "does not name") {
		t.Fatalf("cross-user read: %v", err)
	}
}

func TestPooledKeysAnswerExceededOnly(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	credA, a := f.device([]string{aliceSID}, []string{engGroup}, 0)
	_, b := f.device([]string{bobUPN}, []string{engGroup}, 0)
	group := groupKey(credA)
	if err := a.Push(ctx, "ea", []routingadmin.SeedRow{{Day: today(), Key: group, USD: 2}}); err != nil {
		t.Fatal(err)
	}
	rows, err := b.Totals(ctx, "eb", time.Now().AddDate(0, 0, -1), []string{group})
	if err != nil || len(rows) != 0 {
		t.Fatalf("under the limit nothing is sent (no pooled totals): %+v %v", rows, err)
	}
	if err := b.Push(ctx, "eb", []routingadmin.SeedRow{{Day: today(), Key: group, USD: 4}}); err != nil {
		t.Fatal(err)
	}
	rows, err = b.Totals(ctx, "eb", time.Now().AddDate(0, 0, -1), []string{group})
	if err != nil || len(rows) != 1 || rows[0].USD != ExceededUSD || rows[0].Key != group {
		t.Fatalf("over the limit: one exceeded row: %+v %v", rows, err)
	}
}

// A3-REVOKE: a revoked device is refused and its spend stays.
func TestRevokedDeviceIsRefused(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred, a := f.device([]string{aliceSID}, nil, 0)
	key := userKey(cred, "daily", 0)
	if err := a.Push(ctx, "ea", []routingadmin.SeedRow{{Day: today(), Key: key, USD: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RevokeDevice(ctx, cred.Device, ""); err != nil {
		t.Fatal(err)
	}
	err := a.Push(ctx, "ea", []routingadmin.SeedRow{{Day: today(), Key: key, USD: 2}})
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked push: %v", err)
	}
	if _, err := a.Totals(ctx, "ea", time.Now(), []string{key}); err == nil {
		t.Fatal("a revoked device reads nothing")
	}
	devices, _ := f.store.Devices(ctx)
	if len(devices) != 1 || devices[0].Status != DeviceRevoked {
		t.Fatalf("devices %+v", devices)
	}
	report, _ := f.store.Report(ctx, today(), false)
	if len(report) != 1 || report[0].USD != 1 {
		t.Fatalf("its spend stays: %+v", report)
	}
	if _, err := f.store.RevokeDevice(ctx, "d000000000000000000000000", ""); err == nil {
		t.Fatal("revoking an unknown device must fail")
	}
}

func TestDeviceDailyCapClamps(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred, a := f.device([]string{aliceSID}, nil, 10)
	key := userKey(cred, "daily", 0)
	if err := a.Push(ctx, "e1", []routingadmin.SeedRow{{Day: today(), Key: key, USD: 8}}); err != nil {
		t.Fatal(err)
	}
	if err := a.Push(ctx, "e2", []routingadmin.SeedRow{{Day: today(), Key: key, USD: 5}}); err != nil {
		t.Fatal(err)
	}
	report, _ := f.store.Report(ctx, today(), false)
	if len(report) != 1 || report[0].USD != 10 {
		t.Fatalf("one device adds at most its cap per day: %+v", report)
	}
	devices, _ := f.store.Devices(ctx)
	if devices[0].OverCapDay != today() || devices[0].CapUSD != 10 {
		t.Fatalf("over-cap day recorded: %+v", devices[0])
	}
}

// post sends a hand-made request for device id with key k.
func (f *fixture) post(id string, k DeviceKey, path string, body []byte, at time.Time) (int, string) {
	f.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+path, bytes.NewReader(body))
	req.Header.Set(HeaderDevice, id)
	req.Header.Set(HeaderTime, strconv.FormatInt(at.Unix(), 10))
	req.Header.Set(HeaderSignature, k.Sign(http.MethodPost, path, at, body))
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var e ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&e)
	return resp.StatusCode, e.Error
}

func TestAuthFailuresAndReplayAreRefused(t *testing.T) {
	f := newFixture(t)
	cred, _ := f.device([]string{aliceSID}, nil, 0)
	key, _ := cred.Key()
	body, _ := json.Marshal(PushRequest{Epoch: "e1", Seq: 5, Rows: []Row{{Day: today(), Key: userKey(cred, "daily", 0), USD: 1}}})
	if code, _ := f.post(cred.Device, key, PathPush, body, time.Now()); code != http.StatusOK {
		t.Fatalf("signed push: %d", code)
	}
	if code, reason := f.post(cred.Device, key, PathPush, body, time.Now()); code != http.StatusConflict || reason != "replayed" {
		t.Fatalf("replay: %d %s", code, reason)
	}
	other, _ := NewDeviceKey(cred.Device, bytes.Repeat([]byte{9}, SecretBytes))
	unknown, _ := NewDeviceKey("d111111111111111111111111", cred.Secret)
	for name, c := range map[string]struct {
		id string
		k  DeviceKey
		at time.Time
	}{
		"wrong secret":   {cred.Device, other, time.Now()},
		"unknown device": {unknown.ID(), unknown, time.Now()},
		"old request":    {cred.Device, key, time.Now().Add(-10 * time.Minute)},
		"no device":      {"", key, time.Now()},
	} {
		if code, reason := f.post(c.id, c.k, PathPush, body, c.at); code != http.StatusUnauthorized || reason != "unauthorized" {
			t.Fatalf("%s: %d %s", name, code, reason)
		}
	}
	bad, _ := json.Marshal(PushRequest{Epoch: "e2", Seq: 1, Rows: []Row{{Day: today(), Key: "user:Alice Smith", USD: 1}}})
	if code, _ := f.post(cred.Device, key, PathPush, bad, time.Now()); code != http.StatusBadRequest {
		t.Fatalf("a key that is not a charge key: %d", code)
	}
}

func TestClientRefusesPlaintextAndUntrustedCertificates(t *testing.T) {
	key, _ := NewDeviceKey("d000000000000000000000001", bytes.Repeat([]byte{1}, SecretBytes))
	for _, raw := range []string{"http://store:8443", "https://user:pw@store", "https://store/path", "https://store?x=1", "store:8443"} {
		if _, err := NewClient(raw, key, nil, time.Second); err == nil {
			t.Fatalf("%s must be refused", raw)
		}
	}
	f := newFixture(t)
	cred, _ := f.device([]string{aliceSID}, nil, 0)
	k, _ := cred.Key()
	untrusted, err := NewClient(f.srv.URL, k, nil, 2*time.Second) // system roots only
	if err != nil {
		t.Fatal(err)
	}
	if err := untrusted.Push(context.Background(), "e1", []routingadmin.SeedRow{{Day: today(), Key: userKey(cred, "daily", 0), USD: 1}}); err == nil {
		t.Fatal("a certificate no trusted CA signed must fail")
	}
}

func TestClientRefusesARewrittenAnswer(t *testing.T) {
	f := newFixture(t)
	cred, _ := f.device([]string{aliceSID}, nil, 0)
	key := userKey(cred, "daily", 0)
	inner := &Handler{Store: f.store}
	rewrite := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		inner.ServeHTTP(rec, r)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(bytes.Replace(rec.Body.Bytes(), []byte(`"rows":null`), []byte(`"rows":[{"day":"`+today()+`","key":"`+key+`","usd":9999}]`), 1))
	}))
	defer rewrite.Close()
	k, _ := cred.Key()
	client, _ := NewClient(rewrite.URL, k, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rewrite.Certificate().Raw}), 5*time.Second)
	if _, err := client.Totals(context.Background(), "e1", time.Now().AddDate(0, 0, -1), []string{key}); err == nil {
		t.Fatal("a rewritten answer must be refused")
	}
}

// A3-NONAMES: neither the credential's store record nor the store file
// carries a user or group name, and the pseudonyms depend on the tenant secret.
func TestStoreHoldsNoNames(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred, a := f.device([]string{aliceSID, bobUPN}, []string{engGroup}, 0)
	if err := a.Push(ctx, "e1", []routingadmin.SeedRow{
		{Day: today(), Key: userKey(cred, "daily", 0), USD: 1},
		{Day: today(), Key: userKey(cred, "daily", 1), USD: 1},
		{Day: today(), Key: groupKey(cred), USD: 1},
	}); err != nil {
		t.Fatal(err)
	}
	_ = f.store.Close()
	for _, name := range []string{"store.db", "store.db-wal"} {
		data, err := os.ReadFile(filepath.Join(f.dir, name))
		if err != nil {
			continue
		}
		lower := bytes.ToLower(data)
		for _, s := range []string{"bob@", "dclab", "s-1-5-21"} {
			if bytes.Contains(lower, []byte(s)) {
				t.Fatalf("%s holds %q", name, s)
			}
		}
	}
	other, _, _ := Issue(subjectKey(t, 2), IssueInput{Budgets: testBudgets, Users: []string{aliceSID}})
	if other.Users[0].ID == cred.Users[0].ID {
		t.Fatal("fleet ids must depend on the tenant secret")
	}
}

func TestCredentialRoundTripAndScope(t *testing.T) {
	f := newFixture(t)
	cred, rec, err := Issue(f.subject, IssueInput{Budgets: append(testBudgets,
		config.RoutingBudget{ID: "named", Scope: "user", Subject: bobUPN, Period: "day", LimitUSD: 1},
		config.RoutingBudget{ID: "anyconn", Scope: "connector", Subject: "*", Period: "day", LimitUSD: 1}),
		Users: []string{aliceSID}, Groups: []string{"DCLAB\\other"}})
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeCredential(cred.Encode())
	if err != nil || back.Device != cred.Device || len(back.Users) != 1 || !bytes.Equal(back.Secret, rec.Secret) {
		t.Fatalf("round trip: %v", err)
	}
	for _, k := range rec.Keys {
		if strings.HasPrefix(k, "user:named:") || strings.HasPrefix(k, "group:") {
			t.Fatalf("a budget the device's users are not in is not allowed: %s", k)
		}
	}
	if len(rec.ConnectorBudgets) != 1 || rec.ConnectorBudgets[0] != "anyconn" {
		t.Fatalf("connector * budgets: %v", rec.ConnectorBudgets)
	}
	for _, bad := range []string{"", "not base64!", cred.Encode()[:20]} {
		if _, err := DecodeCredential(bad); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
	if _, _, err := Issue(f.subject, IssueInput{Budgets: testBudgets, Users: []string{"alice"}}); err == nil {
		t.Fatal("a user that is neither a UPN nor a SID must be refused")
	}
}

func TestPruneDropsOldDaysAndIdleWriters(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred, _ := f.device([]string{aliceSID}, nil, 0)
	dev := f.store.device(ctx, cred.Device)
	key := userKey(cred, "daily", 0)
	old := time.Now().UTC().AddDate(0, 0, -RetentionDays-1).Format(time.DateOnly)
	if err := f.store.Push(ctx, dev, PushRequest{Epoch: "e1", Seq: 1, Rows: []Row{{Day: today(), Key: key, USD: 2}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`INSERT INTO spend (day, charge_key, device, epoch, usd) VALUES (?, ?, ?, ?, ?)`, old, key, cred.Device, "e0", 1); err != nil {
		t.Fatal(err)
	}
	f.store.now = func() time.Time { return time.Now().Add(WriterIdle + time.Minute) }
	if err := f.store.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	var writers int
	_ = f.store.db.QueryRow(`SELECT COUNT(*) FROM writers`).Scan(&writers)
	report, _ := f.store.Report(ctx, "2000-01-01", false)
	if writers != 0 || len(report) != 1 || report[0].USD != 2 {
		t.Fatalf("writers %d report %+v", writers, report)
	}
}

func TestRequestBounds(t *testing.T) {
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
	limit := RateLimiter(2)
	if !limit("a") || !limit("a") || limit("a") || !limit("b") {
		t.Fatal("two per minute per key")
	}
	if clientKey("[2001:db8:1:2:aaaa::1]:443") != clientKey("[2001:db8:1:2:bbbb::9]:443") || clientKey("192.0.2.1:443") != "192.0.2.1" {
		t.Fatal("IPv4 by address, IPv6 by /64")
	}
	if periodStart("week", time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)) != "2026-11-09" ||
		periodStart("month", time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)) != "2026-11-01" {
		t.Fatal("weeks start on Monday, months on the 1st")
	}
}

// The cap holds per device and day over every key and writer, and closed
// days never grow (review 2 P1-1).
func TestCapCannotBeSplitOrBackdated(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred, a := f.device([]string{aliceSID}, []string{engGroup}, 10)
	user, group := userKey(cred, "daily", 0), groupKey(cred)
	for _, row := range []routingadmin.SeedRow{{Day: today(), Key: user, USD: 10}, {Day: today(), Key: group, USD: 10}, {Day: today(), Key: "connector:codex:codex", USD: 10}} {
		if err := a.Push(ctx, "e1", []routingadmin.SeedRow{row}); err != nil {
			t.Fatal(err)
		}
	}
	var old []routingadmin.SeedRow
	for d := 2; d < 31; d++ {
		old = append(old, routingadmin.SeedRow{Day: time.Now().UTC().AddDate(0, 0, -d).Format(time.DateOnly), Key: group, USD: 10})
	}
	if err := a.Push(ctx, "e1", old); err != nil {
		t.Fatal(err)
	}
	report, _ := f.store.Report(ctx, "2000-01-01", false)
	var total float64
	for _, r := range report {
		total += r.USD
	}
	if total != 10 {
		t.Fatalf("one cap per device and day, no backdating: %v %+v", total, report)
	}
}

// A row never goes down, so a device cannot bisect a pooled total (P2-1).
func TestRowsNeverGoDown(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred, a := f.device([]string{aliceSID}, []string{engGroup}, 0)
	group := groupKey(cred)
	for _, usd := range []float64{4, 1} {
		if err := a.Push(ctx, "e1", []routingadmin.SeedRow{{Day: today(), Key: group, USD: usd}}); err != nil {
			t.Fatal(err)
		}
	}
	report, _ := f.store.Report(ctx, today(), false)
	if len(report) != 1 || report[0].USD != 4 {
		t.Fatalf("a lower value is ignored: %+v", report)
	}
}

func TestRevokeCanDropForgedSpendAndStaysRevoked(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred, rec, err := Issue(f.subject, IssueInput{Budgets: testBudgets, Users: []string{aliceSID}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.AddDevice(ctx, rec, false); err != nil {
		t.Fatal(err)
	}
	k, _ := cred.Key()
	a, _ := NewClient(f.srv.URL, k, f.caPEM, 5*time.Second)
	if err := a.Push(ctx, "e1", []routingadmin.SeedRow{{Day: today(), Key: userKey(cred, "daily", 0), USD: 3}}); err != nil {
		t.Fatal(err)
	}
	if n, err := f.store.RevokeDevice(ctx, cred.Device, today()); err != nil || n != 1 {
		t.Fatalf("drop: %d %v", n, err)
	}
	if report, _ := f.store.Report(ctx, "2000-01-01", true); len(report) != 0 {
		t.Fatalf("dropped: %+v", report)
	}
	if err := f.store.AddDevice(ctx, rec, false); !errors.Is(err, ErrRevoked) {
		t.Fatalf("a revoked device is not trusted again by a second add: %v", err)
	}
	if err := f.store.AddDevice(ctx, rec, true); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownPooledBudgetIsReported(t *testing.T) {
	f := newFixture(t)
	f.store.SetBudgets(map[string]Budget{"codex": {LimitUSD: 50, Period: "day"}}) // the eng budget is missing
	cred, a := f.device([]string{aliceSID}, []string{engGroup}, 0)
	_, err := a.Totals(context.Background(), "e1", time.Now(), []string{groupKey(cred)})
	if err == nil || !strings.Contains(err.Error(), "does not know budget eng") {
		t.Fatalf("an unknown budget is named, never read as not exceeded: %v", err)
	}
}

func TestPerDeviceBounds(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred, a := f.device([]string{aliceSID}, nil, 0)
	key := userKey(cred, "daily", 0)
	for i := 0; i < MaxWritersPerDevice; i++ {
		if err := a.Push(ctx, "w"+strconv.Itoa(i), []routingadmin.SeedRow{{Day: today(), Key: key, USD: float64(i + 1)}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Push(ctx, "wextra", []routingadmin.SeedRow{{Day: today(), Key: key, USD: 100}}); err == nil {
		t.Fatal("writers per device are bounded")
	}
	if _, err := f.store.db.Exec(`UPDATE writers SET last_seen = 0`); err != nil {
		t.Fatal(err)
	}
	_ = f.store.Prune(ctx)
	for i := 0; i < MaxEpochsPerDay-MaxWritersPerDevice; i++ {
		if err := a.Push(ctx, "x"+strconv.Itoa(i), []routingadmin.SeedRow{{Day: today(), Key: key, USD: 0.01}}); err != nil {
			t.Fatal(err)
		}
		_, _ = f.store.db.Exec(`UPDATE writers SET last_seen = 0`)
		_ = f.store.Prune(ctx)
	}
	if err := a.Push(ctx, "xmore", []routingadmin.SeedRow{{Day: today(), Key: key, USD: 0.01}}); err == nil {
		t.Fatal("writers per device and day are bounded, pruned or not")
	}
	cred2, rec2, err := Issue(f.subject, IssueInput{Budgets: append(append([]config.RoutingBudget(nil), testBudgets...),
		config.RoutingBudget{ID: "any", Scope: "connector", Subject: "*", Period: "day", LimitUSD: 1}), Users: []string{bobUPN}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.AddDevice(ctx, rec2, false); err != nil {
		t.Fatal(err)
	}
	k2, _ := cred2.Key()
	c, _ := NewClient(f.srv.URL, k2, f.caPEM, 5*time.Second)
	var open []routingadmin.SeedRow
	var keys []string
	for i := 0; i <= MaxOpenKeysPerDay; i++ {
		k := "connector:any:c" + strconv.Itoa(i)
		open, keys = append(open, routingadmin.SeedRow{Day: today(), Key: k, USD: 0.01}), append(keys, k)
	}
	if err := c.Push(ctx, "e1", open); err == nil {
		t.Fatal("connector names of a * budget are bounded per device and day")
	}
	if _, err := c.Totals(ctx, "e1", time.Now(), keys); err == nil {
		t.Fatal("open keys a device may ask about are bounded")
	}
}

// A repeated row is stored once (verify 3, P2-5), and an honest long-running
// writer with many closed days is not refused.
func TestRepeatedRowsAreMerged(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred, a := f.device([]string{aliceSID}, nil, 0)
	key := userKey(cred, "daily", 0)
	var rows []routingadmin.SeedRow
	for i := 1; i <= 2000; i++ {
		rows = append(rows, routingadmin.SeedRow{Day: today(), Key: key, USD: float64(i) / 1000})
	}
	for d := 2; d < 40; d++ {
		rows = append(rows, routingadmin.SeedRow{Day: time.Now().UTC().AddDate(0, 0, -d).Format(time.DateOnly), Key: key, USD: 1})
	}
	if err := a.Push(ctx, "e1", rows); err != nil {
		t.Fatal(err)
	}
	report, _ := f.store.Report(ctx, "2000-01-01", true)
	if len(report) != 1 || report[0].USD != 2 {
		t.Fatalf("one row, the largest value, open days only: %+v", report)
	}
}
