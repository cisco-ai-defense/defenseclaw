// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package leader

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/podcert"
)

type observeIn struct {
	Partition string `json:"partition"`
	Step      string `json:"step"`
}

type observeOut struct {
	Count int    `json:"count"`
	ReqID string `json:"request_id"`
}

func newServer(leading *atomic.Bool, applied *atomic.Int64) *Server {
	s := &Server{IsLeader: leading.Load}
	s.Handle(MethodChainObserve, Typed(func(ctx context.Context, in observeIn) (observeOut, error) {
		n := applied.Add(1)
		if in.Step == "slow" {
			time.Sleep(50 * time.Millisecond)
		}
		if in.Step == "fail" {
			return observeOut{}, errors.New("disk")
		}
		return observeOut{Count: int(n), ReqID: RequestIDFrom(ctx)}, nil
	}))
	return s
}

func TestServerGateIdempotencyAndErrors(t *testing.T) {
	var leading atomic.Bool
	var applied atomic.Int64
	srv := httptest.NewServer(newServer(&leading, &applied))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client(), Retry: 200 * time.Millisecond}
	ctx := context.Background()

	// Not the leader: retried, then not_leader.
	err := c.Call(ctx, MethodChainObserve, "req-00000001", observeIn{Partition: "p"}, nil)
	if !IsNotLeader(err) {
		t.Fatalf("follower: %v", err)
	}
	leading.Store(true)
	var out observeOut
	if err := c.Call(ctx, MethodChainObserve, "req-00000001", observeIn{Partition: "p"}, &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 1 || out.ReqID != "req-00000001" {
		t.Fatalf("answer %+v", out)
	}
	// A retry with the same request ID replays, it does not apply again.
	var again observeOut
	if err := c.Call(ctx, MethodChainObserve, "req-00000001", observeIn{Partition: "p"}, &again); err != nil {
		t.Fatal(err)
	}
	if again != out || applied.Load() != 1 {
		t.Fatalf("replay %+v applied %d", again, applied.Load())
	}
	// Concurrent duplicates wait for the first.
	var wg sync.WaitGroup
	before := applied.Load()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.Call(ctx, MethodChainObserve, "req-slow-0001", observeIn{Step: "slow"}, nil)
		}()
	}
	wg.Wait()
	if n := applied.Load() - before; n != 1 {
		t.Fatalf("concurrent duplicates applied %d times", n)
	}
	// A failure is not replayed: the retry runs again.
	before = applied.Load()
	_ = c.Call(ctx, MethodChainObserve, "req-fail-0001", observeIn{Step: "fail"}, nil)
	_ = c.Call(ctx, MethodChainObserve, "req-fail-0001", observeIn{Step: "fail"}, nil)
	if n := applied.Load() - before; n != 2 {
		t.Fatalf("failed call applied %d times, want 2", n)
	}
	// Unknown method, bad request ID, unknown fields.
	if err := c.Call(ctx, "Nope", "req-00000002", observeIn{}, nil); err == nil {
		t.Fatal("unknown method answered")
	}
	resp, _ := srv.Client().Post(srv.URL+PathPrefix+MethodChainObserve, "application/json",
		jsonReader(t, map[string]any{"request_id": "x", "body": map[string]any{}}))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("short request id: %d", resp.StatusCode)
	}
	resp.Body.Close()
	var we *WireError
	err = c.Call(ctx, MethodChainObserve, "req-00000003", map[string]any{"extra": 1}, nil)
	if !errors.As(err, &we) || we.Code != CodeBadRequest {
		t.Fatalf("unknown field: %v", err)
	}
}

func TestClientFollowsALeaderChange(t *testing.T) {
	var leading atomic.Bool
	var applied atomic.Int64
	srv := httptest.NewServer(newServer(&leading, &applied))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client(), Retry: 5 * time.Second}
	go func() {
		time.Sleep(300 * time.Millisecond)
		leading.Store(true)
	}()
	start := time.Now()
	if err := c.Call(context.Background(), MethodChainObserve, "", observeIn{}, nil); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 250*time.Millisecond {
		t.Fatal("answered before a leader existed")
	}
}

// --- mTLS ---

type pki struct {
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	dir   string
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &pki{ca: ca, caKey: key, dir: t.TempDir()}
	writePEM(t, filepath.Join(p.dir, "trust.pem"), "CERTIFICATE", der)
	return p
}

func writePEM(t *testing.T, path, typ string, der []byte, more ...[]byte) {
	t.Helper()
	b := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	for _, m := range more {
		b = append(b, m...)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// bundle issues a leaf with the SPIFFE ID and writes a credential bundle.
func (p *pki) bundle(t *testing.T, name, spiffe string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(spiffe)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{u},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	path := filepath.Join(p.dir, name+".pem")
	writePEM(t, path, "EC PRIVATE KEY", kd, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return path
}

const (
	gwID     = "spiffe://cluster.local/ns/defenseclaw-system/sa/defenseclaw-gateway"
	leaderID = "spiffe://cluster.local/ns/defenseclaw-system/sa/defenseclaw-gateway-leader"
	actorID  = "spiffe://cluster.local/ns/a2/sa/some-actor"
)

func TestMutualTLSPeerAllowlist(t *testing.T) {
	p := newPKI(t)
	trust := filepath.Join(p.dir, "trust.pem")
	serverFiles, err := podcert.NewFiles(p.bundle(t, "leader", leaderID, p.ca, p.caKey), trust)
	if err != nil {
		t.Fatal(err)
	}
	var leading atomic.Bool
	leading.Store(true)
	var applied atomic.Int64
	// httptest's StartTLS adds its own certificate, which Go serves to a
	// client that sends no SNI; serve the pod certificate alone instead.
	srv := httptest.NewUnstartedServer(newServer(&leading, &applied))
	srv.Listener = tls.NewListener(srv.Listener, serverFiles.ServerConfig([]string{gwID}))
	srv.Start()
	srv.URL = "https://" + srv.Listener.Addr().String()
	defer srv.Close()

	call := func(clientBundle string, serverIDs []string) error {
		files, err := podcert.NewFiles(clientBundle, trust)
		if err != nil {
			t.Fatal(err)
		}
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: files.ClientConfig(serverIDs)}, Timeout: 2 * time.Second}
		c := &Client{BaseURL: srv.URL, HTTP: hc, Retry: time.Millisecond}
		return c.Call(context.Background(), MethodChainObserve, NewRequestID(), observeIn{}, nil)
	}
	if err := call(p.bundle(t, "gw", gwID, p.ca, p.caKey), []string{leaderID}); err != nil {
		t.Fatalf("gateway to leader: %v", err)
	}
	if err := call(p.bundle(t, "actor", actorID, p.ca, p.caKey), []string{leaderID}); err == nil {
		t.Fatal("a pod with another SPIFFE ID reached the leader")
	}
	if err := call(p.bundle(t, "gw2", gwID, p.ca, p.caKey), []string{"spiffe://elsewhere/sa/x"}); err == nil {
		t.Fatal("client accepted a leader with another SPIFFE ID")
	}
	// A certificate from another CA with the right SPIFFE ID.
	other := newPKI(t)
	if err := call(other.bundle(t, "forged", gwID, other.ca, other.caKey), []string{leaderID}); err == nil {
		t.Fatal("a certificate from another CA reached the leader")
	}
	if applied.Load() != 1 {
		t.Fatalf("applied %d", applied.Load())
	}
}

// --- Lease ---

type fakeLease struct {
	mu    sync.Mutex
	l     *Lease
	rv    int
	fails atomic.Bool
}

func (f *fakeLease) Get(context.Context) (*Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails.Load() {
		return nil, errors.New("api down")
	}
	if f.l == nil {
		return nil, ErrLeaseNotFound
	}
	c := *f.l
	return &c, nil
}

func (f *fakeLease) Create(_ context.Context, l *Lease) (*Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.l != nil {
		return nil, ErrLeaseConflict
	}
	f.rv++
	c := *l
	c.Metadata.ResourceVersion = strconv.Itoa(f.rv)
	f.l = &c
	out := c
	return &out, nil
}

func (f *fakeLease) Update(_ context.Context, l *Lease) (*Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails.Load() {
		return nil, errors.New("api down")
	}
	if f.l == nil || l.Metadata.ResourceVersion != f.l.Metadata.ResourceVersion {
		return nil, ErrLeaseConflict
	}
	f.rv++
	c := *l
	c.Metadata.ResourceVersion = strconv.Itoa(f.rv)
	f.l = &c
	out := c
	return &out, nil
}

func (f *fakeLease) holder() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.l == nil || f.l.Spec.HolderIdentity == nil {
		return ""
	}
	return *f.l.Spec.HolderIdentity
}

func TestElectorFailover(t *testing.T) {
	api := &fakeLease{}
	mk := func(id string) *Elector {
		return &Elector{API: api, Name: "defenseclaw-leader", Ns: "defenseclaw-system", Identity: id,
			LeaseDuration: 2 * time.Second, RenewDeadline: 1500 * time.Millisecond, RetryPeriod: 50 * time.Millisecond}
	}
	a, b := mk("pod-a"), mk("pod-b")
	ctxA, stopA := context.WithCancel(context.Background())
	ctxB, stopB := context.WithCancel(context.Background())
	defer stopB()
	var started atomic.Int64
	a.OnStarted = func(context.Context) { started.Add(1) }
	b.OnStarted = func(context.Context) { started.Add(1) }
	go func() { _ = a.Run(ctxA) }()
	waitFor(t, func() bool { return a.IsLeader() })
	go func() { _ = b.Run(ctxB) }()
	time.Sleep(200 * time.Millisecond)
	if b.IsLeader() || api.holder() != "pod-a" {
		t.Fatalf("two leaders or wrong holder %q", api.holder())
	}
	// The leader stops (pod deleted): it releases, the follower takes over
	// well before the lease would expire.
	start := time.Now()
	stopA()
	waitFor(t, func() bool { return b.IsLeader() })
	if d := time.Since(start); d > time.Second {
		t.Fatalf("failover took %v", d)
	}
	if a.IsLeader() || api.holder() != "pod-b" {
		t.Fatal("old leader still leads")
	}
	if started.Load() != 2 {
		t.Fatalf("started %d", started.Load())
	}
}

func TestElectorLosesLeaseWhenAPIIsDown(t *testing.T) {
	api := &fakeLease{}
	e := &Elector{API: api, Name: "l", Ns: "n", Identity: "pod-a",
		LeaseDuration: time.Second, RenewDeadline: 300 * time.Millisecond, RetryPeriod: 50 * time.Millisecond}
	stopped := make(chan struct{})
	e.OnStopped = func() { close(stopped) }
	done := make(chan error, 1)
	go func() { done <- e.Run(context.Background()) }()
	waitFor(t, e.IsLeader)
	api.fails.Store(true)
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("leader kept leading without renewing")
	}
	if err := <-done; err == nil || e.IsLeader() {
		t.Fatalf("run ended with %v, leading %v", err, e.IsLeader())
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func jsonReader(t *testing.T, v any) *bytes.Reader {
	t.Helper()
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}
