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

package ateapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/defenseclaw/defenseclaw/third_party/substrate/api/ateapi/v1"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf issues a certificate; dns names make it a server certificate, an
// empty list a client certificate with uri as its SAN.
func (ca *testCA) leaf(t *testing.T, dns []string, uri string) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: dns, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if len(dns) == 0 {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		tmpl.Subject.CommonName = uri
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c, certPEM, keyPEM
}

// server is a minimal Control server that records the credentials it saw.
type server struct {
	pb.UnimplementedControlServer
	mu       sync.Mutex
	auth     []string
	preview  []string
	peerCN   []string
	policies []*pb.EgressPolicy
	actors   int
}

func (s *server) seen(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	md, _ := metadata.FromIncomingContext(ctx)
	s.auth = append(s.auth, strings.Join(md.Get("authorization"), ","))
	s.preview = append(s.preview, strings.Join(md.Get(PreviewHeader), ","))
	if p, ok := peer.FromContext(ctx); ok {
		if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(ti.State.PeerCertificates) > 0 {
			s.peerCN = append(s.peerCN, ti.State.PeerCertificates[0].Subject.CommonName)
		}
	}
}

func (s *server) GetActor(ctx context.Context, req *pb.GetActorRequest) (*pb.Actor, error) {
	s.seen(ctx)
	if req.GetActor().GetName() == "missing" {
		return nil, status.Error(codes.NotFound, "no such actor")
	}
	return &pb.Actor{Metadata: &pb.ResourceMetadata{Atespace: req.GetActor().GetAtespace(), Name: req.GetActor().GetName(), Uid: "u1", Version: 3}}, nil
}

func (s *server) ListActors(ctx context.Context, req *pb.ListActorsRequest) (*pb.ListActorsResponse, error) {
	s.seen(ctx)
	off := 0
	if tok := req.GetOptions().GetPageToken(); tok != "" {
		fmt.Sscanf(tok, "t%d", &off)
	}
	size := int(req.GetOptions().GetPageSize())
	if size == 0 {
		size = 2
	}
	resp := &pb.ListActorsResponse{}
	for i := off; i < min(off+size, s.actors); i++ {
		resp.Actors = append(resp.Actors, &pb.Actor{Metadata: &pb.ResourceMetadata{Atespace: req.GetAtespace(), Name: fmt.Sprintf("a%03d", i)}})
	}
	if off+size < s.actors {
		resp.NextPageToken = fmt.Sprintf("t%d", off+size)
	}
	return resp, nil
}

func (s *server) CreateActorEgressPolicy(ctx context.Context, req *pb.CreateActorEgressPolicyRequest) (*pb.EgressPolicy, error) {
	s.seen(ctx)
	s.mu.Lock()
	s.policies = append(s.policies, req.GetEgressPolicy())
	s.mu.Unlock()
	return req.GetEgressPolicy(), nil
}

type rig struct {
	dir    string
	srv    *server
	lis    *bufconn.Listener
	caFile string
	tok    string
}

// newRig serves Control over TLS on a bufconn listener with a certificate
// for api.ate-system.svc from serverCA. clientCA, when set, makes the
// server require a client certificate from it.
func newRig(t *testing.T, serverCA, clientCA *testCA) *rig {
	t.Helper()
	r := &rig{dir: t.TempDir(), srv: &server{}, lis: bufconn.Listen(1 << 20)}
	cert, _, _ := serverCA.leaf(t, []string{DefaultServerName}, "")
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if clientCA != nil {
		pool := x509.NewCertPool()
		pool.AddCert(clientCA.cert)
		cfg.ClientCAs, cfg.ClientAuth = pool, tls.RequireAndVerifyClientCert
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	pb.RegisterControlServer(gs, r.srv)
	go func() { _ = gs.Serve(r.lis) }()
	t.Cleanup(gs.Stop)
	r.caFile = filepath.Join(r.dir, "ca.crt")
	writeFile(t, r.caFile, serverCA.pem)
	r.tok = filepath.Join(r.dir, "token")
	writeFile(t, r.tok, []byte("tok-one\n"))
	return r
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	// A later mtime than the previous file even on coarse clocks.
	future := time.Now().Add(time.Duration(len(b)) * time.Millisecond)
	_ = os.Chtimes(tmp, future, future)
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) opts() Options {
	return Options{
		Address: DefaultAddress, CAFile: r.caFile, TokenFile: r.tok,
		ContextDialer: func(ctx context.Context, _ string) (net.Conn, error) { return r.lis.DialContext(ctx) },
		CallTimeout:   5 * time.Second,
	}
}

func (r *rig) client(t *testing.T, o Options) *GRPCClient {
	t.Helper()
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestServiceAccountTokenSentAndReread(t *testing.T) {
	ca := newCA(t, "servicedns")
	r := newRig(t, ca, nil)
	c := r.client(t, r.opts())
	ctx := context.Background()
	if _, err := c.GetActor(ctx, Ref("team-a", "x")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, r.tok, []byte("tok-two-rotated"))
	if _, err := c.GetActor(ctx, Ref("team-a", "x")); err != nil {
		t.Fatal(err)
	}
	r.srv.mu.Lock()
	defer r.srv.mu.Unlock()
	if got := r.srv.auth; len(got) != 2 || got[0] != "Bearer tok-one" || got[1] != "Bearer tok-two-rotated" {
		t.Fatalf("authorization headers = %q", got)
	}
	if r.srv.preview[0] != "" {
		t.Fatalf("preview header sent without Preview: %q", r.srv.preview[0])
	}
}

func TestProjectedSymlinkToken(t *testing.T) {
	ca := newCA(t, "servicedns")
	r := newRig(t, ca, nil)
	// The kubelet layout: token -> ..data/token, ..data -> ..<timestamp>.
	ts := filepath.Join(r.dir, "..2026_11_12")
	if err := os.Mkdir(ts, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(ts, "token"), []byte("tok-projected"))
	if err := os.Symlink(ts, filepath.Join(r.dir, "..data")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(r.dir, "ptoken")
	if err := os.Symlink(filepath.Join("..data", "token"), link); err != nil {
		t.Fatal(err)
	}
	o := r.opts()
	o.TokenFile = link
	c := r.client(t, o)
	if _, err := c.GetActor(context.Background(), Ref("team-a", "x")); err != nil {
		t.Fatal(err)
	}
	if got := r.srv.auth[0]; got != "Bearer tok-projected" {
		t.Fatalf("authorization = %q", got)
	}
}

func TestBadTokenFileFailsNew(t *testing.T) {
	ca := newCA(t, "servicedns")
	r := newRig(t, ca, nil)
	for name, content := range map[string]string{"empty": "  \n", "two": "a b"} {
		writeFile(t, r.tok, []byte(content))
		if _, err := New(r.opts()); err == nil {
			t.Errorf("%s token: New succeeded", name)
		} else if strings.Contains(err.Error(), "a b") {
			t.Errorf("%s token: error leaks the token: %v", name, err)
		}
	}
	o := r.opts()
	o.TokenFile = filepath.Join(r.dir, "nope")
	if _, err := New(o); err == nil {
		t.Error("missing token file: New succeeded")
	}
}

func TestServerVerifiedAgainstRotatingBundle(t *testing.T) {
	serving := newCA(t, "servicedns")
	other := newCA(t, "other")
	r := newRig(t, serving, nil)
	writeFile(t, r.caFile, other.pem)
	c := r.client(t, r.opts())
	if _, err := c.GetActor(context.Background(), Ref("team-a", "x")); status.Code(err) != codes.Unavailable {
		t.Fatalf("untrusted server: err = %v, want Unavailable", err)
	}
	// The bundle rotates to include the serving CA; the next handshake uses it.
	writeFile(t, r.caFile, append(append([]byte{}, other.pem...), serving.pem...))
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := c.GetActor(context.Background(), Ref("team-a", "x"))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after rotation: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestServerNameIsChecked(t *testing.T) {
	ca := newCA(t, "servicedns")
	r := newRig(t, ca, nil)
	o := r.opts()
	o.ServerName = "api.other-system.svc"
	c := r.client(t, o)
	_, err := c.GetActor(context.Background(), Ref("team-a", "x"))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("wrong server name: err = %v, want Unavailable", err)
	}
}

func TestPodCertificateMTLS(t *testing.T) {
	serving := newCA(t, "servicedns")
	identity := newCA(t, "podidentity")
	r := newRig(t, serving, identity)
	_, certPEM, keyPEM := identity.leaf(t, nil, "spiffe-ctl")
	bundle := filepath.Join(r.dir, "credential-bundle.pem")
	writeFile(t, bundle, append(keyPEM, certPEM...))
	o := r.opts()
	o.Auth, o.CredentialBundle, o.TokenFile = AuthMTLS, bundle, ""
	c := r.client(t, o)
	if _, err := c.GetActor(context.Background(), Ref("team-a", "x")); err != nil {
		t.Fatal(err)
	}
	r.srv.mu.Lock()
	defer r.srv.mu.Unlock()
	if r.srv.peerCN[0] != "spiffe-ctl" || r.srv.auth[0] != "" {
		t.Fatalf("peer = %q auth = %q", r.srv.peerCN, r.srv.auth)
	}
}

func TestCredentialBundleParsing(t *testing.T) {
	ca := newCA(t, "podidentity")
	_, certPEM, keyPEM := ca.leaf(t, nil, "x")
	if _, err := parseCredentialBundle(append(keyPEM, certPEM...)); err != nil {
		t.Fatalf("key then chain: %v", err)
	}
	for name, b := range map[string][]byte{
		"cert only": certPEM, "key only": keyPEM, "two keys": append(append(keyPEM, keyPEM...), certPEM...), "junk": []byte("x"),
	} {
		if _, err := parseCredentialBundle(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestPreviewHeaderAndPolicyMetadata(t *testing.T) {
	ca := newCA(t, "servicedns")
	r := newRig(t, ca, nil)
	o := r.opts()
	o.Preview = true
	c := r.client(t, o)
	in := &EgressPolicy{Metadata: &ResourceMetadata{Atespace: "wrong", Name: "wrong", Uid: "keep"}, Rules: []*EgressRule{{}}}
	if _, err := c.CreateActorEgressPolicy(context.Background(), Ref("team-a", "a1"), in); err != nil {
		t.Fatal(err)
	}
	r.srv.mu.Lock()
	defer r.srv.mu.Unlock()
	if r.srv.preview[0] != "true" {
		t.Fatalf("preview header = %q", r.srv.preview[0])
	}
	got := r.srv.policies[0].GetMetadata()
	if got.GetAtespace() != "team-a" || got.GetName() != PolicyName || got.GetUid() != "keep" {
		t.Fatalf("policy metadata = %v", got)
	}
	if in.Metadata.Atespace != "wrong" {
		t.Fatal("caller's policy was modified")
	}
}

func TestUpdateNeedsGuards(t *testing.T) {
	ca := newCA(t, "servicedns")
	r := newRig(t, ca, nil)
	c := r.client(t, r.opts())
	_, err := c.UpdateActorEgressPolicy(context.Background(), Ref("a", "b"), &EgressPolicy{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v", err)
	}
}

func TestListAllPaginates(t *testing.T) {
	ca := newCA(t, "servicedns")
	r := newRig(t, ca, nil)
	r.srv.actors = 7
	c := r.client(t, r.opts())
	got, err := AllActors(context.Background(), c, "team-a", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 7 || got[6].GetMetadata().GetName() != "a006" {
		t.Fatalf("got %d actors", len(got))
	}
}

func TestListAllStopsOnRepeatedToken(t *testing.T) {
	calls := 0
	err := ListAll(context.Background(), 0, func(context.Context, ListOptions) (Page[int], error) {
		calls++
		return Page[int]{Items: []int{1}, NextPageToken: "same"}, nil
	}, func(int) error { return nil })
	if !errors.Is(err, ErrPagination) || calls != 2 {
		t.Fatalf("err = %v calls = %d", err, calls)
	}
	stop := errors.New("stop")
	err = ListAll(context.Background(), 0, func(context.Context, ListOptions) (Page[int], error) {
		return Page[int]{Items: []int{1, 2}}, nil
	}, func(int) error { return stop })
	if !errors.Is(err, stop) {
		t.Fatalf("fn error not returned: %v", err)
	}
}

func TestNotFoundKeepsStatus(t *testing.T) {
	ca := newCA(t, "servicedns")
	r := newRig(t, ca, nil)
	c := r.client(t, r.opts())
	_, err := c.GetActor(context.Background(), Ref("team-a", "missing"))
	if !IsNotFound(err) || IsRetryable(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestOptionsAndHelpers(t *testing.T) {
	if _, err := ParseAuth("kerberos"); err == nil {
		t.Error("ParseAuth accepted kerberos")
	}
	if a, _ := ParseAuth(" MTLS "); a != AuthMTLS {
		t.Errorf("ParseAuth(MTLS) = %q", a)
	}
	if _, err := New(Options{Address: "no-port"}); err == nil {
		t.Error("New accepted an address without a port")
	}
	for m, want := range map[string]bool{
		"/substrate.ateapi.v1.Control/GetActor": true, "/substrate.ateapi.v1.Control/ListActors": true,
		"/substrate.ateapi.v1.Control/UpdateActorEgressPolicy": false, "/substrate.ateapi.v1.Control/SuspendActor": false,
	} {
		if isRead(m) != want {
			t.Errorf("isRead(%s) = %v", m, !want)
		}
	}
	if limiter(-1, 0) != nil {
		t.Error("negative QPS should disable the limiter")
	}
	if l := limiter(5, 0); l == nil || l.Burst() != 5 {
		t.Error("burst defaults to QPS")
	}
	for code, want := range map[codes.Code]bool{codes.Unavailable: true, codes.Aborted: true, codes.InvalidArgument: false, codes.PermissionDenied: false} {
		if IsRetryable(status.Error(code, "")) != want {
			t.Errorf("IsRetryable(%s) != %v", code, want)
		}
	}
	if !IsAuth(status.Error(codes.PermissionDenied, "")) || !IsConflict(status.Error(codes.Aborted, "")) || !IsAlreadyExists(status.Error(codes.AlreadyExists, "")) {
		t.Error("status helpers")
	}
	if Key(Ref("a", "b")) != "a/b" {
		t.Error("Key")
	}
}

func TestRateLimitWaitsAndHonoursContext(t *testing.T) {
	ca := newCA(t, "servicedns")
	r := newRig(t, ca, nil)
	o := r.opts()
	o.ReadQPS, o.ReadBurst = 1, 1
	c := r.client(t, o)
	if _, err := c.GetActor(context.Background(), Ref("a", "b")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := c.GetActor(ctx, Ref("a", "b"))
	if c := status.Code(err); c != codes.DeadlineExceeded {
		t.Fatalf("second call within the limit: err = %v", err)
	}
}
