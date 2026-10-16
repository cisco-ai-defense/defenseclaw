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

package openshell_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// startGateway serves Health on loopback with the given client
// authentication and TLS version cap (0: none; nil config: plaintext).
func startGateway(t *testing.T, pki *testPKI, auth tls.ClientAuthType, maxVersion uint16, plaintext bool) string {
	t.Helper()
	var opts []grpc.ServerOption
	if !plaintext {
		cert, err := tls.X509KeyPair(pki.serverPEM, pki.serverKeyPEM)
		if err != nil {
			t.Fatal(err)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert}, ClientCAs: pki.pool, ClientAuth: auth, MaxVersion: maxVersion,
		})))
	}
	srv := grpc.NewServer(opts...)
	pb.RegisterOpenShellServer(srv, healthServer{})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return "https://" + lis.Addr().String()
}

// startSilentTLS completes TLS handshakes without asking for a client
// certificate and then never writes, like a server waiting for a request.
func startSilentTLS(t *testing.T, pki *testPKI) string {
	t.Helper()
	cert, err := tls.X509KeyPair(pki.serverPEM, pki.serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
				var b [1]byte
				_, _ = conn.Read(b[:])
			}()
		}
	}()
	return "https://" + lis.Addr().String()
}

// apiServer answers Health and ListSandboxes like an OpenShell gateway.
// With requireCert set, ListSandboxes refuses a caller without a verified
// client certificate, as the API of OpenShell 0.1.3 and later does (their
// TLS listener lets such a client through the handshake).
type apiServer struct {
	healthServer
	requireCert bool
}

func (s apiServer) ListSandboxes(ctx context.Context, req *pb.ListSandboxesRequest) (*pb.ListSandboxesResponse, error) {
	if s.requireCert {
		p, _ := peer.FromContext(ctx)
		if info, ok := p.AuthInfo.(credentials.TLSInfo); !ok || len(info.State.VerifiedChains) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing authorization header")
		}
	}
	if req.GetWorkspaceScope().GetWorkspace() != openshell.DefaultWorkspace {
		return nil, status.Error(codes.InvalidArgument, "workspace_scope is required")
	}
	return &pb.ListSandboxesResponse{}, nil
}

// startMultiplexedGateway serves api over gRPC and the HTTP routes on one
// TLS port, as OpenShell's gateway does, with the given client
// authentication; /auth/oidc-config answers oidc (404: no OIDC issuer).
func startMultiplexedGateway(t *testing.T, pki *testPKI, auth tls.ClientAuthType, api apiServer, oidc int) string {
	t.Helper()
	cert, err := tls.X509KeyPair(pki.serverPEM, pki.serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	grpcSrv := grpc.NewServer()
	pb.RegisterOpenShellServer(grpcSrv, api)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc"):
			grpcSrv.ServeHTTP(w, r)
		case r.URL.Path == "/auth/oidc-config":
			w.WriteHeader(oidc)
		default:
			http.NotFound(w, r)
		}
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pki.pool, ClientAuth: auth, NextProtos: []string{"h2", "http/1.1"}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}

func probeRegistration(t *testing.T, endpoint string, pki *testPKI) *openshell.Registration {
	t.Helper()
	dir := t.TempDir()
	writeRegistration(t, dir, "openshell", map[string]any{"gateway_endpoint": endpoint, "auth_mode": "mtls"}, pki)
	reg, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestProbeClientAuth(t *testing.T) {
	skipOnWindows(t)
	pki := newPKI(t)
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedEndpoint := "https://" + closed.Addr().String()
	_ = closed.Close()

	refusing := apiServer{requireCert: true}
	cases := []struct {
		name     string
		endpoint string
		// ok: the gateway turns away a client without a certificate;
		// exposed: it does not; otherwise the probe cannot tell. want is
		// in the error.
		ok, exposed bool
		want        string
	}{
		{name: "TLS 1.3 gateway requires a certificate", endpoint: startGateway(t, pki, tls.RequireAndVerifyClientCert, 0, false), ok: true},
		{name: "TLS 1.2 gateway requires a certificate", endpoint: startGateway(t, pki, tls.RequireAndVerifyClientCert, tls.VersionTLS12, false), ok: true},
		{name: "certificate optional, API requires one (OpenShell 0.1.3)", endpoint: startMultiplexedGateway(t, pki, tls.VerifyClientCertIfGiven, refusing, http.StatusNotFound), ok: true},
		{name: "certificate optional, API answers without one", endpoint: startMultiplexedGateway(t, pki, tls.VerifyClientCertIfGiven, apiServer{}, http.StatusNotFound), exposed: true, want: "listed its sandboxes"},
		{name: "certificate optional, API requires one, OIDC issuer", endpoint: startMultiplexedGateway(t, pki, tls.VerifyClientCertIfGiven, refusing, http.StatusOK), exposed: true, want: "OIDC issuer"},
		{name: "certificate optional, API requires one, OIDC settings unknown", endpoint: startMultiplexedGateway(t, pki, tls.VerifyClientCertIfGiven, refusing, http.StatusInternalServerError), exposed: true, want: "500"},
		{name: "certificate optional, no sandbox API", endpoint: startGateway(t, pki, tls.VerifyClientCertIfGiven, 0, false), exposed: true, want: "Unimplemented"},
		{name: "certificate not requested, API refuses", endpoint: startMultiplexedGateway(t, pki, tls.NoClientCert, refusing, http.StatusNotFound), exposed: true, want: "never asked"},
		{name: "certificate not requested", endpoint: startGateway(t, pki, tls.NoClientCert, 0, false), exposed: true},
		{name: "silent server without client auth", endpoint: startSilentTLS(t, pki), exposed: true},
		{name: "plaintext gateway", endpoint: startGateway(t, pki, 0, 0, true)},
		{name: "nothing listening", endpoint: closedEndpoint},
		{name: "server certificate from another CA", endpoint: startGateway(t, newPKI(t), tls.RequireAndVerifyClientCert, 0, false)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := openshell.ProbeClientAuth(context.Background(), probeRegistration(t, tc.endpoint, pki))
			if tc.ok != (err == nil) || tc.exposed != errors.Is(err, openshell.ErrGatewayExposed) || err != nil && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ProbeClientAuth = %v, want ok=%v exposed=%v %q", err, tc.ok, tc.exposed, tc.want)
			}
		})
	}

	if err := openshell.ProbeClientAuth(context.Background(), &openshell.Registration{Endpoint: "http://127.0.0.1:1", AuthMode: openshell.AuthModePlaintext}); err == nil {
		t.Fatal("probed a registration without mTLS files")
	}
}

// TestProbeClientAuthSendsNoCertificateToTheAPI checks the fake that the
// probe passes: its API answers a caller with the registration's
// certificate, so the probe, which it refuses, sent none.
func TestProbeClientAuthSendsNoCertificateToTheAPI(t *testing.T) {
	skipOnWindows(t)
	pki := newPKI(t)
	reg := probeRegistration(t, startMultiplexedGateway(t, pki, tls.VerifyClientCertIfGiven, apiServer{requireCert: true}, http.StatusNotFound), pki)
	if err := openshell.ProbeClientAuth(context.Background(), reg); err != nil {
		t.Fatalf("ProbeClientAuth = %v", err)
	}
	conn, err := reg.DialGRPC()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	scope := &dm.WorkspaceSelector{Selection: &dm.WorkspaceSelector_Workspace{Workspace: openshell.DefaultWorkspace}}
	if _, err := pb.NewOpenShellClient(conn).ListSandboxes(ctx, &pb.ListSandboxesRequest{WorkspaceScope: scope}); err != nil {
		t.Fatalf("ListSandboxes with the registration's certificate = %v", err)
	}
}
