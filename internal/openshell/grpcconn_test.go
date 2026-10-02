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
	"testing"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

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

	cases := []struct {
		name     string
		endpoint string
		trust    *testPKI
		// ok: the gateway demands a certificate; exposed: it plainly
		// does not; otherwise the probe cannot tell.
		ok, exposed bool
	}{
		{name: "TLS 1.3 gateway requires a certificate", endpoint: startGateway(t, pki, tls.RequireAndVerifyClientCert, 0, false), ok: true},
		{name: "TLS 1.2 gateway requires a certificate", endpoint: startGateway(t, pki, tls.RequireAndVerifyClientCert, tls.VersionTLS12, false), ok: true},
		{name: "certificate optional", endpoint: startGateway(t, pki, tls.VerifyClientCertIfGiven, 0, false), exposed: true},
		{name: "certificate not requested", endpoint: startGateway(t, pki, tls.NoClientCert, 0, false), exposed: true},
		{name: "silent server without client auth", endpoint: startSilentTLS(t, pki), exposed: true},
		{name: "plaintext gateway", endpoint: startGateway(t, pki, 0, 0, true)},
		{name: "nothing listening", endpoint: closedEndpoint},
		{name: "server certificate from another CA", endpoint: startGateway(t, newPKI(t), tls.RequireAndVerifyClientCert, 0, false)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := openshell.ProbeClientAuth(context.Background(), probeRegistration(t, tc.endpoint, pki))
			if tc.ok != (err == nil) || tc.exposed != errors.Is(err, openshell.ErrGatewayExposed) {
				t.Fatalf("ProbeClientAuth = %v, want ok=%v exposed=%v", err, tc.ok, tc.exposed)
			}
		})
	}

	if err := openshell.ProbeClientAuth(context.Background(), &openshell.Registration{Endpoint: "http://127.0.0.1:1", AuthMode: openshell.AuthModePlaintext}); err == nil {
		t.Fatal("probed a registration without mTLS files")
	}
}
