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
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// writeRegistration lays out gateways/<name>/{metadata.json,mtls/*} the way
// the openshell 0.1.1 CLI does and returns the registration directory.
func writeRegistration(t *testing.T, configDir, name string, meta map[string]any, pki *testPKI) string {
	t.Helper()
	dir := filepath.Join(configDir, "gateways", name)
	if err := os.MkdirAll(filepath.Join(dir, "mtls"), 0o700); err != nil {
		t.Fatal(err)
	}
	if meta == nil {
		meta = map[string]any{"name": name, "gateway_endpoint": "https://127.0.0.1:17670", "is_remote": false, "gateway_port": 0, "auth_mode": "mtls"}
	}
	data, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0o664); err != nil {
		t.Fatal(err)
	}
	ca, cert, key := []byte("ca"), []byte("cert"), []byte("key")
	if pki != nil {
		ca, cert, key = pki.caPEM, pki.clientPEM, pki.clientKeyPEM
	}
	for file, content := range map[string][]byte{"ca.crt": ca, "tls.crt": cert} {
		if err := os.WriteFile(filepath.Join(dir, "mtls", file), content, 0o664); err != nil {
			t.Fatal(err)
		}
		// The CLI writes certificates 0664; make that survive the umask.
		if err := os.Chmod(filepath.Join(dir, "mtls", file), 0o664); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "mtls", "tls.key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func skipOnWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenShell sandboxes are unsupported on Windows")
	}
}

func TestDiscoverSelection(t *testing.T) {
	skipOnWindows(t)
	cases := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		pin     string
		want    string
		wantErr error
	}{
		{
			name: "active gateway wins",
			setup: func(t *testing.T, dir string) {
				writeRegistration(t, dir, "openshell", nil, nil)
				writeRegistration(t, dir, "work", nil, nil)
				_ = os.WriteFile(filepath.Join(dir, "active_gateway"), []byte("work\n"), 0o664)
			},
			want: "work",
		},
		{
			name: "pinned name overrides active",
			setup: func(t *testing.T, dir string) {
				writeRegistration(t, dir, "openshell", nil, nil)
				writeRegistration(t, dir, "work", nil, nil)
				_ = os.WriteFile(filepath.Join(dir, "active_gateway"), []byte("work"), 0o664)
			},
			pin:  "openshell",
			want: "openshell",
		},
		{
			name: "package default without active file",
			setup: func(t *testing.T, dir string) {
				writeRegistration(t, dir, "alpha", nil, nil)
				writeRegistration(t, dir, "openshell", nil, nil)
			},
			want: "openshell",
		},
		{
			name:  "single registration",
			setup: func(t *testing.T, dir string) { writeRegistration(t, dir, "solo", nil, nil) },
			want:  "solo",
		},
		{
			name: "ambiguous registrations",
			setup: func(t *testing.T, dir string) {
				writeRegistration(t, dir, "a", nil, nil)
				writeRegistration(t, dir, "b", nil, nil)
			},
			wantErr: openshell.ErrNoGateway,
		},
		{
			name:    "nothing installed",
			setup:   func(*testing.T, string) {},
			wantErr: openshell.ErrNoGateway,
		},
		{
			name:    "pinned registration missing",
			setup:   func(t *testing.T, dir string) { writeRegistration(t, dir, "openshell", nil, nil) },
			pin:     "gone",
			wantErr: openshell.ErrGatewayNotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			reg, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: dir, SystemDir: t.TempDir(), Gateway: tc.pin})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Discover = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if reg.Name != tc.want || reg.Source != openshell.SourceUser || reg.Endpoint != "https://127.0.0.1:17670" || !reg.Local() {
				t.Fatalf("registration = %+v", reg)
			}
			if reg.TLS == nil || reg.TLS.Key != filepath.Join(dir, "gateways", tc.want, "mtls", "tls.key") {
				t.Fatalf("tls files = %+v", reg.TLS)
			}
			if reg.Target() != "127.0.0.1:17670" {
				t.Fatalf("target = %q", reg.Target())
			}
		})
	}
}

func TestDiscoverRejectsInvalidNames(t *testing.T) {
	skipOnWindows(t)
	dir := t.TempDir()
	writeRegistration(t, dir, "openshell", nil, nil)
	for _, name := range []string{"../etc", "a.b", "a/b", "sp ace"} {
		if _, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: dir, Gateway: name}); err == nil {
			t.Fatalf("pinned %q accepted", name)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "active_gateway"), []byte("../../evil"), 0o600)
	if _, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: dir}); err == nil || !strings.Contains(err.Error(), "invalid gateway") {
		t.Fatalf("hostile active_gateway = %v", err)
	}
}

func TestDiscoverSystemRegistration(t *testing.T) {
	skipOnWindows(t)
	user, system := t.TempDir(), t.TempDir()
	writeRegistration(t, system, "fleet", nil, nil)
	reg, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: user, SystemDir: system})
	if err != nil || reg.Source != openshell.SourceSystem || reg.Name != "fleet" {
		t.Fatalf("system registration = %+v, %v", reg, err)
	}
}

func TestDiscoverRefusesRemoteAndUnsupportedModes(t *testing.T) {
	skipOnWindows(t)
	cases := []struct {
		name     string
		meta     map[string]any
		wantErr  error
		warnings int
	}{
		{name: "is_remote", meta: map[string]any{"gateway_endpoint": "https://127.0.0.1:17670", "is_remote": true, "auth_mode": "mtls"}, wantErr: openshell.ErrRemoteGateway},
		{name: "remote host", meta: map[string]any{"gateway_endpoint": "https://gw.example.com:443", "auth_mode": "mtls"}, wantErr: openshell.ErrRemoteGateway},
		{name: "oidc", meta: map[string]any{"gateway_endpoint": "https://127.0.0.1:17670", "auth_mode": "oidc"}, wantErr: openshell.ErrUnsupportedAuthMode},
		{name: "cloudflare", meta: map[string]any{"gateway_endpoint": "https://localhost:17670", "auth_mode": "cloudflare_jwt"}, wantErr: openshell.ErrUnsupportedAuthMode},
		{name: "mtls over http", meta: map[string]any{"gateway_endpoint": "http://127.0.0.1:17670", "auth_mode": "mtls"}, wantErr: openshell.ErrUnsupportedAuthMode},
		{name: "plaintext over https", meta: map[string]any{"gateway_endpoint": "https://127.0.0.1:17670", "auth_mode": "plaintext"}, wantErr: openshell.ErrUnsupportedAuthMode},
		{name: "loopback plaintext warns", meta: map[string]any{"gateway_endpoint": "http://[::1]:17670", "auth_mode": "plaintext"}, warnings: 1},
		{name: "missing endpoint", meta: map[string]any{"auth_mode": "mtls"}, wantErr: errors.New("no gateway_endpoint")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeRegistration(t, dir, "openshell", tc.meta, nil)
			reg, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: dir})
			switch {
			case tc.wantErr == nil:
				if err != nil || len(reg.Warnings) != tc.warnings {
					t.Fatalf("Discover = %+v, %v", reg, err)
				}
			case errors.Is(tc.wantErr, openshell.ErrRemoteGateway) || errors.Is(tc.wantErr, openshell.ErrUnsupportedAuthMode):
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Discover = %v, want %v", err, tc.wantErr)
				}
				if reg == nil {
					t.Fatal("registration not returned alongside the refusal")
				}
			default:
				if err == nil || !strings.Contains(err.Error(), tc.wantErr.Error()) {
					t.Fatalf("Discover = %v, want %v", err, tc.wantErr)
				}
			}
		})
	}
}

func TestDiscoverChecksCredentialPermissions(t *testing.T) {
	skipOnWindows(t)
	if os.Geteuid() == 0 {
		t.Skip("permission semantics differ for root")
	}
	cases := []struct {
		name     string
		mutate   func(t *testing.T, mtls string)
		wantErr  bool
		wantFix  string
		warnings int
	}{
		{name: "cli defaults warn on group-writable certs", mutate: func(*testing.T, string) {}, warnings: 2},
		{name: "tightened certs", mutate: func(t *testing.T, m string) {
			chmod(t, filepath.Join(m, "ca.crt"), 0o644)
			chmod(t, filepath.Join(m, "tls.crt"), 0o600)
		}},
		{name: "group-readable key", mutate: func(t *testing.T, m string) { chmod(t, filepath.Join(m, "tls.key"), 0o640) }, wantErr: true, wantFix: "chmod 600 "},
		{name: "world-readable key", mutate: func(t *testing.T, m string) { chmod(t, filepath.Join(m, "tls.key"), 0o604) }, wantErr: true, wantFix: "chmod 600 "},
		{name: "world-writable ca", mutate: func(t *testing.T, m string) { chmod(t, filepath.Join(m, "ca.crt"), 0o666) }, wantErr: true, wantFix: "chmod 644 "},
		{name: "key symlink", mutate: func(t *testing.T, m string) {
			key := filepath.Join(m, "tls.key")
			real := filepath.Join(t.TempDir(), "real.key")
			if err := os.Rename(key, real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, key); err != nil {
				t.Fatal(err)
			}
		}, wantErr: true},
		{name: "world-writable mtls dir", mutate: func(t *testing.T, m string) { chmod(t, m, 0o777) }, wantErr: true, wantFix: "chmod 700 "},
		{name: "missing key", mutate: func(t *testing.T, m string) { _ = os.Remove(filepath.Join(m, "tls.key")) }, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			reg := writeRegistration(t, dir, "openshell", nil, nil)
			tc.mutate(t, filepath.Join(reg, "mtls"))
			got, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: dir})
			if !tc.wantErr {
				if err != nil || len(got.Warnings) != tc.warnings {
					t.Fatalf("Discover = %+v, %v", got, err)
				}
				return
			}
			if err == nil {
				t.Fatal("insecure credentials accepted")
			}
			var perm *openshell.PermissionError
			if tc.wantFix != "" {
				if !errors.As(err, &perm) || !strings.HasPrefix(perm.Fix, tc.wantFix) || !errors.Is(err, openshell.ErrInsecureCredentials) {
					t.Fatalf("Discover = %v (fix %q)", err, fixOf(perm))
				}
			}
		})
	}
}

func fixOf(p *openshell.PermissionError) string {
	if p == nil {
		return ""
	}
	return p.Fix
}

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestUserConfigDirFollowsXDG(t *testing.T) {
	skipOnWindows(t)
	t.Setenv("XDG_CONFIG_HOME", "/custom/xdg")
	if dir, err := openshell.UserConfigDir(); err != nil || dir != "/custom/xdg/openshell" {
		t.Fatalf("UserConfigDir = %q, %v", dir, err)
	}
	t.Setenv("XDG_CONFIG_HOME", "relative")
	if _, err := openshell.UserConfigDir(); err == nil {
		t.Fatal("relative XDG_CONFIG_HOME accepted")
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/home/dev")
	if dir, err := openshell.UserConfigDir(); err != nil || dir != "/home/dev/.config/openshell" {
		t.Fatalf("UserConfigDir = %q, %v", dir, err)
	}
}

func TestCheckPlatform(t *testing.T) {
	for goos, ok := range map[string]bool{"linux": true, "darwin": true, "windows": false, "freebsd": false} {
		if err := openshell.CheckPlatform(goos); (err == nil) != ok || (!ok && !errors.Is(err, openshell.ErrUnsupportedPlatform)) {
			t.Fatalf("CheckPlatform(%s) = %v", goos, err)
		}
	}
}

// testPKI is a gateway CA with a loopback server certificate and a client
// certificate, as openshell-gateway generate-certs produces.
type testPKI struct {
	caPEM, serverPEM, serverKeyPEM, clientPEM, clientKeyPEM []byte
	pool                                                    *x509.CertPool
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "openshell-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	issue := func(serial int64, usage x509.ExtKeyUsage) ([]byte, []byte) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "openshell"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"host.openshell.internal"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, _ := x509.MarshalECPrivateKey(key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	}
	p := &testPKI{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pool: x509.NewCertPool()}
	p.pool.AddCert(caCert)
	p.serverPEM, p.serverKeyPEM = issue(2, x509.ExtKeyUsageServerAuth)
	p.clientPEM, p.clientKeyPEM = issue(3, x509.ExtKeyUsageClientAuth)
	return p
}

type healthServer struct {
	pb.UnimplementedOpenShellServer
}

func (healthServer) Health(context.Context, *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{Status: pb.ServiceStatus_SERVICE_STATUS_HEALTHY, Version: "0.1.1"}, nil
}

// startMTLSGateway serves Health over mTLS on loopback, requiring a client
// certificate from the test CA.
func startMTLSGateway(t *testing.T, pki *testPKI) string {
	t.Helper()
	cert, err := tls.X509KeyPair(pki.serverPEM, pki.serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert}, ClientCAs: pki.pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12,
	})))
	pb.RegisterOpenShellServer(srv, healthServer{})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return "https://" + lis.Addr().String()
}

func TestDialOverMTLS(t *testing.T) {
	skipOnWindows(t)
	pki := newPKI(t)
	endpoint := startMTLSGateway(t, pki)
	dir := t.TempDir()
	writeRegistration(t, dir, "openshell", map[string]any{"name": "openshell", "gateway_endpoint": endpoint, "is_remote": false, "auth_mode": "mtls"}, pki)

	reg, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	c, err := openshell.Dial(reg, openshell.ClientOptions{RPCTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h, err := c.Health(context.Background())
	if err != nil || !h.Healthy || h.CheckVersion() != nil {
		t.Fatalf("health over mTLS = %+v, %v", h, err)
	}

	// The raw stream connection uses the same trust material.
	conn, err := reg.DialGRPC()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if res, err := pb.NewOpenShellClient(conn).Health(ctx, &pb.HealthRequest{}); err != nil || res.GetVersion() != "0.1.1" {
		t.Fatalf("raw health = %v, %v", res, err)
	}

	// A client certificate from another CA is refused by the gateway.
	other := newPKI(t)
	dir2 := t.TempDir()
	writeRegistration(t, dir2, "openshell", map[string]any{"gateway_endpoint": endpoint, "auth_mode": "mtls"}, &testPKI{
		caPEM: pki.caPEM, clientPEM: other.clientPEM, clientKeyPEM: other.clientKeyPEM,
	})
	reg2, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: dir2})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := openshell.Dial(reg2, openshell.ClientOptions{RPCTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if _, err := c2.Health(context.Background()); err == nil {
		t.Fatal("gateway accepted a foreign client certificate")
	}
}

func TestDialRefusesUnusableRegistrations(t *testing.T) {
	for _, reg := range []*openshell.Registration{
		nil,
		{Endpoint: "https://gw.example.com", AuthMode: openshell.AuthModeMTLS, Remote: true},
		{Endpoint: "https://127.0.0.1:1", AuthMode: openshell.AuthModeMTLS},
		{Endpoint: "https://127.0.0.1:1", AuthMode: openshell.AuthModeOIDC},
		{Endpoint: "https://127.0.0.1:1", AuthMode: openshell.AuthModePlaintext},
	} {
		if _, err := openshell.Dial(reg, openshell.ClientOptions{}); err == nil {
			t.Fatalf("Dial(%+v) succeeded", reg)
		}
		if reg != nil {
			if _, err := reg.DialGRPC(); err == nil {
				t.Fatalf("DialGRPC(%+v) succeeded", reg)
			}
		}
	}
}
