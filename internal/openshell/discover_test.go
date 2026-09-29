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

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// writeRegistration lays out gateways/<name>/{metadata.json,mtls/*} the way
// the openshell 0.1.1 CLI does, with its 0664 metadata and certificates,
// and returns the registration directory.
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
	writeFile(t, filepath.Join(dir, "metadata.json"), string(data), 0o664)
	ca, cert, key := []byte("ca"), []byte("cert"), []byte("key")
	if pki != nil {
		ca, cert, key = pki.caPEM, pki.clientPEM, pki.clientKeyPEM
	}
	writeFile(t, filepath.Join(dir, "mtls", "ca.crt"), string(ca), 0o664)
	writeFile(t, filepath.Join(dir, "mtls", "tls.crt"), string(cert), 0o664)
	writeFile(t, filepath.Join(dir, "mtls", "tls.key"), string(key), 0o600)
	return dir
}

// writeFile writes content with exactly mode, whatever the umask.
func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	chmod(t, path, mode)
}

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// moveBehindLink moves path elsewhere and leaves a symbolic link to it.
func moveBehindLink(t *testing.T, path string) {
	t.Helper()
	moved := filepath.Join(t.TempDir(), filepath.Base(path))
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, path); err != nil {
		t.Fatal(err)
	}
}

// realTempDir is t.TempDir with its symbolic links resolved (macOS links
// /var to /private/var), the form in which Discover and
// GatewayConfigurator report paths.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func skipOnWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenShell sandboxes are unsupported on Windows")
	}
}

func skipAsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission semantics differ for root")
	}
}

func TestDiscoverSelection(t *testing.T) {
	skipOnWindows(t)
	cases := []struct {
		name         string
		regs, system []string
		active, pin  string
		want         string
		source       openshell.RegistrationSource
		wantErr      error
	}{
		{name: "active gateway wins", regs: []string{"openshell", "work"}, active: "work\n", want: "work"},
		{name: "pinned name overrides active", regs: []string{"openshell", "work"}, active: "work", pin: "openshell", want: "openshell"},
		{name: "package default without active file", regs: []string{"alpha", "openshell"}, want: "openshell"},
		{name: "single registration", regs: []string{"solo"}, want: "solo"},
		{name: "system registration", system: []string{"fleet"}, want: "fleet", source: openshell.SourceSystem},
		{name: "ambiguous registrations", regs: []string{"a", "b"}, wantErr: openshell.ErrNoGateway},
		{name: "nothing installed", wantErr: openshell.ErrNoGateway},
		{name: "pinned registration missing", regs: []string{"openshell"}, pin: "gone", wantErr: openshell.ErrGatewayNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, system := realTempDir(t), realTempDir(t)
			for _, name := range tc.regs {
				writeRegistration(t, dir, name, nil, nil)
			}
			for _, name := range tc.system {
				writeRegistration(t, system, name, nil, nil)
			}
			if tc.active != "" {
				writeFile(t, filepath.Join(dir, "active_gateway"), tc.active, 0o664)
			}
			reg, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: dir, SystemDir: system, Gateway: tc.pin})
			if tc.wantErr != nil || err != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Discover = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if tc.source == "" {
				tc.source = openshell.SourceUser
			} else {
				dir = system
			}
			if reg.Name != tc.want || reg.Source != tc.source || reg.Endpoint != "https://127.0.0.1:17670" || !reg.Local() || reg.Target() != "127.0.0.1:17670" {
				t.Fatalf("registration = %+v", reg)
			}
			if reg.TLS == nil || reg.TLS.Key != filepath.Join(dir, "gateways", tc.want, "mtls", "tls.key") {
				t.Fatalf("tls files = %+v", reg.TLS)
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
	writeFile(t, filepath.Join(dir, "active_gateway"), "../../evil", 0o600)
	if _, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: dir}); err == nil || !strings.Contains(err.Error(), "invalid gateway") {
		t.Fatalf("hostile active_gateway = %v", err)
	}
}

func TestDiscoverRefusesRemoteAndUnsupportedModes(t *testing.T) {
	skipOnWindows(t)
	for _, tc := range []struct {
		name    string
		meta    map[string]any
		wantErr error
	}{
		{"is_remote", map[string]any{"gateway_endpoint": "https://127.0.0.1:17670", "is_remote": true, "auth_mode": "mtls"}, openshell.ErrRemoteGateway},
		{"remote host", map[string]any{"gateway_endpoint": "https://gw.example.com:443", "auth_mode": "mtls"}, openshell.ErrRemoteGateway},
		{"oidc", map[string]any{"gateway_endpoint": "https://127.0.0.1:17670", "auth_mode": "oidc"}, openshell.ErrUnsupportedAuthMode},
		{"cloudflare", map[string]any{"gateway_endpoint": "https://localhost:17670", "auth_mode": "cloudflare_jwt"}, openshell.ErrUnsupportedAuthMode},
		{"mtls over http", map[string]any{"gateway_endpoint": "http://127.0.0.1:17670", "auth_mode": "mtls"}, openshell.ErrUnsupportedAuthMode},
		{"plaintext over https", map[string]any{"gateway_endpoint": "https://127.0.0.1:17670", "auth_mode": "plaintext"}, openshell.ErrUnauthenticatedGateway},
		{"loopback plaintext", map[string]any{"gateway_endpoint": "http://[::1]:17670", "auth_mode": "plaintext"}, openshell.ErrUnauthenticatedGateway},
		{"no auth", map[string]any{"gateway_endpoint": "http://127.0.0.1:17670"}, openshell.ErrUnauthenticatedGateway},
		{"missing endpoint", map[string]any{"auth_mode": "mtls"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeRegistration(t, dir, "openshell", tc.meta, nil)
			reg, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: dir})
			if tc.wantErr == nil {
				if err == nil || !strings.Contains(err.Error(), "no gateway_endpoint") {
					t.Fatalf("Discover = %v", err)
				}
				return
			}
			// The registration comes back alongside the refusal.
			if !errors.Is(err, tc.wantErr) || reg == nil {
				t.Fatalf("Discover = %+v, %v; want %v", reg, err, tc.wantErr)
			}
		})
	}
}

func TestDiscoverChecksCredentialPermissions(t *testing.T) {
	skipOnWindows(t)
	skipAsRoot(t)
	at := func(file string, mode os.FileMode) func(t *testing.T, mtls string) {
		return func(t *testing.T, m string) { chmod(t, filepath.Join(m, file), mode) }
	}
	for _, tc := range []struct {
		name     string
		mutate   func(t *testing.T, mtls string)
		wantErr  bool
		wantFix  string
		warnings int
	}{
		{name: "cli defaults warn on group-writable certs", mutate: func(*testing.T, string) {}, warnings: 2},
		{name: "tightened certs", mutate: func(t *testing.T, m string) { at("ca.crt", 0o644)(t, m); at("tls.crt", 0o600)(t, m) }},
		{name: "group-readable key", mutate: at("tls.key", 0o640), wantErr: true, wantFix: "chmod 600 "},
		{name: "world-readable key", mutate: at("tls.key", 0o604), wantErr: true, wantFix: "chmod 600 "},
		{name: "world-writable ca", mutate: at("ca.crt", 0o666), wantErr: true, wantFix: "chmod 644 "},
		{name: "key symlink", mutate: func(t *testing.T, m string) { moveBehindLink(t, filepath.Join(m, "tls.key")) }, wantErr: true},
		{name: "world-writable mtls dir", mutate: at("", 0o777), wantErr: true, wantFix: "chmod 700 "},
		{name: "missing key", mutate: func(t *testing.T, m string) { _ = os.Remove(filepath.Join(m, "tls.key")) }, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A private config directory, as the CLI creates it; t.TempDir
			// itself follows the umask.
			dir := filepath.Join(t.TempDir(), "openshell")
			reg := writeRegistration(t, dir, "openshell", nil, nil)
			tc.mutate(t, filepath.Join(reg, "mtls"))
			got, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: dir})
			if !tc.wantErr {
				if err != nil || len(got.Warnings) != tc.warnings {
					t.Fatalf("Discover = %+v, %v", got, err)
				}
				return
			}
			var perm *openshell.PermissionError
			if err == nil || (tc.wantFix != "" && (!errors.As(err, &perm) || !strings.HasPrefix(perm.Fix, tc.wantFix) || !errors.Is(err, openshell.ErrInsecureCredentials))) {
				t.Fatalf("Discover = %v (%+v), want an insecure-credentials refusal fixed by %q", err, perm, tc.wantFix)
			}
		})
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

// A Mac runs sandboxes in OpenShell MicroVMs, which need Apple silicon.
func TestCheckHost(t *testing.T) {
	for _, tc := range []struct {
		goos, goarch string
		ok           bool
	}{
		{"linux", "amd64", true}, {"linux", "arm64", true}, {"darwin", "arm64", true},
		{"darwin", "amd64", false}, {"windows", "amd64", false}, {"windows", "arm64", false},
	} {
		err := openshell.CheckHost(tc.goos, tc.goarch)
		if (err == nil) != tc.ok || (!tc.ok && !errors.Is(err, openshell.ErrUnsupportedPlatform)) {
			t.Fatalf("CheckHost(%s, %s) = %v", tc.goos, tc.goarch, err)
		}
		if tc.goos == "darwin" && !tc.ok && !strings.Contains(err.Error(), "Apple silicon") {
			t.Fatalf("CheckHost(%s, %s) = %v, which does not say why", tc.goos, tc.goarch, err)
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

func TestDialOverMTLS(t *testing.T) {
	skipOnWindows(t)
	pki := newPKI(t)
	endpoint := startGateway(t, pki, tls.RequireAndVerifyClientCert, 0, false)
	reg := probeRegistration(t, endpoint, pki)
	c, err := openshell.Dial(reg, openshell.ClientOptions{RPCTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if h, err := c.Health(context.Background()); err != nil || !h.Healthy || h.CheckVersion() != nil {
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
	c2, err := openshell.Dial(probeRegistration(t, endpoint, &testPKI{caPEM: pki.caPEM, clientPEM: other.clientPEM, clientKeyPEM: other.clientKeyPEM}),
		openshell.ClientOptions{RPCTimeout: 2 * time.Second})
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
		{Endpoint: "https://127.0.0.1:1", AuthMode: openshell.AuthModeMTLS, TLS: &openshell.TLSFiles{CA: "/nonexistent/ca.crt", Cert: "/nonexistent/tls.crt", Key: "/nonexistent/tls.key"}},
		{Endpoint: "https://127.0.0.1:1", AuthMode: openshell.AuthModeOIDC},
		{Endpoint: "https://127.0.0.1:1", AuthMode: openshell.AuthModePlaintext},
		{Endpoint: "http://127.0.0.1:1", AuthMode: openshell.AuthModePlaintext},
		{Endpoint: "http://127.0.0.1:1", AuthMode: openshell.AuthModeNone},
	} {
		_, err := openshell.Dial(reg, openshell.ClientOptions{})
		unauthenticated := reg != nil && (reg.AuthMode == openshell.AuthModePlaintext || reg.AuthMode == openshell.AuthModeNone)
		if err == nil || unauthenticated != errors.Is(err, openshell.ErrUnauthenticatedGateway) {
			t.Fatalf("Dial(%+v) = %v", reg, err)
		}
		if reg != nil {
			if _, err := reg.DialGRPC(); err == nil || unauthenticated != errors.Is(err, openshell.ErrUnauthenticatedGateway) {
				t.Fatalf("DialGRPC(%+v) = %v", reg, err)
			}
		}
	}
}

func TestDiscoverChecksRegistrationFiles(t *testing.T) {
	skipOnWindows(t)
	skipAsRoot(t)
	active := func(content string, mode os.FileMode) func(t *testing.T, base, reg string) {
		return func(t *testing.T, base, _ string) { writeFile(t, filepath.Join(base, "active_gateway"), content, mode) }
	}
	in := func(path string, mode os.FileMode) func(t *testing.T, base, reg string) {
		return func(t *testing.T, base, _ string) { chmod(t, filepath.Join(base, path), mode) }
	}
	inReg := func(path string, mode os.FileMode) func(t *testing.T, base, reg string) {
		return func(t *testing.T, _, reg string) { chmod(t, filepath.Join(reg, path), mode) }
	}
	for _, tc := range []struct {
		name    string
		mutate  []func(t *testing.T, base, reg string)
		pin     string
		wantErr string
		wantFix os.FileMode
		warn    []string
	}{
		{name: "cli defaults inside private directories", mutate: []func(*testing.T, string, string){active("openshell\n", 0o664)}},
		{name: "group-searchable directories expose group-writable files",
			mutate: []func(*testing.T, string, string){active("openshell\n", 0o664), in("", 0o750), in("gateways", 0o750), inReg("", 0o750)},
			warn:   []string{"metadata.json is group-writable (mode 0664); run chmod go-w ", "active_gateway is group-writable"}},
		{name: "one private directory shields what lies below it",
			mutate: []func(*testing.T, string, string){active("openshell\n", 0o664), in("", 0o750), inReg("", 0o770)},
			warn:   []string{"active_gateway is group-writable"}},
		{name: "group-writable directory", mutate: []func(*testing.T, string, string){in("", 0o770)}, warn: []string{"openshell is group-writable (mode 0770)"}},
		{name: "world-writable metadata", mutate: []func(*testing.T, string, string){inReg("metadata.json", 0o666)}, wantErr: "metadata.json: is writable by every user", wantFix: 0o644},
		{name: "world-writable registration directory", mutate: []func(*testing.T, string, string){inReg("", 0o777)}, wantErr: "is writable by every user", wantFix: 0o755},
		{name: "world-writable gateways directory", mutate: []func(*testing.T, string, string){in("gateways", 0o757)}, wantErr: "gateways: is writable by every user", wantFix: 0o755},
		{name: "world-writable config directory", mutate: []func(*testing.T, string, string){in("", 0o777)}, wantErr: "is writable by every user", wantFix: 0o755},
		{name: "world-writable active_gateway that selected the gateway", mutate: []func(*testing.T, string, string){active("openshell", 0o666)},
			wantErr: "active_gateway: is writable by every user", wantFix: 0o644},
		{name: "unused active_gateway is not consulted", mutate: []func(*testing.T, string, string){active("openshell", 0o666)}, pin: "openshell"},
		// Unpinned, the link is not even listed as a registration; pinned,
		// reading through it is refused.
		{name: "symlinked registration directory", mutate: []func(*testing.T, string, string){func(t *testing.T, _, reg string) { moveBehindLink(t, reg) }},
			pin: "openshell", wantErr: "symlink"},
		{name: "symlinked metadata", mutate: []func(*testing.T, string, string){func(t *testing.T, _, reg string) { moveBehindLink(t, filepath.Join(reg, "metadata.json")) }},
			wantErr: "metadata.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := filepath.Join(t.TempDir(), "openshell")
			reg := writeRegistration(t, base, "openshell", nil, nil)
			chmod(t, filepath.Join(reg, "mtls", "ca.crt"), 0o644)
			chmod(t, filepath.Join(reg, "mtls", "tls.crt"), 0o644)
			for _, m := range tc.mutate {
				m(t, base, reg)
			}
			got, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: base, SystemDir: t.TempDir(), Gateway: tc.pin})
			if tc.wantErr != "" {
				var perm *openshell.PermissionError
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || (tc.wantFix != 0 && (!errors.As(err, &perm) || perm.FixMode != tc.wantFix ||
					!strings.HasPrefix(perm.Fix, "chmod go-w ") || !errors.Is(err, openshell.ErrInsecureRegistration) || errors.Is(err, openshell.ErrInsecureCredentials))) {
					t.Fatalf("Discover = %v (%+v), want %q fixed to %o", err, perm, tc.wantErr, tc.wantFix)
				}
				return
			}
			if err != nil || len(got.Warnings) != len(tc.warn) {
				t.Fatalf("Discover = %+v, %v; want warnings %q", got, err, tc.warn)
			}
			for i, w := range tc.warn {
				if !strings.Contains(got.Warnings[i], w) {
					t.Fatalf("warning %d = %q, want %q", i, got.Warnings[i], w)
				}
			}
		})
	}

	t.Run("user active_gateway naming a system registration", func(t *testing.T) {
		user, system := filepath.Join(t.TempDir(), "openshell"), filepath.Join(t.TempDir(), "openshell")
		writeRegistration(t, system, "fleet", nil, nil)
		if err := os.MkdirAll(user, 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(user, "active_gateway"), "fleet", 0o644)
		if reg, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: user, SystemDir: system}); err != nil || reg.Source != openshell.SourceSystem {
			t.Fatalf("Discover = %+v, %v", reg, err)
		}
		chmod(t, user, 0o777)
		if _, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: user, SystemDir: system}); !errors.Is(err, openshell.ErrInsecureRegistration) {
			t.Fatalf("world-writable user directory: %v", err)
		}
	})

	t.Run("symlinked config directory is followed", func(t *testing.T) {
		real := filepath.Join(realTempDir(t), "openshell")
		writeRegistration(t, real, "openshell", nil, nil)
		writeRegistration(t, real, "dev", nil, nil)
		writeFile(t, filepath.Join(real, "active_gateway"), "dev\n", 0o644)
		link := filepath.Join(t.TempDir(), "openshell")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		reg, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: link, SystemDir: t.TempDir()})
		// The CLI's active_gateway wins through the link as it does
		// without one, and every path names the real directory.
		regDir := filepath.Join(real, "gateways", "dev")
		if err != nil || reg.Name != "dev" || reg.Dir != regDir || reg.ActiveGatewayFile != filepath.Join(real, "active_gateway") ||
			reg.TLS == nil || reg.TLS.Key != filepath.Join(regDir, "mtls", "tls.key") {
			t.Fatalf("Discover = %+v, %v", reg, err)
		}
	})
}

// TestDiscoverReportsActiveGatewayProblems: an active_gateway that cannot
// be read must not be skipped, or DefenseClaw would drive a different
// gateway than the operator's CLI.
func TestDiscoverReportsActiveGatewayProblems(t *testing.T) {
	skipOnWindows(t)
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, active string)
		pin     string
		want    string
		wantIs  error
		wantErr string
	}{
		{name: "symlinked active_gateway", setup: func(t *testing.T, active string) {
			writeFile(t, active, "dev\n", 0o644)
			moveBehindLink(t, active)
		}, wantIs: openshell.ErrInsecureRegistration, wantErr: "active_gateway: is a symbolic link"},
		{name: "oversized active_gateway", setup: func(t *testing.T, active string) { writeFile(t, active, strings.Repeat("d", 5000), 0o644) }, wantErr: "read limit"},
		{name: "active_gateway is a directory", setup: func(t *testing.T, active string) {
			if err := os.Mkdir(active, 0o700); err != nil {
				t.Fatal(err)
			}
		}, wantErr: "not a regular file"},
		{name: "unreadable active_gateway", setup: func(t *testing.T, active string) {
			skipAsRoot(t)
			writeFile(t, active, "dev\n", 0o200)
		}, wantErr: "permission denied"},
		{name: "empty active_gateway falls back to the package default", setup: func(t *testing.T, active string) { writeFile(t, active, "\n", 0o644) }, want: "openshell"},
		{name: "a pinned gateway does not read active_gateway", setup: func(t *testing.T, active string) {
			if err := os.Symlink("/nonexistent", active); err != nil {
				t.Fatal(err)
			}
		}, pin: "dev", want: "dev"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(realTempDir(t), "openshell")
			writeRegistration(t, dir, "openshell", nil, nil)
			writeRegistration(t, dir, "dev", nil, nil)
			tc.setup(t, filepath.Join(dir, "active_gateway"))
			reg, err := openshell.Discover(openshell.DiscoverOptions{ConfigDir: dir, SystemDir: t.TempDir(), Gateway: tc.pin})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || errors.Is(err, openshell.ErrNoGateway) || (tc.wantIs != nil && !errors.Is(err, tc.wantIs)) {
					t.Fatalf("Discover = %+v, %v; want %q (%v)", reg, err, tc.wantErr, tc.wantIs)
				}
				return
			}
			if err != nil || reg.Name != tc.want || reg.ActiveGatewayFile != "" {
				t.Fatalf("Discover = %+v, %v; want %s", reg, err, tc.want)
			}
		})
	}
}
