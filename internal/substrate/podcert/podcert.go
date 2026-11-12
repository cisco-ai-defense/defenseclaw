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

// Package podcert serves and checks TLS with the pod certificates Agent
// Substrate projects (podCertificate volumes): a credential bundle (the
// private key and the certificate chain in one PEM file, rotated in place
// by the kubelet) and a ClusterTrustBundle PEM. Both are re-read when they
// change, so a rotation needs no restart.
package podcert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"
)

// recheck is how often the files' modification times are looked at.
const recheck = 10 * time.Second

// Files re-reads a credential bundle and a trust bundle on change.
type Files struct {
	// Bundle is the credential bundle (key + chain), Trust the trust
	// bundle. Either may be empty when unused.
	Bundle string
	Trust  string

	mu        sync.Mutex
	checked   time.Time
	certMod   time.Time
	trustMod  time.Time
	cert      *tls.Certificate
	pool      *x509.CertPool
	now       func() time.Time
	lastError error
}

// NewFiles loads both files once, so a bad path fails at start.
func NewFiles(bundle, trust string) (*Files, error) {
	f := &Files{Bundle: bundle, Trust: trust, now: time.Now}
	if err := f.reload(true); err != nil {
		return nil, err
	}
	return f, nil
}

func modTime(path string) (time.Time, error) {
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}
	return st.ModTime(), nil
}

// reload re-reads whatever changed. A failed re-read keeps the last good
// material (a rotation caught half-written is retried on the next check).
func (f *Files) reload(force bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	if !force && now.Sub(f.checked) < recheck {
		return f.lastError
	}
	f.checked = now
	f.lastError = nil
	if f.Bundle != "" {
		mod, err := modTime(f.Bundle)
		if err == nil && (force || !mod.Equal(f.certMod) || f.cert == nil) {
			var cert tls.Certificate
			cert, err = LoadCredentialBundle(f.Bundle)
			if err == nil {
				f.cert, f.certMod = &cert, mod
			}
		}
		if err != nil {
			f.lastError = fmt.Errorf("podcert: credential bundle: %w", err)
		}
	}
	if f.Trust != "" {
		mod, err := modTime(f.Trust)
		if err == nil && (force || !mod.Equal(f.trustMod) || f.pool == nil) {
			var pool *x509.CertPool
			pool, err = LoadTrustBundle(f.Trust)
			if err == nil {
				f.pool, f.trustMod = pool, mod
			}
		}
		if err != nil && f.lastError == nil {
			f.lastError = fmt.Errorf("podcert: trust bundle: %w", err)
		}
	}
	if force && f.lastError != nil {
		return f.lastError
	}
	return nil
}

// Certificate returns the current certificate.
func (f *Files) Certificate() (*tls.Certificate, error) {
	_ = f.reload(false)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cert == nil {
		return nil, errors.New("podcert: no certificate loaded")
	}
	return f.cert, nil
}

// Pool returns the current trust pool.
func (f *Files) Pool() (*x509.CertPool, error) {
	_ = f.reload(false)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pool == nil {
		return nil, errors.New("podcert: no trust bundle loaded")
	}
	return f.pool, nil
}

// LoadCredentialBundle reads a PEM file holding one private key and the
// certificate chain, leaf first.
func LoadCredentialBundle(path string) (tls.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, err
	}
	var certPEM, keyPEM []byte
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			certPEM = append(certPEM, pem.EncodeToMemory(block)...)
		case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY":
			if keyPEM != nil {
				return tls.Certificate{}, errors.New("more than one private key")
			}
			keyPEM = pem.EncodeToMemory(block)
		}
	}
	if certPEM == nil || keyPEM == nil {
		return tls.Certificate{}, errors.New("a credential bundle needs a private key and a certificate")
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// LoadTrustBundle reads a PEM file of CA certificates.
func LoadTrustBundle(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("no certificate in the trust bundle")
	}
	return pool, nil
}

// ServerConfig serves TLS 1.2+ with the bundle's certificate. With
// clientIDs non-empty it requires a client certificate that chains to the
// trust bundle and carries one of those URI SANs (SPIFFE IDs).
func (f *Files) ServerConfig(clientIDs []string) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return f.Certificate()
		},
	}
	if len(clientIDs) == 0 {
		return cfg
	}
	cfg.ClientAuth = tls.RequireAnyClientCert
	// VerifyConnection runs on every handshake, resumed ones included.
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		return f.verifyPeer(cs.PeerCertificates, clientIDs, x509.ExtKeyUsageClientAuth)
	}
	return cfg
}

// ClientConfig presents the bundle's certificate and requires a server
// certificate that chains to the trust bundle and carries one of serverIDs
// as a URI SAN.
func (f *Files) ClientConfig(serverIDs []string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return f.Certificate()
		},
		// Pod identity certificates name a SPIFFE ID, not a DNS name, so
		// the default host-name check cannot apply. The full check (chain
		// to the trust bundle, key usage, an allowed SPIFFE ID) runs in
		// VerifyConnection, which Go calls on every handshake, resumed
		// ones included; it is never skipped.
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			return f.verifyPeer(cs.PeerCertificates, serverIDs, x509.ExtKeyUsageServerAuth)
		},
	}
}

func (f *Files) verifyPeer(certs []*x509.Certificate, allowed []string, usage x509.ExtKeyUsage) error {
	if len(certs) == 0 {
		return errors.New("podcert: the peer sent no certificate")
	}
	pool, err := f.Pool()
	if err != nil {
		return err
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{usage},
	}); err != nil {
		return errors.New("podcert: the peer certificate does not chain to the trust bundle")
	}
	if len(allowed) == 0 {
		return errors.New("podcert: no peer identity is allowed")
	}
	for _, u := range certs[0].URIs {
		if slices.Contains(allowed, u.String()) {
			return nil
		}
	}
	return errors.New("podcert: the peer identity is not allowed")
}
