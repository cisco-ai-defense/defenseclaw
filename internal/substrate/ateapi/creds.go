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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	maxPEMBytes   = 1 << 20
	maxTokenBytes = 64 << 10
)

// fileCache rereads a small file when its size or modification time changes
// (the kubelet replaces projected files atomically), and at least every
// maxAge, and parses it with parse. It never logs the content.
type fileCache[T any] struct {
	path  string
	parse func([]byte) (T, error)

	mu      sync.Mutex
	modTime time.Time
	size    int64
	readAt  time.Time
	val     T
	ok      bool
}

const fileCacheMaxAge = 30 * time.Second

func (f *fileCache[T]) get(limit int64) (T, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var zero T
	st, err := os.Stat(f.path)
	if err != nil {
		return zero, fmt.Errorf("ateapi: %s: %w", f.path, err)
	}
	if f.ok && st.ModTime().Equal(f.modTime) && st.Size() == f.size && time.Since(f.readAt) < fileCacheMaxAge {
		return f.val, nil
	}
	b, err := readBounded(f.path, limit)
	if err != nil {
		return zero, fmt.Errorf("ateapi: read %s: %w", f.path, err)
	}
	v, err := f.parse(b)
	if err != nil {
		return zero, fmt.Errorf("ateapi: %s: %w", f.path, err)
	}
	f.val, f.ok, f.modTime, f.size, f.readAt = v, true, st.ModTime(), st.Size(), time.Now()
	return v, nil
}

// readBounded reads a regular file of at most limit bytes. Unlike
// safefile.ReadRegularFileBounded it follows a leaf symlink: every file in a
// Kubernetes projected volume is a link into the kubelet's current ..data
// directory, which the kubelet swaps atomically on rotation.
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return b, nil
}

// tokenSource is the bearer credential for AuthServiceAccount. The token is
// reread from disk (cached on size and mtime), never cached past rotation
// and never logged.
type tokenSource struct {
	path string
	once sync.Once
	fc   *fileCache[string]
}

func (t *tokenSource) token() (string, error) {
	t.once.Do(func() {
		t.fc = &fileCache[string]{path: t.path, parse: func(b []byte) (string, error) {
			tok := strings.TrimSpace(string(b))
			if tok == "" {
				return "", errors.New("token file is empty")
			}
			if strings.ContainsAny(tok, " \t\r\n") {
				return "", errors.New("token file holds more than one token")
			}
			return tok, nil
		}}
	})
	return t.fc.get(maxTokenBytes)
}

// GetRequestMetadata implements credentials.PerRPCCredentials.
func (t *tokenSource) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	tok, err := t.token()
	if err != nil {
		return nil, err
	}
	return map[string]string{"authorization": "Bearer " + tok}, nil
}

// RequireTransportSecurity implements credentials.PerRPCCredentials: the
// token is never sent in the clear.
func (t *tokenSource) RequireTransportSecurity() bool { return true }

// tlsSource builds the client TLS configuration: ate-api-server is verified
// against CAFile (reread when the trust bundle rotates) under ServerName, and
// with AuthMTLS the pod certificate is reread on every handshake.
type tlsSource struct {
	serverName string
	ca         *fileCache[*x509.CertPool]
	bundle     *fileCache[*tls.Certificate]
}

func newTLSSource(caFile, serverName string, auth Auth, bundle string) (*tlsSource, error) {
	s := &tlsSource{serverName: serverName}
	if caFile != "" {
		s.ca = &fileCache[*x509.CertPool]{path: caFile, parse: parseCAPool}
		if _, err := s.ca.get(maxPEMBytes); err != nil {
			return nil, err
		}
	}
	if auth == AuthMTLS {
		s.bundle = &fileCache[*tls.Certificate]{path: bundle, parse: parseCredentialBundle}
		if _, err := s.bundle.get(maxPEMBytes); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *tlsSource) config() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.serverName}
	if s.ca != nil {
		// Chain verification moves to VerifyConnection so each handshake
		// uses the current trust bundle; the server is still fully verified
		// (chain, server-auth usage, name) before any request is sent.
		cfg.InsecureSkipVerify = true //nolint:gosec // verified in verifyServer against the reread bundle
		cfg.VerifyConnection = s.verifyServer
	}
	if s.bundle != nil {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return s.bundle.get(maxPEMBytes)
		}
	}
	return cfg
}

func (s *tlsSource) verifyServer(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("ateapi: ate-api-server sent no certificate")
	}
	roots, err := s.ca.get(maxPEMBytes)
	if err != nil {
		return err
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, err = cs.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		DNSName:       s.serverName,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("ateapi: verify ate-api-server certificate for %s: %w", s.serverName, err)
	}
	return nil
}

func parseCAPool(b []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("holds no PEM certificate")
	}
	return pool, nil
}

// parseCredentialBundle reads a projected pod certificate: one PEM file with
// the private key followed by the certificate chain.
func parseCredentialBundle(b []byte) (*tls.Certificate, error) {
	var keyPEM, certPEM bytes.Buffer
	for rest := b; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch {
		case blk.Type == "CERTIFICATE":
			_ = pem.Encode(&certPEM, blk)
		case strings.HasSuffix(blk.Type, "PRIVATE KEY"):
			if keyPEM.Len() > 0 {
				return nil, errors.New("credential bundle holds more than one private key")
			}
			_ = pem.Encode(&keyPEM, blk)
		}
	}
	if keyPEM.Len() == 0 || certPEM.Len() == 0 {
		return nil, errors.New("credential bundle needs a private key and a certificate")
	}
	cert, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	if err != nil {
		return nil, fmt.Errorf("credential bundle: %w", err)
	}
	return &cert, nil
}
