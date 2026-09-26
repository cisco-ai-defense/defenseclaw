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

package openshell

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const maxPEMBytes = 1 << 20

// TLSConfig builds the client mTLS configuration of an mtls registration
// from the same files the openshell CLI uses. The file checks run again
// here, so a key loosened after discovery is refused.
func (r *Registration) TLSConfig() (*tls.Config, error) {
	if r == nil || r.AuthMode != AuthModeMTLS || r.TLS == nil {
		return nil, errors.New("openshell: registration is not an mtls registration")
	}
	if _, err := CheckTLSFiles(r.TLS); err != nil {
		return nil, err
	}
	caPEM, err := safefile.ReadRegularFileBounded(r.TLS.CA, maxPEMBytes)
	if err != nil {
		return nil, fmt.Errorf("openshell: read gateway CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("openshell: %s holds no PEM certificate", r.TLS.CA)
	}
	certPEM, err := safefile.ReadRegularFileBounded(r.TLS.Cert, maxPEMBytes)
	if err != nil {
		return nil, fmt.Errorf("openshell: read client certificate: %w", err)
	}
	keyPEM, err := safefile.ReadRegularFileBounded(r.TLS.Key, maxPEMBytes)
	if err != nil {
		return nil, fmt.Errorf("openshell: read client key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("openshell: load client certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
	}, nil
}

// DialGRPC opens a raw gRPC connection to the registration's gateway, for
// the streaming RPCs the SDK does not expose in full (WatchSandbox with
// logs, events and resume cursors). The connection keeps HTTP/2 pings
// going so a silently dropped long-lived stream is noticed.
func (r *Registration) DialGRPC(extra ...grpc.DialOption) (*grpc.ClientConn, error) {
	if r == nil {
		return nil, errors.New("openshell: nil registration")
	}
	if r.Remote {
		return nil, fmt.Errorf("%w: %s", ErrRemoteGateway, r.Endpoint)
	}
	var creds credentials.TransportCredentials
	switch r.AuthMode {
	case AuthModeMTLS:
		cfg, err := r.TLSConfig()
		if err != nil {
			return nil, err
		}
		creds = credentials.NewTLS(cfg)
	case AuthModePlaintext, AuthModeNone:
		if !strings.HasPrefix(r.Endpoint, "http://") {
			return nil, fmt.Errorf("%w: %s over %s", ErrUnsupportedAuthMode, r.AuthMode, r.Endpoint)
		}
		creds = insecure.NewCredentials()
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAuthMode, r.AuthMode)
	}
	opts := append([]grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: time.Minute, Timeout: 20 * time.Second}),
	}, extra...)
	conn, err := grpc.NewClient(r.Target(), opts...)
	if err != nil {
		return nil, fmt.Errorf("openshell: dial %s: %w", r.Endpoint, err)
	}
	return conn, nil
}
