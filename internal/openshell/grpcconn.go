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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
	pool, err := r.caPool()
	if err != nil {
		return nil, err
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

func (r *Registration) caPool() (*x509.CertPool, error) {
	caPEM, err := safefile.ReadRegularFileBounded(r.TLS.CA, maxPEMBytes)
	if err != nil {
		return nil, fmt.Errorf("openshell: read gateway CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("openshell: %s holds no PEM certificate", r.TLS.CA)
	}
	return pool, nil
}

// ErrGatewayExposed means someone other than the caller could drive the
// gateway: it accepted a TLS session from a client that presented no
// certificate, or its configuration turns off TLS or client certificate
// authentication, enables OIDC or unauthenticated users, or listens
// beyond loopback.
var ErrGatewayExposed = errors.New("openshell: the gateway can be reached without the registration's client certificate")

// Client-auth probe bounds. A gateway that requires a certificate sends
// its alert as soon as it reads the client's empty one, right after the
// handshake; on loopback two seconds are plenty.
const (
	probeTimeout     = 10 * time.Second
	probeAlertWindow = 2 * time.Second
)

// ProbeClientAuth connects to the registration's gateway over TLS, trusting
// only the registration's CA, as a client with no certificate, and returns
// nil only when the gateway asks for a certificate and then refuses the
// client for having none. It returns ErrGatewayExposed when the gateway
// lets the client in instead, and another error when it cannot tell: the
// gateway is down, does not speak TLS, or presents a certificate the
// registration's CA did not sign. Nothing is sent after the handshake.
func ProbeClientAuth(ctx context.Context, reg *Registration) error {
	if reg == nil || reg.AuthMode != AuthModeMTLS || reg.TLS == nil {
		return errors.New("openshell: registration is not an mtls registration")
	}
	pool, err := reg.caPool()
	if err != nil {
		return err
	}
	target := reg.Target()
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("openshell: gateway endpoint %s: %w", reg.Endpoint, err)
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	var requested atomic.Bool
	d := &tls.Dialer{Config: &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: host, NextProtos: []string{"h2"},
		// Called when the server sends a CertificateRequest; the empty
		// certificate sends none.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			requested.Store(true)
			return &tls.Certificate{}, nil
		},
	}}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err == nil {
		defer conn.Close()
		// A TLS 1.3 server checks the client's certificate after the
		// client's side of the handshake is done; its verdict is the first
		// record it sends.
		_ = conn.SetReadDeadline(time.Now().Add(probeAlertWindow))
		var b [1]byte
		_, err = conn.Read(b[:])
		var nerr net.Error
		switch {
		case err == nil:
			return fmt.Errorf("%w: %s accepted a TLS session from a client with no certificate", ErrGatewayExposed, reg.Endpoint)
		case errors.As(err, &nerr) && nerr.Timeout() && ctx.Err() == nil:
			return fmt.Errorf("%w: %s kept a TLS session with a client with no certificate open", ErrGatewayExposed, reg.Endpoint)
		}
	}
	if requested.Load() && missingCertAlert(err) {
		return nil
	}
	return fmt.Errorf("openshell: could not confirm that %s requires a client certificate: %w", reg.Endpoint, err)
}

// missingCertAlert reports whether err is a TLS alert a server sends a
// client that did not present the certificate it asked for:
// certificate_required (TLS 1.3), or handshake_failure or bad_certificate
// (TLS 1.2).
func missingCertAlert(err error) bool {
	var op *net.OpError
	if !errors.As(err, &op) || op.Op != "remote error" || op.Err == nil {
		return false
	}
	switch op.Err.Error() {
	case "tls: certificate required", "tls: handshake failure", "tls: bad certificate":
		return true
	}
	return false
}

// DialGRPC opens a raw gRPC connection to the registration's mTLS
// gateway, for the streaming RPCs the SDK does not expose in full
// (WatchSandbox with logs, events and resume cursors). Like Dial it
// refuses registrations without client certificates. The connection keeps
// HTTP/2 pings going so a silently dropped long-lived stream is noticed.
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
		return nil, unauthenticatedError(r)
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
