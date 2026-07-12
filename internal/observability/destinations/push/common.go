// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package push implements the observability-v8 HTTP push adapters. Adapters in
// this package receive only immutable destination projections from delivery;
// they never receive a canonical record or producer object.
package push

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

// Construction errors are intentionally content-free. In particular, they
// never quote an endpoint, header, token, certificate, or projected record.
var (
	ErrInvalidConfig  = errors.New("observability push: invalid configuration")
	ErrUnsafeEndpoint = errors.New("observability push: unsafe endpoint")
)

// WarningCode is the complete set of safe, bounded adapter preparation
// warnings. Destination is a validated stable token; no warning contains
// endpoint or secret material.
type WarningCode string

const (
	WarningTLSVerificationDisabled WarningCode = "tls_verification_disabled"
	WarningPrivateNetworksAllowed  WarningCode = "private_networks_allowed"
	WarningCGNATAllowed            WarningCode = "cgnat_allowed"
	WarningActivationDNSDegraded   WarningCode = "activation_dns_degraded"
	WarningPlaintextCredentials    WarningCode = "plaintext_credentials"
)

type Warning struct {
	Destination string
	Code        WarningCode
}

type WarningObserver interface{ ObservePushWarning(Warning) }

type WarningObserverFunc func(Warning)

func (function WarningObserverFunc) ObservePushWarning(warning Warning) { function(warning) }

// ActivationState records whether activation-time resolution succeeded. A
// temporary resolver failure prepares a degraded adapter so the delivery
// worker can retry through the same guard. An unsafe answer never prepares an
// adapter.
type ActivationState string

const (
	ActivationReady    ActivationState = "ready"
	ActivationDegraded ActivationState = "degraded"
)

// TLSOptions is copied during construction. CABundle contains already-read
// PEM CA bytes; adapters never read a path or ambient exporter setting.
type TLSOptions struct {
	CABundle           []byte
	InsecureSkipVerify bool
}

// NetworkOptions is destination-local. The injected resolver and dialer are
// useful for deterministic tests, but every connection still passes through
// netguard.V8SafeDialContext.
type NetworkOptions struct {
	AllowPrivateNetworks bool
	AllowCGNAT           bool
	Resolver             netguard.V8Resolver
	Dialer               netguard.V8Dialer
}

type baseConfig struct {
	destination string
	endpoint    string
	tls         TLSOptions
	network     NetworkOptions
	observer    WarningObserver
	credentials bool
}

type preparedTransport struct {
	endpoint   *url.URL
	client     *http.Client
	activation ActivationState
}

func prepareTransport(ctx context.Context, config baseConfig) (preparedTransport, error) {
	if ctx == nil || !observability.IsStableToken(config.destination) {
		return preparedTransport{}, ErrInvalidConfig
	}
	policy := netguard.V8NetworkSafetyPolicy{
		AllowPrivateNetworks: config.network.AllowPrivateNetworks,
		AllowCGNAT:           config.network.AllowCGNAT,
	}
	endpoint, err := netguard.ParseV8PushURL(config.endpoint, policy)
	if err != nil {
		return preparedTransport{}, classifyConstructionError(err)
	}
	if endpoint.Scheme != "https" && (len(config.tls.CABundle) != 0 || config.tls.InsecureSkipVerify) {
		return preparedTransport{}, ErrInvalidConfig
	}

	tlsConfig, err := newTLSConfig(endpoint, config.tls)
	if err != nil {
		return preparedTransport{}, err
	}
	resolver := config.network.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := config.network.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	activation := ActivationReady
	if err := netguard.ResolveV8PushURL(ctx, endpoint, policy, resolver); err != nil {
		switch {
		case errors.Is(err, netguard.ErrV8ResolutionFailed), errors.Is(err, netguard.ErrV8ConnectionFailed):
			activation = ActivationDegraded
			emitWarning(config.observer, Warning{Destination: config.destination, Code: WarningActivationDNSDegraded})
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return preparedTransport{}, err
		default:
			return preparedTransport{}, classifyConstructionError(err)
		}
	}

	emitPolicyWarnings(config, endpoint.Scheme)
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           netguard.V8SafeDialContext(policy, dialer, resolver),
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 0,
	}
	return preparedTransport{
		endpoint: endpoint,
		client: &http.Client{
			Transport:     transport,
			CheckRedirect: netguard.BlockV8Redirects,
		},
		activation: activation,
	}, nil
}

func newTLSConfig(endpoint *url.URL, options TLSOptions) (*tls.Config, error) {
	if endpoint == nil || endpoint.Scheme != "https" {
		return nil, nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if len(options.CABundle) != 0 && !roots.AppendCertsFromPEM(append([]byte(nil), options.CABundle...)) {
		return nil, ErrInvalidConfig
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		// #nosec G402 -- this reviewed, destination-scoped opt-in is surfaced
		// through WarningObserver and is never inferred from ambient state.
		InsecureSkipVerify: options.InsecureSkipVerify,
	}, nil
}

func classifyConstructionError(err error) error {
	if errors.Is(err, netguard.ErrV8AddressProhibited) ||
		errors.Is(err, netguard.ErrV8RedirectBlocked) {
		return ErrUnsafeEndpoint
	}
	return ErrInvalidConfig
}

func emitPolicyWarnings(config baseConfig, scheme string) {
	if config.tls.InsecureSkipVerify {
		emitWarning(config.observer, Warning{Destination: config.destination, Code: WarningTLSVerificationDisabled})
	}
	if config.network.AllowPrivateNetworks {
		emitWarning(config.observer, Warning{Destination: config.destination, Code: WarningPrivateNetworksAllowed})
	}
	if config.network.AllowCGNAT {
		emitWarning(config.observer, Warning{Destination: config.destination, Code: WarningCGNATAllowed})
	}
	if scheme == "http" && config.credentials {
		emitWarning(config.observer, Warning{Destination: config.destination, Code: WarningPlaintextCredentials})
	}
}

func emitWarning(observer WarningObserver, warning Warning) {
	if observer == nil {
		return
	}
	defer func() { _ = recover() }()
	observer.ObservePushWarning(warning)
}

func cloneHeaders(headers map[string]string) (http.Header, error) {
	if len(headers) > 128 {
		return nil, ErrInvalidConfig
	}
	cloned := make(http.Header, len(headers))
	for name, value := range headers {
		if !validHeaderName(name) || !validHeaderValue(value) || forbiddenHeader(name) {
			return nil, ErrInvalidConfig
		}
		canonical := http.CanonicalHeaderKey(name)
		if _, duplicate := cloned[canonical]; duplicate {
			return nil, ErrInvalidConfig
		}
		cloned[canonical] = []string{value}
	}
	return cloned, nil
}

func validHeaderName(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character))) {
			return false
		}
	}
	return true
}

func validHeaderValue(value string) bool {
	if len(value) > 64*1024 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character == '\r' || character == '\n' || character == 0 || character == 0x7f {
			return false
		}
	}
	return true
}

func forbiddenHeader(name string) bool {
	switch strings.ToLower(name) {
	case "host", "content-length", "content-type", "connection", "proxy-connection",
		"keep-alive", "transfer-encoding", "upgrade", "trailer", "te":
		return true
	default:
		return false
	}
}

func validSecret(value string) bool {
	if value == "" || len(value) > 64*1024 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validBoundedWireValue(value string) bool {
	// HEC wrapper metadata is deliberately small enough that JSON's worst-case
	// HTML escaping still fits the per-record wrapper allowance.
	if len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

type requestWriteTracker struct{ wrote atomic.Bool }

func (tracker *requestWriteTracker) traceContext(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { tracker.wrote.Store(true) },
	})
}

func (tracker *requestWriteTracker) mayHaveReachedPeer() bool {
	return tracker != nil && tracker.wrote.Load()
}

func classifyTransportError(err error, mayHaveReachedPeer bool) delivery.DeliveryOutcome {
	var networkError net.Error
	switch {
	case err == nil:
		return delivery.OutcomeDelivered
	case errors.Is(err, netguard.ErrV8AddressProhibited),
		errors.Is(err, netguard.ErrV8EndpointInvalid),
		errors.Is(err, netguard.ErrV8RedirectBlocked):
		return delivery.OutcomeUnsafeEndpoint
	case mayHaveReachedPeer:
		// Request bytes may have reached the collector. Retrying is allowed,
		// but downstream record identity must be used for deduplication.
		return delivery.OutcomeAmbiguous
	case errors.Is(err, netguard.ErrV8ResolutionFailed),
		errors.Is(err, netguard.ErrV8ConnectionFailed),
		errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return delivery.OutcomeTransient
	case errors.As(err, &networkError):
		return delivery.OutcomeTransient
	default:
		// A generic RoundTrip error can happen after request bytes reached the
		// peer but before its acknowledgement arrived.
		return delivery.OutcomeAmbiguous
	}
}

func classifyHTTPStatus(status int) delivery.DeliveryOutcome {
	switch {
	case status >= 200 && status <= 299:
		return delivery.OutcomeDelivered
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return delivery.OutcomeAuthentication
	case status == http.StatusRequestTimeout || status == http.StatusTooEarly ||
		status == http.StatusTooManyRequests || (status >= 500 && status <= 599):
		return delivery.OutcomeTransient
	default:
		return delivery.OutcomePermanentPayload
	}
}
