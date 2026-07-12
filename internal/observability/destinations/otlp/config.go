// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

const (
	ProtocolGRPC         = "grpc"
	ProtocolGRPCProtobuf = "grpc/protobuf"
	ProtocolHTTP         = "http"
	ProtocolHTTPProtobuf = "http/protobuf"

	defaultLoggerName = "defenseclaw"
	maxEndpointBytes  = 2_048
	maxHeaderCount    = 128
	maxHeaderBytes    = 16 * 1024
	maxLoggerBytes    = 255
	maxCABundleBytes  = 4 * 1024 * 1024
	maxQueueItems     = 65_536
	maxQueueBytes     = 256 * 1024 * 1024
	maxBatchItems     = 8_192
	maxBatchBytes     = 64 * 1024 * 1024
)

type TLSConfig struct {
	Insecure bool
	CABundle []byte
}

type NetworkSafety struct {
	AllowPrivateNetworks bool
	AllowCGNAT           bool
}

type SignalOverride struct {
	Endpoint string
	Path     string
}

type BatchConfig struct {
	MaxQueueSize        int
	MaxQueueBytes       int
	MaxExportBatchSize  int
	MaxExportBatchBytes int
	ScheduledDelay      time.Duration
	ExportInterval      time.Duration
	ExportTimeout       time.Duration
}

type SignalOutcome string

const (
	SignalOutcomeExported         SignalOutcome = "exported"
	SignalOutcomeRetried          SignalOutcome = "retried"
	SignalOutcomePartialRejected  SignalOutcome = "partial_rejected"
	SignalOutcomeRejectedOversize SignalOutcome = "rejected_oversize"
	SignalOutcomeExportFailed     SignalOutcome = "export_failed"
	SignalOutcomeQueueFull        SignalOutcome = "queue_full"
)

type SignalEvent struct {
	Signal  observability.Signal
	Outcome SignalOutcome
	Count   uint64
}

type SignalObserver interface{ ObserveOTLPSignal(SignalEvent) }

type SignalObserverFunc func(SignalEvent)

func (function SignalObserverFunc) ObserveOTLPSignal(event SignalEvent) { function(event) }

type CanaryAcknowledgement struct {
	Destination string
	TraceID     string
}

type CanaryAcknowledgementObserver interface {
	ObserveOTLPCanaryAcknowledgement(CanaryAcknowledgement)
}

type CanaryAcknowledgementObserverFunc func(CanaryAcknowledgement)

func (function CanaryAcknowledgementObserverFunc) ObserveOTLPCanaryAcknowledgement(event CanaryAcknowledgement) {
	function(event)
}

// Config is a detached, already-secret-resolved compiled destination. Headers
// are exact values for this destination; the factory never expands environment
// variables or consults OTEL_EXPORTER_* state.
type Config struct {
	Destination    string
	Protocol       string
	Endpoint       string
	Selected       []observability.Signal
	SignalOverride map[observability.Signal]SignalOverride
	Headers        map[string]string
	LoggerName     string
	Timeout        time.Duration
	TLS            TLSConfig
	NetworkSafety  NetworkSafety
	Batch          BatchConfig
}

type Dependencies struct {
	Resolver            netguard.V8Resolver
	Dialer              netguard.V8Dialer
	TemporalitySelector sdkmetric.TemporalitySelector
	AggregationSelector sdkmetric.AggregationSelector
	Observer            SignalObserver
	CanaryObserver      CanaryAcknowledgementObserver
}

type signalConfig struct {
	signal      observability.Signal
	protocol    string
	url         *url.URL
	path        string
	policy      netguard.V8NetworkSafetyPolicy
	resolver    netguard.V8Resolver
	dialer      netguard.V8Dialer
	tls         *tls.Config
	timeout     time.Duration
	headers     map[string]string
	temporality sdkmetric.TemporalitySelector
	aggregation sdkmetric.AggregationSelector
	observer    SignalObserver
	canary      CanaryAcknowledgementObserver
	tracker     *dialOutcomeTracker
}

// Factory is immutable after Prepare. Exporter/adapter constructors are
// single-use per signal so one runtime generation cannot accidentally share a
// connection or queue with another provider graph.
type Factory struct {
	config  Config
	signals map[observability.Signal]signalConfig
	mu      sync.Mutex
	created map[observability.Signal]bool
}

// Prepare performs offline validation, exact TLS preparation, and guarded
// activation-time resolution for every selected signal. It creates no SDK
// processor/reader queue and mutates no global provider.
func Prepare(ctx context.Context, config Config, dependencies Dependencies) (*Factory, error) {
	if ctx == nil || !observability.IsStableToken(config.Destination) ||
		config.Timeout <= 0 || config.Timeout > 10*time.Minute || len(config.Selected) == 0 ||
		config.Batch.MaxQueueSize <= 0 || config.Batch.MaxQueueBytes <= 0 ||
		config.Batch.MaxExportBatchSize <= 0 || config.Batch.MaxExportBatchBytes <= 0 ||
		config.Batch.MaxQueueSize > maxQueueItems || config.Batch.MaxQueueBytes > maxQueueBytes ||
		config.Batch.MaxExportBatchSize > maxBatchItems || config.Batch.MaxExportBatchBytes > maxBatchBytes ||
		config.Batch.MaxExportBatchSize > config.Batch.MaxQueueSize ||
		config.Batch.ScheduledDelay <= 0 {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	protocol, ok := normalizeProtocol(config.Protocol)
	if !ok || !validHeaders(config.Headers) || (protocol == ProtocolGRPC && !validGRPCHeaders(config.Headers)) {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	if config.LoggerName == "" {
		config.LoggerName = defaultLoggerName
	}
	if len(config.LoggerName) > maxLoggerBytes || !utf8.ValidString(config.LoggerName) || strings.ContainsAny(config.LoggerName, "\x00\r\n") {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	if config.TLS.Insecure && len(config.TLS.CABundle) != 0 {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	tlsConfig, err := loadTLS(config.TLS)
	if err != nil {
		return nil, err
	}
	policy := netguard.V8NetworkSafetyPolicy{
		AllowPrivateNetworks: config.NetworkSafety.AllowPrivateNetworks,
		AllowCGNAT:           config.NetworkSafety.AllowCGNAT,
	}
	seen := make(map[observability.Signal]bool, len(config.Selected))
	signals := make(map[observability.Signal]signalConfig, len(config.Selected))
	for _, signal := range config.Selected {
		if seen[signal] || (signal != observability.SignalLogs && signal != observability.SignalTraces && signal != observability.SignalMetrics) {
			return nil, newError(ErrorInvalidConfig, nil)
		}
		seen[signal] = true
		override := config.SignalOverride[signal]
		endpoint := config.Endpoint
		if override.Endpoint != "" {
			endpoint = override.Endpoint
		}
		resolved, resolveErr := resolveSignal(ctx, protocol, endpoint, override.Path, config.TLS.Insecure, policy, dependencies)
		if resolveErr != nil {
			return nil, resolveErr
		}
		resolved.signal = signal
		resolved.tls = cloneTLS(tlsConfig)
		resolved.timeout = config.Timeout
		resolved.headers = cloneHeaders(config.Headers)
		resolved.temporality = dependencies.TemporalitySelector
		if resolved.temporality == nil {
			resolved.temporality = sdkmetric.DefaultTemporalitySelector
		}
		resolved.aggregation = dependencies.AggregationSelector
		if resolved.aggregation == nil {
			resolved.aggregation = sdkmetric.DefaultAggregationSelector
		}
		resolved.observer = dependencies.Observer
		resolved.canary = dependencies.CanaryObserver
		resolved.tracker = &dialOutcomeTracker{}
		signals[signal] = resolved
	}
	for signal := range config.SignalOverride {
		if !seen[signal] {
			return nil, newError(ErrorInvalidConfig, nil)
		}
	}
	config.Protocol = protocol
	config.Selected = append([]observability.Signal(nil), config.Selected...)
	config.Headers = cloneHeaders(config.Headers)
	config.SignalOverride = cloneOverrides(config.SignalOverride)
	config.TLS.CABundle = append([]byte(nil), config.TLS.CABundle...)
	return &Factory{config: config, signals: signals, created: make(map[observability.Signal]bool)}, nil
}

func normalizeProtocol(value string) (string, bool) {
	switch value {
	case ProtocolGRPC, ProtocolGRPCProtobuf:
		return ProtocolGRPC, true
	case ProtocolHTTP, ProtocolHTTPProtobuf:
		return ProtocolHTTP, true
	default:
		return "", false
	}
}

func resolveSignal(
	ctx context.Context,
	protocol, endpoint, overridePath string,
	insecure bool,
	policy netguard.V8NetworkSafetyPolicy,
	dependencies Dependencies,
) (signalConfig, error) {
	if endpoint == "" || len(endpoint) > maxEndpointBytes || strings.ContainsAny(endpoint, "\x00\r\n\t ") {
		return signalConfig{}, newError(ErrorInvalidConfig, nil)
	}
	raw := endpoint
	if !strings.Contains(raw, "://") {
		if protocol != ProtocolGRPC {
			return signalConfig{}, newError(ErrorInvalidConfig, nil)
		}
		scheme := "https"
		if insecure {
			scheme = "http"
		}
		raw = scheme + "://" + raw
	}
	u, err := netguard.ParseV8PushURL(raw, policy)
	if err != nil {
		return signalConfig{}, networkError(err)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return signalConfig{}, newError(ErrorInvalidConfig, nil)
	}
	if (u.Scheme == "http") != insecure {
		return signalConfig{}, newError(ErrorInvalidConfig, nil)
	}
	if protocol == ProtocolGRPC && (overridePath != "" || (u.Path != "" && u.Path != "/")) {
		return signalConfig{}, newError(ErrorInvalidConfig, nil)
	}
	resolvedPath := overridePath
	if resolvedPath != "" && !validSignalPath(resolvedPath) {
		return signalConfig{}, newError(ErrorInvalidConfig, nil)
	}
	if protocol == ProtocolHTTP {
		if resolvedPath == "" && u.Path != "" && u.Path != "/" {
			resolvedPath = u.EscapedPath()
		}
	}
	if err := netguard.ResolveV8PushURL(ctx, u, policy, dependencies.Resolver); err != nil {
		// A temporary/no-answer DNS failure cannot prove the endpoint unsafe.
		// Keep the optional signal pipeline inactive-but-constructible and let
		// the guarded dial path re-resolve on every attempt. Prohibited/mixed
		// answers, invalid endpoints, and cancellation remain activation errors.
		if !errors.Is(err, netguard.ErrV8ResolutionFailed) {
			return signalConfig{}, networkError(err)
		}
	}
	return signalConfig{
		protocol: protocol, url: cloneURL(u), path: resolvedPath, policy: policy,
		resolver: dependencies.Resolver, dialer: dependencies.Dialer,
	}, nil
}

func (factory *Factory) claim(signal observability.Signal) (signalConfig, error) {
	if factory == nil {
		return signalConfig{}, newError(ErrorInvalidConfig, nil)
	}
	factory.mu.Lock()
	defer factory.mu.Unlock()
	config, ok := factory.signals[signal]
	if !ok || factory.created[signal] {
		return signalConfig{}, newError(ErrorInvalidConfig, nil)
	}
	factory.created[signal] = true
	if config.protocol == ProtocolHTTP && config.path == "" {
		switch signal {
		case observability.SignalLogs:
			config.path = "/v1/logs"
		case observability.SignalTraces:
			config.path = "/v1/traces"
		case observability.SignalMetrics:
			config.path = "/v1/metrics"
		}
	}
	return config, nil
}

func loadTLS(config TLSConfig) (*tls.Config, error) {
	if config.Insecure {
		return nil, nil
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(config.CABundle) == 0 {
		return tlsConfig, nil
	}
	if len(config.CABundle) > maxCABundleBytes {
		return nil, newError(ErrorTLS, nil)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(append([]byte(nil), config.CABundle...)) {
		return nil, newError(ErrorTLS, nil)
	}
	tlsConfig.RootCAs = pool
	return tlsConfig, nil
}

func newHTTPClient(config signalConfig) (*http.Client, *http.Transport) {
	safeDial := netguard.V8SafeDialContext(config.policy, config.dialer, config.resolver)
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			connection, err := safeDial(ctx, network, address)
			config.tracker.record(err)
			return connection, err
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   config.timeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       cloneTLS(config.tls),
	}
	clientTransport := observedRoundTripper{inner: transport}
	return &http.Client{Transport: clientTransport, Timeout: config.timeout, CheckRedirect: netguard.BlockV8Redirects}, transport
}

func retryBounds(timeout time.Duration) (time.Duration, time.Duration) {
	initial := 100 * time.Millisecond
	if timeout < 4*initial {
		initial = timeout / 4
		if initial <= 0 {
			initial = time.Nanosecond
		}
	}
	maximum := 5 * time.Second
	if maximum > timeout/2 {
		maximum = timeout / 2
	}
	if maximum < initial {
		maximum = initial
	}
	return initial, maximum
}

func cleanupContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 || timeout > 5*time.Second {
		timeout = 5 * time.Second
	}
	base := context.Background()
	if parent != nil {
		base = context.WithoutCancel(parent)
	}
	return context.WithTimeout(base, timeout)
}

func signalURL(config signalConfig) string {
	u := cloneURL(config.url)
	decoded, err := url.PathUnescape(config.path)
	if err != nil {
		return ""
	}
	u.Path = decoded
	if decoded != config.path {
		u.RawPath = config.path
	} else {
		u.RawPath = ""
	}
	u.RawQuery, u.Fragment = "", ""
	return u.String()
}

func validSignalPath(value string) bool {
	if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\x00\r\n?#") {
		return false
	}
	_, err := url.PathUnescape(value)
	return err == nil
}

func validHeaders(headers map[string]string) bool {
	if len(headers) > maxHeaderCount {
		return false
	}
	total := 0
	for key, value := range headers {
		total += len(key) + len(value)
		if total > maxHeaderBytes || !validHeaderName(key) || !validHeaderValue(value) ||
			strings.EqualFold(key, "content-length") || strings.EqualFold(key, "content-type") ||
			strings.EqualFold(key, "host") || strings.EqualFold(key, "connection") {
			return false
		}
	}
	return true
}

func validHeaderName(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, character := range []byte(value) {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character))) {
			return false
		}
	}
	return true
}

func validHeaderValue(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func validGRPCHeaders(headers map[string]string) bool {
	for key := range headers {
		normalized := strings.ToLower(key)
		if strings.HasPrefix(normalized, "grpc-") || strings.HasSuffix(normalized, "-bin") {
			return false
		}
		for _, character := range []byte(normalized) {
			if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
				character == '-' || character == '_' || character == '.') {
				return false
			}
		}
	}
	return true
}

func cloneHeaders(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneOverrides(source map[observability.Signal]SignalOverride) map[observability.Signal]SignalOverride {
	result := make(map[observability.Signal]SignalOverride, len(source))
	for signal, value := range source {
		result[signal] = value
	}
	return result
}

func cloneTLS(source *tls.Config) *tls.Config {
	if source == nil {
		return nil
	}
	return source.Clone()
}

func cloneURL(source *url.URL) *url.URL {
	if source == nil {
		return nil
	}
	result := *source
	return &result
}
