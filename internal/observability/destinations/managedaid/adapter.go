// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package managedaid owns the generated managed-enterprise Cisco AI Defense
// log transport. It consumes only destination-projected immutable v8 bytes.
package managedaid

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/otlp"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/push"
)

const (
	defaultTimeout        = 10 * time.Second
	remintMinimumInterval = 30 * time.Second
	maxResponseBytes      = 64 * 1024
	jsonEscapeFactor      = 6
	jsonRequestBaseBytes  = 256 * 1024
)

var payloadPrefix = []byte(`{"payload":`)

// ProviderResolver is a process-stable, lazy seam. The sidecar binds it to
// ensureCMIDProvider so the inspection and telemetry lanes share one cache and
// Invalidate operation without making credentials a destination-plan field.
type ProviderResolver interface {
	ResolveCMIDProvider(context.Context) (cloudreg.Provider, error)
}

type ProviderResolverFunc func(context.Context) (cloudreg.Provider, error)

func (function ProviderResolverFunc) ResolveCMIDProvider(ctx context.Context) (cloudreg.Provider, error) {
	return function(ctx)
}

// Config contains only release-owned effective-plan fields and the canonical
// OTLP resource snapshot. No credential or source-record field is accepted.
type Config struct {
	Destination string
	Endpoint    string
	LoggerName  string
	Timeout     time.Duration
	Resource    otlp.LogResourceSnapshot
	Network     push.NetworkOptions
	Warnings    push.WarningObserver
}

// Adapter is synchronous; the common generation dispatcher owns its bounded
// queue, batching, retries, health, activation, and drain lifecycle.
type Adapter struct {
	endpoint string
	timeout  time.Duration
	resolver ProviderResolver
	builder  *otlp.CanonicalLogRequestBuilder
	client   *http.Client

	remintMu   sync.Mutex
	lastRemint time.Time
	closed     atomic.Bool
	available  bool
}

var _ delivery.Adapter = (*Adapter)(nil)

// New creates no worker, performs no request, and never resolves CMID. An
// unavailable endpoint or provider is represented by a drop-only adapter so a
// managed sink failure cannot reject the v8 graph or user destinations.
func New(ctx context.Context, source Config, resolver ProviderResolver) (*Adapter, error) {
	timeout := source.Timeout
	if timeout <= 0 || timeout > defaultTimeout {
		timeout = defaultTimeout
	}
	builder, err := otlp.NewCanonicalLogRequestBuilder(
		source.Destination, source.LoggerName, source.Resource,
	)
	if err != nil {
		return nil, err
	}
	endpoint, endpointOK := validEndpoint(source.Endpoint)
	client := &http.Client{}
	if endpointOK && ctx != nil {
		preparedEndpoint, preparedClient, prepareErr := prepareAuthenticatedTransport(
			ctx, source.Destination, endpoint, source.Network, source.Warnings,
		)
		if prepareErr == nil && preparedClient != nil {
			endpoint, client = preparedEndpoint, preparedClient
		} else {
			endpointOK = false
		}
	} else {
		endpointOK = false
	}
	return &Adapter{
		endpoint: endpoint, timeout: timeout, resolver: resolver, builder: builder,
		client: client, available: endpointOK && resolver != nil,
	}, nil
}

func prepareAuthenticatedTransport(
	ctx context.Context,
	destination string,
	endpoint string,
	network push.NetworkOptions,
	warnings push.WarningObserver,
) (preparedEndpoint string, client *http.Client, err error) {
	defer func() {
		if recover() != nil {
			preparedEndpoint, client, err = "", nil, errors.New("managed transport unavailable")
		}
	}()
	preparedEndpoint, client, _, err = push.PrepareAuthenticatedHTTPTransport(
		ctx, destination, endpoint, network, warnings,
	)
	return preparedEndpoint, client, err
}

func validEndpoint(raw string) (string, bool) {
	if len(raw) == 0 || len(raw) > 2_048 || !utf8.ValidString(raw) ||
		strings.IndexFunc(raw, unicode.IsSpace) >= 0 {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.Host == "" ||
		parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.RawFragment != "" || strings.Contains(raw, "#") ||
		parsed.Path != config.ObservabilityV8ManagedAIDIngestPath ||
		parsed.EscapedPath() != config.ObservabilityV8ManagedAIDIngestPath ||
		parsed.RawPath != "" || strings.HasSuffix(parsed.Host, ":") {
		return "", false
	}
	if port := parsed.Port(); port != "" {
		value, portErr := strconv.Atoi(port)
		if portErr != nil || value < 1 || value > 65_535 {
			return "", false
		}
	}
	return parsed.String(), true
}

// EncodedSize is a conservative OTLP/JSON upper bound. JSON may escape each
// projected byte; the dispatcher uses this result to split before retention.
func (adapter *Adapter) EncodedSize(projectedSizes []int) (int, bool) {
	if adapter == nil || adapter.builder == nil {
		return 0, false
	}
	total := jsonRequestBaseBytes + len(payloadPrefix) + 1
	for _, size := range projectedSizes {
		if size < 0 || size > (int(^uint(0)>>1)-65_536)/jsonEscapeFactor {
			return 0, false
		}
		addition := size*jsonEscapeFactor + 65_536
		if total > int(^uint(0)>>1)-addition {
			return 0, false
		}
		total += addition
	}
	return total, true
}

func (adapter *Adapter) Deliver(ctx context.Context, batch delivery.Batch) delivery.DeliveryResult {
	if adapter == nil || ctx == nil || adapter.closed.Load() || !adapter.available {
		return delivery.DeliveryResult{Outcome: delivery.OutcomeAuthentication}
	}
	estimate, ok := adapter.EncodedSize(batchSizes(batch))
	if !ok || estimate != batch.EncodedSize() {
		return delivery.DeliveryResult{Outcome: delivery.OutcomePermanentPayload}
	}
	request, ok := adapter.builder.Build(batch)
	if !ok {
		return delivery.DeliveryResult{Outcome: delivery.OutcomePermanentPayload}
	}
	inner, err := otlp.MarshalCanonicalLogRequestJSON(request)
	if err != nil || len(inner) > estimate-len(payloadPrefix)-1 {
		return delivery.DeliveryResult{Outcome: delivery.OutcomePermanentPayload}
	}
	body := make([]byte, 0, len(payloadPrefix)+len(inner)+1)
	body = append(body, payloadPrefix...)
	body = append(body, inner...)
	body = append(body, '}')

	deadline, cancel := context.WithTimeout(ctx, adapter.timeout)
	defer cancel()
	provider, err := resolveProvider(deadline, adapter.resolver)
	if err != nil {
		return delivery.DeliveryResult{Outcome: classifyCredentialError(err)}
	}
	if provider == nil {
		return delivery.DeliveryResult{Outcome: delivery.OutcomeAuthentication}
	}
	token, err := providerToken(deadline, provider)
	if err != nil {
		return delivery.DeliveryResult{Outcome: delivery.OutcomeTransient}
	}
	if !validToken(token) {
		return delivery.DeliveryResult{Outcome: delivery.OutcomeAuthentication}
	}
	status, outcome := adapter.post(deadline, body, token)
	if outcome != "" {
		return delivery.DeliveryResult{Outcome: outcome}
	}
	if status == http.StatusUnauthorized {
		fresh, outcome := adapter.remint(deadline, provider, token)
		if outcome != "" {
			return delivery.DeliveryResult{Outcome: outcome}
		}
		status, outcome = adapter.post(deadline, body, fresh)
		if outcome != "" {
			return delivery.DeliveryResult{Outcome: outcome}
		}
	}
	return delivery.DeliveryResult{Outcome: classifyStatus(status)}
}

func classifyCredentialError(err error) delivery.DeliveryOutcome {
	if errors.Is(err, cloudreg.ErrNoProviderRegistered) {
		return delivery.OutcomeAuthentication
	}
	return delivery.OutcomeTransient
}

func batchSizes(batch delivery.Batch) []int {
	items := batch.Items()
	result := make([]int, len(items))
	for index := range items {
		result[index] = items[index].Size()
	}
	return result
}

func resolveProvider(ctx context.Context, resolver ProviderResolver) (provider cloudreg.Provider, err error) {
	defer func() {
		if recover() != nil {
			provider, err = nil, errors.New("managed provider unavailable")
		}
	}()
	return resolver.ResolveCMIDProvider(ctx)
}

func providerToken(ctx context.Context, provider cloudreg.Provider) (token string, err error) {
	defer func() {
		if recover() != nil {
			token, err = "", errors.New("managed token unavailable")
		}
	}()
	return provider.Token(ctx)
}

func validToken(token string) bool {
	return token != "" && strings.TrimSpace(token) == token && len(token) <= 64*1024 &&
		utf8.ValidString(token) && !strings.ContainsAny(token, "\x00\r\n")
}

func (adapter *Adapter) post(ctx context.Context, body []byte, token string) (int, delivery.DeliveryOutcome) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, adapter.endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, delivery.OutcomePermanentPayload
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	var wrote atomic.Bool
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { wrote.Store(true) },
	}))
	response, err := adapter.client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return 0, classifyTransportError(err, wrote.Load())
	}
	if response == nil {
		return 0, delivery.OutcomeAmbiguous
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil || len(responseBody) > maxResponseBytes {
		return 0, delivery.OutcomeAmbiguous
	}
	return response.StatusCode, ""
}

func (adapter *Adapter) remint(
	ctx context.Context,
	provider cloudreg.Provider,
	current string,
) (string, delivery.DeliveryOutcome) {
	adapter.remintMu.Lock()
	defer adapter.remintMu.Unlock()
	if !adapter.lastRemint.IsZero() && time.Since(adapter.lastRemint) < remintMinimumInterval {
		token, err := providerToken(ctx, provider)
		return classifyRemintedToken(token, current, err)
	}
	if !invalidateProvider(provider) {
		return "", delivery.OutcomeTransient
	}
	adapter.lastRemint = time.Now()
	token, err := providerToken(ctx, provider)
	return classifyRemintedToken(token, current, err)
}

func classifyRemintedToken(token, current string, err error) (string, delivery.DeliveryOutcome) {
	if err != nil {
		return "", delivery.OutcomeTransient
	}
	if !validToken(token) || token == current {
		return "", delivery.OutcomeAuthentication
	}
	return token, ""
}

func invalidateProvider(provider cloudreg.Provider) (ok bool) {
	defer func() { ok = recover() == nil }()
	provider.Invalidate()
	return true
}

func classifyStatus(status int) delivery.DeliveryOutcome {
	switch {
	case status >= 200 && status < 300:
		return delivery.OutcomeDelivered
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return delivery.OutcomeAuthentication
	case status == http.StatusRequestTimeout || status == http.StatusTooEarly ||
		status == http.StatusTooManyRequests || status >= 500:
		return delivery.OutcomeTransient
	default:
		return delivery.OutcomePermanentPayload
	}
}

func classifyTransportError(err error, wrote bool) delivery.DeliveryOutcome {
	var networkError net.Error
	switch {
	case errors.Is(err, netguard.ErrV8AddressProhibited),
		errors.Is(err, netguard.ErrV8EndpointInvalid),
		errors.Is(err, netguard.ErrV8RedirectBlocked):
		return delivery.OutcomeUnsafeEndpoint
	case wrote:
		return delivery.OutcomeAmbiguous
	case errors.Is(err, netguard.ErrV8ResolutionFailed),
		errors.Is(err, netguard.ErrV8ConnectionFailed),
		errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &networkError):
		return delivery.OutcomeTransient
	default:
		return delivery.OutcomeAmbiguous
	}
}

// CloseIdleConnections releases only this generation's transport pool.
func (adapter *Adapter) CloseIdleConnections() {
	if adapter == nil || adapter.closed.Swap(true) {
		return
	}
	if adapter.client != nil {
		adapter.client.CloseIdleConnections()
	}
}
