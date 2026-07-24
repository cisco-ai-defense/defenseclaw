// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package push

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

type HTTPJSONLConfig struct {
	Destination string
	Endpoint    string
	Method      string
	Headers     map[string]string
	BearerToken string
	// SecretHeaders reports that at least one entry in Headers originated from
	// a secret-provider reference. The resolved value itself remains only in
	// Headers and is never included in warnings.
	SecretHeaders bool
	TLS           TLSOptions
	Network       NetworkOptions
	Observer      WarningObserver
}

// HTTPJSONL is an immutable delivery.Adapter. NewHTTPJSONL performs guarded
// activation-time resolution but makes no HTTP request.
type HTTPJSONL struct {
	endpoint   string
	method     string
	headers    http.Header
	client     *http.Client
	activation ActivationState
}

var _ delivery.Adapter = (*HTTPJSONL)(nil)

func NewHTTPJSONL(ctx context.Context, config HTTPJSONLConfig) (*HTTPJSONL, error) {
	method := config.Method
	if method == "" {
		method = http.MethodPost
	}
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch {
		return nil, ErrInvalidConfig
	}
	headers, err := cloneHeaders(config.Headers)
	if err != nil {
		return nil, err
	}
	if config.BearerToken != "" {
		_, hasAuthorization := headers["Authorization"]
		if !validSecret(config.BearerToken) || hasAuthorization {
			return nil, ErrInvalidConfig
		}
		headers.Set("Authorization", "Bearer "+config.BearerToken)
	}
	prepared, err := prepareTransport(ctx, baseConfig{
		destination: config.Destination,
		endpoint:    config.Endpoint,
		tls:         config.TLS,
		network:     config.Network,
		observer:    config.Observer,
		credentials: config.BearerToken != "" || config.SecretHeaders || hasAuthenticationHeader(headers),
	})
	if err != nil {
		return nil, err
	}
	return &HTTPJSONL{
		endpoint: prepared.endpoint.String(), method: method,
		headers: headers, client: prepared.client, activation: prepared.activation,
	}, nil
}

func hasAuthenticationHeader(headers http.Header) bool {
	for name := range headers {
		canonical := strings.ToLower(name)
		if canonical == "authorization" || canonical == "proxy-authorization" ||
			strings.Contains(canonical, "api-key") || strings.Contains(canonical, "apikey") ||
			strings.Contains(canonical, "token") || strings.Contains(canonical, "secret") {
			return true
		}
	}
	return false
}

func (adapter *HTTPJSONL) ActivationState() ActivationState {
	if adapter == nil {
		return ActivationDegraded
	}
	return adapter.activation
}

// CloseIdleConnections releases generation-local pooled connections. Runtime
// graph factories register this method as an acquisition cleanup alongside the
// owning delivery dispatcher.
func (adapter *HTTPJSONL) CloseIdleConnections() {
	if adapter != nil && adapter.client != nil {
		adapter.client.CloseIdleConnections()
	}
}

// EncodedSize is exact: every immutable projected JSON object is followed by
// one LF, including the final item.
func (*HTTPJSONL) EncodedSize(projectedSizes []int) (int, bool) {
	return delivery.DelimitedEncodedSize(projectedSizes, 0, 1, 1)
}

func (adapter *HTTPJSONL) Deliver(ctx context.Context, batch delivery.Batch) delivery.DeliveryResult {
	if adapter == nil || ctx == nil || batch.Len() == 0 {
		return delivery.DeliveryResult{Outcome: delivery.OutcomePermanentPayload}
	}
	var body bytes.Buffer
	if batch.EncodedSize() > 0 {
		body.Grow(batch.EncodedSize())
	}
	for _, item := range batch.Items() {
		projected := item.Bytes()
		if !validNDJSONProjection(projected) {
			return delivery.DeliveryResult{Outcome: delivery.OutcomePermanentPayload}
		}
		_, _ = body.Write(projected)
		_ = body.WriteByte('\n')
	}
	if body.Len() != batch.EncodedSize() {
		return delivery.DeliveryResult{Outcome: delivery.OutcomePermanentPayload}
	}
	writeTracker := &requestWriteTracker{}
	req, err := http.NewRequestWithContext(writeTracker.traceContext(ctx), adapter.method, adapter.endpoint, bytes.NewReader(body.Bytes()))
	if err != nil {
		return delivery.DeliveryResult{Outcome: delivery.OutcomePermanentPayload}
	}
	req.Header = adapter.headers.Clone()
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := adapter.client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
	}
	if err != nil {
		return delivery.DeliveryResult{Outcome: classifyTransportError(err, writeTracker.mayHaveReachedPeer())}
	}
	return delivery.DeliveryResult{Outcome: classifyHTTPStatus(resp.StatusCode)}
}

func validNDJSONProjection(projected []byte) bool {
	return len(projected) > 0 && utf8.Valid(projected) &&
		!bytes.ContainsAny(projected, "\r\n") && json.Valid(projected)
}
