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

// Package leader is the transport of the gateway's stateful calls on Agent
// Substrate (PLAN §5.4, D11, D13). Stateless gateway replicas forward
// ChainObserve, IntentGet/Put, AskOpen/Resolve and RegistrationWrite to the
// one leader, which holds a Kubernetes Lease and the store volume.
//
// The wire is HTTPS with mutual TLS between pods (pod identity
// certificates, peer SPIFFE IDs allowlisted): POST /leader/v1/<method>
// with {"request_id": "...", "body": {...}}, answered {"body": {...}} or
// {"error": {"code": "...", "message": "..."}}. A replica that is not the
// leader answers 503 not_leader. Every call is idempotent by request ID:
// the leader keeps each answer for IdempotencyTTL and replays it to a
// retry, and a retry that arrives while the first call runs waits for it.
//
// This package is the transport and the leader-only gate. What each method
// does to the store (tool chains, intent, asks, registrations) is
// registered with Server.Handle by the store's owner.
package leader

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Methods.
const (
	MethodChainObserve      = "ChainObserve"
	MethodIntentGet         = "IntentGet"
	MethodIntentPut         = "IntentPut"
	MethodAskOpen           = "AskOpen"
	MethodAskResolve        = "AskResolve"
	MethodRegistrationWrite = "RegistrationWrite"
	// MethodRegistrationGet and MethodRegistrationList are the reads
	// followers make of the registrations the leader keeps.
	MethodRegistrationGet  = "RegistrationGet"
	MethodRegistrationList = "RegistrationList"
)

// Methods lists every method a leader serves.
var Methods = []string{
	MethodChainObserve, MethodIntentGet, MethodIntentPut,
	MethodAskOpen, MethodAskResolve, MethodRegistrationWrite,
	MethodRegistrationGet, MethodRegistrationList,
}

// Error codes.
const (
	CodeNotLeader     = "not_leader"
	CodeBadRequest    = "bad_request"
	CodeUnknownMethod = "unknown_method"
	CodeInternal      = "internal"
	CodeUnavailable   = "unavailable"
)

// PathPrefix is the route prefix of leader calls.
const PathPrefix = "/leader/v1/"

const (
	maxBodyBytes = 4 << 20
	// IdempotencyTTL is how long an answer is replayed to a retry.
	IdempotencyTTL = 10 * time.Minute
	// maxIdempotent bounds the replay cache.
	maxIdempotent = 200000
)

var requestIDRE = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)

// Request is the wire request.
type Request struct {
	RequestID string          `json:"request_id"`
	Body      json.RawMessage `json:"body"`
}

// Response is the wire answer.
type Response struct {
	Body  json.RawMessage `json:"body,omitempty"`
	Error *WireError      `json:"error,omitempty"`
}

// WireError is a call failure.
type WireError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *WireError) Error() string { return "leader: " + e.Code + ": " + e.Message }

// IsNotLeader reports the not_leader refusal.
func IsNotLeader(err error) bool {
	var we *WireError
	return errors.As(err, &we) && we.Code == CodeNotLeader
}

// Handler serves one method's body.
type Handler func(ctx context.Context, body json.RawMessage) (json.RawMessage, error)

// Typed adapts a typed function to a Handler.
func Typed[In, Out any](fn func(ctx context.Context, in In) (Out, error)) Handler {
	return func(ctx context.Context, body json.RawMessage) (json.RawMessage, error) {
		var in In
		if len(body) > 0 {
			dec := json.NewDecoder(bytes.NewReader(body))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&in); err != nil {
				return nil, &WireError{Code: CodeBadRequest, Message: "body does not decode"}
			}
		}
		out, err := fn(ctx, in)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	}
}

type requestIDKey struct{}

// RequestIDFrom returns the request ID of a leader call, for a store that
// records it to stay idempotent across a leader change.
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// NewRequestID returns a random request ID.
func NewRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Server serves leader calls. IsLeader gates every call.
type Server struct {
	IsLeader func() bool
	// Now replaces the clock (tests).
	Now func() time.Time

	mu       sync.Mutex
	handlers map[string]Handler
	done     map[string]*idemEntry
}

type idemEntry struct {
	ready  chan struct{}
	resp   Response
	status int
	at     time.Time
}

// Handle registers fn for method.
func (s *Server) Handle(method string, fn Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handlers == nil {
		s.handlers = map[string]Handler{}
	}
	s.handlers[method] = fn
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, PathPrefix) {
		writeWire(w, http.StatusNotFound, Response{Error: &WireError{Code: CodeUnknownMethod, Message: "not found"}})
		return
	}
	method := strings.TrimPrefix(r.URL.Path, PathPrefix)
	s.mu.Lock()
	h, ok := s.handlers[method]
	s.mu.Unlock()
	if !ok {
		writeWire(w, http.StatusNotFound, Response{Error: &WireError{Code: CodeUnknownMethod, Message: "unknown method"}})
		return
	}
	if s.IsLeader == nil || !s.IsLeader() {
		writeWire(w, http.StatusServiceUnavailable, Response{Error: &WireError{Code: CodeNotLeader, Message: "this replica is not the leader"}})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil || len(raw) > maxBodyBytes {
		writeWire(w, http.StatusRequestEntityTooLarge, Response{Error: &WireError{Code: CodeBadRequest, Message: "body too large"}})
		return
	}
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil || !requestIDRE.MatchString(req.RequestID) {
		writeWire(w, http.StatusBadRequest, Response{Error: &WireError{Code: CodeBadRequest, Message: "request_id and body are required"}})
		return
	}
	key := method + "\x00" + req.RequestID
	entry, first := s.claim(key)
	if !first {
		select {
		case <-entry.ready:
			writeWire(w, entry.status, entry.resp)
		case <-r.Context().Done():
		}
		return
	}
	ctx := context.WithValue(r.Context(), requestIDKey{}, req.RequestID)
	body, err := h(ctx, req.Body)
	status, resp := http.StatusOK, Response{Body: body}
	if err != nil {
		var we *WireError
		if !errors.As(err, &we) {
			we = &WireError{Code: CodeInternal, Message: "the leader could not complete the call"}
		}
		resp = Response{Error: we}
		status = statusOf(we.Code)
	}
	s.finish(key, entry, status, resp)
	writeWire(w, status, resp)
}

func statusOf(code string) int {
	switch code {
	case CodeBadRequest:
		return http.StatusBadRequest
	case CodeNotLeader, CodeUnavailable:
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}

func (s *Server) claim(key string) (*idemEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done == nil {
		s.done = map[string]*idemEntry{}
	}
	now := s.now()
	if e, ok := s.done[key]; ok && (e.at.IsZero() || now.Sub(e.at) < IdempotencyTTL) {
		return e, false
	}
	if len(s.done) >= maxIdempotent {
		for k, e := range s.done {
			if !e.at.IsZero() && now.Sub(e.at) >= IdempotencyTTL {
				delete(s.done, k)
			}
		}
	}
	e := &idemEntry{ready: make(chan struct{})}
	s.done[key] = e
	return e, true
}

func (s *Server) finish(key string, e *idemEntry, status int, resp Response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.status, e.resp, e.at = status, resp, s.now()
	if status >= 500 {
		// A failure is not an answer to replay: a retry runs again.
		delete(s.done, key)
	}
	close(e.ready)
}

func writeWire(w http.ResponseWriter, status int, resp Response) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// Client calls the leader.
type Client struct {
	// BaseURL is https://<leader service>:<port>.
	BaseURL string
	HTTP    *http.Client
	// Retry bounds how long a call keeps retrying not_leader and transport
	// failures (a leader change takes about 30 s). Zero is 45 s.
	Retry time.Duration
}

// Call sends one call and decodes its answer into out (may be nil). The
// same request ID is used on every retry. ctx bounds the whole call.
func (c *Client) Call(ctx context.Context, method, requestID string, in, out any) error {
	if requestID == "" {
		requestID = NewRequestID()
	}
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(Request{RequestID: requestID, Body: body})
	retry := c.Retry
	if retry <= 0 {
		retry = 45 * time.Second
	}
	deadline := time.Now().Add(retry)
	backoff := 100 * time.Millisecond
	for {
		resp, err := c.once(ctx, method, payload)
		if err == nil && resp.Error == nil {
			if out != nil && len(resp.Body) > 0 {
				return json.Unmarshal(resp.Body, out)
			}
			return nil
		}
		if err == nil {
			err = resp.Error
		}
		retryable := IsNotLeader(err) || isTransport(err)
		if !retryable || time.Now().Add(backoff).After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
}

type transportError struct{ err error }

func (e *transportError) Error() string { return "leader: transport: " + e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

func isTransport(err error) bool {
	var te *transportError
	var we *WireError
	return errors.As(err, &te) || (errors.As(err, &we) && we.Code == CodeUnavailable)
}

func (c *Client) once(ctx context.Context, method string, payload []byte) (Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+PathPrefix+method, bytes.NewReader(payload))
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		return Response{}, errors.New("leader: client has no HTTP client")
	}
	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, &transportError{err: err}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return Response{}, &transportError{err: err}
	}
	var out Response
	if err := json.Unmarshal(raw, &out); err != nil {
		if resp.StatusCode >= 500 {
			return Response{}, &transportError{err: fmt.Errorf("status %d", resp.StatusCode)}
		}
		return Response{}, fmt.Errorf("leader: answer does not decode (status %d)", resp.StatusCode)
	}
	if out.Error == nil && resp.StatusCode != http.StatusOK {
		out.Error = &WireError{Code: CodeInternal, Message: fmt.Sprintf("status %d", resp.StatusCode)}
	}
	return out, nil
}
