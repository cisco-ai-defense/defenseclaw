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
	"container/list"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
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
	// MethodRegistrationLookup answers the callout's name lookup: the UID,
	// profile and attendance of an actor's newest incarnation (GAP-0090).
	MethodRegistrationLookup = "RegistrationLookup"
	// MethodActivityObserve carries a gateway replica's batch of last
	// activity per actor; MethodActivitySnapshot answers the controller's
	// idle check (internal/substrate/activity).
	MethodActivityObserve  = "ActivityObserve"
	MethodActivitySnapshot = "ActivitySnapshot"
	// MethodCalloutPublish carries the controller's read of Substrate's
	// egress callout slot; MethodCalloutStatus answers it to gateway
	// replicas, which may not read the slot themselves (GAP-0505).
	MethodCalloutPublish = "CalloutPublish"
	MethodCalloutStatus  = "CalloutStatus"
	// MethodRevocationPut adds an ended sign-in to the leader's list and
	// MethodRevocationSince is a replica's pull of it
	// (internal/substrate/revocation, B5.1).
	MethodRevocationPut   = "RevocationPut"
	MethodRevocationSince = "RevocationSince"
	// MethodRelayCertClaim, MethodRelayCertClear and MethodRelayCertGet
	// keep the live relay serving certificate per actor (GAP-0861): every
	// gateway replica checks a certificate request without proof of the
	// live key, a renewal (GAP-0928) and an attach against the same record.
	MethodRelayCertClaim = "RelayCertClaim"
	MethodRelayCertClear = "RelayCertClear"
	MethodRelayCertGet   = "RelayCertGet"
)

// Methods lists every method a leader serves.
var Methods = []string{
	MethodChainObserve, MethodIntentGet, MethodIntentPut,
	MethodAskOpen, MethodAskResolve, MethodRegistrationWrite,
	MethodRegistrationGet, MethodRegistrationList, MethodRegistrationLookup,
	MethodActivityObserve, MethodActivitySnapshot,
	MethodCalloutPublish, MethodCalloutStatus,
	MethodRevocationPut, MethodRevocationSince,
	MethodRelayCertClaim, MethodRelayCertClear, MethodRelayCertGet,
}

// Error codes.
const (
	CodeNotLeader     = "not_leader"
	CodeBadRequest    = "bad_request"
	CodeUnknownMethod = "unknown_method"
	CodeInternal      = "internal"
	CodeUnavailable   = "unavailable"
	CodeForbidden     = "forbidden"
)

// PathPrefix is the route prefix of leader calls.
const PathPrefix = "/leader/v1/"

const (
	maxBodyBytes = 4 << 20
	// IdempotencyTTL is how long an answer is replayed to a retry.
	IdempotencyTTL = 10 * time.Minute
	// maxIdempotent bounds the replay cache's answers in number, and
	// maxIdempotentBytes in size (GAP-0404): past either, the oldest
	// finished answers leave first and a retry of one runs again (GAP-0057).
	maxIdempotent      = 200000
	maxIdempotentBytes = 64 << 20
	// idemEntryOverhead is what one kept answer costs besides its key and
	// body (the map entry, the entry, the list element).
	idemEntryOverhead = 256
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

// MessageUndecodable is the bad_request message of a body the method's
// strict decoder refuses, for example a field this leader's version does not
// know.
const MessageUndecodable = "body does not decode"

// IsUndecodable reports a leader's refusal of a body it could not decode.
// A follower newer than its leader sees it when it sends a field the leader
// does not know yet (GAP-0943).
func IsUndecodable(err error) bool {
	var we *WireError
	return errors.As(err, &we) && we.Code == CodeBadRequest && we.Message == MessageUndecodable
}

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
				return nil, &WireError{Code: CodeBadRequest, Message: MessageUndecodable}
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

// Permissions maps a peer identity (the SPIFFE ID in its verified mTLS
// certificate) to the methods it may call; "*" is every method except the
// NamedOnly ones (GAP-0094, GAP-0553).
type Permissions map[string][]string

// NamedOnly are the methods only one role may call, so "*" does not grant
// them: an identity calls one only if it is named for it. The controller
// alone publishes its read of the egress callout slot; a gateway replica
// that could publish would tell every replica the slot is DefenseClaw's
// (GAP-0553).
var NamedOnly = map[string]bool{MethodCalloutPublish: true}

// Allows reports whether peer may call method.
func (p Permissions) Allows(peer, method string) bool {
	for _, m := range p[peer] {
		if m == method || m == "*" && !NamedOnly[method] {
			return true
		}
	}
	return false
}

// Peers lists every identity with a permission (the TLS allowlist).
func (p Permissions) Peers() []string {
	out := make([]string, 0, len(p))
	for id := range p {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// PeerID is the first URI SAN of the verified client certificate of r, ""
// without one. The TLS layer (podcert) has already checked the chain and
// that the identity is on the allowlist.
func PeerID(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	for _, u := range r.TLS.PeerCertificates[0].URIs {
		return u.String()
	}
	return ""
}

// Server serves leader calls. IsLeader gates every call.
type Server struct {
	IsLeader func() bool
	// Permit, when set, limits each peer identity to its methods; a call
	// without a verified identity, or for a method its identity lacks, is
	// refused (403 forbidden). Nil checks nothing (tests, plain HTTP).
	Permit Permissions
	// Now replaces the clock (tests).
	Now func() time.Time

	mu       sync.Mutex
	handlers map[string]Handler
	// reads are methods without side effects: their answers are not kept
	// for replay (GAP-0057).
	reads map[string]bool
	done  map[string]*idemEntry
	// finished is the kept answers, oldest first, and doneBytes their size.
	// Every call prunes the front: an answer leaves at IdempotencyTTL, or
	// earlier past maxIdempotentBytes. Before, an expired answer stayed
	// until the map held 200,000 of them, so the leader kept every hook
	// call's answer (about 2 KiB to 10 KiB each, 5 calls per tool call) and
	// gave nothing back while it ran (GAP-0404).
	finished  list.List
	doneBytes int64
}

type idemEntry struct {
	ready  chan struct{}
	resp   Response
	status int
	at     time.Time
	// key, size and elem: the entry's place in finished (nil while it runs).
	key  string
	size int64
	elem *list.Element
}

// Handle registers fn for method.
func (s *Server) Handle(method string, fn Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handlers == nil {
		s.handlers = map[string]Handler{}
	}
	s.handlers[method] = fn
	delete(s.reads, method)
}

// HandleRead registers fn for a method without side effects. Its answers
// are not kept for replay: a retry simply reads again.
func (s *Server) HandleRead(method string, fn Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handlers == nil {
		s.handlers = map[string]Handler{}
	}
	if s.reads == nil {
		s.reads = map[string]bool{}
	}
	s.handlers[method] = fn
	s.reads[method] = true
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
	read := s.reads[method]
	s.mu.Unlock()
	if !ok {
		writeWire(w, http.StatusNotFound, Response{Error: &WireError{Code: CodeUnknownMethod, Message: "unknown method"}})
		return
	}
	if s.Permit != nil && !s.Permit.Allows(PeerID(r), method) {
		writeWire(w, http.StatusForbidden, Response{Error: &WireError{Code: CodeForbidden, Message: "this peer may not call the method"}})
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
	if read {
		ctx := context.WithValue(r.Context(), requestIDKey{}, req.RequestID)
		body, err := h(ctx, req.Body)
		status, resp := http.StatusOK, Response{Body: body}
		if err != nil {
			var we *WireError
			if !errors.As(err, &we) {
				we = &WireError{Code: CodeInternal, Message: "the leader could not complete the call"}
			}
			resp, status = Response{Error: we}, statusOf(we.Code)
		}
		writeWire(w, status, resp)
		return
	}
	key := method + "\x00" + req.RequestID
	entry, first := s.claim(key)
	if entry == nil {
		writeWire(w, http.StatusServiceUnavailable, Response{Error: &WireError{Code: CodeUnavailable, Message: "the leader is busy"}})
		return
	}
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
	case CodeForbidden:
		return http.StatusForbidden
	case "not_found":
		return http.StatusNotFound
	case "decided":
		return http.StatusConflict
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
	s.pruneLocked(now)
	if e, ok := s.done[key]; ok && (e.at.IsZero() || now.Sub(e.at) < IdempotencyTTL) {
		return e, false
	}
	if len(s.done) >= maxIdempotent {
		for k, e := range s.done {
			if !e.at.IsZero() && now.Sub(e.at) >= IdempotencyTTL {
				s.dropLocked(k, e)
			}
		}
	}
	if len(s.done) >= maxIdempotent {
		// Still full of fresh answers: drop finished ones until there is
		// room (a retry after that runs again), so the map never grows past
		// its cap (GAP-0057).
		for k, e := range s.done {
			if len(s.done) < maxIdempotent*9/10 {
				break
			}
			if !e.at.IsZero() {
				s.dropLocked(k, e)
			}
		}
		if len(s.done) >= maxIdempotent {
			return nil, false // every entry is in flight
		}
	}
	e := &idemEntry{ready: make(chan struct{})}
	s.done[key] = e
	return e, true
}

// pruneLocked drops the kept answers past IdempotencyTTL, oldest first, and
// the oldest past maxIdempotentBytes.
func (s *Server) pruneLocked(now time.Time) {
	for f := s.finished.Front(); f != nil; f = s.finished.Front() {
		e := f.Value.(*idemEntry)
		if now.Sub(e.at) < IdempotencyTTL && s.doneBytes <= maxIdempotentBytes {
			return
		}
		s.dropLocked(e.key, e)
	}
}

// dropLocked forgets the answer e kept under key.
func (s *Server) dropLocked(key string, e *idemEntry) {
	if e.elem != nil {
		s.finished.Remove(e.elem)
		e.elem = nil
		s.doneBytes -= e.size
	}
	if s.done[key] == e {
		delete(s.done, key)
	}
}

func (s *Server) finish(key string, e *idemEntry, status int, resp Response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.status, e.resp, e.at = status, resp, s.now()
	switch {
	case status >= 500:
		// A failure is not an answer to replay: a retry runs again.
		delete(s.done, key)
	case s.done[key] == e:
		e.key, e.size = key, int64(len(key)+len(resp.Body)+idemEntryOverhead)
		if resp.Error != nil {
			e.size += int64(len(resp.Error.Code) + len(resp.Error.Message))
		}
		e.elem = s.finished.PushBack(e)
		s.doneBytes += e.size
		s.pruneLocked(e.at)
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

type noRetryKey struct{}

// WithoutRetry makes every Call under ctx a single attempt: a best-effort
// read (the agent activity of list and status, GAP-1018) fails at once on a
// leader that cannot be reached instead of retrying until ctx ends.
func WithoutRetry(ctx context.Context) context.Context {
	return context.WithValue(ctx, noRetryKey{}, true)
}

// Call sends one call and decodes its answer into out (may be nil). The
// same request ID is used on every retry. ctx bounds the whole call; under
// WithoutRetry there is no retry.
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
	single := ctx.Value(noRetryKey{}) != nil
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
		if !retryable || single || time.Now().Add(backoff).After(deadline) {
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
