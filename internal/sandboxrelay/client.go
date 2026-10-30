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

package sandboxrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	pathpkg "path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Client defaults.
const (
	// DefaultCallTimeout bounds one call to the managed gateway. A relayed
	// hook may wait on a judge or an approval, so it is generous; the
	// sandbox's own hook deadline is the tighter bound in practice.
	DefaultCallTimeout = 2 * time.Minute
	// IdleConnections is the keep-alive pool to the hook socket. Concurrency
	// is bounded by the gateway's in-flight caps, not by the pool.
	IdleConnections = 4
	// MaxRelayResponseBytes bounds a relayed call's answer body.
	MaxRelayResponseBytes = 4 << 20
	// maxJSONResponseBytes bounds every other answer body.
	maxJSONResponseBytes = 4 << 20
	// maxErrorBodyBytes bounds a non-2xx answer the client decodes.
	maxErrorBodyBytes = 64 << 10
)

// ClientOptions configure NewClient.
type ClientOptions struct {
	// SocketPath is the managed gateway's hook socket
	// (managed.StandaloneLayoutFor(goos).HookSocketPath). Absolute and clean.
	SocketPath string
	// TrustedOwners are the uids besides root that may own the socket and
	// its directory: the managed gateway's service account.
	TrustedOwners []int
	// Timeout bounds one call; zero uses DefaultCallTimeout.
	Timeout time.Duration
}

// UnixClient is the Client over the managed gateway's hook socket. Before
// the first dial and on every redial it checks that the socket's directory
// is a real directory owned by root or a trusted owner and writable by no
// one else, and that the socket itself belongs to root or a trusted owner:
// no other local account can have planted a listener there.
type UnixClient struct {
	socket    string
	trusted   []int
	http      *http.Client
	transport *http.Transport
}

var _ Client = (*UnixClient)(nil)

// NewClient checks the hook socket and returns a client over it. An
// untrusted socket returns an error wrapping ErrSocketUntrusted.
func NewClient(opts ClientOptions) (*UnixClient, error) {
	if err := CheckSocket(opts.SocketPath, opts.TrustedOwners); err != nil {
		return nil, err
	}
	trusted := append([]int(nil), opts.TrustedOwners...)
	path := opts.SocketPath
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if err := CheckSocket(path, trusted); err != nil {
				return nil, err
			}
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
		MaxIdleConns:          IdleConnections,
		MaxIdleConnsPerHost:   IdleConnections,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0,
		DisableCompression:    true,
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultCallTimeout
	}
	return &UnixClient{
		socket:    path,
		trusted:   trusted,
		transport: transport,
		http:      &http.Client{Transport: transport, Timeout: timeout},
	}, nil
}

// CheckSocket is the daemon's check of the hook socket at path (B2): the
// directory is a real directory owned by root or one of trustedOwners and
// not group- or world-writable, and the socket is a socket owned by root
// or one of trustedOwners. Failures wrap ErrSocketUntrusted.
func CheckSocket(path string, trustedOwners []int) error {
	if path == "" || !strings.HasPrefix(path, "/") || pathpkg.Clean(path) != path {
		return fmt.Errorf("%w: hook socket path %q is not absolute and clean", ErrSocketUntrusted, path)
	}
	return checkSocketOwner(path, append([]int{0}, trustedOwners...))
}

// Close releases the idle connections.
func (c *UnixClient) Close() error {
	c.transport.CloseIdleConnections()
	return nil
}

// Settings is GET settings.
func (c *UnixClient) Settings(ctx context.Context) (DaemonSettings, error) {
	var out DaemonSettings
	err := c.call(ctx, http.MethodGet, PathSettings, nil, nil, nil, &out)
	return out, err
}

// Resolve is POST policy/resolve; req.Connector is the connector claim.
func (c *UnixClient) Resolve(ctx context.Context, req ResolveRequest) (ResolveResponse, error) {
	req.V = WireVersion
	if len(req.RepoOverlay) > MaxRepoOverlayBytes {
		return ResolveResponse{}, &InvalidRequestError{Message: fmt.Sprintf("the repository policy is larger than %d bytes", MaxRepoOverlayBytes)}
	}
	if len(req.UserPack) > MaxUserPackBytes {
		return ResolveResponse{}, &InvalidRequestError{Message: fmt.Sprintf("the pack is larger than %d bytes", MaxUserPackBytes)}
	}
	header := http.Header{}
	header.Set(ConnectorHeader, req.Connector)
	var out ResolveResponse
	err := c.call(ctx, http.MethodPost, PathPolicyResolve, nil, header, req, &out)
	return out, err
}

// Bind is POST registrations/{id}/bind.
func (c *UnixClient) Bind(ctx context.Context, registration string, req BindRequest) (RegistrationView, error) {
	if err := validRegistration(registration); err != nil {
		return RegistrationView{}, err
	}
	req.V = WireVersion
	var out RegistrationView
	err := c.call(ctx, http.MethodPost, PathRegistrations+url.PathEscape(registration)+RegistrationBindSub, nil, nil, req, &out)
	return out, err
}

// Deleted is POST registrations/{id}/deleted.
func (c *UnixClient) Deleted(ctx context.Context, registration string) error {
	if err := validRegistration(registration); err != nil {
		return err
	}
	body := struct {
		V int `json:"v"`
	}{WireVersion}
	return c.call(ctx, http.MethodPost, PathRegistrations+url.PathEscape(registration)+RegistrationDelSub, nil, nil, body, nil)
}

// Report is POST registrations/{id}/state: whether the registration's
// sandbox runs now, answered like policy/current.
func (c *UnixClient) Report(ctx context.Context, registration string, running bool) (CurrentPolicy, error) {
	if err := validRegistration(registration); err != nil {
		return CurrentPolicy{}, err
	}
	var out CurrentPolicy
	err := c.call(ctx, http.MethodPost, PathRegistrations+url.PathEscape(registration)+RegistrationStateSub, nil, nil,
		StateReport{V: WireVersion, Running: running}, &out)
	return out, err
}

// Restart is POST registrations/{id}/restart: the registration's sandbox
// starts again under the new registration it answers.
func (c *UnixClient) Restart(ctx context.Context, registration string) (RegistrationView, error) {
	if err := validRegistration(registration); err != nil {
		return RegistrationView{}, err
	}
	body := struct {
		V int `json:"v"`
	}{WireVersion}
	var out RegistrationView
	err := c.call(ctx, http.MethodPost, PathRegistrations+url.PathEscape(registration)+RegistrationRestartSub, nil, nil, body, &out)
	return out, err
}

// Current is GET policy/current.
func (c *UnixClient) Current(ctx context.Context, registration string) (CurrentPolicy, error) {
	if err := validRegistration(registration); err != nil {
		return CurrentPolicy{}, err
	}
	var out CurrentPolicy
	err := c.call(ctx, http.MethodGet, PathPolicyCurrent, url.Values{RegistrationQuery: {registration}}, nil, nil, &out)
	return out, err
}

// Explain is POST policy/explain.
func (c *UnixClient) Explain(ctx context.Context, req ExplainRequest) (sandboxapi.ManagedExplain, error) {
	req.V = WireVersion
	var out sandboxapi.ManagedExplain
	err := c.call(ctx, http.MethodPost, PathPolicyExplain, nil, nil, req, &out)
	return out, err
}

// PolicyTest is POST policy/test: for the registration's sandbox, or
// without one for a new run of the connector.
func (c *UnixClient) PolicyTest(ctx context.Context, req PolicyTestRequest) (sandboxapi.PolicyTestResult, error) {
	if req.Registration == "" && req.Connector == "" {
		return sandboxapi.PolicyTestResult{}, errors.New("sandboxrelay: a policy test names a registration or a connector")
	}
	header, err := packScope(req.Registration, req.Connector)
	if err != nil {
		return sandboxapi.PolicyTestResult{}, err
	}
	req.V = WireVersion
	var out sandboxapi.PolicyTestResult
	err = c.call(ctx, http.MethodPost, PathPolicyTest, nil, header, req, &out)
	return out, err
}

// Packs is GET policy/packs.
func (c *UnixClient) Packs(ctx context.Context, registration, connector string) ([]PackView, error) {
	header, err := packScope(registration, connector)
	if err != nil {
		return nil, err
	}
	var out []PackView
	err = c.call(ctx, http.MethodGet, PathPolicyPacks, nil, header, nil, &out)
	return out, err
}

// Pack is GET policy/packs/{name}.
func (c *UnixClient) Pack(ctx context.Context, registration, connector, name string) (PackView, error) {
	if name == "" || strings.ContainsAny(name, "/\\") {
		return PackView{}, &InvalidRequestError{Message: fmt.Sprintf("%s is not a pack name; `defenseclaw sandbox pack list` shows the packs",
			strconv.Quote(sandboxapi.DisplayText(truncateName(name))))}
	}
	header, err := packScope(registration, connector)
	if err != nil {
		return PackView{}, err
	}
	var out PackView
	err = c.call(ctx, http.MethodGet, PathPolicyPacks+"/"+url.PathEscape(name), nil, header, nil, &out)
	return out, err
}

// truncateName bounds a caller's text echoed in a message.
func truncateName(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}

// packScope is the scope of a packs call, in the headers the gateway reads
// it from: the registration of one of the caller's sandboxes, or the
// connector claim of a new run (GAP-0181).
func packScope(registration, connector string) (http.Header, error) {
	header := http.Header{}
	if registration != "" {
		if err := validRegistration(registration); err != nil {
			return nil, err
		}
		header.Set(RegistrationHeader, registration)
	}
	if connector != "" {
		header.Set(ConnectorHeader, connector)
	}
	return header, nil
}

// Decide is POST decisions.
func (c *UnixClient) Decide(ctx context.Context, req DecisionRequest) (DecisionResult, error) {
	if err := validRegistration(req.Registration); err != nil {
		return DecisionResult{}, err
	}
	req.V = WireVersion
	var out DecisionResult
	err := c.call(ctx, http.MethodPost, PathDecisions, nil, nil, req, &out)
	return out, err
}

// Decisions is GET decisions.
func (c *UnixClient) Decisions(ctx context.Context, registration string) ([]Decision, error) {
	if err := validRegistration(registration); err != nil {
		return nil, err
	}
	var out []Decision
	err := c.call(ctx, http.MethodGet, PathDecisions, url.Values{RegistrationQuery: {registration}}, nil, nil, &out)
	return out, err
}

// Events is POST events. A batch without a registration holds only the kinds
// EventWithoutRegistration names.
func (c *UnixClient) Events(ctx context.Context, batch EventBatch) error {
	if batch.Registration == "" {
		for _, ev := range batch.Events {
			if !EventWithoutRegistration(ev.Kind) {
				return fmt.Errorf("sandboxrelay: a %s record needs a registration", ev.Kind)
			}
		}
	} else if err := validRegistration(batch.Registration); err != nil {
		return err
	}
	if len(batch.Events) > MaxEventBatchRecords {
		return fmt.Errorf("sandboxrelay: an event batch holds at most %d records", MaxEventBatchRecords)
	}
	batch.V = WireVersion
	raw, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("sandboxrelay: encode events: %w", err)
	}
	if len(raw) > MaxEventBatchBytes {
		return fmt.Errorf("sandboxrelay: an event batch is at most %d bytes", MaxEventBatchBytes)
	}
	return c.call(ctx, http.MethodPost, PathEvents, nil, nil, json.RawMessage(raw), nil)
}

// connectorTarget is a connector name in a relayed path.
var connectorTarget = lazyregexp.New(`^[a-z][a-z0-9-]{0,31}$`)

// inspectTargets are the inspect kinds of a relayed inspect call.
var inspectTargets = map[string]bool{"tool": true, "request": true, "response": true, "tool-response": true}

// RelayPath is the hook-socket route of a relayed call.
func RelayPath(class RouteClass, target string) (string, error) {
	switch class {
	case RouteHook:
		if connectorTarget.MatchString(target) {
			return PathHookPrefix + target, nil
		}
	case RouteNotify:
		if connectorTarget.MatchString(target) {
			return PathNotifyPrefix + target, nil
		}
	case RouteInspect:
		if inspectTargets[target] {
			return PathInspectPrefix + target, nil
		}
	default:
		return "", fmt.Errorf("sandboxrelay: route class %q is not relayed", class)
	}
	return "", fmt.Errorf("sandboxrelay: invalid %s target %q", class, target)
}

// ForwardedHeader returns the request headers a relayed call sends: only
// the ForwardHeaders allowlist copied out of in, then the headers the relay
// sets itself (RegistrationHeader, ClientHeader, AgentSurfaceHeader,
// DaemonContractHeader). Anything else the sandbox sent (its bearer, identity, session facts,
// request ids, any X-DefenseClaw-Sandbox-* header) is dropped. The
// allowlisted headers are at most MaxForwardHeaderBytes in total, or
// ErrHeadersTooLarge.
func ForwardedHeader(in http.Header, registration string) (http.Header, error) {
	out := http.Header{}
	size := 0
	for _, name := range ForwardHeaders {
		for _, value := range in.Values(name) {
			size += len(name) + len(value) + len(": \r\n")
			out.Add(name, value)
		}
	}
	if size > MaxForwardHeaderBytes {
		return nil, ErrHeadersTooLarge
	}
	out.Set(RegistrationHeader, registration)
	out.Set(ClientHeader, ClientHeaderValue)
	out.Set(AgentSurfaceHeader, AgentSurfaceValue)
	out.Set(DaemonContractHeader, daemonContractValue)
	return out, nil
}

// Relay forwards one hook, notify or inspect call: the body unchanged, only
// the allowlisted headers. The gateway's answer comes back unchanged as a
// RelayResponse whatever its status; an error means the call could not be
// made or its answer could not be read, and fails the hook closed.
func (c *UnixClient) Relay(ctx context.Context, call RelayCall) (RelayResponse, error) {
	if err := validRegistration(call.Registration); err != nil {
		return RelayResponse{}, err
	}
	path, err := RelayPath(call.Class, call.Target)
	if err != nil {
		return RelayResponse{}, err
	}
	header, err := ForwardedHeader(call.Header, call.Registration)
	if err != nil {
		return RelayResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://managed-gateway"+path, bytes.NewReader(call.Body))
	if err != nil {
		return RelayResponse{}, fmt.Errorf("sandboxrelay: build request: %w", err)
	}
	if call.Class == RouteHook {
		if v := EncodeEgressRefusals(call.EgressRefusals); v != "" {
			header.Set(EgressRefusalsHeader, v)
		}
	}
	req.Header = header
	req.ContentLength = int64(len(call.Body))
	resp, err := c.do(req)
	if err != nil {
		return RelayResponse{}, err
	}
	defer resp.Body.Close()
	// Trailers arrive after the body, so read it to its end.
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxRelayResponseBytes+1))
	if err != nil {
		return RelayResponse{}, fmt.Errorf("%w: read the answer: %v", ErrGatewayUnreachable, err)
	}
	if len(body) > MaxRelayResponseBytes {
		return RelayResponse{}, fmt.Errorf("%w: the answer is larger than %d bytes", ErrGatewayUnreachable, MaxRelayResponseBytes)
	}
	out := RelayResponse{Status: resp.StatusCode, Header: http.Header{}, Body: body}
	for _, name := range ResponseHeaders {
		if v := resp.Header.Get(name); v != "" {
			out.Header.Set(name, v)
		}
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		if v := resp.Header.Get("Retry-After"); v != "" {
			out.Header.Set("Retry-After", v)
		}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		out.Decision = ParseHookDecision(resp.Trailer.Get(DecisionTrailer))
	}
	return out, nil
}

// OTLP forwards one OTLP export.
func (c *UnixClient) OTLP(ctx context.Context, call OTLPCall) error {
	if err := validRegistration(call.Registration); err != nil {
		return err
	}
	switch call.Signal {
	case OTLPLogs, OTLPMetrics, OTLPTraces:
	default:
		return fmt.Errorf("sandboxrelay: unknown OTLP signal %q", call.Signal)
	}
	if len(call.Body) > MaxOTLPBodyBytes {
		return fmt.Errorf("sandboxrelay: an OTLP export is at most %d bytes", MaxOTLPBodyBytes)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://managed-gateway"+PathOTLPPrefix+call.Signal, bytes.NewReader(call.Body))
	if err != nil {
		return fmt.Errorf("sandboxrelay: build request: %w", err)
	}
	req.ContentLength = int64(len(call.Body))
	req.Header.Set(RegistrationHeader, call.Registration)
	req.Header.Set(ClientHeader, ClientHeaderValue)
	req.Header.Set(DaemonContractHeader, daemonContractValue)
	if call.ContentType != "" {
		req.Header.Set("Content-Type", call.ContentType)
	}
	if call.ContentEncoding != "" {
		req.Header.Set("Content-Encoding", call.ContentEncoding)
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return decodeError(resp)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBodyBytes))
	return nil
}

// ParseHookDecision decodes a DecisionTrailer value: nil when it is empty,
// larger than MaxHookDecisionBytes, malformed, of another version or
// without an action. Strings are truncated to their bounds.
func ParseHookDecision(raw string) *HookDecision {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MaxHookDecisionBytes {
		return nil
	}
	var d HookDecision
	if err := json.Unmarshal([]byte(raw), &d); err != nil || d.V != WireVersion || d.Action == "" {
		return nil
	}
	for _, s := range []*string{&d.Event, &d.Tool, &d.ToolUseID, &d.SessionID, &d.CallRef, &d.ResultStatus,
		&d.Action, &d.Severity, &d.ModelError} {
		*s = truncateUTF8(*s, MaxHookDecisionStringBytes)
	}
	d.Reason = truncateUTF8(d.Reason, MaxHookDecisionReasonBytes)
	return &d
}

func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// daemonContractValue is DaemonContractHeader's value.
var daemonContractValue = strconv.Itoa(DaemonContract)

// validRegistration refuses an empty or malformed registration id before
// it goes into a header or a path.
func validRegistration(id string) error {
	if id == "" || len(id) > 64 {
		return fmt.Errorf("sandboxrelay: invalid registration id")
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return fmt.Errorf("sandboxrelay: invalid registration id")
		}
	}
	return nil
}

// call sends one JSON request (in nil sends no body on GET and {} on POST)
// and decodes a JSON answer into out (nil discards it).
func (c *UnixClient) call(ctx context.Context, method, path string, query url.Values, header http.Header, in, out any) error {
	u := "http://managed-gateway" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var body io.Reader
	var length int64
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("sandboxrelay: encode %s: %w", path, err)
		}
		if method == http.MethodPost && path == PathPolicyResolve && len(raw) > MaxResolveBytes {
			return fmt.Errorf("sandboxrelay: a policy resolve request is at most %d bytes", MaxResolveBytes)
		}
		body, length = bytes.NewReader(raw), int64(len(raw))
	} else if method != http.MethodGet {
		body, length = strings.NewReader("{}"), 2
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return fmt.Errorf("sandboxrelay: build request: %w", err)
	}
	req.ContentLength = length
	for name, values := range header {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	req.Header.Set(ClientHeader, ClientHeaderValue)
	req.Header.Set(DaemonContractHeader, daemonContractValue)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return decodeError(resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBodyBytes))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJSONResponseBytes)).Decode(out); err != nil {
		return fmt.Errorf("%w: decode %s: %v", ErrGatewayUnreachable, path, err)
	}
	return nil
}

// do sends req; a transport failure wraps ErrSocketUntrusted when the
// socket check refused the dial, else ErrGatewayUnreachable.
func (c *UnixClient) do(req *http.Request) (*http.Response, error) {
	resp, err := c.http.Do(req)
	if err == nil {
		return resp, nil
	}
	if errors.Is(err, ErrSocketUntrusted) {
		return nil, fmt.Errorf("%w (%s)", ErrSocketUntrusted, c.socket)
	}
	return nil, fmt.Errorf("%w: %v", ErrGatewayUnreachable, err)
}

func decodeError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	e := &Error{Status: resp.StatusCode, RetryAfter: resp.Header.Get("Retry-After")}
	var body ErrorBody
	if json.Unmarshal(raw, &body) == nil {
		e.Reason, e.Message = body.Error, body.Message
	}
	return e
}
