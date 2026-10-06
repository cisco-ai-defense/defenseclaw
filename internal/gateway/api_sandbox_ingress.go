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

package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// The sandbox ingress is a second listener, on 127.0.0.1:<ingress_port>,
// that OpenShell sandboxes reach as host.openshell.internal. The
// host-networked OpenShell supervisor relays every sandbox connection, so
// all of it arrives from loopback: loopback therefore grants nothing here.
//
// The listener serves only what a sandboxed harness needs: its connector's
// hook route, the Codex notify bridge, the shared inspect endpoints and
// OTLP-HTTP ingest. Every request must carry a sandbox binding credential
// as "Authorization: Bearer dcsb_..." (OpenShell substitutes the real value
// for the placeholder the workload sees). The master gateway token, the
// connector hook tokens and the OTLP path tokens are never accepted, and a
// binding credential is refused by the main API listener in turn.
//
// Middleware, outermost first:
//
//	authenticate  credential -> binding (401); a credential anywhere but
//	              the Authorization header is refused (400); binding +
//	              FSView into ctx
//	trace, request ID (always minted), correlation (identity from the
//	              binding's host user)
//	authorize     route allowlist and connector match (404/403),
//	              per-binding limiter with separate hook and OTLP
//	              slots (429), in-flight tracking
//	metrics, CSRF, body limit (OTLP far below the host receiver's cap)
//	idempotency   replay of a retried hook post by key
//	mux           hook / notify / inspect / OTLP handlers

const (
	// SandboxHookIdempotencyHeader carries a retry-stable key on sandbox hook
	// posts. OpenShell's relay occasionally drops a response after the
	// gateway processed the request; the hook retries once with the same key
	// and receives the original verdict instead of a second evaluation.
	SandboxHookIdempotencyHeader = "X-DefenseClaw-Hook-Idempotency-Key"
	// sandboxIdempotentReplayHeader marks a replayed response.
	sandboxIdempotentReplayHeader = "X-DefenseClaw-Idempotent-Replay"

	defaultSandboxIdempotencyTTL = 2 * time.Minute
	// defaultSandboxOTLPMaxBodyBytes caps one sandbox OTLP upload. The
	// receiver buffers the whole body before decoding, so with the
	// limiter's OTLP slots this bounds the memory sandbox telemetry can pin.
	// Harness exporters batch far below it.
	defaultSandboxOTLPMaxBodyBytes int64 = 4 << 20
)

// sandboxIngressShutdownTimeout bounds graceful shutdown. A variable so
// tests can shorten it.
var sandboxIngressShutdownTimeout = 5 * time.Second

// sandboxInspectPaths are the inspect endpoints a binding with
// RouteInspect may call.
var sandboxInspectPaths = []string{
	"/api/v1/inspect/tool",
	"/api/v1/inspect/request",
	"/api/v1/inspect/response",
	"/api/v1/inspect/tool-response",
}

// sandboxOTLPPaths are the header-authenticated OTLP-HTTP signal routes. The
// legacy /otlp/<source>/<token>/ path form is not served: it puts a
// credential in the URL and exists only for exporters that cannot set
// headers, which no sandboxed harness needs.
var sandboxOTLPPaths = []string{"/v1/logs", "/v1/metrics", "/v1/traces"}

// sandboxIdentityHeaders are dropped from every sandbox request. Handlers
// that read identity straight from headers must see only what the binding
// establishes.
var sandboxIdentityHeaders = []string{
	llmEventUserIDHeader, llmEventUserNameHeader,
	"X-User-Id", "X-User-ID", "X-User", "X-User-Name", "X-Username",
}

// SandboxIngressConfig configures the sandbox ingress listener. The sidecar
// supplies it from openshell configuration; this package reads no config
// keys itself.
type SandboxIngressConfig struct {
	// Addr is the loopback host:port to listen on, e.g. 127.0.0.1:18971.
	Addr string
	// Bindings authenticates sandbox credentials. Required.
	Bindings sandboxauth.Matcher
	// Limiter bounds each binding. Nil uses sandboxauth defaults.
	Limiter *sandboxauth.Limiter
	// InFlight counts open requests per binding for quiescence-aware policy
	// batching. Nil creates one; SandboxIngressInFlight returns it.
	InFlight *sandboxauth.InFlight
	// IdempotencyTTL is how long a completed hook response stays
	// replayable. Zero uses two minutes.
	IdempotencyTTL time.Duration
	// FS is the host filesystem FSView reads through. Nil uses the OS.
	FS sandboxauth.FS
	// OTLPMaxBodyBytes caps one OTLP upload. Zero uses 4 MiB; it may not
	// exceed the host receiver's cap.
	OTLPMaxBodyBytes int64
	// OnRequest observes every admitted request after authorization, before
	// its handler runs: the sandbox manager's hook-coverage signal. It runs
	// on the request goroutine and must not block.
	OnRequest func(binding sandboxauth.Binding, route sandboxauth.Route)
	// OnHookDecision observes every hook verdict reached for a sandbox
	// binding. It must not block.
	OnHookDecision func(SandboxHookDecision)
	// OnListening is told once RunSandboxIngress holds its socket: until
	// then another program may be the one listening on the ingress port.
	OnListening func()
	// EgressUnblock reports whether the sandbox's egress proxy reaches host
	// because the user unblocked it, and the unblock's scope ("sandbox" or
	// "always"). A sandbox verdict decided only by destination rules for
	// hosts it reports is an allow (liftUnblockedDestinations). Nil lifts
	// nothing. It runs on the request goroutine and must not block.
	EgressUnblock func(binding sandboxauth.Binding, host string) (scope string, ok bool)
	// EgressRefusals returns the destinations the sandbox's egress proxy
	// refused a CONNECT to shortly before, that its agent has not been told
	// of, and marks them told. The post-tool hook of a shell or fetch tool
	// call adds them to its context (addSandboxEgressRefusals): the 403
	// body of a refused CONNECT never reaches the agent. Nil tells nothing.
	// It runs on the request goroutine and must not block.
	EgressRefusals func(binding sandboxauth.Binding) []SandboxEgressRefusal
	// OnHookFailure observes every authenticated hook or inspect post the
	// ingress answered with a status outside 2xx. Sandbox hooks fail closed
	// on such an answer, so the harness did not do what the hook was about.
	// A hook DefenseClaw failed evaluating (a recovered panic) is answered
	// with a block and reported too, with status 500. A replayed answer to
	// a retried post is not reported again. It runs on the request
	// goroutine and must not block.
	OnHookFailure func(SandboxHookFailure)
}

// SandboxHookDecision is one hook verdict for a sandbox binding.
type SandboxHookDecision struct {
	BindingID   string
	SandboxName string
	Connector   string
	// Event is the harness hook event; Tool the tool it concerns.
	Event string
	Tool  string
	// ToolUseID is the harness's per-call ID (Claude Code, Codex and Cursor
	// tool_use_id, OpenCode callID, Amp toolUseID): it pairs a call's
	// pre-tool event with its post-tool event.
	ToolUseID string
	// SessionID and ToolInput are the call's session and tool input (empty
	// when the event carries none). They name a call whose hooks send no
	// per-call ID the gateway reads (Kiro CLI, Copilot CLI, Devin CLI).
	SessionID string
	ToolInput json.RawMessage
	// ResultStatus is the status field a post-tool event reports (Amp's
	// tool.result: done, error or cancelled).
	ResultStatus string
	// Action is the verdict (allow, block, alert, confirm).
	Action     string
	WouldBlock bool
	Severity   string
	// Reason is the plain reason the agent was given (see
	// sandboxVerdictReason): rule metadata, never matched content.
	Reason string
}

// SandboxHookFailure is one authenticated sandbox hook or inspect post the
// ingress answered with an error status.
type SandboxHookFailure struct {
	BindingID   string
	SandboxName string
	Connector   string
	// Route is the route class of the post (hook or inspect).
	Route sandboxauth.Route
	// Status is the HTTP status of the answer, or 500 for a hook
	// DefenseClaw failed evaluating and answered with a fail-closed block.
	Status int
}

type sandboxIngressState struct {
	addr     string
	bindings sandboxauth.Matcher
	limiter  *sandboxauth.Limiter
	inFlight *sandboxauth.InFlight
	idem     *hookIdempotencyCache
	fs       sandboxauth.FS
	// otlpMaxBytes is the OTLP request body cap.
	otlpMaxBytes int64
	// onRequest, onHookDecision and onHookFailure are the manager's
	// observers.
	onRequest      func(sandboxauth.Binding, sandboxauth.Route)
	onHookDecision func(SandboxHookDecision)
	onListening    func()
	onHookFailure  func(SandboxHookFailure)
	// egressUnblock is the manager's unblock lookup
	// (SandboxIngressConfig.EgressUnblock).
	egressUnblock func(sandboxauth.Binding, string) (string, bool)
	// egressRefusals is the manager's refusal lookup
	// (SandboxIngressConfig.EgressRefusals).
	egressRefusals func(sandboxauth.Binding) []SandboxEgressRefusal
	// authFailures bounds auth-failure telemetry. Every sandbox shares one
	// source address, so a flood of bad credentials cannot be told apart
	// per caller; it still gets 401, just not one event per request.
	authFailures *rate.Limiter

	handlerOnce sync.Once
	handler     http.Handler
}

// SetSandboxIngress configures (or, with a zero config, removes) the
// sandbox ingress listener. It validates the address and binding source
// but opens no socket; RunSandboxIngress does.
func (a *APIServer) SetSandboxIngress(cfg SandboxIngressConfig) error {
	if a == nil {
		return errors.New("sandbox ingress: nil API server")
	}
	if cfg.Addr == "" && cfg.Bindings == nil {
		a.sandboxIngressMu.Lock()
		a.sandboxIngress = nil
		a.sandboxIngressMu.Unlock()
		return nil
	}
	if cfg.Bindings == nil {
		return errors.New("sandbox ingress: a binding store is required")
	}
	if err := validateSandboxIngressAddr(cfg.Addr, a.addr); err != nil {
		return err
	}
	otlpMaxBytes := cfg.OTLPMaxBodyBytes
	switch {
	case otlpMaxBytes == 0:
		otlpMaxBytes = defaultSandboxOTLPMaxBodyBytes
	case otlpMaxBytes < 0 || otlpMaxBytes > otlpRequestBodyMaxBytes:
		return fmt.Errorf("sandbox ingress: OTLP body cap must be between 1 and %d bytes", otlpRequestBodyMaxBytes)
	}
	st := &sandboxIngressState{
		addr:           cfg.Addr,
		bindings:       cfg.Bindings,
		limiter:        cfg.Limiter,
		inFlight:       cfg.InFlight,
		fs:             cfg.FS,
		otlpMaxBytes:   otlpMaxBytes,
		authFailures:   rate.NewLimiter(10, 20),
		onRequest:      cfg.OnRequest,
		onHookDecision: cfg.OnHookDecision,
		onListening:    cfg.OnListening,
		onHookFailure:  cfg.OnHookFailure,
		egressUnblock:  cfg.EgressUnblock,
		egressRefusals: cfg.EgressRefusals,
	}
	if st.limiter == nil {
		st.limiter = sandboxauth.NewLimiter(sandboxauth.DefaultLimiterConfig())
	}
	if st.inFlight == nil {
		st.inFlight = sandboxauth.NewInFlight(nil)
	}
	ttl := cfg.IdempotencyTTL
	if ttl <= 0 {
		ttl = defaultSandboxIdempotencyTTL
	}
	st.idem = newHookIdempotencyCache(ttl, nil)
	a.sandboxIngressMu.Lock()
	a.sandboxIngress = st
	a.sandboxIngressMu.Unlock()
	return nil
}

// SandboxIngressAddr returns the configured ingress address, or "".
func (a *APIServer) SandboxIngressAddr() string {
	if st := a.sandboxIngressState(); st != nil {
		return st.addr
	}
	return ""
}

// SandboxIngressInFlight returns the in-flight tracker the ingress updates,
// or nil when the ingress is not configured.
func (a *APIServer) SandboxIngressInFlight() *sandboxauth.InFlight {
	if st := a.sandboxIngressState(); st != nil {
		return st.inFlight
	}
	return nil
}

// ForgetSandboxBinding drops per-binding limiter, in-flight and
// idempotency state after the binding is revoked.
func (a *APIServer) ForgetSandboxBinding(bindingID string) {
	st := a.sandboxIngressState()
	if st == nil {
		return
	}
	st.limiter.Forget(bindingID)
	st.inFlight.Forget(bindingID)
	st.idem.forget(bindingID)
}

// SandboxIngressHandler returns the ingress handler chain, for in-process
// use and tests. The route table is built on first use from the connector
// registry, so call it after SetConnectorRegistry.
func (a *APIServer) SandboxIngressHandler() (http.Handler, error) {
	st := a.sandboxIngressState()
	if st == nil {
		return nil, errors.New("sandbox ingress is not configured")
	}
	st.handlerOnce.Do(func() { st.handler = a.newSandboxIngressHandler(st) })
	return st.handler, nil
}

// RunSandboxIngress serves the ingress until ctx ends, then shuts it down
// gracefully. It returns an error when the ingress is not configured or the
// address cannot be bound.
func (a *APIServer) RunSandboxIngress(ctx context.Context) error {
	st := a.sandboxIngressState()
	if st == nil {
		return errors.New("sandbox ingress is not configured")
	}
	handler, err := a.SandboxIngressHandler()
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:    st.addr,
		Handler: handler,
		// Hooks may legitimately wait on a verdict (judge, approvals), so
		// there is no write timeout; slow or idle clients are still bounded.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		// Request contexts keep ctx's values but not its cancellation:
		// stopping the ingress must let running hooks finish their verdicts
		// during the shutdown grace period instead of failing them at once.
		BaseContext: func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}
	ln, err := listenWithRetry(ctx, st.addr, 30*time.Second)
	if err != nil {
		return fmt.Errorf("sandbox ingress: listen %s: %w", st.addr, err)
	}
	if st.onListening != nil {
		st.onListening()
	}
	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "[sandbox-ingress] listening on %s\n", ln.Addr())
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("sandbox ingress: serve %s: %w", st.addr, err)
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), sandboxIngressShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			// Requests still running after the grace period are cut off;
			// closing their connections cancels their contexts.
			_ = srv.Close()
			return fmt.Errorf("sandbox ingress: shutdown %s: %w", st.addr, err)
		}
		return nil
	}
}

func (a *APIServer) sandboxIngressState() *sandboxIngressState {
	if a == nil {
		return nil
	}
	a.sandboxIngressMu.RLock()
	defer a.sandboxIngressMu.RUnlock()
	return a.sandboxIngress
}

// validateSandboxIngressAddr requires a loopback IP literal and an explicit
// port distinct from the main API address. DefenseClaw never listens for
// sandboxes beyond loopback; OpenShell relays host.openshell.internal there.
func validateSandboxIngressAddr(addr, mainAddr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("sandbox ingress: address %q must be host:port: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("sandbox ingress: address %q must be a loopback IP literal", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("sandbox ingress: address %q has an invalid port", addr)
	}
	if n != 0 && listenAddrsMayClash(ip, n, mainAddr) {
		return fmt.Errorf("sandbox ingress: address %q clashes with the main API address %q", addr, mainAddr)
	}
	return nil
}

// listenAddrsMayClash reports whether the main API listen address other may
// occupy the ingress socket ip:port. It errs toward a clash, so a bad pair
// is refused at configuration time instead of failing only after
// listenWithRetry's bind budget:
//
//   - an empty host (":18970") or an unspecified IP binds every address;
//   - "localhost" binds loopback, which is all the ingress ever uses;
//   - any other hostname resolves to addresses unknown here, so the same
//     port alone counts as a clash.
func listenAddrsMayClash(ip net.IP, port int, other string) bool {
	host, otherPort, err := net.SplitHostPort(strings.TrimSpace(other))
	if err != nil {
		return false
	}
	p, err := strconv.Atoi(otherPort)
	if err != nil {
		if p, err = net.LookupPort("tcp", otherPort); err != nil {
			return false
		}
	}
	if p != port {
		return false
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return true
	}
	if otherIP := net.ParseIP(host); otherIP != nil {
		return otherIP.IsUnspecified() || otherIP.Equal(ip)
	}
	if strings.EqualFold(host, "localhost") {
		return ip.IsLoopback()
	}
	return true
}

// sandboxIngressRoute is the route class and connector of one exact path.
type sandboxIngressRoute struct {
	class     sandboxauth.Route
	connector string
}

type sandboxRouteContextKey struct{}

func withSandboxIngressRoute(ctx context.Context, route sandboxauth.Route) context.Context {
	return context.WithValue(ctx, sandboxRouteContextKey{}, route)
}

func sandboxIngressRouteFrom(ctx context.Context) (sandboxauth.Route, bool) {
	route, ok := ctx.Value(sandboxRouteContextKey{}).(sandboxauth.Route)
	return route, ok
}

// sandboxHookOutcome is what a hook handler tells the ingress about its
// answer beyond the status: whether it blocked the call because DefenseClaw
// failed evaluating it (a recovered panic). Such an answer is a 200 block,
// but it is a hook failure all the same (OnHookFailure).
type sandboxHookOutcome struct {
	failedClosed atomic.Bool
}

type sandboxHookOutcomeKey struct{}

func withSandboxHookOutcome(ctx context.Context) (context.Context, *sandboxHookOutcome) {
	outcome := &sandboxHookOutcome{}
	return context.WithValue(ctx, sandboxHookOutcomeKey{}, outcome), outcome
}

// markSandboxHookFailedClosed records that the request's hook answer is a
// fail-closed block. A request without an outcome (host traffic) is left
// alone.
func markSandboxHookFailedClosed(ctx context.Context) {
	if outcome, ok := ctx.Value(sandboxHookOutcomeKey{}).(*sandboxHookOutcome); ok {
		outcome.failedClosed.Store(true)
	}
}

func (a *APIServer) newSandboxIngressHandler(st *sandboxIngressState) http.Handler {
	mux, exact := a.sandboxIngressMux()
	var reg *AgentRegistry
	if a.scannerCfg != nil {
		reg = InstallSharedAgentRegistry(a.scannerCfg.Agent.ID, a.scannerCfg.Agent.Name)
	} else {
		reg = InstallSharedAgentRegistry("", "")
	}
	var h http.Handler = mux
	h = st.idem.middleware(h)
	h = apiBodyLimitMiddleware(h, apiRequestBodyMaxBytes, st.otlpMaxBytes)
	h = a.apiCSRFProtect(h)
	h = a.metricsMiddleware(h)
	h = a.sandboxIngressAuthorize(st, exact, h)
	h = CorrelationMiddleware(reg)(h)
	h = sandboxRequestIDMiddleware(h)
	h = inboundTraceContextMiddleware(h)
	h = a.sandboxIngressAuthenticate(st, h)
	return h
}

// sandboxIngressMux registers the only handlers the ingress serves and
// returns the exact hook/notify path table. Plugin connectors are excluded:
// a sandbox can only run a reviewed builtin harness.
func (a *APIServer) sandboxIngressMux() (*http.ServeMux, map[string]sandboxIngressRoute) {
	mux := http.NewServeMux()
	exact := make(map[string]sandboxIngressRoute)
	reg := a.connectorRegistry
	if reg == nil {
		reg = sharedDefaultRegistry()
	}
	for _, name := range reg.Names() {
		if !connector.IsKnownBuiltinConnector(name) {
			continue
		}
		conn, ok := reg.Get(name)
		if !ok {
			continue
		}
		if endpoint, ok := conn.(connector.HookEndpoint); ok {
			factory, registered := connectorHookHandlerByName[name]
			path := endpoint.HookAPIPath()
			if registered && path != "" {
				if _, dup := exact[path]; !dup {
					mux.Handle(path, http.HandlerFunc(factory(a)))
					exact[path] = sandboxIngressRoute{class: sandboxauth.RouteHook, connector: name}
				}
			}
		}
		if endpoint, ok := conn.(connector.NotifyEndpoint); ok && name == "codex" {
			path := endpoint.NotifyAPIPath()
			if _, dup := exact[path]; path != "" && !dup {
				mux.HandleFunc(path, a.handleCodexNotify)
				exact[path] = sandboxIngressRoute{class: sandboxauth.RouteNotify, connector: name}
			}
		}
	}
	mux.HandleFunc("/api/v1/inspect/tool", a.handleInspectTool)
	mux.HandleFunc("/api/v1/inspect/request", a.handleInspectRequest)
	mux.HandleFunc("/api/v1/inspect/response", a.handleInspectResponse)
	mux.HandleFunc("/api/v1/inspect/tool-response", a.handleInspectToolResponse)
	mux.HandleFunc("/v1/logs", a.handleOTLPLogs)
	mux.HandleFunc("/v1/metrics", a.handleOTLPMetrics)
	mux.HandleFunc("/v1/traces", a.handleOTLPTraces)
	return mux, exact
}

// sandboxBearer extracts the one Authorization bearer credential. Anything
// ambiguous (several Authorization headers, another scheme) is refused.
func sandboxBearer(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	scheme, token, ok := strings.Cut(strings.TrimSpace(values[0]), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

func (a *APIServer) sandboxIngressAuthenticate(st *sandboxIngressState, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := sandboxBearer(r)
		if !ok {
			a.sandboxIngressAuthFailure(st, r, gatewaylog.ErrCodeAuthMissingToken, "missing_token")
			writeSandboxIngressError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		binding, err := st.bindings.Match(token)
		if err != nil {
			a.sandboxIngressAuthFailure(st, r, gatewaylog.ErrCodeAuthInvalidToken, "invalid_token")
			writeSandboxIngressError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if sandboxCredentialOutsideAuthorization(r) {
			// OpenShell substitutes the real credential for its placeholder in
			// every header and in the query string. A header or query value
			// that carries it would be echoed back (request IDs) or persisted
			// to audit sinks, handing the workload the credential it must only
			// ever see as a placeholder.
			a.sandboxIngressAuthFailure(st, r, gatewaylog.ErrCodeAuthInvalidToken, "invalid_token")
			writeSandboxIngressError(w, http.StatusBadRequest,
				"sandbox credentials are accepted only in the Authorization header")
			return
		}
		view := sandboxauth.NewFSView(binding, st.fs)
		ctx := sandboxauth.WithRequest(r.Context(), binding, view)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sandboxCredentialOutsideAuthorization reports whether anything the
// request carries besides its single Authorization header holds sandbox
// credential material: another header's name or value, the host, the path
// or the query. Percent-encoded and Basic-encoded forms count too.
func sandboxCredentialOutsideAuthorization(r *http.Request) bool {
	for name, values := range r.Header {
		if name == "Authorization" {
			continue
		}
		// Header names arrive canonicalised, which changes letter case.
		if containsSandboxCredential(strings.ToLower(name)) {
			return true
		}
		for _, value := range values {
			if containsSandboxCredential(value) {
				return true
			}
		}
	}
	return containsSandboxCredential(r.Host) ||
		containsSandboxCredential(r.RequestURI) ||
		containsSandboxCredential(r.URL.Path) ||
		containsSandboxCredential(r.URL.RawPath) ||
		containsSandboxCredential(r.URL.RawQuery)
}

func containsSandboxCredential(s string) bool {
	if s == "" {
		return false
	}
	if strings.Contains(s, sandboxauth.TokenPrefix) {
		return true
	}
	if strings.Contains(s, "%") {
		if decoded, err := url.PathUnescape(s); err == nil && strings.Contains(decoded, sandboxauth.TokenPrefix) {
			return true
		}
	}
	if scheme, rest, ok := strings.Cut(strings.TrimSpace(s), " "); ok && strings.EqualFold(scheme, "Basic") {
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest)); err == nil &&
			strings.Contains(string(decoded), sandboxauth.TokenPrefix) {
			return true
		}
	}
	return false
}

// sandboxRequestIDMiddleware is requestIDMiddleware with every
// client-supplied request ID dropped, so the ID is always minted. The
// request ID is echoed in a response header and persisted to every audit
// sink; a sandbox must not choose what either carries.
func sandboxRequestIDMiddleware(next http.Handler) http.Handler {
	inner := requestIDMiddleware(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range clientRequestIDHeaders {
			r.Header.Del(name)
		}
		inner.ServeHTTP(w, r)
	})
}

func (a *APIServer) sandboxIngressAuthFailure(st *sandboxIngressState, r *http.Request, code gatewaylog.ErrorCode, reason string) {
	if !st.authFailures.Allow() {
		return
	}
	a.emitHTTPAuthFailure(r.Context(), r, "sandbox-ingress", code, reason)
}

// sandboxIngressAuthorize admits an authenticated request only on a route
// its binding lists, for its own connector, within its budget.
func (a *APIServer) sandboxIngressAuthorize(
	st *sandboxIngressState,
	exact map[string]sandboxIngressRoute,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		binding, ok := sandboxauth.FromContext(r.Context())
		if !ok {
			writeSandboxIngressError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		route, known := classifySandboxIngressRequest(r, exact, binding)
		if !known {
			writeSandboxIngressError(w, http.StatusNotFound, "not found")
			return
		}
		observed := st.onHookFailure != nil && sandboxRouteFailsClosed(route.class)
		var sw *sandboxStatusRecorder
		if observed {
			sw = &sandboxStatusRecorder{ResponseWriter: w}
			w = sw
		}
		if err := binding.Authorize(route.class, route.connector); err != nil {
			writeSandboxIngressError(w, http.StatusForbidden, err.Error())
			if observed {
				st.observeHookFailure(binding, route, sw, false)
			}
			return
		}
		release, err := st.limiter.Acquire(binding, route.class)
		if err != nil {
			w.Header().Set("Retry-After", "1")
			writeSandboxIngressError(w, http.StatusTooManyRequests, err.Error())
			if observed {
				st.observeHookFailure(binding, route, sw, false)
			}
			return
		}
		defer release()
		end := st.inFlight.Begin(binding.ID)
		defer end()
		if st.onRequest != nil {
			st.onRequest(binding, route.class)
		}

		for _, header := range sandboxIdentityHeaders {
			r.Header.Del(header)
		}
		ctx := withSandboxIngressRoute(r.Context(), route.class)
		ctx, outcome := withSandboxHookOutcome(ctx)
		switch route.class {
		case sandboxauth.RouteHook, sandboxauth.RouteNotify:
			ctx = withAuthenticatedHookConnector(ctx, binding.Connector)
		case sandboxauth.RouteInspect:
			ctx = withAuthenticatedInspectConnector(ctx, binding.Connector)
		case sandboxauth.RouteOTLP:
			// The authenticated source is the binding's connector; the
			// receiver attributes by this header.
			r.Header.Set(otelSourceHeader, binding.Connector)
		}
		ctx = PromoteSessionIfAuthenticated(ctx)
		// Session promotion re-resolves the agent identity from the
		// registry; restore the binding's host user on top of it.
		ctx = contextWithSandboxUser(ctx, binding)
		ctx = a.attachSandboxHostSubject(ctx, binding)
		next.ServeHTTP(w, r.WithContext(ctx))
		// A panicking handler never gets here: the server drops its
		// connection, which the hook sees as a transport failure.
		if observed {
			st.observeHookFailure(binding, route, sw, outcome.failedClosed.Load())
		}
	})
}

// sandboxRouteFailsClosed reports whether the sandbox hooks posting to a
// route class fail closed on an error answer: the connector hooks and the
// inspect scripts do; the Codex notify bridge and the OTLP exporters are
// advisory.
func sandboxRouteFailsClosed(route sandboxauth.Route) bool {
	return route == sandboxauth.RouteHook || route == sandboxauth.RouteInspect
}

// observeHookFailure reports an authenticated hook or inspect post answered
// outside 2xx, or with a fail-closed block (failedClosed, reported as 500),
// unless the answer replays the first answer to a retried post.
func (st *sandboxIngressState) observeHookFailure(binding sandboxauth.Binding, route sandboxIngressRoute, sw *sandboxStatusRecorder, failedClosed bool) {
	if sw.Header().Get(sandboxIdempotentReplayHeader) != "" {
		return
	}
	status := sw.finalStatus()
	if status >= 200 && status < 300 {
		if !failedClosed {
			return
		}
		status = http.StatusInternalServerError
	}
	st.onHookFailure(SandboxHookFailure{
		BindingID: binding.ID, SandboxName: binding.SandboxName, Connector: binding.Connector,
		Route: route.class, Status: status,
	})
}

// sandboxStatusRecorder keeps the final status of a response: the first
// status of 200 or above that was written, or the implicit 200 of a body
// written without one.
type sandboxStatusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *sandboxStatusRecorder) WriteHeader(status int) {
	if r.status == 0 && status >= 200 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *sandboxStatusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(p)
}

func (r *sandboxStatusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *sandboxStatusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// finalStatus is the recorded status; a handler that wrote nothing answered
// 200.
func (r *sandboxStatusRecorder) finalStatus() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}

// classifySandboxIngressRequest maps a request onto its route class and the
// connector it acts for. Inspect names its connector in
// X-DefenseClaw-Connector; OTLP in x-defenseclaw-source, defaulting to the
// binding's connector when absent. Anything else is not served.
func classifySandboxIngressRequest(
	r *http.Request,
	exact map[string]sandboxIngressRoute,
	binding sandboxauth.Binding,
) (sandboxIngressRoute, bool) {
	path := r.URL.Path
	if route, ok := exact[path]; ok {
		return route, true
	}
	if slices.Contains(sandboxInspectPaths, path) {
		return sandboxIngressRoute{
			class:     sandboxauth.RouteInspect,
			connector: r.Header.Get("X-DefenseClaw-Connector"),
		}, true
	}
	if slices.Contains(sandboxOTLPPaths, path) {
		source := strings.TrimSpace(r.Header.Get(otelSourceHeader))
		if source == "" {
			return sandboxIngressRoute{class: sandboxauth.RouteOTLP, connector: binding.Connector}, true
		}
		return sandboxIngressRoute{
			class:     sandboxauth.RouteOTLP,
			connector: normalizeConnectorTelemetrySource(source),
		}, true
	}
	return sandboxIngressRoute{}, false
}

// observeSandboxHookDecision hands a sandbox hook verdict to the manager.
func (a *APIServer) observeSandboxHookDecision(ctx context.Context, req agentHookRequest, resp agentHookResponse) {
	binding, ok := sandboxauth.FromContext(ctx)
	if !ok {
		return
	}
	st := a.sandboxIngressState()
	if st == nil || st.onHookDecision == nil {
		return
	}
	st.onHookDecision(SandboxHookDecision{
		BindingID: binding.ID, SandboxName: binding.SandboxName, Connector: binding.Connector,
		Event: req.HookEventName, Tool: req.ToolName, ToolUseID: req.ToolInvocationID,
		SessionID: req.SessionID, ToolInput: sandboxDecisionToolInput(req),
		ResultStatus: strings.TrimSpace(payloadString(req.Payload, "status")),
		Action:       resp.Action, WouldBlock: resp.WouldBlock, Severity: resp.Severity, Reason: resp.Reason,
	})
}

// sandboxDecisionToolInput is the tool input a hook event carries, or nil.
// ToolArgs falls back to the whole payload when the event has no input
// field, and that differs between a call's pre-tool and post-tool events,
// so it never names a call.
func sandboxDecisionToolInput(req agentHookRequest) json.RawMessage {
	if firstValue(req.Payload, "tool_input", "toolInput", "tool_args", "toolArgs", "args", "arguments") == nil {
		return nil
	}
	return req.ToolArgs
}

func contextWithSandboxUser(ctx context.Context, binding sandboxauth.Binding) context.Context {
	id := AgentIdentityFromContext(ctx)
	id.UserID, id.UserIDKind, id.UserName = sandboxBindingUser(binding)
	return ContextWithAgentIdentity(ctx, id)
}

// attachSandboxHostSubject verifies sandbox traffic as the binding's host
// user. The sandbox manager launches every sandbox as the gateway's own
// account and records it as the host user, and only that sandbox holds the
// binding's credential, so on a per-user gateway the host user is verified
// like host traffic's process owner: the same directory facts, 15-minute
// refresh and lookup-failure handling, and identity.observed. A binding
// that names another account, and every sandbox of a service-account
// gateway, get no subject.
func (a *APIServer) attachSandboxHostSubject(ctx context.Context, binding sandboxauth.Binding) context.Context {
	if !identityFactsEnabled.Load() || a.userScopedCredentialsRequired() {
		return ctx
	}
	hostID, _, hostName := sandboxBindingUser(binding)
	if ownerID, _ := localProcessUser(); hostID == "" || hostID != ownerID {
		return ctx
	}
	return attachVerifiedSubject(ctx, a.observabilityV8RuntimeEmitter(), hostID, hostName, subjectSourceProcessOwner)
}

func writeSandboxIngressError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "{\"error\":%q}\n", message)
}

// requestCarriesSandboxCredential reports whether any credential slot the
// main API reads holds a sandbox binding credential.
func requestCarriesSandboxCredential(r *http.Request) bool {
	for _, name := range []string{"Authorization", "X-DefenseClaw-Token", "X-DC-Auth"} {
		for _, value := range r.Header.Values(name) {
			value = strings.TrimSpace(value)
			if scheme, rest, ok := strings.Cut(value, " "); ok && strings.EqualFold(scheme, "Bearer") {
				value = strings.TrimSpace(rest)
			}
			if sandboxauth.HasTokenPrefix(value) {
				return true
			}
		}
	}
	if pathToken, _, ok := parseOTLPPathToken(r.URL.Path); ok && sandboxauth.HasTokenPrefix(pathToken) {
		return true
	}
	return false
}
