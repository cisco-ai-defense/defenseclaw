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
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
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
//	authenticate  credential -> binding (401); binding + FSView into ctx
//	trace, request ID, correlation (identity from the binding's host user)
//	authorize     route allowlist and connector match (404/403),
//	              per-binding limiter (429), in-flight tracking
//	metrics, CSRF, body limit
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
	// sandboxIngressShutdownTimeout bounds graceful shutdown.
	sandboxIngressShutdownTimeout = 5 * time.Second
)

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
}

type sandboxIngressState struct {
	addr     string
	bindings sandboxauth.Matcher
	limiter  *sandboxauth.Limiter
	inFlight *sandboxauth.InFlight
	idem     *hookIdempotencyCache
	fs       sandboxauth.FS
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
	st := &sandboxIngressState{
		addr:         cfg.Addr,
		bindings:     cfg.Bindings,
		limiter:      cfg.Limiter,
		inFlight:     cfg.InFlight,
		fs:           cfg.FS,
		authFailures: rate.NewLimiter(10, 20),
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
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	ln, err := listenWithRetry(ctx, st.addr, 30*time.Second)
	if err != nil {
		return fmt.Errorf("sandbox ingress: listen %s: %w", st.addr, err)
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
		return srv.Shutdown(shutdownCtx)
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
	if n != 0 && sameListenAddr(addr, mainAddr) {
		return fmt.Errorf("sandbox ingress: address %q is the main API address", addr)
	}
	return nil
}

func sameListenAddr(a, b string) bool {
	ah, ap, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}
	bh, bp, err := net.SplitHostPort(b)
	if err != nil || ap != bp {
		return false
	}
	aip, bip := net.ParseIP(ah), net.ParseIP(bh)
	if aip == nil || bip == nil {
		return ah == bh
	}
	return aip.Equal(bip) || aip.IsUnspecified() || bip.IsUnspecified()
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
	h = apiBodyLimitMiddleware(h, apiRequestBodyMaxBytes, otlpRequestBodyMaxBytes)
	h = a.apiCSRFProtect(h)
	h = a.metricsMiddleware(h)
	h = a.sandboxIngressAuthorize(st, exact, h)
	h = CorrelationMiddleware(reg)(h)
	h = requestIDMiddleware(h)
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
		view := sandboxauth.NewFSView(binding, st.fs)
		ctx := sandboxauth.WithRequest(r.Context(), binding, view)
		next.ServeHTTP(w, r.WithContext(ctx))
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
		if err := binding.Authorize(route.class, route.connector); err != nil {
			writeSandboxIngressError(w, http.StatusForbidden, err.Error())
			return
		}
		release, err := st.limiter.Acquire(binding, route.class)
		if err != nil {
			w.Header().Set("Retry-After", "1")
			writeSandboxIngressError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		defer release()
		end := st.inFlight.Begin(binding.ID)
		defer end()

		for _, header := range sandboxIdentityHeaders {
			r.Header.Del(header)
		}
		ctx := withSandboxIngressRoute(r.Context(), route.class)
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
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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

func contextWithSandboxUser(ctx context.Context, binding sandboxauth.Binding) context.Context {
	id := AgentIdentityFromContext(ctx)
	id.UserID, id.UserIDKind, id.UserName = sandboxBindingUser(binding)
	return ContextWithAgentIdentity(ctx, id)
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
