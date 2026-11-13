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
	cryptorand "crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ratelimit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// The Agent Substrate gateway serves two listeners (PLAN §5.1, D15):
//
//   - the actor listener, Service defenseclaw-actor, the only DefenseClaw
//     host in rendered EgressPolicies. It serves hook, notify and inspect
//     posts, the relay session check, /llm/* and OTLP, and nothing else.
//     Every request must carry the actor JWT Substrate egress puts in
//     x-defenseclaw-actor; the token is verified (identity.ActorVerifier,
//     live actor UID included) and the actor's registration found before
//     any handler runs.
//   - the admin listener, Service defenseclaw-admin, never in an
//     EgressPolicy: the launcher, fleet and bundle APIs for signed-in
//     people (OIDC), own data only for users, and the callout's verdict
//     route (service token).
//
// Actor middleware, outermost first:
//
//	allowlist     a path the actor listener does not serve is 404, before
//	              anything else, so admin paths do not exist here
//	authenticate  actor JWT (401), registration (403), connector of the
//	              route against the registration (403); the token header,
//	              Authorization and identity headers are dropped
//	envelope      a hook or notify post's kit envelope is unwrapped: the
//	              handler reads the agent's payload, the kit's file facts
//	              go into the context (claims)
//	trace, request ID (always minted), correlation
//	limit         fair share per actor UID and atespace (429)
//	scope         sandbox scope (a copy-mode binding: no host path is ever
//	              read for an actor), verified actor, person, profile
//	metrics, CSRF, body limit
//	route         the connector's hook handler, notify, inspect, relay
//	              verify, /llm, OTLP

const (
	// substrateActorHeader carries the actor JWT ("Bearer <jwt>").
	substrateActorHeader = "x-defenseclaw-actor"
	// substrateWarmHeader marks the kit's warm-up GET.
	substrateWarmHeader = "X-DefenseClaw-Warm"
	// Response headers that tell the kit the authoritative run mode and
	// the fail mode it applies when the gateway cannot answer (D8).
	substrateModeHeader     = "X-DefenseClaw-Actor-Mode"
	substrateFailModeHeader = "X-DefenseClaw-Fail-Mode"

	substrateHookPrefix    = "/api/v1/substrate/hook/"
	substrateNotifyPrefix  = "/api/v1/substrate/notify/"
	substrateInspectPrefix = "/api/v1/substrate/inspect/"
	substrateRelayVerify   = "/api/v1/substrate/relay/verify"
	substrateLLMPrefix     = "/llm/"

	substrateShutdownTimeout = 10 * time.Second
)

// SubstrateConfig configures the Agent Substrate listeners. The serve
// --substrate wiring builds it from the substrate config section.
type SubstrateConfig struct {
	// ActorAddr and AdminAddr are host:port to listen on; either may be
	// empty (that listener does not run, as on the leader).
	ActorAddr string
	AdminAddr string
	// ActorTLS and AdminTLS serve TLS (the servicedns pod certificate).
	// Nil serves plain HTTP: tests only, or TLS ended in front.
	ActorTLS *tls.Config
	AdminTLS *tls.Config

	Actors        SubstrateActorVerifier
	People        SubstratePersonVerifier
	Sessions      *identity.SessionSigner
	Registrations registry.Store
	Limiter       *ratelimit.Limiter
	// Lookup finds a live actor by atespace/name (the callout knows no
	// UID).
	Lookup identity.ActorLookup
	// IsAdmin reports an administrator (the existing admin check over the
	// person's groups).
	IsAdmin func(identity.Person) bool
	// CalloutToken returns the callout's service token; nil turns the
	// callout verdict route off.
	CalloutToken func() (string, error)
	// FailOpenInteractive is the interactive fail mode (OSS default and
	// permissive tiers fail open with a warning; managed and strict fail
	// closed). Unattended runs always fail closed (D8).
	FailOpenInteractive bool
	// LLM serves /llm/<provider>/... for a verified actor (nil: 404).
	LLM http.Handler
	// Actions creates and deletes actors for the launcher (nil: 501).
	Actions SubstrateActorActions
	// PolicyReset records an admin policy_conflict reset for the
	// controller (nil: 501).
	PolicyReset SubstratePolicyReset
	// Profiles picks a create's profile and launcher atespace (nil: every
	// create is refused).
	Profiles SubstrateProfileResolver
	// Usage answers own-only usage (stream 10 seam; nil: 501).
	Usage SubstrateUsage
	// Bundles applies and shows signed policy bundles (nil: 501).
	Bundles SubstrateBundles
	// Activity receives the last-activity feed of A3's idle logic.
	Activity SubstrateActivitySink
	// Skills scans the skill folders the kit attaches (GAP-0039); nil
	// scans nothing.
	Skills SubstrateSkillScanner
	// BlockUnscannedSkills says whether a skill folder that reaches an
	// actor of this connector without a scan is refused (managed installs and
	// the strict tier) rather than alerted on (OSS default tiers).
	BlockUnscannedSkills func(connector string) bool
	// SkillReceiptKey signs skill scan receipts; every replica must have the
	// same key (derived from the shared chain key). Empty: a random key per
	// process, so receipts hold only on the replica that gave them.
	SkillReceiptKey []byte
	// Asks is the leader's ask and decision store (nil: 501).
	Asks SubstrateAskStore
	// UnattendedAsk is what an unattended actor's ask does for its profile
	// (SubstrateUnattendedAskFor; nil: deny, D12).
	UnattendedAsk func(profile string) SubstrateUnattendedAsk
	// Policies reads an actor's egress policy for policy explain.
	Policies SubstratePolicyReader
	// Relays reaches an actor's relay through the router for attach
	// (nil: attach answers 503).
	Relays SubstrateRelayDialer
	// WorkspaceMaxBytes caps a workspace upload through attach
	// (substrate.workspace_max_bytes, E23).
	WorkspaceMaxBytes int64
	// Doctor runs the gateway-side doctor checks; Info is the
	// unauthenticated sign-in information (issuer, client_id, sign_in).
	Doctor func(ctx context.Context) []SubstrateCheck
	Info   map[string]any
	// Secrets are substrate.secrets; SecretStore writes Kubernetes-backed
	// values (nil: list only).
	Secrets     []config.SubstrateSecret
	SecretStore SubstrateSecretStore
	// OnRateLimited counts defenseclaw.substrate.rate_limited.
	OnRateLimited func(scope ratelimit.Scope, route string)
	// Chains is the leader's chain and intent state (lane A13): a verified
	// actor's tool-chain windows and the judge's session intent live there,
	// so every replica sees the same. Nil turns the chain lane off for
	// actors and keeps the judge's intent per process.
	Chains *chainstate.Client
}

// SubstrateActorVerifier verifies actor tokens (identity.ActorVerifier).
type SubstrateActorVerifier interface {
	Verify(ctx context.Context, token string) (identity.Actor, error)
}

// SubstratePersonVerifier verifies people (identity.PersonVerifier).
type SubstratePersonVerifier interface {
	Verify(ctx context.Context, token string) (identity.Person, error)
}

// SubstrateActivitySink is fed the activity of verified actors.
type SubstrateActivitySink interface {
	ObserveActivity(kind, atespace, actorUID string, at time.Time)
}

// Activity kinds.
const (
	SubstrateActivityHook  = "hook"
	SubstrateActivityModel = "model"
	SubstrateActivityRelay = "relay"
)

type substrateState struct {
	cfg SubstrateConfig
	// refusals bounds refusal log lines: a flood of bad tokens is still
	// refused, not logged line by line.
	refusals *rate.Limiter

	// receiptKey signs skill scan receipts (substrate_skills.go);
	// receiptShared says every replica has it.
	receiptKey    []byte
	receiptShared bool
	// alert raises an audit alert (the API server's logger).
	alert func(ctx context.Context, severity, summary string, details map[string]any)

	actorOnce, adminOnce sync.Once
	actorHandler         http.Handler
	adminHandler         http.Handler
}

// SetSubstrate configures (or, with a zero config, removes) the Substrate
// listeners. It opens no socket; RunSubstrate does.
func (a *APIServer) SetSubstrate(cfg SubstrateConfig) error {
	if a == nil {
		return errors.New("substrate: nil API server")
	}
	if cfg.ActorAddr == "" && cfg.AdminAddr == "" && cfg.Actors == nil && cfg.People == nil {
		a.substrateMu.Lock()
		a.substrate = nil
		a.substrateMu.Unlock()
		useSubstrateChains(nil)
		return nil
	}
	if cfg.ActorAddr != "" {
		if cfg.Actors == nil || cfg.Registrations == nil {
			return errors.New("substrate: the actor listener needs the actor verifier and the registrations")
		}
		if cfg.Limiter == nil {
			cfg.Limiter = ratelimit.New(ratelimit.Config{})
		}
	}
	if cfg.AdminAddr != "" && (cfg.People == nil || cfg.Registrations == nil) {
		return errors.New("substrate: the admin listener needs the person verifier and the registrations")
	}
	if cfg.ActorAddr != "" && cfg.ActorAddr == cfg.AdminAddr {
		return errors.New("substrate: the actor and admin listeners need different addresses (D15)")
	}
	if cfg.IsAdmin == nil {
		cfg.IsAdmin = func(identity.Person) bool { return false }
	}
	st := &substrateState{cfg: cfg, refusals: rate.NewLimiter(5, 20), receiptKey: cfg.SkillReceiptKey, receiptShared: len(cfg.SkillReceiptKey) > 0}
	if !st.receiptShared {
		st.receiptKey = make([]byte, 32)
		if _, err := cryptorand.Read(st.receiptKey); err != nil {
			return fmt.Errorf("substrate: skill receipt key: %w", err)
		}
	}
	st.alert = func(ctx context.Context, severity, summary string, details map[string]any) {
		if a.logger != nil {
			_ = a.logger.LogAlertCtx(ctx, "substrate", severity, summary, details)
		}
		st.logRefusal("%s: %v", summary, details["folder"])
	}
	a.substrateMu.Lock()
	a.substrate = st
	a.substrateMu.Unlock()
	useSubstrateChains(cfg.Chains)
	return nil
}

func (a *APIServer) substrateState() *substrateState {
	if a == nil {
		return nil
	}
	a.substrateMu.RLock()
	defer a.substrateMu.RUnlock()
	return a.substrate
}

// SubstrateActorHandler is the actor listener's handler chain.
func (a *APIServer) SubstrateActorHandler() (http.Handler, error) {
	st := a.substrateState()
	if st == nil || st.cfg.Actors == nil {
		return nil, errors.New("substrate: the actor listener is not configured")
	}
	st.actorOnce.Do(func() { st.actorHandler = a.newSubstrateActorHandler(st) })
	return st.actorHandler, nil
}

// SubstrateAdminHandler is the admin listener's handler chain.
func (a *APIServer) SubstrateAdminHandler() (http.Handler, error) {
	st := a.substrateState()
	if st == nil || st.cfg.People == nil {
		return nil, errors.New("substrate: the admin listener is not configured")
	}
	st.adminOnce.Do(func() { st.adminHandler = a.newSubstrateAdminHandler(st) })
	return st.adminHandler, nil
}

// RunSubstrate serves the configured listeners until ctx ends.
func (a *APIServer) RunSubstrate(ctx context.Context) error {
	st := a.substrateState()
	if st == nil {
		return errors.New("substrate: not configured")
	}
	type served struct {
		name string
		addr string
		tls  *tls.Config
		h    func() (http.Handler, error)
	}
	var list []served
	if st.cfg.ActorAddr != "" {
		list = append(list, served{"actor", st.cfg.ActorAddr, st.cfg.ActorTLS, a.SubstrateActorHandler})
	}
	if st.cfg.AdminAddr != "" {
		list = append(list, served{"admin", st.cfg.AdminAddr, st.cfg.AdminTLS, a.SubstrateAdminHandler})
	}
	if len(list) == 0 {
		return errors.New("substrate: no listener address")
	}
	a.startPendingHookRecovery(ctx)
	errCh := make(chan error, len(list))
	var servers []*http.Server
	for _, s := range list {
		h, err := s.h()
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", s.addr)
		if err != nil {
			return fmt.Errorf("substrate %s listener: %w", s.name, err)
		}
		if s.tls != nil {
			ln = tls.NewListener(ln, s.tls)
		}
		srv := &http.Server{
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			// Hooks may wait on a verdict; model streams run long. Slow
			// clients are still bounded by the read limits.
			ReadTimeout:    2 * time.Minute,
			IdleTimeout:    2 * time.Minute,
			MaxHeaderBytes: 64 << 10,
			BaseContext:    func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
			ErrorLog:       nil,
		}
		servers = append(servers, srv)
		name := s.name
		go func() {
			fmt.Fprintf(os.Stderr, "[substrate] %s listener on %s\n", name, ln.Addr())
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("substrate %s listener: %w", name, err)
				return
			}
			errCh <- nil
		}()
	}
	select {
	case err := <-errCh:
		shutdownSubstrate(servers)
		return err
	case <-ctx.Done():
		shutdownSubstrate(servers)
		return nil
	}
}

func shutdownSubstrate(servers []*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), substrateShutdownTimeout)
	defer cancel()
	for _, s := range servers {
		if err := s.Shutdown(ctx); err != nil {
			_ = s.Close()
		}
	}
}

// --- actor listener ---

// substrateActorRoute is a served actor route.
type substrateActorRoute struct {
	class     sandboxauth.Route
	connector string // hook and notify: the path's connector
	native    string // the handler's own path (hook, notify, inspect)
	llm       bool
	relay     bool
}

// classifySubstrateActorPath maps a path to its route, or false (404).
func (a *APIServer) classifySubstrateActorPath(path string) (substrateActorRoute, bool) {
	switch {
	case strings.HasPrefix(path, substrateHookPrefix):
		name := strings.TrimPrefix(path, substrateHookPrefix)
		native, ok := a.substrateHookNative(name)
		if !ok {
			return substrateActorRoute{}, false
		}
		return substrateActorRoute{class: sandboxauth.RouteHook, connector: name, native: native}, true
	case strings.HasPrefix(path, substrateNotifyPrefix):
		name := strings.TrimPrefix(path, substrateNotifyPrefix)
		if name != "codex" {
			return substrateActorRoute{}, false
		}
		return substrateActorRoute{class: sandboxauth.RouteNotify, connector: name, native: "/api/v1/codex/notify"}, true
	case strings.HasPrefix(path, substrateInspectPrefix):
		native := "/api/v1/inspect/" + strings.TrimPrefix(path, substrateInspectPrefix)
		for _, p := range sandboxInspectPaths {
			if p == native {
				return substrateActorRoute{class: sandboxauth.RouteInspect, native: native}, true
			}
		}
		return substrateActorRoute{}, false
	case path == substrateRelayVerify:
		return substrateActorRoute{relay: true}, true
	case strings.HasPrefix(path, substrateLLMPrefix) && len(path) > len(substrateLLMPrefix):
		return substrateActorRoute{llm: true}, true
	}
	for _, p := range sandboxOTLPPaths {
		if p == path {
			return substrateActorRoute{class: sandboxauth.RouteOTLP, native: path}, true
		}
	}
	return substrateActorRoute{}, false
}

// substrateHookNative is the host hook path of a builtin connector with a
// gateway hook handler; plugin connectors are not served to actors.
func (a *APIServer) substrateHookNative(name string) (string, bool) {
	if name == "" || strings.Contains(name, "/") {
		return "", false
	}
	if _, ok := connectorHookHandlerByName[name]; !ok {
		return "", false
	}
	reg := a.connectorRegistry
	if reg == nil {
		reg = sharedDefaultRegistry()
	}
	conn, ok := reg.Get(name)
	if !ok {
		return "", false
	}
	ep, ok := conn.(interface{ HookAPIPath() string })
	if !ok || ep.HookAPIPath() == "" {
		return "", false
	}
	return ep.HookAPIPath(), true
}

func (a *APIServer) newSubstrateActorHandler(st *substrateState) http.Handler {
	var reg *AgentRegistry
	if a.scannerCfg != nil {
		reg = InstallSharedAgentRegistry(a.scannerCfg.Agent.ID, a.scannerCfg.Agent.Name)
	} else {
		reg = InstallSharedAgentRegistry("", "")
	}
	var h http.Handler = http.HandlerFunc(a.serveSubstrateActorRoute)
	// A model call carries the whole conversation: /llm takes the guardrail
	// proxy's own passthrough cap, every other route the API cap.
	h = bodyLimitMiddleware(h, func(r *http.Request) int64 {
		switch {
		case strings.HasPrefix(r.URL.Path, substrateLLMPrefix):
			return substrateLLMMaxBody
		case isOTLPEndpointPath(r.URL.Path):
			return defaultSandboxOTLPMaxBodyBytes
		}
		return apiRequestBodyMaxBytes
	})
	// No browser CSRF gate (X-DefenseClaw-Client) here: an actor request
	// is authenticated by the actor token egress injects, has no cookies
	// and comes from no browser; the agent SDKs and the kit send no client
	// tag (GAP-0037, lead ruling 11-12 21:05Z). The admin listener keeps it.
	h = a.metricsMiddleware(h)
	h = a.substrateActorScope(st, h)
	h = CorrelationMiddleware(reg)(h)
	h = sandboxRequestIDMiddleware(h)
	h = inboundTraceContextMiddleware(h)
	h = substrateEnvelopeMiddleware(st, h)
	h = a.substrateActorAuthenticate(st, h)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, ok := a.classifySubstrateActorPath(r.URL.Path)
		if !ok || (r.URL.RawPath != "" && !substrateLLMRawPathOK(route, r.URL.RawPath)) {
			writeSandboxIngressError(w, http.StatusNotFound, "not found")
			return
		}
		h.ServeHTTP(w, r.WithContext(withSubstrateRoute(r.Context(), route)))
	})
}

type substrateRouteKey struct{}

func withSubstrateRoute(ctx context.Context, r substrateActorRoute) context.Context {
	return context.WithValue(ctx, substrateRouteKey{}, r)
}

func substrateRouteFrom(ctx context.Context) substrateActorRoute {
	r, _ := ctx.Value(substrateRouteKey{}).(substrateActorRoute)
	return r
}

type substrateRegistrationKey struct{}

func substrateRegistrationFrom(ctx context.Context) (registry.Registration, bool) {
	r, ok := ctx.Value(substrateRegistrationKey{}).(registry.Registration)
	return r, ok
}

// substrateActorToken extracts the one actor token. Several headers, or a
// value that is not "Bearer <token>", count as none.
func substrateActorToken(r *http.Request) string {
	values := r.Header.Values(substrateActorHeader)
	if len(values) != 1 {
		return ""
	}
	scheme, tok, ok := strings.Cut(strings.TrimSpace(values[0]), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(tok)
}

// writeSubstrateRefusal answers an actor request the gateway refuses
// before any handler: a closed reason, never request material.
func writeSubstrateRefusal(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "{\"error\":%q,\"reason\":%q}\n", http.StatusText(status), reason)
}

func (a *APIServer) substrateActorAuthenticate(st *substrateState, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := substrateRouteFrom(r.Context())
		tok := substrateActorToken(r)
		// The token never reaches a handler, a log or an audit sink, and
		// no credential header from the actor is honoured.
		r.Header.Del(substrateActorHeader)
		r.Header.Del("Authorization")
		r.Header.Del("Proxy-Authorization")
		for _, h := range sandboxIdentityHeaders {
			r.Header.Del(h)
		}
		if tok == "" {
			writeSubstrateRefusal(w, http.StatusUnauthorized, string(identity.ReasonMissing))
			return
		}
		actor, err := st.cfg.Actors.Verify(r.Context(), tok)
		if err != nil {
			reason := identity.ReasonOf(err)
			status := http.StatusUnauthorized
			if identity.Unavailable(err) {
				status = http.StatusServiceUnavailable
			}
			// The message names the check, never token bytes (identity.Error).
			st.logRefusal("actor token refused: %s (%v)", reason, err)
			writeSubstrateRefusal(w, status, string(reason))
			return
		}
		// The fair-share limits run right after the token check, before
		// the registration lookup and the envelope read, so a flooding
		// actor costs no leader call and no body read (GAP-0057).
		release, lerr := st.cfg.Limiter.Acquire(actor.Atespace, actor.UID)
		if lerr != nil {
			scope, _ := ratelimit.IsLimited(lerr)
			if st.cfg.OnRateLimited != nil {
				st.cfg.OnRateLimited(scope, substrateRouteName(route))
			}
			writeHookRateLimited(w, "substrate_"+string(scope), "this actor is over its request budget; retry shortly")
			return
		}
		defer release()
		reg, ok, err := st.cfg.Registrations.Get(r.Context(), actor.Atespace, actor.UID)
		switch {
		case err != nil:
			st.logRefusal("registration lookup failed for %s: %v", actor.Ref(), err)
			writeSubstrateRefusal(w, http.StatusServiceUnavailable, "registration_unavailable")
			return
		case !ok || reg.Deleted:
			st.logRefusal("actor %s (uid %s) is not registered", actor.Ref(), actor.UID)
			writeSubstrateRefusal(w, http.StatusForbidden, "actor_not_registered")
			return
		}
		if route.connector != "" && reg.Connector != "" && sandboxauth.CanonicalConnector(route.connector) != sandboxauth.CanonicalConnector(reg.Connector) {
			writeSubstrateRefusal(w, http.StatusForbidden, "connector_mismatch")
			return
		}
		key, kerr := sandboxreg.SubstrateKey(actor.Atespace, actor.UID)
		if kerr != nil || key != reg.Key {
			writeSubstrateRefusal(w, http.StatusForbidden, "actor_not_registered")
			return
		}
		ctx := withSubstrateActor(r.Context(), verifiedSubstrateActor(actor.Atespace, actor.Name, actor.UID, actor.Subject, key))
		ctx = context.WithValue(ctx, substrateRegistrationKey{}, reg)
		w.Header().Set(substrateModeHeader, substrateMode(reg))
		w.Header().Set(substrateFailModeHeader, substrateFailMode(st.cfg, reg))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func substrateMode(reg registry.Registration) string {
	if reg.Unattended {
		return "unattended"
	}
	return "interactive"
}

// substrateFailMode is D8: unattended closed in every tier; interactive as
// on hosts.
func substrateFailMode(cfg SubstrateConfig, reg registry.Registration) string {
	if reg.Unattended || !cfg.FailOpenInteractive {
		return "closed"
	}
	return "open"
}

func substrateRouteName(r substrateActorRoute) string {
	switch {
	case r.llm:
		return "llm"
	case r.relay:
		return "relay"
	}
	return string(r.class)
}

// substrateActorScope puts the sandbox scope, the verified actor's person
// and profile on the request, as the OpenShell ingress does for a binding.
func (a *APIServer) substrateActorScope(st *substrateState, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		actor, _ := substrateActorFrom(ctx)
		reg, _ := substrateRegistrationFrom(ctx)
		route := substrateRouteFrom(ctx)
		// A copy-mode binding: path checks never translate an actor's
		// path to a host path, and nothing reads the gateway pod's own
		// files for an actor. The binding exists only in this context.
		binding := sandboxauth.Binding{
			ID:             reg.Key,
			SandboxID:      actor.UID,
			SandboxName:    actor.Atespace + "/" + actor.Name,
			Connector:      sandboxauth.CanonicalConnector(reg.Connector),
			AgentVersion:   reg.HarnessVersion,
			HookContractID: substrateHookContract(ctx, reg),
			PolicyProfile:  reg.Profile,
			Routes:         []sandboxauth.Route{sandboxauth.RouteHook, sandboxauth.RouteNotify, sandboxauth.RouteInspect, sandboxauth.RouteOTLP},
			Workdir:        sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
			RegistrationID: reg.Key,
		}
		ctx = sandboxauth.WithRequest(ctx, binding, nil)
		ctx = withSandboxIngressRoute(ctx, route.class)
		ctx, _ = withSandboxHookOutcome(ctx)
		switch route.class {
		case sandboxauth.RouteHook, sandboxauth.RouteNotify:
			ctx = withAuthenticatedHookConnector(ctx, binding.Connector)
			ctx = withProfilePath(ctx, profilePathHook)
		case sandboxauth.RouteInspect:
			ctx = withAuthenticatedInspectConnector(ctx, binding.Connector)
			ctx = withProfilePath(ctx, profilePathInspect)
		case sandboxauth.RouteOTLP:
			r.Header.Set(otelSourceHeader, binding.Connector)
		}
		ctx = PromoteSessionIfAuthenticated(ctx)
		ctx = contextWithSubstratePerson(ctx, reg)
		// The verified caller on every actor route, as for /llm: hook
		// decisions, profiles and audit rows see the same person
		// (substrate_identity.go).
		if route.llm || route.class == sandboxauth.RouteHook || route.class == sandboxauth.RouteNotify || route.class == sandboxauth.RouteInspect {
			ctx = a.attachSubstrateSubject(ctx, reg)
		}
		if route.class != "" && route.class != sandboxauth.RouteOTLP {
			ctx = a.withGuardrailProfileDecision(ctx, binding.Connector)
		}
		if st.cfg.Activity != nil && (route.class == sandboxauth.RouteHook || route.llm || route.relay) {
			kind := SubstrateActivityHook
			switch {
			case route.llm:
				kind = SubstrateActivityModel
			case route.relay:
				kind = SubstrateActivityRelay
			}
			// Gateway receive time only (E15): nothing the actor sends.
			st.cfg.Activity.ObserveActivity(kind, actor.Atespace, actor.UID, time.Now())
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// contextWithSubstratePerson attributes the request to the registration's
// person (or, for an attributed actor, to nobody).
func contextWithSubstratePerson(ctx context.Context, reg registry.Registration) context.Context {
	id := AgentIdentityFromContext(ctx)
	id.UserID, id.UserIDKind, id.UserName = "", "", ""
	if reg.Person.Subject != "" {
		id.UserID = sanitizeLLMEventUser(reg.Person.Subject)
		id.UserName = sanitizeLLMEventUser(reg.Person.Principal)
	}
	return ContextWithAgentIdentity(ctx, id)
}

func (a *APIServer) serveSubstrateActorRoute(w http.ResponseWriter, r *http.Request) {
	route := substrateRouteFrom(r.Context())
	st := a.substrateState()
	switch {
	case route.relay:
		a.serveSubstrateRelayVerify(st, w, r)
		return
	case route.llm:
		if st == nil || st.cfg.LLM == nil {
			writeSandboxIngressError(w, http.StatusNotFound, "not found")
			return
		}
		st.cfg.LLM.ServeHTTP(w, r)
		return
	}
	// The handler sees the path it serves on the host.
	u := *r.URL
	u.Path, u.RawPath = route.native, ""
	r.URL = &u
	switch route.class {
	case sandboxauth.RouteHook:
		if r.Method == http.MethodGet && r.Header.Get(substrateWarmHeader) != "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		factory := connectorHookHandlerByName[route.connector]
		factory(a).ServeHTTP(w, r)
	case sandboxauth.RouteNotify:
		a.handleCodexNotify(w, r)
	case sandboxauth.RouteInspect:
		switch route.native {
		case "/api/v1/inspect/tool":
			a.handleInspectTool(w, r)
		case "/api/v1/inspect/request":
			a.handleInspectRequest(w, r)
		case "/api/v1/inspect/response":
			a.handleInspectResponse(w, r)
		case "/api/v1/inspect/tool-response":
			a.handleInspectToolResponse(w, r)
		}
	case sandboxauth.RouteOTLP:
		switch route.native {
		case "/v1/logs":
			a.handleOTLPLogs(w, r)
		case "/v1/metrics":
			a.handleOTLPMetrics(w, r)
		case "/v1/traces":
			a.handleOTLPTraces(w, r)
		}
	default:
		writeSandboxIngressError(w, http.StatusNotFound, "not found")
	}
}

// substrateProfileSubject is the profile subject of an actor request: the
// person the launcher verified (OIDC subject, principal and groups) and
// bound to the actor at create. An attributed actor has none, so only the
// assignments that need no person select its profile.
func substrateProfileSubject(ctx context.Context) (profileSubject, bool) {
	if _, ok := substrateActorFrom(ctx); !ok {
		return profileSubject{}, false
	}
	reg, ok := substrateRegistrationFrom(ctx)
	if !ok || reg.Person.Subject == "" {
		return profileSubject{}, false
	}
	return profileSubject{
		UserID: reg.Person.Subject, UserName: reg.Person.Principal,
		Principal: reg.Person.Principal, UPN: reg.Person.Principal,
		Groups: append([]string(nil), reg.Person.Groups...),
	}, true
}

// logRefusal writes a rate-limited refusal line for operators.
func (st *substrateState) logRefusal(format string, args ...any) {
	if st == nil || st.refusals == nil || !st.refusals.Allow() {
		return
	}
	fmt.Fprintf(os.Stderr, "[substrate] "+format+"\n", args...)
}

// substrateLLMMaxBody is the guardrail proxy's passthrough body cap, which
// a model call through /llm gets too.
const substrateLLMMaxBody = 10 << 20

// substrateLLMRawPathOK admits an escaped /llm path: provider SDKs escape
// the model ID (Bedrock "...-v1%3A0"). An escaped separator, backslash or
// dot is still refused, so the decoded path is the one the route checks.
func substrateLLMRawPathOK(route substrateActorRoute, raw string) bool {
	if !route.llm {
		return false
	}
	l := strings.ToLower(raw)
	if !strings.Contains(l, "%5c") && !strings.Contains(l, "%2e") {
		if !strings.Contains(l, "%2f") {
			return true
		}
		// The one escaped slash allowed: inside a Bedrock ARN model ID
		// (GAP-0129).
		if esc, ok := strings.CutPrefix(raw, substrateLLMPrefix+"bedrock"); ok {
			_, ok := substrateBedrockARNPath(esc)
			return ok
		}
	}
	return false
}
