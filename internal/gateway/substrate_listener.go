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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ratelimit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
	"github.com/defenseclaw/defenseclaw/internal/substrate/revocation"
	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
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
	// substrateRelayTask takes a --task run's end (substrate_task.go).
	substrateRelayTask = "/api/v1/substrate/relay/task"
	// substrateRelayTamper takes a relay guard trip (substrate_task.go).
	substrateRelayTamper = "/api/v1/substrate/relay/tamper"
	// substrateRelayCert signs the relay's TLS serving certificate
	// (substrate_relaycert.go).
	substrateRelayCert = "/api/v1/substrate/relay/cert"
	substrateLLMPrefix = "/llm/"

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
	// Managed is a managed_enterprise deployment. It refuses an actor whose
	// agent signs in to a vendor account, because the token would sit in the
	// actor and its snapshots (E9); an open-source deployment allows it with
	// a warning.
	Managed bool
	// SecretPlaceholders maps bound secret names to the environment variable
	// names the actor carries in their place (substrate.secrets[].inject.
	// placeholder). Nil means no secret is bound to a vendor key.
	SecretPlaceholders func(names []string) []string
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
	// ProfileWhy says why the caller gets the profile they get (policy
	// explain with no agent named; nil leaves it out).
	ProfileWhy SubstrateProfileExplainer
	// WorkloadEntry names the match.substrate.workloads entry a workload
	// subject matches and its profile (SubstrateWorkloadEntry over the live
	// config); nil leaves the workload answer out of the actor list.
	WorkloadEntry func(subject string) (entry, profile string)
	// Usage answers the usage API (own rows; an administrator's all=1 reads
	// every owner). Nil: 501 usage_unavailable.
	Usage SubstrateUsage
	// UsageDisabled is substrate.usage.enabled: false: the usage API answers
	// 501 usage_disabled, and the replica counts no spend on the leader.
	UsageDisabled bool
	// SpendLeader moves this replica's budget spend and usage onto the
	// leader (nil: not a cluster replica, or usage disabled).
	SpendLeader SubstrateSpendLeader
	// UsageSyncInterval is substrate.usage.sync_interval (0: the default).
	UsageSyncInterval time.Duration
	// Bundles applies and shows signed policy bundles (nil: 501).
	Bundles SubstrateBundles
	// Activity receives the last-activity feed of A3's idle logic.
	Activity SubstrateActivitySink
	// ActivityFeed is the leader's activity snapshot, read by list and
	// status for the agent state (B3.6; nil: no activity in the answers).
	ActivityFeed SubstrateActivityFeed
	// ActivityConfig is the live substrate.activity block (nil: defaults).
	ActivityConfig func() config.SubstrateActivityConfig
	// Skills scans the skill folders the kit attaches (GAP-0039); nil
	// scans nothing.
	Skills SubstrateSkillScanner
	// BlockUnscannedSkills says whether a skill folder that reaches an
	// actor of this connector without a scan is refused (managed installs and
	// the strict tier) rather than alerted on (OSS default tiers).
	BlockUnscannedSkills func(connector string) bool
	// MCP is the runtime MCP scan of hook events (E20, GAP-0185); nil
	// turns it off. BlockUnscannedSkills is its fail mode too.
	MCP SubstrateMCPScanner
	// TemplateSkills returns the admitted skill folder digests of the attested
	// template "atespace/name" (the controller's verdict): a folder with one
	// of them is trusted without a scan (GAP-0164). Nil trusts none.
	TemplateSkills func(ctx context.Context, template string) ([]string, error)
	// SkillScanLimits returns skills.scan.timeout and skills.pending_wait
	// (B5.4); nil or 0 waits for the whole scan.
	SkillScanLimits func() (timeout, pendingWait time.Duration)
	// SkillReceiptKey signs skill scan receipts; every replica must have the
	// same key (derived from the shared chain key). Empty: a random key per
	// process, so receipts hold only on the replica that gave them.
	SkillReceiptKey []byte
	// Asks is the leader's ask and decision store (nil: 501).
	Asks SubstrateAskStore
	// SandboxClass is the isolation class an actor of profile must run in
	// (SubstrateSandboxClassFor: the profile floor's sandbox_class, never
	// weaker than substrate.default_sandbox_class). Create puts it on the
	// actor's worker selector when the template's class does not meet it.
	// nil: the template decides.
	SandboxClass func(profile string) string
	// UnattendedAsk is what an unattended actor's ask does for its profile
	// (SubstrateUnattendedAskFor; nil: deny, D12).
	UnattendedAsk func(profile string) SubstrateUnattendedAsk
	// Policies reads an actor's egress policy for policy explain.
	Policies SubstratePolicyReader
	// Relays reaches an actor's relay through the router for attach
	// (nil: attach answers 503).
	Relays SubstrateRelayDialer
	// RelayCA signs relay serving certificates and verifies them on attach
	// (B3.5, the gateway.relayCASecret Secret); nil: TLS relays cannot be
	// reached and /relay/cert answers relay_ca_missing.
	RelayCA *relaytls.CA
	// RelayTLS is substrate.relay_tls ("" is auto).
	RelayTLS relaytls.Mode
	// RelayCerts is the leader's record of the live relay serving
	// certificate per actor (GAP-0861), shared by every replica and kept
	// over restarts. nil: in refuse mode /relay/cert answers
	// relay_cert_record_unavailable; in flag mode every certificate asked
	// for without proof of the live key is a HIGH row.
	RelayCerts registry.RelayCerts
	// RelayCertReissue is the active substrate.relay_cert_reissue (refuse
	// or flag; "" is auto: refuse when Managed).
	RelayCertReissue string
	// Interactive is substrate.interactive in force (B3 port forward and
	// MCP bridge switches; nil: the defaults).
	Interactive func() config.SubstrateInteractiveConfig
	// WorkspaceMaxBytes caps a workspace upload through attach
	// (substrate.workspace_max_bytes, E23).
	WorkspaceMaxBytes int64
	// KeyReplay reads substrate.launcher.key_replay live for launchers
	// (B3.1); nil reports ask.
	KeyReplay func() string
	// UploadScan reads substrate.launcher.upload_scan live for launchers
	// (B1); nil reports the defaults.
	UploadScan func() config.SubstrateUploadScanConfig
	// FilesPush and FilesSync read substrate.files.push and .sync live;
	// nil reports on.
	FilesPush func() bool
	FilesSync func() bool
	// Revocations is this replica's copy of the ended sign-ins list,
	// RevocationSource the leader it pulls from and writes revokes to, and
	// Streams the open attach streams it closes on a revoke (B5.1). nil:
	// revocation is off (substrate.identity.revocation.enabled: false).
	Revocations      *revocation.Snapshot
	RevocationSource revocation.Source
	Streams          *revocation.Streams
	// Git reads substrate.git live for launchers (B2 2.5: the https
	// rewrite map, submodules, LFS); nil reports the defaults.
	Git func() config.SubstrateGitConfig
	// GitPush is allow, ask or deny for pull --push-branch from an actor
	// of profile (SubstrateGitPushFor, read live; B2 2.4). nil: the push
	// route answers push_unavailable.
	GitPush func(profile string) string
	// PushGrants opens and closes the leader's push grants (GAP-1073): an
	// allowed pull --push-branch that asks for one (?grant=1) gets a grant
	// the egress callout enforces. nil: no grant, and the launcher warns.
	PushGrants SubstratePushGrants
	// Doctor runs the gateway-side doctor checks; Info is the
	// unauthenticated sign-in information (issuer, client_id, sign_in).
	Doctor func(ctx context.Context) []SubstrateCheck
	Info   map[string]any
	// EgressCallout is who holds Substrate's egress callout slot, as the
	// controller last reported it through the leader (nil: not reported).
	// /info carries its class and the checks that are off, /doctor the
	// holder (GAP-0497).
	EgressCallout func(ctx context.Context) (controller.CalloutStatus, bool)
	// SignInServer is the OIDC issuer people sign in with (nil: none
	// configured). The gateway checks it from its own network every
	// signInCheckEvery; /info names a failing cause, /doctor the detail,
	// and a sign-in the gateway cannot verify names the cause (GAP-0262).
	SignInServer SubstrateSignInServer
	// Secrets are substrate.secrets; SecretStore writes Kubernetes-backed
	// values (nil: list only).
	Secrets     []config.SubstrateSecret
	SecretStore SubstrateSecretStore
	// Bindings is the self-service binding store (nil when
	// self_service_secrets.mode is off); SelfService and SecretTemplates
	// are its config, NoSwapHosts substrate.egress.no_swap_hosts.
	Bindings        *secretbind.Store
	SelfService     config.SubstrateSelfServiceSecretsConfig
	SecretTemplates []config.SubstrateSecretTemplate
	// LiveSelfService, when set, is the self-service config and template
	// catalog in force now (config.yaml applied live): mode, limits, asks
	// and templates follow it; namespace and provider stay the boot ones.
	LiveSelfService func() (config.SubstrateSelfServiceSecretsConfig, []config.SubstrateSecretTemplate)
	// LiveNoSwapHosts, when set, is substrate.egress.no_swap_hosts as the
	// gateway follows config.yaml; NoSwapHosts is the boot value.
	LiveNoSwapHosts func() []string
	NoSwapHosts     []string
	// SecretAudit receives each typed secret change record
	// (log.substrate.secret.changed); nil sends it to the gateway's
	// sandbox recorder. Tests capture it here.
	SecretAudit func(context.Context, audit.SubstrateSecretChangeEvent)
	// Chains is the leader's chain and intent state (lane A13): a verified
	// actor's tool-chain windows and the judge's session intent live there,
	// so every replica sees the same. Nil turns the chain lane off for
	// actors and keeps the judge's intent per process.
	Chains *chainstate.Client
	// Relay takes the records the leader collects from the controller, the
	// callout and its own lifecycle feed; RunSubstrate records each batch
	// through this replica's telemetry runtime (GAP-0450, GAP-0453). Nil:
	// nothing is relayed.
	Relay *telemetryrelay.Taker
	// SecretUses reads when the caller's agents last reached each host,
	// for the last use secrets list and test show (S6b). Nil: no last use.
	SecretUses SubstrateSecretUses
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
	// SubstrateActivityTaskEnd marks the end of an actor's --task run: the
	// controller frees the actor's worker (GAP-0274).
	SubstrateActivityTaskEnd = "task_end"
	// SubstrateActivityAttach is an open terminal attachment, reported
	// about every minute while the attach route proxies it: a controller
	// without a CPU feed does not suspend an attached actor (GAP-0534).
	SubstrateActivityAttach = "attach"
)

type substrateState struct {
	cfg SubstrateConfig
	// activityAsks remembers a failed pending-asks read of list and status
	// (GAP-1018).
	activityAsks substrateActivityAsksDown
	// taskEnds bounds the task-end audit rows per actor.
	taskEnds substrateTaskEnds
	// streams counts the open port forwards and MCP bridges per actor on
	// this replica (GAP-0818), and serializes over-cap MCP judging.
	streams substrateStreamCounts
	// refusals bounds refusal log lines: a flood of bad tokens is still
	// refused, not logged line by line.
	refusals *rate.Limiter
	// audit writes a substrate audit row through the API server's logger
	// (none while it has no logger).
	audit func(ctx context.Context, severity, summary string, details map[string]any)
	// logOut is the gateway log (stderr); now is the clock. Tests set both.
	logOut io.Writer
	now    func() time.Time
	// budget is the BUDGET cell of an agent (substrateActorBudget); nil
	// when the server has no live config.
	budget func(reg registry.Registration) string
	// readBudgets reads the budget keys of regs before a view
	// (substrateReadBudgetKeys); nil with budget.
	readBudgets func(ctx context.Context, regs []registry.Registration)

	// receiptKey signs skill scan receipts (substrate_skills.go);
	// receiptShared says every replica has it.
	receiptKey    []byte
	receiptShared bool
	// alert raises an audit alert (the API server's logger).
	alert func(ctx context.Context, severity, summary string, details map[string]any)
	// action writes one skill audit row (B5.4: substrate.skill.*).
	action func(ctx context.Context, action, severity string, details map[string]any)
	// scanMu guards scans, the skill scans in flight (B5.4 pending), their
	// count per actor UID (GAP-0932) and scanFree, closed when one ends.
	scanMu     sync.Mutex
	scans      map[string]*skillScanCall
	scanActors map[string]int
	scanFree   chan struct{}
	// scanKept is the outcome of a managed or strict scan that ended after
	// its post stopped waiting (a held folder, GAP-0980), for the next post
	// of that content, and heldSince is when that content was first held:
	// a hold ends at skills.scan.timeout, whatever the scanner does.
	scanKept  map[string]skillScanKept
	heldSince map[string]time.Time
	// alerted is alertOnce's memory (substrate_skills.go).
	alertMu    sync.Mutex
	alerted    map[string]bool
	pending    map[string]int
	pendingOld map[string]int

	// tokens remembers cluster-wide actor token refusals (the key set,
	// the issuer, the control API), which /info reports so a launcher
	// never calls a task finished whose every call was refused (GAP-0194).
	tokens actorTokenHealth
	// signIn is the last check of the OIDC sign-in server (GAP-0262).
	signIn signInHealth
	// calloutView is the hook path's last read of the egress callout slot
	// (GAP-0505, substrate_callout_note.go).
	calloutView substrateCalloutView

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
		if cfg.Chains != nil {
			// The fair-share budgets are the actor's across the gateway
			// replicas, counted through the leader (GAP-0566).
			cfg.Limiter.ShareThrough(cfg.Chains.RateShare)
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
	st.budget = func(reg registry.Registration) string {
		now := time.Now()
		if st.now != nil {
			now = st.now()
		}
		return substrateActorBudget(a.liveConfig(), reg, now)
	}
	st.readBudgets = func(ctx context.Context, regs []registry.Registration) {
		substrateReadBudgetKeys(ctx, a.liveConfig(), regs)
	}
	st.audit = func(ctx context.Context, severity, summary string, details map[string]any) {
		if a.logger != nil {
			_ = a.logger.LogAlertCtx(ctx, "substrate", severity, summary, details)
		}
	}
	st.action = func(ctx context.Context, action, severity string, details map[string]any) {
		if a.logger != nil {
			raw, _ := json.Marshal(details)
			_ = a.logger.LogActionCtxSeverity(ctx, action, fmt.Sprint(details["folder"]), string(raw), severity)
		}
	}
	st.alert = func(ctx context.Context, severity, summary string, details map[string]any) {
		st.audit(ctx, severity, summary, details)
		st.logRefusal("%s: %v", summary, details["folder"])
	}
	if cfg.Revocations != nil {
		// RV1-07: the leader's list of ended sign-ins was reset (its volume
		// was recreated, or the file moved aside). Say so; the replica
		// keeps what it knew until it lapses.
		cfg.Revocations.OnReset(func(kept int) {
			summary := fmt.Sprintf("the leader's list of ended sign-ins was reset: this replica keeps the %d end(s) it knew until they lapse; a replica that starts now does not know them", kept)
			st.audit(context.Background(), "HIGH", summary, map[string]any{"event": "substrate.signin.list_reset", "kept": kept})
			st.logRefusal("%s", summary)
		})
	}
	a.substrateMu.Lock()
	a.substrate = st
	a.substrateMu.Unlock()
	if cfg.Chains != nil && cfg.Chains.ObserveLatency == nil {
		cfg.Chains.ObserveLatency = a.recordSubstrateLeaderObserve
	}
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
	if st.cfg.Relay != nil {
		st.cfg.Relay.Record = a.recordSubstrateRelay
		// GAP-0486: the leader knows this replica before it serves a hook
		// call. Bounded: a leader out of reach only delays the marks.
		jctx, cancel := context.WithTimeout(ctx, substrateRelayJoinWait)
		_ = st.cfg.Relay.Join(jctx)
		cancel()
		go st.cfg.Relay.Run(ctx)
	}
	if st.cfg.SignInServer != nil {
		go st.watchSignIn(ctx)
	}
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
	// task is the relay's task-end report (relay is set too).
	task bool
	// tamper is the relay's guard trip report (relay is set too).
	tamper bool
	// cert is the relay's certificate request (relay is set too).
	cert bool
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
	case path == substrateRelayTask:
		return substrateActorRoute{relay: true, task: true}, true
	case path == substrateRelayTamper:
		return substrateActorRoute{relay: true, tamper: true}, true
	case path == substrateRelayCert:
		return substrateActorRoute{relay: true, cert: true}, true
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
		start := time.Now()
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
			st.authRefused(r, substrateListenerActor, identity.ReasonMissing)
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
			st.authRefused(r, substrateListenerActor, reason)
			st.tokens.refused(reason, time.Now())
			writeSubstrateRefusal(w, status, string(reason))
			return
		}
		st.tokens.verified(time.Now())
		// The fair-share limits run right after the token check, before
		// the registration lookup and the envelope read, so a flooding
		// actor costs no leader call and no body read (GAP-0057).
		release, lerr := st.cfg.Limiter.Acquire(actor.Atespace, actor.UID)
		if lerr != nil {
			scope, _ := ratelimit.IsLimited(lerr)
			a.recordSubstrateRateLimited()
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
		// E9: an actor made some other way than the launcher still gets
		// nothing from a managed gateway when its agent signs in to a vendor
		// account.
		if d := st.cfg.signinDecision(reg.Connector, reg.Secrets); !d.Allowed {
			st.logRefusal("actor %s refused: %s (%s)", actor.Ref(), substrateSigninRefusedCode, reg.Connector)
			writeSubstrateSigninRefusal(w, d)
			return
		}
		ctx := withSubstrateActor(r.Context(), verifiedSubstrateActor(actor.Atespace, actor.Name, actor.UID, actor.Subject, key))
		ctx = context.WithValue(ctx, substrateRegistrationKey{}, reg)
		w.Header().Set(substrateModeHeader, substrateMode(reg))
		w.Header().Set(substrateFailModeHeader, substrateFailMode(st.cfg, reg))
		hook := route.class == sandboxauth.RouteHook && r.Method == http.MethodPost
		var claim *substrateResumeClaim
		if hook && st.cfg.Relay != nil && st.cfg.Relay.Resumes().Hook(actor.UID, start) {
			// Maybe its first hook call after a resume: the leader decides,
			// while the call is served (GAP-0486).
			claim = startSubstrateResumeClaim(st.cfg.Relay, actor.UID, start)
			ctx = withFirstHookAfterResume(ctx, claim)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
		if hook {
			// A hook call; the kit's GET warm-up pings are not counted.
			d := time.Since(start)
			a.recordSubstrateHookRTT(d)
			if claim.isFirst() {
				a.recordSubstrateFirstHookAfterResume(d)
			}
		}
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

// substrateRouteName is the closed route name of an actor request (llm,
// relay or the route class). The auth-refusal audit row and its window key
// use it; caller text never does.
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
		if route.llm || route.task || route.tamper || route.class == sandboxauth.RouteHook || route.class == sandboxauth.RouteNotify || route.class == sandboxauth.RouteInspect {
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
			// While a model stream is open the agent is thinking: report it
			// every 10 s. Off (status_window 0s) adds no timer.
			if route.llm && st.activityConfig().EffectiveStatusWindow() > 0 {
				defer substrateReportOpenModel(st.cfg.Activity, actor.Atespace, actor.UID)()
			}
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
		// The person's principal on the records' identity group
		// (defenseclaw.user.principal, identity.source oidc, assurance
		// verified): the registration holds what the OIDC token verified
		// (GAP-0454). It feeds telemetry only, never profile selection.
		ctx = context.WithValue(ctx, substratePersonIdentityKey{}, substratePersonIdentity{userID: id.UserID, principal: reg.Person.Principal})
	}
	return ContextWithAgentIdentity(ctx, id)
}

type substratePersonIdentityKey struct{}

type substratePersonIdentity struct{ userID, principal string }

// substrateRequestIdentity is the identity group of a record of userID on a
// request a verified actor made for its person.
func substrateRequestIdentity(ctx context.Context, userID string) (*llmEventIdentity, bool) {
	p, ok := ctx.Value(substratePersonIdentityKey{}).(substratePersonIdentity)
	if !ok || p.userID == "" || p.userID != userID || strings.TrimSpace(p.principal) == "" {
		return nil, false
	}
	return &llmEventIdentity{Directory: useridentity.DirectoryFacts{Principal: p.principal,
		Source: useridentity.SourceOIDC, Assurance: useridentity.AssuranceVerified}}, true
}

func (a *APIServer) serveSubstrateActorRoute(w http.ResponseWriter, r *http.Request) {
	route := substrateRouteFrom(r.Context())
	st := a.substrateState()
	switch {
	case route.task:
		a.serveSubstrateRelayTask(st, w, r)
		return
	case route.tamper:
		a.serveSubstrateRelayTamper(st, w, r)
		return
	case route.cert:
		a.serveSubstrateRelayCert(st, w, r)
		return
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

// substrateWorkloadSubject is the OIDC subject of the CI workload a verified
// actor was started by (its registration's person), "" for a person or no
// registration (GAP-0540).
func substrateWorkloadSubject(ctx context.Context) string {
	if _, ok := substrateActorFrom(ctx); !ok {
		return ""
	}
	reg, ok := substrateRegistrationFrom(ctx)
	if !ok || reg.Attributed || reg.Person.Kind != identity.PersonWorkload {
		return ""
	}
	return reg.Person.Subject
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
	st.logLine(format, args...)
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
