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

// Package hookexec runs DefenseClaw agent hooks natively in Go instead of via
// the bundled Bash hook scripts. It is the execution path used on Windows,
// where agents invoke the DefenseClaw binary directly (no Git Bash, no .cmd
// wrapper, no jq, and no PATH lockdown — because Go never shells out).
//
// The behavior here mirrors the .sh hooks under internal/gateway/connector/hooks:
// the same gateway endpoint, per-connector stdout shape and exit code, and the
// same fail-open-on-outage / fail-closed-on-misconfig policy. Native transport
// deadlines may follow the agent's registered event budget. Unix keeps using
// the .sh hooks unchanged; golden tests pin the shared decision contract.
package hookexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// blockExit is the failure/block exit used by connectors whose upstream hook
// contracts interpret process status. Hermes is explicitly excluded: it only
// blocks through valid synchronous JSON written to stdout.
const blockExit = 2

// defaultMaxBody caps how many bytes of the agent's hook payload we read from
// stdin before refusing it, matching DEFENSECLAW_HOOK_MAX_BODY in the .sh
// hooks (1 MiB). A 1 MiB+ hook event is well outside any legitimate payload
// and silently truncating it would yield a confusing downstream parse error.
const defaultMaxBody int64 = 1 << 20

const (
	defaultHookRequestTimeout = 10 * time.Second
	hookResponseGrace         = time.Second
)

var (
	errInvalidHookRequest           = errors.New("invalid hook request")
	errManagedGatewayPeerUnverified = errors.New("enterprise managed gateway peer unverified")
	// errManagedGatewayNotRunning wraps a peer-verification failure whose
	// cause is that the managed gateway service is not running (Windows SCM
	// reports it stopped). The hook still fails closed.
	errManagedGatewayNotRunning = errors.New("enterprise managed gateway service is not running")
)

const managedGatewayPeerUnverifiedReason = "enterprise_managed_gateway_peer_unverified"

// managedGatewayNotRunningReason is the hook-failure reason of a Windows
// standalone managed hook whose gateway service is stopped, instead of
// managedGatewayPeerUnverifiedReason. Secure Client keeps the latter.
const managedGatewayNotRunningReason = "enterprise_managed_gateway_not_running"

const (
	codexBoundEventHeader    = "X-DefenseClaw-Hook-Event"
	codexBoundContractHeader = "X-DefenseClaw-Hook-Contract"
)

// HookDialectHeader carries the --hook-surface value of the hook
// configuration that invoked this hook: the payload and veto dialect the
// gateway decodes it with. It is one header for every connector; each
// connector lists the values it accepts (hookDialects). Kiro's bash hook
// (kiro-hook.sh) keeps sending the older X-DefenseClaw-Kiro-Surface header,
// which the gateway still reads.
const HookDialectHeader = "X-DefenseClaw-Hook-Dialect"

// AgentHostHeader carries the name of the process that started the agent
// (agentprocess.Host), sent only by a managed enterprise hook. The gateway
// records it in the hook audit so a desktop app's embedded agent (Devin
// Local under Devin Desktop) is told apart from the same agent run in a
// terminal. The user can influence it: it is attribution, never policy.
const AgentHostHeader = "X-DefenseClaw-Agent-Host"

// AgentSurfaceHeader carries the surface (cli, desktop or extension) a
// standalone enterprise hook classified its caller as
// (connector.ClassifyAgentSurface). Under
// enterprise.enrollment.unverified_versions: refuse the gateway refuses a
// call from an app or extension surface whose hook delivery is not
// live-verified (SurfaceUnverifiedReason). The user can influence it: it
// enforces the administrator's surface policy for honest callers, and an
// unclassified call omits it.
const AgentSurfaceHeader = "X-DefenseClaw-Agent-Surface"

// AgentSurfaceHeaderValue returns surface when it is cli, desktop or
// extension, else "".
func AgentSurfaceHeaderValue(surface string) string {
	switch surface = strings.ToLower(strings.TrimSpace(surface)); surface {
	case "cli", "desktop", "extension":
		return surface
	}
	return ""
}

// SurfaceUnverifiedReason is the gateway's refusal reason for a hook call
// from a surface refused under unverified_versions: refuse.
const SurfaceUnverifiedReason = "enterprise_managed_surface_unverified"

// maxAgentHostLength bounds AgentHostHeaderValue.
const maxAgentHostLength = 64

// AgentHostHeaderValue reduces a process name to a bounded header token:
// lowercase [a-z0-9._-], any other character becoming "-". It returns ""
// when nothing but separators is left.
func AgentHostHeaderValue(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	for _, r := range name {
		if b.Len() >= maxAgentHostLength {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if strings.Trim(b.String(), "-._") == "" {
		return ""
	}
	return b.String()
}

// hookDialects lists, per connector, the values --hook-surface may carry:
// the hook dialects that connector's installed configuration speaks. Kiro
// marks the .kiro/hooks configuration that Kiro IDE and `kiro-cli --v3` read
// with v3 (connector.KiroHookSurfaceV3); its CLI 2.x agent configuration is
// left unmarked, so v2 is never rendered.
var hookDialects = map[string][]string{
	"kiro": {"v3"},
	// The VS Code Local harness reads the Copilot hook directories but
	// speaks its own PascalCase, snake_case dialect
	// (connector.CopilotHookSurfaceVSCodeLocal).
	"copilot": {copilotVSCodeLocalSurface},
}

// copilotVSCodeLocalSurface is connector.CopilotHookSurfaceVSCodeLocal.
const copilotVSCodeLocalSurface = "vscode-local"

// copilotVSCodeLocal reports a hook command registered for the VS Code Local
// harness rather than the Copilot CLI.
func copilotVSCodeLocal(opts Options) bool {
	return opts.Connector == "copilot" && hookDialect(opts) == copilotVSCodeLocalSurface
}

// HookSurfaceAllowed reports whether connector lists surface as a
// --hook-surface value. The CLI refuses any other value before Run.
func HookSurfaceAllowed(connector, surface string) bool {
	surface = strings.TrimSpace(surface)
	for _, allowed := range hookDialects[strings.ToLower(strings.TrimSpace(connector))] {
		if surface == allowed {
			return true
		}
	}
	return false
}

// hookDialect returns opts.HookSurface when the connector lists it.
func hookDialect(opts Options) string {
	if !HookSurfaceAllowed(opts.Connector, opts.HookSurface) {
		return ""
	}
	return strings.TrimSpace(opts.HookSurface)
}

// Options configures a single hook invocation. The CLI entrypoint fills these
// from flags + environment; tests construct them directly so the full decision
// matrix can be exercised without a real gateway or agent.
type Options struct {
	// Connector is the logical connector name, e.g. "claudecode", "codex".
	Connector string
	// Event is the agent hook event used for deadlines and failure logs. Claude
	// Code supplies it in the payload when the CLI flag is omitted.
	Event string
	// HookContractID is the finite Setup-selected connector contract bound into
	// the protected native Windows command. Codex uses it to prevent local
	// failure paths from backfilling newer lifecycle controls into legacy tiers.
	HookContractID string
	// HookSurface is the hook dialect the invoking hook configuration speaks
	// (--hook-surface; Kiro's .kiro/hooks configuration passes "v3"). It is
	// forwarded in HookDialectHeader when the connector lists the value.
	HookSurface string
	// APIAddr is the gateway "host:port" the hook posts to.
	APIAddr string
	// FailMode is "open" or "closed"; it governs invalid responses
	// (4xx / bad JSON) and transport failures. StrictAvailability forces
	// closed independently. Empty defaults to "open".
	FailMode string

	// Home is DEFENSECLAW_HOME (default ~/.defenseclaw). If it does not exist
	// or contains a .disabled file the hook is a no-op (exit 0).
	Home string
	// HookDir holds connector-scoped and legacy token sidecars (default Home/hooks).
	HookDir string
	// Token, when set, is the resolved gateway token (e.g. from the
	// DEFENSECLAW_GATEWAY_TOKEN env var). A connector-scoped token file takes
	// precedence so an inherited generic gateway token cannot shadow the
	// narrower credential; Token still precedes the legacy .token fallback.
	Token string
	// AuthenticatedManagedToken is the connector-scoped token captured from
	// the same authenticated, immutable managed-runtime generation as the
	// endpoint and service identity. A non-nil value is an explicit mode
	// assertion: ManagedEnterprise execution must use this snapshot directly
	// and must not probe or reread mutable legacy token sidecars. A nil value
	// preserves the legacy resolution path; a non-nil empty value fails closed.
	// It is ignored outside ManagedEnterprise mode.
	AuthenticatedManagedToken *string

	// StrictAvailability mirrors DEFENSECLAW_STRICT_AVAILABILITY: when true,
	// transport failures and a missing token fail closed instead of open.
	StrictAvailability bool
	// ManagedEnterprise marks an administrator-enrolled native hook. User
	// deletion of Home or creation of Home\.disabled is tampering, not an
	// operator-requested no-op, and must therefore fail closed.
	ManagedEnterprise bool
	// AgentHost is the name of the process that started the agent; it is
	// sent (AgentHostHeader) only with ManagedEnterprise.
	AgentHost string
	// AgentSurface is the surface the hook classified its caller as
	// (AgentSurfaceHeader); "" when unclassified.
	AgentSurface string
	// ManagedRuntimeFailure is a stable, non-sensitive resolver diagnostic
	// selected before target-owned runtime files are consulted.
	ManagedRuntimeFailure string
	// ExplainUnenrolledAccount makes the refusal of an account absent from
	// the protected target set (managedSIDUnregisteredReason), or registered
	// but without a runtime yet (managedEnrollmentPendingReason), say so,
	// not "gateway unreachable". The Windows standalone hook sets it; Secure
	// Client keeps its message.
	ExplainUnenrolledAccount bool
	// ManagedGatewayServiceName is the administrator-protected SCM identity
	// that must own the connected loopback listener before any HTTP bytes are
	// written. It is ignored outside ManagedEnterprise mode.
	ManagedGatewayServiceName string
	// ManagedStandalone selects the unix standalone-profile transport: the
	// hook trusts the gateway only after the kernel reports that the
	// listener runs as root or ManagedServiceUID. It is ignored outside
	// ManagedEnterprise mode. It is also set, with ManagedRuntimeFailure,
	// when the standalone runtime failed its checks: no transport is then
	// selected, and the failure gets the standalone profile's fail-closed
	// results (managedStandaloneStopEvent).
	ManagedStandalone bool
	// ManagedUnixSocket is the standalone hook socket. The standalone hook
	// dials only this socket and sends no bearer token: the gateway
	// authorizes the caller by its kernel-verified uid. It is required with
	// ManagedStandalone; an empty value fails closed rather than selecting
	// loopback TCP.
	ManagedUnixSocket string
	// ManagedServiceUID is the gateway service account uid from the
	// root-owned runtime descriptor.
	ManagedServiceUID int

	// MaxBody overrides the stdin cap in bytes (default defaultMaxBody).
	MaxBody int64

	// TraceParent / TraceState are W3C trace-context candidates forwarded to
	// the gateway after validation (invalid values are dropped, never sent).
	TraceParent string
	TraceState  string

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// HTTPClient lets tests inject a stub transport. When nil a client with a
	// 2s connect timeout and a connector/event-specific total budget is used.
	HTTPClient *http.Client
	// GatewayRecovery is installed only by the protected native Windows hook
	// launcher. After an exact connection-refused result, it may start and wait
	// for the installer-owned gateway. Run invokes it at most once and retries
	// the original authenticated hook request once within the same deadline.
	GatewayRecovery func(context.Context, error) error
	// Now is injectable for deterministic failure-log timestamps in tests.
	Now func() time.Time
	// StartedAt, when set, is when the hook process began work the
	// request budget must include (the standalone foreign-hook guard's scan
	// runs before Run). Zero starts the budget when Run is called.
	StartedAt time.Time
}

// Run executes the hook described by opts and returns the process exit code.
// Connector-native stdout is the enforcement surface when the upstream
// contract defines one. In particular, Antigravity blocking is expressed only
// by synchronous PreToolUse stdout {"decision":"deny"}; no Antigravity
// behavior relies on a non-zero process exit code.
func Run(ctx context.Context, opts Options) int {
	startedAt := opts.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	opts = withDefaults(opts)

	sp, ok := specFor(opts.Connector)
	if ok && copilotVSCodeLocal(opts) {
		sp = copilotVSCodeLocalSpec
	}
	if !ok {
		// Unknown connector is a wiring bug, not a policy decision. Fail loud
		// so it surfaces in tests / setup rather than silently disabling the
		// guardrail. The CLI validates --connector against the registry, so
		// this is unreachable in normal operation.
		fmt.Fprintf(opts.Stderr, "defenseclaw: unknown hook connector %q\n", opts.Connector)
		return blockExit
	}
	failMode := normalizeFailMode(opts.FailMode)
	if opts.ManagedEnterprise && strings.TrimSpace(opts.ManagedRuntimeFailure) != "" {
		reason := strings.TrimSpace(opts.ManagedRuntimeFailure)
		if strings.HasPrefix(reason, ForeignHookBlockedReasonPrefix) {
			return failForeignHookBlocked(opts, sp, reason)
		}
		resolveManagedStandaloneFailureEvent(&opts, sp)
		if opts.ExplainUnenrolledAccount && !sp.failOpenOnly &&
			(reason == managedSIDUnregisteredReason || reason == managedEnrollmentPendingReason) {
			return failUnenrolled(opts, sp, reason)
		}
		return failUnreachable(
			opts,
			sp,
			"closed",
			reason,
		)
	}

	// DEFENSECLAW_HOME guard: an ordinary removed/disabled installation is an
	// intentional no-op. Administrator-managed hooks carry ManagedEnterprise
	// (and invalid runtimes also set StrictAvailability), so a missing or
	// disabled machine-policy home must block instead of bypassing enforcement.
	if info, err := os.Stat(opts.Home); err != nil || !info.IsDir() {
		if opts.ManagedEnterprise {
			resolveManagedStandaloneFailureEvent(&opts, sp)
			return failUnreachable(
				opts,
				sp,
				"closed",
				"enterprise_managed_runtime_home_missing",
			)
		}
		return handleUnavailableHome(opts, sp, "DefenseClaw home is unavailable")
	}
	if _, err := os.Stat(filepath.Join(opts.Home, ".disabled")); err == nil {
		if opts.ManagedEnterprise {
			resolveManagedStandaloneFailureEvent(&opts, sp)
			return failUnreachable(
				opts,
				sp,
				"closed",
				"enterprise_managed_runtime_disable_sentinel_forbidden",
			)
		}
		return handleUnavailableHome(opts, sp, "DefenseClaw home is disabled")
	}

	payload, overflow, err := readCapped(opts.Stdin, opts.MaxBody)
	if err != nil {
		// stdin read error is treated like an oversized/unusable payload.
		overflow = true
	}
	if overflow {
		return handleOversized(opts, sp, failMode)
	}
	if strings.EqualFold(strings.TrimSpace(opts.Connector), "codex") {
		event, bindingErr := validateCodexInvocationBinding(
			opts.Event,
			opts.HookContractID,
			payload,
		)
		opts.Event = strings.TrimSpace(opts.Event)
		if bindingErr != nil {
			return failResponse(opts, sp, failMode, bindingErr.Error())
		}
		opts.Event = event
	} else if strings.EqualFold(strings.TrimSpace(opts.Connector), "antigravity") {
		opts.Event = strings.TrimSpace(opts.Event)
		if !validAntigravityEvent(opts.Event) {
			// Antigravity's official stdin schemas do not carry event identity.
			// Setup binds a reviewed event into each protected command; never
			// accept a payload-selected substitute when that binding is absent.
			return failResponse(opts, sp, "open", "missing or unsupported Antigravity hook event binding")
		}
	} else {
		opts.Event = resolveHookEvent(opts.Event, payload)
	}
	if opts.Connector == "copilot" && !validCopilotEventForOptions(opts) {
		// Copilot's official camelCase stdin bodies do not identify the
		// event. Setup supplies the reviewed event through an exact --event
		// binding; never infer it from a body field or forward an untrusted
		// registration. This is a local integration failure, so Copilot must
		// receive its documented fail-open result.
		return failResponse(opts, sp, failMode, "missing or unsupported Copilot hook event binding")
	}
	requestTimeout := hookRequestTimeout(opts.Connector, opts.Event) - time.Since(startedAt)
	if requestTimeout <= 0 {
		return failUnreachable(opts, sp, failMode, "hook request budget exhausted before gateway contact")
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	if opts.ManagedEnterprise && opts.ManagedStandalone && strings.TrimSpace(opts.ManagedUnixSocket) == "" {
		// The standalone profile has exactly one hook transport, the
		// peer-authorized unix socket. Without it there is nothing this
		// hook may contact: never fall back to loopback TCP or a token.
		return failUnreachable(opts, sp, "closed", managedGatewayPeerUnverifiedReason)
	}
	if opts.HTTPClient == nil {
		if opts.ManagedEnterprise {
			var err error
			if opts.ManagedStandalone {
				opts.HTTPClient, err = managedStandaloneHTTPClient(
					requestTimeout,
					opts.ManagedUnixSocket,
					opts.ManagedServiceUID,
				)
			} else {
				opts.HTTPClient, err = managedEnterpriseHTTPClient(
					requestTimeout,
					opts.APIAddr,
					opts.ManagedGatewayServiceName,
				)
			}
			if err != nil {
				return failUnreachable(opts, sp, "closed", managedGatewayPeerUnverifiedReason)
			}
		} else {
			opts.HTTPClient = defaultHTTPClient(requestTimeout)
		}
	}

	// Cursor 2.4+ imports Claude Code hooks while also running its native
	// Cursor hooks. The imported invocation is still a Cursor event and carries
	// a top-level cursor_version marker. When DefenseClaw's live Cursor bridge
	// is installed, let that bridge be the sole policy and telemetry owner so
	// the same event is not also attributed to Claude Code. Keep this before the
	// missing-token branch: a missing Claude token must not fail-closed an
	// imported Cursor copy that the Cursor bridge is already handling.
	if suppressCursorCompatibilityImport(opts, payload) {
		return 0
	}

	var token string
	if opts.ManagedEnterprise && opts.ManagedStandalone {
		// The standalone hook socket authenticates this process by its
		// kernel-verified uid. No bearer is read or sent, so there is no
		// user-readable credential to steal or replay.
		return doRequest(ctx, opts, sp, failMode, payload, "")
	}
	if opts.ManagedEnterprise && opts.AuthenticatedManagedToken != nil {
		// The resolver authenticated this token as part of one immutable
		// runtime generation. Do not touch the legacy token paths here: doing
		// so would split authority across generations after validation.
		token = *opts.AuthenticatedManagedToken
		if strings.TrimSpace(token) == "" {
			return failUnreachable(
				opts,
				sp,
				"closed",
				"authenticated managed runtime token is empty",
			)
		}
	} else {
		// Missing-token branch: only taken when BOTH the env token is empty AND
		// the resolved token sidecar is absent. (An empty token inside an existing
		// file is intentionally NOT a missing token — it selects the loopback
		// no-auth path, same as the .sh.)
		tokenFile, scopedTokenFile := hookTokenFile(opts.HookDir, opts.Connector)
		if opts.Token == "" && !fileExists(tokenFile) {
			return handleMissingToken(opts, sp, failMode, missingTokenFile(opts.HookDir, opts.Connector, tokenFile))
		}

		token = opts.Token
		if scopedTokenFile || token == "" {
			loaded, readErr := readTokenFileForModeE(
				tokenFile,
				scopedTokenFile,
				opts.ManagedEnterprise,
			)
			if readErr != nil && opts.ManagedEnterprise {
				// Managed enterprise mode must not silently omit Authorization when
				// the token sidecar is present but unreadable, malformed, or fails a
				// stability/identity check. Fail closed so unauthenticated loopback
				// requests never sneak past connector-side auth.
				return failUnreachable(opts, sp, "closed", "managed hook token unreadable")
			}
			if opts.ManagedEnterprise && strings.TrimSpace(loaded) == "" {
				// An empty sidecar parses without error but sendHookRequest would
				// then omit Authorization entirely and the connector-side loopback
				// path would accept the credential-less request. Managed mode has
				// no no-auth path, so fail closed here.
				return failUnreachable(opts, sp, "closed", "managed hook token empty")
			}
			token = loaded
		}
	}

	return doRequest(ctx, opts, sp, failMode, payload, token)
}

// RunCodexNotify forwards the JSON payload Codex appends to its configured
// `notify` argv array. Notifications are telemetry-only and deliberately
// best-effort: every local/configuration/transport/response failure returns 0,
// matching the legacy Bash bridge's `curl ... || true` contract.
func RunCodexNotify(ctx context.Context, opts Options, payload []byte) int {
	opts = withDefaults(opts)
	if info, err := os.Stat(opts.Home); err != nil || !info.IsDir() {
		return 0
	}
	if _, err := os.Stat(filepath.Join(opts.Home, ".disabled")); err == nil {
		return 0
	}
	if len(payload) == 0 || int64(len(payload)) > opts.MaxBody {
		return 0
	}

	var token string
	if opts.ManagedEnterprise && opts.AuthenticatedManagedToken != nil {
		token = *opts.AuthenticatedManagedToken
		if strings.TrimSpace(token) == "" {
			// Notifications remain best-effort, but authenticated managed mode
			// must never fall back to a different generation's token sidecar.
			fmt.Fprintln(opts.Stderr, "authenticated managed runtime token is empty")
			return 0
		}
	} else {
		tokenFile, scopedTokenFile := hookTokenFile(opts.HookDir, "codex")
		if opts.Token == "" && !fileExists(tokenFile) {
			return 0
		}
		token = opts.Token
		if scopedTokenFile || token == "" {
			token = readTokenFileForMode(
				tokenFile,
				scopedTokenFile,
				opts.ManagedEnterprise,
			)
		}
	}

	if perUserForeignListener(opts) > 0 {
		return 0
	}
	notifyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(notifyCtx, http.MethodPost,
		"http://"+opts.APIAddr+"/api/v1/codex/notify", bytes.NewReader(payload))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "codex-notify/1.0")
	req.Header.Set("x-defenseclaw-source", "codex-notify")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if v := strings.TrimSpace(opts.TraceParent); v != "" && validTraceparent(v) {
		req.Header.Set("traceparent", v)
	}
	if v := strings.TrimSpace(opts.TraceState); v != "" && validTracestate(v) {
		req.Header.Set("tracestate", v)
	}
	if opts.HTTPClient == nil {
		if opts.ManagedEnterprise {
			var err error
			opts.HTTPClient, err = managedEnterpriseHTTPClient(
				defaultHookRequestTimeout,
				opts.APIAddr,
				opts.ManagedGatewayServiceName,
			)
			if err != nil {
				fmt.Fprintln(opts.Stderr, managedGatewayPeerUnverifiedReason)
				return 0
			}
		} else {
			opts.HTTPClient = defaultHTTPClient(defaultHookRequestTimeout)
		}
	}

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		if opts.ManagedEnterprise && errors.Is(err, errManagedGatewayPeerUnverified) {
			fmt.Fprintln(opts.Stderr, managedGatewayPeerUnverifiedReason)
		}
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, defaultMaxBody))
	return 0
}

// doRequest performs the gateway POST and dispatches the response through the
// connector-specific decision logic, applying the transport vs response
// failure split exactly like the .sh hooks.
func doRequest(ctx context.Context, opts Options, sp spec, failMode string, payload []byte, token string) int {
	if pid := perUserForeignListener(opts); pid > 0 {
		return failUnreachable(opts, sp, failMode, foreignListenerReason(opts.APIAddr, pid))
	}
	ctx, stopWatch, releaseWatch := watchManagedGatewayStarts(ctx, opts)
	defer releaseWatch()
	resp, err := sendHookRequest(ctx, opts, sp, payload, token)
	stopWatch()
	if errors.Is(err, errInvalidHookRequest) {
		return failResponse(opts, sp, failMode, err.Error())
	}
	if err != nil && opts.GatewayRecovery != nil && connectionRefused(err) {
		if recoveryErr := opts.GatewayRecovery(ctx, err); recoveryErr == nil && ctx.Err() == nil {
			// The initial request proved no listener was present. Recovery verifies
			// and starts the exact installer-owned gateway, including authenticated
			// readiness, before this single retry.
			resp, err = sendHookRequest(ctx, opts, sp, payload, token)
		} else {
			return failUnreachable(opts, sp, failMode, "gateway cold start failed")
		}
	}
	if err != nil {
		reason := "gateway unreachable"
		if errors.Is(context.Cause(ctx), errGatewayStartFailing) {
			reason = errGatewayStartFailing.Error()
		}
		if errors.Is(err, errManagedGatewayPeerUnverified) {
			// Managed peer-verification failure must fail closed on the transport
			// surface too, mirroring the up-front client-build path. A managed
			// hook launched with FailMode="open" must not let an unverified
			// gateway peer surface as an allow-by-default.
			return failUnreachable(opts, sp, "closed", managedPeerFailureReason(opts, err))
		}
		return failUnreachable(opts, sp, failMode, reason)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, defaultMaxBody))

	switch {
	case resp.StatusCode >= 500 && resp.StatusCode < 600:
		return failUnreachable(opts, sp, failMode, fmt.Sprintf("gateway returned HTTP %d", resp.StatusCode))
	case resp.StatusCode == http.StatusForbidden && refusalReason(body) == SurfaceUnverifiedReason:
		// A policy decision, not a failure: block in every fail mode (a stop
		// event keeps its neutral allow).
		if strings.TrimSpace(opts.Event) == "" {
			opts.Event = resolveHookEvent("", payload)
		}
		return failForeignHookBlocked(opts, sp, surfaceUnverifiedText(opts))
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return failResponse(opts, sp, failMode, fmt.Sprintf("gateway returned HTTP %d", resp.StatusCode))
	}

	return sp.decide(opts, body)
}

// refusalReason is the reason of a gateway refusal body
// ({"error":"forbidden","reason":...}), or "".
func refusalReason(body []byte) string {
	var refusal struct {
		Reason string `json:"reason"`
	}
	if json.Unmarshal(body, &refusal) != nil {
		return ""
	}
	return strings.TrimSpace(refusal.Reason)
}

// surfaceUnverifiedText is the block message of a call the gateway refused
// on its surface.
func surfaceUnverifiedText(opts Options) string {
	where := "this app or extension"
	switch AgentSurfaceHeaderValue(opts.AgentSurface) {
	case "desktop":
		where = "this desktop app"
	case "extension":
		where = "this editor extension"
	}
	return "DefenseClaw blocked this " + hookEventSubject(opts.Event) + ": your organization allows this agent only where DefenseClaw has verified its protection, and " +
		where + " is not verified. Use the agent's command-line tool, or contact your administrator. (" + SurfaceUnverifiedReason + ")"
}

func sendHookRequest(
	ctx context.Context,
	opts Options,
	sp spec,
	payload []byte,
	token string,
) (*http.Response, error) {
	url := "http://" + opts.APIAddr + sp.endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidHookRequest, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", sp.hookName+"/1.0")
	if opts.Connector == "codex" {
		// These values come from Setup's protected, event-specific command.
		// The bearer-authenticated gateway compares them with both the official
		// stdin event and its persisted contract lock before policy evaluation.
		req.Header.Set(codexBoundEventHeader, opts.Event)
		req.Header.Set(codexBoundContractHeader, opts.HookContractID)
	}
	if opts.Connector == "antigravity" && validAntigravityEvent(opts.Event) {
		// The official Antigravity stdin body has no event-name field. Carry
		// Setup's event-specific registration metadata separately so the
		// gateway can decode the body without rewriting it here.
		req.Header.Set("X-DefenseClaw-Antigravity-Event", opts.Event)
	}
	if opts.Connector == "copilot" && validCopilotEventForOptions(opts) {
		// Native camelCase Copilot bodies likewise omit event identity. Keep
		// the official stdin bytes intact and forward only the reviewed
		// event-specific registration argument through an authenticated
		// DefenseClaw header.
		req.Header.Set("X-DefenseClaw-Copilot-Event", opts.Event)
	}
	if dialect := hookDialect(opts); dialect != "" {
		// Kiro's .kiro/hooks configuration (Kiro IDE, kiro-cli --v3) and its
		// CLI 2.x agent configuration honor different vetoes, and the
		// release cannot tell them apart. The marker on the command can.
		req.Header.Set(HookDialectHeader, dialect)
	}
	if opts.ManagedEnterprise {
		if host := AgentHostHeaderValue(opts.AgentHost); host != "" {
			req.Header.Set(AgentHostHeader, host)
		}
	}
	if surface := AgentSurfaceHeaderValue(opts.AgentSurface); surface != "" {
		req.Header.Set(AgentSurfaceHeader, surface)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if v := strings.TrimSpace(opts.TraceParent); v != "" && validTraceparent(v) {
		req.Header.Set("traceparent", v)
	}
	if v := strings.TrimSpace(opts.TraceState); v != "" && validTracestate(v) {
		req.Header.Set("tracestate", v)
	}
	setUserIdentityHeaders(req)

	return opts.HTTPClient.Do(req)
}

// setUserIdentityHeaders reports which end user this hook is running as.
//
// The gateway cannot work this out for itself. Under a managed install it runs
// as a service account with its own token and profile, so resolving "the
// current user" there would attribute every event on a multi-user endpoint to
// that one service identity. This process does run as the real user.
//
// The gateway accepts these headers from loopback only, and treats them as
// attribution evidence rather than an authenticated assertion: any local
// process can reach the loopback listener and claim any value. They must never
// carry an authorization decision.
//
// A value that is not a safe header field is dropped rather than sanitized,
// so a hostile account name cannot smuggle a second header into every hook
// call the endpoint makes.
func setUserIdentityHeaders(req *http.Request) {
	identity := useridentity.Current()
	if v := identity.ID; safeIdentityHeaderValue(v) {
		req.Header.Set("X-DefenseClaw-User-Id", v)
	}
	if v := identity.Name; safeIdentityHeaderValue(v) {
		req.Header.Set("X-DefenseClaw-User-Name", v)
	}
	// The session the hook runs in (SSH, logind, the Kerberos default
	// principal): claimed facts the gateway uses for attribution only.
	// useridentity renders it from an allowlisted charset and bounds it.
	if v := useridentity.CurrentSessionFactsHeader(); v != "" {
		req.Header.Set(useridentity.SessionFactsHeader, v)
	}
}

// safeIdentityHeaderValue accepts only printable US-ASCII without the
// delimiters a downstream log or header parser would treat as structure. This
// is stricter than RFC 7230 field-value on purpose: these two values are an
// OS identifier and an account name, and nothing legitimate in either needs a
// quote, a comma, or a byte outside that range.
func safeIdentityHeaderValue(v string) bool {
	if v == "" || len(v) > maxIdentityHeaderLength {
		return false
	}
	for _, r := range v {
		if r < 0x21 || r > 0x7e {
			return false
		}
		switch r {
		case '"', ',', ';', '\\':
			return false
		}
	}
	return true
}

// maxIdentityHeaderLength bounds the reported values. A SID and an account
// name are both far shorter; a longer value is not an identity we can vouch
// for and is dropped rather than truncated, since a truncated identifier
// would silently join to the wrong user.
const maxIdentityHeaderLength = 256

func validAntigravityEvent(event string) bool {
	switch strings.TrimSpace(event) {
	case "PreInvocation", "PreToolUse", "PostToolUse", "PostInvocation", "Stop":
		return true
	default:
		return false
	}
}

// validCopilotEventForOptions checks the bound event against the dialect of
// the invoking hook command: the VS Code Local harness names its events in
// PascalCase, the Copilot CLI in lowerCamel.
func validCopilotEventForOptions(opts Options) bool {
	if copilotVSCodeLocal(opts) {
		switch strings.TrimSpace(opts.Event) {
		case "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse",
			"PreCompact", "SubagentStart", "SubagentStop", "Stop":
			return true
		}
		return false
	}
	return validCopilotEvent(opts.Event)
}

func validCopilotEvent(event string) bool {
	switch strings.TrimSpace(event) {
	case "sessionStart", "sessionEnd", "userPromptSubmitted", "userPromptTransformed",
		"preToolUse", "postToolUse", "permissionRequest", "agentStop",
		"subagentStart", "subagentStop", "postToolUseFailure", "errorOccurred",
		"preCompact", "notification":
		return true
	default:
		return false
	}
}

// decide shapes the connector-native stdout + exit code from a 2xx gateway
// response body, returning a fail_response result if the body is not JSON.
func (sp spec) decide(opts Options, body []byte) int {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return failResponse(opts, sp, normalizeFailMode(opts.FailMode), "invalid JSON response")
	}
	if sp.connector == "hermes" {
		return decideHermes(opts, sp, fields)
	}

	action, ok := rawString(fields, "action")
	if !ok || (action != "allow" && action != "alert" && action != "block" && action != "confirm") {
		if sp.style == styleClaudeCode || sp.style == styleCodex || sp.style == styleActionStderr {
			return failResponse(opts, sp, normalizeFailMode(opts.FailMode), "invalid or missing action in gateway response")
		}
		action = "allow"
	}
	reason := rawStringOr(fields, "reason", "")
	output := compactField(fields, sp.outputField)

	switch sp.style {
	case styleClaudeCode:
		if output != "" {
			fmt.Fprintln(opts.Stdout, output)
		}
		if action == "block" {
			if output != "" {
				return 0
			}
			if reason == "" {
				reason = sp.defaultBlockReason
			}
			fmt.Fprintln(opts.Stderr, reason)
			return blockExit
		}
		return 0

	case styleCodex:
		if strings.EqualFold(strings.TrimSpace(opts.Event), "SessionEnd") {
			// SessionEnd is advisory and Codex ignores its output. Discard even
			// a malformed gateway block/ask response so teardown can never be
			// turned into an enforcement surface.
			return 0
		}
		if action == "block" && !codexEventCanControl(opts.HookContractID, opts.Event) {
			// Advisory, unknown, and legacy-tier lifecycle events have no
			// certified control shape. Do not synthesize one from a generic
			// policy action.
			return 0
		}
		if output != "" {
			fmt.Fprintln(opts.Stdout, output)
		}
		if action == "block" {
			if output != "" {
				return 0
			}
			if reason == "" {
				reason = sp.defaultBlockReason
			}
			return emitCodexBlock(opts, reason)
		}
		return 0

	case styleHookEcho:
		if output != "" {
			fmt.Fprintln(opts.Stdout, output)
		} else if sp.dialect == copilotVSCodeLocalSurface && (action == "block" || action == "confirm") {
			if reason == "" {
				reason = sp.defaultBlockReason
			}
			if body := copilotVSCodeLocalOutput(opts.Event, action, reason); body != "" {
				fmt.Fprintln(opts.Stdout, body)
			}
		} else if sp.connector == "cursor" && (action == "block" || action == "confirm") {
			if reason == "" {
				reason = sp.defaultBlockReason
			}
			fmt.Fprintln(opts.Stdout, cursorActionOutput(opts.Event, action, reason))
		} else {
			return emitHookResult(opts, sp, sp.openAllow)
		}
		return 0

	case styleHookEchoDecision:
		if output != "" {
			d := decodeDecision(output)
			blocked := d == "deny" || d == "block"
			if blocked && sp.connector == "devin" {
				// Devin shows an exit-2 hook's stdout verbatim ("Tool
				// rejected: <stdout>"), so its block is the plain reason.
				reason := decodeReason(output)
				if reason == "" {
					reason = sp.defaultBlockReason
				}
				fmt.Fprintln(opts.Stdout, devinBlockText(reason))
				return blockExit
			}
			fmt.Fprintln(opts.Stdout, output)
			if blocked {
				return blockExit
			}
		}
		return 0

	case styleHookDecisionStderr:
		// Mirror kiro-hook.sh: stdout stays empty, and a hook_output
		// decision of deny or block is reported on stderr with exit 2.
		if output != "" {
			if d := decodeDecision(output); d == "deny" || d == "block" {
				if reason := decodeReason(output); reason != "" {
					fmt.Fprintln(opts.Stderr, attributedReason(reason))
				}
				return blockExit
			}
		}
		return 0

	case styleActionStderr:
		if action == "block" {
			if reason == "" {
				reason = sp.defaultBlockReason
			}
			fmt.Fprintln(opts.Stderr, reason)
			return blockExit
		}
		return 0

	case stylePluginBridge:
		// The plugin applies the decision; hand it the response unchanged
		// (compacted onto one line).
		var compact bytes.Buffer
		if err := json.Compact(&compact, body); err != nil {
			return failResponse(opts, sp, normalizeFailMode(opts.FailMode), "invalid JSON response")
		}
		fmt.Fprintln(opts.Stdout, compact.String())
		return 0

	default:
		return 0
	}
}

func decideHermes(opts Options, sp spec, fields map[string]json.RawMessage) int {
	action, ok := rawString(fields, "action")
	if !ok {
		return failResponse(opts, sp, "open", "invalid or missing action in Hermes gateway response")
	}
	rawOutput, present := fields[sp.outputField]
	if !present || strings.TrimSpace(string(rawOutput)) == "null" {
		return 0
	}
	var output map[string]json.RawMessage
	if err := json.Unmarshal(rawOutput, &output); err != nil || output == nil {
		return failResponse(opts, sp, "open", "invalid Hermes hook_output object")
	}

	valid := false
	switch strings.ToLower(strings.TrimSpace(opts.Event)) {
	case "pre_tool_call":
		valid = action == "block" && (validHermesBlockOutput(output, "decision", "reason") ||
			validHermesBlockOutput(output, "action", "message"))
	case "pre_llm_call":
		valid = (action == "allow" || action == "alert") &&
			exactJSONKeys(output, "context") &&
			nonEmptyJSONString(output, "context")
	case "pre_verify":
		outputAction, outputActionOK := rawString(output, "action")
		valid = action == "continue" &&
			exactJSONKeys(output, "action", "message") &&
			outputActionOK && outputAction == "continue" &&
			nonEmptyJSONString(output, "message")
	}
	if !valid {
		return failResponse(opts, sp, "open", "unsupported or contradictory Hermes gateway response")
	}
	fmt.Fprintln(opts.Stdout, compactField(fields, sp.outputField))
	return 0
}

func validHermesBlockOutput(output map[string]json.RawMessage, decisionKey, reasonKey string) bool {
	decision, ok := rawString(output, decisionKey)
	return exactJSONKeys(output, decisionKey, reasonKey) &&
		ok && decision == "block" &&
		nonEmptyJSONString(output, reasonKey)
}

func nonEmptyJSONString(fields map[string]json.RawMessage, key string) bool {
	raw, ok := fields[key]
	if !ok {
		return false
	}
	var value string
	return json.Unmarshal(raw, &value) == nil && strings.TrimSpace(value) != ""
}

func exactJSONKeys(fields map[string]json.RawMessage, keys ...string) bool {
	if len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			return false
		}
	}
	return true
}

// handleMissingToken mirrors defenseclaw_handle_missing_token: log the bypass,
// then allow (exit 0) by default or block (exit 2) under strict availability.
// Managed enterprise mode has no unauthenticated path, so a missing token is
// always fatal there regardless of the caller-supplied fail mode.
// No connector-specific JSON body is emitted on this path.
func handleMissingToken(opts Options, sp spec, failMode, tokenFile string) int {
	reason := "missing gateway token: " + tokenFile + " not found"
	logHookFailure(opts, sp, reason, "transport", failMode)
	if code, handled := managedCopilotFailClosed(opts, sp, reason); handled {
		return code
	}
	if opts.ManagedEnterprise || (!sp.failOpenOnly && (opts.StrictAvailability || failMode == "closed")) {
		if sp.connector == "antigravity" {
			fmt.Fprintf(opts.Stderr,
				"defenseclaw: %s, applying Antigravity's event-specific failure response\n", reason)
		} else {
			fmt.Fprintf(opts.Stderr,
				"defenseclaw: %s, blocking %s (fail mode closed)\n", reason, sp.subject)
		}
		return emitHookResult(opts, sp, sp.unreachableStrict)
	}
	return emitHookResult(opts, sp, sp.openAllow)
}

func handleUnavailableHome(opts Options, sp spec, reason string) int {
	if code, handled := managedCopilotFailClosed(opts, sp, reason); handled {
		return code
	}
	if !sp.failOpenOnly && (opts.StrictAvailability || opts.ManagedEnterprise) {
		if sp.connector == "antigravity" {
			fmt.Fprintf(opts.Stderr, "defenseclaw: %s, applying Antigravity's event-specific failure response\n", reason)
		} else {
			fmt.Fprintf(opts.Stderr, "defenseclaw: %s, blocking %s (managed/strict availability)\n", reason, sp.subject)
		}
		return emitHookResult(opts, sp, sp.unreachableStrict)
	}
	return emitHookResult(opts, sp, sp.openAllow)
}

// handleOversized mirrors the per-connector oversized-payload branch.
func handleOversized(opts Options, sp spec, failMode string) int {
	if !sp.failOpenOnly && failMode == "closed" && managedStandaloneStopEvent(opts, sp) {
		return allowManagedStandaloneStop(opts, sp, "stdin body exceeded cap", "transport")
	}
	logHookFailure(opts, sp, "stdin body exceeded cap", "transport", failMode)
	closes := !sp.failOpenOnly && failMode == "closed"
	if closes && managedPlainFailClosed(opts, sp) {
		return failManagedStandaloneClosed(opts, sp, sp.oversizedClosed, "oversized", "stdin body exceeded cap")
	}
	fmt.Fprintf(opts.Stderr, "defenseclaw: %s hook refusing oversized payload\n", sp.connector)
	if code, handled := managedCopilotFailClosed(opts, sp, "stdin body exceeded cap"); handled {
		return code
	}
	if closes {
		return emitHookResult(opts, sp, sp.oversizedClosed)
	}
	return emitHookResult(opts, sp, sp.openAllow)
}

// failUnreachable applies the connector's effective fail mode to native hook
// transport failures. Strict availability remains an unconditional closed
// override for compatibility with existing deployments.
func failUnreachable(opts Options, sp spec, failMode, reason string) int {
	if !sp.failOpenOnly && (opts.StrictAvailability || failMode == "closed") && managedStandaloneStopEvent(opts, sp) {
		return allowManagedStandaloneStop(opts, sp, reason, "transport")
	}
	logHookFailure(opts, sp, reason, "transport", failMode)
	if code, handled := managedCopilotFailClosed(opts, sp, reason); handled {
		return code
	}
	if !sp.failOpenOnly && (opts.StrictAvailability || failMode == "closed") {
		if sp.connector == "antigravity" {
			fmt.Fprintf(opts.Stderr,
				"defenseclaw: gateway unreachable, applying Antigravity's event-specific failure response: %s\n", reason)
		} else if managedPlainFailClosed(opts, sp) {
			return failManagedStandaloneClosed(opts, sp, sp.unreachableStrict, "transport", reason)
		} else {
			fmt.Fprintf(opts.Stderr,
				"defenseclaw: %s (fail mode closed): %s\n", unreachableLead(opts, sp, reason, "blocking"), unreachableDetail(opts, reason))
			if text := perUserGatewayDownText(opts, reason); text != "" {
				return emitPerUserGatewayDown(opts, sp, text)
			}
		}
		return emitHookResult(opts, sp, sp.unreachableStrict)
	}
	fmt.Fprintf(opts.Stderr, "defenseclaw: %s: %s\n", unreachableLead(opts, sp, reason, "allowing"), unreachableDetail(opts, reason))
	return emitHookResult(opts, sp, sp.openAllow)
}

// unreachableLead starts the unreachable line. Another account's process on
// the gateway port answers, so the gateway is not "unreachable" there; the
// line names the blocked or allowed event instead, a prompt rather than a
// tool for UserPromptSubmit (GAP-1706).
func unreachableLead(opts Options, sp spec, reason, verdict string) string {
	if strings.HasPrefix(reason, foreignListenerReasonPrefix) {
		return verdict + " this " + hookEventSubject(opts.Event)
	}
	return "gateway unreachable, " + verdict + " " + sp.subject
}

// unreachableDetail is the text after the colon of the unreachable line. The
// lead already says "gateway unreachable", so a per-user hook names the next
// step instead of repeating it (GAP-1204); a managed hook's gateway is not the
// user's to restart, and every other reason is kept.
func unreachableDetail(opts Options, reason string) string {
	if reason != "gateway unreachable" || opts.ManagedEnterprise || opts.ManagedUnixSocket != "" {
		return reason
	}
	return "check `defenseclaw-gateway status`, or run `defenseclaw-gateway restart`"
}

// perUserGatewayDownText is what a per-user hook that fails closed because
// this account's gateway is not running shows in the agent: the agents that
// display the structured denial (Codex, OpenCode, Cursor and the JSON-bodied
// hooks) never show stderr, so they showed only "DefenseClaw hook failed
// closed" with no cause or next step (GAP-1337). Managed hooks keep their own
// text (managedStandaloneFailClosedText).
func perUserGatewayDownText(opts Options, reason string) string {
	if strings.HasPrefix(reason, foreignListenerReasonPrefix) && !opts.ManagedEnterprise {
		return "DefenseClaw blocked this " + hookEventSubject(opts.Event) + ": " + reason + "."
	}
	if reason != "gateway unreachable" || opts.ManagedEnterprise || opts.ManagedUnixSocket != "" {
		return ""
	}
	return "DefenseClaw blocked this " + hookEventSubject(opts.Event) + ": the DefenseClaw gateway is not running or " +
		"not answering (fail mode closed). Check it with `defenseclaw-gateway status`, start it with " +
		"`defenseclaw-gateway start`, then try again."
}

// emitPerUserGatewayDown renders perUserGatewayDownText in each connector's
// fail-closed shape; connectors without a structured body keep theirs.
func emitPerUserGatewayDown(opts Options, sp spec, text string) int {
	result := sp.unreachableStrict
	if sp.connector == "codex" {
		if result.exit == 0 {
			return emit(opts.Stdout, result)
		}
		return emitCodexBlock(opts, text)
	}
	if sp.connector == "devin" {
		result.body = strings.ReplaceAll(result.body, failedClosed, devinBlockText(text))
	} else if strings.Contains(result.body, failedClosed) {
		// The body is JSON for every other connector that has one; keep it valid.
		encoded := mustJSONString(text)
		if strings.Contains(result.body, `"`+failedClosed+`"`) {
			result.body = strings.ReplaceAll(result.body, `"`+failedClosed+`"`, encoded)
		} else {
			result.body = strings.ReplaceAll(result.body, failedClosed, text)
		}
	}
	return emitHookResult(opts, sp, result)
}

// managedSIDUnregisteredReason is enterprisehooks'
// WindowsManagedSIDUnregisteredReason: the account running the agent is not
// in the administrator's protected target set.
const managedSIDUnregisteredReason = "enterprise_managed_sid_unregistered"

// managedEnrollmentPendingReason is enterprisehooks'
// WindowsManagedEnrollmentPendingReason: the machine policy registers the
// account, but it has not signed in since, so it has no runtime yet.
const managedEnrollmentPendingReason = "enterprise_managed_enrollment_pending"

// unenrolledAccountExplanation is why an unenrolled account's call is blocked.
const unenrolledAccountExplanation = "this account is not enrolled in DefenseClaw on this computer; the administrator's " +
	"policy has not enrolled it yet (enrollment runs while the account is signed in) or excludes it; ask your " +
	"administrator if this continues"

// failUnenrolled blocks, like failUnreachable in closed mode, a tool call of
// an account the administrator has not enrolled (yet) or excludes, and says
// so: the gateway is up, and the refusal is the enrollment policy. An agent
// that shows its structured denial rather than stderr (Codex, Cursor and
// the JSON-bodied hooks) gets the same explanation instead of the generic
// failed-closed text.
func failUnenrolled(opts Options, sp spec, reason string) int {
	logHookFailure(opts, sp, reason, "transport", "closed")
	if code, handled := managedCopilotFailClosed(opts, sp, reason); handled {
		return code
	}
	fmt.Fprintf(opts.Stderr, "defenseclaw: blocking %s: %s (%s)\n", sp.subject, unenrolledAccountExplanation, reason)
	explanation := "DefenseClaw: " + unenrolledAccountExplanation
	if sp.connector == "codex" {
		return emitCodexBlock(opts, explanation)
	}
	result := sp.unreachableStrict
	result.body = strings.ReplaceAll(result.body, failedClosed, explanation)
	return emitHookResult(opts, sp, result)
}

func rawString(fields map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := fields[key]
	if !ok {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(value)), true
}

// failResponse mirrors the response-layer failure path: honor FAIL_MODE.
func failResponse(opts Options, sp spec, failMode, reason string) int {
	if !managedStandaloneHook(opts) {
		// The standalone hook socket carries no token, so the token-drift
		// advice does not apply there.
		reason = responseFailureReason(reason)
	}
	closes := !sp.failOpenOnly && failMode != "open"
	if closes && managedStandaloneStopEvent(opts, sp) {
		return allowManagedStandaloneStop(opts, sp, reason, "response")
	}
	logHookFailure(opts, sp, reason, "response", failMode)
	if closes && managedPlainFailClosed(opts, sp) {
		return failManagedStandaloneClosed(opts, sp, sp.responseClosed, "response", reason)
	}
	fmt.Fprintf(opts.Stderr, "defenseclaw: %s hook error: %s\n", sp.errLabel, reason)
	if code, handled := managedCopilotFailClosed(opts, sp, reason); handled {
		return code
	}
	if sp.failOpenOnly || failMode == "open" {
		return emitHookResult(opts, sp, sp.openAllow)
	}
	return emitHookResult(opts, sp, sp.responseClosed)
}

func responseFailureReason(reason string) string {
	if strings.Contains(reason, "HTTP 401") || strings.Contains(reason, "HTTP 403") {
		return reason + " (gateway auth failed; possible token drift. Run `defenseclaw doctor --fix` or `defenseclaw-gateway restart`.)"
	}
	return reason
}

// managedCopilotFailClosed denies an administrator-managed Copilot tool call
// when DefenseClaw itself cannot decide. Copilot has no fail-closed hook
// contract (its own timeouts and non-JSON errors allow), so per-user Copilot
// hooks fail open; a managed hook still owns Copilot's native structured
// deny for preToolUse and permissionRequest and uses it. Other events cannot
// block and keep the fail-open result.
func managedCopilotFailClosed(opts Options, sp spec, reason string) (int, bool) {
	if !opts.ManagedEnterprise || sp.connector != "copilot" {
		return 0, false
	}
	message := mustJSONString(managedCopilotDenyMessage(reason))
	var body string
	// Exact reviewed event names only: an unreviewed spelling never reaches
	// the gateway and never synthesizes enforcement.
	switch opts.Event {
	case "preToolUse":
		body = `{"permissionDecision":"deny","permissionDecisionReason":` + message + `}`
	case "permissionRequest":
		body = `{"behavior":"deny","message":` + message + `}`
	default:
		if sp.dialect != copilotVSCodeLocalSurface {
			return 0, false
		}
		if body = copilotVSCodeLocalOutput(opts.Event, "block", managedCopilotDenyMessage(reason)); body == "" {
			return 0, false
		}
	}
	fmt.Fprintf(opts.Stderr, "defenseclaw: blocking managed %s (fail mode closed): %s\n", sp.subject, reason)
	fmt.Fprintln(opts.Stdout, body)
	return 0, true
}

// ForeignHookBlockedReasonPrefix starts the enterprise foreign-hook guard's
// denial reason (internal/enterprisepolicy.EvaluateForeignHooks). That reason
// names the unapproved hook file, its digest and the allowlist key and holds
// no secret.
const ForeignHookBlockedReasonPrefix = "enterprise_foreign_hook_blocked:"

// failForeignHookBlocked delivers the enterprise foreign-hook guard's
// denial as the connector's native block with the guard's reason as the
// message, so the user sees which file to remove and which allowlist key an
// administrator would use. Only the standalone guard sets this reason; the
// gateway's surface refusal (SurfaceUnverifiedReason) is delivered the
// same way. A
// stop or session-end event (foreignHookStopEvent) gets the connector's
// neutral allow instead, because a block there would keep the agent running;
// the block is still logged. Every other event gets a block. Commands that do
// not bind their event (the Cursor, Claude Code and Devin hooks) take it from
// the payload, as their gateway path does; an event the payload does not
// name unambiguously is blocked.
func failForeignHookBlocked(opts Options, sp spec, reason string) int {
	switch sp.connector {
	case "codex", "copilot", "antigravity":
		// These commands bind the reviewed event out of band.
	default:
		if strings.TrimSpace(opts.Event) == "" {
			if payload, overflow, err := readCapped(opts.Stdin, opts.MaxBody); err == nil && !overflow {
				opts.Event = resolveHookEvent("", payload)
			}
		}
	}
	if foreignHookStopEvent(sp.connector, opts.Event) {
		logHookFailure(opts, sp, reason, "policy", "open")
		fmt.Fprintf(opts.Stderr, "defenseclaw: not blocking the %s %s event (a block would keep the agent running); tool calls stay blocked: %s\n", sp.errLabel, strings.TrimSpace(opts.Event), reason)
		return emitHookResult(opts, sp, sp.openAllow)
	}
	if foreignHookCursorOpenEvent(sp.connector, opts.Event) {
		// Cursor has no block response for these events, and the generic
		// exit-2 block on the first start in a folder left cursor-agent on
		// "Trusting workspace..." with no message (GAP-1257). The session
		// block is already recorded, so the first prompt or tool call gets
		// the block and its reason.
		logHookFailure(opts, sp, reason, "policy", "open")
		fmt.Fprintf(opts.Stderr, "defenseclaw: not blocking the %s %s event (Cursor cannot show a block there); prompts and tool calls in this session stay blocked: %s\n", sp.errLabel, strings.TrimSpace(opts.Event), reason)
		return emitHookResult(opts, sp, sp.openAllow)
	}
	logHookFailure(opts, sp, reason, "policy", "closed")
	if code, handled := managedCopilotFailClosed(opts, sp, reason); handled {
		return code
	}
	fmt.Fprintf(opts.Stderr, "defenseclaw: blocking %s: %s\n", sp.subject, reason)
	message := mustJSONString(reason)
	switch sp.connector {
	case "codex":
		return emitCodexBlock(opts, reason)
	case "cursor":
		fmt.Fprintln(opts.Stdout, cursorFallbackOutput(opts.Event, true, reason))
		return sp.unreachableStrict.exit
	case "antigravity":
		if strings.TrimSpace(opts.Event) == "PreToolUse" {
			fmt.Fprintln(opts.Stdout, `{"decision":"deny","reason":`+message+`}`)
			return 0
		}
	case "devin":
		fmt.Fprintln(opts.Stdout, devinBlockText(reason))
		return sp.unreachableStrict.exit
	case "openhands":
		fmt.Fprintln(opts.Stdout, `{"decision":"deny","reason":`+message+`}`)
		return sp.unreachableStrict.exit
	case "opencode":
		fmt.Fprintln(opts.Stdout, openCodeDenyBody(reason))
		return sp.unreachableStrict.exit
	}
	if sp.failOpenOnly {
		return emitHookResult(opts, sp, sp.openAllow)
	}
	// Claude Code shows stderr on its exit-2 block; the rest keep their
	// strict failure response.
	return emitHookResult(opts, sp, sp.unreachableStrict)
}

// foreignHookCursorOpenEvent reports Cursor's workspaceOpen and sessionStart,
// which run while cursor-agent opens and trusts a folder.
func foreignHookCursorOpenEvent(connector, event string) bool {
	if connector != "cursor" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(event)) {
	case "workspaceopen", "sessionstart":
		return true
	}
	return false
}

// foreignHookStopEvent reports the stop and session-end events of the
// connectors the foreign-hook guard covers. A block on a stop event denies
// nothing; it makes the agent go on: Claude Code (Stop, SubagentStop, and
// TeammateIdle for an agent-team teammate), Codex (Stop, SubagentStop),
// Devin (Stop) and Copilot (agentStop, subagentStop) continue the turn, and
// Cursor submits a stop hook's followup_message as the next prompt. So a
// session the guard blocks would loop until the agent restarts. The
// session-end events, and Claude Code's StopFailure, cannot be blocked at
// all. The names are the vendors' exact event names; Cursor's match
// case-insensitively, like its responses (cursorActionOutput). OpenCode and
// Amp run the guard on tool calls only.
func foreignHookStopEvent(connector, event string) bool {
	event = strings.TrimSpace(event)
	switch connector {
	case "claudecode":
		switch event {
		case "Stop", "SubagentStop", "TeammateIdle", "StopFailure", "SessionEnd":
			return true
		}
	case "codex":
		switch event {
		case "Stop", "SubagentStop", "SessionEnd":
			return true
		}
	case "cursor":
		switch strings.ToLower(event) {
		case "stop", "subagentstop", "sessionend":
			return true
		}
	case "devin":
		switch event {
		case "Stop", "SessionEnd":
			return true
		}
	case "copilot":
		switch event {
		case "agentStop", "subagentStop", "sessionEnd",
			// VS Code Local harness (--hook-surface vscode-local).
			"Stop", "SubagentStop":
			return true
		}
	}
	return false
}

// managedStandaloneStopEvent reports a stop or session-end event
// (foreignHookStopEvent) of a Unix standalone managed hook. Failing such an
// event closed denies nothing; it keeps the agent running, and every later
// turn fails closed and stops again, so the agent loops on model turns until
// DefenseClaw is back. On the standalone profile every fail-closed reason
// (gateway unreachable or unverified, missing hook socket, invalid runtime,
// unusable response) therefore gives these events the connector's neutral
// allow, as the foreign-hook guard does. Tool and prompt events still fail
// closed. Per-user hooks and the Secure Client profile never set
// ManagedStandalone and keep their results.
func managedStandaloneStopEvent(opts Options, sp spec) bool {
	return opts.ManagedEnterprise && opts.ManagedStandalone && foreignHookStopEvent(sp.connector, opts.Event)
}

// allowManagedStandaloneStop answers a managed standalone stop event that
// would have failed closed with the connector's neutral allow; the failure is
// still logged, with the fail mode it got.
func allowManagedStandaloneStop(opts Options, sp spec, reason, category string) int {
	logHookFailure(opts, sp, reason, category, "open")
	fmt.Fprintf(opts.Stderr,
		"DefenseClaw is not blocking the %s event, because a block there would keep the agent running; prompts and tool calls stay blocked until DefenseClaw is available. (%s)\n",
		strings.TrimSpace(opts.Event), reason)
	return emitHookResult(opts, sp, sp.openAllow)
}

// managedStandaloneHook reports a Unix standalone managed hook. Per-user
// hooks, the Secure Client profile and Windows never set ManagedStandalone.
func managedStandaloneHook(opts Options) bool {
	return opts.ManagedEnterprise && opts.ManagedStandalone
}

// managedPlainFailClosed reports a managed hook whose fail-closed result
// uses the plain text of managedStandaloneFailClosedText: the Unix
// standalone hook and the Windows standalone hook (ExplainUnenrolledAccount;
// Copilot keeps its own denial). Secure Client keeps its text.
func managedPlainFailClosed(opts Options, sp spec) bool {
	if managedStandaloneHook(opts) {
		return true
	}
	return opts.ManagedEnterprise && opts.ExplainUnenrolledAccount && sp.connector != "copilot"
}

// managedPeerFailureReason is the hook-failure reason of a managed
// peer-verification failure: a Windows standalone hook says when the gateway
// service is simply not running; every other hook keeps
// managedGatewayPeerUnverifiedReason.
func managedPeerFailureReason(opts Options, err error) string {
	if opts.ExplainUnenrolledAccount && errors.Is(err, errManagedGatewayNotRunning) {
		return managedGatewayNotRunningReason
	}
	return managedGatewayPeerUnverifiedReason
}

// failManagedStandaloneClosed delivers a Unix standalone managed hook's
// fail-closed result with the plain text of managedStandaloneFailClosedText:
// on stderr (the block message Claude Code shows) and as the reason in the
// connector's native block body where it has one. The exit codes are the
// connector's usual fail-closed ones.
func failManagedStandaloneClosed(opts Options, sp spec, result failResult, layer, reason string) int {
	text := managedStandaloneFailClosedText(opts.Event, layer, reason)
	fmt.Fprintln(opts.Stderr, text)
	switch sp.connector {
	case "codex":
		if result.exit == 0 {
			return emit(opts.Stdout, result)
		}
		return emitCodexBlock(opts, text)
	case "cursor":
		fmt.Fprintln(opts.Stdout, cursorFallbackOutput(opts.Event, true, text))
		return result.exit
	case "devin":
		fmt.Fprintln(opts.Stdout, devinBlockText(text))
		return result.exit
	case "opencode":
		fmt.Fprintln(opts.Stdout, openCodeDenyBody(text))
		return result.exit
	}
	return emitHookResult(opts, sp, result)
}

// managedStandaloneFailClosedText is what a standalone managed hook (Unix or
// Windows, managedPlainFailClosed) says when it fails closed: that DefenseClaw blocked the prompt or tool
// call, why in plain words, what to do, and the internal reason last in
// parentheses, e.g. "DefenseClaw blocked this prompt: the DefenseClaw
// gateway is not available. Try again in a moment; if this continues,
// contact your administrator. (enterprise_managed_gateway_peer_unverified)".
func managedStandaloneFailClosedText(event, layer, reason string) string {
	var cause, advice string
	switch {
	case layer == "oversized":
		cause, advice = "it is too large for DefenseClaw to inspect", "Make it smaller and try again."
	case layer == "response":
		cause, advice = "the DefenseClaw gateway returned an answer DefenseClaw could not use",
			"Try again; if this continues, contact your administrator."
	case reason == managedGatewayNotRunningReason:
		cause, advice = "the DefenseClaw gateway service is not running on this computer",
			"Try again in a moment; if this continues, ask your administrator to start the DefenseClaw gateway service."
	case strings.HasPrefix(reason, "enterprise_managed_runtime") ||
		reason == "enterprise_managed_hook_socket_missing" ||
		reason == "enterprise_machine_policy_summary_untrusted":
		cause, advice = "DefenseClaw is not set up correctly on this computer", "Contact your administrator."
	default:
		cause, advice = "the DefenseClaw gateway is not available",
			"Try again in a moment; if this continues, contact your administrator."
	}
	return "DefenseClaw blocked this " + hookEventSubject(event) + ": " + cause + ". " + advice + " (" + strings.TrimSpace(reason) + ")"
}

// hookEventSubject names what an agent hook event carries, in the words a
// user knows: a prompt, a tool call or a tool result.
func hookEventSubject(event string) string {
	event = strings.TrimSpace(event)
	switch strings.ToLower(event) {
	case "userpromptsubmit", "beforesubmitprompt", "userpromptsubmitted", "userprompttransformed":
		return "prompt"
	case "pretooluse", "permissionrequest", "beforeshellexecution", "beforemcpexecution",
		"beforereadfile", "beforetabfileread", "tool.execute.before":
		return "tool call"
	case "posttooluse", "posttoolusefailure", "aftershellexecution", "aftermcpexecution",
		"afterfileedit", "tool.execute.after":
		return "tool result"
	case "sessionstart":
		return "session start"
	case "":
		return "request"
	default:
		return event + " event"
	}
}

// resolveManagedStandaloneFailureEvent names the event of a managed
// standalone invocation that fails before its payload is read. The Claude
// Code, Cursor and Devin commands do not bind their event, so it comes from
// the payload, as in failForeignHookBlocked; the Codex, Copilot and
// Antigravity commands bind it out of band. Other invocations are left
// untouched, so their stdin is never read here.
func resolveManagedStandaloneFailureEvent(opts *Options, sp spec) {
	if opts == nil || !opts.ManagedEnterprise || !opts.ManagedStandalone || strings.TrimSpace(opts.Event) != "" {
		return
	}
	switch sp.connector {
	case "codex", "copilot", "antigravity":
		return
	}
	if payload, overflow, err := readCapped(opts.Stdin, opts.MaxBody); err == nil && !overflow {
		opts.Event = resolveHookEvent("", payload)
	}
}

// managedCopilotDenyMessage is the text Copilot shows for a managed local
// denial. Copilot surfaces only the structured reason (not stderr), so a
// foreign-hook guard denial carries its own reason and the user learns which
// file to remove; every other local failure keeps the generic text.
func managedCopilotDenyMessage(reason string) string {
	reason = strings.TrimSpace(reason)
	if strings.HasPrefix(reason, ForeignHookBlockedReasonPrefix) {
		return reason
	}
	return "DefenseClaw policy service is unavailable."
}

// emit writes the connector-native failure body (if any) and returns its exit
// code. Hermes failure results are always empty exit-0 allows.
func emit(out io.Writer, r failResult) int {
	if r.body != "" {
		fmt.Fprintln(out, r.body)
	}
	return r.exit
}

// emitHookResult supplies event-specific stdout contracts on local, transport,
// and response fallbacks. Cursor accepts different fields per event and treats
// exit 2 as a generic block. Antigravity only documents structured PreToolUse
// blocking, so its native bridge exits successfully after emitting that body.
func emitHookResult(opts Options, sp spec, result failResult) int {
	if sp.connector == "codex" {
		if result.exit == 0 {
			return emit(opts.Stdout, result)
		}
		reason := failedClosed
		if strings.Contains(result.body, tooLarge) {
			reason = tooLarge
		}
		return emitCodexBlock(opts, reason)
	}
	if sp.connector == "cursor" {
		fmt.Fprintln(opts.Stdout, cursorFallbackOutput(
			opts.Event,
			result.closed || result.exit != 0,
			result.body,
		))
		return result.exit
	}
	if sp.dialect == copilotVSCodeLocalSurface {
		return emitCopilotVSCodeLocalResult(opts, sp, result)
	}
	if sp.connector != "antigravity" {
		return emit(opts.Stdout, result)
	}
	closed := result.closed || result.exit != 0
	var body string
	switch strings.TrimSpace(opts.Event) {
	case "PreToolUse":
		if closed {
			body = `{"decision":"deny","reason":"DefenseClaw policy service is unavailable."}`
		} else {
			body = `{"decision":"allow"}`
		}
	case "Stop":
		body = `{"decision":"allow"}`
	default:
		body = `{}`
	}
	fmt.Fprintln(opts.Stdout, body)
	return 0
}

func codexEventCanControl(contractID, event string) bool {
	switch strings.TrimSpace(event) {
	case "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "Stop":
		// These controls predate the protected contract flag. Preserve exact
		// failure behavior for upgraded legacy registrations whose command has
		// not yet been reconciled.
		return true
	case "SessionStart", "SubagentStop", "PreCompact", "PostCompact":
		return contractID == "codex-hooks-v3" ||
			contractID == "codex-hooks-v3-generic" ||
			contractID == "codex-hooks-v4"
	default:
		return false
	}
}

// emitCodexBlock translates local fail-closed and missing structured gateway
// responses into the exact event-specific Codex control schema. Structured
// stdout exits successfully because current Codex treats a non-zero
// UserPromptSubmit status as hook failure rather than a policy decision.
func emitCodexBlock(opts Options, reason string) int {
	if !codexEventCanControl(opts.HookContractID, opts.Event) {
		switch strings.TrimSpace(opts.Event) {
		case "SessionEnd", "SubagentStart":
			return 0
		default:
			// Fail loud without inventing a control schema for a legacy,
			// missing, invalid, or future contract.
			return blockExit
		}
	}
	if reason == "" {
		reason = failedClosed
	}
	encodedReason := mustJSONString(reason)
	switch strings.TrimSpace(opts.Event) {
	case "SessionStart", "PreCompact", "PostCompact":
		fmt.Fprintf(opts.Stdout, "{\"continue\":false,\"stopReason\":%s}\n", encodedReason)
	case "PermissionRequest":
		fmt.Fprintf(opts.Stdout,
			"{\"hookSpecificOutput\":{\"hookEventName\":\"PermissionRequest\",\"decision\":{\"behavior\":\"deny\",\"message\":%s}}}\n",
			encodedReason,
		)
	case "UserPromptSubmit", "PostToolUse", "SubagentStop", "Stop":
		fmt.Fprintf(opts.Stdout, "{\"decision\":\"block\",\"reason\":%s}\n", encodedReason)
	case "PreToolUse":
		fmt.Fprintf(opts.Stdout,
			"{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":%s}}\n",
			encodedReason,
		)
	default:
		// An unknown event cannot safely receive a guessed JSON shape. Preserve
		// the old non-zero failure signal so Codex reports the hook failure.
		return blockExit
	}
	return 0
}

func withDefaults(o Options) Options {
	if o.Stdin == nil {
		o.Stdin = os.Stdin
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.MaxBody <= 0 {
		o.MaxBody = defaultMaxBody
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Home == "" {
		if home, err := os.UserHomeDir(); err == nil {
			o.Home = filepath.Join(home, ".defenseclaw")
		}
	}
	if o.HookDir == "" {
		o.HookDir = filepath.Join(o.Home, "hooks")
	}
	return o
}

// ClaudeCodeHookTimeoutSeconds returns the timeout written into Claude Code's
// hook registration for event. The native HTTP path uses the same source of
// truth so a 60- or 90-second registered event is never capped at 10 seconds.
func ClaudeCodeHookTimeoutSeconds(event string) int {
	switch strings.TrimSpace(event) {
	case "MessageDisplay":
		return 10
	case "SessionEnd":
		return 60
	case "PostToolBatch", "Stop", "SubagentStop":
		return 90
	default:
		return 30
	}
}

func resolveHookEvent(explicit string, payload []byte) string {
	if event := strings.TrimSpace(explicit); event != "" {
		return event
	}
	var envelope struct {
		HookEventName string `json:"hook_event_name"`
		Event         string `json:"event"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return ""
	}
	hookEventName := strings.TrimSpace(envelope.HookEventName)
	event := strings.TrimSpace(envelope.Event)
	if hookEventName != "" && event != "" && !strings.EqualFold(hookEventName, event) {
		return ""
	}
	if hookEventName != "" {
		return hookEventName
	}
	return event
}

func validateCodexInvocationBinding(
	explicitEvent string,
	contractID string,
	payload []byte,
) (string, error) {
	event := strings.TrimSpace(explicitEvent)
	if event == "" {
		return "", errors.New("Codex hook command is missing its installer-bound event")
	}
	contractID = strings.TrimSpace(contractID)
	if contractID == "" {
		return "", errors.New("Codex hook command is missing its installer-bound contract")
	}
	var envelope struct {
		HookEventName string `json:"hook_event_name"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return "", errors.New("Codex hook stdin is not valid JSON")
	}
	stdinEvent := strings.TrimSpace(envelope.HookEventName)
	if stdinEvent == "" {
		return "", errors.New("Codex hook stdin is missing hook_event_name")
	}
	if stdinEvent != event {
		return "", fmt.Errorf(
			"Codex hook stdin event %q does not match installer-bound event %q",
			stdinEvent,
			event,
		)
	}
	if !codexContractAllowsEvent(contractID, event) {
		return "", fmt.Errorf(
			"Codex hook event %q is not registered by installer-bound contract %q",
			event,
			contractID,
		)
	}
	return event, nil
}

func codexContractAllowsEvent(contractID, event string) bool {
	switch strings.TrimSpace(contractID) {
	case "codex-hooks-v1":
		switch event {
		case "SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "Stop":
			return true
		}
	case "codex-hooks-v2":
		switch event {
		case "SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "PreCompact", "PostCompact", "Stop":
			return true
		}
	case "codex-hooks-v3", "codex-hooks-v3-generic":
		switch event {
		case "SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "SubagentStart", "SubagentStop", "PreCompact", "PostCompact", "Stop":
			return true
		}
	case "codex-hooks-v4":
		switch event {
		case "SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "SubagentStart", "SubagentStop", "PreCompact", "PostCompact", "Stop", "SessionEnd":
			return true
		}
	}
	return false
}

// RequestTimeout is the total budget a hook invocation for connector and
// event has before the agent's own hook timeout.
func RequestTimeout(connector, event string) time.Duration {
	return hookRequestTimeout(connector, event)
}

func hookRequestTimeout(connector, event string) time.Duration {
	if strings.EqualFold(strings.TrimSpace(connector), "codex") &&
		strings.EqualFold(strings.TrimSpace(event), "SessionEnd") {
		// Codex caps SessionEnd command hooks at three seconds. Finish the
		// gateway round-trip with one second left for stdout flushing and the
		// native Windows PowerShell Start-Process -Wait wrapper to observe the
		// hook executable's exit, preventing the child from outliving the host.
		return 3*time.Second - hookResponseGrace
	}
	if strings.EqualFold(strings.TrimSpace(connector), "antigravity") ||
		strings.EqualFold(strings.TrimSpace(connector), "copilot") {
		// Setup registers every official Antigravity and Copilot handler with
		// timeout=30.
		// Keep one second for the parent runtime to receive and parse stdout.
		return 29 * time.Second
	}
	if !strings.EqualFold(strings.TrimSpace(connector), "claudecode") {
		return defaultHookRequestTimeout
	}
	if strings.TrimSpace(event) == "" {
		// A malformed/unknown payload may still be a 10-second MessageDisplay
		// event. Use the shortest registered budget so Claude can receive our
		// failure response instead of killing the hook first.
		return 10*time.Second - hookResponseGrace
	}
	registeredBudget := time.Duration(ClaudeCodeHookTimeoutSeconds(event)) * time.Second
	if registeredBudget <= hookResponseGrace {
		return registeredBudget
	}
	// Return control before Claude Code reaches its own process deadline so the
	// hook can still emit the configured fail-open/fail-closed response.
	return registeredBudget - hookResponseGrace
}

// defaultHTTPClient applies the supplied total request budget.
//
// CheckRedirect refuses to follow redirects, mirroring `curl` without `-L`
// (the .sh hooks never passed -L). The gateway hook endpoints never legitimately
// redirect, so a 3xx is surfaced to doRequest as a non-2xx response (handled by
// FAIL_MODE) instead of being followed. This keeps the hook from chasing a
// redirect to a different host/port — which would otherwise widen the SSRF
// surface and could leak the gateway bearer token to an unintended target if the
// configured gateway address were ever tampered with.
func defaultHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = defaultHookRequestTimeout
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func normalizeFailMode(m string) string {
	if strings.EqualFold(strings.TrimSpace(m), "closed") {
		return "closed"
	}
	return "open"
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// suppressCursorCompatibilityImport mirrors the early no-op in
// claude-code-hook.sh for Cursor's Claude Code hook compatibility layer. The
// payload marker alone is insufficient: a genuine Claude Code hook must keep
// flowing when the Cursor connector is inactive. The scoped Cursor token plus
// a live (v1+) managed Cursor script are the setup/teardown-owned proof that
// DefenseClaw's native Cursor bridge is installed. Teardown writes a v0
// tombstone and may leave the token behind, so v0 must never suppress.
func suppressCursorCompatibilityImport(opts Options, payload []byte) bool {
	if !strings.EqualFold(strings.TrimSpace(opts.Connector), "claudecode") {
		return false
	}

	var origin struct {
		CursorVersion string `json:"cursor_version"`
	}
	if err := json.Unmarshal(payload, &origin); err != nil || origin.CursorVersion == "" {
		return false
	}
	if !fileExists(filepath.Join(opts.HookDir, ".hook-cursor.token")) {
		return false
	}
	return liveManagedCursorHook(filepath.Join(opts.HookDir, "cursor-hook.sh"))
}

// liveManagedCursorHook reads only the bounded script header and accepts the
// generated line-2 marker when its schema version begins at v1 or later. The
// v0 marker is reserved for teardown's disabled tombstone.
func liveManagedCursorHook(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	header, err := io.ReadAll(io.LimitReader(f, 512))
	if err != nil {
		return false
	}
	lines := bytes.SplitN(header, []byte{'\n'}, 3)
	if len(lines) < 2 {
		return false
	}
	const prefix = "# defenseclaw-managed-hook v"
	marker := string(lines[1])
	if !strings.HasPrefix(marker, prefix) {
		return false
	}
	version := marker[len(prefix):]
	return len(version) > 0 && version[0] >= '1' && version[0] <= '9'
}

// missingTokenFile names the token file a user can find and restore: the
// connector-scoped one Setup writes, else the legacy shared one (GAP-1425).
func missingTokenFile(hookDir, connector, legacy string) string {
	if name := strings.ToLower(strings.TrimSpace(connector)); name != "" {
		return filepath.Join(hookDir, ".hook-"+name+".token")
	}
	return legacy
}

func hookTokenFile(hookDir, connector string) (string, bool) {
	scoped := filepath.Join(hookDir, ".hook-"+strings.ToLower(strings.TrimSpace(connector))+".token")
	if fileExists(scoped) {
		return scoped, true
	}
	return filepath.Join(hookDir, ".token"), false
}

// readTokenFile parses DEFENSECLAW_GATEWAY_TOKEN out of a token sidecar,
// which setup writes as `DEFENSECLAW_GATEWAY_TOKEN="<token>"` (Go-quoted). An
// unreadable/empty file yields an empty token (loopback no-auth path).
const managedHookTokenMaxBytes int64 = 64 << 10

func readTokenFile(path string, allowRaw bool) string {
	return readTokenFileForMode(path, allowRaw, false)
}

func readTokenFileForMode(
	path string,
	allowRaw bool,
	managedEnterprise bool,
) string {
	token, _ := readTokenFileForModeE(path, allowRaw, managedEnterprise)
	return token
}

// readTokenFileForModeE reports the underlying read error alongside the
// parsed token so managed callers can distinguish an unreadable/rejected
// sidecar from a legitimately empty file. Non-managed callers continue to
// treat any error as an empty token (loopback no-auth path).
func readTokenFileForModeE(
	path string,
	allowRaw bool,
	managedEnterprise bool,
) (string, error) {
	var (
		data []byte
		err  error
	)
	if managedEnterprise {
		data, err = readManagedTokenFile(path, managedHookTokenMaxBytes)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return "", err
	}
	return parseTokenFile(data, allowRaw), nil
}

func parseTokenFile(data []byte, allowRaw bool) string {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "export ")
		const key = "DEFENSECLAW_GATEWAY_TOKEN="
		if !strings.HasPrefix(line, key) {
			continue
		}
		val := strings.TrimSpace(line[len(key):])
		if unq, err := strconv.Unquote(val); err == nil {
			return unq
		}
		return strings.Trim(val, `"'`)
	}
	if !allowRaw {
		return ""
	}
	raw := strings.TrimSuffix(string(data), "\n")
	if strings.ContainsAny(raw, "\r\n") {
		return ""
	}
	return raw
}

// rawStringOr returns the JSON string value at key, or def when the key is
// missing, null, or not a string (matching jq's `.key // "def"`).
func rawStringOr(m map[string]json.RawMessage, key, def string) string {
	raw, ok := m[key]
	if !ok {
		return def
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return def
	}
	if s == "" {
		return def
	}
	return s
}

// compactField returns the compact JSON of m[field], or "" when the field is
// missing or JSON null (matching jq's `.field // empty`).
func compactField(m map[string]json.RawMessage, field string) string {
	if field == "" {
		return ""
	}
	raw, ok := m[field]
	if !ok {
		return ""
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return trimmed
	}
	return buf.String()
}

// decodeDecision pulls the `decision` string from an already-compact JSON
// object (the connector's hook_output) for the OpenHands deny/block path.
func decodeDecision(output string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(output), &m); err != nil {
		return ""
	}
	return rawStringOr(m, "decision", "")
}

// devinBlockText is the stdout of a Devin hook that exits 2. Devin shows that
// stdout verbatim as the rejection ("Tool rejected: <stdout>") instead of
// parsing it, so a block prints its reason on one plain line, not the
// {"decision":"block"} object; exit 2 alone is the veto.
func devinBlockText(reason string) string {
	return strings.Join(strings.Fields(reason), " ")
}

// decodeReason pulls the `reason` string from an already-compact JSON
// object (the connector's hook_output).
func decodeReason(output string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(output), &m); err != nil {
		return ""
	}
	return rawStringOr(m, "reason", "")
}

// attributedReason is a block reason as the harness shows it: DefenseClaw's
// own reasons name it already ("Blocked by DefenseClaw rule ..."), any other
// one gets the "defenseclaw: " prefix (kiro-hook.sh kiro_block_reason).
func attributedReason(reason string) string {
	if strings.Contains(strings.ToLower(reason), "defenseclaw") {
		return reason
	}
	return "defenseclaw: " + reason
}

// mustJSONString returns s as a JSON string literal (quoted + escaped).
func mustJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// copilotVSCodeLocalOutput is the VS Code Local harness body for a block or
// confirm on an event that has one (connector.CopilotVSCodeLocalHookOutput),
// or "". The harness reads stdout only on exit 0.
func copilotVSCodeLocalOutput(event, action, reason string) string {
	message := mustJSONString(reason)
	switch strings.TrimSpace(event) {
	case "PreToolUse":
		decision := "deny"
		if action == "confirm" {
			decision = "ask"
		}
		return `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"` + decision +
			`","permissionDecisionReason":` + message + `}}`
	case "UserPromptSubmit":
		if action == "block" {
			return `{"continue":false,"stopReason":` + message + `}`
		}
	}
	return ""
}

// emitCopilotVSCodeLocalResult delivers a local failure result to the VS
// Code Local harness. A closed result denies the tool call or stops the
// prompt with the structured body and exit 0, which does not depend on the
// Windows PowerShell wrapper preserving exit 2. Every other event cannot be
// denied, and a non-zero exit there only surfaces a warning, so it gets no
// output and exit 0.
func emitCopilotVSCodeLocalResult(opts Options, sp spec, result failResult) int {
	if !(result.closed || result.exit != 0) {
		return emit(opts.Stdout, result)
	}
	reason := strings.TrimSpace(result.body)
	if reason == "" {
		reason = failedClosed
	}
	if body := copilotVSCodeLocalOutput(opts.Event, "block", reason); body != "" {
		fmt.Fprintln(opts.Stdout, body)
	}
	return 0
}
