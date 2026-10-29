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
// the bundled Bash hook scripts. It is used on Windows and by managed native
// hooks on Unix; Windows agents invoke the binary directly without Git Bash,
// a .cmd wrapper, or jq.
//
// The behavior here mirrors the .sh hooks under internal/gateway/connector/hooks:
// the same gateway endpoint, per-connector stdout shape and exit code, and the
// same configured outage behavior and closed misconfiguration policy. Native
// transport deadlines may follow the agent's registered event budget. Golden
// tests pin the shared decision contract.
package hookexec

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/copilotargs"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
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

// DefaultMaxBody is defaultMaxBody for the hook command, which reads the
// payload before Run (ArmAnswerWatchdog).
const DefaultMaxBody = defaultMaxBody

const (
	defaultHookRequestTimeout = 10 * time.Second
	hookResponseGrace         = time.Second
)

var (
	errInvalidHookRequest           = errors.New("invalid hook request")
	errManagedGatewayPeerUnverified = errors.New("enterprise managed gateway peer unverified")
	// errManagedGatewayNotRunning wraps a peer-verification failure whose
	// cause is that the managed gateway service is not running (Windows SCM
	// reports it stopped). The hook fails closed, except an authenticated
	// Secure Client hook, which follows its fail mode (managedPeerFailMode).
	errManagedGatewayNotRunning = errors.New("enterprise managed gateway service is not running")
	// errManagedHookSocketSELinuxDenied wraps a Unix standalone peer failure
	// where SELinux kept this account from the hook socket.
	errManagedHookSocketSELinuxDenied = errors.New("SELinux denied this account access to the DefenseClaw hook socket")
	// errManagedGatewayPortHeld wraps a peer-verification failure whose
	// cause is that the gateway service runs but another process listens on
	// its API port (Windows). The hook still fails closed.
	errManagedGatewayPortHeld = errors.New("another process holds the enterprise managed gateway API port")
)

// managedHookSocketSELinuxDeniedReason is the hook-failure reason of a Unix
// standalone hook that SELinux kept from the hook socket (a confined user on
// a host without the DefenseClaw SELinux module).
const managedHookSocketSELinuxDeniedReason = "enterprise_managed_hook_socket_selinux_denied"

const managedGatewayPeerUnverifiedReason = "enterprise_managed_gateway_peer_unverified"

// managedGatewayNotRunningReason is the hook-failure reason of a Windows
// standalone managed hook whose gateway service is stopped, instead of
// managedGatewayPeerUnverifiedReason. Secure Client keeps the latter.
const managedGatewayNotRunningReason = "enterprise_managed_gateway_not_running"

// managedGatewayPortHeldReason is the hook-failure reason of a Windows
// standalone managed hook that reached another process on the gateway API
// port while the gateway service runs: it said the service was not running
// (GAP-1029). Secure Client keeps managedGatewayPeerUnverifiedReason.
const managedGatewayPortHeldReason = "enterprise_managed_gateway_port_held"

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

// ClientRefusalHeader carries, on the standalone hook socket, a refusal the
// hook made itself before it could send the event: the gateway records it
// (audit row and log line) and answers 403. Only
// IsManagedProcessContextReason limits the accepted values.
const ClientRefusalHeader = "X-DefenseClaw-Client-Refusal"

// ManagedUserNamespaceReason is the refusal of a hook that runs in a private
// user namespace (unshare -U, a sandbox tool): from there it cannot check the
// root-owned runtime state, whose owners read as the overflow uid.
const ManagedUserNamespaceReason = "enterprise_managed_user_namespace"

const (
	ManagedTracedProcessReason         = "enterprise_managed_traced_process"
	ManagedProcessContextUnknownReason = "enterprise_managed_process_context_unverified"
	// ManagedPolicyViewReason is the gateway's alert for managed hook calls
	// under a vendor policy view it can not prove; never a refusal.
	ManagedPolicyViewReason = "enterprise_managed_policy_view_unverified"
)

// IsManagedProcessContextReason accepts only the hook's fixed context
// diagnostics, never caller-supplied text, for the managed socket refusal
// audit.
func IsManagedProcessContextReason(reason string) bool {
	switch reason {
	case ManagedUserNamespaceReason, ManagedTracedProcessReason, ManagedProcessContextUnknownReason:
		return true
	default:
		return false
	}
}

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
const copilotVSCodeLocalSurface = copilotargs.SurfaceVSCodeLocal

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
	// gatewayRefusal is what a per-user hook the gateway refused with an
	// error status shows in the agent (perUserRefusalText); doRequest sets it.
	gatewayRefusal string
	// answerSpentLocally is set when this standalone hook reached its
	// gateway request with less than hookGatewayAnswerFloor of the answer
	// budget left: a missing answer then fails closed (failNoAnswer).
	answerSpentLocally bool
	// answeredErrorStatus records an HTTP refusal seen before a retry. A
	// failed retry cannot turn that answered error into an outage allow.
	answeredErrorStatus int
	// managedOutageOpen is set on a standalone hook outside Secure Client
	// for a failure that ManagedOutageFailsOpen lets through (the gateway is
	// not running, was still restarting, or gave no answer). Only such a
	// failure takes the administrator's open; every other failure is closed
	// (managedNonOutageMode, bounded review P1).
	managedOutageOpen bool
	// perUserOutage is set on a per-user hook for a failure that is a gateway
	// outage (withPerUserOutage): this account's gateway refused or dropped
	// the connection, gave no connection within the restart budget, or could
	// not be started. Only such a failure asks OutageFailModeNow; an answer the
	// gateway gave, a stalled answer and every local failure stay closed.
	perUserOutage bool
	// The already bounded input is retained for failure-only audit correlation
	// and session warning deduplication. It is never written to the audit log.
	failurePayload []byte
	// oversizedReview marks a balanced per-user call whose bounded prefix was
	// sent to the gateway (OversizeUninspectedField). Only its answered allow
	// gets the size warning.
	oversizedReview bool
	// answerBy is the answer deadline of a tool call (answerDeadline);
	// doRequest sets it, and the request then asks for progress reports.
	answerBy time.Time
	// answerWatch is the answer watchdog of a tool call
	// (startAnswerWatchdog); doRequest stands it down once the gateway's
	// decision is in.
	answerWatch *answerWatchdog
	// AnswerWatchdog is the answer watchdog the hook command armed for this
	// call before Run (ArmAnswerWatchdog). Run adopts it: it holds all of
	// Run's output and gives the call's fail-closed answer at the answer
	// deadline, rendered again for the call Run resolved.
	AnswerWatchdog *AnswerWatchdog
	// requestFacts are the headers of a call that cost work to compute,
	// computed once for all of its tries (doRequest).
	requestFacts *hookRequestFacts
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
	// closed independently. Only "open" opens: empty or any other value is
	// "closed" (owner rule: hooks fail closed unless the operator chose open).
	FailMode string
	// OutageFailModeNow returns the outage mode the hook's own config on disk
	// gives this connector at call time. A nil callback keeps the outage
	// closed. No mode written at setup time may override this decision.
	OutageFailModeNow func() string

	// Home is DEFENSECLAW_HOME (default ~/.defenseclaw). If it does not exist
	// or contains a .disabled file the hook is a no-op (exit 0).
	Home string
	// FailureLogHome resolves the invoking user's diagnostic directory for
	// the failure rows of a managed hook. It is never on the answer path:
	// a tool call's answer watchdog runs it once in the background from the
	// moment it is armed (cacheFailureLogHome), so the watchdog's own row
	// does not wait on it; any other call runs it only when it writes a row.
	// Enforcement still uses the administrator-owned Home, and a managed row
	// never goes there: with no resolver, or an empty answer, there is no row.
	FailureLogHome func() string
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
	// SecureClient pins the pre-1.0 hook response behavior for that profile.
	SecureClient bool
	// AgentHost is the name of the process that started the agent; it is
	// sent (AgentHostHeader) only with ManagedEnterprise.
	AgentHost string
	// AgentSurface is the surface the hook classified its caller as
	// (AgentSurfaceHeader); "" when unclassified.
	AgentSurface string
	// ManagedRuntimeFailure is a stable, non-sensitive resolver diagnostic
	// selected before target-owned runtime files are consulted.
	ManagedRuntimeFailure string
	// InvocationFailure is why a per-user hook command failed before it
	// could check the call (an unknown flag, a malformed value, a stray
	// argument) while its policy is closed: Run answers it with the
	// connector's own block, never the generic status 1 most agents run the
	// call on (GAP-0982). A managed hook sets ManagedRuntimeFailure instead.
	InvocationFailure string
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
	// results.
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
	// for the gateway. Run invokes it at most once per call. A managed hook
	// calls it after the restart budget and retries the original
	// authenticated request once within the same deadline; a per-user hook
	// runs it beside the restart-budget tries, with a context that outlives
	// the call (awaitPerUserGateway).
	GatewayRecovery func(context.Context, error) error
	// Now is injectable for deterministic failure-log timestamps in tests.
	Now func() time.Time
	// StartedAt, when set, is when the hook process began work the
	// request budget must include (the standalone foreign-hook guard's scan
	// runs before Run). Zero starts the budget when Run is called.
	StartedAt time.Time
	// Exit ends the hook process with a status. The answer watchdog of a
	// tool call calls it after it wrote the call's fail-closed answer at the
	// answer deadline, when the call's own work is still held up. Nil (a
	// caller that runs Run in process) writes that answer and lets Run
	// return it.
	Exit func(int)
	// AssetFacts renders the assetfacts.Header value for a payload: what the
	// standalone gateway, a service account, cannot read in this user's
	// home. It is sent by standalone managed hooks only.
	AssetFacts func(connector string, payload []byte) string

	// refusal is the HookRefusalHeader value of a call that only reports a
	// refusal the hook made (reportOversizedRefusal).
	refusal string
}

// Run executes the hook described by opts and returns the process exit code.
// Connector-native stdout is the enforcement surface when the upstream
// contract defines one. In particular, Antigravity blocking is expressed only
// by synchronous PreToolUse stdout {"decision":"deny"}; no Antigravity
// behavior relies on a non-zero process exit code.
func Run(ctx context.Context, opts Options) int {
	if watchdog := opts.AnswerWatchdog; watchdog != nil {
		// The hook command armed the watchdog before it resolved the
		// runtime (GAP-0155): every answer of the call, the early ones
		// included, goes through it.
		opts.AnswerWatchdog = nil
		watchdog.hold(&opts)
		return watchdog.finish(runHook(ctx, opts))
	}
	return runHook(ctx, opts)
}

// runHook is Run once the answer watchdog (if any) holds the output.
func runHook(ctx context.Context, opts Options) int {
	startedAt := opts.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	opts = withDefaults(opts)
	opts.StartedAt = startedAt
	closeDuringInstall(&opts, "")

	sp, ok := specFor(opts.Connector)
	if ok && copilotVSCodeLocal(opts) {
		sp = copilotVSCodeLocalSpec
	}
	if !ok {
		if reason, removed := removedConnectorReason(opts.Connector); removed {
			// until 1.1: a Windows hook an older release registered for a
			// removed connector runs this launcher, not a script; it
			// blocks the way the script's stub does.
			if strings.EqualFold(strings.TrimSpace(opts.Connector), "openhands") {
				body, _ := json.Marshal(map[string]string{"decision": "deny", "reason": reason})
				fmt.Fprintln(opts.Stdout, string(body))
			}
			fmt.Fprintln(opts.Stderr, reason)
			return blockExit
		}
		// Unknown connector is a wiring bug, not a policy decision. Fail loud
		// so it surfaces in tests / setup rather than silently disabling the
		// guardrail. The CLI validates --connector against the registry, so
		// this is unreachable in normal operation.
		fmt.Fprintf(opts.Stderr, "defenseclaw: unknown hook connector %q\n", opts.Connector)
		return blockExit
	}
	// A managed hook's FailMode comes from administrator-owned runtime state
	// only (internal/cli: the Windows runtime generation or the Unix runtime
	// descriptor), never from a connector or the caller's environment.
	failMode := normalizeFailMode(opts.FailMode)
	if opts.StrictAvailability && !opts.ManagedEnterprise && (sp.connector == "copilot" || sp.connector == "antigravity") {
		// Strict availability closes a per-user Copilot CLI or Antigravity
		// hook whatever mode it was rendered with, as copilot-hook.sh and
		// antigravity-hook.sh do: the answer checks (decide) and every
		// failure path read the closed mode, so a Windows sidecar rendered
		// open cannot let a block without its native deny through. Other
		// connectors keep strict availability's transport and missing-token
		// scope.
		failMode = "closed"
		opts.FailMode = "closed"
	}
	if reason := strings.TrimSpace(opts.InvocationFailure); reason != "" && !opts.ManagedEnterprise {
		return failInvocation(opts, sp, reason)
	}
	if opts.ManagedEnterprise && strings.TrimSpace(opts.ManagedRuntimeFailure) != "" {
		if code, handled := refuseClosedUnboundHook(&opts, sp, "closed"); handled {
			return code
		}
		reason := strings.TrimSpace(opts.ManagedRuntimeFailure)
		if strings.HasPrefix(reason, ForeignHookBlockedReasonPrefix) {
			return failForeignHookBlocked(opts, sp, reason)
		}
		resolveManagedStandaloneFailureEvent(&opts, sp)
		if opts.ExplainUnenrolledAccount && !sp.failOpenOnly &&
			(reason == managedSIDUnregisteredReason || reason == managedEnrollmentPendingReason) {
			return failEnrollmentRefusal(opts, sp, reason)
		}
		return failUnreachable(
			opts,
			sp,
			"closed",
			reason,
		)
	}

	// A registration that lost its event is refused before an early exit
	// (an unavailable home, oversized input) answers it as an event that
	// cannot block.
	if code, handled := refuseClosedUnboundHook(&opts, sp, failMode); handled {
		return code
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
		return handleUnavailableHome(opts, sp, failMode, "DefenseClaw home is unavailable")
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
		return handleUnavailableHome(opts, sp, failMode, "DefenseClaw home is disabled")
	}

	payload, overflow, err := readCapped(opts.Stdin, opts.MaxBody)
	opts.failurePayload = payload
	// The agent may take its time writing the payload: an install that
	// started meanwhile closes this call.
	failMode = closeDuringInstall(&opts, failMode)
	if err != nil {
		// stdin read error is treated like an oversized/unusable payload.
		overflow = true
	}
	if overflow {
		opts.Event = managedHermesPrefixEvent(opts, sp, payload)
		return handleOversized(ctx, opts, sp, failMode, payload, startedAt)
	}
	if strings.EqualFold(strings.TrimSpace(opts.Connector), "codex") {
		event, bindingErr := validateCodexInvocationBinding(
			opts.Event,
			opts.HookContractID,
			payload,
		)
		opts.Event = strings.TrimSpace(opts.Event)
		if bindingErr != nil {
			if managedNativeDecision(opts) {
				return failManagedCodexBinding(opts, sp, bindingErr.Error())
			}
			return failResponse(opts, sp, nonOutageFailMode(opts, failMode), bindingErr.Error())
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
		bound := strings.TrimSpace(opts.Event) != ""
		opts.Event = resolveHookEvent(opts.Event, payload)
		if !bound && sp.connector == "hermes" && hookEventFieldsConflict(payload) {
			// Disagreeing event fields are ambiguous input, never a gateway
			// outage: outside Secure Client they block in every fail mode.
			conflict := opts
			if !opts.SecureClient {
				conflict.FailMode = "closed"
			}
			if hermesBlocksFailures(conflict, sp) {
				return failHermesEventConflict(conflict, sp)
			}
		}
	}
	if opts.Connector == "copilot" && !validCopilotEventForOptions(opts) {
		// Copilot's official camelCase stdin bodies do not identify the
		// event. Setup supplies the reviewed event through an exact --event
		// binding; never infer it from a body field or forward an untrusted
		// registration. A hook that fails closed was refused above
		// (refuseClosedUnboundHook). A broken binding is no gateway outage:
		// only a Secure Client hook gives Copilot its documented fail-open
		// result for this local integration failure.
		return failResponse(opts, sp, nonOutageFailMode(opts, failMode), "missing or unsupported Copilot hook event binding")
	}
	deadline := answerDeadline(opts, startedAt)
	// The work before the gateway request (the foreign-hook scan and
	// session exchange, the managed runtime) counts against the answer
	// budget. When it left the gateway less than hookGatewayAnswerFloor, a
	// missing answer is not the gateway's outage, and fail mode open does not
	// apply to it (final review, P2).
	opts.answerSpentLocally = gatewayAnswerWindowShort(opts, deadline)
	switch {
	case opts.answerWatch != nil && deadline.IsZero():
		// The hook command armed the watchdog for an event that is not a
		// tool call after all: it stands down.
		opts.answerWatch.answered()
	case opts.answerWatch != nil:
		opts.answerWatch.adopt(&opts, sp, failMode)
	case !deadline.IsZero():
		// A tool call is answered by its answer deadline even when this
		// process runs late (GAP-0155, GAP-0167).
		watchdog := startAnswerWatchdog(&opts, sp, failMode, deadline, progressCeiling(opts, startedAt))
		return watchdog.finish(sendToGateway(ctx, opts, sp, failMode, payload, startedAt))
	}
	return sendToGateway(ctx, opts, sp, failMode, payload, startedAt)
}

// failInvocation answers a per-user hook command that failed before it
// could check the call (Options.InvocationFailure) with the connector's
// closed answer for that event: Codex's own block object, Claude Code's,
// Devin's and Kiro's exit 2, Hermes' block directive, Copilot's and
// Antigravity's deny, Cursor's. It reads the payload for the event an
// unbound command does not name; an unbound Copilot or Antigravity command
// gets the denies refuseClosedUnboundHook gives.
func failInvocation(opts Options, sp spec, reason string) int {
	opts.FailMode = "closed"
	opts.StrictAvailability = true
	if code, handled := refuseClosedUnboundHook(&opts, sp, "closed"); handled {
		return code
	}
	payload, _, _ := readCapped(opts.Stdin, opts.MaxBody)
	opts.Event = resolveHookEvent(strings.TrimSpace(opts.Event), payload)
	return failResponse(opts, sp, "closed", reason)
}

// sendToGateway is Run once the call's payload and event are known: it
// builds the gateway client, reads the token and sends the call.
func sendToGateway(ctx context.Context, opts Options, sp spec, failMode string, payload []byte, startedAt time.Time) int {
	requestTimeout := hookRequestTimeout(opts.Connector, opts.Event) - time.Since(startedAt)
	if requestTimeout <= 0 {
		// The hook spent its own budget: no gateway outage was observed.
		return failUnreachable(opts, sp, nonOutageFailMode(opts, failMode), "hook request budget exhausted before gateway contact")
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, requestTimeout)
	requestHandedOff := false
	defer func() {
		if !requestHandedOff {
			cancel()
		}
	}()
	if opts.ManagedEnterprise && opts.ManagedStandalone && strings.TrimSpace(opts.ManagedUnixSocket) == "" {
		// The standalone profile has exactly one hook transport, the
		// peer-authorized unix socket. Without it there is nothing this
		// hook may contact: never fall back to loopback TCP or a token.
		return failUnreachable(opts, sp, "closed", managedGatewayPeerUnverifiedReason)
	}
	if opts.HTTPClient == nil {
		if opts.ManagedEnterprise {
			var err error
			// A gateway that binds its own hook socket (macOS) has none
			// for a moment while it restarts: wait for it within the
			// restart budget instead of failing closed at once.
			opts.HTTPClient, err = newManagedHookHTTPClient(ctx, opts, requestTimeout,
				gatewayRestartDeadline(opts, startedAt))
			if err != nil {
				return failUnreachable(withManagedOutage(opts, err), sp, managedPeerFailMode(opts, failMode, err), managedPeerFailureReason(opts, err))
			}
		} else {
			var err error
			opts.HTTPClient, err = newPerUserHookHTTPClient(requestTimeout, opts.APIAddr)
			if err != nil {
				return failUnreachable(opts, sp, "closed", "per-user gateway listener ownership could not be verified: "+err.Error())
			}
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
		return doRequest(ctx, opts, sp, failMode, payload, "", cancel, &requestHandedOff)
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

	return doRequest(ctx, opts, sp, failMode, payload, token, cancel, &requestHandedOff)
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
			var err error
			opts.HTTPClient, err = newPerUserHookHTTPClient(defaultHookRequestTimeout, opts.APIAddr)
			if err != nil {
				return 0
			}
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
func doRequest(ctx context.Context, opts Options, sp spec, failMode string, payload []byte, token string, requestCancel context.CancelFunc, requestHandedOff *bool) int {
	if pid := perUserForeignListener(opts); pid > 0 {
		return failUnreachable(opts, sp, failMode, foreignListenerReason(opts.APIAddr, pid))
	}
	restartDeadline := gatewayRestartDeadline(opts, opts.StartedAt)
	// One deadline bounds every wait of a tool call: the restart tries, the
	// dials, a gateway that accepted the call but does not answer, and the
	// resends below (hookAnswerBudget).
	opts.answerBy = answerDeadline(opts, opts.StartedAt)
	ctx, stopAnswer, stopResponseDeadline, releaseAnswer := awaitAnswerBy(ctx, opts.answerBy, progressCeiling(opts, opts.StartedAt), opts.answerWatch)
	ctx, stopWatch, releaseWatch := watchManagedGatewayStarts(ctx, opts, restartDeadline)
	// The account, its session, the asset facts and the resolved write
	// paths are computed once, for every try of this call.
	opts.requestFacts = &hookRequestFacts{}
	// A try that must have its connection within the restart budget
	// (connectBy); the response is read under its context.
	var releases []func()
	cleanup := func() {
		for _, release := range releases {
			release()
		}
		releaseWatch()
		releaseAnswer()
	}
	handedOff := false
	defer func() {
		if !handedOff {
			cleanup()
		}
	}()
	// A per-user hook's first try always gets a moment to connect
	// (firstTryConnectDeadline); the managed first try is send below.
	firstTry := !opts.ManagedEnterprise
	sendConnectedBy := func() (*http.Response, error) {
		connectDeadline := restartDeadline
		if firstTry {
			firstTry = false
			connectDeadline = firstTryConnectDeadline(restartDeadline, time.Now())
		}
		tryCtx, release := connectBy(ctx, connectDeadline)
		releases = append(releases, release)
		resp, err := sendHookRequest(tryCtx, opts, sp, payload, token)
		return resp, notConnectedError(tryCtx, err)
	}
	send := func() (*http.Response, error) { return sendHookRequest(ctx, opts, sp, payload, token) }
	if !opts.ManagedEnterprise {
		// Every try of a per-user hook.
		send = sendConnectedBy
	}
	resp, err := send()
	if !opts.ManagedEnterprise {
		// This account's own gateway is restarting or starting: send the
		// call again until the restart budget ends, starting the gateway
		// beside the tries after a refused connection.
		wait := awaitPerUserGateway(ctx, opts, restartDeadline, resp, err, send)
		resp, err = wait.resp, wait.err
		// Only a last try this account's gateway refused or dropped is an
		// outage; a listener whose owner was not proven fails below.
		outage := perUserOutageError(opts, err)
		switch {
		case wait.recoveryErr != nil && outage:
			// Keep the cause: hook-failures.jsonl is the only record of
			// why a hook could not start the gateway (GAP-0480).
			return failUnreachable(withPerUserOutage(opts), sp, failMode, coldStartFailureReason(wait.recoveryErr))
		case wait.outlasted && outage:
			return failUnreachable(withPerUserOutage(opts), sp, failMode, perUserGatewayRestartingReason)
		}
	}
	// A managed gateway that is restarting refuses the connection, or drops
	// one it accepted as it exits: send the call again, to the gateway that
	// starts, until the restart budget ends. Every try verifies the peer
	// again, and a call that never gets an answer still fails closed below.
	// A try after such a failure must have its connection within the
	// restart budget: one that began just before the budget ended and met a
	// slow service manager held the not-running deny past the answer budget
	// (GAP-0155, GAP-0167). It ends with the cause the gateway gave before.
	for opts.ManagedEnterprise && err != nil && awaitGatewayRestart(ctx, restartDeadline, err) {
		cause := err
		resp, err = sendConnectedBy()
		if errors.Is(err, errGatewayNotConnected) && ctx.Err() == nil {
			resp, err = nil, cause
			break
		}
	}
	if errors.Is(err, errInvalidHookRequest) {
		return failResponse(opts, sp, nonOutageFailMode(opts, failMode), err.Error())
	}
	// A managed Windows hook starts the installer-owned gateway after the
	// restart budget; a per-user hook started its own gateway above.
	if err != nil && opts.ManagedEnterprise && opts.GatewayRecovery != nil && connectionRefused(err) {
		if recoveryErr := opts.GatewayRecovery(ctx, err); recoveryErr == nil && ctx.Err() == nil {
			// The initial request proved no listener was present. Recovery verifies
			// and starts the exact installer-owned gateway, including authenticated
			// readiness, before this single retry.
			resp, err = sendHookRequest(ctx, opts, sp, payload, token)
		} else if gatewayNoAnswer(ctx) {
			return failNoAnswer(opts, sp, failMode)
		} else {
			return failUnreachable(opts, sp, failMode, coldStartFailedReason)
		}
	}
	// A response status is evidence that the gateway answered. An incomplete
	// 2xx body is an unusable answer, not an outage that may fail open.
	// Error statuses retain their existing retry and refusal handling.
	knownStatus := 0
	// markManagedAnsweredError (w8-mgmt) records the status on opts too, so
	// ManagedOutageFailsOpen, noAnswerFailMode and the watchdog's rendered
	// answer treat every later failure of the call as an answered error.
	noteStatus := func() {
		if err != nil {
			return
		}
		markManagedAnsweredError(&opts, sp, resp.StatusCode)
		if resp != nil && !opts.SecureClient &&
			(resp.StatusCode >= 200 && resp.StatusCode < 300 || managedNativeDecision(opts)) {
			knownStatus = resp.StatusCode
			opts.answerWatch.gatewayAnsweredError(opts, sp, resp.StatusCode)
		}
	}
	noteStatus()
	// A gateway that has taken all it can answer in time (or an account over
	// its own budget) answers 429 with Retry-After at once. The call has not
	// been evaluated, so it is sent again a few times within the hook's own
	// deadline instead of failing the tool call for a burst the gateway
	// clears in seconds (GAP-0205).
	//
	// A tool call with an answer budget is never denied for a busy gateway
	// before that budget ends (GAP-0050, owner ruling: in action or closed
	// mode a deny only after the full hook budget). A refusal of the
	// account's own budget (its in-flight cap or rate) clears as soon as
	// one of the account's own calls ends, usually well inside the whole
	// second Retry-After can say, so such a call is sent again after
	// hookCallerBusyRetryDelay; a resend that no longer fits waits for the
	// budget to end and the call is then denied as unanswered.
	retries := hookBusyRetries
	if !opts.answerBy.IsZero() {
		retries = hookBusyBoundedRetries
	}
	for retry := 0; !opts.SecureClient && err == nil && resp.StatusCode == http.StatusTooManyRequests && retry < retries; retry++ {
		delay := retryAfterDelay(resp.Header.Get("Retry-After"))
		if !opts.answerBy.IsZero() && callerBudgetRefusal(resp) {
			delay = min(delay, hookCallerBusyRetryDelay)
		}
		_ = resp.Body.Close()
		if !retryFitsAnswer(opts.answerBy, delay) {
			// A resend could not be answered within the tool call's
			// answer budget: the gateway is too busy for it now. The call
			// is denied when the budget ends, not before it.
			<-ctx.Done()
			if gatewayNoAnswer(ctx) {
				return failAfterErrorStatus(opts, sp, failMode, knownStatus)
			}
			return failUnreachable(opts, sp, nonOutageFailMode(opts, failMode), "gateway busy")
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			if gatewayNoAnswer(ctx) {
				return failAfterErrorStatus(opts, sp, failMode, knownStatus)
			}
			// The gateway answered 429: it is up, so no outage applies.
			return failUnreachable(opts, sp, nonOutageFailMode(opts, failMode), "gateway busy")
		case <-timer.C:
		}
		resp, err = sendHookRequest(ctx, opts, sp, payload, token)
		noteStatus()
	}
	// A newly enrolled Windows standalone account holds its runtime (and the
	// credential in it) a moment before the guardian's authorization ledger,
	// which the gateway rereads every second, names it, so its first call
	// can meet a 401 (GAP-0680). The call was not evaluated: send it again a
	// few times within the hook's deadline. Secure Client is unchanged.
	for retry := 0; err == nil && resp.StatusCode == http.StatusUnauthorized &&
		opts.ManagedEnterprise && opts.ExplainUnenrolledAccount && retry < hookAuthRetries &&
		retryFitsAnswer(opts.answerBy, hookAuthRetryDelay); retry++ {
		_ = resp.Body.Close()
		timer := time.NewTimer(hookAuthRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return failResponse(opts, sp, nonOutageFailMode(opts, failMode), fmt.Sprintf("gateway returned HTTP %d", http.StatusUnauthorized))
		case <-timer.C:
		}
		resp, err = sendHookRequest(ctx, opts, sp, payload, token)
		noteStatus()
	}
	delivery := (*hookDeliveryRequest)(nil)
	if err == nil && resp != nil {
		delivery = hookDeliveryResponse(resp.Body)
	}
	stopWatch()
	if delivery != nil && !delivery.capabilityReceived() {
		// A server that asks for a receipt without advertising full duplex
		// cannot accept one: its proposal is not an enforceable answer.
		delivery.close()
		_ = resp.Body.Close()
		return failResponse(opts, sp, "closed", "gateway delivery confirmation unavailable")
	}
	// Every check of the answer below, and every failure answer, uses the
	// install state of now: an install that started while the gateway had
	// not answered closes this call.
	failMode = closeDuringInstall(&opts, failMode)
	if err != nil {
		if managedNativeDecision(opts) && opts.answeredErrorStatus != 0 {
			return failAfterErrorStatus(opts, sp, "closed", opts.answeredErrorStatus)
		}
		reason := "gateway unreachable"
		switch cause := context.Cause(ctx); {
		case errors.Is(cause, errGatewayNoAnswer):
			// No decision in time: the hook's fail mode decides, unless
			// the gateway already answered with an error status.
			return failAfterErrorStatus(opts, sp, failMode, knownStatus)
		case errors.Is(cause, errGatewayStartFailing):
			reason = errGatewayStartFailing.Error()
		case errors.Is(cause, errGatewayRestarting):
			// A restart does not prove that the gateway service is stopped.
			return failUnreachable(opts, sp, "closed", managedGatewayRestartingReason)
		}
		if errors.Is(err, errManagedGatewayPeerUnverified) {
			// Managed peer-verification failure fails closed on the transport
			// surface too, mirroring the up-front client-build path: a managed
			// hook launched with FailMode="open" must not let an unverified
			// gateway peer surface as an allow-by-default. The one exception
			// is a gateway service that is not running (see
			// managedPeerFailMode).
			return failUnreachable(withManagedOutage(opts, err), sp, managedPeerFailMode(opts, failMode, err), managedPeerFailureReason(opts, err))
		}
		if !opts.SecureClient && (errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, errGatewayTookCallNoAnswer) || errors.Is(ctx.Err(), context.DeadlineExceeded)) {
			return failNoAnswer(opts, sp, failMode)
		}
		if reason == "gateway unreachable" && !opts.SecureClient && !secureClientHook(opts) && errors.Is(err, errGatewayTookCallNoAnswer) {
			// Same fail mode; the record says the gateway stalled, not that
			// it could not be reached. Secure Client keeps its reason.
			reason = noAnswerReason(opts)
		}
		if perUserOutageError(opts, err) {
			// This account's gateway refused or dropped the connection, or
			// gave none in time, and sent no status: an outage.
			opts = withPerUserOutage(opts)
		} else if !opts.ManagedEnterprise && errors.Is(err, errPerUserPeerUnverified) {
			reason = perUserPeerUnverifiedReason(opts)
		}
		return failUnreachable(opts, sp, failMode, reason)
	}
	defer func() {
		if !handedOff {
			_ = resp.Body.Close()
		}
	}()
	// A successful verdict is in only when its whole body is: the answer
	// budget holds while it is read. A gateway that sent its headers and part
	// of a body, then stalled or dropped the connection, has not answered, and
	// the bytes it sent are never taken as its decision. An error status is
	// already an answered refusal even if its body stalls or the connection
	// drops.
	var body []byte
	var readErr error
	if delivery != nil || resp.Header.Get(HookDeliveryRequiredHeader) == "1" {
		// A released request's answer is the same one line, ahead of the
		// gateway's audit write.
		body, readErr = bufio.NewReader(io.LimitReader(resp.Body, defaultMaxBody+1)).ReadBytes('\n')
	} else {
		body, readErr = io.ReadAll(io.LimitReader(resp.Body, defaultMaxBody+1))
	}
	if delivery == nil {
		stopAnswer()
	} else if readErr == nil && int64(len(body)) <= defaultMaxBody {
		// The complete proposal arrived in time. Its deadline no longer
		// governs the receipt, but the watchdog still owns the agent output
		// until finish commits it.
		stopResponseDeadline()
	}
	if (readErr != nil || int64(len(body)) > defaultMaxBody) && managedNativeDecision(opts) &&
		(resp.StatusCode < 200 || resp.StatusCode >= 300) {
		// The status line already answered with an error. A truncated or
		// oversized body cannot turn that error into an outage allow.
		return failResponse(opts, sp, nonOutageFailMode(opts, failMode), fmt.Sprintf("gateway returned HTTP %d", resp.StatusCode))
	}
	if readErr != nil {
		// HTTP 2xx plus an incomplete body is a malformed answer. The
		// gateway was reached, so outage-open mode cannot apply.
		return failAfterErrorStatus(opts, sp, failMode, knownStatus)
	}
	if int64(len(body)) > defaultMaxBody {
		if opts.SecureClient {
			return failResponse(opts, sp, normalizeFailMode(opts.FailMode), "gateway response too large")
		}
		return failResponse(opts, sp, "closed", "gateway response too large")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		opts.gatewayRefusal = perUserRefusalText(opts, resp.StatusCode, body)
	}
	// An HTTP status proves that the gateway was reached. Only Secure Client
	// may apply an open preference to a refusal or server error.
	answeredFailMode := nonOutageFailMode(opts, failMode)
	switch {
	case resp.StatusCode >= 500 && resp.StatusCode < 600:
		// A server error is the running gateway's answer, never an outage:
		// it closes outside Secure Client in every tier and fail mode.
		if !opts.SecureClient {
			return failResponse(opts, sp, answeredFailMode, fmt.Sprintf("gateway returned HTTP %d", resp.StatusCode))
		}
		return failUnreachable(opts, sp, failMode, fmt.Sprintf("gateway returned HTTP %d", resp.StatusCode))
	case (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusRequestEntityTooLarge) &&
		refusalReason(body) == MalformedHookPayloadReason && !opts.SecureClient:
		// A malformed event is a local check failure, never a gateway
		// outage. An explicit per-user open setting cannot turn it into
		// a tool call whose pre-tool fields DefenseClaw never parsed.
		return failResponse(opts, sp, "closed", "gateway refused malformed hook payload")
	case resp.StatusCode == http.StatusForbidden && refusalReason(body) == SurfaceUnverifiedReason:
		// A policy decision, not a failure: block in every fail mode (a stop
		// event keeps its neutral allow).
		if strings.TrimSpace(opts.Event) == "" {
			opts.Event = resolveHookEvent("", payload)
		}
		return failForeignHookBlocked(opts, sp, surfaceUnverifiedText(opts))
	case resp.StatusCode == http.StatusForbidden && managedStandaloneHook(opts) &&
		refusalReason(body) == managedUIDUnregisteredReason:
		// The gateway is up and refuses an account the enumerator has not
		// enrolled yet (or the policy excludes): say so, not "HTTP 403"
		// (GAP-0738).
		if strings.TrimSpace(opts.Event) == "" {
			opts.Event = resolveHookEvent("", payload)
		}
		return failEnrollmentRefusal(opts, sp, managedUIDUnregisteredReason)
	case resp.StatusCode == http.StatusForbidden && managedStandaloneHook(opts) &&
		refusalReason(body) == managedRootDeniedReason:
		// enrollment.root: deny refuses root: say so, not "an answer
		// DefenseClaw could not use" (GAP-0556).
		if strings.TrimSpace(opts.Event) == "" {
			opts.Event = resolveHookEvent("", payload)
		}
		return failEnrollmentRefusal(opts, sp, managedRootDeniedReason)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		// An authentication refusal is integrity, not an outage.
		return failResponse(opts, sp, answeredFailMode, fmt.Sprintf("gateway returned HTTP %d", resp.StatusCode))
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return failResponse(opts, sp, answeredFailMode, fmt.Sprintf("gateway returned HTTP %d", resp.StatusCode))
	}

	code := sp.decide(opts, body)
	if opts.oversizedReview && validUniqueGatewayResponse(body) {
		var verdict struct {
			Action string `json:"action"`
		}
		if json.Unmarshal(body, &verdict) == nil && (verdict.Action == "allow" || verdict.Action == "alert") {
			quiet := opts
			quiet.Stderr = io.Discard
			logHookFailure(quiet, sp, "stdin body exceeded cap; oversize, command not inspected", "transport", "open", false)
			fmt.Fprintf(opts.Stderr, "defenseclaw: warning: %s hook payload exceeded the bounded inspection cap (oversize, command not inspected); gateway allowed this call and recorded its verdict\n", sp.connector)
		}
	}
	if delivery != nil && resp.StatusCode == http.StatusOK && readErr == nil {
		opts.answerWatch.setDeliveryReceipt(func(answered, localBlock bool) {
			// finish calls this only after it writes the answer to the agent.
			// Keep the request alive for the receipt, using its request/HTTP
			// deadline rather than the already-met answer deadline.
			stopAnswer()
			if answered {
				receiptTimer := time.AfterFunc(hookDeliveryReceiptTimeout, requestCancel)
				defer receiptTimer.Stop()
				if delivery.acknowledge(localBlock) == nil {
					// Keep the request alive until HTTP has carried the receipt
					// to the gateway. A successful Pipe.Write alone only proves
					// that the transport read it into its own buffer.
					var confirmed [len(HookDeliveryConfirmed)]byte
					_, _ = io.ReadFull(resp.Body, confirmed[:])
				}
			} else {
				delivery.close()
			}
			_ = resp.Body.Close()
			cleanup()
			requestCancel()
		})
		handedOff = true
		*requestHandedOff = true
	}
	return code
}

// failAfterErrorStatus fails a call the gateway answered with the error
// status status (0: none) and then left without a decision. On a standalone
// hook that is no outage, so it is blocked in every fail mode: a busy gateway
// (429) with the no-answer reason a closed hook gives it, any other status
// with that status, as when its whole body is in. Per-user and Secure Client
// hooks, and a call with no error status, keep failNoAnswer.
func failAfterErrorStatus(opts Options, sp spec, failMode string, status int) int {
	if status >= 200 && status < 300 && !opts.SecureClient {
		return failResponse(opts, sp, "closed", "incomplete gateway response")
	}
	if status == 0 || !managedNativeDecision(opts) {
		return failNoAnswer(opts, sp, failMode)
	}
	if status == http.StatusTooManyRequests {
		return failUnreachable(opts, sp, "closed", managedGatewayNoAnswerReason)
	}
	reason := fmt.Sprintf("gateway returned HTTP %d", status)
	if status >= 500 && status < 600 {
		return failUnreachable(opts, sp, "closed", reason)
	}
	return failResponse(opts, sp, "closed", reason)
}

// perUserRefusalText is what a per-user hook shows in the agent when the
// gateway answered it with an error status and its own message
// ({"error": ...}): the agents that display the structured denial showed
// only "DefenseClaw hook failed closed", with no cause and no next step,
// for example after an agent update left its protected hook setup stale
// (GAP-0159; doctor names the fix). Managed hooks keep their own text, and
// a body that is not the gateway's JSON keeps the generic one.
func perUserRefusalText(opts Options, status int, body []byte) string {
	if opts.ManagedEnterprise || opts.ManagedUnixSocket != "" {
		return ""
	}
	var refusal struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &refusal) != nil {
		return ""
	}
	msg := strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, refusal.Error)), " ")
	if msg == "" {
		return ""
	}
	if len(msg) > 200 {
		msg = strings.ToValidUTF8(msg[:200], "") + "…"
	}
	return fmt.Sprintf("DefenseClaw blocked this %s: the DefenseClaw gateway refused it (HTTP %d: %s). "+
		"Run `defenseclaw doctor` to see why and how to fix it.", hookEventSubject(opts.Event), status, msg)
}

// hookBusyRetries is how many times a hook sends its call again after the
// gateway answered 429. A call with an answer budget may send it up to
// hookBusyBoundedRetries times: its budget, not the count, ends the resends.
const (
	hookBusyRetries        = 4
	hookBusyBoundedRetries = 32
)

// hookCallerBusyRetryDelay is the pause before a call with an answer budget
// is sent again after the gateway refused it for the account's own budget
// (GAP-0050). The refusal is local to the account and costs the gateway no
// evaluation, and a slot of the account frees as soon as one of its calls
// ends.
var hookCallerBusyRetryDelay = 250 * time.Millisecond

// callerBusyReason is the reason of a 429 for one caller's own budget
// (hook_caller_limits.go managedHookReasonRateLimited); a full gateway
// answers enterprise_managed_overloaded and keeps its Retry-After.
const callerBusyReason = "enterprise_managed_rate_limited"

// callerBusyRefusalBodyLimit bounds the 429 body read for its reason.
const callerBusyRefusalBodyLimit = 4 << 10

// callerBudgetRefusal reports a 429 whose body names the caller's own budget.
func callerBudgetRefusal(resp *http.Response) bool {
	if resp == nil || resp.Body == nil {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, callerBusyRefusalBodyLimit))
	return refusalReason(body) == callerBusyReason
}

// hookAuthRetries and hookAuthRetryDelay bound the resend of a Windows
// standalone call the gateway answered 401 (GAP-0680): about 8 seconds,
// inside every agent's hook timeout.
const hookAuthRetries = 4

var hookAuthRetryDelay = 2 * time.Second

// retryAfterDelay is the pause a 429's Retry-After asks for, in whole seconds,
// kept between 1 s and 3 s; a missing or unreadable value means 1 s.
func retryAfterDelay(value string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds < 1 {
		seconds = 1
	}
	return time.Duration(min(seconds, 3)) * time.Second
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
	if opts.refusal != "" {
		req.Header.Set(HookRefusalHeader, opts.refusal)
	}
	if !opts.answerBy.IsZero() {
		// The call is bounded by hookAnswerBudget: ask the gateway to say
		// when it waits on a remote scanner, which keeps the call waiting.
		req.Header.Set(HookProgressHeader, "1")
	}
	if v := strings.TrimSpace(opts.TraceParent); v != "" && validTraceparent(v) {
		req.Header.Set("traceparent", v)
	}
	if v := strings.TrimSpace(opts.TraceState); v != "" && validTracestate(v) {
		req.Header.Set("tracestate", v)
	}
	opts.requestFacts.set(req.Header, opts, payload)
	var delivery *hookDeliveryRequest
	if wantsHookDeliveryReceipt(opts) {
		req, delivery = prepareHookDeliveryRequest(req, payload, hookDeliveryWait(opts))
	}

	var connected atomic.Bool
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { connected.Store(true) },
	}))
	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		if delivery != nil {
			delivery.close()
		}
		return nil, markConnectedTimeout(err, connected.Load())
	}
	if delivery != nil {
		// A 103 after the capability wait still asks for a receipt; the
		// gateway reads the released marker instead and takes none.
		if resp.Header.Get(HookDeliveryRequiredHeader) == "1" && !delivery.wasReleased() {
			resp.Body = &hookDeliveryResponseBody{ReadCloser: resp.Body, delivery: delivery}
		} else {
			delivery.close()
		}
	}
	return resp, nil
}

// hookRequestFacts are the headers of a hook call that cost work to
// compute: the resolved write paths, the account and its session (system
// calls; on Windows a call into the LSA) and the asset facts read from the
// user's home. A call that waits for a restarting gateway sends its request
// again every 200 ms, and on a host that was already slow computing them for
// every try held the call past its answer budget (GAP-0155). They are
// computed once, on the first try, and copied into every try after it.
type hookRequestFacts struct {
	once   sync.Once
	header http.Header
}

// set adds the call's facts to header; a nil hookRequestFacts computes them
// for this request alone.
func (f *hookRequestFacts) set(header http.Header, opts Options, payload []byte) {
	if f == nil {
		setHookRequestFacts(header, opts, payload)
		return
	}
	f.once.Do(func() {
		f.header = make(http.Header)
		setHookRequestFacts(f.header, opts, payload)
	})
	for name, values := range f.header {
		header[name] = slices.Clone(values)
	}
}

func setHookRequestFacts(header http.Header, opts Options, payload []byte) {
	startupEvent := hookpaths.IsSessionStartEvent(opts.Event)
	if opts.ManagedEnterprise && !opts.SecureClient &&
		(runtime.GOOS != "windows" || startupEvent) {
		// The surface and bound event are the ones this call sends the
		// gateway (HookDialectHeader, X-DefenseClaw-Copilot-Event), so the
		// evidence reads the body in the dialect the gateway judges.
		if resolved := hookpaths.ResolveConnector(opts.Connector, hookDialect(opts), opts.Event, payload); resolved != "" {
			header.Set(hookpaths.Header, resolved)
		}
	}
	setUserIdentityHeaderValues(header, opts)
	if opts.AssetFacts != nil && opts.ManagedEnterprise && !secureClientHook(opts) {
		if value := opts.AssetFacts(opts.Connector, payload); value != "" {
			header.Set(assetfacts.Header, value)
		}
	}
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
func setUserIdentityHeaders(req *http.Request, opts Options) {
	setUserIdentityHeaderValues(req.Header, opts)
}

// setUserIdentityHeaderValues is setUserIdentityHeaders for a header set.
func setUserIdentityHeaderValues(header http.Header, opts Options) {
	// A Secure Client hook keeps its earlier requests: the account name as
	// the system reports it and no session facts, so it runs no klist and
	// writes nothing in the home of the user (issue #1092).
	secureClient := secureClientHook(opts)
	useridentity.KeepQualifiedNames(secureClient)
	identity := useridentity.Current()
	if v := identity.ID; safeIdentityHeaderValue(v) {
		header.Set("X-DefenseClaw-User-Id", v)
	}
	if v := identity.Name; safeIdentityHeaderValue(v) {
		header.Set("X-DefenseClaw-User-Name", v)
	}
	// The session the hook runs in (SSH, logind, the Kerberos default
	// principal): claimed facts the gateway uses for attribution only.
	// useridentity renders it from an allowlisted charset and bounds it.
	if secureClient {
		return
	}
	if v := useridentity.CurrentSessionFactsHeader(); v != "" {
		header.Set(useridentity.SessionFactsHeader, v)
	}
}

// secureClientHook reports a hook of the Secure Client profile: an
// administrator-managed hook that is neither the Unix standalone hook nor
// the Windows standalone binary.
func secureClientHook(opts Options) bool {
	return opts.ManagedEnterprise && !managedStandaloneHook(opts) && !opts.ExplainUnenrolledAccount
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
	// The answer is checked with the install state of now: an install that
	// started while the gateway's body was read closes this call, so an
	// answer whose native output contradicts its action is refused, not
	// forwarded (GAP-0916).
	closeDuringInstall(&opts, "")
	if !opts.SecureClient && !validUniqueGatewayResponse(body) {
		return failResponse(opts, sp, "closed", "invalid or ambiguous JSON response")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return failResponse(opts, sp, nonOutageFailMode(opts, normalizeFailMode(opts.FailMode)), "invalid JSON response")
	}
	if sp.connector == "hermes" {
		return decideHermes(opts, sp, fields)
	}

	action, ok := rawString(fields, "action")
	if !ok || (action != "allow" && action != "alert" && action != "block" && action != "confirm") {
		lifecycle := managedNativeDecision(opts) && NeutralLifecycleEvent(sp.connector, opts.Event)
		if opts.SecureClient && (sp.style == styleClaudeCode || sp.style == styleCodex || sp.style == styleActionStderr) {
			return failResponse(opts, sp, normalizeFailMode(opts.FailMode), "invalid or missing action in gateway response")
		}
		if !opts.SecureClient && !lifecycle {
			return failResponse(opts, sp, "closed", "invalid or missing action in gateway response")
		}
		action = "allow"
		if lifecycle && sp.style == stylePluginBridge {
			body = []byte(`{"action":"allow"}`)
		}
	}
	reason := rawStringOr(fields, "reason", "")
	output := compactField(fields, sp.outputField)
	if sp.style == stylePluginBridge {
		output = compactField(fields, "hook_output")
	}
	if sp.connector == "claudecode" && action == "block" && claudeTerminalStopEvent(opts.Event) &&
		output != "" && !nativeOutputAgrees(sp, opts.Event, action, output) {
		// A contradictory Stop directive cannot turn a gateway block into a
		// neutral allow or a retrying decision. A block without a directive
		// is a policy denial: exit 2 gives Claude Code its feedback below.
		logHookFailure(opts, sp, "gateway block without a matching Claude Stop answer", "response", "closed", true)
		if reason == "" {
			reason = "DefenseClaw hook failed closed."
		}
		fmt.Fprintln(opts.Stdout, `{"continue":false,"stopReason":`+mustJSONString(reason)+`}`)
		return 0
	}
	if managedNativeDecision(opts) && managedNativeBlockableEvent(sp.connector, opts.Event) && output == "" &&
		(action == "block" || action == "confirm" || (sp.connector == "cursor" && action == "allow")) &&
		(sp.style == styleHookEcho || sp.style == styleHookEchoDecision || sp.style == styleHookDecisionStderr || sp.style == stylePluginBridge) {
		return failResponse(opts, sp, "closed", "missing native output in gateway response")
	}
	if !opts.SecureClient &&
		(action == "block" || action == "confirm") &&
		(sp.style == styleHookEcho || sp.style == styleHookEchoDecision || sp.style == styleHookDecisionStderr || sp.style == stylePluginBridge) &&
		(sp.connector != "cursor" || output != "" || managedNativeDecision(opts)) &&
		!nativeOutputAgrees(sp, opts.Event, action, output) {
		return failNativeDecision(opts, sp, "native output contradicts gateway action")
	}
	if !opts.SecureClient && output != "" && (action == "block" || action == "confirm") &&
		(sp.style == styleClaudeCode || sp.style == styleCodex) &&
		(sp.style != styleCodex || codexEventCanControl(opts.HookContractID, opts.Event)) &&
		!nativeOutputAgrees(sp, opts.Event, action, output) {
		return failResponse(opts, sp, "closed", "native output contradicts gateway action")
	}
	if !opts.SecureClient && action == "confirm" && output == "" &&
		(sp.style == styleClaudeCode || sp.style == styleCodex) &&
		(sp.style != styleCodex || codexEventCanControl(opts.HookContractID, opts.Event)) {
		// A confirmation is the gateway's ask; Claude Code and Codex ask only
		// through the native object, so without one the call would run as if
		// the gateway had allowed it. It is refused closed, in every fail
		// mode, as an answer that contradicts its action is (GAP-0983).
		return failResponse(opts, sp, "closed", missingNativeAskReason)
	}

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
		if sp.connector == "copilot" && (action == "allow" || action == "alert") {
			var ids []string
			if json.Unmarshal(fields["rule_ids"], &ids) == nil && slices.Contains(ids, "HOOK-TOOL-CALL-UNPARSED") && reason != "" {
				fmt.Fprintln(opts.Stderr, "defenseclaw: "+reason)
			}
		}
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
			return failResponse(opts, sp, nonOutageFailMode(opts, normalizeFailMode(opts.FailMode)), "invalid JSON response")
		}
		fmt.Fprintln(opts.Stdout, compact.String())
		return 0

	default:
		return 0
	}
}

// missingNativeAskReason is the hook-failure reason of a confirmation that
// carries no native ask (GAP-0983).
const missingNativeAskReason = "confirm without native output in gateway response"

// managedNativeDecision reports a managed hook outside Secure Client (the
// standalone profile, Unix or Windows).
func managedNativeDecision(opts Options) bool {
	return opts.ManagedEnterprise && !opts.SecureClient
}

// markManagedAnsweredError makes the first HTTP error decisive for the
// watchdog and every later failure path. A later valid verdict can still
// decide the call; a failed retry cannot become a gateway outage.
func markManagedAnsweredError(opts *Options, sp spec, status int) {
	if !managedNativeDecision(*opts) || status >= 200 && status < 300 || opts.answeredErrorStatus == status {
		return
	}
	opts.answeredErrorStatus = status
	opts.answerWatch.closeForAnsweredError(*opts, sp)
}

func answeredErrorReason(opts Options) string {
	return fmt.Sprintf("gateway returned HTTP %d", opts.answeredErrorStatus)
}

// nonOutageFailMode is the fail mode of a failure that is no confirmed
// gateway outage: an HTTP status or other answer, an integrity failure (an
// authentication refusal, a local event binding or hook contract mismatch),
// an invalid request or a budget the hook spent itself. Outside Secure
// Client it is closed whatever the user or administrator chose for outages;
// Secure Client keeps failMode.
func nonOutageFailMode(opts Options, failMode string) string {
	if opts.SecureClient {
		return failMode
	}
	return "closed"
}

// withManagedOutage marks opts for a failure caused by err, a gateway outage
// that ManagedOutageFailsOpen lets through.
func withManagedOutage(opts Options, err error) Options {
	opts.managedOutageOpen = ManagedOutageFailsOpen(opts, err)
	return opts
}

// managedNonOutageMode is the fail mode of a failure on a standalone hook
// outside Secure Client: failMode only for an outage withManagedOutage
// marked, closed for everything else (oversized input, an unusable or
// error answer, a transport error that is not an outage, a local budget),
// for every connector. opts.FailMode follows, because the Hermes and
// Copilot helpers read it. Per-user and Secure Client hooks keep failMode.
func managedNonOutageMode(opts *Options, failMode string) string {
	if managedNativeDecision(*opts) && !opts.managedOutageOpen {
		opts.FailMode = "closed"
		return "closed"
	}
	return failMode
}

func failNativeDecision(opts Options, sp spec, reason string) int {
	if !opts.SecureClient {
		// A complete but contradictory answer cannot use outage-open mode.
		opts.FailMode = "closed"
	}
	if sp.connector == "copilot" && !opts.SecureClient {
		// Copilot CLI ignores a failed hook process, but honors its native
		// structured deny. An unusable 2xx verdict is a failed check.
		if body := copilotVSCodeLocalOutput(opts.Event, "block", reason); sp.dialect == copilotVSCodeLocalSurface && body != "" {
			fmt.Fprintln(opts.Stdout, body)
			return 0
		}
		message := mustJSONString("DefenseClaw hook failed closed")
		switch opts.Event {
		case "preToolUse":
			fmt.Fprintln(opts.Stdout, `{"permissionDecision":"deny","permissionDecisionReason":`+message+`}`)
			return 0
		case "permissionRequest":
			fmt.Fprintln(opts.Stdout, `{"behavior":"deny","message":`+message+`}`)
			return 0
		}
	}
	return failResponse(opts, sp, normalizeFailMode(opts.FailMode), reason)
}

func managedNativeBlockableEvent(connector, event string) bool {
	switch connector {
	case "cursor":
		switch strings.ToLower(strings.TrimSpace(event)) {
		case "beforesubmitprompt", "pretooluse", "beforereadfile", "beforetabfileread", "beforeshellexecution", "beforemcpexecution":
			return true
		}
	case "copilot":
		return event == "preToolUse" || event == "permissionRequest"
	case "antigravity", "devin":
		return event == "PreToolUse"
	case "kiro":
		return event == "PreToolUse" || event == "UserPromptSubmit"
	case "opencode":
		return event == "tool.execute.before"
	}
	return false
}

func claudeTerminalStopEvent(event string) bool {
	switch event {
	case "Stop", "SubagentStop", "TeammateIdle":
		return true
	}
	return false
}

// nativeOutputAgrees checks the vendor decision that actually reaches the
// agent. A complete gateway response can still contain an allow-shaped native
// directive beside a block action; the native directive wins at the agent.
func nativeOutputAgrees(sp spec, event, action, output string) bool {
	blockable := managedNativeBlockableEvent(sp.connector, event)
	if sp.style == styleClaudeCode {
		blockable = true
	}
	if sp.style == styleCodex {
		blockable = codexEventCanControl("codex-hooks-v4", event)
	}
	if sp.dialect == copilotVSCodeLocalSurface && (event == "PreToolUse" || event == "UserPromptSubmit") {
		blockable = true
	}
	if !blockable {
		return true
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(output), &fields); err != nil || fields == nil {
		return false
	}
	want := "deny"
	if action == "confirm" {
		want = "ask"
	}
	switch sp.connector {
	case "claudecode", "codex":
		if sp.style == styleClaudeCode && action == "block" && claudeTerminalStopEvent(event) {
			// A recovered gateway panic ends the turn without another
			// Stop callback. This universal field takes precedence over
			// the event's retrying decision:block response.
			if raw, present := fields["continue"]; present {
				return bytes.Equal(bytes.TrimSpace(raw), []byte("false")) &&
					rawStringOr(fields, "stopReason", "") != ""
			}
		}
		var nested map[string]json.RawMessage
		if json.Unmarshal(fields["hookSpecificOutput"], &nested) == nil && nested != nil {
			if outputEvent := rawStringOr(nested, "hookEventName", ""); outputEvent != "" && outputEvent != event {
				return false
			}
			switch event {
			case "PreToolUse":
				return rawStringOr(nested, "permissionDecision", "") == want
			case "PermissionRequest":
				var decision map[string]json.RawMessage
				return json.Unmarshal(nested["decision"], &decision) == nil &&
					rawStringOr(decision, "behavior", "") == want
			case "Elicitation", "ElicitationResult":
				return action == "block" && rawStringOr(nested, "action", "") == "decline"
			case "UserPromptSubmit":
				// Older Codex contracts also carry a prompt denial here.
				if sp.style == styleCodex && rawStringOr(nested, "permissionDecision", "") == want {
					return true
				}
			}
		}
		if event == "PreToolUse" || event == "PermissionRequest" || event == "Elicitation" || event == "ElicitationResult" {
			return false
		}
		if action == "confirm" {
			return rawStringOr(fields, "decision", "") == "ask"
		}
		if event == "PreCompact" && sp.style == styleClaudeCode {
			// Claude Code stops a compaction on decision block, the shape
			// the gateway renders for it (GAP-0326).
			return rawStringOr(fields, "decision", "") == "block"
		}
		if event == "SessionStart" || event == "PreCompact" || event == "PostCompact" {
			var continued bool
			return sp.style == styleCodex && json.Unmarshal(fields["continue"], &continued) == nil && !continued
		}
		return rawStringOr(fields, "decision", "") == "block"
	case "cursor":
		if event == "beforeSubmitPrompt" {
			var continued bool
			return action == "block" && json.Unmarshal(fields["continue"], &continued) == nil && !continued
		}
		return rawStringOr(fields, "permission", "") == want
	case "copilot":
		if sp.dialect == copilotVSCodeLocalSurface {
			if event == "UserPromptSubmit" {
				var continued bool
				return action == "block" && json.Unmarshal(fields["continue"], &continued) == nil && !continued
			}
			var nested map[string]json.RawMessage
			if err := json.Unmarshal(fields["hookSpecificOutput"], &nested); err != nil {
				return false
			}
			return rawStringOr(nested, "permissionDecision", "") == want
		}
		if event == "permissionRequest" {
			return rawStringOr(fields, "behavior", "") == want
		}
		return rawStringOr(fields, "permissionDecision", "") == want
	case "antigravity":
		// Antigravity reads only its documented decision values. A
		// confirmation must be force_ask: its plain ask honors a cached
		// Always Allow grant and can run the call unasked (GAP-0405).
		if action == "confirm" {
			want = "force_ask"
		}
		return rawStringOr(fields, "decision", "") == want
	case "devin", "kiro", "opencode":
		decision := rawStringOr(fields, "decision", "")
		if action == "confirm" {
			return decision == "ask" || decision == "confirm"
		}
		return decision == "deny" || decision == "block"
	}
	return false
}

func decideHermes(opts Options, sp spec, fields map[string]json.RawMessage) int {
	invalidMode, configuredMode := "closed", "closed"
	if opts.SecureClient {
		invalidMode, configuredMode = "open", normalizeFailMode(opts.FailMode)
	}
	action, ok := rawString(fields, "action")
	if !ok {
		return failResponse(opts, sp, invalidMode, "invalid or missing action in Hermes gateway response")
	}
	rawOutput, present := fields[sp.outputField]
	if !present || strings.TrimSpace(string(rawOutput)) == "null" {
		if hermesToolCallEvent(opts.Event) && !managedHermesAnswerUsable(action) {
			// A block without its directive, or an answer with no usable
			// verdict, would let the call run. Outside Secure Client an
			// unusable response blocks in every outage mode.
			if action == "block" {
				return failResponse(opts, sp, configuredMode, "Hermes gateway block without a hook_output directive")
			}
			return failResponse(opts, sp, configuredMode, "invalid or missing action in Hermes gateway response")
		}
		return 0
	}
	var output map[string]json.RawMessage
	if err := json.Unmarshal(rawOutput, &output); err != nil || output == nil {
		return failResponse(opts, sp, invalidMode, "invalid Hermes hook_output object")
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
		return failResponse(opts, sp, invalidMode, "unsupported or contradictory Hermes gateway response")
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
	failMode = closeDuringInstall(&opts, failMode)
	closes := opts.ManagedEnterprise || (!sp.failOpenOnly && (opts.StrictAvailability || failMode == "closed"))
	if opts.ManagedEnterprise {
		// A managed hook's token is installer state: a missing one is a
		// broken or altered install, not an outage, so it is closed in
		// fail mode open too.
		failMode = "closed"
		opts.FailMode = "closed"
	}
	if closes && failClosedStopEvent(opts, sp) {
		return allowFailClosedStop(opts, sp, reason, "transport")
	}
	logHookFailure(opts, sp, reason, "transport", failMode, closes)
	if code, handled := copilotFailClosed(opts, sp, "transport", reason); handled {
		return code
	}
	if closes {
		if sp.connector == "antigravity" {
			fmt.Fprintf(opts.Stderr,
				"defenseclaw: %s, applying Antigravity's event-specific failure response\n", reason)
		} else {
			fmt.Fprintf(opts.Stderr,
				"defenseclaw: %s, blocking %s (fail mode closed)\n", reason, sp.subject)
		}
		return emitHookResult(opts, sp, sp.unreachableStrict)
	}
	return emitFailOpenAllow(opts, sp, reason)
}

// handleUnavailableHome refuses an unavailable registered per-user hook in
// closed mode. Explicitly open hooks keep their no-op behavior. Run handles
// managed hooks before this function.
func handleUnavailableHome(opts Options, sp spec, failMode, reason string) int {
	if failMode == "closed" || opts.StrictAvailability {
		if sp.connector == "hermes" {
			if code, handled := hermesFailClosed(opts, sp, "transport", reason); handled {
				return code
			}
		}
		if sp.connector == "copilot" && managedNativeBlockableEvent(sp.connector, opts.Event) {
			opts.FailMode = "closed"
			return failNativeDecision(opts, sp, reason)
		}
	}
	closes := !sp.failOpenOnly && (opts.StrictAvailability || failMode == "closed")
	if closes && failClosedStopEvent(opts, sp) {
		return allowFailClosedStop(opts, sp, reason, "transport")
	}
	if closes {
		if sp.connector == "antigravity" {
			fmt.Fprintf(opts.Stderr, "defenseclaw: %s, applying Antigravity's event-specific failure response\n", reason)
		} else {
			basis := "fail mode closed"
			if opts.StrictAvailability {
				basis = "strict availability"
			}
			fmt.Fprintf(opts.Stderr, "defenseclaw: %s, blocking %s (%s)\n", reason, sp.subject, basis)
		}
		return emitHookResult(opts, sp, sp.unreachableStrict)
	}
	return emitFailOpenAllow(opts, sp, reason)
}

// handleOversized mirrors the per-connector oversized-payload branch. prefix
// is the start of the payload the hook read before it stopped at its cap.
func handleOversized(ctx context.Context, opts Options, sp spec, failMode string, prefix []byte, startedAt time.Time) int {
	failMode = closeDuringInstall(&opts, failMode)
	// The bounded read has inspected no more than MaxBody+1 bytes. A balanced
	// per-user hook asks the gateway to judge the metadata and content prefix.
	// Only a gateway allow permits the call; a transport outage follows the
	// existing per-user outage rule in sendToGateway.
	if !opts.ManagedEnterprise && !opts.SecureClient && !opts.StrictAvailability &&
		opts.OutageFailModeNow != nil && normalizeFailMode(opts.OutageFailModeNow()) == "open" && !perUserInstallWindow(opts) {
		// A prefix the reducer cannot turn into one request (a duplicated
		// key) keeps the closed oversize answer below. Every review is marked
		// uninspected (OversizeUninspectedField): the gateway warns and
		// audits it in observe mode and blocks it in action mode.
		bound := opts.Event
		if sp.connector == "copilot" || sp.connector == "antigravity" {
			bound = "" // their bodies carry no event; the request header binds it
		}
		if review := oversizedReviewPayload(prefix, bound); review != nil {
			if strings.TrimSpace(opts.Event) == "" {
				opts.Event = resolveHookEvent("", review)
			}
			opts.oversizedReview = true
			return sendToGateway(ctx, opts, sp, failMode, review, startedAt)
		}
	}
	// All managed and strict hooks keep their closed local-failure behavior.
	failMode = managedNonOutageMode(&opts, failMode)
	if !opts.SecureClient {
		failMode, opts.FailMode = "closed", "closed"
	}
	if !sp.failOpenOnly && failMode == "closed" && failClosedStopEvent(opts, sp) {
		return allowFailClosedStop(opts, sp, "stdin body exceeded cap", "transport")
	}
	closes := !sp.failOpenOnly && failMode == "closed"
	logHookFailure(opts, sp, "stdin body exceeded cap", "transport", failMode, closes)
	if closes && managedPlainFailClosed(opts, sp) {
		fields := payloadPrefixFields(prefix)
		if strings.TrimSpace(opts.Event) == "" {
			// Claude Code binds no event: without it the refusal was a raw
			// stderr line about a "request" (GAP-0965).
			opts.Event = fields["hook_event_name"]
			if opts.Event == "" {
				opts.Event = fields["event"]
			}
		}
		reportOversizedRefusal(opts, sp, fields)
		return failManagedStandaloneClosed(opts, sp, sp.oversizedClosed, "oversized", "stdin body exceeded cap")
	}
	fmt.Fprintf(opts.Stderr, "defenseclaw: %s hook refusing oversized payload\n", sp.connector)
	if code, handled := hermesFailClosed(opts, sp, "oversized", "stdin body exceeded cap"); handled {
		return code
	}
	if code, handled := copilotFailClosed(opts, sp, "oversized", "stdin body exceeded cap"); handled {
		return code
	}
	if closes {
		return emitHookResult(opts, sp, sp.oversizedClosed)
	}
	return emitFailOpenAllow(opts, sp, "stdin body exceeded cap")
}

// failUnreachable applies the connector's effective fail mode to native hook
// transport failures. Strict availability remains an unconditional closed
// override for compatibility with existing deployments.
// emitFailOpenAllow answers a call that a failure lets through (fail mode
// open) with the connector's allow. The managed OpenCode plugin (the only
// caller of the OpenCode hook, always --enterprise-managed) reads an empty
// answer as closed, so it gets an explicit allow with the fail-open notice
// (GAP-0351); every other connector keeps its openAllow. On a standalone
// host the explicit allow is given only for an outage withManagedOutage
// marked; any other path gets the empty answer, which the plugin blocks.
func emitFailOpenAllow(opts Options, sp spec, reason string) int {
	// The installer may acquire the lock while the gateway call is in flight.
	// Recheck at the last shared fail-open exit as well as at hook entry.
	if sp.connector == "copilot" && perUserInstallWindow(opts) {
		if code, blocked := blockPerUserCopilotInstall(opts, sp); blocked {
			return code
		}
	}
	if sp.connector == "opencode" && opts.ManagedEnterprise && (!managedNativeDecision(opts) || opts.managedOutageOpen) {
		fmt.Fprintln(opts.Stdout, openCodeFailOpenBody(openCodeFailOpenNotice(reason)))
		return 0
	}
	return emitHookResult(opts, sp, sp.openAllow)
}

// withPerUserOutage marks opts for a per-user failure that is a gateway
// outage, so failUnreachable answers it with the runtime config's mode.
func withPerUserOutage(opts Options) Options {
	opts.perUserOutage = !opts.ManagedEnterprise && opts.ManagedUnixSocket == "" && !opts.SecureClient
	return opts
}

// perUserOutageError reports a per-user transport error that is a gateway
// outage: a connection this account's gateway refused, reset or closed
// before any status (it exited or is restarting), or none within the
// restart budget. A call the gateway took and did not answer in time
// (errGatewayTookCallNoAnswer), a listener whose owner was not proven
// (errPerUserPeerUnverified), an invalid request and every other error are
// not, and neither is any error after an HTTP status: the gateway answered.
func perUserOutageError(opts Options, err error) bool {
	if opts.ManagedEnterprise || opts.ManagedUnixSocket != "" || opts.SecureClient || err == nil ||
		opts.answeredErrorStatus != 0 || errors.Is(err, errGatewayTookCallNoAnswer) || errors.Is(err, errInvalidHookRequest) ||
		errors.Is(err, errPerUserPeerUnverified) {
		return false
	}
	return gatewayRestartShaped(err)
}

// perUserOutageMode is the fail mode of a per-user failure: the config on
// disk (OutageFailModeNow) decides a classified gateway outage, and failMode
// governs every other failure.
// Strict availability and this account's install window close the outage
// too (closeDuringInstall runs first).
func perUserOutageMode(opts *Options, failMode string) string {
	if !opts.perUserOutage {
		return failMode
	}
	mode := "closed"
	if !opts.StrictAvailability && !perUserInstallWindow(*opts) && opts.OutageFailModeNow != nil {
		mode = normalizeFailMode(opts.OutageFailModeNow())
	}
	opts.FailMode = mode
	return mode
}

func failUnreachable(opts Options, sp spec, failMode, reason string) int {
	failMode = closeDuringInstall(&opts, failMode)
	failMode = managedNonOutageMode(&opts, failMode)
	failMode = perUserOutageMode(&opts, failMode)
	if perUserInstallWindow(opts) {
		// An install or upgrade stops this account's gateway and starts it
		// again when it is done. That window is not an outage, so an open
		// fail mode does not let the call through unchecked (GAP-0649).
		if sp.connector == "copilot" {
			if code, blocked := blockPerUserCopilotInstall(opts, sp); blocked {
				return code
			}
		}
		failMode = "closed"
		opts.FailMode = "closed"
	}
	if failMode == "closed" {
		// A refusal passed in closed (a peer DefenseClaw cannot verify, an
		// invalid runtime) stays closed for the connectors whose helpers read
		// the hook's own mode (Hermes) even when that mode is open.
		opts.FailMode = "closed"
	}
	if !sp.failOpenOnly && (opts.StrictAvailability || failMode == "closed") && failClosedStopEvent(opts, sp) {
		return allowFailClosedStop(opts, sp, reason, "transport")
	}
	blocked := !sp.failOpenOnly && (opts.StrictAvailability || failMode == "closed")
	logHookFailure(opts, sp, reason, "transport", failMode, blocked)
	if !managedCopilotOpen(opts, sp, failMode) {
		if code, handled := copilotFailClosed(opts, sp, "transport", reason); handled {
			return code
		}
	}
	if blocked {
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
	showWarning := true
	if opts.perUserOutage {
		showWarning = firstOutageWarning(opts)
	}
	if text := perUserOutageOpenText(opts, reason); text != "" && opts.perUserOutage {
		if showWarning && perUserGatewayDownNotice(opts, sp, reason) == "" {
			fmt.Fprintf(opts.Stderr, "defenseclaw: %s\n", text)
		}
	} else {
		if showWarning {
			fmt.Fprintf(opts.Stderr, "defenseclaw: %s: %s\n", unreachableLead(opts, sp, reason, "allowing"), unreachableDetail(opts, reason))
		}
	}
	if notice := perUserGatewayDownNotice(opts, sp, reason); notice != "" && showWarning {
		fmt.Fprintln(opts.Stdout, notice)
		return 0
	}
	return emitFailOpenAllow(opts, sp, reason)
}

// installLockName is the folder install.sh and install.ps1 hold in the data
// directory while they install or upgrade this account's DefenseClaw
// (internal/cli installLockName).
const installLockName = ".install.lock"

// perUserInstallWindow reports a per-user hook (not managed, not Secure
// Client) running while an install or upgrade of this account's DefenseClaw
// holds installLockName.
func perUserInstallWindow(opts Options) bool {
	if opts.ManagedEnterprise || opts.ManagedUnixSocket != "" || opts.SecureClient || strings.TrimSpace(opts.Home) == "" {
		return false
	}
	return installLockHeld(opts.Home)
}

// Copilot ignores a failed hook process. During a per-user install every
// failure answer (no gateway, an error status, an unusable answer, a missing
// token) needs the native deny for each actionable event, so no failure
// turns into an unchecked call. A call the gateway answers keeps that answer
// in the default and permissive tiers, as every other connector's does
// (owner decision 2026-10-24, GAP-1372). Lifecycle events have no blocking
// response and remain neutral so an agent can stop.
func blockPerUserCopilotInstall(opts Options, sp spec) (int, bool) {
	if NeutralLifecycleEvent(sp.connector, opts.Event) {
		return 0, false
	}
	message := perUserGatewayDownText(opts, "gateway unreachable")
	quoted := mustJSONString(message)
	var body string
	if sp.dialect == copilotVSCodeLocalSurface {
		body = copilotVSCodeLocalOutput(opts.Event, "block", message)
	} else {
		switch opts.Event {
		case "preToolUse":
			body = `{"permissionDecision":"deny","permissionDecisionReason":` + quoted + `}`
		case "permissionRequest":
			body = `{"behavior":"deny","message":` + quoted + `}`
		default:
			// An unreviewed event binding must not open a tool call while
			// the installer holds the lock. Copilot ignores fields it cannot
			// use on lifecycle events.
			body = `{"permissionDecision":"deny","permissionDecisionReason":` + quoted +
				`,"behavior":"deny","message":` + quoted + `}`
		}
	}
	if body == "" {
		return 0, false
	}
	logHookFailure(opts, sp, "per-user install or upgrade in progress", "transport", "closed", true)
	fmt.Fprintln(opts.Stderr, "defenseclaw: blocking Copilot call while DefenseClaw is being installed or upgraded")
	fmt.Fprintln(opts.Stdout, body)
	return 0, true
}

const coldStartFailedReason = "gateway cold start failed"

// coldStartFailureReason is the logged reason of a failed hook cold start,
// with the first line of its cause, bounded.
func coldStartFailureReason(err error) string {
	if err == nil {
		return coldStartFailedReason
	}
	// The cause names local paths only; Secure Client keeps the bare reason.
	cause, _, _ := strings.Cut(strings.TrimSpace(err.Error()), "\n")
	if len(cause) > 300 {
		cause = cause[:300]
	}
	return coldStartFailedReason + ": " + cause
}

// perUserGatewayDownNotice is the systemMessage a fail-open per-user Claude
// Code or Codex hook prints when the gateway of this account is down. Those
// agents do not show stderr after exit 0, so an agent in outage-open mode ran
// unguarded with no message (GAP-0377). The Unix hooks print the same notice
// (defenseclaw_unreachable_notice_json) on the same events. A missing answer
// never fails open outside Secure Client (noAnswerFailMode), so only the
// outage reasons have a notice.
func perUserGatewayDownNotice(opts Options, sp spec, reason string) string {
	if opts.ManagedEnterprise || opts.ManagedUnixSocket != "" {
		return ""
	}
	var events []string
	switch sp.connector {
	case "claudecode":
		events = []string{"SessionStart", "UserPromptSubmit", "PreToolUse"}
	case "codex":
		events = []string{"SessionStart", "PreToolUse"}
	default:
		return ""
	}
	if !slices.ContainsFunc(events, func(event string) bool { return strings.EqualFold(event, strings.TrimSpace(opts.Event)) }) {
		return ""
	}
	text := perUserOutageOpenText(opts, reason)
	if text == "" {
		return ""
	}
	return `{"systemMessage":` + mustJSONString(text) + `}`
}

// perUserOutageDoctorHint ends every per-user outage warning: the command
// that finds and repairs what keeps the gateway down.
const perUserOutageDoctorHint = " If it does not start, run `defenseclaw doctor`."

// perUserOutageOpenText is the one warning a per-user hook gives when it lets
// a call through because this account's gateway is down (OutageFailMode
// open): the cause and the fix. "" for a reason that is no outage.
func perUserOutageOpenText(opts Options, reason string) string {
	cause := ""
	switch {
	case reason == "gateway unreachable":
		cause = "this account's gateway is not running"
	case reason == perUserGatewayRestartingReason:
		cause = "this account's gateway is restarting or not running (no answer within 3 seconds)"
	case strings.HasPrefix(reason, coldStartFailedReason) && fileExists(filepath.Join(opts.Home, gatewayStoppedMarker)):
		cause = "this account's gateway was stopped with `defenseclaw-gateway stop`"
	case strings.HasPrefix(reason, coldStartFailedReason):
		// The logged reason carries the cause of the failed start (GAP-0480).
		cause = "this account's gateway is not running and could not be started"
	default:
		return ""
	}
	return "DefenseClaw is not checking this session: " + cause + ", so calls run unchecked (fail mode open " +
		"for an outage). Run `defenseclaw-gateway start` to resume protection." + perUserGatewayStatusHint +
		perUserOutageDoctorHint
}

// perUserGatewayStatusHint ends a per-user gateway-down notice: the command
// that shows the gateway's state (GAP-0093), as the Unix hooks say it.
const perUserGatewayStatusHint = " `defenseclaw-gateway status` shows its state."

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
	if opts.ManagedEnterprise || opts.ManagedUnixSocket != "" {
		return reason
	}
	switch reason {
	case "gateway unreachable":
		return "check `defenseclaw-gateway status`, or run `defenseclaw-gateway restart`"
	case perUserGatewayRestartingReason:
		return "this account's gateway is restarting or not running (no answer within 3 seconds); " +
			"try again in a moment, or check `defenseclaw-gateway status`"
	case perUserGatewayNoAnswerReason:
		return "this account's gateway did not answer in time (it may be restarting or busy); " +
			"try again in a moment, or check `defenseclaw-gateway status`"
	}
	return reason
}

// perUserGatewayDownText is what a per-user hook that fails closed because
// this account's gateway is not running shows in the agent: the agents that
// display the structured denial (Codex, OpenCode, Cursor and the JSON-bodied
// hooks) never show stderr, so they showed only "DefenseClaw hook failed
// closed" with no cause or next step (GAP-1337). Managed hooks keep their own
// text (managedStandaloneFailClosedText).
func perUserGatewayDownText(opts Options, reason string) string {
	if opts.gatewayRefusal != "" {
		// The gateway answered with an error of its own (perUserRefusalText).
		return opts.gatewayRefusal
	}
	if strings.HasPrefix(reason, foreignListenerReasonPrefix) && !opts.ManagedEnterprise {
		return "DefenseClaw blocked this " + hookEventSubject(opts.Event) + ": " + reason + "."
	}
	if opts.ManagedEnterprise || opts.ManagedUnixSocket != "" {
		return ""
	}
	if perUserInstallWindow(opts) {
		return "DefenseClaw blocked this " + hookEventSubject(opts.Event) + ": DefenseClaw is being installed or " +
			"upgraded for this account, and its gateway starts again when that is done. Try again in a moment; " +
			"if the installer has stopped, run the installer again to finish or undo the interrupted install."
	}
	if reason == perUserGatewayRestartingReason {
		return "DefenseClaw blocked this " + hookEventSubject(opts.Event) + ": this account's DefenseClaw gateway is " +
			"restarting or not running and did not answer within 3 seconds (fail mode closed). Try again in a " +
			"moment; if this continues, check it with `defenseclaw-gateway status` and start it with " +
			"`defenseclaw-gateway start`."
	}
	if reason == perUserGatewayNoAnswerReason {
		return "DefenseClaw blocked this " + hookEventSubject(opts.Event) + ": this account's DefenseClaw gateway " +
			"did not answer in time (fail mode closed); it may be restarting or busy. Try again in a moment; if " +
			"this continues, check it with `defenseclaw-gateway status`."
	}
	lead := "DefenseClaw blocked this " + hookEventSubject(opts.Event) + ": "
	switch {
	case reason == "gateway unreachable":
		return lead + "the DefenseClaw gateway is not running or not answering (fail mode closed). " +
			"Check it with `defenseclaw-gateway status`, start it with `defenseclaw-gateway start`, then try again."
	case strings.HasPrefix(reason, coldStartFailedReason) && fileExists(filepath.Join(opts.Home, gatewayStoppedMarker)):
		// The hook does not start a gateway the user stopped (GAP-0486:
		// the agent showed only the cold-start error).
		return lead + "the DefenseClaw gateway was stopped with `defenseclaw-gateway stop` (fail mode closed). " +
			"Start it with `defenseclaw-gateway start`, then try again." + perUserGatewayStatusHint
	case strings.HasPrefix(reason, coldStartFailedReason):
		return lead + "the DefenseClaw gateway is not running and could not be started (fail mode closed). " +
			"Run `defenseclaw-gateway start` to see why, then try again."
	}
	return ""
}

// gatewayStoppedMarker is the file `defenseclaw-gateway stop` leaves in the
// data directory; while it exists hooks do not start the gateway
// (internal/cli gatewayStoppedMarkerName).
const gatewayStoppedMarker = "gateway.stopped"

// emitPerUserGatewayDown renders perUserGatewayDownText in each connector's
// fail-closed shape; connectors without a structured body keep theirs.
func emitPerUserGatewayDown(opts Options, sp spec, text string) int {
	if sp.connector == "claudecode" && !opts.SecureClient {
		return emitPerUserClaudeGatewayDown(opts, text)
	}
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

// managedRootDeniedReason is the Unix standalone gateway refusal of uid 0
// under enrollment.root: deny (internal/gateway managedHookReasonRootDenied).
const managedRootDeniedReason = "enterprise_managed_root_denied"

// rootDeniedExplanation is why root's call is blocked while the
// administrator's policy refuses root.
const rootDeniedExplanation = "your organization does not allow agents to run as root on this computer. " +
	"Run the agent from your own account (" + managedRootDeniedReason + ")"

// managedUIDUnregisteredReason is the Unix standalone gateway refusal of an
// account that is not enrolled (internal/gateway managedHookReasonUIDUnregistered).
const managedUIDUnregisteredReason = "enterprise_managed_uid_unregistered"

// unixUnenrolledAccountExplanation is why the call of an account the Linux or
// macOS enumerator has not enrolled is blocked.
const unixUnenrolledAccountExplanation = "this account is not enrolled in DefenseClaw on this computer yet. " +
	"DefenseClaw enrolls a new account within about five minutes of its first sign-in, so try again then; " +
	"if this continues, the policy may exclude this account, so ask your administrator"

// unenrolledAccountExplanation is why an unenrolled Windows account's call is
// blocked. It leads with the next step and the wait, because Claude Code
// shows only the first line's first 80-odd characters (GAP-0385): a new
// account waited 4-7 minutes behind "this account is not enrolled in
// DefenseClaw on t...". Enrollment follows the desktop sign-in and, for
// Claude Code, its first start, which records the build the enumerator
// verifies; the next cycle (within five minutes) then enrolls the account.
const unenrolledAccountExplanation = "this account is not enrolled yet; restart the agent in 5 minutes. " +
	"DefenseClaw enrolls an account within 5 minutes once you have signed in and the agent is installed " +
	"(console or Remote Desktop; not SSH, a scheduled task or runas). " +
	"For Claude Code, the wait starts at its first start if that is later. " +
	"If this continues, the policy may exclude this account: ask your administrator"

// failEnrollmentRefusal blocks, like failUnreachable in closed mode, a tool
// call of an account the administrator has not enrolled (yet) or excludes, or
// of root under enrollment.root: deny, and says so: the gateway is up, and
// the refusal is the enrollment policy. An agent
// that shows its structured denial rather than stderr (Codex, Cursor and
// the JSON-bodied hooks) gets the same explanation instead of the generic
// failed-closed text.
func failEnrollmentRefusal(opts Options, sp spec, reason string) int {
	if !sp.failOpenOnly && failClosedStopEvent(opts, sp) {
		// Nothing is refused, so no refusal is reported.
		return allowFailClosedStop(opts, sp, reason, "transport")
	}
	reportUnenrolledRefusal(opts, sp, reason)
	logHookFailure(opts, sp, reason, "transport", "closed", true)
	if code, handled := copilotFailClosed(opts, sp, "transport", reason); handled {
		return code
	}
	why := unenrolledAccountExplanation
	switch reason {
	case managedUIDUnregisteredReason:
		why = unixUnenrolledAccountExplanation
	case managedRootDeniedReason:
		why = rootDeniedExplanation
	}
	explanation := "DefenseClaw: " + why
	if managedStandaloneHook(opts) && (reason == managedUIDUnregisteredReason || reason == managedRootDeniedReason) {
		explanation = "DefenseClaw blocked this " + hookEventSubject(opts.Event) + ": " + why + "."
	}
	// Claude Code shows a structured block without its hook-command prefix
	// (GAP-0554, GAP-0636).
	if sp.connector == "claudecode" && managedStandaloneHook(opts) {
		return emitManagedClaudeBlock(opts, explanation)
	}
	// The agent shows this line as the hook error, cut short: the explanation
	// leads, and the reason code stays in the hook-failure log (GAP-0385).
	fmt.Fprintln(opts.Stderr, explanation)
	if sp.connector == "codex" {
		return emitCodexBlock(opts, explanation)
	}
	result := sp.unreachableStrict
	result.body = strings.ReplaceAll(result.body, failedClosed, explanation)
	return emitHookResult(opts, sp, result)
}

// unenrolledRefusalReportBudget bounds the refusal report of an unenrolled
// account; the refusal itself never waits for the gateway.
const unenrolledRefusalReportBudget = 500 * time.Millisecond

// sendUnenrolledRefusal delivers a refusal report to the gateway's refusal
// pipe (a no-op off Windows); tests replace it.
var sendUnenrolledRefusal = refusalpipe.Send

// reportUnenrolledRefusal reports the Windows standalone hook's refusal of
// an account the administrator excludes or has not enrolled yet, so the
// gateway writes the audit row an administrator reviews (GAP-1242). The
// gateway names the account from the pipe client token; the report carries
// only the connector, the reason and the event and tool the agent sent. It
// is best effort: the refusal text and exit code do not depend on it, and
// nothing is written on disk. The Unix standalone gateway refuses and audits
// an unenrolled caller itself (managedUIDUnregisteredReason).
func reportUnenrolledRefusal(opts Options, sp spec, reason string) {
	if reason != managedSIDUnregisteredReason && reason != managedEnrollmentPendingReason {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), unenrolledRefusalReportBudget)
	defer cancel()
	// The refusal used to return before stdin was read; an agent that keeps
	// stdin open must not hold it, so the payload read gets part of the
	// budget and the report goes without the event and tool after that.
	read := make(chan []byte, 1)
	go func() {
		payload, overflow, err := readCapped(opts.Stdin, opts.MaxBody)
		if overflow || err != nil {
			payload = nil
		}
		read <- payload
	}()
	var payload []byte
	select {
	case payload = <-read:
	case <-time.After(unenrolledRefusalReportBudget / 2):
	}
	_ = sendUnenrolledRefusal(ctx, refusalpipe.Report{
		Connector: sp.connector,
		Reason:    reason,
		Event:     resolveHookEvent(opts.Event, payload),
		Tool:      payloadToolName(payload),
	})
}

// payloadToolName is the tool a hook payload names, when it names one.
func payloadToolName(payload []byte) string {
	var fields struct {
		ToolName      string `json:"tool_name"`
		ToolNameCamel string `json:"toolName"`
	}
	if len(payload) == 0 || json.Unmarshal(payload, &fields) != nil {
		return ""
	}
	if fields.ToolName != "" {
		return fields.ToolName
	}
	return fields.ToolNameCamel
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
	failMode = closeDuringInstall(&opts, failMode)
	if sp.connector == "copilot" && perUserInstallWindow(opts) {
		if code, blocked := blockPerUserCopilotInstall(opts, sp); blocked {
			return code
		}
	}
	// The gateway answered, or a local check failed: never an outage.
	failMode = managedNonOutageMode(&opts, failMode)
	if failMode == "closed" {
		// As in failUnreachable: a closed result stays closed for Hermes.
		opts.FailMode = "closed"
	}
	if !managedStandaloneHook(opts) && !opts.ExplainUnenrolledAccount {
		// The standalone hook socket carries no token, so the token-drift
		// advice does not apply there. The Windows standalone hook runs as
		// a standard user, who can run neither command (GAP-0680); its
		// fail-closed text already says to contact the administrator.
		reason = responseFailureReason(reason)
	}
	closes := !sp.failOpenOnly && failMode != "open"
	if closes && failClosedStopEvent(opts, sp) {
		return allowFailClosedStop(opts, sp, reason, "response")
	}
	logHookFailure(opts, sp, reason, "response", failMode, closes)
	if closes && managedPlainFailClosed(opts, sp) {
		return failManagedStandaloneClosed(opts, sp, sp.responseClosed, "response", reason)
	}
	fmt.Fprintf(opts.Stderr, "defenseclaw: %s hook error: %s\n", sp.errLabel, reason)
	if code, handled := hermesFailClosed(opts, sp, "response", reason); handled {
		return code
	}
	if !managedCopilotOpen(opts, sp, failMode) {
		if code, handled := copilotFailClosed(opts, sp, "response", reason); handled {
			return code
		}
	}
	if sp.failOpenOnly || failMode == "open" {
		return emitFailOpenAllow(opts, sp, reason)
	}
	if opts.gatewayRefusal != "" {
		return emitPerUserGatewayDown(opts, sp, opts.gatewayRefusal)
	}
	return emitHookResult(opts, sp, sp.responseClosed)
}

// closeDuringInstall is the one install check of a native hook call: Run
// reads it when the call starts, after the agent's payload is in and when
// the gateway has answered (or failed to); decide reads it once the whole
// body is in, and every failure answer reads it again when it answers.
// While the installer holds the per-user data directory
// (perUserInstallInProgress), and on a managed host while its lifecycle
// runs (managedLifecycleActive), the call is closed, with strict
// availability, so an install or upgrade that starts during a call closes
// it as well (GAP-0893, GAP-0894, GAP-0916, GAP-1074, GAP-1075). It returns
// the fail mode to answer with.
func closeDuringInstall(opts *Options, failMode string) string {
	if !perUserInstallInProgress(*opts) && !managedLifecycleActive(*opts) {
		return failMode
	}
	opts.FailMode = "closed"
	opts.StrictAvailability = true
	return "closed"
}

// perUserInstallInProgress forces closed while the account's installer owns
// its data directory (installLockHeld).
func perUserInstallInProgress(opts Options) bool {
	if opts.ManagedEnterprise || opts.SecureClient || opts.Home == "" {
		return false
	}
	return installLockHeld(opts.Home)
}

// installLockLstat reads the install lock; a variable for tests.
var installLockLstat = os.Lstat

// installLockHeld reports whether the installer holds the per-user data
// directory home: its .install.lock exists, as any file type (a symlink
// marker too, so changing its type cannot open a hook during install or
// upgrade), or it cannot be read for any reason but its absence, and it is
// not stale (installLockStale: its installer is proven gone). A lock whose
// state cannot be verified is held (GAP-0862).
func installLockHeld(home string) bool {
	return installLockHeldBy(installLockLstat, home)
}

func installLockHeldBy(lstat func(string) (fs.FileInfo, error), home string) bool {
	info, err := lstat(filepath.Join(home, ".install.lock"))
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist)
	}
	return !installLockStale(lstat, home, info)
}

// InstallLockHeld is installLockHeld for the hook command, which answers
// some failures before Run (hookPreRunFailsClosed).
func InstallLockHeld(home string) bool {
	return strings.TrimSpace(home) != "" && installLockHeld(home)
}

func responseFailureReason(reason string) string {
	if strings.Contains(reason, "HTTP 401") || strings.Contains(reason, "HTTP 403") {
		return reason + " (gateway auth failed; possible token drift. Run `defenseclaw doctor --fix` or `defenseclaw-gateway restart`.)"
	}
	return reason
}

// failManagedCodexBinding keeps the shell hook's binding-error wording in
// Codex's native denial body. A mismatched registered event is an integrity
// refusal, including when the administrator allows outages to fail open.
// A registered Stop event still gets the neutral Stop rule, as in
// failResponse: blocking Stop keeps Codex running and repeats the failing
// hook (#1140).
func failManagedCodexBinding(opts Options, sp spec, reason string) int {
	reason = "codex hook binding error: " + reason
	if failClosedStopEvent(opts, sp) {
		return allowFailClosedStop(opts, sp, reason, "response")
	}
	logHookFailure(opts, sp, reason, "response", "closed", true)
	fmt.Fprintln(opts.Stderr, "defenseclaw: "+reason)
	return emitCodexBlock(opts, "DefenseClaw blocked this "+hookEventSubject(opts.Event)+": "+reason)
}

// invalidManagedCopilotBindingReason is the hook-failure reason of a managed
// Copilot hook whose command binds no reviewed Copilot event.
const invalidManagedCopilotBindingReason = "enterprise_managed_copilot_event_binding_invalid"

// failInvalidManagedCopilotBinding answers a managed standalone Copilot hook
// whose command binds no reviewed Copilot event: a registration DefenseClaw
// did not render (verify reports DefenseClaw's drop-in not intact, or an
// event it does not publish, and ensure rewrites it). It is an integrity
// failure, closed in every fail mode. Copilot's hook contract has a deny
// only for preToolUse (permissionDecision) and permissionRequest (behavior),
// and its stdin bodies do not name the event, so the hook writes both deny
// fields: whichever of the two events Copilot ran it for, its deny is there.
// Every other Copilot event (sessionStart, sessionEnd, userPromptSubmitted,
// postToolUse, errorOccurred and the rest) cannot block in Copilot's
// contract and ignores them. The answer is never an allow decision.
func failInvalidManagedCopilotBinding(opts Options, sp spec) int {
	reason := invalidManagedCopilotBindingReason
	return refuseInvalidCopilotBinding(opts, sp, "managed "+sp.subject, reason,
		"DefenseClaw blocked this Copilot call: its DefenseClaw hook is registered without a Copilot event DefenseClaw reviewed. "+
			"Ask your administrator to run ensure, which rewrites the DefenseClaw policy hook. ("+reason+")")
}

// failInvalidPerUserCopilotBinding answers a per-user Copilot CLI hook in fail
// mode closed whose command binds no reviewed Copilot event like
// failInvalidManagedCopilotBinding, with the per-user next step, as
// copilot-hook.sh does on Linux and macOS.
func failInvalidPerUserCopilotBinding(opts Options, sp spec) int {
	return refuseInvalidCopilotBinding(opts, sp, sp.subject, "missing or unsupported Copilot hook event binding",
		"DefenseClaw blocked this tool call: its DefenseClaw hook is registered without a Copilot event DefenseClaw reviewed. "+
			"Run `defenseclaw setup copilot` to register it again.")
}

// unboundAntigravityBindingReason is the hook-failure reason of an Antigravity
// hook whose registered command binds no reviewed event.
const unboundAntigravityBindingReason = "missing or unsupported Antigravity hook event binding"

// refuseClosedUnboundHook refuses a Copilot CLI or Antigravity hook that
// fails closed (a standalone managed hook, or a per-user hook in fail mode
// closed or strict availability) when its registered command binds no
// reviewed event. Neither agent names the event in its hook input, so such a
// hook would otherwise answer every failure as an event that cannot block.
// Copilot gets both of its denies (refuseInvalidCopilotBinding). Antigravity
// reads the same decision field on Stop, so it gets PreToolUse's deny for
// any input that may be a tool call; only an input that is clearly another
// event (antigravityNonToolInput) keeps the neutral answer. Secure Client
// hooks and hooks in fail mode open are not handled here.
func refuseClosedUnboundHook(opts *Options, sp spec, failMode string) (int, bool) {
	// A registration that lost its event is a broken install, never a
	// gateway outage: outside Secure Client it is refused in every fail mode.
	if opts.SecureClient {
		return 0, false
	}
	switch {
	case sp.connector == "copilot" && !validCopilotEventForOptions(*opts):
		if managedNativeDecision(*opts) {
			return failInvalidManagedCopilotBinding(*opts, sp), true
		}
		closed := *opts
		closed.FailMode = "closed"
		if perUserCopilotFailsClosed(closed, sp) {
			return failInvalidPerUserCopilotBinding(closed, sp), true
		}
	case sp.connector == "antigravity" && !validAntigravityEvent(opts.Event):
		// Read the input here, then hand the same bytes to the rest of Run.
		data, err := io.ReadAll(io.LimitReader(opts.Stdin, opts.MaxBody+1))
		opts.Stdin = io.MultiReader(bytes.NewReader(data), opts.Stdin)
		if err == nil && antigravityNonToolInput(data, int64(len(data)) > opts.MaxBody) {
			return 0, false
		}
		text := "DefenseClaw blocked this tool call: its DefenseClaw hook is registered without an Antigravity event DefenseClaw reviewed. " +
			"Run `defenseclaw setup antigravity` to register it again."
		if opts.ManagedEnterprise {
			text = "DefenseClaw blocked this tool call: its DefenseClaw hook is registered without an Antigravity event DefenseClaw reviewed. " +
				"Ask your administrator to run ensure, which rewrites the DefenseClaw hooks."
		}
		opts.FailMode = "closed"
		logHookFailure(*opts, sp, unboundAntigravityBindingReason, "response", "closed", true)
		fmt.Fprintf(opts.Stderr, "defenseclaw: blocking %s (fail mode closed): %s (event %q)\n",
			sp.subject, unboundAntigravityBindingReason, strings.TrimSpace(opts.Event))
		fmt.Fprintln(opts.Stdout, `{"decision":"deny","reason":`+mustJSONString(text)+`}`)
		return 0, true
	}
	return 0, false
}

// antigravityNonToolInput reports an Antigravity hook input that is clearly
// not a tool call: a JSON object with a field of PreInvocation,
// PostInvocation or Stop and no tool field (toolCall, tool_call, stepIdx).
// Anything else (a missing or malformed toolCall, input that is not JSON or
// over the cap) may be a tool call. Antigravity's other events carry
// counters and short text only.
func antigravityNonToolInput(data []byte, overflow bool) bool {
	if overflow {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return false
	}
	for _, key := range []string{"toolCall", "tool_call", "stepIdx"} {
		if _, ok := fields[key]; ok {
			return false
		}
	}
	for _, key := range []string{"invocationNum", "initialNumSteps", "executionNum", "terminationReason", "fullyIdle"} {
		if _, ok := fields[key]; ok {
			return true
		}
	}
	return false
}

// refuseInvalidCopilotBinding writes both of Copilot's denies with text and
// logs the refusal closed: loggedFailMode counts a Copilot event it does not
// know as one that cannot block.
func refuseInvalidCopilotBinding(opts Options, sp spec, subject, reason, text string) int {
	opts.FailMode = "closed"
	logged := sp
	logged.failOpenOnly = false
	logHookFailure(opts, logged, reason, "response", "closed", true)
	message := mustJSONString(text)
	fmt.Fprintf(opts.Stderr, "defenseclaw: blocking %s (fail mode closed): %s (event %q)\n", subject, reason, strings.TrimSpace(opts.Event))
	fmt.Fprintln(opts.Stdout, `{"permissionDecision":"deny","permissionDecisionReason":`+message+`,"behavior":"deny","message":`+message+`}`)
	return 0
}

// copilotFailClosed denies a Copilot tool call when DefenseClaw itself cannot
// decide. Copilot has no fail-closed hook contract (its own timeouts and
// non-JSON errors allow), but it honors its native structured deny for
// preToolUse and permissionRequest, so a managed hook and a per-user hook in
// fail mode closed (perUserCopilotFailClosed) use it. layer is the failure
// layer (transport, response, oversized, policy) the per-user text names.
// Other events cannot block and keep the fail-open result.
//
// The same transport failure paths give a Hermes tool call that fails closed
// its block (hermesFailClosed): Hermes too has no fail-closed hook contract
// and blocks only through its native directive.
func copilotFailClosed(opts Options, sp spec, layer, reason string) (int, bool) {
	if sp.connector == "hermes" {
		return hermesFailClosed(opts, sp, "transport", reason)
	}
	if sp.connector != "copilot" {
		return 0, false
	}
	if !opts.ManagedEnterprise {
		return perUserCopilotFailClosed(opts, sp, layer, reason)
	}
	text := managedCopilotDenyMessage(reason)
	if reason == managedUIDUnregisteredReason {
		text = "DefenseClaw: " + unixUnenrolledAccountExplanation
	}
	if reason == managedGatewayNotRunningReason || reason == managedGatewayPortHeldReason ||
		reason == managedGatewayRestartingReason {
		// Say the service is stopped and who starts it, that it is
		// restarting, or that another program holds its port
		// (managedPeerFailureReason, the foreign-hook guard).
		text = managedStandaloneFailClosedText(opts.Event, "transport", reason)
	}
	message := mustJSONString(text)
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
		if body = copilotVSCodeLocalOutput(opts.Event, "block", text); body == "" {
			return 0, false
		}
	}
	fmt.Fprintf(opts.Stderr, "defenseclaw: blocking managed %s (fail mode closed): %s\n", sp.subject, reason)
	fmt.Fprintln(opts.Stdout, body)
	return 0, true
}

// perUserCopilotFailsClosed reports a per-user Copilot CLI hook that fails
// closed: its fail mode is not explicitly open, or strict availability is on.
// The VS Code Local surface has a fail-closed contract of its own.
func perUserCopilotFailsClosed(opts Options, sp spec) bool {
	return sp.connector == "copilot" && !opts.ManagedEnterprise && sp.dialect != copilotVSCodeLocalSurface &&
		(opts.StrictAvailability || normalizeFailMode(opts.FailMode) == "closed")
}

// perUserCopilotFailClosed denies a per-user Copilot CLI tool call or
// permission request that DefenseClaw could not check, in fail mode closed,
// with Copilot's native deny and a text that says why and what to do
// (perUserFailClosedText), as copilot-hook.sh does on Linux and macOS.
// handled is false for every other invocation.
func perUserCopilotFailClosed(opts Options, sp spec, layer, reason string) (int, bool) {
	if !perUserCopilotFailsClosed(opts, sp) {
		return 0, false
	}
	message := mustJSONString(perUserFailClosedText(opts, layer, reason))
	var body string
	switch opts.Event {
	case "preToolUse":
		body = `{"permissionDecision":"deny","permissionDecisionReason":` + message + `}`
	case "permissionRequest":
		body = `{"behavior":"deny","message":` + message + `}`
	default:
		return 0, false
	}
	fmt.Fprintf(opts.Stderr, "defenseclaw: blocking %s (fail mode closed): %s\n", sp.subject, reason)
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
// stop or session-end event (NeutralLifecycleEvent) gets the connector's
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
	if NeutralLifecycleEvent(sp.connector, opts.Event) {
		logDeliberateAllow(opts, sp, reason, "policy")
		fmt.Fprintf(opts.Stderr, "defenseclaw: not blocking the %s %s event (a block would keep the agent running); tool calls stay blocked: %s\n", sp.errLabel, strings.TrimSpace(opts.Event), reason)
		return emitHookResult(opts, sp, sp.openAllow)
	}
	if foreignHookCursorOpenEvent(sp.connector, opts.Event) {
		// Cursor has no block response for these events, and the generic
		// exit-2 block on the first start in a folder left cursor-agent on
		// "Trusting workspace..." with no message (GAP-1257). The session
		// block is already recorded, so the first prompt or tool call gets
		// the block and its reason.
		logDeliberateAllow(opts, sp, reason, "policy")
		fmt.Fprintf(opts.Stderr, "defenseclaw: not blocking the %s %s event (Cursor cannot show a block there); prompts and tool calls in this session stay blocked: %s\n", sp.errLabel, strings.TrimSpace(opts.Event), reason)
		return emitHookResult(opts, sp, sp.openAllow)
	}
	logHookFailure(opts, sp, reason, "policy", "closed", true)
	if code, handled := copilotFailClosed(opts, sp, "policy", reason); handled {
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

// failClosedStopEvent reports a stop or session-end event
// (NeutralLifecycleEvent) of a hook that is about to fail closed. Failing
// such an event closed denies nothing; it keeps the agent running (Codex,
// Claude Code, Devin and Copilot continue the turn when a stop hook blocks,
// Cursor submits the block as the next prompt), and every later turn fails
// closed and stops again, so the agent loops on model turns until
// DefenseClaw is back (#1140). Every fail-closed reason (gateway unreachable
// or unverified, missing token, hook socket or home, invalid runtime,
// unenrolled account, oversized payload, unusable response) therefore gives
// these events the connector's neutral allow, as the foreign-hook guard
// does, on the per-user hooks and on the Unix and Windows standalone
// managed hooks. Tool, prompt and session-start events still fail closed.
// The Secure Client profile keeps its results. The shell hooks apply the
// same rule (defenseclaw_failed_stop_event in _hardening.sh).
func failClosedStopEvent(opts Options, sp spec) bool {
	if opts.SecureClient || secureClientHook(opts) {
		return false
	}
	return NeutralLifecycleEvent(sp.connector, opts.Event)
}

// logDeliberateAllow records a failure that a reviewed rule answers with the
// connector's neutral allow (a stop/session-end event, or a Cursor event with
// no block response). The generic "inspection bypassed" warning is left out:
// the caller prints its own explanation, which is the first line the agent
// shows. Managed OpenCode background events have a diagnostic outcome.
func logDeliberateAllow(opts Options, sp spec, reason, category string) {
	quiet := opts
	quiet.Stderr = io.Discard
	logHookFailure(quiet, sp, reason, category, "open", false)
}

// allowFailClosedStop answers a stop event that would have failed closed
// with the connector's neutral allow; the failure is still logged, with the
// fail mode it got.
func allowFailClosedStop(opts Options, sp spec, reason, category string) int {
	logDeliberateAllow(opts, sp, reason, category)
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

// managedPeerFailMode is the fail mode of a managed peer-verification
// failure. A hook whose gateway service is proven not running follows its
// own fail mode. A refused connection to an existing socket remains an
// unverified peer failure. That is an authenticated Secure Client
// hook (opts.SecureClient, set only on a host the strict Secure Client
// classifier verified, and secureClientHook, #1163) or a standalone hook,
// whose fail mode is the administrator's (owner decision 2026-10-20). Every
// other peer failure (another process on the gateway port, a service the
// hook cannot query) fails closed.
func managedPeerFailMode(opts Options, failMode string, err error) string {
	if errors.Is(err, errManagedGatewayNotRunning) && ((opts.SecureClient && secureClientHook(opts)) || managedNativeDecision(opts)) {
		return failMode
	}
	return "closed"
}

// ManagedOutageFailsOpen reports whether err, from a gateway contact a
// managed hook makes before its hook request (the foreign-hook guard's
// session exchange), is an outage that the hook's open fail mode lets
// through (GAP-0346). It holds only for a standalone hook outside Secure
// Client (managedNativeDecision) whose administrator chose open for the
// connector (opts.FailMode, which the managed runtime sets), without strict
// availability or a runtime failure, and only when err proves the gateway
// service is not running. Every other error (a peer
// DefenseClaw cannot verify, another program on the gateway port, an
// unusable answer), any failure after an HTTP error reply
// (Options.answeredErrorStatus) and every
// closed or unset mode keep the refusal.
// A lifecycle transition (managedLifecycleActive) keeps it too: an install,
// upgrade, repair or lifecycle restart is not an outage (GAP-0993, GAP-1074,
// GAP-1075).
func ManagedOutageFailsOpen(opts Options, err error) bool {
	if err == nil || !managedNativeDecision(opts) || opts.StrictAvailability || opts.answeredErrorStatus != 0 ||
		strings.TrimSpace(opts.ManagedRuntimeFailure) != "" || normalizeFailMode(opts.FailMode) != "open" {
		return false
	}
	if errors.Is(err, errManagedGatewayPortHeld) || errors.Is(err, errAnswerBudgetSpentLocally) {
		return false
	}
	// Only a proven stopped service is an outage; a restart or a missing
	// answer keeps the refusal.
	if !errors.Is(err, errManagedGatewayNotRunning) {
		return false
	}
	return !managedLifecycleActive(opts)
}

// managedCopilotOpen reports a managed GitHub Copilot hook whose delivery
// mode is open: an authenticated Secure Client hook (#1163), or a standalone
// hook whose administrator chose open. A proven stopped service may allow
// the call under open; an unanswered or unverified gateway stays closed.
// A closed mode (configured, strict availability, or another program on the
// gateway port) and the enrollment and policy refusals still deny.
func managedCopilotOpen(opts Options, sp spec, failMode string) bool {
	return sp.connector == "copilot" && ((opts.SecureClient && secureClientHook(opts)) || managedNativeDecision(opts)) &&
		!opts.StrictAvailability && normalizeFailMode(failMode) == "open"
}

// managedPeerFailureReason is the hook-failure reason of a managed
// peer-verification failure: every managed hook says when the gateway
// service is proven not running (a stopped Windows service, or a Unix
// standalone socket missing in a trusted directory); any other
// Secure Client peer failure keeps managedGatewayPeerUnverifiedReason.
func managedPeerFailureReason(opts Options, err error) string {
	if errors.Is(err, errManagedGatewayNotRunning) {
		return managedGatewayNotRunningReason
	}
	if managedStandaloneHook(opts) && errors.Is(err, errManagedHookSocketSELinuxDenied) {
		return managedHookSocketSELinuxDeniedReason
	}
	if opts.ExplainUnenrolledAccount && errors.Is(err, errManagedGatewayPortHeld) {
		return managedGatewayPortHeldReason
	}
	return managedGatewayPeerUnverifiedReason
}

// ManagedGatewayNotRunningReason is the reason code of a managed hook whose
// gateway service is not running.
const ManagedGatewayNotRunningReason = managedGatewayNotRunningReason

// ErrManagedGatewayNotRunning is wrapped by every managed hook transport
// error that means the gateway service is not running.
var ErrManagedGatewayNotRunning = errManagedGatewayNotRunning

// ManagedGatewayNotRunning reports an error from a managed hook transport
// (ExchangeForeignHookSession included) that means the gateway service is
// not running: a stopped Windows service, or a missing or refusing Unix hook
// socket.
func ManagedGatewayNotRunning(err error) bool {
	return errors.Is(err, errManagedGatewayNotRunning)
}

// ManagedGatewayPortHeldReason is the reason code of a Windows standalone
// managed hook that found another process on the gateway API port.
const ManagedGatewayPortHeldReason = managedGatewayPortHeldReason

// ManagedGatewayPortHeld reports a managed hook transport error that means
// another process holds the gateway API port while the service runs.
func ManagedGatewayPortHeld(err error) bool {
	return errors.Is(err, errManagedGatewayPortHeld)
}

// ManagedTransportFailureText is the plain text of a standalone hook that
// failed closed because its gateway is stopped or its port is held, for a
// caller that shows the guard's reason as is (the OpenCode plugin); ok is
// false for any other reason.
func ManagedTransportFailureText(event, reason string) (string, bool) {
	if reason != managedGatewayNotRunningReason && reason != managedGatewayPortHeldReason &&
		reason != managedGatewayRestartingReason && reason != managedGatewayNoAnswerReason {
		return "", false
	}
	return managedStandaloneFailClosedText(event, "transport", reason), true
}

// failManagedStandaloneClosed delivers a Unix standalone managed hook's
// fail-closed result with the plain text of managedStandaloneFailClosedText:
// on stderr (the block message Claude Code shows) and as the reason in the
// connector's native block body where it has one. The exit codes are the
// connector's usual fail-closed ones.
func failManagedStandaloneClosed(opts Options, sp spec, result failResult, layer, reason string) int {
	text := managedStandaloneFailClosedText(opts.Event, layer, reason)
	if sp.connector == "claudecode" {
		return emitManagedClaudeBlock(opts, text)
	}
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

// emitPerUserClaudeGatewayDown delivers perUserGatewayDownText to Claude
// Code. Claude Code shows a failed hook's stderr after the hook's whole
// command line, and on Windows that line is the cmd.exe launcher guard with
// its own "launcher is missing" sentence, so the user read reinstall advice
// for a launcher that exists (rel-1-0-2 GAP-0486). A prompt or tool call
// gets the structured block of a policy verdict, and a session start (which
// cannot be blocked) a systemMessage, so only the text shows. A session end
// or subagent start cannot be blocked either and has nothing to show: it
// exits 0 with no output (as Codex's do, emitCodexBlock), so Claude Code
// does not print that hook's command line after the prompt's block
// (rel-1-0-3 GAP-0203). The failure is in hook-failures.jsonl.
func emitPerUserClaudeGatewayDown(opts Options, text string) int {
	switch strings.TrimSpace(opts.Event) {
	case "SessionStart":
		fmt.Fprintln(opts.Stdout, `{"systemMessage":`+mustJSONString(text)+`}`)
		return 0
	case "SessionEnd", "SubagentStart":
		return 0
	}
	return emitManagedClaudeBlock(opts, text)
}

// emitManagedClaudeBlock uses the same structured block shapes as a gateway
// policy verdict, so Claude Code shows the reason without a hook-command
// prefix (managed hooks, and per-user hooks whose gateway is down).
func emitManagedClaudeBlock(opts Options, reason string) int {
	encoded := mustJSONString(reason)
	switch opts.Event {
	case "UserPromptSubmit", "UserPromptExpansion":
		fmt.Fprintf(opts.Stdout, "{\"decision\":\"block\",\"reason\":%s}\n", encoded)
	case "PreToolUse":
		fmt.Fprintf(opts.Stdout, "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":%s}}\n", encoded)
	default:
		fmt.Fprintln(opts.Stderr, reason)
		return blockExit
	}
	return 0
}

// managedRuntimeHomeMissingReason is the refusal of a managed hook whose
// account has no DefenseClaw folder (troubleshooting.mdx).
const managedRuntimeHomeMissingReason = "enterprise_managed_runtime_home_missing"

// managedStandaloneFailClosedText is what a standalone managed hook (Unix or
// Windows, managedPlainFailClosed) says when it fails closed: that DefenseClaw blocked the prompt or tool
// call, why in plain words and what to do, e.g. "DefenseClaw blocked this
// prompt: the DefenseClaw gateway is not available. Try again in a moment;
// if this continues, contact your administrator." The internal reason goes
// to the hook-failure log only (GAP-0554).
func managedStandaloneFailClosedText(event, layer, reason string) string {
	var cause, advice, code string
	switch {
	case layer == "oversized":
		cause, advice = "it is too large for DefenseClaw to inspect", "Make it smaller and try again."
	case layer == "input":
		cause, advice = "its hook input names two different events, so DefenseClaw cannot tell what to check",
			"Try again; if this continues, contact your administrator."
	case layer == "response":
		cause, advice = "the DefenseClaw gateway returned an answer DefenseClaw could not use",
			"Try again; if this continues, contact your administrator."
	case reason == managedGatewayNotRunningReason:
		cause, advice = "the DefenseClaw gateway service is not running on this computer",
			// The service is also stopped while a lifecycle transaction is
			// pending, which starting it does not fix (GAP-0509).
			"Try again in a moment; if this continues, ask your administrator to check DefenseClaw on this computer: `"+
				managedStatusCommand(runtime.GOOS)+"` names what to do."
		// The documented refusal code goes last, as in the shell hooks'
		// text, so an administrator can look it up (GAP-1179).
		code = reason
	case reason == managedGatewayRestartingReason:
		cause, advice = "the DefenseClaw gateway is restarting to apply a change on this computer",
			"Try again in a few seconds; if this continues, contact your administrator."
		code = reason
	case reason == managedGatewayNoAnswerReason:
		// A restart, an upgrade, a repair or a busy host: the gateway gave
		// no decision within the tool call's answer budget (GAP-0155).
		cause, advice = "the DefenseClaw gateway did not answer in time (it may be restarting or busy)",
			"Try again in a few seconds; if this continues, contact your administrator."
		code = reason
	case reason == managedGatewayPortHeldReason:
		cause, advice = "another program is using the DefenseClaw gateway's port on this computer, so DefenseClaw cannot check it",
			"Ask your administrator to check DefenseClaw on this computer: `"+managedStatusCommand(runtime.GOOS)+"` names the program."
		code = reason
	case reason == ManagedUserNamespaceReason:
		// The setup is fine; the agent's process is the problem (GAP-0923).
		cause, advice = "this agent runs in a private user namespace (for example one started with unshare or a sandbox tool), where DefenseClaw cannot check it or reach its hook socket",
			"Start the agent from your normal login session; if this continues, contact your administrator."
	case reason == ManagedTracedProcessReason:
		cause, advice = "this agent's hook is being traced, so another process may change the policy paths it reads",
			"Start the agent without a tracer; if this continues, contact your administrator."
	case reason == ManagedProcessContextUnknownReason:
		cause, advice = "DefenseClaw cannot verify this agent's Linux process context and managed policy view",
			"Start the agent from your normal login session; if this continues, contact your administrator."
	case reason == managedHookSocketSELinuxDeniedReason:
		cause, advice = "SELinux does not let your account reach the DefenseClaw gateway on this computer",
			"Ask your administrator to run `enterprise linux repair`, which loads the DefenseClaw SELinux module that SELinux-confined accounts need."
	case reason == managedRuntimeHomeMissingReason:
		// It said only "not set up correctly" (GAP-0759); the guardian
		// normally puts the folder back on its own.
		cause, advice = "your DefenseClaw folder (.defenseclaw in your user profile) is missing",
			"DefenseClaw normally puts it back on its own; try again in a minute. If this continues, contact your administrator."
		code = reason
	case strings.HasPrefix(reason, "enterprise_managed_runtime") ||
		reason == "enterprise_managed_hook_socket_missing" ||
		reason == "enterprise_machine_policy_summary_untrusted":
		cause, advice = "DefenseClaw is not set up correctly on this computer", "Contact your administrator."
	default:
		cause, advice = "the DefenseClaw gateway is not available",
			"Try again in a moment; if this continues, contact your administrator."
	}
	text := "DefenseClaw blocked this " + hookEventSubject(event) + ": " + cause + ". " + advice
	if code != "" {
		text += " (" + code + ")"
	}
	return text
}

// managedStatusCommand is the lifecycle status command of the platform the
// hook runs on, which the block text of a stopped gateway names: a Linux
// developer was told to run `enterprise windows status` (GAP-1179).
func managedStatusCommand(goos string) string {
	switch goos {
	case "windows":
		return "enterprise windows status"
	case "darwin":
		return "enterprise macos status"
	}
	return "enterprise linux status"
}

// hookEventSubject names what an agent hook event carries, in the words a
// user knows: a prompt, a tool call or a tool result.
func hookEventSubject(event string) string {
	event = strings.TrimSpace(event)
	switch strings.ToLower(event) {
	case "userpromptsubmit", "beforesubmitprompt", "userpromptsubmitted", "userprompttransformed":
		return "prompt"
	case "pretooluse", "permissionrequest", "beforeshellexecution", "beforemcpexecution",
		"beforereadfile", "beforetabfileread", "tool.execute.before", "pre_tool_call":
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
// standalone invocation (Unix, or the Windows standalone binary,
// managedPlainFailClosed) that fails before its payload is read. The Claude
// Code, Cursor and Devin commands do not bind their event, so it comes from
// the payload, as in failForeignHookBlocked; the Codex, Copilot and
// Antigravity commands bind it out of band. Without it a Windows Cursor hook
// whose gateway service was stopped answered {} (Cursor's response for an
// event it cannot name), and Cursor ran the tool call (GAP-1032). Other
// invocations, Secure Client included, are left untouched, so their stdin is
// never read here.
func resolveManagedStandaloneFailureEvent(opts *Options, sp spec) {
	if opts == nil || !opts.ManagedEnterprise || strings.TrimSpace(opts.Event) != "" ||
		(!opts.ManagedStandalone && !opts.ExplainUnenrolledAccount) {
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
	event, _ := pickHookEvent(envelope.HookEventName, envelope.Event)
	return event
}

// pickHookEvent names the event of an invocation whose command binds none
// from the payload's two top-level fields: either one alone, or both when
// they agree. Two fields that name different events name no event, and
// conflict is true.
func pickHookEvent(hookEventName, event string) (resolved string, conflict bool) {
	hookEventName, event = strings.TrimSpace(hookEventName), strings.TrimSpace(event)
	if hookEventName != "" && event != "" && !strings.EqualFold(hookEventName, event) {
		return "", true
	}
	if hookEventName != "" {
		return hookEventName, false
	}
	return event, false
}

// hookEventFieldsConflict reports a payload whose top-level hook_event_name
// and event fields name different events (pickHookEvent).
func hookEventFieldsConflict(payload []byte) bool {
	var envelope struct {
		HookEventName string `json:"hook_event_name"`
		Event         string `json:"event"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return false
	}
	_, conflict := pickHookEvent(envelope.HookEventName, envelope.Event)
	return conflict
}

func validateCodexInvocationBinding(
	explicitEvent string,
	contractID string,
	payload []byte,
) (string, error) {
	event := strings.TrimSpace(explicitEvent)
	if event == "" {
		return "", errors.New("Codex hook command is missing its installer-bound event") //nolint:staticcheck // Match the shipped hook diagnostic.
	}
	contractID = strings.TrimSpace(contractID)
	if contractID == "" {
		return "", errors.New("Codex hook command is missing its installer-bound contract") //nolint:staticcheck // Match the shipped hook diagnostic.
	}
	var envelope struct {
		HookEventName string `json:"hook_event_name"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return "", errors.New("Codex hook stdin is not valid JSON") //nolint:staticcheck // Match the shipped hook diagnostic.
	}
	stdinEvent := strings.TrimSpace(envelope.HookEventName)
	if stdinEvent == "" {
		return "", errors.New("Codex hook stdin is missing hook_event_name") //nolint:staticcheck // Match the shipped hook diagnostic.
	}
	if stdinEvent != event {
		return "", fmt.Errorf( //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
			"Codex hook stdin event %q does not match installer-bound event %q",
			stdinEvent,
			event,
		)
	}
	if !codexContractAllowsEvent(contractID, event) {
		return "", fmt.Errorf( //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
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
			DialContext: (&net.Dialer{Timeout: hookDialTimeout}).DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// normalizeFailMode resolves a hook's fail mode as the config resolver does
// (config.GuardrailConfig.EffectiveHookFailMode): only an explicit "open"
// opens; empty (a hook command without --fail-mode whose sidecar is missing
// or names no mode) and any other value fail closed.
func normalizeFailMode(m string) string {
	if strings.EqualFold(strings.TrimSpace(m), "open") {
		return "open"
	}
	return "closed"
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

// removedConnectorReason is the block reason of a hook for a connector 1.0.4
// removed (until 1.1), or false.
func removedConnectorReason(connector string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(connector)) {
	case "openhands":
		return "DefenseClaw blocked this call: OpenHands support was removed in DefenseClaw 1.0.4. " +
			"To use OpenHands without DefenseClaw, remove every DefenseClaw hook from your OpenHands hooks.json, then restart OpenHands.", true
	case "omnigent":
		return "DefenseClaw blocked this call: OmniGent support was removed in DefenseClaw 1.0.4. " +
			"To use OmniGent without DefenseClaw, remove DefenseClaw's policy from your OmniGent config.yaml, then restart OmniGent.", true
	}
	return "", false
}

// decodeDecision pulls the `decision` string from an already-compact JSON
// object (the connector's hook_output) for the Devin deny/block path.
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
	if !result.closed && result.exit == 0 {
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
