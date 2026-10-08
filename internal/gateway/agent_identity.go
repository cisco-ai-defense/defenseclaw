// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	osuser "os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// agentIdentityFromContext returns the agent identity
// (defenseclaw.agent.identity.id) the hook path resolved for this request.
// verified is true only when every component of the ID came from a verified
// source: the platform machine id, a kernel- or credential-verified user (or
// the user a per-user gateway runs as), the route's connector, and the config
// root the gateway resolved for that user. Headers and payload fields never
// contribute. The ID is "" before the hook path runs, on non-hook traffic and
// under the Secure Client integration.
func agentIdentityFromContext(ctx context.Context) (id string, verified bool) {
	identity := AgentIdentityFromContext(ctx)
	if identity.IdentityID == "" {
		return "", false
	}
	return identity.IdentityID, identity.IdentityVerified
}

// agentIdentityFacts is everything the hook path knows about one agent
// identity: the ID, its components, and the claimed install hint.
type agentIdentityFacts struct {
	ID          string
	Verified    bool
	MachineHash string
	UserID      string
	UserName    string
	Connector   string
	InstallFP   string
	// InstallHint is a config root the agent claimed (a CLAUDE_CONFIG_DIR or
	// CODEX_HOME style override seen in the payload) that differs from
	// InstallFP. It is recorded for operators and never moves the ID.
	InstallHint string
}

// agentIdentityConfig is the config the gateway resolves connector config
// roots with. Set by NewSidecar and on every reload.
var agentIdentityConfig atomic.Pointer[config.Config]

// connectorConfigRootRel caches, per connector, its config root relative to
// a home directory. Cleared when the config changes.
var connectorConfigRootRel sync.Map

func setAgentIdentityConfig(cfg *config.Config) {
	agentIdentityConfig.Store(cfg)
	connectorConfigRootRel.Clear()
}

// agentIdentityUser is the user an agent identity is derived for.
type agentIdentityUser struct {
	ID       string
	Name     string
	Home     string
	Sandbox  string
	Self     bool // the account this per-user gateway runs as
	Verified bool
}

// resolveHookAgentIdentity derives the agent identity of an authenticated
// hook request. It returns the zero value under the Secure Client
// integration, which emits no agent identity.
func resolveHookAgentIdentity(ctx context.Context, req agentHookRequest) agentIdentityFacts {
	if ManagedEnterpriseActive() {
		return agentIdentityFacts{}
	}
	connectorName := strings.ToLower(strings.TrimSpace(req.ConnectorName))
	user := hookAgentIdentityUser(ctx)
	if connectorName == "" || user.ID == "" {
		return agentIdentityFacts{}
	}
	machine, machineVerified := agentidentity.HostMachineHash()
	facts := agentIdentityFacts{
		MachineHash: machine,
		UserID:      agentidentity.NormalizeUserID(user.ID),
		// The account as the host names it (an SSSD dcad-alice@dclab.test
		// stays qualified), so an agent-identities row can be passed back
		// to the other admin views. defenseclaw.user.name stays bare.
		UserName:  user.Name,
		Connector: connectorName,
		InstallFP: agentIdentityInstallFP(connectorName, user),
	}
	facts.ID = agentidentity.AgentID(agentidentity.Inputs{
		MachineHash: facts.MachineHash, UserID: facts.UserID, Connector: facts.Connector, InstallFP: facts.InstallFP,
	})
	if facts.ID == "" {
		return agentIdentityFacts{}
	}
	facts.Verified = machineVerified && user.Verified
	if hint := claimedInstallHint(req.Payload); hint != "" &&
		agentidentity.NormalizeInstallFP(hint) != agentidentity.NormalizeInstallFP(facts.InstallFP) {
		facts.InstallHint = hint
	}
	return facts
}

// hookAgentIdentityUser picks the user an agent identity belongs to, most
// trusted source first. Only the last case, a service-account gateway
// reached without a verified caller, falls back to the claimed identity
// headers, and it is never marked verified.
func hookAgentIdentityUser(ctx context.Context) agentIdentityUser {
	if binding, ok := sandboxauth.FromContext(ctx); ok {
		uid, _, name := sandboxBindingUser(binding)
		return agentIdentityUser{
			ID: uid, Name: name, Sandbox: firstNonEmpty(binding.SandboxID, binding.ID), Verified: uid != "",
		}
	}
	if peer, ok := managedHookPeerFromContext(ctx); ok {
		return agentIdentityUser{ID: strconv.Itoa(peer.UID), Name: peer.Name, Home: peer.Home, Verified: true}
	}
	if identity, _ := ctx.Value(verifiedUserScopedIdentityContextKey{}).(string); identity != "" {
		user := agentIdentityUser{ID: identity, Home: userScopedIdentityHome(identity), Verified: true}
		if bound := AgentIdentityFromContext(ctx); bound.UserID == identity {
			user.Name = bound.UserName
		}
		return user
	}
	if !gatewayRunsAsServiceAccount() {
		return gatewaySelfUser()
	}
	claimed := AgentIdentityFromContext(ctx)
	if claimed.UserID == "" {
		return agentIdentityUser{}
	}
	return agentIdentityUser{ID: claimed.UserID, Name: claimed.UserName, Home: userScopedIdentityHome(claimed.UserID)}
}

var gatewaySelf struct {
	once sync.Once
	user agentIdentityUser
}

// gatewaySelfUser is the account a per-user gateway runs as. Only that
// account can read the gateway token a hook authenticates with, so it is the
// verified user of every authenticated hook.
func gatewaySelfUser() agentIdentityUser {
	gatewaySelf.once.Do(func() {
		self := agentIdentityUser{Self: true, Verified: true}
		if current, err := osuser.Current(); err == nil && current != nil {
			self.ID, self.Name, self.Home = current.Uid, current.Username, current.HomeDir
		}
		if self.ID == "" {
			if uid := os.Getuid(); uid >= 0 {
				self.ID = strconv.Itoa(uid)
			}
		}
		// Named as every verified hook caller is: the account database's
		// name for the uid or SID. That keeps an SSSD user@realm but gives
		// the bare Windows account, not os/user's DOMAIN\user, so agent
		// identities agree with the other per-user views (GAP-0107).
		if name := userScopedIdentityName(self.ID); name != "" {
			self.Name = name
		}
		if self.Home == "" {
			self.Home, _ = os.UserHomeDir()
		}
		self.Name = sanitizeLLMEventUser(self.Name)
		gatewaySelf.user = self
	})
	return gatewaySelf.user
}

// agentIdentityInstallFP is the connector's config root for user, as the
// gateway resolves it. Both per-user and service-account gateways use a
// stable root under the verified user's home; the gateway startup environment
// says nothing reliable about the connector installation. Runtime overrides
// are recorded only as install hints. A sandbox names its own install.
func agentIdentityInstallFP(connectorName string, user agentIdentityUser) string {
	if user.Sandbox != "" {
		return "openshell-sandbox:" + user.Sandbox
	}
	cfg := agentIdentityConfig.Load()
	if user.Self {
		switch strings.ToLower(strings.TrimSpace(connectorName)) {
		case "claudecode", "codex", "hermes", "opencode", "omnigent":
		default:
			return filepath.Clean(cfg.ConnectorHomeDir(connectorName))
		}
	}
	if user.Home == "" {
		return ""
	}
	return filepath.Join(user.Home, connectorConfigRootRelative(cfg, connectorName))
}

// connectorConfigRootRelative is the connector's config root relative to a
// home directory: the default root the connector uses, without any
// environment override, or "."+connector for a connector whose root lies
// outside the home.
func connectorConfigRootRelative(cfg *config.Config, connectorName string) string {
	// These roots have runtime environment overrides in ConnectorHomeDir.
	// They must not become part of a verified identity after a restart.
	switch strings.ToLower(strings.TrimSpace(connectorName)) {
	case "claudecode":
		return ".claude"
	case "codex":
		return ".codex"
	case "hermes":
		if runtime.GOOS == "windows" {
			return filepath.Join("AppData", "Local", "hermes")
		}
		return ".hermes"
	case "opencode":
		return filepath.Join(".config", "opencode")
	case "omnigent":
		return ".omnigent"
	}
	if cached, ok := connectorConfigRootRel.Load(connectorName); ok {
		return cached.(string)
	}
	rel := "." + connectorName
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if candidate, err := filepath.Rel(home, cfg.ConnectorHomeDir(connectorName)); err == nil &&
			candidate != "." && !filepath.IsAbs(candidate) && candidate != ".." &&
			!strings.HasPrefix(candidate, ".."+string(filepath.Separator)) {
			rel = candidate
		}
	}
	connectorConfigRootRel.Store(connectorName, rel)
	return rel
}

// maxInstallHintBytes bounds the recorded hint.
const maxInstallHintBytes = 512

// claimedInstallHint returns the config root the agent's payload implies: an
// explicit config-dir field, or the root a transcript path lives under
// (<root>/projects/... for Claude Code, <root>/sessions/... for Codex). It is
// agent-controlled and only ever recorded as a hint.
func claimedInstallHint(payload map[string]interface{}) string {
	if payload == nil {
		return ""
	}
	hint := firstString(payload, "config_dir", "configDir", "claude_config_dir", "codex_home")
	if hint == "" {
		// Find the marker on a slash-normalized copy but cut the original, so a
		// Windows hint keeps its backslashes like the install root beside it.
		transcript := firstString(payload, "transcript_path", "transcriptPath")
		normalized := strings.ReplaceAll(transcript, `\`, "/")
		for _, marker := range []string{"/projects/", "/sessions/"} {
			if i := strings.Index(normalized, marker); i > 0 {
				hint = transcript[:i]
				break
			}
		}
	}
	hint = strings.TrimSpace(displaySafeText(hint))
	if hint == "" || len(hint) > maxInstallHintBytes {
		return ""
	}
	return hint
}

// displaySafeText replaces what makes agent-claimed text render other than
// it reads on an admin's terminal with a space: C0 and C1 controls, and the
// bidi overrides, isolates and marks and other invisible format characters
// stripZeroWidth drops (GAP-0380).
func displaySafeText(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 0x80 && r <= 0x9F) || (r > 0x7F && stripZeroWidth(string(r)) == "") {
			return ' '
		}
		return r
	}, stripLogInjectionRunes(s))
}

// hookSubagentID is the sub-agent a hook belongs to, or "" for the session's
// root agent. A sub-agent that runs in a child session already has its own
// session instance, so only a sub-agent sharing its parent's session needs
// one derived. Claude Code and Codex report agent_id only inside a
// sub-agent; other connectors are treated as sub-agent hooks only when they
// say so.
func hookSubagentID(req agentHookRequest) string {
	agentID := strings.TrimSpace(req.AgentID)
	if agentID == "" || strings.TrimSpace(req.ChildSessionID) != "" {
		return ""
	}
	switch event := canonicalEvent(req.HookEventName); {
	case event == "subagentstart" || event == "subagentstop":
		return agentID
	case subagentOnlyAgentIDConnector(req.ConnectorName):
		// These connectors report agent_id only inside a sub-agent, on every
		// hook of it (GAP-0137), not only on its start and stop. Any other
		// agent id is one correlation minted or restored for the main agent
		// on a session or turn boundary; keying the instance on it moved
		// ais- whenever a new one was minted, as on a resume after a
		// gateway restart.
		if reported, _, _ := extractAgentIdentityFromHookPayload(req.Payload); strings.TrimSpace(reported) == agentID {
			return agentID
		}
		return ""
	case strings.TrimSpace(req.ParentAgentID) != "" && strings.TrimSpace(req.ParentAgentID) != agentID:
		return agentID
	}
	return ""
}

// subagentOnlyAgentIDConnector reports whether name's hooks carry agent_id
// only inside a sub-agent: the main agent's hooks carry none. Claude Code
// and Codex (0.159 and later) do. Any hook of such a connector that names an
// agent belongs to a child of the session's main agent, whatever the event.
func subagentOnlyAgentIDConnector(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "claudecode", "codex":
		return true
	}
	return false
}

// payloadNamesSubagent reports whether a hook of source names agentID in its
// own payload and source reports agent_id only inside a sub-agent. An agent
// id that correlation minted or restored for the main agent is not in the
// payload, so it never counts.
func payloadNamesSubagent(source, agentID string, payload map[string]interface{}) bool {
	if agentID == "" || !subagentOnlyAgentIDConnector(source) {
		return false
	}
	reported, _, _ := extractAgentIdentityFromHookPayload(payload)
	return strings.TrimSpace(reported) == agentID
}

var agentIdentityIDPattern = regexp.MustCompile(`^agt-[0-9a-f]{16}$`)

// agentIdentityV8 is defenseclaw.agent.identity.id for a generated record,
// absent unless id has the registered shape.
func agentIdentityV8(id string) observability.Optional[string] {
	if !agentIdentityIDPattern.MatchString(id) {
		return observability.Absent[string]()
	}
	return observability.Present(id)
}

// agentIdentityV8FromContext is agentIdentityV8 of the hook path's identity.
func agentIdentityV8FromContext(ctx context.Context) observability.Optional[string] {
	id, _ := agentIdentityFromContext(ctx)
	return agentIdentityV8(id)
}

// inventoryAgentIdentityID is the agent identity of userID's install of
// connectorName: the ID the hook path derives for that user's hooks, so an
// inventory record joins the agent's decisions. "" when it cannot be derived.
func inventoryAgentIdentityID(connectorName, userID string) string {
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	if ManagedEnterpriseActive() || connectorName == "" || userID == "" {
		return ""
	}
	user := agentIdentityUser{ID: userID, Home: userScopedIdentityHome(userID)}
	if self := gatewaySelfUser(); !gatewayRunsAsServiceAccount() && self.ID == userID {
		user = self
	}
	machine, _ := agentidentity.HostMachineHash()
	return agentidentity.AgentID(agentidentity.Inputs{
		MachineHash: machine, UserID: agentidentity.NormalizeUserID(user.ID),
		Connector: connectorName, InstallFP: agentIdentityInstallFP(connectorName, user),
	})
}

// withSessionAgentInstance joins a request outside the hook path (the Codex
// notify webhook) to the agent instance its session was seen under on the hook
// path, on the audit envelope, so its records carry the same ais- as the
// session's hook records. Like agentIdentityIDForTraffic it is a join, not a
// verification: it never sets the identity on the context (GAP-0203).
func withSessionAgentInstance(ctx context.Context, sessionID string) context.Context {
	identityID := agentIdentityIDForTraffic(ctx, AgentIdentityFromContext(ctx))
	if identityID == "" {
		return ctx
	}
	// The hook path keys a sandbox's sessions apart from the host's, so the
	// join must use the same key or it never finds a sandboxed session.
	instance := SharedAgentRegistry().peekAgentInstance(identityID, sandboxSessionStateKey(ctx, sessionID))
	if instance == "" {
		return ctx
	}
	return refreshAuditEnvelopeFromIdentity(ctx, "", AgentIdentity{AgentInstanceID: instance})
}

// agentIdentityIDForTraffic is the agent identity of a request outside the
// hook path (the LLM proxy, guardrail evaluate): the identity on ctx, else
// the one identity its session was seen under on the hook path. The session
// link is a join, not a verification, so it never feeds
// agentIdentityFromContext.
func agentIdentityIDForTraffic(ctx context.Context, identity AgentIdentity) string {
	if ctx.Value(acpUnboundAgentContextKey{}) != nil {
		return ""
	}
	return agentIdentityIDForSession(ctx, identity, firstNonEmpty(SessionIDFromContext(ctx), audit.EnvelopeFromContext(ctx).SessionID))
}

// agentIdentityIDForSession is agentIdentityIDForTraffic for traffic that
// names its session itself, as a native OTLP record does.
func agentIdentityIDForSession(ctx context.Context, identity AgentIdentity, sessionID string) string {
	if identity.IdentityID != "" {
		return identity.IdentityID
	}
	// A session id is caller supplied. The registry has no verified owner
	// mapping for a session-only join, so a shared gateway cannot attribute
	// its hook identity to another request by that id alone.
	if serviceAccountGatewayFromContext(ctx) || gatewayRunsAsServiceAccount() {
		return ""
	}
	reg := SharedAgentRegistry()
	if reg == nil {
		return ""
	}
	return reg.AgentIdentityForSession(ctx, sessionID)
}
