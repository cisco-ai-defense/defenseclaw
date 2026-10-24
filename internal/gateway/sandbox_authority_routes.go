// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// Request bounds of the authority routes other than resolve.
const (
	sandboxSmallBodyMax    = 4 << 10
	sandboxExplainBodyMax  = sandboxrelay.MaxResolveBytes
	sandboxMCPClaimsMax    = 256
	sandboxListMax         = 64
	sandboxProjectPathMax  = 4096
	sandboxRepoPolicySrc   = ".defenseclaw/sandbox.yaml"
	sandboxExplainLookupIn = identityDirectoryBudget
)

// sandboxResolveWait is how long policy/resolve waits for the identity
// lookup before it answers provisional (Q9); tests shorten it.
var sandboxResolveWait = sandboxrelay.ResolveIdentityWait

// registerSandboxAuthorityRoutes adds the managed sandbox authority routes
// to the hook-socket mux. The relayed hook, notify, inspect and OTLP routes
// are the relay's (sandbox_relay.go).
func (a *APIServer) registerSandboxAuthorityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+sandboxrelay.PathSettings, a.handleSandboxSettings)
	mux.HandleFunc("POST "+sandboxrelay.PathPolicyResolve, a.handleSandboxResolve)
	mux.HandleFunc("POST "+sandboxrelay.PathRegistrations+"{id}"+sandboxrelay.RegistrationBindSub, a.handleSandboxBind)
	mux.HandleFunc("POST "+sandboxrelay.PathRegistrations+"{id}"+sandboxrelay.RegistrationDelSub, a.handleSandboxDeleted)
	mux.HandleFunc("POST "+sandboxrelay.PathRegistrations+"{id}"+sandboxrelay.RegistrationStateSub, a.handleSandboxState)
	mux.HandleFunc("GET "+sandboxrelay.PathPolicyCurrent, a.handleSandboxCurrent)
	mux.HandleFunc("POST "+sandboxrelay.PathPolicyExplain, a.handleSandboxExplain)
	mux.HandleFunc("POST "+sandboxrelay.PathPolicyTest, a.handleSandboxPolicyTest)
	mux.HandleFunc("GET "+sandboxrelay.PathPolicyPacks, a.handleSandboxPacks)
	mux.HandleFunc("GET "+sandboxrelay.PathPolicyPacks+"/{name}", a.handleSandboxPacks)
	mux.HandleFunc("POST "+sandboxrelay.PathDecisions, a.handleSandboxDecide)
	mux.HandleFunc("GET "+sandboxrelay.PathDecisions, a.handleSandboxDecisions)
	mux.HandleFunc("POST "+sandboxrelay.PathEvents, a.handleSandboxEvents)
}

// sandboxRouteStart is every authority handler's preamble: the verified
// peer, the authority and the request pinned to one generation.
func (a *APIServer) sandboxRouteStart(w http.ResponseWriter, r *http.Request) (*http.Request, managedHookPeer, *sandboxAuthority, bool) {
	peer, ok := sandboxPeer(w, r)
	if !ok {
		return r, peer, nil, false
	}
	auth, err := a.sandboxAuth()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sandbox-authority] unavailable: %v\n", err)
		writeSandboxReason(w, sandboxrelay.ReasonUnavailable, sandboxTextUnavailable)
		return r, peer, nil, false
	}
	return a.pinRequestGeneration(r), peer, auth, true
}

// decodeSandboxJSON strictly decodes one JSON body of at most max bytes
// into v and answers 400 otherwise.
func decodeSandboxJSON(w http.ResponseWriter, r *http.Request, max int64, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, max+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		writeSandboxRefusal(w, http.StatusBadRequest, "invalid_request", sandboxTextBadRequest)
		return false
	}
	return true
}

// sandboxConnectorClaim is a known connector a route names (the
// X-DefenseClaw-Connector claim or a body field), or "".
func sandboxConnectorClaim(name string) string {
	name = config.NormalizeConnectorName(name)
	if name == "" || !connector.IsKnownBuiltinConnector(name) {
		return ""
	}
	return name
}

// sandboxRefuseRun answers a refused run: the reason's status with a
// ResolveResponse whose Refusal carries the user text and the caller's
// request-access contact, and the ErrorBody keys for the client's error.
func sandboxRefuseRun(w http.ResponseWriter, reason, message, requestAccess string) {
	status := sandboxrelay.ReasonStatus(reason)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		sandboxrelay.ResolveResponse
		Error   string `json:"error"`
		Message string `json:"message"`
	}{
		ResolveResponse: sandboxrelay.ResolveResponse{
			V:       sandboxrelay.WireVersion,
			Refusal: &sandboxrelay.Refusal{Reason: reason, Message: message, RequestAccess: requestAccess},
		},
		Error: reason, Message: message,
	})
}

// sandboxHostAvailability says whether this host can run sandboxes for
// peer under floor F, on which compute driver, and why not: the gate's
// availability probe (platform, docker or /dev/kvm access for the peer's
// uid, the MicroVM driver's docker fallback, the lifecycle's prerequisite
// state; sandbox_availability.go), so the gate and the launcher share one
// verdict. The reason is bare ("OpenShell is not installed") and names only
// the caller's own facts; sandboxapi.UnavailableSentence frames it
// (GAP-0175).
var sandboxHostAvailability = func(cfg *config.Config, peer managedHookPeer, floor config.OpenShellAdminConfig) sandboxAvailability {
	return defaultSandboxAvailability.check(cfg, peer.UID, true, floor)
}

// sandboxUnavailableText is the caller's sentence of an unavailable answer.
func sandboxUnavailableText(avail sandboxAvailability) string {
	return sandboxapi.UnavailableSentence(avail.Why)
}

// sandboxDriverClaim checks the compute driver the caller's daemon chose
// at sandbox start (its own KVM probe, as the user) against
// enterprise.openshell.driver and the caller's driver_fallback under floor
// F, and returns the driver and reason to register, or a typed refusal. A
// daemon that names no driver gets the gateway's own view (avail). The
// docker fallback is only for a MicroVM configuration on Linux whose
// fallback is docker, and only with a fallback reason; a profile's
// driver_fallback: none refuses it.
func sandboxDriverClaim(cfg *config.Config, goos string, floor config.OpenShellAdminConfig, driver, reason string, avail sandboxAvailability) (string, string, *sandboxrelay.Refusal) {
	want := sandboxDriverFor(cfg, goos)
	if driver == "" {
		driver, reason = avail.Driver, avail.DriverReason
	}
	switch {
	case goos == "darwin" || want == config.EnterpriseOpenShellDriverDocker:
		// One driver, no fallback: macOS runs only the MicroVM driver.
		if goos == "darwin" {
			want = config.EnterpriseOpenShellDriverVM
		}
		if driver != want {
			return "", "", sandboxDriverSwitchRefusal(driver, want)
		}
		return driver, openshell.DriverReasonConfigured, nil
	case driver == config.EnterpriseOpenShellDriverDocker && reason == openshell.DriverReasonConfigured:
		// A daemon holding the earlier explicit Docker configuration must
		// refresh it before claiming a VM or an auto-selected fallback. It
		// receives no registration or permission to keep the old choice.
		return "", "", sandboxDriverSwitchRefusal(driver, want)
	case driver == config.EnterpriseOpenShellDriverVM:
		if want == config.EnterpriseOpenShellDriverAuto {
			return driver, openshell.DriverReasonKVMAvailable, nil
		}
		return driver, openshell.DriverReasonConfigured, nil
	case driver != config.EnterpriseOpenShellDriverDocker || !openshell.IsFallbackReason(reason):
		return "", "", &sandboxrelay.Refusal{Reason: sandboxrelay.ReasonUnavailable, Message: "The sandbox request is malformed: unknown compute driver choice."}
	case sandboxDriverFallbackFor(cfg, goos, floor) != config.EnterpriseOpenShellFallbackDocker:
		return "", "", &sandboxrelay.Refusal{Reason: sandboxrelay.ReasonUnavailable, Message: sandboxUnavailableText(sandboxVMRequired(reason))}
	}
	return driver, reason, nil
}

func sandboxDriverSwitchRefusal(running, selected string) *sandboxrelay.Refusal {
	return &sandboxrelay.Refusal{Reason: sandboxrelay.DetailSetupChanging,
		Message: "Your sandbox service still uses the " + running + " driver, but the current sandbox configuration selects " + selected +
			". Stop your sandboxes with `defenseclaw sandbox stop NAME`, then retry the command so the authorized update can finish."}
}

func sandboxOperational(cfg *config.Config, floor config.OpenShellAdminConfig) sandboxrelay.OperationalSettings {
	o := cfg.OpenShell
	out := sandboxrelay.OperationalSettings{
		IngressPort:      cfg.OpenShellIngressPort(),
		EgressPort:       cfg.OpenShellEgressPort(),
		GatewayName:      o.Gateway.Name,
		GatewayWorkspace: o.Gateway.Workspace,
		Image:            sandboxrelay.ImageSettings{Base: o.Image.Base, HarnessVersions: maps.Clone(o.Image.HarnessVersions)},
		Approvals:        sandboxrelay.ApprovalsSettings{DebounceMs: o.Approvals.DebounceMs, AgentProposals: o.Approvals.AgentProposals},
		MCP:              sandboxrelay.MCPSettings{Import: o.MCP.Import, HostPorts: slices.Clone(o.MCP.HostPorts)},
		Harnesses:        slices.Clone(o.Harnesses),
		Wrappers:         slices.Clone(o.Wrappers),
		TokenDelivery:    o.TokenDelivery,
		Middleware:       o.Middleware.Enabled,
		LLM:              o.LLM,
		KeepHeadless:     o.KeepHeadless,
		// OpenShell's own telemetry stays off on a managed host unless the
		// caller's floor allows it.
		UpstreamTelemetry: o.UpstreamTelemetry && floor.AllowUpstreamTelemetry != nil && *floor.AllowUpstreamTelemetry,
	}
	// The administrator's trusted CAs, read here as the gateway's service
	// account from an administrator-owned file.
	if trusted, err := image.TrustedCAsFor(cfg); err != nil {
		out.TrustedCAError = err.Error()
	} else {
		out.TrustedCAs = string(trusted)
	}
	return out
}

// sandboxEnterprise is enterprise.openshell as the caller's daemon runs
// with it under floor F: the wanted driver and the caller's own fallback.
func sandboxEnterprise(cfg *config.Config, floor config.OpenShellAdminConfig) sandboxrelay.EnterpriseOpenShell {
	e := cfg.Enterprise.OpenShell
	out := sandboxrelay.EnterpriseOpenShell{
		Install: e.Install, Driver: e.SandboxDriver(runtime.GOOS), DriverFallback: e.SandboxDriverFallback(runtime.GOOS, floor),
		Version: e.Version, GatewayPort: e.GatewayPort, E2fsprogsDir: e.E2fsprogsDir,
	}
	if out.Install == "" {
		out.Install = "prerequisite"
	}
	// The release the daemon installs in setup mode (the 1.0.3 pin "0.1.3"
	// runs no sandbox), as ensure renders it.
	out.Version, _ = openshell.ManagedSetupPin(out.Install == config.EnterpriseOpenShellInstallSetup, strings.TrimSpace(out.Version))
	if out.GatewayPort == 0 {
		out.GatewayPort = config.DefaultEnterpriseOpenShellGatewayPort
	}
	out.GatewayConfigPath, out.GatewayConfigDigest = sandboxRenderedGateway(runtime.GOOS)
	return out
}

// sandboxRenderedGateway is the gateway.toml the lifecycle renders from
// enterprise.openshell and its independent pinned digest. Reading a digest
// of gateway.toml itself would accept a hand edit as its own baseline.
var sandboxRenderedGateway = func(goos string) (path, digest string) {
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil || layout.ConfigDir == "" {
		return "", ""
	}
	dir := filepath.Join(layout.ConfigDir, "openshell")
	path = filepath.Join(dir, openshell.GatewayTOMLFile)
	if _, err := os.Stat(path); err != nil {
		return "", ""
	}
	digest, err = openshell.ReadRenderedGatewayDigest(filepath.Join(dir, openshell.GatewayRenderedDigestFile))
	if err != nil {
		return path, "invalid"
	}
	return path, digest
}

// sandboxSettingsDigest digests the host sandbox settings a daemon runs
// with for floor.
func sandboxSettingsDigest(cfg *config.Config, floor config.OpenShellAdminConfig) string {
	if cfg == nil {
		return ""
	}
	return sandboxDigestOf(struct {
		Enabled     bool
		Operational sandboxrelay.OperationalSettings
		Enterprise  sandboxrelay.EnterpriseOpenShell
	}{cfg.OpenShell.Enabled, sandboxOperational(cfg, floor), sandboxEnterprise(cfg, floor)})
}

// handleSandboxSettings answers GET settings: what the caller's daemon runs
// with. The connector claim, when sent, must pass decide; without one the
// caller must pass decide for some sandbox harness.
func (a *APIServer) handleSandboxSettings(w http.ResponseWriter, r *http.Request) {
	r, peer, _, ok := a.sandboxRouteStart(w, r)
	if !ok {
		return
	}
	connectorName := ""
	if raw := strings.TrimSpace(r.Header.Get(sandboxrelay.ConnectorHeader)); raw != "" {
		if connectorName = sandboxConnectorClaim(raw); connectorName == "" {
			writeSandboxRefusal(w, http.StatusForbidden, managedHookReasonConnectorUnknown, "")
			return
		}
		if !a.sandboxDecide(w, r, peer, connectorName) {
			return
		}
	} else if !a.sandboxDecideAny(w, r, peer) {
		return
	}
	cfg := a.liveBaseConfig(r.Context())
	match := a.sandboxMatchPeer(r.Context(), peer, connectorName, 0)
	if match.decision.Refused != "" {
		sandboxRefuseView(w, match.decision)
		return
	}
	floor, floorDigest, err := sandboxFloorFor(cfg, match.decision.Name)
	if err != nil {
		writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
		return
	}
	avail := sandboxHostAvailability(cfg, peer, floor)
	// The bare reason: the launcher frames it once (GAP-0175).
	available, why := avail.Available, ""
	if !available {
		why = strings.TrimSpace(avail.Why)
	}
	if !cfg.OpenShell.Enabled {
		available, why = false, sandboxUnavailableOff
	}
	view := sandboxreg.Registration{Profile: match.decision.Name, ProfileDigest: match.decision.Digest, EffectiveDigest: floorDigest}
	a.writeJSON(w, http.StatusOK, sandboxrelay.DaemonSettings{
		V: sandboxrelay.WireVersion, Enabled: cfg.OpenShell.Enabled, Available: available, Unavailable: why,
		Operational: sandboxOperational(cfg, floor), Enterprise: sandboxEnterprise(cfg, floor),
		Generation: a.sandboxViewGeneration(cfg, view), RequestAccess: sandboxRequestAccess(floor),
		SelectedDriver: avail.Driver, DriverReason: avail.DriverReason, ForeignSandboxes: sandboxForeignAction(floor),
	})
}

// sandboxForeignAction is floor F's foreign_sandboxes: alert only when F
// says so, else stop (an empty value is stop on a managed computer).
func sandboxForeignAction(f config.OpenShellAdminConfig) string {
	if strings.EqualFold(strings.TrimSpace(f.ForeignSandboxes), config.OpenShellForeignSandboxesAlert) {
		return config.OpenShellForeignSandboxesAlert
	}
	return config.OpenShellForeignSandboxesStop
}

// sandboxResolveInput is what a resolve asked for; its run inputs are kept
// in the registration's run record so a re-match can resolve the same run
// again (sandboxRunInput).
type sandboxResolveInput struct {
	Req  sandboxrelay.ResolveRequest
	Repo *packs.RepoPolicy
	// Profile is the caller's own guardrail profile the floor is for; a
	// refusal of its required pack names it.
	Profile string
	// Subject is the account the run is for: the peer's uid and its home
	// from the account database, never the gateway's own.
	Subject packs.Subject
}

// sandboxSubject is the resolver subject of peer.
func sandboxSubject(peer managedHookPeer) packs.Subject {
	return packs.Subject{UID: peer.UID, Home: peer.Home}
}

// sandboxInputProblem is the text of a resolve failure the caller's own input
// caused (their --pack, a pack file or a repository policy of theirs), which
// they can fix and which says nothing of the organization's policy. Anything
// else is the organization's own files and stays the generic "can't be
// loaded" answer (GAP-0559, GAP-0563).
func sandboxInputProblem(err error) (string, bool) {
	var input *packs.InputError
	if errors.As(err, &input) {
		return input.Error(), true
	}
	return "", false
}

// sandboxResolveEffective resolves the run in for its subject under floor
// F: the resolver reads no pack the subject named with the gateway's own
// file access (a --pack file arrives as the bytes the daemon read as the
// user, UserPack) and matches require_copy_for on the resolved project.
var sandboxResolveEffective = func(cfg *config.Config, floor config.OpenShellAdminConfig, in sandboxResolveInput) (*packs.Effective, []packs.Violation, error) {
	f := in.Req.Flags
	subject := in.Subject
	return packs.Resolve(cfg, packs.Flags{
		Pack: f.Pack, Harness: in.Req.Harness, Project: in.Req.ProjectReal, Profile: f.Profile,
		// Managed hosts are copy-only (D2).
		Copy: true, Safe: f.Safe, Yolo: f.Yolo, Unmask: slices.Clone(f.Unmask), HostPorts: slices.Clone(f.HostPorts),
		NoMCP: f.NoMCP, Learn: f.Learn, ProcessTree: f.ProcessTree, CPU: f.CPU, Memory: f.Memory,
		RepoPolicy: in.Repo, FloorProfile: profileUserLabel(in.Profile),
		Subject: &subject, Floor: &floor, UserPack: in.Req.UserPack, ProjectReal: in.Req.ProjectReal,
	})
}

// sandboxEffectiveDigest is the effective sandbox policy digest users see.
func sandboxEffectiveDigest(eff *packs.Effective) string { return eff.Digest() }

// sandboxFilterMCP keeps the claimed MCP servers the managed gateway's
// block list and asset policy allow for a sandbox (sandboxMCPClaims). When
// the claims can't be judged every claimed server is left out, which fails
// closed.
var sandboxFilterMCP = func(ctx context.Context, a *APIServer, peer managedHookPeer, connectorName string, claims []sandboxrelay.MCPServerClaim) ([]string, []sandboxrelay.MCPSkip) {
	kept, skipped, err := a.sandboxMCPClaims(ctx, connectorName, claims)
	if err == nil {
		return kept, skipped
	}
	fmt.Fprintf(os.Stderr, "[sandbox-authority] mcp claims uid=%d: %v\n", peer.UID, err)
	kept, skipped = []string{}, []sandboxrelay.MCPSkip{}
	for _, c := range claims {
		if name := strings.TrimSpace(c.Name); validSandboxMCPClaimName(name) {
			skipped = append(skipped, sandboxrelay.MCPSkip{Name: name, Reason: sandboxrelay.MCPSkipOrganizationBlock})
		}
	}
	return kept, skipped
}

// sandboxRunMCPJudge records the actual run's MCP decision. A pack that
// disables import leaves every claimed server out before the gateway's
// server-level policy is relevant.
func sandboxRunMCPJudge(ctx context.Context, a *APIServer, peer managedHookPeer, connectorName string,
	claims []sandboxrelay.MCPServerClaim, importMCP bool) ([]string, []sandboxrelay.MCPSkip) {
	if importMCP {
		return sandboxFilterMCP(ctx, a, peer, connectorName, claims)
	}
	skipped := make([]sandboxrelay.MCPSkip, 0, len(claims))
	for _, claim := range claims {
		skipped = append(skipped, sandboxrelay.MCPSkip{Name: claim.Name, Reason: sandboxrelay.MCPSkipOrganizationBlock})
	}
	return nil, skipped
}

// validateSandboxResolve bounds every claim of a resolve; the text is the
// refusal's.
func validateSandboxResolve(req *sandboxrelay.ResolveRequest) string {
	req.Connector = config.NormalizeConnectorName(req.Connector)
	req.Harness = strings.ToLower(strings.TrimSpace(req.Harness))
	switch {
	case req.V != sandboxrelay.WireVersion:
		return "unsupported request version"
	case sandboxConnectorClaim(req.Connector) == "" || req.Harness == "":
		return "unknown agent"
	case len(req.RepoOverlay) > sandboxrelay.MaxRepoOverlayBytes:
		return "the repository policy is too large"
	case len(req.UserPack) > sandboxrelay.MaxUserPackBytes:
		return "the pack file is too large"
	case !sandboxCleanAbsPath(req.ProjectReal):
		return "the project path must be an absolute, resolved path"
	case req.Driver != "" && req.Driver != "docker" && req.Driver != "vm":
		return "unknown compute driver"
	case req.DriverReason != "" && !openshell.ValidDriverReason(req.DriverReason):
		return "unknown compute driver reason"
	case len(req.MCP) > sandboxMCPClaimsMax:
		return "too many MCP servers"
	}
	f := req.Flags
	switch f.Profile {
	case "", "open", "balanced", "strict":
	default:
		return "unknown policy profile"
	}
	if len(f.Unmask) > sandboxListMax || len(f.HostPorts) > sandboxListMax {
		return "too many flag values"
	}
	for _, port := range f.HostPorts {
		if port < 1 || port > 65535 {
			return "a host port is out of range"
		}
	}
	for _, s := range append([]string{f.Pack, f.CPU, f.Memory, req.HarnessVersion, req.HookContract, req.TamperTier,
		req.OpenShell.Version, req.OpenShell.InstallMode, req.OpenShell.SettingsDigest}, f.Unmask...) {
		if len(s) > 256 || !sandboxPrintable(s) {
			return "a field is malformed"
		}
	}
	if !sandboxValidMCPClaims(req.MCP) {
		return "an MCP server claim is malformed"
	}
	return ""
}

// sandboxValidMCPClaims reports claims every one of which is well formed
// (sandboxrelay.ValidMCPServerClaim).
func sandboxValidMCPClaims(claims []sandboxrelay.MCPServerClaim) bool {
	for _, m := range claims {
		if !sandboxrelay.ValidMCPServerClaim(m) {
			return false
		}
	}
	return true
}

func sandboxCleanAbsPath(p string) bool {
	return p != "" && len(p) <= sandboxProjectPathMax && filepath.IsAbs(p) && filepath.Clean(p) == p &&
		!strings.ContainsFunc(p, func(c rune) bool { return c < 0x20 || c == 0x7f })
}

func sandboxHarnessAllowed(floor config.OpenShellAdminConfig, harnessName string) bool {
	if len(floor.AllowedHarnesses) == 0 {
		return true
	}
	return slices.ContainsFunc(floor.AllowedHarnesses, func(h string) bool {
		return config.NormalizeConnectorName(h) == harnessName
	})
}

// handleSandboxResolve answers POST policy/resolve: it judges the run the
// caller's daemon is about to create against the caller's own floor and
// registers it (pending, sandboxreg.PendingTTL), or refuses it with the caller's
// request-access contact.
func (a *APIServer) handleSandboxResolve(w http.ResponseWriter, r *http.Request) {
	r, peer, auth, ok := a.sandboxRouteStart(w, r)
	if !ok {
		return
	}
	var req sandboxrelay.ResolveRequest
	if !decodeSandboxJSON(w, r, sandboxrelay.MaxResolveBytes, &req) {
		return
	}
	if msg := validateSandboxResolve(&req); msg != "" {
		writeSandboxRefusal(w, http.StatusBadRequest, "invalid_request", "The sandbox request is malformed: "+msg+".")
		return
	}
	if claim := strings.TrimSpace(r.Header.Get(sandboxrelay.ConnectorHeader)); claim != "" && config.NormalizeConnectorName(claim) != req.Connector {
		writeSandboxReason(w, sandboxrelay.ReasonConnectorMismatch, sandboxTextConnectorMismatch)
		return
	}
	if !a.sandboxDecide(w, r, peer, req.Connector) {
		return
	}
	cfg := a.liveBaseConfig(r.Context())
	baseAccess := sandboxRequestAccess(cfg.OpenShell.Admin)
	// The subject key binds a registration to the account name; without one a
	// recycled uid could not be told apart (GAP-0109). While the account
	// database gives none (a directory outage), the name the uid last
	// resolved to stands in (GAP-0507).
	accountName := sandboxStandInName(peer)
	// Every refused resolution is recorded for the administrator as a
	// failed log.sandbox.policy.resolved of the caller, which is mandatory
	// (GAP-0148): the attempt names the caller and, once matched, the
	// profile it was judged under.
	attempt := sandboxreg.Registration{UID: peer.UID, UserName: accountName, Connector: req.Connector, Harness: req.Harness}
	if accountName != "" {
		attempt.SubjectKey = sandboxSubjectKey(auth.key, peer.UID, accountName, "")
	}
	refuse := func(reason, message, requestAccess string) {
		sandboxRecordResolveRefused(a, attempt, reason)
		sandboxRefuseRun(w, reason, message, requestAccess)
	}
	if accountName == "" {
		refuse(sandboxrelay.ReasonUnavailable, sandboxTextAccountUnknown, baseAccess)
		return
	}
	if !cfg.OpenShell.Enabled {
		refuse(sandboxrelay.ReasonUnavailable, "Sandboxes are turned off on this computer.", baseAccess)
		return
	}
	facts, why := sandboxCheckHarness(cfg, req.Harness, req.Connector, req.HarnessVersion, req.HookContract)
	if why != "" {
		refuse(sandboxrelay.ReasonNotAllowed, why, baseAccess)
		return
	}
	match := a.sandboxMatchPeer(r.Context(), peer, req.Connector, sandboxResolveWait)
	if match.decision.Refused != "" {
		refuse(sandboxrelay.ReasonUnavailable, match.decision.Refused, baseAccess)
		return
	}
	attempt.Profile, attempt.ProfileMatch, attempt.MatchedGroup = match.decision.Name, match.decision.Match, match.decision.MatchedGroup
	attempt.ProfileDigest, attempt.Provisional = match.decision.Digest, match.provisional
	floor, floorDigest, err := sandboxFloorFor(cfg, match.decision.Name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sandbox-authority] floor uid=%d profile=%q: %v\n", peer.UID, match.decision.Name, err)
		refuse(sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable, baseAccess)
		return
	}
	access := sandboxRequestAccess(floor)
	if sandboxDaemonOutdated(r) {
		logOutdatedSandboxDaemon(peer, sandboxrelay.PathPolicyResolve)
		refuse(sandboxrelay.ReasonDaemonOutdated, sandboxTextDaemonOutdated, access)
		return
	}
	// Where sandboxes can run for the caller, and on which driver: the
	// gateway's view under the caller's floor (a profile's driver_fallback:
	// none applies here), then the driver the daemon chose at sandbox start.
	avail := sandboxHostAvailability(cfg, peer, floor)
	if !avail.Available {
		refuse(sandboxrelay.ReasonUnavailable, sandboxUnavailableText(avail), access)
		return
	}
	driver, driverReason, refusal := sandboxDriverClaim(cfg, runtime.GOOS, floor, req.Driver, req.DriverReason, avail)
	if refusal != nil {
		refuse(refusal.Reason, refusal.Message, access)
		return
	}
	if floor.Allowed != nil && !*floor.Allowed {
		refuse(sandboxrelay.ReasonNotAllowed, "Your organization doesn't allow sandboxes for your account.", access)
		return
	}
	if !sandboxHarnessAllowed(floor, req.Harness) {
		refuse(sandboxrelay.ReasonNotAllowed, "Your organization doesn't allow this agent in a sandbox.", access)
		return
	}
	in := sandboxResolveInput{Req: req, Subject: sandboxSubject(peer), Profile: match.decision.Name}
	in.Repo, err = sandboxExplainRepo(req.RepoOverlay)
	var eff *packs.Effective
	var violations []packs.Violation
	if err == nil {
		eff, violations, err = sandboxResolveEffective(cfg, floor, in)
	}
	if err != nil {
		if text, ok := sandboxInputProblem(err); ok {
			refuse(sandboxrelay.ReasonNotAllowed, text, access)
			return
		}
		fmt.Fprintf(os.Stderr, "[sandbox-authority] resolve uid=%d: %v\n", peer.UID, err)
		refuse(sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable, access)
		return
	}
	if fatal := packs.FirstFatal(violations); fatal != nil {
		text := fatal.Error()
		if fatal.Key == "mcp.host_ports" && fatal.Admin() && fatal.Detail != "" {
			// A --host-port the profile does not open: the flag and why, not
			// the configuration key (GAP-0558).
			text = "--host-port " + fatal.Attempted + " isn't allowed: " + fatal.Detail
		}
		refuse(sandboxrelay.ReasonNotAllowed, text, access)
		return
	}
	effective, err := json.Marshal(eff)
	var requiredPack json.RawMessage
	if err == nil && eff.RequiredPackContent() != nil {
		requiredPack, err = json.Marshal(eff.RequiredPackContent())
	}
	if err != nil {
		refuse(sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable, access)
		return
	}
	kept, skipped := sandboxRunMCPJudge(r.Context(), a, peer, req.Connector, req.MCP, eff.MCP.Import)
	id, err := sandboxreg.NewID()
	if err != nil {
		refuse(sandboxrelay.ReasonUnavailable, sandboxTextUnavailable, access)
		return
	}
	reg := sandboxreg.Registration{
		ID: id, UserName: accountName,
		SubjectKey:  sandboxSubjectKey(auth.key, peer.UID, accountName, ""),
		FactsDigest: sandboxFactsDigest(auth.key, match.facts, match.resolved),
		Profile:     match.decision.Name, ProfileMatch: match.decision.Match, MatchedGroup: match.decision.MatchedGroup,
		ProfileDigest: match.decision.Digest, Generation: a.sandboxHostGeneration(r.Context()),
		EffectiveDigest: sandboxEffectiveDigest(eff), Provisional: match.provisional,
		Connector: req.Connector, Harness: req.Harness, HarnessVersion: strings.TrimSpace(req.HarnessVersion),
		MCPKept: kept, MCPSkipped: skipped,
		HookContract: facts.Contract, TamperTier: facts.TamperTier, WorkdirMode: "copy",
		ProjectReal: req.ProjectReal, Driver: driver, DriverReason: driverReason, OpenShell: req.OpenShell.Version,
		InstallMode: sandboxEnterprise(cfg, floor).Install, CreatedAt: auth.clock(),
	}
	if !match.provisional {
		created := match.decision.Name
		reg.CreateProfile = &created
	}
	run := &sandboxreg.Run{
		Flags: req.Flags, RepoOverlay: req.RepoOverlay, UserPack: req.UserPack,
		PolicyKey: a.sandboxPolicyKey(r.Context(), cfg), FloorDigest: floorDigest,
		HostPorts: slices.Clone(eff.MCP.HostPorts),
	}
	if err := auth.store.CreateRun(peer.UID, reg, run); err != nil {
		fmt.Fprintf(os.Stderr, "[sandbox-authority] register uid=%d: %v\n", peer.UID, err)
		if errors.Is(err, sandboxreg.ErrFull) {
			refuse(sandboxrelay.ReasonUnavailable, "Too many sandboxes are registered for your account; delete the ones you no longer use.", access)
			return
		}
		refuse(sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable, access)
		return
	}
	stored, _, _ := auth.store.Get(peer.UID, id)
	sandboxRecordResolved(a, stored)
	bannerProfile, bannerDescription := sandboxProfileLabel(cfg, stored.Profile, stored.ProfileMatch)
	a.writeJSON(w, http.StatusOK, sandboxrelay.ResolveResponse{
		V: sandboxrelay.WireVersion,
		Registration: sandboxrelay.RegistrationView{
			ID: stored.ID, State: stored.State, Provisional: stored.Provisional,
			ExpiresAt: stored.CreatedAt.Add(sandboxreg.PendingTTL),
		},
		Effective: effective, RequiredPack: requiredPack, Operational: sandboxOperational(cfg, floor), MCPKept: kept, MCPSkipped: skipped,
		Banner: sandboxrelay.BannerView{
			Profile: bannerProfile, Description: bannerDescription,
			Provisional: stored.Provisional, PolicyDigest: stored.EffectiveDigest,
		},
		Generation: a.sandboxViewGeneration(cfg, stored),
	})
}

func sandboxRegistrationView(reg sandboxreg.Registration) sandboxrelay.RegistrationView {
	view := sandboxrelay.RegistrationView{
		V: sandboxrelay.WireVersion, ID: reg.ID, State: reg.State, Provisional: reg.Provisional,
		BoundAt: reg.BoundAt, SandboxID: reg.SandboxID, SandboxName: reg.SandboxName, BindingID: reg.BindingID,
	}
	if reg.State == sandboxreg.StatePending {
		view.ExpiresAt = reg.CreatedAt.Add(sandboxreg.PendingTTL)
	}
	return view
}

// handleSandboxBind answers POST registrations/{id}/bind: the caller's
// pending registration becomes live for the sandbox its daemon created.
func (a *APIServer) handleSandboxBind(w http.ResponseWriter, r *http.Request) {
	r, peer, auth, ok := a.sandboxRouteStart(w, r)
	if !ok {
		return
	}
	reg, ok := a.sandboxRegistrationFor(w, auth, peer, r.PathValue("id"), true, false)
	if !ok || !a.sandboxDecide(w, r, peer, reg.Connector) || !a.sandboxCheckSubject(w, auth, peer, reg) {
		return
	}
	var req sandboxrelay.BindRequest
	if !decodeSandboxJSON(w, r, sandboxSmallBodyMax, &req) {
		return
	}
	if req.V != sandboxrelay.WireVersion {
		writeSandboxRefusal(w, http.StatusBadRequest, "invalid_request", sandboxTextBadRequest)
		return
	}
	live, err := auth.store.Bind(peer.UID, reg.ID, req)
	switch {
	case err == nil:
		a.writeJSON(w, http.StatusOK, sandboxRegistrationView(live))
	case errors.Is(err, sandboxreg.ErrInvalid):
		writeSandboxRefusal(w, http.StatusBadRequest, "invalid_request", sandboxTextBadRequest)
	case errors.Is(err, sandboxreg.ErrTombstoned), errors.Is(err, sandboxreg.ErrRevoked):
		writeSandboxReason(w, sandboxrelay.ReasonRegistrationRevoked, sandboxTextRegistrationGone)
	case errors.Is(err, sandboxreg.ErrExpired):
		writeSandboxReason(w, sandboxrelay.ReasonRegistrationExpired, sandboxTextRegistrationGone)
	case errors.Is(err, sandboxreg.ErrInUse), errors.Is(err, sandboxreg.ErrNotPending):
		writeSandboxReason(w, sandboxrelay.ReasonNotAllowed, "This sandbox is already registered.")
	case errors.Is(err, sandboxreg.ErrDriverMismatch):
		writeSandboxReason(w, sandboxrelay.ReasonNotAllowed, "This sandbox runs on another compute driver than the one your organization's policy chose for it; delete it and start it again.")
	case errors.Is(err, sandboxreg.ErrNotFound):
		writeSandboxReason(w, sandboxrelay.ReasonRegistrationUnknown, sandboxTextRegistrationUnkn)
	default:
		fmt.Fprintf(os.Stderr, "[sandbox-authority] bind uid=%d: %v\n", peer.UID, err)
		writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
	}
}

// handleSandboxDeleted answers POST registrations/{id}/deleted: the
// caller's sandbox is gone. A pending registration is dropped, a live one
// becomes a tombstone (its sandbox ids never register again, and a stop a
// due re-match asks for still revokes it), and a tombstone is dropped with
// a gateway revocation's sandbox ids retired (sandboxreg.FileStore.Deleted).
// Only the account that registered it may report it deleted.
func (a *APIServer) handleSandboxDeleted(w http.ResponseWriter, r *http.Request) {
	r, peer, auth, ok := a.sandboxRouteStart(w, r)
	if !ok {
		return
	}
	reg, found, err := auth.store.Get(peer.UID, strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
		return
	}
	if !found {
		writeSandboxReason(w, sandboxrelay.ReasonRegistrationUnknown, sandboxTextRegistrationUnkn)
		return
	}
	if !a.sandboxDecide(w, r, peer, reg.Connector) || !a.sandboxCheckSubject(w, auth, peer, reg) {
		return
	}
	if reg.State == sandboxreg.StateLive || reg.State == sandboxreg.StateStopped {
		// A re-match due now records its stop first, so reporting the
		// sandbox deleted never evades it.
		a.sandboxRematchIfDue(r.Context(), auth, peer, reg)
	}
	if err := auth.store.Deleted(peer.UID, reg.ID); err != nil && !errors.Is(err, sandboxreg.ErrNotFound) {
		writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// sandboxRevokedText is the user text of a revoked registration: what the
// policy no longer allows when a re-match revoked it.
func sandboxRevokedText(auth *sandboxAuthority, reg sandboxreg.Registration) string {
	switch reg.RevokedReason {
	case sandboxrelay.ReasonSubjectChanged:
		return sandboxTextSubjectChanged
	case sandboxreg.ReasonPolicyChanged:
		if text := auth.stopText(reg.UID, reg.ID); text != "" {
			return text
		}
	}
	return sandboxTextRegistrationGone
}

// handleSandboxCurrent answers GET policy/current?registration=ID: the
// complete floor of the caller's registration now, its generation, and
// whether it is revoked or must stop.
func (a *APIServer) handleSandboxCurrent(w http.ResponseWriter, r *http.Request) {
	a.serveSandboxCurrent(w, r, r.URL.Query().Get(sandboxrelay.RegistrationQuery), false)
}

// handleSandboxState answers POST registrations/{id}/state: the caller's
// daemon reports whether the registration's sandbox runs now
// (sandboxreg.FileStore.Report) and is answered like policy/current. Only
// a bound registration has a sandbox to report.
func (a *APIServer) handleSandboxState(w http.ResponseWriter, r *http.Request) {
	a.serveSandboxCurrent(w, r, r.PathValue("id"), true)
}

// serveSandboxCurrent answers policy/current for the caller's registration
// id, after recording the daemon's state report when report is set.
func (a *APIServer) serveSandboxCurrent(w http.ResponseWriter, r *http.Request, id string, report bool) {
	r, peer, auth, ok := a.sandboxRouteStart(w, r)
	if !ok {
		return
	}
	var state sandboxrelay.StateReport
	if report {
		if !decodeSandboxJSON(w, r, sandboxSmallBodyMax, &state) {
			return
		}
		if state.V != sandboxrelay.WireVersion {
			writeSandboxRefusal(w, http.StatusBadRequest, "invalid_request", sandboxTextBadRequest)
			return
		}
	}
	reg, ok := a.sandboxRegistrationFor(w, auth, peer, id, !report, true)
	if !ok || !a.sandboxDecide(w, r, peer, reg.Connector) {
		return
	}
	if reg.State != sandboxreg.StateRevoked {
		if !a.sandboxCheckSubject(w, auth, peer, reg) {
			return
		}
		reg = a.sandboxRematchIfDue(r.Context(), auth, peer, reg)
	}
	// A daemon below the floor contract gets a revocation and may report
	// its sandbox stopped, which ends the lease at once; it never renews a
	// running sandbox or confirms a floor it cannot carry (GAP-0182).
	outdated := sandboxDaemonOutdated(r)
	if outdated && reg.State != sandboxreg.StateRevoked && (!report || state.Running) {
		refuseOutdatedSandboxDaemon(w, peer, r.URL.Path)
		return
	}
	cfg := a.liveBaseConfig(r.Context())
	// The create-pinned floor (GAP-0242): the same floor every other
	// route of a registered sandbox resolves under.
	floor, _, err := sandboxRegistrationFloor(cfg, reg)
	if err != nil {
		writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
		return
	}
	var requiredPack json.RawMessage
	if floor.RequiredPack != "" && !packs.IsBuiltin(floor.RequiredPack) && reg.State != sandboxreg.StateRevoked {
		// The required pack as the run loaded it: the pack the sandbox
		// runs, or the required one a stricter pack stands in for. Only
		// the second case carried it before, so a sandbox that ran the
		// required pack itself got policy_unloadable on every poll and
		// kept the floor of its create (GAP-0058).
		eff, _, err := sandboxRegistrationEffective(cfg, auth, peer, reg, floor)
		if err != nil || eff.RequiredPackLoaded() == nil {
			writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
			return
		}
		requiredPack, err = json.Marshal(eff.RequiredPackLoaded())
		if err != nil {
			writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
			return
		}
	}
	// Every live registration's daemon polls once a minute: the fleet's
	// active-sandbox gauge is exported again on them, so a sandbox that runs
	// quietly does not go stale on the Sandboxes board (#1241).
	a.refreshManagedSandboxActive(r.Context())
	if report && reg.State != sandboxreg.StateRevoked {
		next, err := auth.store.Report(peer.UID, reg.ID, state.Running)
		switch {
		case err == nil, errors.Is(err, sandboxreg.ErrRevoked):
			reg = next
		default:
			fmt.Fprintf(os.Stderr, "[sandbox-authority] state report uid=%d registration=%s: %v\n", peer.UID, reg.ID, err)
			writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
			return
		}
		if state.Running && reg.State != sandboxreg.StateRevoked {
			a.sandboxGuestSignal(r.Context(), auth, reg, audit.SandboxGuestRunningWithoutGuest)
		}
	}
	// A running sandbox counts again on its daemon's first poll after a
	// gateway restart, not only at its next phase change (#1241).
	a.trackManagedSandboxActive(r.Context(), auth, peer.UID, reg)
	provisional := reg.Provisional
	current := sandboxrelay.CurrentPolicy{
		V: sandboxrelay.WireVersion, Generation: a.sandboxViewGeneration(cfg, reg),
		Floor: &floor, RequiredPack: requiredPack, Digest: reg.EffectiveDigest, Profile: sandboxUserProfile(cfg, reg), Provisional: &provisional,
		UpdatedAt: sandboxreg.PolicyUpdatedAt(reg),
	}
	minProfile := floor.MinProfile
	current.MinProfile = &minProfile
	switch {
	case reg.State == sandboxreg.StateRevoked:
		current.Revoked, current.RevokedReason = true, sandboxRevokedText(auth, reg)
	case outdated:
		refuseOutdatedSandboxDaemon(w, peer, r.URL.Path)
		return
	}
	a.writeJSON(w, http.StatusOK, current)
}

// sandboxRegistrationEffective resolves a registered sandbox's policy
// again with the run it was created with (its run record); a scope without
// a registration resolves its harness and project alone.
func sandboxRegistrationEffective(cfg *config.Config, auth *sandboxAuthority, peer managedHookPeer, reg sandboxreg.Registration, floor config.OpenShellAdminConfig) (*packs.Effective, []packs.Violation, error) {
	run, ok, err := auth.store.Run(reg.UID, reg.ID)
	if err != nil {
		return nil, nil, err
	}
	in, err := sandboxRunInput(reg, run)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		in = sandboxResolveInput{Req: sandboxrelay.ResolveRequest{
			V: sandboxrelay.WireVersion, Harness: reg.Harness, Connector: reg.Connector, ProjectReal: reg.ProjectReal,
		}}
	}
	in.Subject = sandboxSubject(peer)
	return sandboxResolveEffective(cfg, floor, in)
}

// sandboxOwnScope is the caller's policy scope of a route that names a
// registration (RegistrationHeader or a body field) or, without one, a
// connector claim: the profile and match it uses.
type sandboxOwnScope struct {
	reg        sandboxreg.Registration
	registered bool
	connector  string
	match      sandboxMatch
}

// sandboxScope resolves and authorizes the scope of an explain, test or
// packs call; it answered the refusal when ok is false.
func (a *APIServer) sandboxScope(w http.ResponseWriter, r *http.Request, auth *sandboxAuthority, peer managedHookPeer, registration, claim string) (sandboxOwnScope, bool) {
	if registration = strings.TrimSpace(registration); registration != "" {
		reg, ok := a.sandboxRegistrationFor(w, auth, peer, registration, true, false)
		if !ok || !a.sandboxDecide(w, r, peer, reg.Connector) || !a.sandboxCheckSubject(w, auth, peer, reg) {
			return sandboxOwnScope{}, false
		}
		reg = a.sandboxRematchIfDue(r.Context(), auth, peer, reg)
		if match := a.sandboxMatchPeer(r.Context(), peer, reg.Connector, sandboxExplainLookupIn); match.decision.Refused != "" {
			sandboxRefuseView(w, match.decision)
			return sandboxOwnScope{}, false
		}
		return sandboxOwnScope{
			reg: reg, registered: true, connector: reg.Connector,
			match: sandboxMatch{
				decision:    profileDecision{Name: reg.Profile, Match: reg.ProfileMatch, MatchedGroup: reg.MatchedGroup, Digest: reg.ProfileDigest},
				provisional: reg.Provisional,
			},
		}, true
	}
	connectorName := sandboxConnectorClaim(claim)
	if connectorName == "" {
		writeSandboxRefusal(w, http.StatusForbidden, managedHookReasonConnectorUnknown, "")
		return sandboxOwnScope{}, false
	}
	if !a.sandboxDecide(w, r, peer, connectorName) {
		return sandboxOwnScope{}, false
	}
	match := a.sandboxMatchPeer(r.Context(), peer, connectorName, sandboxExplainLookupIn)
	if match.decision.Refused != "" {
		sandboxRefuseView(w, match.decision)
		return sandboxOwnScope{}, false
	}
	return sandboxOwnScope{connector: connectorName, match: match}, true
}

// sandboxRefuseView does not expose Name: it may include a candidate
// profile whose membership was not proven for this account.
func sandboxRefuseView(w http.ResponseWriter, decision profileDecision) {
	writeSandboxReason(w, sandboxrelay.ReasonUnavailable, decision.Refused)
}

// sandboxScopeFloor is the floor of scope: its sandbox's registration floor
// (sandboxRegistrationFloor), or for a caller without one the floor of the
// profile it matches now.
func sandboxScopeFloor(cfg *config.Config, scope sandboxOwnScope) (config.OpenShellAdminConfig, string, error) {
	if scope.registered {
		return sandboxRegistrationFloor(cfg, scope.reg)
	}
	return sandboxFloorFor(cfg, scope.match.decision.Name)
}

// sandboxTextProfileWithheld is the explain description of a decision whose
// profiles are withheld (sandboxProfileWithheld).
const sandboxTextProfileWithheld = "More than one guardrail profile may apply until your identity is confirmed: the strictest " +
	"combination of them is enforced, which can be stricter than the policy shown here."

// sandboxProfileWithheld reports whether the caller's profile decision was
// taken on identity facts that are not proven (default_lookup_failed) and
// is not the default profile: its profile, or a member of its combination,
// may be another account's, so the caller's views name and show none of it.
func sandboxProfileWithheld(cfg *config.Config, profile, match string) bool {
	return cfg != nil && match == profileMatchDefaultLookupFailed && strings.TrimSpace(profile) != strings.TrimSpace(cfg.Guardrail.DefaultProfile)
}

// sandboxProfileLabel is how the caller's own views name profile, matched
// by match: profileUserLabel, and profileMeetLabel with no description when
// its details are withheld (sandboxProfileWithheld).
func sandboxProfileLabel(cfg *config.Config, profile, match string) (label, description string) {
	if sandboxProfileWithheld(cfg, profile, match) {
		return profileMeetLabel, ""
	}
	return profileUserLabel(profile), sandboxProfileDescription(cfg, profile)
}

// sandboxUserProfile is the name of reg's profile in its owner's views.
func sandboxUserProfile(cfg *config.Config, reg sandboxreg.Registration) string {
	label, _ := sandboxProfileLabel(cfg, reg.Profile, reg.ProfileMatch)
	return label
}

// sandboxOverlayKeys are the floor keys a profile's sandbox section sets
// (by their config names).
// A meet's are the keys any of its members' sections sets.
func sandboxOverlayKeys(cfg *config.Config, profile string) map[string]bool {
	keys := map[string]bool{}
	if cfg == nil || profile == "" {
		return keys
	}
	members := []string{profile}
	if meet, ok := config.ProfileMeetMembers(profile); ok {
		members = meet
	}
	for _, member := range members {
		p, ok := cfg.Guardrail.Profiles[member]
		if !ok || p.Sandbox == nil {
			continue
		}
		v := reflect.ValueOf(*p.Sandbox)
		t := v.Type()
		for i := range t.NumField() {
			name, _, _ := strings.Cut(t.Field(i).Tag.Get("mapstructure"), ",")
			if name != "" && !v.Field(i).IsZero() {
				keys[name] = true
			}
		}
	}
	return keys
}

// handleSandboxExplain answers POST policy/explain: the caller's own
// sandbox policy, never another account's.
func (a *APIServer) handleSandboxExplain(w http.ResponseWriter, r *http.Request) {
	r, peer, auth, ok := a.sandboxRouteStart(w, r)
	if !ok {
		return
	}
	var req sandboxrelay.ExplainRequest
	if !decodeSandboxJSON(w, r, sandboxExplainBodyMax, &req) {
		return
	}
	if req.V != sandboxrelay.WireVersion || (req.ProjectReal != "" && !sandboxCleanAbsPath(req.ProjectReal)) ||
		len(req.MCP) > sandboxMCPClaimsMax || !sandboxValidMCPClaims(req.MCP) {
		writeSandboxRefusal(w, http.StatusBadRequest, "invalid_request", sandboxTextBadRequest)
		return
	}
	scope, ok := a.sandboxScope(w, r, auth, peer, req.Registration, req.Connector)
	if !ok {
		return
	}
	cfg := a.liveBaseConfig(r.Context())
	profile := scope.match.decision.Name
	floor, _, err := sandboxScopeFloor(cfg, scope)
	if err != nil {
		writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
		return
	}
	label, description := profileUserLabel(profile), sandboxProfileDescription(cfg, profile)
	if sandboxProfileWithheld(cfg, profile, scope.match.decision.Match) {
		// The profiles that may apply include ones not proven to be the
		// caller's, possibly another account's: the floor enforced stays
		// theirs combined, but the caller is shown only the organization's
		// floor and its default profile's (privacy: users see only their own
		// effective policy).
		if floor, _, err = sandboxFloorFor(cfg, strings.TrimSpace(cfg.Guardrail.DefaultProfile)); err != nil {
			writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
			return
		}
		profile, label, description = strings.TrimSpace(cfg.Guardrail.DefaultProfile), profileMeetLabel, sandboxTextProfileWithheld
	}
	out := sandboxapi.ManagedExplain{
		Profile: label, Description: description,
		Match: scope.match.decision.Match, MatchedGroup: scope.match.decision.MatchedGroup,
		Provisional: scope.match.provisional, Allowed: floor.Allowed == nil || *floor.Allowed,
		RequiredFor: slices.Clone(floor.RequiredFor), WhenUnavailable: floor.WhenUnavailable,
		AllowedHarnesses: slices.Clone(floor.AllowedHarnesses), AllowedCredentials: slices.Clone(floor.AllowedCredentials),
		EgressAllowOnly: slices.Clone(floor.EgressAllowOnly), EgressBlock: slices.Clone(floor.EgressBlock),
		UserApprovals: floor.UserApprovals, AllowUnblock: floor.AllowUnblock == nil || *floor.AllowUnblock,
		// The action in force, stop when the floor leaves it unset (r103 GAP-0225).
		ForeignSandboxes: sandboxForeignAction(floor),
		WorkdirMode:      "copy", AllowMount: false, AllowHostPorts: floor.AllowHostPorts == nil || *floor.AllowHostPorts,
		AllowYolo: floor.AllowYolo == nil || *floor.AllowYolo, OnSilence: floor.OnSilence, MaxSilenceAfter: floor.MaxSilenceAfter,
		ProcessTree: floor.ProcessTree != nil && *floor.ProcessTree, DeleteStoppedAfter: floor.DeleteStoppedAfter,
		RequestAccess:  sandboxRequestAccess(floor),
		DriverFallback: sandboxDriverFallbackFor(cfg, runtime.GOOS, floor),
	}
	// Give the caller the same host-run gate the hook applies (GAP-0555).
	if len(floor.RequiredFor) > 0 {
		authorizer, _ := r.Context().Value(sandboxRouteAuthorizerKey{}).(*managedHookAuthorizer)
		exempt := authorizer != nil && authorizer.hostRunExempt(peer)
		out.HostRunGate = requireSandboxHostGate(true, exempt)
		out.EnrollmentExempt = out.HostRunGate == requireSandboxExempt
	}
	// The posture is the authoritative resolution of the explained run
	// under the caller's floor, its required pack and profile minimum
	// included: the daemon cannot read the administrator's packs, and its
	// own resolution left them out (GAP-0179, GAP-0438).
	var eff *packs.Effective
	var violations []packs.Violation
	tier := ""
	importMCP := true
	if scope.registered {
		out.PolicyDigest, out.UpdatedAt = scope.reg.EffectiveDigest, sandboxreg.PolicyUpdatedAt(scope.reg)
		out.Driver, out.DriverReason = scope.reg.Driver, scope.reg.DriverReason
		eff, violations, err = sandboxRegistrationEffective(cfg, auth, peer, scope.reg, floor)
		tier = scope.reg.TamperTier
		if err == nil {
			importMCP = eff.MCP.Import
		}
	} else {
		// The driver a sandbox would get now, by the gateway's view (the
		// daemon's own probe at sandbox start decides).
		if avail := sandboxHostAvailability(cfg, peer, floor); avail.Available {
			out.Driver, out.DriverReason = avail.Driver, avail.DriverReason
		}
		in := sandboxResolveInput{Req: sandboxrelay.ResolveRequest{V: sandboxrelay.WireVersion, Harness: scope.connector, Connector: scope.connector,
			ProjectReal: req.ProjectReal, RepoOverlay: req.RepoOverlay, UserPack: req.UserPack},
			Subject: sandboxSubject(peer), Profile: profile}
		if req.Flags != nil {
			in.Req.Flags = *req.Flags
		}
		in.Repo, err = sandboxExplainRepo(req.RepoOverlay)
		if err == nil {
			eff, violations, err = sandboxResolveEffective(cfg, floor, in)
		}
		if err == nil {
			out.PolicyDigest = sandboxEffectiveDigest(eff)
			out.Workspace = manager.WorkspacePolicyOf(eff)
			importMCP = eff.MCP.Import
		}
		if spec, ok := harness.Get(scope.connector); ok && strings.TrimSpace(req.Harness) != "" {
			// Only an explain of a named agent shows that agent's answer
			// to silent hooks (GAP-0477).
			tier = spec.TamperTier
		}
	}
	// The caller's own MCP servers, judged as a resolve judges them: the
	// MCP row of the caller's explain, and what a start brings along.
	if scope.registered && len(req.MCP) == 0 {
		out.MCPIncluded = slices.Clone(scope.reg.MCPKept)
		for _, s := range scope.reg.MCPSkipped {
			out.MCPBlocked = append(out.MCPBlocked, sandboxapi.ManagedMCP{Name: s.Name, Reason: s.Reason})
		}
	} else if len(req.MCP) > 0 {
		kept, skipped := sandboxRunMCPJudge(r.Context(), a, peer, scope.connector, req.MCP, importMCP)
		out.MCPIncluded = kept
		for _, s := range skipped {
			out.MCPBlocked = append(out.MCPBlocked, sandboxapi.ManagedMCP{Name: s.Name, Reason: s.Reason})
		}
	}
	if err == nil {
		out.Posture = manager.ManagedPostureOf(eff, violations, tier)
	} else if text, ok := sandboxInputProblem(err); ok {
		// The caller's own pack choice or repository file: they can fix it,
		// so say what it is rather than "can't be loaded" (GAP-0559).
		writeSandboxReason(w, sandboxrelay.ReasonNotAllowed, text)
		return
	} else {
		fmt.Fprintf(os.Stderr, "[sandbox-authority] explain uid=%d: %v\n", peer.UID, err)
	}
	if req.Sources {
		out.Sources = sandboxExplainSources(cfg, profile, floor)
	}
	a.writeJSON(w, http.StatusOK, out)
}

// sandboxExplainRepo parses a run's repository policy (nil without one). A
// repository policy that does not parse is the caller's own file: the error
// names the file and the key (packs.InputError).
func sandboxExplainRepo(overlay []byte) (*packs.RepoPolicy, error) {
	if len(overlay) == 0 {
		return nil, nil
	}
	problem := func(reason string) error {
		return &packs.InputError{Err: errors.New("The project's " + sandboxRepoPolicySrc + " is not valid: " + reason)}
	}
	if len(overlay) > sandboxrelay.MaxRepoOverlayBytes {
		return nil, problem("it is too large")
	}
	repo, err := packs.ParseRepoPolicy(overlay, sandboxRepoPolicySrc)
	if err != nil {
		var pe *packs.Error
		if errors.As(err, &pe) {
			reason := pe.Reason
			if pe.Field != "" {
				reason = pe.Field + ": " + reason
			}
			return nil, problem(reason)
		}
		return nil, problem(err.Error())
	}
	return repo, nil
}

// sandboxExplainKeys are the floor keys a managed explain's sources name.
var sandboxExplainKeys = []string{"allowed", "required_for", "when_unavailable", "allowed_harnesses", "allowed_credentials",
	"egress_allow_only", "egress_block", "user_approvals", "allow_unblock", "allow_mount", "allow_host_ports", "allow_yolo",
	"on_silence", "max_silence_after", "process_tree", "foreign_sandboxes", "delete_stopped_after", "request_access", "driver_fallback",
	"min_profile", "required_pack"}

// sandboxExplainSources says where each floor key of the caller's floor
// comes from: the caller's profile only where its sandbox section set the
// key and that changed the value the organization's base gives everyone; a
// profile value the base clamps (allow_yolo: true under a base false), or
// one equal to it, is the organization's (GAP-0518). allow_mount and the
// copy-only workdir_mode are the organization's on every managed computer
// (SPEC D2).
func sandboxExplainSources(cfg *config.Config, profile string, floor config.OpenShellAdminConfig) map[string]string {
	overlay := sandboxOverlayKeys(cfg, profile)
	base := config.OpenShellAdminConfig{}
	if cfg != nil {
		base = cfg.OpenShell.Admin
	}
	baseFields, floorFields := sandboxAdminFields(base), sandboxAdminFields(floor)
	out := map[string]string{"workdir_mode": sandboxapi.ExplainSourceOrganization}
	for _, key := range sandboxExplainKeys {
		out[key] = sandboxapi.ExplainSourceOrganization
		if key == "allow_mount" {
			continue
		}
		if overlay[key] && !reflect.DeepEqual(baseFields[key], floorFields[key]) {
			out[key] = sandboxapi.ExplainSourceProfile
		}
	}
	return out
}

// sandboxAdminFields are f's fields by their configuration key.
func sandboxAdminFields(f config.OpenShellAdminConfig) map[string]any {
	v := reflect.ValueOf(f)
	t := v.Type()
	out := make(map[string]any, t.NumField())
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("mapstructure"), ",")
		if name == "" {
			continue
		}
		field := v.Field(i)
		if field.Kind() == reflect.Pointer {
			if field.IsNil() {
				out[name] = nil
				continue
			}
			field = field.Elem()
		}
		out[name] = field.Interface()
	}
	return out
}

// handleSandboxPolicyTest answers POST policy/test for the caller's
// registered sandbox (RegistrationHeader): each destination judged by its
// effective egress policy.
func (a *APIServer) handleSandboxPolicyTest(w http.ResponseWriter, r *http.Request) {
	r, peer, auth, ok := a.sandboxRouteStart(w, r)
	if !ok {
		return
	}
	var req sandboxrelay.PolicyTestRequest
	if !decodeSandboxJSON(w, r, apiRequestBodyMaxBytes, &req) {
		return
	}
	if req.V != sandboxrelay.WireVersion || len(req.Checks) == 0 || len(req.Checks) > sandboxapi.MaxPolicyChecks ||
		(req.ProjectReal != "" && !sandboxCleanAbsPath(req.ProjectReal)) {
		writeSandboxRefusal(w, http.StatusBadRequest, "invalid_request", sandboxTextBadRequest)
		return
	}
	for _, c := range req.Checks {
		if c.Port < 0 || c.Port > 65535 || c.Host == "" || len(c.Host) > 253 {
			writeSandboxRefusal(w, http.StatusBadRequest, "invalid_request", sandboxTextBadRequest)
			return
		}
	}
	scope, ok := a.sandboxScope(w, r, auth, peer, r.Header.Get(sandboxrelay.RegistrationHeader), r.Header.Get(sandboxrelay.ConnectorHeader))
	if !ok {
		return
	}
	cfg := a.liveBaseConfig(r.Context())
	floor, _, err := sandboxScopeFloor(cfg, scope)
	if err != nil {
		writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
		return
	}
	var eff *packs.Effective
	if scope.registered {
		eff, _, err = sandboxRegistrationEffective(cfg, auth, peer, scope.reg, floor)
	} else {
		// A new run's own policy, as policy/resolve would resolve it
		// (GAP-0438): no sandbox, so no unblock or host port applies.
		in := sandboxResolveInput{Req: sandboxrelay.ResolveRequest{V: sandboxrelay.WireVersion, Harness: scope.connector, Connector: scope.connector,
			ProjectReal: req.ProjectReal, RepoOverlay: req.RepoOverlay}, Subject: sandboxSubject(peer), Profile: scope.match.decision.Name}
		if in.Repo, err = sandboxExplainRepo(req.RepoOverlay); err == nil {
			eff, _, err = sandboxResolveEffective(cfg, floor, in)
		}
	}
	if err != nil {
		if text, ok := sandboxInputProblem(err); ok {
			writeSandboxReason(w, sandboxrelay.ReasonNotAllowed, text)
			return
		}
		fmt.Fprintf(os.Stderr, "[sandbox-authority] policy test uid=%d: %v\n", peer.UID, err)
		writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
		return
	}
	decider, err := eff.EgressDecider(nil)
	if err != nil {
		writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
		return
	}
	out := sandboxapi.PolicyTestResult{Sandbox: scope.reg.SandboxName, Profile: eff.Profile, NetworkMode: eff.NetworkMode}
	if eff.Pack != nil {
		out.Pack = eff.Pack.Name
	}
	for _, c := range req.Checks {
		chk := eff.CheckEgress(decider, egress.Principal{}, c.Host, c.Port)
		out.Decisions = append(out.Decisions, sandboxapi.PolicyDecision{
			PolicyCheck: c, Allowed: chk.Allowed, Rule: string(chk.Rule), Match: chk.Match, Source: chk.Source,
			Reason: chk.Reason, Unblockable: chk.Unblockable,
		})
	}
	a.writeJSON(w, http.StatusOK, out)
}

// handleSandboxPacks answers GET policy/packs and policy/packs/{name}:
// only the packs of the caller's own effective chain.
func (a *APIServer) handleSandboxPacks(w http.ResponseWriter, r *http.Request) {
	r, peer, auth, ok := a.sandboxRouteStart(w, r)
	if !ok {
		return
	}
	scope, ok := a.sandboxScope(w, r, auth, peer, r.Header.Get(sandboxrelay.RegistrationHeader), r.Header.Get(sandboxrelay.ConnectorHeader))
	if !ok {
		return
	}
	cfg := a.liveBaseConfig(r.Context())
	floor, _, err := sandboxScopeFloor(cfg, scope)
	if err != nil {
		writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
		return
	}
	reg := scope.reg
	if !scope.registered {
		reg = sandboxreg.Registration{Harness: scope.connector, Connector: scope.connector}
	}
	eff, _, err := sandboxRegistrationEffective(cfg, auth, peer, reg, floor)
	if err != nil || eff.Pack == nil {
		writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
		return
	}
	views := sandboxPackViews(eff.Pack)
	name := r.PathValue("name")
	if name == "" {
		a.writeJSON(w, http.StatusOK, views)
		return
	}
	for _, view := range views {
		if view.Name != name {
			continue
		}
		if name == eff.Pack.Name {
			if raw, err := eff.Pack.Marshal(); err == nil {
				view.Content = string(raw)
			}
		}
		a.writeJSON(w, http.StatusOK, view)
		return
	}
	// A pack outside the caller's chain is not named, existing or not.
	writeSandboxRefusal(w, http.StatusNotFound, "pack_unknown", "No pack of that name is part of your sandbox policy.")
}

// sandboxPackViews lists a pack and its extends chain without host paths.
func sandboxPackViews(p *packs.Pack) []sandboxrelay.PackView {
	source := func(builtin bool) string {
		if builtin {
			return "builtin"
		}
		return "organization"
	}
	views := []sandboxrelay.PackView{{Name: p.Name, Source: source(p.Builtin), Digest: p.Digest, Description: p.Description, Extends: p.Extends}}
	for _, link := range p.Chain {
		if link.Name == p.Name {
			continue
		}
		views = append(views, sandboxrelay.PackView{Name: link.Name, Source: source(link.Builtin), Digest: link.Digest})
	}
	return views
}

// sandboxDecisionStored says whether the gateway keeps a decision: a user
// block, an unblock, or an "always" answer. A session-only allow lives in
// the daemon.
func sandboxDecisionStored(d sandboxrelay.DecisionRequest) bool {
	return d.Kind == sandboxrelay.DecisionEgressBlock || d.Kind == sandboxrelay.DecisionUnblock || d.Scope == sandboxrelay.DecisionScopeAlways
}

func sandboxDecisionView(d sandboxreg.Decision) sandboxrelay.Decision {
	return sandboxrelay.Decision{ID: d.ID, Registration: d.Registration, Kind: d.Kind, Host: d.Host, Scope: d.Scope, CreatedAt: d.CreatedAt}
}

// sandboxDecisionCheck is the §6.2 truth table (sandboxreg.CheckDecision);
// tests replace it.
var sandboxDecisionCheck = sandboxreg.CheckDecision

// sandboxCheckDecision re-checks d against floor; a user block always
// passes (it only tightens).
func sandboxCheckDecision(floor config.OpenShellAdminConfig, d sandboxrelay.DecisionRequest) error {
	if d.Kind == sandboxrelay.DecisionEgressBlock {
		return nil
	}
	return sandboxDecisionCheck(floor, d)
}

// handleSandboxDecide answers POST decisions: an ask answer, an unblock or
// a user block of the caller's live sandbox, re-checked against the
// caller's floor (a direct call past it is refused) and recorded with the
// person who made it.
func (a *APIServer) handleSandboxDecide(w http.ResponseWriter, r *http.Request) {
	r, peer, auth, ok := a.sandboxRouteStart(w, r)
	if !ok {
		return
	}
	var req sandboxrelay.DecisionRequest
	if !decodeSandboxJSON(w, r, sandboxSmallBodyMax, &req) {
		return
	}
	req.Host = strings.TrimSpace(req.Host)
	shape := sandboxreg.Decision{Registration: req.Registration, Kind: req.Kind, Host: req.Host, Scope: req.Scope}
	if req.V != sandboxrelay.WireVersion || sandboxreg.ValidDecision(shape) != nil || len(req.ApprovalID) > 128 ||
		(req.ApprovalID != "" && !audit.ValidApprovalID(req.ApprovalID)) || req.Port < 0 || req.Port > 65535 {
		writeSandboxRefusal(w, http.StatusBadRequest, "invalid_request", sandboxTextBadRequest)
		return
	}
	reg, ok := a.sandboxRegistrationFor(w, auth, peer, req.Registration, false, false)
	if !ok || !a.sandboxDecide(w, r, peer, reg.Connector) || !a.sandboxCheckSubject(w, auth, peer, reg) {
		return
	}
	reg = a.sandboxRematchIfDue(r.Context(), auth, peer, reg)
	if reg.State == sandboxreg.StateRevoked {
		writeSandboxReason(w, sandboxrelay.ReasonRegistrationRevoked, sandboxTextRegistrationGone)
		return
	}
	if match := a.sandboxMatchPeer(r.Context(), peer, reg.Connector, 0); match.decision.Refused != "" {
		// The floor a decision is checked against is the person's own:
		// none is proven while a fact an assignment needs is not.
		sandboxRefuseView(w, match.decision)
		return
	}
	if !sandboxDecisionStored(req) && !sandboxAdmitsCalls(w, auth, reg) {
		// A session-only answer is for the sandbox while it runs; a stopped
		// one has nothing to apply it to (GAP-0574). A saved decision is
		// kept for its next start.
		return
	}
	cfg := a.liveBaseConfig(r.Context())
	floor, _, err := sandboxRegistrationFloor(cfg, reg)
	if err != nil {
		writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
		return
	}
	if err := sandboxCheckDecision(floor, req); err != nil {
		var refused *sandboxreg.DecisionRefusedError
		if errors.As(err, &refused) {
			// The managed refusal's one shape: the check's reason as a
			// sentence, then the contact and the Quote line; the bare join
			// ran the blocklist reason into "To ask for access" (GAP-0504).
			// The refusal is a decision too: the floor, not the person, decided
			// (GAP-0632).
			sandboxRecordAskDecided(r.Context(), a, reg, req, sandboxAskOutcome{Refused: true})
			writeSandboxRefusal(w, http.StatusForbidden, sandboxrelay.ReasonDecisionRefused,
				sandboxapi.AccessRefusedWhy(refused.Message, refused.Rule, req.Host, sandboxUserProfile(cfg, reg), reg.SandboxName, floor.RequestAccess))
			return
		}
		fmt.Fprintf(os.Stderr, "[sandbox-authority] decision check uid=%d: %v\n", peer.UID, err)
		writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
		return
	}
	shape.CreatedAt = auth.clock()
	shape.Actor = sandboxreg.DecisionActor{UID: peer.UID, PrincipalHash: sandboxPrincipalHash(auth.key, sandboxPeerPrincipal(r.Context()))}
	result := sandboxrelay.DecisionResult{V: sandboxrelay.WireVersion, Decision: sandboxDecisionView(shape)}
	if sandboxDecisionStored(req) {
		if err := auth.decisions.Add(peer.UID, shape); err != nil {
			fmt.Fprintf(os.Stderr, "[sandbox-authority] decision store uid=%d: %v\n", peer.UID, err)
			writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
			return
		}
		saved, _ := auth.decisions.List(peer.UID, reg.ID)
		for _, d := range saved {
			if d.Kind == shape.Kind && d.Scope == shape.Scope && strings.EqualFold(d.Host, shape.Host) {
				result.Decision = sandboxDecisionView(d)
			}
		}
		result.Stored = true
	}
	// Every taken decision is recorded, kept or not: a session allow is the
	// one a fleet cannot otherwise trace (GAP-0632).
	sandboxRecordAskDecided(r.Context(), a, reg, req, sandboxAskOutcome{Stored: result.Stored})
	a.writeJSON(w, http.StatusOK, result)
}

// sandboxPeerPrincipal is the verified principal of the request, if the
// directory gave one.
func sandboxPeerPrincipal(ctx context.Context) string {
	subject, ok := verifiedSubjectFromContext(ctx)
	if !ok {
		return ""
	}
	if subject.Directory.Principal != "" {
		return subject.Directory.Principal
	}
	return subject.Directory.UPN
}

// handleSandboxDecisions answers GET decisions?registration=ID: the
// caller's saved decisions that apply to the registration (its own and
// the caller's "always" ones), capped by the caller's floor now.
func (a *APIServer) handleSandboxDecisions(w http.ResponseWriter, r *http.Request) {
	r, peer, auth, ok := a.sandboxRouteStart(w, r)
	if !ok {
		return
	}
	reg, ok := a.sandboxRegistrationFor(w, auth, peer, r.URL.Query().Get(sandboxrelay.RegistrationQuery), true, false)
	if !ok || !a.sandboxDecide(w, r, peer, reg.Connector) || !a.sandboxCheckSubject(w, auth, peer, reg) {
		return
	}
	cfg := a.liveBaseConfig(r.Context())
	floor, _, err := sandboxRegistrationFloor(cfg, reg)
	if err != nil {
		writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
		return
	}
	saved, err := auth.decisions.List(peer.UID, "")
	if err != nil {
		writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
		return
	}
	out := []sandboxrelay.Decision{}
	for _, d := range saved {
		if d.Registration != reg.ID && d.Scope != sandboxrelay.DecisionScopeAlways {
			continue
		}
		req := sandboxrelay.DecisionRequest{V: sandboxrelay.WireVersion, Registration: reg.ID, Kind: d.Kind, Host: d.Host, Scope: d.Scope}
		if sandboxCheckDecision(floor, req) != nil {
			continue
		}
		out = append(out, sandboxDecisionView(d))
	}
	a.writeJSON(w, http.StatusOK, out)
}

// sandboxEmitEvent records one daemon-side event of peer's sandbox, with
// the identity the gateway verified (emitSandboxDaemonEvent); tests replace
// it.
var sandboxEmitEvent = func(ctx context.Context, a *APIServer, peer managedHookPeer, reg sandboxreg.Registration, ev sandboxrelay.Event) {
	if !sandboxrelay.EventTelemetry(ev.Kind) {
		// The lifecycle and egress records come by the hundred; their own
		// records are the trail.
		fmt.Fprintf(os.Stderr, "[sandbox-authority] event uid=%d registration=%s kind=%s\n", peer.UID, reg.ID, ev.Kind)
	}
	emitSandboxDaemonEvent(ctx, a, reg, ev)
}

// handleSandboxEvents answers POST events: a batch of the caller's
// daemon-side records, stamped with the caller's verified identity. A batch
// names one of the caller's registrations, or none when it holds only
// foreign sandbox and container records and refused runs
// (sandboxrelay.EventWithoutRegistration):
// those are then stamped with the verified peer alone, once the peer's
// account is known and the authorizer allows it a sandbox harness.
func (a *APIServer) handleSandboxEvents(w http.ResponseWriter, r *http.Request) {
	r, peer, auth, ok := a.sandboxRouteStart(w, r)
	if !ok {
		return
	}
	var batch sandboxrelay.EventBatch
	if !decodeSandboxJSON(w, r, sandboxrelay.MaxEventBatchBytes, &batch) {
		return
	}
	if batch.V != sandboxrelay.WireVersion || len(batch.Events) == 0 || len(batch.Events) > sandboxrelay.MaxEventBatchRecords {
		writeSandboxRefusal(w, http.StatusBadRequest, "invalid_request", sandboxTextBadRequest)
		return
	}
	telemetry, rows := 0, 0
	unreadable := make([]bool, len(batch.Events))
	for i, ev := range batch.Events {
		switch ev.Kind {
		case sandboxrelay.EventForeignSandbox, sandboxrelay.EventForeignRule, sandboxrelay.EventForeignContainer,
			sandboxrelay.EventSettingsDrift, sandboxrelay.EventAccessRefused, sandboxrelay.EventAccountBusy,
			sandboxrelay.EventSandboxLifecycle, sandboxrelay.EventSandboxEgress:
		default:
			writeSandboxRefusal(w, http.StatusBadRequest, "invalid_request", sandboxTextBadRequest)
			return
		}
		// Every payload string is the daemon's claim, so control characters
		// (ESC, NUL, C1, bidi and zero-width marks) never reach the managed
		// audit (sandboxClaimPayload). A payload two of whose keys are one
		// once cleaned refuses the batch; one that is not JSON is dropped.
		isTelemetry := sandboxrelay.EventTelemetry(ev.Kind)
		if isTelemetry {
			telemetry++
		}
		payload, err := sandboxClaimPayload(ev.Payload)
		switch {
		case errors.Is(err, errSandboxClaimKeyCollision):
			writeSandboxRefusal(w, http.StatusBadRequest, "invalid_request", sandboxTextBadRequest)
			return
		case err != nil:
			unreadable[i] = true
			continue
		}
		batch.Events[i].Payload = payload
		if !isTelemetry {
			rows += sandboxEventRows(batch.Events[i])
		}
	}
	if telemetry > 0 && len(batch.Events) > sandboxrelay.MaxTelemetryBatchRecords || rows > sandboxEventRecordBurst {
		writeSandboxRefusal(w, http.StatusBadRequest, "invalid_request", sandboxTextBadRequest)
		return
	}
	var reg sandboxreg.Registration
	if strings.TrimSpace(batch.Registration) == "" {
		if len(batch.Events) > sandboxrelay.MaxUnregisteredEventRecords {
			writeSandboxRefusal(w, http.StatusBadRequest, "invalid_request", sandboxTextBadRequest)
			return
		}
		for _, ev := range batch.Events {
			if !sandboxrelay.EventWithoutRegistration(ev.Kind) {
				writeSandboxRefusal(w, http.StatusBadRequest, "invalid_request", sandboxTextBadRequest)
				return
			}
		}
		accountName := sandboxStandInName(peer)
		if accountName == "" {
			writeSandboxReason(w, sandboxrelay.ReasonUnavailable, sandboxTextAccountUnknown)
			return
		}
		if !a.sandboxDecideAny(w, r, peer) {
			return
		}
		reg = sandboxreg.Registration{UID: peer.UID, UserName: accountName,
			SubjectKey: sandboxSubjectKey(auth.key, peer.UID, accountName, "")}
	} else {
		// A batch of only lifecycle and egress records may name a revoked
		// registration: the daemon reports a sandbox deleted right after
		// recording its deleting and deleted phases, and a sandbox the
		// gateway revoked (a changed policy) is then stopped and deleted by
		// its daemon. Those records still describe the caller's own sandbox
		// (GAP-0003); sandboxTelemetryAdmit bounds what such a tombstone
		// takes.
		telemetryOnly := telemetry == len(batch.Events)
		var ok bool
		reg, ok = a.sandboxRegistrationFor(w, auth, peer, batch.Registration, true, telemetryOnly)
		if !ok || !a.sandboxDecide(w, r, peer, reg.Connector) || !a.sandboxCheckSubject(w, auth, peer, reg) {
			return
		}
		if telemetry > 0 && !sandboxTelemetryAdmit(w, auth, peer, reg, telemetry) {
			return
		}
	}
	// The records of the other events, by the record (sandboxEventRows).
	if rows > 0 && !sandboxBudgetAdmit(w, &auth.eventRecords, peer, rows, auth.clock()) {
		return
	}
	now := auth.clock()
	if auth.eventReplay.duplicate(peer.UID, batch, now) {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	refused, lifecycle := 0, false
	for i, ev := range batch.Events {
		if unreadable[i] {
			sandboxRecordFailed(ev.Kind, fmt.Errorf("payload is not the event's JSON"))
			continue
		}
		if ev.Time.IsZero() || ev.Time.After(now.Add(time.Minute)) {
			ev.Time = now
		}
		if sandboxrelay.EventTelemetry(ev.Kind) && !sandboxTelemetryRecordAllowed(reg, ev) {
			refused++
			continue
		}
		sandboxEmitEvent(r.Context(), a, peer, reg, ev)
		lifecycle = lifecycle || ev.Kind == sandboxrelay.EventSandboxLifecycle
		if ev.Kind == sandboxrelay.EventForeignSandbox {
			a.sandboxRevokeForeign(auth, peer, ev)
		}
	}
	if lifecycle && reg.State != sandboxreg.StateRevoked {
		a.sandboxForgetIfGone(auth, peer.UID, reg)
	}
	if refused > 0 {
		fmt.Fprintf(os.Stderr, "[sandbox-authority] refused %d sandbox telemetry record(s) uid=%d registration=%s state=%s\n",
			refused, peer.UID, reg.ID, reg.State)
	}
	w.WriteHeader(http.StatusAccepted)
}

// sandboxRevokeForeign revokes the caller's registrations bound to the
// sandbox a foreign_sandbox record names. The caller's daemon found that
// sandbox on their OpenShell gateway made for none of its registrations, so
// a registration naming it was never bound by that daemon, and the sandbox's
// stop or delete must not leave it live (GAP-0529).
func (a *APIServer) sandboxRevokeForeign(auth *sandboxAuthority, peer managedHookPeer, ev sandboxrelay.Event) {
	var p sandboxEventPayload
	if len(ev.Payload) == 0 || json.Unmarshal(ev.Payload, &p) != nil {
		return
	}
	revoked, err := auth.store.RevokeSandbox(peer.UID, strings.TrimSpace(p.SandboxID), strings.TrimSpace(p.Sandbox), sandboxreg.ReasonForeign)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sandbox-authority] revoke the registrations of a foreign sandbox uid=%d: %v\n", peer.UID, err)
		return
	}
	for _, reg := range revoked {
		fmt.Fprintf(os.Stderr, "[sandbox-authority] revoked uid=%d registration=%s reason=%s\n", peer.UID, reg.ID, sandboxreg.ReasonForeign)
	}
}
