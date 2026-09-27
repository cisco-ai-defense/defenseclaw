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

package sandboxauth

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

var (
	// ErrUnauthenticated is returned when a presented credential does not
	// belong to a live binding. Callers answer 401 and must not say why.
	ErrUnauthenticated = errors.New("sandboxauth: unknown or revoked sandbox credential")
	// ErrNotFound is returned for an unknown binding ID.
	ErrNotFound = errors.New("sandboxauth: binding not found")
	// ErrExists is returned when a sandbox already has a binding. Rotate it
	// instead of minting a second credential for the same sandbox.
	ErrExists = errors.New("sandboxauth: sandbox already has a binding")
	// ErrInvalidSpec wraps every binding validation failure.
	ErrInvalidSpec = errors.New("sandboxauth: invalid binding")
	// ErrRouteNotAllowed is returned when a binding may not use a route.
	ErrRouteNotAllowed = errors.New("sandboxauth: route not allowed for this sandbox")
	// ErrConnectorMismatch is returned when a request names a connector
	// other than the one the binding was minted for.
	ErrConnectorMismatch = errors.New("sandboxauth: request connector does not match the sandbox binding")
	// ErrUnsupportedPlatform is returned where the binding store cannot run.
	ErrUnsupportedPlatform = errors.New("sandboxauth: sandbox bindings are not supported on this platform")
)

const (
	// SandboxGOOS is the operating system every OpenShell sandbox runs,
	// whatever the host is. Hook contracts for a sandboxed harness resolve
	// for it.
	SandboxGOOS = "linux"
	// SandboxHome is the agent's HOME inside every OpenShell sandbox. A "~"
	// in a sandboxed tool call means this directory, never the host user's
	// home.
	SandboxHome = "/sandbox"
)

// WorkdirMode says how the project reached the sandbox.
type WorkdirMode string

const (
	// WorkdirMount is a live bind mount of the host project folder.
	WorkdirMount WorkdirMode = "mount"
	// WorkdirCopy is a sanitized copy uploaded into the sandbox. Paths in
	// copy-mode hook payloads have no host counterpart.
	WorkdirCopy WorkdirMode = "copy"
)

// Route is a class of ingress endpoint a binding may call. The gateway maps
// concrete HTTP paths onto these classes; the binding only ever names the
// class plus its single connector.
type Route string

const (
	// RouteHook is the connector's harness hook endpoint.
	RouteHook Route = "hook"
	// RouteNotify is the connector's fire-and-forget notify endpoint
	// (Codex agent-turn-complete).
	RouteNotify Route = "notify"
	// RouteInspect is the shared /api/v1/inspect/* surface, admitted only
	// when the request names the binding's own connector.
	RouteInspect Route = "inspect"
	// RouteOTLP is OTLP-HTTP logs/metrics/traces ingest, admitted only when
	// the declared telemetry source is the binding's own connector.
	RouteOTLP Route = "otlp"
)

// KnownRoutes lists every route class in a stable order.
func KnownRoutes() []Route {
	return []Route{RouteHook, RouteNotify, RouteInspect, RouteOTLP}
}

func (r Route) valid() bool {
	return slices.Contains(KnownRoutes(), r)
}

// Mount maps one sandbox path onto the host path bind-mounted there.
type Mount struct {
	// SandboxPath is the absolute POSIX path inside the sandbox, e.g.
	// /work/myapp.
	SandboxPath string `json:"sandbox_path"`
	// HostPath is the absolute host path mounted at SandboxPath.
	HostPath string `json:"host_path"`
	// ReadOnly records how the path was mounted. FSView reads either kind.
	ReadOnly bool `json:"read_only,omitempty"`
}

// Workdir describes the project view the sandbox received.
type Workdir struct {
	Mode WorkdirMode `json:"mode"`
	// Mounts is required in mount mode. Copy mode may record read-only
	// context mounts, but FSView still grants no host access in copy mode.
	Mounts []Mount `json:"mounts,omitempty"`
	// Masks are sandbox paths that the sandbox sees as empty files (secret
	// files hidden behind an empty read-only bind). FSView refuses them, and
	// any host path that resolves to them, so the gateway never reads a
	// secret the agent was not shown.
	Masks []string `json:"masks,omitempty"`
}

// HostUser is the host account that launched the sandbox. Hook telemetry
// from the sandbox is attributed to this user and never to identity
// headers the sandbox supplies.
type HostUser struct {
	// UID is the POSIX uid, decimal.
	UID string `json:"uid,omitempty"`
	// Name is the bare account name.
	Name string `json:"name,omitempty"`
}

// RateLimit overrides the Limiter defaults for one binding. Zero fields keep
// the default.
type RateLimit struct {
	// RequestsPerSecond is the sustained hook/notify/inspect rate.
	RequestsPerSecond float64 `json:"rps,omitempty"`
	// Burst is the hook/notify/inspect bucket size.
	Burst int `json:"burst,omitempty"`
	// MaxInFlight caps concurrent hook, notify and inspect requests. OTLP
	// uploads have their own, smaller cap (LimiterConfig.OTLPMaxInFlight).
	MaxInFlight int `json:"max_in_flight,omitempty"`
}

// Spec is the caller-owned description of a sandbox binding. The store adds
// the identity, credential hash and timestamps.
type Spec struct {
	// SandboxID is the OpenShell sandbox id. It may be empty at mint time and
	// filled in with FileStore.Update once the sandbox exists.
	SandboxID string
	// SandboxName is the OpenShell sandbox name; unique per store.
	SandboxName string
	// Connector is the one DefenseClaw connector (claudecode, codex, ...)
	// whose routes the sandbox may call.
	Connector string
	// AgentVersion is the harness version installed in the sandbox image.
	AgentVersion string
	// HookContractID is the reviewed hook contract the image was built for.
	// Hook handlers resolve the connector profile from it instead of the
	// host's contract lock or agent-version cache.
	HookContractID string
	// PolicyProfile is the OpenShell policy profile (open, balanced, strict).
	PolicyProfile string
	// Routes are the route classes the sandbox may call. Empty selects
	// hook and OTLP, plus notify for codex.
	Routes    []Route
	Workdir   Workdir
	HostUser  HostUser
	RateLimit RateLimit
	// TTL bounds the credential lifetime. Zero means no expiry; the
	// manager revokes on delete and rotates on start.
	TTL time.Duration
}

// Binding is one sandbox's ingress authorization. It never contains the
// credential itself.
type Binding struct {
	ID             string    `json:"id"`
	SandboxID      string    `json:"sandbox_id,omitempty"`
	SandboxName    string    `json:"sandbox_name"`
	Connector      string    `json:"connector"`
	AgentVersion   string    `json:"agent_version,omitempty"`
	HookContractID string    `json:"hook_contract_id,omitempty"`
	PolicyProfile  string    `json:"policy_profile,omitempty"`
	Routes         []Route   `json:"routes"`
	Workdir        Workdir   `json:"workdir"`
	HostUser       HostUser  `json:"host_user,omitzero"`
	RateLimit      RateLimit `json:"rate_limit,omitzero"`
	TokenHash      string    `json:"token_sha256"`
	Generation     uint64    `json:"generation"`
	CreatedAt      time.Time `json:"created_at"`
	RotatedAt      time.Time `json:"rotated_at"`
	ExpiresAt      time.Time `json:"expires_at,omitzero"`
	// TTLSeconds is the credential lifetime re-applied on every rotation.
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
}

// Spec returns the caller-owned fields of b, so an Update round trip keeps
// everything the caller did not change.
func (b Binding) Spec() Spec {
	return Spec{
		SandboxID:      b.SandboxID,
		SandboxName:    b.SandboxName,
		Connector:      b.Connector,
		AgentVersion:   b.AgentVersion,
		HookContractID: b.HookContractID,
		PolicyProfile:  b.PolicyProfile,
		Routes:         slices.Clone(b.Routes),
		Workdir:        b.Workdir.clone(),
		HostUser:       b.HostUser,
		RateLimit:      b.RateLimit,
		TTL:            time.Duration(b.TTLSeconds) * time.Second,
	}
}

// Allows reports whether the binding lists route.
func (b Binding) Allows(route Route) bool {
	return slices.Contains(b.Routes, route)
}

// Authorize admits route on behalf of connectorName only when the binding
// lists the route and connectorName is the binding's own connector.
func (b Binding) Authorize(route Route, connectorName string) error {
	if !b.Allows(route) {
		return ErrRouteNotAllowed
	}
	if CanonicalConnector(connectorName) != b.Connector {
		return ErrConnectorMismatch
	}
	return nil
}

// Expired reports whether the credential lifetime has ended at now.
func (b Binding) Expired(now time.Time) bool {
	return !b.ExpiresAt.IsZero() && !now.Before(b.ExpiresAt)
}

func (w Workdir) clone() Workdir {
	return Workdir{Mode: w.Mode, Mounts: slices.Clone(w.Mounts), Masks: slices.Clone(w.Masks)}
}

// CanonicalConnector lowercases a connector name and folds the aliases the
// gateway accepts for Claude Code and Gemini CLI.
func CanonicalConnector(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "claude", "claude-code", "claude_code":
		return "claudecode"
	case "gemini", "gemini-cli", "gemini_cli":
		return "geminicli"
	default:
		return name
	}
}

// DefaultRoutes is the route set a connector needs when the caller does not
// choose one: its hook endpoint and native OTLP, plus the notify bridge for
// Codex. Inspect is opt-in because only the shared inspect scripts use it.
func DefaultRoutes(connectorName string) []Route {
	routes := []Route{RouteHook, RouteOTLP}
	if CanonicalConnector(connectorName) == "codex" {
		routes = append(routes, RouteNotify)
	}
	return sortedRoutes(routes)
}

const (
	maxPathLength    = 4096
	maxMounts        = 64
	maxMasks         = 256
	maxRPS           = 1000
	maxBurst         = 10000
	maxInFlightLimit = 1024
)

var (
	connectorPattern   = regexp.MustCompile(`^[a-z][a-z0-9]{0,31}$`)
	sandboxNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	sandboxIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	contractIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	uidPattern         = regexp.MustCompile(`^[0-9]{1,10}$`)
	userNamePattern    = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$`)
	bindingIDPattern   = regexp.MustCompile(`^sb_[0-9a-f]{32}$`)
)

// normalize validates s and returns its canonical form: connector folded,
// routes deduplicated and sorted, paths cleaned. It never touches the
// filesystem; mount-source policy belongs to the workspace layer that
// created the mounts.
func (s Spec) normalize() (Spec, error) {
	s.Connector = CanonicalConnector(s.Connector)
	if !connectorPattern.MatchString(s.Connector) {
		return Spec{}, invalid("connector %q is not a connector name", s.Connector)
	}
	s.SandboxName = strings.TrimSpace(s.SandboxName)
	if !sandboxNamePattern.MatchString(s.SandboxName) {
		return Spec{}, invalid("sandbox name %q is not a valid OpenShell name", s.SandboxName)
	}
	s.SandboxID = strings.TrimSpace(s.SandboxID)
	if s.SandboxID != "" && !sandboxIDPattern.MatchString(s.SandboxID) {
		return Spec{}, invalid("sandbox id is malformed")
	}
	s.AgentVersion = strings.TrimSpace(s.AgentVersion)
	if len(s.AgentVersion) > 128 || !printableASCII(s.AgentVersion) {
		return Spec{}, invalid("agent version is malformed")
	}
	s.HookContractID = strings.TrimSpace(s.HookContractID)
	if s.HookContractID != "" && !contractIDPattern.MatchString(s.HookContractID) {
		return Spec{}, invalid("hook contract id %q is malformed", s.HookContractID)
	}
	s.PolicyProfile = strings.ToLower(strings.TrimSpace(s.PolicyProfile))
	switch s.PolicyProfile {
	case "", "open", "balanced", "strict":
	default:
		return Spec{}, invalid("policy profile %q is not open, balanced or strict", s.PolicyProfile)
	}
	if len(s.Routes) == 0 {
		s.Routes = DefaultRoutes(s.Connector)
	}
	for _, route := range s.Routes {
		if !route.valid() {
			return Spec{}, invalid("unknown route %q", route)
		}
	}
	s.Routes = sortedRoutes(s.Routes)
	workdir, err := s.Workdir.normalize()
	if err != nil {
		return Spec{}, err
	}
	s.Workdir = workdir
	s.HostUser.UID = strings.TrimSpace(s.HostUser.UID)
	if s.HostUser.UID != "" && !uidPattern.MatchString(s.HostUser.UID) {
		return Spec{}, invalid("host uid must be a decimal POSIX uid")
	}
	s.HostUser.Name = strings.TrimSpace(s.HostUser.Name)
	if s.HostUser.Name != "" && !userNamePattern.MatchString(s.HostUser.Name) {
		return Spec{}, invalid("host user name is malformed")
	}
	if err := s.RateLimit.validate(); err != nil {
		return Spec{}, err
	}
	if s.TTL < 0 || (s.TTL > 0 && s.TTL < time.Second) {
		return Spec{}, invalid("ttl must be zero or at least one second")
	}
	s.TTL = s.TTL.Truncate(time.Second)
	return s, nil
}

func (w Workdir) normalize() (Workdir, error) {
	switch w.Mode {
	case WorkdirMount, WorkdirCopy:
	default:
		return Workdir{}, invalid("workdir mode %q is not mount or copy", w.Mode)
	}
	if w.Mode == WorkdirMount && len(w.Mounts) == 0 {
		return Workdir{}, invalid("mount mode needs at least one mount")
	}
	if len(w.Mounts) > maxMounts {
		return Workdir{}, invalid("too many mounts")
	}
	if len(w.Masks) > maxMasks {
		return Workdir{}, invalid("too many masks")
	}
	out := Workdir{Mode: w.Mode}
	seen := make(map[string]bool, len(w.Mounts))
	for _, m := range w.Mounts {
		sandboxPath, ok := cleanSandboxPath(m.SandboxPath)
		if !ok || sandboxPath == "/" {
			return Workdir{}, invalid("mount sandbox path %q must be an absolute clean path below /", m.SandboxPath)
		}
		hostPath, ok := cleanHostPath(m.HostPath)
		if !ok {
			return Workdir{}, invalid("mount host path %q must be an absolute clean path below the filesystem root", m.HostPath)
		}
		if seen[sandboxPath] {
			return Workdir{}, invalid("duplicate mount at %s", sandboxPath)
		}
		seen[sandboxPath] = true
		out.Mounts = append(out.Mounts, Mount{SandboxPath: sandboxPath, HostPath: hostPath, ReadOnly: m.ReadOnly})
	}
	slices.SortFunc(out.Mounts, func(a, b Mount) int { return strings.Compare(a.SandboxPath, b.SandboxPath) })
	masks := make(map[string]bool, len(w.Masks))
	for _, mask := range w.Masks {
		cleaned, ok := cleanSandboxPath(mask)
		if !ok || cleaned == "/" {
			return Workdir{}, invalid("mask %q must be an absolute clean sandbox path", mask)
		}
		masks[cleaned] = true
	}
	for mask := range masks {
		out.Masks = append(out.Masks, mask)
	}
	slices.Sort(out.Masks)
	return out, nil
}

func (r RateLimit) validate() error {
	if r.RequestsPerSecond < 0 || r.RequestsPerSecond > maxRPS {
		return invalid("rate limit rps must be between 0 and %d", maxRPS)
	}
	if r.Burst < 0 || r.Burst > maxBurst {
		return invalid("rate limit burst must be between 0 and %d", maxBurst)
	}
	if r.MaxInFlight < 0 || r.MaxInFlight > maxInFlightLimit {
		return invalid("max in-flight must be between 0 and %d", maxInFlightLimit)
	}
	return nil
}

// validate checks a stored binding. It is stricter than normalize about the
// store-owned fields because a tampered or truncated file must fail closed.
func (b Binding) validate() error {
	if !bindingIDPattern.MatchString(b.ID) {
		return invalid("binding id is malformed")
	}
	if !tokenHashPattern.MatchString(b.TokenHash) {
		return invalid("binding %s has no credential hash", b.ID)
	}
	if b.Generation == 0 || b.CreatedAt.IsZero() || b.RotatedAt.IsZero() {
		return invalid("binding %s is missing lifecycle fields", b.ID)
	}
	normalized, err := b.Spec().normalize()
	if err != nil {
		return err
	}
	if normalized.Connector != b.Connector || !slices.Equal(normalized.Routes, b.Routes) {
		return invalid("binding %s is not in canonical form", b.ID)
	}
	return nil
}

func sortedRoutes(routes []Route) []Route {
	out := slices.Clone(routes)
	slices.Sort(out)
	return slices.Compact(out)
}

// cleanSandboxPath accepts only absolute, already-clean POSIX paths. The
// sandbox is always Linux, so host path rules never apply here.
func cleanSandboxPath(p string) (string, bool) {
	if p == "" || len(p) > maxPathLength || strings.ContainsRune(p, 0) || !strings.HasPrefix(p, "/") {
		return "", false
	}
	cleaned := path.Clean(p)
	return cleaned, cleaned == p
}

func cleanHostPath(p string) (string, bool) {
	if p == "" || len(p) > maxPathLength || strings.ContainsRune(p, 0) || !filepath.IsAbs(p) {
		return "", false
	}
	cleaned := filepath.Clean(p)
	if cleaned != p || filepath.Dir(cleaned) == cleaned {
		return "", false
	}
	return cleaned, true
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSpec, fmt.Sprintf(format, args...))
}
