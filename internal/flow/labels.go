// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// Audience is the reach of data, as a small lattice self > internal > public.
// A higher value is stricter; the session label is the maximum (meet) seen.
type Audience uint8

const (
	AudiencePublic   Audience = 0
	AudienceInternal Audience = 1
	AudienceSelf     Audience = 2
)

// Trust is the trust of data; suspicious is stricter than trusted. It rides
// along for the enterprise/managed lanes and does not fire in default.
type Trust uint8

const (
	TrustTrusted    Trust = 0
	TrustSuspicious Trust = 1
)

// Label is audience and trust. The zero value (public, trusted) is "no label".
type Label struct {
	Audience Audience
	Trust    Trust
}

// labeled reports whether the label is anything stricter than public/trusted.
func (l Label) labeled() bool { return l.Audience > AudiencePublic || l.Trust > TrustTrusted }

// meet returns the stricter of two labels (the max on each axis). The session
// label only ever moves toward this, never back.
func (l Label) meet(o Label) Label {
	if o.Audience > l.Audience {
		l.Audience = o.Audience
	}
	if o.Trust > l.Trust {
		l.Trust = o.Trust
	}
	return l
}

// String renders the label for the status/explain view.
func (l Label) String() string {
	a := map[Audience]string{AudiencePublic: "public", AudienceInternal: "internal", AudienceSelf: "self"}[l.Audience]
	if l.Trust == TrustSuspicious {
		return a + ",suspicious"
	}
	return a
}

// LabelSet is one named family of secret sources. "credentials" is on by
// default; config can add path globs and secret-file name patterns.
type LabelSet struct {
	Name     string
	Audience Audience
}

// Config is the engine's view of guardrail.secret_flow. The gateway builds it
// from config.SecretFlowConfig; flow never imports internal/config.
type Config struct {
	// Mode is off, shadow or on. The engine runs the same in shadow and on;
	// the caller decides whether the verdict participates.
	Mode string
	// Credentials turns the built-in credential label set on (default true).
	Credentials bool
	// ExtraPathGlobs are extra absolute/home path globs labeled as secret.
	ExtraPathGlobs []string
	// ExtraSecretPatterns are extra basename patterns (globs) labeled secret.
	ExtraSecretPatterns []string
	// Reencodings indexes base64/hex/url-encoded forms of each secret value.
	Reencodings bool
	// MaxLabeledPaths and MaxValueDigests bound the per-session memory.
	MaxLabeledPaths int
	MaxValueDigests int
	// DestinationAllowlist holds hosts/host-suffixes that do not count as
	// external sinks (your own git remote, a package registry).
	DestinationAllowlist []string
	// SinkDefault/SinkStrict/SinkManaged are the action per mode. Default is
	// validated to never be block.
	SinkDefault Action
	SinkStrict  Action
	SinkManaged Action
	// StrictOrManaged is set by the caller for the strict profile and every
	// managed install (they fail closed).
	StrictOrManaged bool
	// Managed is set for a managed install (reserved for internal labels from
	// identity groups; not built yet).
	Managed bool
	// Home is the resolved user home, for the built-in credential set.
	Home string
	// Flavor selects path rules for the built-in set.
	Flavor effects.Flavor
}

// credentialRelPaths mirrors internal/effectrules: home-relative credential
// files besides SSH private keys. Kept here (not imported) so the label set is
// data-driven and this package stays dependency-light.
var credentialRelPaths = []string{
	".aws/credentials", ".git-credentials", ".netrc", ".npmrc", ".pypirc",
	".kube/config", ".docker/config.json", ".config/gcloud/credentials.db",
	".config/gh/hosts.yml",
}

// credentialBasenamePatterns are basename globs that mark a credential file
// wherever it sits (an agent often reads a project-local one).
var credentialBasenamePatterns = []string{
	".env", ".env.*", "*.pem", "*.key", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
	"*.p12", "*.pfx", "credentials.json", "service-account*.json", "*token*.json",
}

// benignEnvSuffixes are .env siblings that are templates, not secrets.
var benignEnvSuffixes = []string{".env.example", ".env.sample", ".env.template", ".env.dist"}

// labelForTarget returns the label and sets for a read target that is a
// secret source, if any. It matches on the resolved target, never on command
// text (so a heredoc body that mentions ".env" is not a source).
func (cfg Config) labelForTarget(t effects.Target) (Label, []string, bool) {
	if t.Type != effects.TargetPath {
		return Label{}, nil, false
	}
	p := t.Path
	if p == "" {
		p = t.Spelling
	}
	if p == "" {
		return Label{}, nil, false
	}
	base := baseOf(p, t.Flavor)
	if isBenignEnv(base) {
		return Label{}, nil, false
	}
	var sets []string
	if cfg.Credentials {
		if matchesBuiltinCredential(p, base, cfg.Home, t.Flavor) {
			sets = append(sets, "credentials")
		}
	}
	for _, g := range cfg.ExtraSecretPatterns {
		if ok, _ := path.Match(g, base); ok {
			sets = append(sets, "extra_secret")
			break
		}
	}
	for _, g := range cfg.ExtraPathGlobs {
		if globMatchPath(g, p, cfg.Home, t.Flavor) {
			sets = append(sets, "extra_path")
			break
		}
	}
	if len(sets) == 0 {
		return Label{}, nil, false
	}
	return Label{Audience: AudienceSelf}, dedup(sets), true
}

func matchesBuiltinCredential(p, base, home string, flavor effects.Flavor) bool {
	for _, g := range credentialBasenamePatterns {
		if ok, _ := path.Match(g, base); ok {
			return true
		}
	}
	norm := toSlashLower(p, flavor)
	if strings.Contains(norm, "/.ssh/") && !strings.HasSuffix(norm, ".pub") {
		return true
	}
	if strings.HasPrefix(norm, "/proc/") && strings.HasSuffix(norm, "/environ") {
		return true
	}
	if home != "" {
		h := toSlashLower(home, flavor)
		for _, rel := range credentialRelPaths {
			if norm == h+"/"+rel {
				return true
			}
		}
	} else {
		for _, rel := range credentialRelPaths {
			if strings.HasSuffix(norm, "/"+rel) {
				return true
			}
		}
	}
	return false
}

// isAllowlistedHost reports whether a sink's host is on the allowlist (own
// remote, a registry) or is local. A host matches a bare entry exactly or as
// a dotted suffix (github.com matches api.github.com). An empty host is not
// allowlisted: an external send whose host the effect model could not place
// is still a candidate sink.
func (cfg Config) isAllowlistedHost(rawHost string) bool {
	host := strings.ToLower(strings.TrimSpace(rawHost))
	if host == "" {
		return false
	}
	// Loopback and link-local never count as external.
	if isLocalHost(host) {
		return true
	}
	for _, a := range cfg.DestinationAllowlist {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

// action maps the hits to the action the active mode would take. Default never
// blocks: SinkDefault is validated to alert. The caller passes StrictOrManaged.
func (cfg Config) action(hits []Hit) Action {
	if len(hits) == 0 {
		return ActionAllow
	}
	// A session-context-only hit never fires in default (brief step 3).
	if !cfg.StrictOrManaged && onlySessionContext(hits) {
		return ActionAllow
	}
	if cfg.StrictOrManaged {
		if cfg.Managed {
			return cfg.SinkManaged
		}
		return cfg.SinkStrict
	}
	return cfg.SinkDefault
}

func onlySessionContext(hits []Hit) bool {
	for _, h := range hits {
		if h.Kind != HitSessionContext {
			return false
		}
	}
	return true
}

func isLocalHost(h string) bool {
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	switch h {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0", "ip6-localhost":
		return true
	}
	return strings.HasPrefix(h, "127.") || strings.HasPrefix(h, "169.254.") ||
		strings.HasPrefix(h, "192.168.") || strings.HasPrefix(h, "10.") ||
		strings.HasPrefix(h, "172.16.") || strings.HasPrefix(h, "fe80:")
}

// --- small path helpers (flavor-aware, no filepath/OS dependence) ---

func toSlashLower(p string, flavor effects.Flavor) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if flavor == effects.FlavorWindows {
		return strings.ToLower(p)
	}
	return p
}

func baseOf(p string, flavor effects.Flavor) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	if flavor == effects.FlavorWindows {
		return strings.ToLower(p)
	}
	return p
}

func isBenignEnv(base string) bool {
	for _, s := range benignEnvSuffixes {
		if base == s {
			return true
		}
	}
	return false
}

func globMatchPath(g, p, home string, flavor effects.Flavor) bool {
	g = strings.ReplaceAll(g, `\`, "/")
	if home != "" && strings.HasPrefix(g, "~/") {
		g = toSlashLower(home, flavor) + g[1:]
	}
	np := toSlashLower(p, flavor)
	if flavor == effects.FlavorWindows {
		g = strings.ToLower(g)
	}
	ok, err := path.Match(g, np)
	return err == nil && ok
}

func basename(t effects.Target) string {
	p := t.Path
	if p == "" {
		p = t.Spelling
	}
	return baseOf(p, t.Flavor)
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
