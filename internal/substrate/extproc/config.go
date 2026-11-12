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

package extproc

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the callout's configuration: the substrate.extproc settings,
// the secret bindings of substrate.secrets and the profiles' egress parts,
// rendered by the chart into one file.
type Config struct {
	// FailureMode is closed (refuse) or open (allow with an alert) when the
	// callout can't decide: a Control API outage past the stale window, a
	// tool judge error, an internal error. Managed installs render closed.
	FailureMode string `yaml:"failure_mode"`
	// BodyInspection is auto (use body mode when the egress filter allows
	// mode_override, detected at run time), on (assume it does) or off.
	BodyInspection string `yaml:"body_inspection"`
	// BodyMaxBytes caps a buffered body; a larger one is judged on its
	// headers and recorded body_over_cap. Default 1 MiB.
	BodyMaxBytes int64 `yaml:"body_max_bytes"`
	// MCPHosts are the MCP servers whose JSON-RPC bodies are inspected:
	// "host" or "host=name" (name is the MCP server name the tool rules see).
	MCPHosts []string `yaml:"mcp_hosts"`
	// BodyHosts are other admin-listed hosts whose bodies get the DLP scans.
	BodyHosts []string `yaml:"body_hosts"`
	// DefenseClawHosts are DefenseClaw's own actor-facing hosts. Their
	// requests (hooks, model calls) are allowed without inspection: the
	// gateway inspects them, and their bodies are never buffered.
	DefenseClawHosts []string `yaml:"defenseclaw_hosts"`
	// InternalHosts are DefenseClaw Services an actor must never reach
	// through egress, in every spelling (the admin Service, D15). They are
	// refused before any other check. The chart renders them; the default
	// is the admin Service in defenseclaw-system.
	InternalHosts []string `yaml:"internal_hosts"`
	// ClusterDomains are in-cluster name suffixes (svc.cluster.local). The
	// EgressPolicy decided they are reachable; the egress guard's intranet
	// rule (.local) must not refuse them.
	ClusterDomains []string `yaml:"cluster_domains"`
	// ActorTrustDomain is the SPIFFE trust domain of actor identities.
	ActorTrustDomain string `yaml:"actor_trust_domain"`
	// EgressPeers are the SPIFFE IDs allowed to call the callout.
	EgressPeers []string `yaml:"egress_peers"`
	// RequestAccess is the request-access contact refusals name.
	RequestAccess string `yaml:"request_access"`
	// LogHeaders adds the request headers, redacted, to every event.
	LogHeaders bool `yaml:"log_headers"`
	// RedactHeaders are extra header names whose values are always redacted.
	RedactHeaders []string `yaml:"redact_headers"`
	// BlocklistFiles are egress feed files used instead of the built-in
	// blocklist (policies/sandbox/egress/blocklist.yaml); empty uses it.
	BlocklistFiles []string `yaml:"blocklist_files"`

	UID   UIDConfig   `yaml:"uid"`
	Chain ChainConfig `yaml:"chain"`
	Ask   AskConfig   `yaml:"ask"`
	Judge JudgeConfig `yaml:"judge"`
	DLP   DLPConfig   `yaml:"dlp"`

	// Secrets are the substrate.secrets bindings: which header carries a
	// secret's value on which hosts, and its placeholder. Values are never
	// here.
	Secrets []SecretBinding `yaml:"secrets"`
	// ActorSecretsDir holds the values of the profiles' actor_secrets, one
	// file per name (a mounted Secret), read again when they change.
	ActorSecretsDir string `yaml:"actor_secrets_dir"`

	// DefaultProfile names the profile for actors no profile's atespaces
	// match; empty is a profile with the feeds alone.
	DefaultProfile string          `yaml:"default_profile"`
	Profiles       []ProfileConfig `yaml:"profiles"`
}

// UIDConfig configures the live-UID cache.
type UIDConfig struct {
	// CacheTTL is how long a resolved UID is used without asking again.
	CacheTTL time.Duration `yaml:"cache_ttl"`
	// StaleMax is how long a cached UID still serves while the Control API
	// is down (§5.5: 60 s, then refuse).
	StaleMax time.Duration `yaml:"stale_max"`
}

// ChainConfig configures the chain integration.
type ChainConfig struct {
	// CheckBudget bounds the synchronous egress-chain check. Default 20 ms.
	CheckBudget time.Duration `yaml:"check_budget"`
	// QueueSize bounds the observed_egress queue; a full queue drops.
	QueueSize int `yaml:"queue_size"`
	// FailureMode decides a request whose chain check could not answer (an
	// error, the budget, the actor's in-flight cap): auto (default) refuses
	// for unattended actors and alerts for the rest, closed always refuses
	// (managed installs), open always alerts.
	FailureMode string `yaml:"failure_mode"`
}

// AskConfig configures ask-required hosts.
type AskConfig struct {
	// Hold is how long a request waits for an ask's outcome, at most
	// MessageBudget.
	Hold time.Duration `yaml:"hold"`
}

// JudgeConfig points the MCP tool judge at the gateway's callout verdict
// route (calloutapi.Path) on the admin listener.
type JudgeConfig struct {
	URL       string        `yaml:"url"`
	TokenFile string        `yaml:"token_file"`
	CAFile    string        `yaml:"ca_file"`
	Timeout   time.Duration `yaml:"timeout"`
}

// DLPConfig tunes the header scans.
type DLPConfig struct {
	// CredentialHeaders is alert (default) or deny for a secret-shaped value
	// in a credential header (Authorization and the like) on a host no
	// secret is bound to. Secret shapes in the URL and in other headers are
	// always refused.
	CredentialHeaders string `yaml:"credential_headers"`
}

// SecretBinding is one substrate.secrets entry as the callout needs it.
type SecretBinding struct {
	Name        string   `yaml:"name"`
	Hosts       []string `yaml:"hosts"`
	Header      string   `yaml:"header"`
	Placeholder string   `yaml:"placeholder"`
}

// ProfileConfig is the egress part of a profile.
type ProfileConfig struct {
	Name string `yaml:"name"`
	// Atespaces are path.Match globs (eng-*) of the atespaces the profile
	// applies to; the first matching profile wins.
	Atespaces []string     `yaml:"atespaces"`
	Egress    EgressLists  `yaml:"egress"`
	URLRules  []URLRuleCfg `yaml:"url_rules"`
	// AskHosts need an approved ask before a request reaches them.
	AskHosts []string `yaml:"ask_hosts"`
	// ActorSecrets name the exposed values (files in ActorSecretsDir) whose
	// exact value must never leave in a URL, header or inspected body.
	ActorSecrets []string `yaml:"actor_secrets"`
	// UnattendedAsks is deny (default) or queue (D12).
	UnattendedAsks string `yaml:"unattended_asks"`
}

// EgressLists are the egress.Decider host lists, in its pattern forms.
type EgressLists struct {
	AdminBlock []string `yaml:"admin_block"`
	AllowOnly  []string `yaml:"allow_only"`
	Block      []string `yaml:"block"`
	Allow      []string `yaml:"allow"`
}

// URLRuleCfg is a profile URL and method rule. The first rule matching the
// host, method and path decides: allow ends the rule pass, deny refuses, ask
// raises an ask.
type URLRuleCfg struct {
	Name       string   `yaml:"name"`
	Hosts      []string `yaml:"hosts"`
	Methods    []string `yaml:"methods"`
	PathPrefix string   `yaml:"path_prefix"`
	Action     string   `yaml:"action"`
}

// Defaults.
const (
	DefaultBodyMaxBytes = 1 << 20
	defaultCacheTTL     = 60 * time.Second
	defaultStaleMax     = 60 * time.Second
	defaultCheckBudget  = 20 * time.Millisecond
	defaultQueueSize    = 4096
	defaultAskHold      = 1500 * time.Millisecond
	defaultJudgeTimeout = 1500 * time.Millisecond
	// MessageBudget is the time the callout takes to answer one message
	// (headers or body), under the egress filter's 2 s message timeout
	// (atenet v1.0.0), so DefenseClaw's answer, not Envoy's failure
	// mode, decides (GAP-0062). ask.hold and judge.timeout fit inside it.
	MessageBudget  = 1800 * time.Millisecond
	maxConfigBytes = 4 << 20
)

// Failure modes and body inspection settings.
const (
	FailureClosed = "closed"
	FailureOpen   = "open"
	BodyAuto      = "auto"
	ChainAuto     = "auto"
	BodyOn        = "on"
	BodyOff       = "off"
	dlpAlert      = "alert"
	dlpDeny       = "deny"
)

// ErrInvalidConfig reports a configuration that fails validation.
var ErrInvalidConfig = errors.New("extproc: invalid config")

// LoadConfig reads and validates a config file.
func LoadConfig(file string) (*Config, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	return ParseConfig(data)
}

// ParseConfig decodes and validates a config document. Unknown keys are
// errors, so a misspelt rule fails at load instead of matching nothing.
func ParseConfig(data []byte) (*Config, error) {
	if len(data) > maxConfigBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalidConfig, maxConfigBytes)
	}
	var cfg Config
	if len(bytes.TrimSpace(data)) > 0 {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
		}
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// normalize applies defaults and validates; it is idempotent.
func (c *Config) normalize() error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalidConfig}, args...)...)
	}
	switch c.FailureMode = strings.ToLower(strings.TrimSpace(c.FailureMode)); c.FailureMode {
	case "":
		c.FailureMode = FailureClosed
	case FailureClosed, FailureOpen:
	default:
		return bad("failure_mode %q (want closed or open)", c.FailureMode)
	}
	switch c.BodyInspection = strings.ToLower(strings.TrimSpace(c.BodyInspection)); c.BodyInspection {
	case "":
		c.BodyInspection = BodyAuto
	case BodyAuto, BodyOn, BodyOff:
	default:
		return bad("body_inspection %q (want auto, on or off)", c.BodyInspection)
	}
	switch {
	case c.BodyMaxBytes == 0:
		c.BodyMaxBytes = DefaultBodyMaxBytes
	case c.BodyMaxBytes < 0 || c.BodyMaxBytes > DefaultBodyMaxBytes:
		// D9: the cap is 1 MiB; a larger buffer is a memory lever an actor
		// could pull on every replica.
		return bad("body_max_bytes %d (1 to %d)", c.BodyMaxBytes, DefaultBodyMaxBytes)
	}
	switch c.DLP.CredentialHeaders = strings.ToLower(strings.TrimSpace(c.DLP.CredentialHeaders)); c.DLP.CredentialHeaders {
	case "":
		c.DLP.CredentialHeaders = dlpAlert
	case dlpAlert, dlpDeny:
	default:
		return bad("dlp.credential_headers %q (want alert or deny)", c.DLP.CredentialHeaders)
	}
	if c.ActorTrustDomain == "" {
		c.ActorTrustDomain = DefaultActorTrustDomain
	}
	if len(c.EgressPeers) == 0 {
		c.EgressPeers = []string{DefaultEgressPeer}
	}
	if len(c.ClusterDomains) == 0 {
		c.ClusterDomains = []string{"svc.cluster.local"}
	}
	if len(c.DefenseClawHosts) == 0 {
		c.DefenseClawHosts = []string{"defenseclaw-actor.defenseclaw-system.svc", "defenseclaw-actor.defenseclaw-system.svc.cluster.local"}
	}
	if len(c.InternalHosts) == 0 {
		c.InternalHosts = []string{"defenseclaw-admin.defenseclaw-system.svc.cluster.local", "defenseclaw-admin.defenseclaw-system.svc",
			"defenseclaw-admin.defenseclaw-system", "defenseclaw-admin"}
	}
	setDur := func(d *time.Duration, def time.Duration, name string, max time.Duration) error {
		if *d == 0 {
			*d = def
		}
		if *d < 0 || *d > max {
			return bad("%s %s (0 to %s)", name, *d, max)
		}
		return nil
	}
	for _, d := range []struct {
		p        *time.Duration
		def, max time.Duration
		name     string
	}{
		{&c.UID.CacheTTL, defaultCacheTTL, 10 * time.Minute, "uid.cache_ttl"},
		{&c.UID.StaleMax, defaultStaleMax, 10 * time.Minute, "uid.stale_max"},
		{&c.Chain.CheckBudget, defaultCheckBudget, 500 * time.Millisecond, "chain.check_budget"},
		{&c.Ask.Hold, defaultAskHold, MessageBudget, "ask.hold"},
		{&c.Judge.Timeout, defaultJudgeTimeout, MessageBudget, "judge.timeout"},
	} {
		if err := setDur(d.p, d.def, d.name, d.max); err != nil {
			return err
		}
	}
	switch c.Chain.FailureMode = strings.ToLower(strings.TrimSpace(c.Chain.FailureMode)); c.Chain.FailureMode {
	case "":
		c.Chain.FailureMode = ChainAuto
	case ChainAuto, FailureClosed, FailureOpen:
	default:
		return bad("chain.failure_mode %q (want auto, closed or open)", c.Chain.FailureMode)
	}
	if c.Chain.QueueSize == 0 {
		c.Chain.QueueSize = defaultQueueSize
	}
	if c.Chain.QueueSize < 0 || c.Chain.QueueSize > 1<<20 {
		return bad("chain.queue_size %d", c.Chain.QueueSize)
	}
	for _, list := range []struct {
		name  string
		hosts []string
	}{{"mcp_hosts", mcpHostNames(c.MCPHosts)}, {"body_hosts", c.BodyHosts}, {"defenseclaw_hosts", c.DefenseClawHosts}, {"internal_hosts", c.InternalHosts}} {
		if _, err := newHostMatcher(list.hosts); err != nil {
			return bad("%s: %v", list.name, err)
		}
	}
	for _, d := range c.ClusterDomains {
		if _, _, err := normalizeHost(d); err != nil {
			return bad("cluster_domains: %q", d)
		}
	}
	seen := map[string]bool{}
	for i, s := range c.Secrets {
		if s.Name == "" || seen[s.Name] {
			return bad("secrets[%d]: missing or duplicate name", i)
		}
		seen[s.Name] = true
		if _, err := newHostMatcher(s.Hosts); err != nil {
			return bad("secrets[%s].hosts: %v", s.Name, err)
		}
		if s.Header == "" {
			return bad("secrets[%s]: header is required", s.Name)
		}
	}
	names := map[string]bool{}
	for i := range c.Profiles {
		p := &c.Profiles[i]
		if p.Name == "" || names[p.Name] {
			return bad("profiles[%d]: missing or duplicate name", i)
		}
		names[p.Name] = true
		for _, g := range p.Atespaces {
			if _, err := path.Match(g, ""); err != nil {
				return bad("profiles[%s].atespaces: %q: %v", p.Name, g, err)
			}
		}
		switch p.UnattendedAsks = strings.ToLower(strings.TrimSpace(p.UnattendedAsks)); p.UnattendedAsks {
		case "":
			p.UnattendedAsks = "deny"
		case "deny", "queue":
		default:
			return bad("profiles[%s].unattended_asks %q (want deny or queue)", p.Name, p.UnattendedAsks)
		}
		if _, err := newHostMatcher(p.AskHosts); err != nil {
			return bad("profiles[%s].ask_hosts: %v", p.Name, err)
		}
		for j := range p.URLRules {
			if err := p.URLRules[j].normalize(); err != nil {
				return bad("profiles[%s].url_rules[%d]: %v", p.Name, j, err)
			}
		}
		for _, n := range p.ActorSecrets {
			if !validSecretFileName(n) {
				return bad("profiles[%s].actor_secrets: %q", p.Name, n)
			}
		}
	}
	if c.DefaultProfile != "" && !names[c.DefaultProfile] {
		return bad("default_profile %q is not a profile", c.DefaultProfile)
	}
	return nil
}

func (r *URLRuleCfg) normalize() error {
	switch r.Action = strings.ToLower(strings.TrimSpace(r.Action)); r.Action {
	case "allow", "deny", "ask":
	default:
		return fmt.Errorf("action %q (want allow, deny or ask)", r.Action)
	}
	if len(r.Hosts) == 0 {
		return errors.New("hosts is required")
	}
	if _, err := newHostMatcher(r.Hosts); err != nil {
		return err
	}
	for i, m := range r.Methods {
		r.Methods[i] = strings.ToUpper(strings.TrimSpace(m))
		if r.Methods[i] == "" {
			return errors.New("empty method")
		}
	}
	if r.PathPrefix != "" && !strings.HasPrefix(r.PathPrefix, "/") {
		return fmt.Errorf("path_prefix %q must start with /", r.PathPrefix)
	}
	return nil
}

// mcpHostNames are the hosts of mcp_hosts entries ("host" or "host=name").
func mcpHostNames(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		h, _, _ := strings.Cut(e, "=")
		out = append(out, strings.TrimSpace(h))
	}
	return out
}

var validSecretFileName = actorNamePattern.MatchString
