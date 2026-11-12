// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// In-image layout of the actor kit. The hook binary lives in the OpenShell
// sandbox hook directory (connector.SandboxHookDir) because Codex accepts
// managed hook commands only from its managed_dir.
const (
	ConfigPath   = "/etc/defenseclaw/actor-kit.json"
	LibDir       = "/usr/local/lib/defenseclaw"
	HookDir      = LibDir + "/hooks"
	HookBinary   = HookDir + "/defenseclaw-actor-hook"
	KitDir       = LibDir + "/kit"
	RelayBinary  = KitDir + "/defenseclaw-actor-relay"
	CredHelper   = KitDir + "/git-credential-defenseclaw"
	TrustBundle  = "/run/ate/trust-bundle.pem"
	ProtocolV1   = "dcactor/1"
	ModeEnv      = "DEFENSECLAW_ACTOR_MODE"
	ModeUnattend = "unattended"
	ModeInteract = "interactive"

	// PlaceholderHeader is replaced by Substrate egress with the actor JWT
	// (EgressPolicy replace_headers actor_jwt). Without it nothing is
	// injected, so the kit always sends it.
	PlaceholderHeader = "x-defenseclaw-actor"
	PlaceholderValue  = "placeholder"

	// DefaultGatewayURL is the actor listener Service (PLAN 5.1, D15).
	DefaultGatewayURL = "https://defenseclaw-actor.defenseclaw-system.svc"

	// MaxAttachBytes caps the facts a hook attaches (D9, E19, E20).
	MaxAttachBytes int64 = 1 << 20
)

// Config is the root-owned kit configuration baked into the actor image at
// template build. It holds no secret and no per-actor value (D14, E5).
type Config struct {
	// GatewayURL is the actor listener base URL.
	GatewayURL string `json:"gateway_url"`
	// CAFiles are PEM bundles the hook trusts for the gateway: the projected
	// Substrate trust bundle (egress MITM and system roots).
	CAFiles []string `json:"ca_files"`
	// FailMode is the interactive outage mode, "open" or "closed" (D8).
	// Unattended runs are always closed.
	FailMode string `json:"fail_mode"`
	// ConnectTimeoutMS, MaxTimeMS and RetryMaxTimeMS budget one hook post
	// and its single retry; both must fit the agent's 30 s hook envelope.
	ConnectTimeoutMS int `json:"connect_timeout_ms"`
	MaxTimeMS        int `json:"max_time_ms"`
	RetryMaxTimeMS   int `json:"retry_max_time_ms"`
	// MaxAttachBytes caps attached facts; 0 means MaxAttachBytes.
	MaxAttachBytes int64 `json:"max_attach_bytes"`
	// KitVersion is the kit build the image carries (E18).
	KitVersion string `json:"kit_version"`
	// HookContracts maps a connector to the hook contract its settings were
	// rendered for.
	HookContracts map[string]string `json:"hook_contracts"`
	// LogDir takes hook-failure rows; "" writes none.
	LogDir string `json:"log_dir"`
	// Relay is the relay's part of the configuration.
	Relay RelayConfig `json:"relay"`
}

// RelayConfig configures defenseclaw-actor-relay.
type RelayConfig struct {
	// Listen is the actor ingress port the relay serves.
	Listen string `json:"listen"`
	// Connector is the agent the relay starts in its tmux session.
	Connector string `json:"connector"`
	// Interactive is the agent's interactive argv.
	Interactive []string `json:"interactive"`
	// Headless is the agent's headless argv; the literal "{prompt}" is
	// replaced by the task text.
	Headless []string `json:"headless"`
	// Workdir is where the agent starts ("" keeps the image WORKDIR).
	Workdir string `json:"workdir"`
	// Tmux is the tmux binary.
	Tmux string `json:"tmux"`
	// SessionKeys are the launcher session-token verification keys (E2):
	// key id to a PEM public key file. A2 issues tokens; until then a test key.
	SessionKeys map[string]string `json:"session_keys"`
	// SessionAudience is the aud a session token must carry.
	SessionAudience string `json:"session_audience"`
	// SessionIssuer, when set, is the iss a session token must carry.
	SessionIssuer string `json:"session_issuer"`
	// VerifyURL, when set, makes the relay ask the gateway (through egress,
	// with the actor JWT) whether a presented token is bound to this actor
	// and its person, instead of checking the signature itself.
	VerifyURL string `json:"verify_url"`
	// OutputBufferBytes sizes the long-poll output ring.
	OutputBufferBytes int `json:"output_buffer_bytes"`
}

// DefaultConfig is the configuration a kit image gets when the template build
// does not override a field.
func DefaultConfig() Config {
	return Config{
		GatewayURL:       DefaultGatewayURL,
		CAFiles:          []string{TrustBundle},
		FailMode:         "closed",
		ConnectTimeoutMS: 2000,
		MaxTimeMS:        9000,
		RetryMaxTimeMS:   12000,
		MaxAttachBytes:   MaxAttachBytes,
		KitVersion:       Version,
		Relay: RelayConfig{
			Listen:            ":8080",
			Tmux:              "/usr/bin/tmux",
			SessionAudience:   "dcrelay",
			OutputBufferBytes: 1 << 20,
		},
	}
}

// Version is the kit version, set at build time with -ldflags -X.
var Version = "dev"

// requireRootOwned is false only in tests.
var requireRootOwned = true

// LoadConfig reads the kit configuration. Outside tests the file and its
// directory must be root-owned and not writable by group or others: the agent
// runs as the image USER and must not be able to point its own hooks
// somewhere else.
func LoadConfig(path string) (Config, error) {
	if path == "" {
		path = ConfigPath
	}
	if requireRootOwned {
		for _, p := range []string{filepath.Dir(path), path} {
			if err := rootOwned(p); err != nil {
				return Config{}, err
			}
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("actor kit config: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 256<<10))
	if err != nil {
		return Config{}, fmt.Errorf("actor kit config: %w", err)
	}
	cfg := DefaultConfig()
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("actor kit config %s: %w", path, err)
	}
	return cfg, cfg.Validate()
}

// Validate checks a configuration.
func (c Config) Validate() error {
	u, err := url.Parse(c.GatewayURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("actor kit config: gateway_url %q is not a base URL", c.GatewayURL)
	}
	switch u.Scheme {
	case "https":
	case "http":
		// Substrate egress inspects https and http rules alike, and only a
		// cluster-internal stub (kit-only test cells) is served over http.
	default:
		return fmt.Errorf("actor kit config: gateway_url scheme %q is not http or https", u.Scheme)
	}
	switch c.FailMode {
	case "open", "closed":
	default:
		return fmt.Errorf("actor kit config: fail_mode %q is not open or closed", c.FailMode)
	}
	if c.ConnectTimeoutMS <= 0 || c.MaxTimeMS <= 0 || c.RetryMaxTimeMS <= 0 {
		return errors.New("actor kit config: timeouts must be positive")
	}
	if c.MaxTimeMS+c.RetryMaxTimeMS > 28000 {
		return errors.New("actor kit config: max_time_ms + retry_max_time_ms must fit the agent's 30 s hook envelope")
	}
	if c.MaxAttachBytes < 0 || c.MaxAttachBytes > MaxAttachBytes {
		return fmt.Errorf("actor kit config: max_attach_bytes must be 0..%d", MaxAttachBytes)
	}
	return nil
}

func (c Config) connectTimeout() time.Duration {
	return time.Duration(c.ConnectTimeoutMS) * time.Millisecond
}
func (c Config) maxTime() time.Duration { return time.Duration(c.MaxTimeMS) * time.Millisecond }
func (c Config) retryMaxTime() time.Duration {
	return time.Duration(c.RetryMaxTimeMS) * time.Millisecond
}
func (c Config) attachCap() int64 {
	if c.MaxAttachBytes == 0 {
		return MaxAttachBytes
	}
	return c.MaxAttachBytes
}

// Mode is the run's mode as the kit sees it. The environment can only make a
// run stricter: any value other than "unattended" is interactive.
func Mode(getenv func(string) string) string {
	if strings.TrimSpace(getenv(ModeEnv)) == ModeUnattend {
		return ModeUnattend
	}
	return ModeInteract
}

// FailModeFor is the outage mode of a hook call: closed for unattended runs
// in every tier (D8), the configured mode otherwise.
func (c Config) FailModeFor(mode string) string {
	if mode == ModeUnattend {
		return "closed"
	}
	return c.FailMode
}
