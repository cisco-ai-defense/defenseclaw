// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// In-image layout of the actor kit. The hook binary lives in the OpenShell
// sandbox hook directory (connector.SandboxHookDir) because Codex accepts
// managed hook commands only from its managed_dir.
const (
	ConfigPath  = "/etc/defenseclaw/actor-kit.json"
	LibDir      = "/usr/local/lib/defenseclaw"
	HookDir     = LibDir + "/hooks"
	HookBinary  = HookDir + "/defenseclaw-actor-hook"
	KitDir      = LibDir + "/kit"
	RelayBinary = KitDir + "/defenseclaw-actor-relay"
	CredHelper  = KitDir + "/git-credential-defenseclaw"
	TrustBundle = "/run/ate/trust-bundle.pem"
	// EnvelopeVersion is HookEnvelope.V, the version the gateway's actor
	// listener accepts.
	EnvelopeVersion = "1"
	ModeEnv         = "DEFENSECLAW_ACTOR_MODE"
	ModeUnattend    = "unattended"
	ModeInteract    = "interactive"

	// PlaceholderHeader is replaced by Substrate egress with the actor JWT
	// (EgressPolicy replace_headers actor_jwt). Without it nothing is
	// injected, so the kit always sends it.
	PlaceholderHeader = connector.SandboxActorHeader
	PlaceholderValue  = connector.SandboxActorPlaceholder

	// DefaultGatewayURL is the actor listener Service (PLAN 5.1, D15), by
	// its FQDN: egress resolves only names in the actor's policy, so the
	// short .svc name is NXDOMAIN in an actor (substrate-1 GAP-0023).
	// It is plain HTTP on port 80: the hop from atenet-egress to the Service
	// stays in the cluster, and egress puts the actor JWT in the request
	// (A8 ruling for GAP-0023/GAP-0042).
	DefaultGatewayURL = "http://defenseclaw-actor.defenseclaw-system.svc.cluster.local"

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
	// Managed is a managed_enterprise image: the relay refuses to start an
	// agent that signs in to a vendor account, because the token would sit
	// in the actor and its snapshots (E9). The gateway decides the same from
	// its own configuration; this is the second layer inside the actor.
	Managed bool `json:"managed,omitempty"`
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
	// Connector is the agent the relay starts on its PTY.
	Connector string `json:"connector"`
	// Interactive is the agent's interactive argv.
	Interactive []string `json:"interactive"`
	// Headless is the agent's headless argv; the literal "{prompt}" is
	// replaced by the task text.
	Headless []string `json:"headless"`
	// Workdir is where the agent starts ("" keeps the image WORKDIR).
	Workdir string `json:"workdir"`
	// SessionKeys are the launcher session-token verification keys (E2):
	// key id to a PEM public key file. A2 issues tokens; until then a test key.
	SessionKeys map[string]string `json:"session_keys"`
	// SessionAudience is the aud a session token must carry.
	SessionAudience string `json:"session_audience"`
	// SessionIssuer is the iss a session token must carry; required with
	// SessionKeys (GAP-0073).
	SessionIssuer string `json:"session_issuer"`
	// VerifyURL makes the relay ask the gateway (through egress, with the
	// actor JWT) whether a presented token is bound to this actor and its
	// own person (RelayVerifyURL of GatewayURL). Required with SessionKeys
	// (GAP-0435): the keys check the signature and the actor only, so a
	// relay with keys and no VerifyURL could not tell that the token's
	// person owns the agent. With both, a token must pass the keys and
	// the gateway.
	VerifyURL string `json:"verify_url"`
	// Streams are the relay features the kit was built with (StreamTLS:
	// the relay serves TLS with a certificate the gateway signs, B3.5).
	// The template build writes them and its signed attestation carries
	// them, so the gateway reads them from the template, never from the
	// relay. Empty for kits built before 1.0.11.
	Streams []string `json:"streams,omitempty"`
	// OutputBufferBytes sizes the long-poll output ring.
	OutputBufferBytes int `json:"output_buffer_bytes"`
	// IdentityDir holds the actor's projected identity files (atespace,
	// name, uid), from the template's systemInfo actorMetadata volume.
	IdentityDir string `json:"identity_dir"`
	// Env is extra environment for the agent the relay starts.
	Env map[string]string `json:"env"`
	// TaskStallMS bounds how long a --task run may make no progress (no
	// agent output other than retry notices, no CPU or I/O in its process
	// group) before the relay ends it with exit 124 (GAP-0273); 0 is
	// DefaultTaskStall.
	TaskStallMS int `json:"task_stall_ms,omitempty"`
	// AgentUser is "UID:GID", the unprivileged user the relay starts the
	// agent (and every task, exec and file copy) as, when the relay itself
	// runs as root (GAP-0116). The agent then cannot signal, trace or
	// replace the relay: gVisor delivers SIGKILL and SIGSTOP from inside the
	// actor to its PID 1, so being PID 1 alone does not protect the relay.
	// Empty (images built before 1.0.10): the agent runs as the relay's own
	// user, and the relay warns that they are not separated.
	AgentUser string `json:"agent_user,omitempty"`
	// Protected are the root-owned files of the kit layer that the template
	// build attests (the connector's managed settings, hook registration and
	// the kit's own configuration) and the folders that hold them
	// (ProtectedPaths). The relay refuses the agent when a mount of the
	// actor is at, above or below one of them, also one that reached its
	// place through a symlink admission cannot see (substrate-1 GAP-0439).
	// The build writes it with the relay binary in the same layer.
	Protected []string `json:"protected,omitempty"`
	// ClaudeStateFile is Claude Code's state file (~/.claude.json). Before
	// it starts Claude Code, the relay records there that the start folder
	// and each folder between it and Workdir are trusted
	// (projects[<path>].hasTrustDialogAccepted). The actor is the sandbox,
	// and the image already trusts Workdir. But Claude Code stops carrying
	// a parent's trust at a git repository's root, and the copy of a git
	// project is one (/work/<folder>/.git), so without this every run from
	// macOS or Linux opened on "Is this a project you trust?" with "No,
	// exit" selected (substrate-1 GAP-0446). "" records nothing.
	ClaudeStateFile string `json:"claude_state_file,omitempty"`
}

// AgentIDs parses AgentUser; ok is false when it is empty.
func (r RelayConfig) AgentIDs() (uid, gid int, ok bool, err error) {
	if r.AgentUser == "" {
		return 0, 0, false, nil
	}
	u, g, found := strings.Cut(r.AgentUser, ":")
	uid, uerr := strconv.Atoi(u)
	gid, gerr := strconv.Atoi(g)
	if !found || uerr != nil || gerr != nil || uid <= 0 || gid <= 0 {
		return 0, 0, false, fmt.Errorf("actor kit config: relay.agent_user %q is not a non-root UID:GID", r.AgentUser)
	}
	return uid, gid, true, nil
}

// DefaultTaskStall is the relay's no-progress bound of a --task run: longer
// than one agent model attempt that never answers (Claude Code gives up on
// one after about 6 minutes), short enough that a run whose gateway path is
// stuck ends with a reason instead of hanging (GAP-0273).
const DefaultTaskStall = 10 * time.Minute

// MinTaskStallMS and MaxTaskStallMS bound relay.task_stall_ms (1m, 24h).
const (
	MinTaskStallMS = 60_000
	MaxTaskStallMS = 24 * 60 * 60 * 1000
)

// TaskStall is the relay's no-progress bound of a --task run.
func (r RelayConfig) TaskStall() time.Duration {
	if r.TaskStallMS > 0 {
		return time.Duration(r.TaskStallMS) * time.Millisecond
	}
	return DefaultTaskStall
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
			SessionAudience:   "dcrelay",
			OutputBufferBytes: 1 << 20,
			IdentityDir:       "/run/ate/actor",
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
	if _, _, _, err := c.Relay.AgentIDs(); err != nil {
		return err
	}
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
	if c.Relay.TaskStallMS < 0 || (c.Relay.TaskStallMS > 0 && (c.Relay.TaskStallMS < MinTaskStallMS || c.Relay.TaskStallMS > MaxTaskStallMS)) {
		return fmt.Errorf("actor kit config: relay.task_stall_ms must be 0 (the default, 10m) or %d to %d (1m to 24h)", MinTaskStallMS, MaxTaskStallMS)
	}
	if f := c.Relay.ClaudeStateFile; f != "" && !strings.HasPrefix(f, "/") {
		return fmt.Errorf("actor kit config: relay.claude_state_file %q is not an absolute path", f)
	}
	if c.MaxAttachBytes < 0 || c.MaxAttachBytes > MaxAttachBytes {
		return fmt.Errorf("actor kit config: max_attach_bytes must be 0..%d", MaxAttachBytes)
	}
	if err := c.Relay.CheckSessions(); err != nil {
		return fmt.Errorf("actor kit config: %w", err)
	}
	return nil
}

// RelayVerifyPath is the actor listener route the relay checks a session
// token with (the gateway's /relay/verify).
const RelayVerifyPath = "/api/v1/substrate/relay/verify"

// RelayVerifyURL is the relay's verify_url for an actor listener base URL.
func RelayVerifyURL(gatewayURL string) string {
	return strings.TrimRight(strings.TrimSpace(gatewayURL), "/") + RelayVerifyPath
}

// Relay streams a kit names (relay.streams). StreamTLS marks a relay that
// serves TLS on its listen port; StreamPort and StreamMCP mark one that
// serves port forwards and MCP bridges (B3.2, B3.3), which ride TLS only.
// A stream name is its relay attach route (relay.RoutePort, RouteMCP).
const (
	StreamTLS  = "tls"
	StreamPort = "port"
	StreamMCP  = "mcp"
)

// relayCertPath is the actor-listener route that signs the relay's
// serving certificate; it sits next to the verify route.
const relayCertPath = "/api/v1/substrate/relay/cert"

// ServesTLS reports whether the kit's relay serves TLS.
func (r RelayConfig) ServesTLS() bool {
	for _, s := range r.Streams {
		if s == StreamTLS {
			return true
		}
	}
	return false
}

// CertURL is where the relay asks for its serving certificate: the
// gateway of VerifyURL (the same egress path and actor JWT). "" when the
// relay does not verify through the gateway.
func (r RelayConfig) CertURL() string {
	if r.VerifyURL == "" {
		return ""
	}
	u, err := url.Parse(r.VerifyURL)
	if err != nil || u.Host == "" {
		return ""
	}
	u.Path, u.RawPath, u.RawQuery, u.Fragment = relayCertPath, "", "", ""
	return u.String()
}

// checkStreams refuses an unknown relay stream and TLS without a gateway
// to sign the certificate.
func (r RelayConfig) checkStreams() error {
	for _, s := range r.Streams {
		switch s {
		case StreamTLS:
		case StreamPort, StreamMCP:
			if !r.ServesTLS() {
				return fmt.Errorf("relay stream %s needs relay stream tls", s)
			}
		default:
			return fmt.Errorf("relay stream %q is not known", s)
		}
	}
	if r.ServesTLS() && r.VerifyURL == "" {
		return errors.New("relay stream tls needs relay.verify_url (the gateway signs the relay certificate)")
	}
	return nil
}

// CheckSessions is the relay's start-up rule for session verification
// (GAP-0073), part of Validate, so the template build applies it too
// (substrate-1 GAP-0147) and an image whose relay would refuse to start is
// never built. Session keys need verify_url (GAP-0435) and their issuer.
func (r RelayConfig) CheckSessions() error {
	if err := r.checkStreams(); err != nil {
		return err
	}
	if r.VerifyURL != "" {
		u, err := url.Parse(r.VerifyURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("relay verify_url %q is not an http or https URL", r.VerifyURL)
		}
	}
	if len(r.SessionKeys) == 0 {
		return nil
	}
	if r.VerifyURL == "" {
		return errors.New("relay.session_keys need relay.verify_url (the gateway's session check, <gateway_url>" + RelayVerifyPath +
			"): with the keys alone the relay cannot check that the token's person owns this agent")
	}
	if strings.TrimSpace(r.SessionIssuer) == "" {
		return errors.New("relay session keys need relay.session_issuer (the issuer whose tokens they verify)")
	}
	return nil
}

// SessionKeyID is the key id of a relay session public key (PKIX PEM, P-256
// or Ed25519): the base64url SHA-256 of its PKIX encoding, the rule the
// gateway's session signer uses for the kid of every token it issues
// (identity.SessionSigner.KeyID).
func SessionKeyID(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", errors.New("relay session key: no PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("relay session key: %w", err)
	}
	switch kk := k.(type) {
	case *ecdsa.PublicKey:
		if kk.Curve != elliptic.P256() {
			return "", errors.New("relay session key: the ECDSA key is not P-256")
		}
	case ed25519.PublicKey:
	default:
		return "", errors.New("relay session key: not a P-256 or Ed25519 public key")
	}
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return "", fmt.Errorf("relay session key: %w", err)
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
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

// The capabilities of a kit actor's container (substrate-1 GAP-0458,
// GAP-0376). A Substrate actor's container gets AUDIT_WRITE, KILL and
// NET_BIND_SERVICE by default (Substrate v1.0.0, atelet), and a template
// may add a short list (SETUID and SETGID among them) and drop any. A kit
// image whose relay runs as root and starts the agent as relay.agent_user
// needs SETUID and SETGID for that switch and KILL to stop the agent, and
// nothing else: its template adds the first two and drops the other
// defaults (the relay listens above 1023). An image whose relay and agent
// share a user gets no adjustment: an added capability would be the agent's.
var (
	RelayCapabilitiesAdd  = []string{"SETUID", "SETGID"}
	RelayCapabilitiesDrop = []string{"AUDIT_WRITE", "NET_BIND_SERVICE"}
	// RelayCapabilities are the capabilities the separated relay keeps.
	RelayCapabilities = []string{"KILL", "SETGID", "SETUID"}
	// SubstrateDefaultCapabilities are an actor container's capabilities
	// when its template asks for no adjustment (Substrate v1.0.0).
	SubstrateDefaultCapabilities = []string{"AUDIT_WRITE", "KILL", "NET_BIND_SERVICE"}
)

// SystemDirs are the folders a data mount never goes in (GAP-0441):
// admission refuses a mount path in one (a WORKDIR there admits no data
// mount).
var SystemDirs = []string{"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/usr", "/etc", "/proc", "/sys", "/dev",
	"/run", "/boot", "/var/run"}

// LoadDirs are the system folders whose files programs load, run or read
// at start (libraries, binaries, /etc/ld.so.preload, profiles): the relay
// refuses a data mount that resolves into one through a symlink in the
// image or an image volume, which admission cannot see (GAP-0576). /proc,
// /sys, /dev and /run hold the runtime's and the host's own mounts (the
// actor's /run/ate, a host's /run and /boot/efi in the relay's tests), so
// the relay leaves them, and /boot, to admission. RuntimeMountFiles are
// the files a container runtime binds into /etc.
var (
	LoadDirs          = []string{"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/usr", "/etc"}
	RuntimeMountFiles = []string{"/etc/hosts", "/etc/resolv.conf", "/etc/hostname"}
)

// InLoadDir reports whether the clean mount point p is in one of LoadDirs
// and is not a file the runtime binds.
func InLoadDir(p string) bool {
	if slices.Contains(RuntimeMountFiles, p) {
		return false
	}
	for _, d := range LoadDirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// ActorCapabilities is the capability set Substrate gives an actor
// container: the default, minus drop ("ALL" clears it), plus add; sorted.
func ActorCapabilities(add, drop []string) []string {
	set := map[string]bool{}
	for _, c := range SubstrateDefaultCapabilities {
		set[c] = true
	}
	for _, d := range drop {
		if d == "ALL" {
			set = map[string]bool{}
			break
		}
		delete(set, d)
	}
	for _, a := range add {
		set[a] = true
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
