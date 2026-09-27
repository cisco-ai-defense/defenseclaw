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

package openshell

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Local gateway service and configuration files, as the 0.1.1 package
// installs them.
const (
	// GatewayTOMLFile is read by openshell-gateway through XDG discovery.
	GatewayTOMLFile = "gateway.toml"
	// GatewayEnvFile is the systemd unit's EnvironmentFile.
	GatewayEnvFile = "gateway.env"
	// GatewayService is the systemd user unit.
	GatewayService = "openshell-gateway"
	// GatewayFormula is the Homebrew formula whose service runs the
	// gateway on macOS.
	GatewayFormula = "nvidia/openshell/openshell"
	// GatewayBinary validates configuration (`config preflight`).
	GatewayBinary = "openshell-gateway"
	// GatewayConfigVersion is the gateway.toml schema version 0.1.x reads.
	GatewayConfigVersion = 2

	// EnvTelemetryEnabled switches OpenShell's anonymous usage telemetry.
	EnvTelemetryEnabled = "OPENSHELL_TELEMETRY_ENABLED"
	// envGatewayConfig points the gateway at a different gateway.toml.
	envGatewayConfig = "OPENSHELL_GATEWAY_CONFIG"

	// Gateway settings that decide who can reach the gateway. The
	// variables override their gateway.toml counterparts.
	envDisableTLS     = "OPENSHELL_DISABLE_TLS"
	envEnableMTLSAuth = "OPENSHELL_ENABLE_MTLS_AUTH"
	envOIDCIssuer     = "OPENSHELL_OIDC_ISSUER"
	envBindAddress    = "OPENSHELL_BIND_ADDRESS"
	envServerPort     = "OPENSHELL_SERVER_PORT"
	// defaultGatewayPort is where the package gateway listens.
	defaultGatewayPort = 17670

	// restartPendingFile marks configuration DefenseClaw wrote that the
	// gateway has not been restarted on yet. It lives in the config
	// directory and survives a crash between the write and the restart.
	restartPendingFile = ".defenseclaw-restart-pending"

	maxGatewayFileBytes = 1 << 20
)

// Gateway configuration errors.
var (
	// ErrConfigChanged means a file changed between Plan and Apply.
	ErrConfigChanged = errors.New("openshell: gateway configuration changed since it was planned")
	// ErrPreflight means `openshell-gateway config preflight` rejected the
	// configuration. Nothing was written.
	ErrPreflight = errors.New("openshell: gateway configuration failed preflight")
	// ErrGatewayMismatch means the gateway service is not the one
	// DefenseClaw configures: the service reads another gateway.env or
	// gateway.toml than DefenseClaw would edit (XDG_CONFIG_HOME differs
	// between this process and the systemd user manager, for instance), or
	// the registration reaches another port than the service listens on.
	ErrGatewayMismatch = errors.New("openshell: the gateway service does not match DefenseClaw's view of it")
)

var (
	dockerDriverTable      = []string{"openshell", "drivers", "docker"}
	resourceAdmissionTable = []string{"openshell", "drivers", "docker", "resource_admission"}
)

// bindMountSettings let the docker driver honor the bind mounts DefenseClaw
// requests through SandboxTemplate.DriverConfig. Resource admission is off
// because 0.1.1 admission rejects driver-config mounts.
var bindMountSettings = []tomlSetting{
	{Table: dockerDriverTable, Key: "allow_driver_config", Value: true},
	{Table: dockerDriverTable, Key: "enable_bind_mounts", Value: true},
	{Table: resourceAdmissionTable, Key: "enabled", Value: false},
}

// GatewayConfigurator reads and changes the local gateway's configuration
// and restarts its service. Changes follow plan, consent, apply: Plan
// computes the exact new file contents, the caller shows them and asks,
// and Apply validates, backs up, writes, restarts and verifies, rolling
// everything back when the restarted gateway does not come up healthy.
type GatewayConfigurator struct {
	// Dir is the OpenShell user config directory (default UserConfigDir).
	// The first call replaces it with the directory it resolves to, so a
	// symlinked config directory works and every file, backup and
	// preflight copy lives in the real one.
	Dir string
	// GOOS selects the service manager (default runtime.GOOS).
	GOOS   string
	Runner Runner
	// Gateway is the openshell-gateway binary (default GatewayBinary).
	Gateway string
	// Discover selects the registration that must be usable before bind
	// mounts are enabled and that VerifyGateway checks. Its ConfigDir
	// defaults to Dir.
	Discover DiscoverOptions
	// VerifyGateway waits for the restarted gateway (default
	// WaitForGateway with RestartWait).
	VerifyGateway func(context.Context) error
	// ProbeClientAuth checks that the gateway refuses a client without a
	// certificate, before bind mounts are enabled and again once the
	// gateway runs with them (default ProbeClientAuth).
	ProbeClientAuth func(context.Context, *Registration) error
	RestartWait     time.Duration
	Now             func() time.Time
}

func (g *GatewayConfigurator) defaults() error {
	dir := g.Dir
	if dir == "" {
		var err error
		if dir, err = UserConfigDir(); err != nil {
			return err
		}
	}
	dir, err := resolveConfigDir(dir)
	if err != nil {
		return err
	}
	g.Dir = dir
	if g.Discover.ConfigDir == "" {
		g.Discover.ConfigDir = g.Dir
	}
	if g.GOOS == "" {
		g.GOOS = runtime.GOOS
	}
	if g.Runner == nil {
		g.Runner = ExecRunner{}
	}
	if g.Gateway == "" {
		g.Gateway = GatewayBinary
	}
	if g.RestartWait <= 0 {
		g.RestartWait = 90 * time.Second
	}
	if g.VerifyGateway == nil {
		g.VerifyGateway = func(ctx context.Context) error { return WaitForGateway(ctx, g.Discover, g.RestartWait) }
	}
	if g.ProbeClientAuth == nil {
		g.ProbeClientAuth = ProbeClientAuth
	}
	if g.Now == nil {
		g.Now = time.Now
	}
	return nil
}

// EnvPath is the gateway.env the service reads.
func (g *GatewayConfigurator) EnvPath() (string, error) {
	if err := g.defaults(); err != nil {
		return "", err
	}
	return filepath.Join(g.Dir, GatewayEnvFile), nil
}

// TOMLPath is the gateway.toml the service reads: OPENSHELL_GATEWAY_CONFIG
// from gateway.env when it names an absolute path (its directory
// resolved like Dir), else Dir/gateway.toml.
func (g *GatewayConfigurator) TOMLPath() (string, error) {
	envPath, err := g.EnvPath()
	if err != nil {
		return "", err
	}
	data, _, err := readGatewayFile(envPath)
	if err != nil {
		return "", err
	}
	if p := parseEnvFile(data)[envGatewayConfig]; p != "" && filepath.IsAbs(p) {
		return resolveFilePath(filepath.Clean(p))
	}
	return filepath.Join(g.Dir, GatewayTOMLFile), nil
}

// BindMounts is the docker driver's bind-mount configuration.
type BindMounts struct {
	AllowDriverConfig bool `json:"allow_driver_config"`
	EnableBindMounts  bool `json:"enable_bind_mounts"`
	// ResourceAdmission is the resource_admission.enabled flag; OpenShell
	// enables it by default.
	ResourceAdmission bool `json:"resource_admission"`
}

// Enabled reports whether sandboxes can be created with bind mounts.
func (b BindMounts) Enabled() bool {
	return b.AllowDriverConfig && b.EnableBindMounts && !b.ResourceAdmission
}

// GatewayConfigState is the gateway's on-disk configuration.
type GatewayConfigState struct {
	TOMLPath    string            `json:"toml_path"`
	TOMLExists  bool              `json:"toml_exists"`
	TOMLModTime time.Time         `json:"toml_mtime"`
	BindMounts  BindMounts        `json:"bind_mounts"`
	EnvPath     string            `json:"env_path"`
	EnvExists   bool              `json:"env_exists"`
	EnvModTime  time.Time         `json:"env_mtime"`
	Env         map[string]string `json:"env"`
	// RestartPendingSince is when DefenseClaw wrote configuration the
	// gateway has not been restarted on (zero: none).
	RestartPendingSince time.Time `json:"restart_pending_since"`
	// server holds the gateway.toml listener and authentication settings.
	server gatewayServer
}

// gatewayServer is the [openshell.gateway] part of gateway.toml that
// decides who can reach the gateway.
type gatewayServer struct {
	// BindAddress is "ip:port".
	BindAddress string `toml:"bind_address"`
	DisableTLS  *bool  `toml:"disable_tls"`
	MTLSAuth    struct {
		Enabled *bool `toml:"enabled"`
	} `toml:"mtls_auth"`
	OIDC struct {
		Issuer string `toml:"issuer"`
	} `toml:"oidc"`
	Auth struct {
		AllowUnauthenticatedUsers *bool `toml:"allow_unauthenticated_users"`
	} `toml:"auth"`
}

// TelemetryEnabled reports whether OpenShell's usage telemetry is on (the
// upstream default unless gateway.env turns it off).
func (s *GatewayConfigState) TelemetryEnabled() bool {
	v, ok := s.Env[EnvTelemetryEnabled]
	if !ok {
		return true
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	return err != nil || b
}

// Read loads gateway.toml and gateway.env. Missing files are not errors.
func (g *GatewayConfigurator) Read() (*GatewayConfigState, error) {
	envPath, err := g.EnvPath()
	if err != nil {
		return nil, err
	}
	tomlPath, err := g.TOMLPath()
	if err != nil {
		return nil, err
	}
	st := &GatewayConfigState{TOMLPath: tomlPath, EnvPath: envPath, BindMounts: BindMounts{ResourceAdmission: true}}
	envData, envInfo, err := readGatewayFile(envPath)
	if err != nil {
		return nil, err
	}
	st.Env = parseEnvFile(envData)
	if envInfo != nil {
		st.EnvExists, st.EnvModTime = true, envInfo.ModTime()
	}
	if info, err := os.Lstat(g.restartPendingPath()); err == nil && info.Mode().IsRegular() {
		st.RestartPendingSince = info.ModTime()
	}
	tomlData, tomlInfo, err := readGatewayFile(tomlPath)
	if err != nil {
		return nil, err
	}
	if tomlInfo == nil {
		return st, nil
	}
	st.TOMLExists, st.TOMLModTime = true, tomlInfo.ModTime()
	var doc struct {
		OpenShell struct {
			Gateway gatewayServer `toml:"gateway"`
			Drivers struct {
				Docker struct {
					AllowDriverConfig bool `toml:"allow_driver_config"`
					EnableBindMounts  bool `toml:"enable_bind_mounts"`
					ResourceAdmission struct {
						Enabled *bool `toml:"enabled"`
					} `toml:"resource_admission"`
				} `toml:"docker"`
			} `toml:"drivers"`
		} `toml:"openshell"`
	}
	if err := toml.Unmarshal(tomlData, &doc); err != nil {
		return st, fmt.Errorf("openshell: parse %s: %w", tomlPath, err)
	}
	st.server = doc.OpenShell.Gateway
	d := doc.OpenShell.Drivers.Docker
	st.BindMounts = BindMounts{AllowDriverConfig: d.AllowDriverConfig, EnableBindMounts: d.EnableBindMounts, ResourceAdmission: true}
	if d.ResourceAdmission.Enabled != nil {
		st.BindMounts.ResourceAdmission = *d.ResourceAdmission.Enabled
	}
	return st, nil
}

// GatewayChanges are the configuration changes setup asks for.
type GatewayChanges struct {
	// EnableBindMounts turns on docker-driver bind mounts. They let a
	// sandbox mount any host path through the gateway's root Docker
	// daemon, so Plan and Apply refuse them unless only the caller, over
	// mTLS, can reach the gateway: the registration passes Discover and
	// reaches the service's port, the service's settings keep TLS client
	// authentication on and the listener on loopback, and the gateway
	// turns away a client without a certificate (ProbeClientAuth).
	EnableBindMounts bool
	// Env sets gateway.env entries (e.g. EnvTelemetryEnabled=false). The
	// plan summary prints the values, so they must not be secrets.
	Env map[string]string
	// UnsetEnv removes gateway.env entries.
	UnsetEnv []string
}

// FileChange is one file's planned content.
type FileChange struct {
	Path string `json:"path"`
	// Before is nil when the file does not exist yet.
	Before []byte `json:"-"`
	After  []byte `json:"-"`
	// TOML marks gateway.toml, which is preflighted before it is written.
	TOML bool `json:"toml"`
	// Summary lists the settings changed.
	Summary []string `json:"summary"`
}

// GatewayPlan is exactly what Apply will write. Files that would not
// change are left out; an empty plan needs neither consent nor a restart.
type GatewayPlan struct {
	Files []*FileChange `json:"files"`
	// Restart names how the gateway will be restarted.
	Restart string `json:"restart"`
}

// Empty reports whether nothing would change.
func (p *GatewayPlan) Empty() bool { return p == nil || len(p.Files) == 0 }

// String renders the plan with a line diff of each file.
func (p *GatewayPlan) String() string {
	if p.Empty() {
		return "OpenShell gateway configuration is already up to date\n"
	}
	var b strings.Builder
	b.WriteString("OpenShell gateway configuration changes\n")
	for _, f := range p.Files {
		if f.Before == nil {
			fmt.Fprintf(&b, "  create %s\n", f.Path)
		} else {
			fmt.Fprintf(&b, "  edit %s (a timestamped backup is kept)\n", f.Path)
		}
		for _, s := range f.Summary {
			fmt.Fprintf(&b, "    set %s\n", s)
		}
		if !f.TOML {
			// gateway.env may hold credentials: show only the summary.
			continue
		}
		for _, l := range lineDiff(string(f.Before), string(f.After)) {
			fmt.Fprintf(&b, "      %s\n", strings.TrimRight(l, " "))
		}
	}
	fmt.Fprintf(&b, "  then restart the gateway (%s); running sandboxes restart with it\n", p.Restart)
	return b.String()
}

// Plan computes the changes without touching anything. On Linux it first
// checks that the gateway service reads the files it would edit.
func (g *GatewayConfigurator) Plan(ctx context.Context, ch GatewayChanges) (*GatewayPlan, error) {
	if err := g.defaults(); err != nil {
		return nil, err
	}
	plan := &GatewayPlan{Restart: strings.Join(g.restartCommand().argv(), " ")}
	if !ch.EnableBindMounts && len(ch.Env) == 0 && len(ch.UnsetEnv) == 0 {
		return plan, nil
	}
	env, err := g.serviceEnvironment(ctx)
	if err != nil {
		return nil, err
	}
	if ch.EnableBindMounts {
		if err := g.requirePrivateGateway(ctx, env); err != nil {
			return nil, err
		}
		path, err := g.TOMLPath()
		if err != nil {
			return nil, err
		}
		before, info, err := readGatewayFile(path)
		if err != nil {
			return nil, err
		}
		src := before
		if info == nil {
			before = nil
			src = []byte(fmt.Sprintf("# OpenShell gateway configuration.\n\n[openshell]\nversion = %d\n", GatewayConfigVersion))
		}
		after, err := editTOML(src, bindMountSettings)
		if err != nil {
			return nil, fmt.Errorf("openshell: %s: %w", path, err)
		}
		if info == nil || !bytes.Equal(before, after) {
			fc := &FileChange{Path: path, Before: before, After: after, TOML: true}
			var current map[string]any
			_ = toml.Unmarshal(src, &current)
			for _, s := range bindMountSettings {
				if v, ok := lookupTOML(current, s.Table, s.Key); !ok || v != s.Value {
					fc.Summary = append(fc.Summary, s.String())
				}
			}
			plan.Files = append(plan.Files, fc)
		}
	}
	if len(ch.Env) > 0 || len(ch.UnsetEnv) > 0 {
		path, err := g.EnvPath()
		if err != nil {
			return nil, err
		}
		before, info, err := readGatewayFile(path)
		if err != nil {
			return nil, err
		}
		if info == nil {
			before = nil
		}
		after, summary, err := editEnvFile(before, ch.Env, ch.UnsetEnv)
		if err != nil {
			return nil, fmt.Errorf("openshell: %s: %w", path, err)
		}
		if !bytes.Equal(before, after) {
			plan.Files = append(plan.Files, &FileChange{Path: path, Before: before, After: after, Summary: summary})
		}
	}
	return plan, nil
}

// AppliedFile records one written file for Rollback.
type AppliedFile struct {
	Path string `json:"path"`
	// Backup holds the previous content; empty when the file was created.
	Backup string `json:"backup,omitempty"`
}

// GatewayApplyResult reports what Apply did.
type GatewayApplyResult struct {
	Files     []AppliedFile `json:"files"`
	Restarted bool          `json:"restarted"`
}

// Apply writes the plan, restarts the gateway and waits for it. A file
// that changed since Plan, a TOML preflight failure, an unsafe path or a
// gateway that fails Plan's checks aborts before anything is written.
// When the restart or the health check fails, or the restarted gateway
// with bind mounts no longer turns away a client without a certificate,
// the previous files are restored and the gateway restarted again.
func (g *GatewayConfigurator) Apply(ctx context.Context, plan *GatewayPlan) (*GatewayApplyResult, error) {
	if err := g.defaults(); err != nil {
		return nil, err
	}
	res := &GatewayApplyResult{}
	if plan.Empty() {
		return res, nil
	}
	env, err := g.serviceEnvironment(ctx)
	if err != nil {
		return nil, err
	}
	// gateway.toml changes only enable bind mounts.
	mounts := slices.ContainsFunc(plan.Files, func(f *FileChange) bool { return f.TOML })
	if mounts {
		if err := g.requirePrivateGateway(ctx, env); err != nil {
			return nil, err
		}
	}
	for _, f := range plan.Files {
		current, info, err := readGatewayFile(f.Path)
		if err != nil {
			return nil, err
		}
		if (info == nil) != (f.Before == nil) || (info != nil && !bytes.Equal(current, f.Before)) {
			return nil, fmt.Errorf("%w: %s", ErrConfigChanged, f.Path)
		}
		if f.TOML {
			if err := g.preflight(ctx, f); err != nil {
				return nil, err
			}
		}
	}
	if err := g.markRestartPending(); err != nil {
		return nil, err
	}
	for _, f := range plan.Files {
		applied := AppliedFile{Path: f.Path}
		if f.Before != nil {
			backup, err := g.backup(f.Path, f.Before)
			if err != nil {
				return res, g.rollbackAfter(ctx, res, err, false)
			}
			applied.Backup = backup
		}
		if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
			return res, g.rollbackAfter(ctx, res, fmt.Errorf("openshell: create %s: %w", filepath.Dir(f.Path), err), false)
		}
		if err := safefile.Write(f.Path, f.After); err != nil {
			return res, g.rollbackAfter(ctx, res, fmt.Errorf("openshell: write %s: %w", f.Path, err), false)
		}
		res.Files = append(res.Files, applied)
	}
	if err := g.Restart(ctx); err != nil {
		return res, g.rollbackAfter(ctx, res, err, true)
	}
	if mounts {
		// Check again against the gateway that now honours bind mounts.
		if err := g.requirePrivateGateway(ctx, env); err != nil {
			return res, g.rollbackAfter(ctx, res, err, true)
		}
	}
	res.Restarted = true
	return res, nil
}

// ErrBindMountsRefused means bind mounts were not enabled because someone
// other than the caller might reach the gateway: its registration is
// unusable (a plaintext gateway, files other users can change), points at
// another gateway than the service DefenseClaw configures, or the
// service's settings or a probe show that it lets in clients without the
// registration's certificate.
var ErrBindMountsRefused = errors.New("openshell: refusing to enable bind mounts")

// requirePrivateGateway refuses bind mounts unless only the caller can
// drive the gateway. env is the service's environment (nil when unknown).
func (g *GatewayConfigurator) requirePrivateGateway(ctx context.Context, env map[string]string) error {
	refuse := func(err error) error {
		return fmt.Errorf("%w: the gateway must be reachable only by you over mTLS: %w", ErrBindMountsRefused, err)
	}
	reg, err := Discover(g.Discover)
	if err != nil {
		return refuse(err)
	}
	st, err := g.Read()
	if err != nil {
		return err
	}
	if err := gatewayExposure(reg, st, env); err != nil {
		return refuse(err)
	}
	if err := g.ProbeClientAuth(ctx, reg); err != nil {
		return refuse(err)
	}
	return nil
}

// gatewayExposure checks the settings the gateway service starts with:
// env (the service's environment, nil when unknown) overrides gateway.toml,
// as it does for the gateway. It returns ErrGatewayExposed for settings
// that let in clients without the registration's certificate or listen
// beyond loopback, and ErrGatewayMismatch when the registration reaches
// another port than the service listens on.
func gatewayExposure(reg *Registration, st *GatewayConfigState, env map[string]string) error {
	s := st.server
	var issues []string
	if v, ok := env[envDisableTLS]; ok && envFlag(v) || !ok && s.DisableTLS != nil && *s.DisableTLS {
		issues = append(issues, "TLS is disabled ("+envDisableTLS+" or disable_tls)")
	}
	if v, ok := env[envEnableMTLSAuth]; ok && strings.EqualFold(strings.TrimSpace(v), "false") || !ok && s.MTLSAuth.Enabled != nil && !*s.MTLSAuth.Enabled {
		issues = append(issues, "client certificate authentication is off ("+envEnableMTLSAuth+" or [openshell.gateway.mtls_auth] enabled)")
	}
	if v := strings.TrimSpace(env[envOIDCIssuer]); v != "" || s.OIDC.Issuer != "" {
		issues = append(issues, "OIDC authentication is configured ("+envOIDCIssuer+" or [openshell.gateway.oidc] issuer)")
	}
	if a := s.Auth.AllowUnauthenticatedUsers; a != nil && *a {
		issues = append(issues, "[openshell.gateway.auth] allow_unauthenticated_users is on")
	}
	host, port := "127.0.0.1", strconv.Itoa(defaultGatewayPort)
	if s.BindAddress != "" {
		h, p, err := net.SplitHostPort(s.BindAddress)
		if err != nil {
			return fmt.Errorf("%w: bind_address %q in %s is not ip:port", ErrGatewayMismatch, s.BindAddress, st.TOMLPath)
		}
		host, port = h, p
	}
	if v, ok := env[envBindAddress]; ok {
		host = strings.TrimSpace(v)
	}
	if v, ok := env[envServerPort]; ok {
		port = strings.TrimSpace(v)
	}
	if !isLoopbackHost(host) {
		issues = append(issues, fmt.Sprintf("the gateway listens on %q, beyond this machine", host))
	}
	if len(issues) > 0 {
		return fmt.Errorf("%w: %s", ErrGatewayExposed, strings.Join(issues, "; "))
	}
	if _, regPort, err := net.SplitHostPort(reg.Target()); err != nil || regPort != port {
		return fmt.Errorf("%w: registration %s reaches %s, but the %s service listens on port %s", ErrGatewayMismatch, reg.Name, reg.Endpoint, GatewayService, port)
	}
	return nil
}

// envFlag reads a boolean flag variable the way the gateway's command
// line parser does: anything but an empty or false-like value is true.
func envFlag(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "f", "false", "n", "no", "off":
		return false
	}
	return true
}

// rollbackAfter restores what Apply wrote after cause, restarting the
// gateway again when it was already restarted with the new files.
func (g *GatewayConfigurator) rollbackAfter(ctx context.Context, res *GatewayApplyResult, cause error, restart bool) error {
	if err := g.restore(res); err != nil {
		return fmt.Errorf("%w; restoring the previous configuration also failed: %v", cause, err)
	}
	if restart {
		if err := g.Restart(ctx); err != nil {
			return fmt.Errorf("%w; the previous configuration was restored but the gateway did not come back: %v", cause, err)
		}
	} else {
		// The gateway never saw the new files; the restored ones are what it runs.
		g.clearRestartPending()
	}
	return fmt.Errorf("%w (the previous configuration was restored)", cause)
}

// Rollback restores the files an Apply wrote and restarts the gateway.
func (g *GatewayConfigurator) Rollback(ctx context.Context, res *GatewayApplyResult) error {
	if err := g.defaults(); err != nil {
		return err
	}
	if res == nil || len(res.Files) == 0 {
		return nil
	}
	if err := g.markRestartPending(); err != nil {
		return err
	}
	if err := g.restore(res); err != nil {
		return err
	}
	return g.Restart(ctx)
}

func (g *GatewayConfigurator) restartPendingPath() string {
	return filepath.Join(g.Dir, restartPendingFile)
}

// markRestartPending records, before configuration is written, that the
// gateway must be restarted on it; Restart clears the mark. Doctor reads
// it on every platform, including Homebrew, which reports no start time.
func (g *GatewayConfigurator) markRestartPending() error {
	if err := os.MkdirAll(g.Dir, 0o700); err != nil {
		return fmt.Errorf("openshell: create %s: %w", g.Dir, err)
	}
	stamp := g.Now().UTC().Format(time.RFC3339Nano) + "\n"
	if err := safefile.Write(g.restartPendingPath(), []byte(stamp)); err != nil {
		return fmt.Errorf("openshell: record the pending gateway restart: %w", err)
	}
	return nil
}

func (g *GatewayConfigurator) clearRestartPending() {
	_ = os.Remove(g.restartPendingPath())
}

func (g *GatewayConfigurator) restore(res *GatewayApplyResult) error {
	var errs []error
	for i := len(res.Files) - 1; i >= 0; i-- {
		f := res.Files[i]
		if f.Backup == "" {
			if err := os.Remove(f.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		data, err := safefile.ReadRegularFileBounded(f.Backup, maxGatewayFileBytes)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := safefile.Write(f.Path, data); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// preflight validates the candidate gateway.toml with the gateway's own
// parser, from a private temporary file next to the target.
func (g *GatewayConfigurator) preflight(ctx context.Context, f *FileChange) error {
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("openshell: create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".defenseclaw-preflight-*.toml")
	if err != nil {
		return fmt.Errorf("openshell: preflight: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(f.After); err != nil {
		tmp.Close()
		return fmt.Errorf("openshell: preflight: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("openshell: preflight: %w", err)
	}
	out, err := g.Runner.Output(ctx, Command{Name: g.Gateway, Args: []string{"config", "preflight", "--path", name}, Timeout: time.Minute})
	if err == nil {
		return nil
	}
	detail := strings.TrimSpace(string(out))
	if f.Before != nil {
		if _, origErr := g.Runner.Output(ctx, Command{Name: g.Gateway, Args: []string{"config", "preflight", "--path", f.Path}, Timeout: time.Minute}); origErr != nil {
			return fmt.Errorf("%w: %s already fails preflight before DefenseClaw's change; fix or migrate it first: %s", ErrPreflight, f.Path, detail)
		}
	}
	return fmt.Errorf("%w: DefenseClaw's change to %s: %s (%v)", ErrPreflight, f.Path, detail, err)
}

func (g *GatewayConfigurator) backup(path string, data []byte) (string, error) {
	stamp := g.Now().UTC().Format("20060102T150405Z")
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("%s.defenseclaw-%s.bak", path, stamp)
		if i > 0 {
			name = fmt.Sprintf("%s.defenseclaw-%s-%d.bak", path, stamp, i)
		}
		f, err := safefile.CreateExclusive(name)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("openshell: back up %s: %w", path, err)
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return "", fmt.Errorf("openshell: back up %s: %w", path, err)
		}
		if err := f.Close(); err != nil {
			return "", fmt.Errorf("openshell: back up %s: %w", path, err)
		}
		return name, nil
	}
	return "", fmt.Errorf("openshell: back up %s: too many backups this second", path)
}

type serviceCommand struct {
	name string
	args []string
}

func (c serviceCommand) argv() []string { return append([]string{c.name}, c.args...) }

func (g *GatewayConfigurator) restartCommand() serviceCommand {
	if g.GOOS == "darwin" {
		return serviceCommand{"brew", []string{"services", "restart", GatewayFormula}}
	}
	return serviceCommand{"systemctl", []string{"--user", "restart", GatewayService}}
}

// Restart restarts the gateway service and waits until it is healthy.
func (g *GatewayConfigurator) Restart(ctx context.Context) error {
	if err := g.defaults(); err != nil {
		return err
	}
	c := g.restartCommand()
	if out, err := g.Runner.Output(ctx, Command{Name: c.name, Args: c.args, Timeout: 2 * time.Minute}); err != nil {
		return fmt.Errorf("openshell: restart the gateway: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if err := g.VerifyGateway(ctx); err != nil {
		return fmt.Errorf("openshell: the restarted gateway is not healthy: %w", err)
	}
	g.clearRestartPending()
	return nil
}

// ServiceState is the gateway service as its manager reports it.
type ServiceState struct {
	Manager string `json:"manager"`
	Unit    string `json:"unit"`
	// Installed is false when the manager does not know the service.
	Installed bool `json:"installed"`
	Active    bool `json:"active"`
	// Enabled reports whether the service starts at login. A unit that is
	// only linked, or enabled until the next reboot, does not.
	Enabled bool   `json:"enabled"`
	Status  string `json:"status"`
	// StartedAt is when the service last became active, to the
	// microsecond (zero: unknown, as under Homebrew).
	StartedAt time.Time `json:"started_at"`
	// EnvironmentFiles are the files systemd loads the service's
	// environment from, in order (systemd only).
	EnvironmentFiles []string `json:"environment_files,omitempty"`
	// Environment is what the service starts with before its
	// EnvironmentFiles: the user manager's environment overlaid with the
	// unit's Environment= settings, limited to HOME, XDG_CONFIG_HOME and
	// OPENSHELL_* (systemd only). Values may be sensitive.
	Environment map[string]string `json:"-"`
}

// systemdTimestamp is how `systemctl show --timestamp=us+utc` prints a
// time.
const systemdTimestamp = "Mon 2006-01-02 15:04:05.000000 MST"

// ServiceState asks systemd (Linux) or Homebrew (macOS) about the gateway.
func (g *GatewayConfigurator) ServiceState(ctx context.Context) (*ServiceState, error) {
	if err := g.defaults(); err != nil {
		return nil, err
	}
	if g.GOOS == "darwin" {
		return g.brewServiceState(ctx)
	}
	st := &ServiceState{Manager: "systemd", Unit: GatewayService}
	out, err := g.Runner.Output(ctx, Command{Name: "systemctl", Args: []string{"--user", "show", GatewayService, "--timestamp=us+utc",
		"-p", "LoadState,ActiveState,SubState,UnitFileState,ActiveEnterTimestamp,Environment,EnvironmentFiles"}, Timeout: 30 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("openshell: systemctl --user show %s: %v: %s", GatewayService, err, strings.TrimSpace(string(out)))
	}
	props := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		if k == "EnvironmentFiles" {
			// One line per file: "<path> (ignore_errors=yes)".
			if p, _, _ := strings.Cut(v, " (ignore_errors="); p != "" {
				st.EnvironmentFiles = append(st.EnvironmentFiles, p)
			}
			continue
		}
		props[k] = v
	}
	st.Installed = props["LoadState"] == "loaded"
	st.Active = props["ActiveState"] == "active"
	// Only "enabled" survives a reboot: "linked" units have no Wants
	// symlink, and "enabled-runtime" ones lose theirs with /run.
	st.Enabled = props["UnitFileState"] == "enabled"
	st.Status = strings.TrimSpace(props["ActiveState"] + " (" + props["SubState"] + ")")
	if t, err := time.Parse(systemdTimestamp, props["ActiveEnterTimestamp"]); err == nil {
		st.StartedAt = t
	}
	if st.Environment, err = g.managerEnvironment(ctx); err != nil {
		return nil, err
	}
	for _, kv := range splitSystemdWords(props["Environment"]) {
		if k, v, ok := strings.Cut(kv, "="); ok && serviceEnvKey(k) {
			st.Environment[k] = v
		}
	}
	return st, nil
}

// managerEnvironment reads the systemd user manager's environment, which
// every user service inherits.
func (g *GatewayConfigurator) managerEnvironment(ctx context.Context) (map[string]string, error) {
	out, err := g.Runner.Output(ctx, Command{Name: "systemctl", Args: []string{"--user", "show-environment"}, Timeout: 30 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("openshell: systemctl --user show-environment: %v: %s", err, strings.TrimSpace(string(out)))
	}
	env := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && serviceEnvKey(k) {
			env[k] = unquoteSystemdValue(v)
		}
	}
	return env, nil
}

// serviceEnvKey selects the variables that locate or configure the
// gateway.
func serviceEnvKey(k string) bool {
	return k == "HOME" || k == "XDG_CONFIG_HOME" || strings.HasPrefix(k, "OPENSHELL_")
}

// unquoteSystemdValue undoes the $'...' quoting show-environment applies
// to values with special characters.
func unquoteSystemdValue(v string) string {
	if len(v) < 3 || !strings.HasPrefix(v, "$'") || !strings.HasSuffix(v, "'") {
		return v
	}
	inner := v[2 : len(v)-1]
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c == '\\' && i+1 < len(inner) {
			i++
			switch inner[i] {
			case 'n':
				c = '\n'
			case 't':
				c = '\t'
			default:
				c = inner[i]
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// splitSystemdWords splits a `systemctl show` string list: words are
// separated by spaces and double-quoted, with backslash escapes, when they
// contain special characters.
func splitSystemdWords(s string) []string {
	var words []string
	var b strings.Builder
	inWord, quoted := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && quoted && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		case c == '"':
			quoted, inWord = !quoted, true
		case c == ' ' && !quoted:
			if inWord {
				words = append(words, b.String())
				b.Reset()
				inWord = false
			}
		default:
			b.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, b.String())
	}
	return words
}

// serviceEnvironment checks that the gateway service reads the files
// DefenseClaw edits and returns the environment it starts with. Under
// Homebrew it returns nil: launchd does not read gateway.env.
func (g *GatewayConfigurator) serviceEnvironment(ctx context.Context) (map[string]string, error) {
	if g.GOOS == "darwin" {
		return nil, nil
	}
	svc, err := g.ServiceState(ctx)
	if err != nil {
		return nil, err
	}
	return g.serviceEnv(svc)
}

// serviceEnv merges the service's environment the way systemd does (the
// manager's, then Environment=, then each EnvironmentFile in order) and
// returns ErrGatewayMismatch unless the unit reads EnvPath and resolves
// gateway.toml to TOMLPath.
func (g *GatewayConfigurator) serviceEnv(svc *ServiceState) (map[string]string, error) {
	if err := g.defaults(); err != nil {
		return nil, err
	}
	if g.GOOS == "darwin" {
		return nil, nil
	}
	if svc == nil {
		return nil, errors.New("openshell: the gateway service's state is unknown")
	}
	if !svc.Installed {
		return nil, fmt.Errorf("openshell: the %s user service is not installed", GatewayService)
	}
	envPath, err := g.EnvPath()
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	for k, v := range svc.Environment {
		env[k] = v
	}
	reads := false
	for _, file := range svc.EnvironmentFiles {
		path, err := resolveFilePath(file)
		if err != nil {
			return nil, err
		}
		var data []byte
		if path == envPath {
			reads = true
			data, _, err = readGatewayFile(path)
		} else if data, err = safefile.ReadRegularFileBounded(path, maxGatewayFileBytes); errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			// The user manager cannot read it either.
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("openshell: the %s service's environment file: %w", GatewayService, err)
		}
		for k, v := range parseEnvFile(data) {
			env[k] = v
		}
	}
	if !reads {
		files := "no file"
		if len(svc.EnvironmentFiles) > 0 {
			files = strings.Join(svc.EnvironmentFiles, ", ")
		}
		return nil, fmt.Errorf("%w: the %s service reads its environment from %s, not %s; run DefenseClaw with the XDG_CONFIG_HOME the systemd user manager uses",
			ErrGatewayMismatch, GatewayService, files, envPath)
	}
	tomlPath, err := g.TOMLPath()
	if err != nil {
		return nil, err
	}
	serviceTOML, err := serviceTOMLPath(env)
	if err != nil {
		return nil, err
	}
	if serviceTOML != tomlPath {
		return nil, fmt.Errorf("%w: the %s service reads %s, not %s; set %s in %s or run DefenseClaw with the XDG_CONFIG_HOME the systemd user manager uses",
			ErrGatewayMismatch, GatewayService, serviceTOML, tomlPath, envGatewayConfig, envPath)
	}
	return env, nil
}

// serviceTOMLPath is the gateway.toml the service loads: the absolute
// OPENSHELL_GATEWAY_CONFIG, else XDG discovery in its environment.
func serviceTOMLPath(env map[string]string) (string, error) {
	if p := env[envGatewayConfig]; p != "" && filepath.IsAbs(p) {
		return resolveFilePath(filepath.Clean(p))
	}
	base := env["XDG_CONFIG_HOME"]
	if !filepath.IsAbs(base) {
		home := env["HOME"]
		if !filepath.IsAbs(home) {
			return "", fmt.Errorf("openshell: the systemd user manager has no absolute HOME or XDG_CONFIG_HOME, so the %s service's gateway.toml is unknown", GatewayService)
		}
		base = filepath.Join(home, ".config")
	}
	return resolveFilePath(filepath.Join(base, "openshell", GatewayTOMLFile))
}

// resolveFilePath resolves the links in a file's directory.
func resolveFilePath(p string) (string, error) {
	dir, err := resolveConfigDir(filepath.Dir(p))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(p)), nil
}

func (g *GatewayConfigurator) brewServiceState(ctx context.Context) (*ServiceState, error) {
	st := &ServiceState{Manager: "brew", Unit: GatewayFormula}
	out, err := g.Runner.Output(ctx, Command{Name: "brew", Args: []string{"services", "info", GatewayFormula, "--json"}, Timeout: time.Minute})
	if err != nil {
		return nil, fmt.Errorf("openshell: brew services info %s: %v: %s", GatewayFormula, err, strings.TrimSpace(string(out)))
	}
	var infos []struct {
		Running    bool   `json:"running"`
		Loaded     bool   `json:"loaded"`
		Status     string `json:"status"`
		File       string `json:"file"`
		Registered bool   `json:"registered"`
	}
	if err := json.Unmarshal(out, &infos); err != nil || len(infos) == 0 {
		return nil, fmt.Errorf("openshell: brew services info %s: unexpected output %q", GatewayFormula, strings.TrimSpace(string(out)))
	}
	i := infos[0]
	st.Installed = i.File != "" || i.Loaded || i.Registered
	st.Active, st.Enabled, st.Status = i.Running, i.Loaded || i.Registered, i.Status
	return st, nil
}

// readGatewayFile reads a configuration file. A missing file returns nil
// data and nil info. Symlinks, non-regular files and files owned by
// another user are refused: the gateway runs as the caller, and editing
// through a link could redirect a write.
func readGatewayFile(path string) ([]byte, fs.FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("openshell: %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("openshell: %s is not a regular file", path)
	}
	if !ownedByCaller(info) {
		return nil, nil, fmt.Errorf("openshell: %s is owned by another user", path)
	}
	data, err := safefile.ReadRegularFileBounded(path, maxGatewayFileBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("openshell: read %s: %w", path, err)
	}
	return data, info, nil
}

var envAssignment = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$`)

// parseEnvFile reads systemd EnvironmentFile syntax: KEY=VALUE lines,
// '#' and ';' comments, optional single or double quotes. Later
// assignments win, as they do for systemd.
func parseEnvFile(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		m := envAssignment.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		out[m[1]] = unquoteEnvValue(strings.TrimSpace(m[2]))
	}
	return out
}

func unquoteEnvValue(v string) string {
	if len(v) >= 2 {
		switch {
		case v[0] == '\'' && v[len(v)-1] == '\'':
			return v[1 : len(v)-1]
		case v[0] == '"' && v[len(v)-1] == '"':
			var b strings.Builder
			inner := v[1 : len(v)-1]
			for i := 0; i < len(inner); i++ {
				if inner[i] == '\\' && i+1 < len(inner) {
					i++
				}
				b.WriteByte(inner[i])
			}
			return b.String()
		}
	}
	return v
}

var plainEnvValue = regexp.MustCompile(`^[A-Za-z0-9_./:,@%+=-]*$`)

func quoteEnvValue(v string) string {
	if plainEnvValue.MatchString(v) {
		return v
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(v) + `"`
}

// editEnvFile sets and unsets keys, keeping comments, order and unrelated
// lines. Every assignment of a set key is rewritten; unset keys lose all
// their assignments; new keys are appended.
func editEnvFile(src []byte, set map[string]string, unset []string) ([]byte, []string, error) {
	for k, v := range set {
		if !envKeyPattern.MatchString(k) {
			return nil, nil, fmt.Errorf("invalid variable name %q", k)
		}
		if strings.ContainsAny(v, "\x00\n\r") {
			return nil, nil, fmt.Errorf("variable %s contains a control character", k)
		}
	}
	drop := map[string]bool{}
	for _, k := range unset {
		if !envKeyPattern.MatchString(k) {
			return nil, nil, fmt.Errorf("invalid variable name %q", k)
		}
		if _, ok := set[k]; ok {
			return nil, nil, fmt.Errorf("variable %s is both set and unset", k)
		}
		drop[k] = true
	}
	current := parseEnvFile(src)
	var summary []string
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if old, ok := current[k]; !ok || old != set[k] {
			summary = append(summary, fmt.Sprintf("%s=%s", k, quoteEnvValue(set[k])))
		}
	}
	for _, k := range unset {
		if _, ok := current[k]; ok {
			summary = append(summary, "unset "+k)
		}
	}

	var lines []string
	if len(src) > 0 {
		lines = strings.Split(strings.TrimSuffix(string(src), "\n"), "\n")
	}
	seen := map[string]bool{}
	out := lines[:0]
	for _, line := range lines {
		m := envAssignment.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m != nil {
			if drop[m[1]] {
				continue
			}
			if v, ok := set[m[1]]; ok {
				line = m[1] + "=" + quoteEnvValue(v)
				seen[m[1]] = true
			}
		}
		out = append(out, line)
	}
	for _, k := range keys {
		if !seen[k] {
			out = append(out, k+"="+quoteEnvValue(set[k]))
		}
	}
	if len(out) == 0 {
		return []byte{}, summary, nil
	}
	return []byte(strings.Join(out, "\n") + "\n"), summary, nil
}

// lineDiff is a minimal LCS line diff ("- removed" before "+ added"),
// with unchanged lines omitted.
func lineDiff(a, b string) []string {
	x, y := splitLines(a), splitLines(b)
	n, m := len(x), len(y)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []string
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && x[i] == y[j]:
			i++
			j++
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			out = append(out, "- "+x[i])
			i++
		default:
			out = append(out, "+ "+y[j])
			j++
		}
	}
	return out
}

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, "\r")
	}
	return lines
}
