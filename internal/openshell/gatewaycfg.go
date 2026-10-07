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
	"maps"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Local gateway service and configuration files, as the 0.1.1 package
// installs them.
const (
	// GatewayTOMLFile is read by openshell-gateway through XDG discovery.
	GatewayTOMLFile = "gateway.toml"
	// GatewayEnvFile is the systemd unit's EnvironmentFile; the Homebrew
	// service's wrapper sources it too.
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

	// Gateway settings that select the compute driver and shape the
	// MicroVM (vm) driver's sandboxes. The variables override their
	// gateway.toml counterparts.
	envComputeDriver    = "OPENSHELL_COMPUTE_DRIVER"
	envVMSandboxUID     = "OPENSHELL_VM_SANDBOX_UID"
	envVMSandboxGID     = "OPENSHELL_VM_SANDBOX_GID"
	envVMVCPUs          = "OPENSHELL_VM_DRIVER_VCPUS"
	envVMMemMiB         = "OPENSHELL_VM_DRIVER_MEM_MIB"
	envVMOverlayDiskMiB = "OPENSHELL_VM_OVERLAY_DISK_MIB"
	envVMStateDir       = "OPENSHELL_VM_DRIVER_STATE_DIR"

	// restartPendingFile marks configuration DefenseClaw wrote that the
	// gateway has not been restarted on yet. It lives in the config
	// directory and survives a crash between the write and the restart.
	restartPendingFile = ".defenseclaw-restart-pending"
	// releaseRestartFile records a restart of the gateway service that
	// left a gateway of another release than the CLI (the doctor's
	// Gateway fix, releaseRestart), which the doctor does not offer again.
	releaseRestartFile = ".defenseclaw-release-restart"

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
	// ErrNoGatewayService means the service manager has no gateway
	// service to restart the gateway through: the gateway, where one
	// runs, runs another way (by hand, say), and its operator restarts it
	// on a change (Write). Rollback returns it once it has restored the
	// files.
	ErrNoGatewayService = errors.New("openshell: no gateway service runs the gateway")
)

// What the MicroVM (vm) driver gives every sandbox when
// [openshell.drivers.vm] and gateway.env do not say (OpenShell 0.1.1).
const (
	DefaultVMSandboxUID     = 1000
	DefaultVMSandboxGID     = 1000
	DefaultVMVCPUs          = 2
	DefaultVMMemMiB         = 2048
	DefaultVMOverlayDiskMiB = 4096
)

var (
	gatewayTable           = []string{"openshell", "gateway"}
	dockerDriverTable      = []string{"openshell", "drivers", "docker"}
	resourceAdmissionTable = []string{"openshell", "drivers", "docker", "resource_admission"}
	vmDriverTable          = []string{"openshell", "drivers", "vm"}
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
	// Gateway is the openshell-gateway binary that preflights gateway.toml
	// (default gatewayExecutable: the one on PATH, else the one next to the
	// OpenShell CLI).
	Gateway string
	// CLI is the OpenShell CLI (default DefaultBinary), whose directory
	// holds the gateway of an OpenShell whose prefix is not on PATH.
	CLI string
	// LookPath finds executables on PATH (default exec.LookPath).
	LookPath func(string) (string, error)
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
	// BrewFormulaInstalled reports whether Homebrew holds GatewayFormula
	// (default brewFormulaInstalled). ServiceState asks brew about the
	// service only then: `brew services info` can take most of a minute,
	// and a formula that is not installed has no service to report.
	BrewFormulaInstalled func() bool
	// BrewPrefix is the Homebrew prefix whose var/openshell holds the
	// Homebrew service's own gateway.env and gateway.toml, which it reads
	// when Dir has none (macOS; default homebrewPrefix).
	BrewPrefix string
	// RunningDriver asks the gateway which compute driver it runs, which
	// Apply checks after a restart that switches it (default: discover the
	// Discover registration, dial it and read GetGatewayInfo).
	RunningDriver func(context.Context) (Driver, error)
	// FlushSandboxes runs before every restart, which stops every sandbox
	// on the gateway: where the running driver's stop keeps nothing the
	// workload has not synced (the MicroVM driver), it flushes the disk of
	// every ready sandbox, and an error refuses the restart (default:
	// discover the Discover registration, dial it and FlushSandboxes).
	FlushSandboxes func(context.Context) error
	// ServiceDockerGroupMissing reports that the systemd user manager that
	// runs the gateway service lacks the user's docker group, which a
	// restarted gateway that does not come up names (Linux; default
	// ServiceManagerMissesDockerGroup).
	ServiceDockerGroupMissing func() bool
}

// gatewayExecutable is the openshell-gateway that preflights gateway.toml:
// the one on PATH (its bare name, as an install puts it there), else the
// one next to the OpenShell CLI cli, the only one to find for an OpenShell
// run by hand from a prefix that is not on PATH.
func gatewayExecutable(lookPath func(string) (string, error), cli string) string {
	if _, err := lookPath(GatewayBinary); err == nil {
		return GatewayBinary
	}
	if path, err := lookPath(cli); err == nil {
		next := filepath.Join(filepath.Dir(path), GatewayBinary)
		if info, err := os.Stat(next); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return next
		}
	}
	return GatewayBinary
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
	if g.CLI == "" {
		g.CLI = DefaultBinary
	}
	if g.LookPath == nil {
		g.LookPath = exec.LookPath
	}
	if g.Gateway == "" {
		g.Gateway = gatewayExecutable(g.LookPath, g.CLI)
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
	if g.BrewFormulaInstalled == nil {
		g.BrewFormulaInstalled = brewFormulaInstalled
	}
	if g.BrewPrefix == "" && g.GOOS == "darwin" {
		g.BrewPrefix = homebrewPrefix()
	}
	if g.RunningDriver == nil {
		g.RunningDriver = func(ctx context.Context) (Driver, error) { return runningDriver(ctx, g.Discover) }
	}
	if g.FlushSandboxes == nil {
		g.FlushSandboxes = func(ctx context.Context) error { return flushGatewaySandboxes(ctx, g.Discover) }
	}
	return nil
}

// EnvPath is the gateway.env the service reads: Dir's. On macOS the
// Homebrew service's wrapper sources Dir's when it exists, else the one
// under the Homebrew prefix; with neither, a new file goes to Dir.
func (g *GatewayConfigurator) EnvPath() (string, error) {
	if err := g.defaults(); err != nil {
		return "", err
	}
	return g.homebrewFallback(filepath.Join(g.Dir, GatewayEnvFile), GatewayEnvFile)
}

// TOMLPath is the gateway.toml the service reads: OPENSHELL_GATEWAY_CONFIG
// from gateway.env when it names an absolute path (its directory
// resolved like Dir), else Dir/gateway.toml. On macOS the Homebrew
// service's wrapper starts the gateway on the one under the Homebrew
// prefix when Dir has none and the prefix has.
func (g *GatewayConfigurator) TOMLPath() (string, error) {
	envPath, err := g.EnvPath()
	if err != nil {
		return "", err
	}
	data, _, _, err := g.readConfigFile(envPath)
	if err != nil {
		return "", err
	}
	if p := parseEnvFile(data)[envGatewayConfig]; p != "" && filepath.IsAbs(p) {
		return resolveFilePath(filepath.Clean(p))
	}
	return g.homebrewFallback(filepath.Join(g.Dir, GatewayTOMLFile), GatewayTOMLFile)
}

// homebrewFile is the Homebrew service's own copy of a gateway file, under
// the prefix's var/openshell ("" off macOS).
func (g *GatewayConfigurator) homebrewFile(name string) (string, error) {
	if g.GOOS != "darwin" || g.BrewPrefix == "" {
		return "", nil
	}
	return resolveFilePath(filepath.Join(g.BrewPrefix, "var", "openshell", name))
}

// homebrewFallback is the file the service reads in place of dirFile, one
// of Dir's: on macOS the Homebrew prefix's copy when dirFile does not
// exist and that copy does, as the formula's wrapper decides. A dirFile
// that exists in any form is the one read, so a link or a directory
// there is refused rather than passed over.
func (g *GatewayConfigurator) homebrewFallback(dirFile, name string) (string, error) {
	prefixFile, err := g.homebrewFile(name)
	if err != nil || prefixFile == "" {
		return dirFile, err
	}
	if _, err := os.Lstat(dirFile); !errors.Is(err, fs.ErrNotExist) {
		return dirFile, nil
	}
	if _, err := os.Lstat(prefixFile); err == nil {
		return prefixFile, nil
	}
	return dirFile, nil
}

// readConfigFile reads one of the service's files like readGatewayFile.
// foreign marks the Homebrew prefix's copy when another user owns it (a
// prefix several macOS accounts share): it is read, never written, and a
// change goes to a copy in Dir, which the service reads from then on.
func (g *GatewayConfigurator) readConfigFile(path string) (data []byte, info fs.FileInfo, foreign bool, err error) {
	data, info, err = readGatewayFile(path)
	if !errors.Is(err, errForeignGatewayFile) {
		return data, info, false, err
	}
	for _, name := range []string{GatewayEnvFile, GatewayTOMLFile} {
		if prefixFile, perr := g.homebrewFile(name); perr == nil && prefixFile != "" && prefixFile == path {
			data, info, err = readGatewayFileOf(path, true)
			return data, info, err == nil && info != nil, err
		}
	}
	return nil, nil, false, err
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
	// ComputeDriver is the compute driver the configuration selects:
	// OPENSHELL_COMPUTE_DRIVER from gateway.env, else [openshell.gateway]
	// compute_driver. Empty when neither names one: the gateway then
	// detects one, which is never vm.
	ComputeDriver ComputeDriver `json:"compute_driver,omitempty"`
	// VM is the MicroVM (vm) driver's configuration.
	VM VMConfig `json:"vm"`
	// server holds the gateway.toml listener and authentication settings.
	server gatewayServer
	// docker holds the images the docker driver starts with
	// (RuntimeImages).
	docker dockerRuntime
}

// dockerRuntime is what [openshell.drivers.docker] in gateway.toml says
// about the images OpenShell's docker driver starts with: each one set
// replaces a default image of the gateway's release.
type dockerRuntime struct {
	// SupervisorImage is supervisor_image, SandboxRuntimeImage
	// sandbox_runtime_image and SupervisorBin supervisor_bin.
	SupervisorImage, SandboxRuntimeImage, SupervisorBin string
}

// Driver is the compute driver the configuration selects, and false when
// DefenseClaw does not drive it. No driver named is docker.
func (s *GatewayConfigState) Driver() (Driver, bool) {
	return LookupDriver(string(s.ComputeDriver))
}

// VMConfig is [openshell.drivers.vm] in gateway.toml with the gateway.env
// variables that override it. A nil setting is unset: the driver's
// default applies. The settings hold for every MicroVM on the gateway.
type VMConfig struct {
	SandboxUID     *int64 `json:"sandbox_uid,omitempty"`
	SandboxGID     *int64 `json:"sandbox_gid,omitempty"`
	VCPUs          *int64 `json:"vcpus,omitempty"`
	MemMiB         *int64 `json:"mem_mib,omitempty"`
	OverlayDiskMiB *int64 `json:"overlay_disk_mib,omitempty"`
	// StateDir holds the driver's prepared images and sandboxes (empty:
	// ~/.local/state/openshell/vm-driver).
	StateDir string `json:"state_dir,omitempty"`
	// DriverDir is where the gateway finds the openshell-driver-vm binary
	// (empty: its own search).
	DriverDir string `json:"driver_dir,omitempty"`
}

// VMIdentity is the uid and gid the MicroVM driver runs every sandbox's
// workload as.
type VMIdentity struct {
	UID int64 `json:"uid"`
	GID int64 `json:"gid"`
}

func (id VMIdentity) String() string { return fmt.Sprintf("%d:%d", id.UID, id.GID) }

// VMResources is what the MicroVM driver gives every sandbox. In a
// change, a zero field is left alone.
type VMResources struct {
	VCPUs          int64 `json:"vcpus,omitempty"`
	MemMiB         int64 `json:"mem_mib,omitempty"`
	OverlayDiskMiB int64 `json:"overlay_disk_mib,omitempty"`
}

// Identity is the uid and gid sandboxes run as.
func (v VMConfig) Identity() VMIdentity {
	return VMIdentity{UID: orDefault(v.SandboxUID, DefaultVMSandboxUID), GID: orDefault(v.SandboxGID, DefaultVMSandboxGID)}
}

// Resources is what every MicroVM gets.
func (v VMConfig) Resources() VMResources {
	return VMResources{VCPUs: orDefault(v.VCPUs, DefaultVMVCPUs), MemMiB: orDefault(v.MemMiB, DefaultVMMemMiB),
		OverlayDiskMiB: orDefault(v.OverlayDiskMiB, DefaultVMOverlayDiskMiB)}
}

// Unset is want without the settings v already makes, so that a change
// written with it leaves the user's own values alone.
func (v VMConfig) Unset(want VMResources) VMResources {
	if v.VCPUs != nil {
		want.VCPUs = 0
	}
	if v.MemMiB != nil {
		want.MemMiB = 0
	}
	if v.OverlayDiskMiB != nil {
		want.OverlayDiskMiB = 0
	}
	return want
}

func orDefault(v *int64, def int64) int64 {
	if v == nil {
		return def
	}
	return *v
}

// RecommendedVMResources is what DefenseClaw sets up every MicroVM with,
// above the driver's 2 vCPUs, 2 GiB and 4 GiB overlay, which an agent
// building code outgrows: 4 vCPUs, 4 GiB of memory (a quarter of a
// smaller Mac's, at least the driver's 2 GiB; hostMemory 0 is unknown)
// and a 16 GiB overlay, which is sparse on the host and costs nothing
// until used.
func RecommendedVMResources(hostMemory uint64) VMResources {
	mem := int64(4096)
	if quarter := int64(hostMemory>>20) / 4 / 256 * 256; hostMemory > 0 && quarter < mem {
		mem = max(quarter, DefaultVMMemMiB)
	}
	return VMResources{VCPUs: 4, MemMiB: mem, OverlayDiskMiB: 16384}
}

// Within is v lowered to an organization's openshell.admin.max_resources
// (maxCPUMillis and maxMemoryBytes; 0 is no maximum). Every MicroVM gets
// the gateway-wide values, so a value above the maximum refuses every
// create. A maximum below one vCPU or one MiB leaves that field zero,
// which a change leaves alone.
func (v VMResources) Within(maxCPUMillis, maxMemoryBytes int64) VMResources {
	if maxCPUMillis > 0 {
		v.VCPUs = min(v.VCPUs, maxCPUMillis/1000)
	}
	if maxMemoryBytes > 0 {
		v.MemMiB = min(v.MemMiB, maxMemoryBytes>>20)
	}
	return v
}

// gatewayServer is the [openshell.gateway] part of gateway.toml that
// decides who can reach the gateway, and the compute driver it runs.
type gatewayServer struct {
	ComputeDriver string `toml:"compute_driver"`
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
	envData, envInfo, _, err := g.readConfigFile(envPath)
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
	tomlData, tomlInfo, _, err := g.readConfigFile(tomlPath)
	if err != nil {
		return nil, err
	}
	if tomlInfo != nil {
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
						SupervisorImage     string `toml:"supervisor_image"`
						SandboxRuntimeImage string `toml:"sandbox_runtime_image"`
						SupervisorBin       string `toml:"supervisor_bin"`
					} `toml:"docker"`
					VM struct {
						SandboxUID     *int64 `toml:"sandbox_uid"`
						SandboxGID     *int64 `toml:"sandbox_gid"`
						VCPUs          *int64 `toml:"vcpus"`
						MemMiB         *int64 `toml:"mem_mib"`
						OverlayDiskMiB *int64 `toml:"overlay_disk_mib"`
						StateDir       string `toml:"state_dir"`
						DriverDir      string `toml:"driver_dir"`
					} `toml:"vm"`
				} `toml:"drivers"`
			} `toml:"openshell"`
		}
		if err := toml.Unmarshal(tomlData, &doc); err != nil {
			return st, fmt.Errorf("openshell: parse %s: %w", tomlPath, err)
		}
		st.server = doc.OpenShell.Gateway
		st.ComputeDriver = ComputeDriver(strings.TrimSpace(st.server.ComputeDriver))
		d := doc.OpenShell.Drivers.Docker
		st.BindMounts = BindMounts{AllowDriverConfig: d.AllowDriverConfig, EnableBindMounts: d.EnableBindMounts, ResourceAdmission: true}
		if d.ResourceAdmission.Enabled != nil {
			st.BindMounts.ResourceAdmission = *d.ResourceAdmission.Enabled
		}
		st.docker = dockerRuntime{SupervisorImage: d.SupervisorImage, SandboxRuntimeImage: d.SandboxRuntimeImage, SupervisorBin: d.SupervisorBin}
		st.VM = VMConfig(doc.OpenShell.Drivers.VM)
	}
	st.overrideFromEnv()
	return st, nil
}

// overrideFromEnv applies the gateway.env variables that override the
// compute driver settings of gateway.toml. An empty variable counts as
// unset, and one that is not a number is left to the gateway to refuse.
func (s *GatewayConfigState) overrideFromEnv() {
	if v := strings.TrimSpace(s.Env[envComputeDriver]); v != "" {
		s.ComputeDriver = ComputeDriver(v)
	}
	for key, field := range map[string]**int64{envVMSandboxUID: &s.VM.SandboxUID, envVMSandboxGID: &s.VM.SandboxGID,
		envVMVCPUs: &s.VM.VCPUs, envVMMemMiB: &s.VM.MemMiB, envVMOverlayDiskMiB: &s.VM.OverlayDiskMiB} {
		if n, err := strconv.ParseInt(strings.TrimSpace(s.Env[key]), 10, 64); err == nil {
			*field = &n
		}
	}
	if v := strings.TrimSpace(s.Env[envVMStateDir]); v != "" {
		s.VM.StateDir = v
	}
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
	// ComputeDriver selects the gateway's compute driver ([openshell.gateway]
	// compute_driver); empty leaves it. One gateway runs one driver, so
	// the other driver's sandboxes cannot start after a switch.
	ComputeDriver ComputeDriver
	// VMIdentity sets the uid and gid the MicroVM driver runs every
	// sandbox's workload as ([openshell.drivers.vm] sandbox_uid and
	// sandbox_gid), gateway-wide: sandboxes made outside DefenseClaw run
	// as them too. Neither may be root's.
	VMIdentity *VMIdentity
	// VMResources sets what the MicroVM driver gives every sandbox
	// ([openshell.drivers.vm] vcpus, mem_mib, overlay_disk_mib); zero
	// fields are left alone.
	VMResources *VMResources
	// Env sets gateway.env entries (e.g. EnvTelemetryEnabled=false). The
	// plan summary prints the values, so they must not be secrets.
	Env map[string]string
	// UnsetEnv removes gateway.env entries.
	UnsetEnv []string
}

// tomlSettings are the gateway.toml assignments the changes make. Where
// gateway.env overrides one with another value, Plan sets it there too.
func (ch GatewayChanges) tomlSettings() ([]tomlSetting, error) {
	var out []tomlSetting
	if ch.EnableBindMounts {
		out = append(out, bindMountSettings...)
	}
	if ch.ComputeDriver != "" {
		out = append(out, tomlSetting{Table: gatewayTable, Key: "compute_driver", Value: string(ch.ComputeDriver)})
	}
	if id := ch.VMIdentity; id != nil {
		if id.UID <= 0 || id.GID <= 0 {
			return nil, fmt.Errorf("openshell: refusing to run MicroVM sandboxes as uid %d, gid %d: DefenseClaw runs them as your own user, never as root", id.UID, id.GID)
		}
		out = append(out, tomlSetting{Table: vmDriverTable, Key: "sandbox_uid", Value: id.UID},
			tomlSetting{Table: vmDriverTable, Key: "sandbox_gid", Value: id.GID})
	}
	if r := ch.VMResources; r != nil {
		for _, s := range []tomlSetting{{Key: "vcpus", Value: r.VCPUs}, {Key: "mem_mib", Value: r.MemMiB}, {Key: "overlay_disk_mib", Value: r.OverlayDiskMiB}} {
			switch n := s.Value.(int64); {
			case n < 0:
				return nil, fmt.Errorf("openshell: [openshell.drivers.vm] %s = %d is not a size", s.Key, n)
			case n > 0:
				s.Table = vmDriverTable
				out = append(out, s)
			}
		}
	}
	return out, nil
}

// vmEnvSettings are the gateway.env variables standing for the compute
// driver settings of the changes, with the values the changes give them.
func (ch GatewayChanges) vmEnvSettings() map[string]string {
	out := map[string]string{}
	if ch.ComputeDriver != "" {
		out[envComputeDriver] = string(ch.ComputeDriver)
	}
	if id := ch.VMIdentity; id != nil {
		out[envVMSandboxUID], out[envVMSandboxGID] = strconv.FormatInt(id.UID, 10), strconv.FormatInt(id.GID, 10)
	}
	if r := ch.VMResources; r != nil {
		for key, n := range map[string]int64{envVMVCPUs: r.VCPUs, envVMMemMiB: r.MemMiB, envVMOverlayDiskMiB: r.OverlayDiskMiB} {
			if n > 0 {
				out[key] = strconv.FormatInt(n, 10)
			}
		}
	}
	return out
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
	// SeededFrom is the Homebrew prefix's copy, owned by another user,
	// that Path is created from with the change: the service reads Path
	// from then on, and the other user's file is left alone. Apply checks
	// that it has not changed since (SeedBefore).
	SeededFrom string `json:"seeded_from,omitempty"`
	SeedBefore []byte `json:"-"`
}

// GatewayPlan is exactly what Apply will write. Files that would not
// change are left out; an empty plan needs neither consent nor a restart.
type GatewayPlan struct {
	Files []*FileChange `json:"files"`
	// Restart names how the gateway will be restarted.
	Restart string `json:"restart"`
	// BindMounts marks a plan that enables docker-driver bind mounts: Apply
	// checks again, against the restarted gateway, that only the caller can
	// reach it.
	BindMounts bool `json:"bind_mounts,omitempty"`
	// ComputeDriver is the compute driver the plan configures, which
	// Apply checks the restarted gateway runs; FromDriver is the one the
	// configuration selected before (docker when it named none).
	ComputeDriver ComputeDriver `json:"compute_driver,omitempty"`
	FromDriver    ComputeDriver `json:"from_driver,omitempty"`
	// Manual marks a plan for a gateway that no gateway service runs
	// (DoctorReport.GatewayUnmanaged), which the caller sets: Write writes
	// it, and the gateway loads it once its operator restarts it.
	Manual bool `json:"manual,omitempty"`
}

// manualRestartFlushFirst is what to do before restarting by hand a
// gateway on the MicroVM driver that no gateway service runs (a Manual
// plan): the restart stops its sandboxes without the flush DefenseClaw's
// restarts make first (FlushSandboxes), and `sandbox stop` flushes.
const manualRestartFlushFirst = "first stop the MicroVM sandboxes running on it with `defenseclaw sandbox stop NAME`, which flushes their disks, " +
	"or what they wrote since their last sync is lost"

// switchesDriver reports whether the plan moves the gateway to another
// compute driver.
func (p *GatewayPlan) switchesDriver() bool {
	return p.ComputeDriver != "" && p.ComputeDriver != p.FromDriver
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
		switch {
		case f.SeededFrom != "":
			fmt.Fprintf(&b, "  create %s from %s, which another user owns and is left alone; the gateway reads the new file from then on\n", f.Path, f.SeededFrom)
		case f.Before == nil:
			fmt.Fprintf(&b, "  create %s\n", f.Path)
		default:
			fmt.Fprintf(&b, "  edit %s (a timestamped backup is kept)\n", f.Path)
		}
		for _, s := range f.Summary {
			fmt.Fprintf(&b, "    %s\n", summaryLine(s))
		}
		if !f.TOML {
			// gateway.env may hold credentials: show only the summary.
			continue
		}
		for _, l := range lineDiff(string(f.Before), string(f.After)) {
			fmt.Fprintf(&b, "      %s\n", strings.TrimRight(l, " "))
		}
	}
	// The restart of a gateway no service runs is its user's: DefenseClaw
	// cannot flush the MicroVM sandboxes first, which a stop without a
	// flush empties of what they wrote since their last sync.
	flushFirst := ""
	if p.FromDriver == DriverVM {
		flushFirst = ": " + manualRestartFlushFirst
	}
	switch {
	case p.Manual && p.switchesDriver():
		fmt.Fprintf(&b, "  then you restart the gateway, the way you started it, on the %s compute driver (DefenseClaw cannot restart it), which stops every sandbox on it%s; "+
			"sandboxes made on the %s driver cannot start again unless it is switched back (one gateway runs one driver)\n", p.ComputeDriver, flushFirst, p.FromDriver)
	case p.Manual:
		b.WriteString("  then you restart the gateway, the way you started it, so it loads the change (DefenseClaw cannot restart it); restarting it stops every sandbox on it" +
			flushFirst + "\n")
	case p.switchesDriver():
		fmt.Fprintf(&b, "  then restart the gateway (%s) on the %s compute driver; running sandboxes stop, and sandboxes "+
			"made on the %s driver cannot start again unless it is switched back (one gateway runs one driver)\n", p.Restart, p.ComputeDriver, p.FromDriver)
	default:
		fmt.Fprintf(&b, "  then restart the gateway (%s); running sandboxes restart with it\n", p.Restart)
	}
	return b.String()
}

// summaryLine is one change of a plan's file: "set KEY = VALUE", or
// "remove KEY" for a gateway.env variable it drops (editEnvFile's
// "unset KEY"), saying what that leaves.
func summaryLine(s string) string {
	k, ok := strings.CutPrefix(s, "unset ")
	switch {
	case !ok:
		return "set " + s
	case k == EnvTelemetryEnabled:
		return "remove " + k + " (OpenShell's usage telemetry stays on, its default)"
	}
	return "remove " + k
}

// Plan computes the changes without touching anything. On Linux it first
// checks that the gateway service reads the files it would edit; without
// the service (a gateway run another way, whose environment is not known)
// it plans the files DefenseClaw reads.
func (g *GatewayConfigurator) Plan(ctx context.Context, ch GatewayChanges) (*GatewayPlan, error) {
	if err := g.defaults(); err != nil {
		return nil, err
	}
	plan := &GatewayPlan{Restart: strings.Join(g.restartCommand().argv(), " ")}
	settings, err := ch.tomlSettings()
	if err != nil {
		return nil, err
	}
	if len(settings) == 0 && len(ch.Env) == 0 && len(ch.UnsetEnv) == 0 {
		return plan, nil
	}
	env, err := g.serviceEnvironment(ctx)
	if err != nil && !errors.Is(err, ErrNoGatewayService) {
		return nil, err
	}
	envSet := ch.Env
	var overrides []string
	if len(settings) > 0 {
		st, err := g.Read()
		if err != nil {
			return nil, err
		}
		if ch.EnableBindMounts {
			// Bind mounts are the docker driver's: refuse them for a driver
			// that mounts no host folders, rather than write settings it
			// never reads.
			driver := st.ComputeDriver
			if ch.ComputeDriver != "" {
				driver = ch.ComputeDriver
			}
			if d, known := LookupDriver(string(driver)); known && !d.HostMounts {
				return nil, fmt.Errorf("%w: %s", ErrBindMountsRefused, d.MountRefusal)
			}
		}
		if ch.ComputeDriver != "" {
			plan.ComputeDriver, plan.FromDriver = ch.ComputeDriver, st.ComputeDriver
			if plan.FromDriver == "" {
				plan.FromDriver = DriverDocker
			}
		}
		// gateway.env overrides gateway.toml: a variable there that says
		// otherwise is set to match, or the change would not take.
		for key, want := range ch.vmEnvSettings() {
			if have := strings.TrimSpace(st.Env[key]); have != "" && have != want {
				if _, clash := ch.Env[key]; clash || slices.Contains(ch.UnsetEnv, key) {
					return nil, fmt.Errorf("openshell: %s is both a compute driver setting and a gateway.env change", key)
				}
				if len(overrides) == 0 {
					envSet = maps.Clone(ch.Env)
					if envSet == nil {
						envSet = map[string]string{}
					}
				}
				envSet[key] = want
				overrides = append(overrides, key)
			}
		}
	}
	if ch.EnableBindMounts {
		if err := g.requirePrivateGateway(ctx, env); err != nil {
			return nil, err
		}
	}
	if len(settings) > 0 {
		fc, err := g.planTOML(settings)
		if err != nil {
			return nil, err
		}
		if fc != nil {
			plan.Files = append(plan.Files, fc)
			plan.BindMounts = ch.EnableBindMounts
		}
	}
	if len(envSet) > 0 || len(ch.UnsetEnv) > 0 {
		fc, err := g.planEnv(envSet, ch.UnsetEnv, overrides)
		if err != nil {
			return nil, err
		}
		if fc != nil {
			plan.Files = append(plan.Files, fc)
		}
	}
	if plan.Empty() {
		plan.ComputeDriver, plan.FromDriver = "", ""
	}
	return plan, nil
}

// newGatewayTOML starts a gateway.toml that does not exist yet.
var newGatewayTOML = fmt.Sprintf("# OpenShell gateway configuration.\n\n[openshell]\nversion = %d\n", GatewayConfigVersion)

// planTOML plans settings in the gateway.toml the service reads; nil when
// nothing would change.
func (g *GatewayConfigurator) planTOML(settings []tomlSetting) (*FileChange, error) {
	path, err := g.TOMLPath()
	if err != nil {
		return nil, err
	}
	before, info, foreign, err := g.readConfigFile(path)
	if err != nil {
		return nil, err
	}
	src := before
	if info == nil {
		before, src = nil, []byte(newGatewayTOML)
	}
	after, err := editTOML(src, settings)
	if err != nil {
		return nil, fmt.Errorf("openshell: %s: %w", path, err)
	}
	if info != nil && bytes.Equal(before, after) {
		return nil, nil
	}
	fc := &FileChange{Path: path, Before: before, After: after, TOML: true}
	if foreign {
		fc.Path, fc.Before, fc.SeededFrom, fc.SeedBefore = filepath.Join(g.Dir, GatewayTOMLFile), nil, path, before
	}
	var current map[string]any
	_ = toml.Unmarshal(src, &current)
	for _, s := range settings {
		if v, ok := lookupTOML(current, s.Table, s.Key); !ok || v != s.Value {
			fc.Summary = append(fc.Summary, s.String())
		}
	}
	return fc, nil
}

// planEnv plans gateway.env entries; nil when nothing would change.
// overrides are the variables set because they override a gateway.toml
// setting the plan makes, which the summary says.
func (g *GatewayConfigurator) planEnv(set map[string]string, unset, overrides []string) (*FileChange, error) {
	path, err := g.EnvPath()
	if err != nil {
		return nil, err
	}
	before, info, foreign, err := g.readConfigFile(path)
	if err != nil {
		return nil, err
	}
	if info == nil {
		before = nil
	}
	after, summary, err := editEnvFile(before, set, unset)
	if err != nil {
		return nil, fmt.Errorf("openshell: %s: %w", path, err)
	}
	if bytes.Equal(before, after) {
		return nil, nil
	}
	for i, s := range summary {
		if k, _, _ := strings.Cut(s, "="); slices.Contains(overrides, k) {
			summary[i] = s + " (it overrides gateway.toml)"
		}
	}
	fc := &FileChange{Path: path, Before: before, After: after, Summary: summary}
	if foreign {
		fc.Path, fc.Before, fc.SeededFrom, fc.SeedBefore = filepath.Join(g.Dir, GatewayEnvFile), nil, path, before
	}
	return fc, nil
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
// gateway that fails Plan's checks aborts before anything is written. A
// running sandbox that cannot be flushed before the restart
// (FlushSandboxes) restores the previous files without a restart.
// When the restart or the health check fails, the restarted gateway with
// bind mounts no longer turns away a client without a certificate, or it
// does not run the compute driver the plan configures, the previous files
// are restored and the gateway restarted again.
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
	if err := g.checkPlan(ctx, plan, env); err != nil {
		return nil, err
	}
	if err := g.markRestartPending(); err != nil {
		return nil, err
	}
	if err := g.writeFiles(res, plan); err != nil {
		return res, g.rollbackAfter(ctx, res, err, false)
	}
	// The restart stops every sandbox on the gateway: their disks are
	// flushed first where its driver's stop would not keep what they
	// wrote, and one that cannot be flushed refuses it.
	if err := g.FlushSandboxes(ctx); err != nil {
		return res, g.rollbackAfter(ctx, res, err, false)
	}
	if err := g.restart(ctx); err != nil {
		return res, g.rollbackAfter(ctx, res, err, true)
	}
	if plan.BindMounts {
		// Check again against the gateway that now honours bind mounts.
		if err := g.requirePrivateGateway(ctx, env); err != nil {
			return res, g.rollbackAfter(ctx, res, err, true)
		}
	}
	if plan.ComputeDriver != "" {
		// A gateway.env the plan did not see (launchd's own environment,
		// for one) could still select another driver.
		d, err := g.restartedDriver(ctx)
		if err == nil && d.Name != plan.ComputeDriver {
			err = fmt.Errorf("openshell: the restarted gateway runs the %s compute driver, not %s; something else in its environment selects it", d.Name, plan.ComputeDriver)
		}
		if err != nil {
			return res, g.rollbackAfter(ctx, res, err, true)
		}
	}
	res.Restarted = true
	return res, nil
}

// Write writes the plan of a gateway that no gateway service runs
// (GatewayPlan.Manual): its operator restarts it on the files, so Write
// neither flushes nor restarts anything, and leaves no pending-restart
// mark, which only a restart of DefenseClaw's would clear. It checks what
// Apply checks before it writes, bind mounts against the gateway that
// answers, and restores the previous files when a write fails.
func (g *GatewayConfigurator) Write(ctx context.Context, plan *GatewayPlan) (*GatewayApplyResult, error) {
	if err := g.defaults(); err != nil {
		return nil, err
	}
	res := &GatewayApplyResult{}
	if plan.Empty() {
		return res, nil
	}
	env, err := g.serviceEnvironment(ctx)
	if err != nil && !errors.Is(err, ErrNoGatewayService) {
		return nil, err
	}
	if err := g.checkPlan(ctx, plan, env); err != nil {
		return nil, err
	}
	if err := g.writeFiles(res, plan); err != nil {
		if rerr := g.restore(res); rerr != nil {
			return res, fmt.Errorf("%w; restoring the previous configuration also failed: %v", err, rerr)
		}
		return res, fmt.Errorf("%w (the previous configuration was restored)", err)
	}
	return res, nil
}

// checkPlan refuses a plan whose files changed since Plan, whose
// gateway.toml fails preflight, or that enables bind mounts on a gateway
// others can reach (env: the service's environment, nil when unknown).
func (g *GatewayConfigurator) checkPlan(ctx context.Context, plan *GatewayPlan, env map[string]string) error {
	if plan.BindMounts {
		if err := g.requirePrivateGateway(ctx, env); err != nil {
			return err
		}
	}
	for _, f := range plan.Files {
		current, info, err := readGatewayFile(f.Path)
		if err != nil {
			return err
		}
		if (info == nil) != (f.Before == nil) || (info != nil && !bytes.Equal(current, f.Before)) {
			return fmt.Errorf("%w: %s", ErrConfigChanged, f.Path)
		}
		if f.SeededFrom != "" {
			if seed, _, _, err := g.readConfigFile(f.SeededFrom); err != nil || !bytes.Equal(seed, f.SeedBefore) {
				return fmt.Errorf("%w: %s", ErrConfigChanged, f.SeededFrom)
			}
		}
		if f.TOML {
			if err := g.preflight(ctx, f); err != nil {
				return err
			}
		}
	}
	return nil
}

// writeFiles backs up and writes the plan's files, recording each in res
// for a restore.
func (g *GatewayConfigurator) writeFiles(res *GatewayApplyResult, plan *GatewayPlan) error {
	for _, f := range plan.Files {
		applied := AppliedFile{Path: f.Path}
		if f.Before != nil {
			backup, err := g.backup(f.Path, f.Before)
			if err != nil {
				return err
			}
			applied.Backup = backup
		}
		if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
			return fmt.Errorf("openshell: create %s: %w", filepath.Dir(f.Path), err)
		}
		if err := safefile.Write(f.Path, f.After); err != nil {
			return fmt.Errorf("openshell: write %s: %w", f.Path, err)
		}
		res.Files = append(res.Files, applied)
	}
	return nil
}

// restartedDriver asks the restarted gateway which compute driver it runs
// until it says, within RestartWait: a gateway can answer its health check
// before it answers GetGatewayInfo, or before its driver has connected
// and it has one to report. A driver it names is a definite answer; only
// the last error of a gateway that never names one is returned.
func (g *GatewayConfigurator) restartedDriver(ctx context.Context) (Driver, error) {
	interval := min(2*time.Second, max(g.RestartWait/20, time.Millisecond))
	deadline := time.Now().Add(g.RestartWait)
	for {
		d, err := g.RunningDriver(ctx)
		if err == nil || !time.Now().Before(deadline) {
			return d, err
		}
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return d, err
		case <-t.C:
		}
	}
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
	if err := gatewayExposure(reg, st, env, env == nil && g.NoService(ctx)); err != nil {
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
// another port than the service listens on (gateway.toml, or the
// service's environment). With no gateway service (noService, env nil)
// the ports are not compared: a gateway run by hand takes its port from an
// environment of its own.
func gatewayExposure(reg *Registration, st *GatewayConfigState, env map[string]string, noService bool) error {
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
	host, port, err := st.listenAddress(env)
	if err != nil {
		return err
	}
	if !isLoopbackHost(host) {
		issues = append(issues, fmt.Sprintf("the gateway listens on %q, beyond this machine", host))
	}
	if len(issues) > 0 {
		return fmt.Errorf("%w: %s", ErrGatewayExposed, strings.Join(issues, "; "))
	}
	if env == nil && noService {
		// No gateway service, so no environment to say where the gateway
		// listens (one run by hand takes OPENSHELL_SERVER_PORT from its
		// own): the registration and the client-auth probe of the gateway
		// it reaches decide. A service whose environment cannot be read
		// (Homebrew's, through launchd) is still compared with the
		// registration, or the probe would judge another gateway than the
		// one DefenseClaw edits.
		return nil
	}
	if _, regPort, err := net.SplitHostPort(reg.Target()); err != nil || regPort != port {
		return fmt.Errorf("%w: registration %s reaches %s, but the %s service listens on port %s", ErrGatewayMismatch, reg.Name, reg.Endpoint, GatewayService, port)
	}
	return nil
}

// listenAddress is where the gateway listens: gateway.toml's bind_address
// (default 127.0.0.1:17670), then OPENSHELL_BIND_ADDRESS and
// OPENSHELL_SERVER_PORT in env.
func (s *GatewayConfigState) listenAddress(env map[string]string) (host, port string, err error) {
	host, port = "127.0.0.1", strconv.Itoa(defaultGatewayPort)
	if b := s.server.BindAddress; b != "" {
		if host, port, err = net.SplitHostPort(b); err != nil {
			return "", "", fmt.Errorf("%w: bind_address %q in %s is not ip:port", ErrGatewayMismatch, b, s.TOMLPath)
		}
	}
	// An empty variable counts as unset, as it does for the gateway.
	if v := strings.TrimSpace(env[envBindAddress]); v != "" {
		host = v
	}
	if v := strings.TrimSpace(env[envServerPort]); v != "" {
		port = v
	}
	return host, port, nil
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
		// The gateway must go back to its previous configuration: a
		// sandbox that cannot be flushed does not hold that up.
		_ = g.FlushSandboxes(ctx)
		if err := g.restart(ctx); err != nil {
			// The service manager refused both restarts (brew services
			// without the formula, for one): the gateway may never have
			// stopped. Only one that does not answer is down.
			if errors.Is(cause, errRestartCommand) && errors.Is(err, errRestartCommand) && g.answers(ctx) {
				return fmt.Errorf("%w; the gateway could not be restarted, so it still runs on its old configuration (the previous files were restored)", cause)
			}
			return fmt.Errorf("%w; the previous configuration was restored but the gateway did not come back: %v", cause, err)
		}
	} else {
		// The gateway never saw the new files; the restored ones are what it runs.
		g.clearRestartPending()
	}
	return fmt.Errorf("%w (the previous configuration was restored)", cause)
}

// Rollback restores the files an Apply (or a Write) wrote and restarts the
// gateway. With no gateway service to restart it through, it restores the
// files and returns ErrNoGatewayService: the gateway, run another way,
// loads them once its operator restarts it.
func (g *GatewayConfigurator) Rollback(ctx context.Context, res *GatewayApplyResult) error {
	if err := g.defaults(); err != nil {
		return err
	}
	if res == nil || len(res.Files) == 0 {
		return nil
	}
	if g.NoService(ctx) {
		if err := g.restore(res); err != nil {
			return err
		}
		return ErrNoGatewayService
	}
	// Before anything changes: a sandbox that cannot be flushed refuses
	// the restart.
	if err := g.FlushSandboxes(ctx); err != nil {
		return err
	}
	if err := g.markRestartPending(); err != nil {
		return err
	}
	if err := g.restore(res); err != nil {
		return err
	}
	return g.restart(ctx)
}

// NoService reports that the service manager has no gateway service
// (ErrNoGatewayService), so the gateway, where one runs, is its user's to
// restart: on a Mac the formula is not installed (a file system check,
// without the slow `brew services info`), on Linux systemd does not know
// the user unit. An unknown state is not a missing service.
func (g *GatewayConfigurator) NoService(ctx context.Context) bool {
	if err := g.defaults(); err != nil {
		return false
	}
	if g.GOOS == "darwin" {
		return !g.BrewFormulaInstalled()
	}
	svc, err := g.ServiceState(ctx)
	return err == nil && !svc.Installed
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

// errRestartCommand marks a restart the service manager refused, which
// may have left the gateway running as it was.
var errRestartCommand = errors.New("openshell: restart the gateway")

// answers reports whether the gateway is healthy within a short wait.
func (g *GatewayConfigurator) answers(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return g.VerifyGateway(ctx) == nil
}

// Restart flushes the disks of the gateway's running sandboxes where its
// driver's stop would not (FlushSandboxes), restarts the gateway service
// and waits until it is healthy. A sandbox that could not be flushed
// refuses the restart.
func (g *GatewayConfigurator) Restart(ctx context.Context) error {
	if err := g.defaults(); err != nil {
		return err
	}
	if err := g.FlushSandboxes(ctx); err != nil {
		return err
	}
	return g.restart(ctx)
}

// restart restarts the gateway service and waits until it is healthy.
func (g *GatewayConfigurator) restart(ctx context.Context) error {
	c := g.restartCommand()
	if out, err := g.Runner.Output(ctx, Command{Name: c.name, Args: c.args, Timeout: 2 * time.Minute}); err != nil {
		return fmt.Errorf("%w: %v: %s", errRestartCommand, err, strings.TrimSpace(string(out)))
	}
	if err := g.VerifyGateway(ctx); err != nil {
		missing := g.ServiceDockerGroupMissing
		if missing == nil {
			missing = ServiceManagerMissesDockerGroup
		}
		if g.GOOS == "linux" && missing() {
			return fmt.Errorf("openshell: the restarted gateway is not healthy: %w; %s", err, serviceManagerDockerGroupHint())
		}
		return fmt.Errorf("openshell: the restarted gateway is not healthy: %w", err)
	}
	g.clearRestartPending()
	return nil
}

// ErrUnflushed means the gateway was not restarted: the disks of some of
// its running sandboxes could not be flushed first.
var ErrUnflushed = errors.New("openshell: the gateway was not restarted, because the disks of sandboxes running on it could not be flushed first")

// sandboxFlushWait bounds sync(1) in one sandbox.
const sandboxFlushWait = 20 * time.Second

// FlushSandboxes runs sync(1) in every ready sandbox of the gateway c
// talks to when its compute driver's stop does not keep what a workload
// has not synced (Driver.StopFlushes). A gateway restart stops all of its
// sandboxes, and a MicroVM stopped without a flush brings what it wrote
// since its last one back empty (OpenShell 0.1.1). A gateway that does
// not answer runs nothing a flush could reach; one that answers but whose
// sandboxes could not be listed or flushed fails with ErrUnflushed,
// naming them.
//
// A gateway whose driver is not known, because GetGatewayInfo failed, is
// flushed like one on the vm driver: one failed call (a timeout on a busy
// host, a gateway that answers Health before GetGatewayInfo) does not
// mean that nothing runs on it. It is taken to be down only when the
// list of its sandboxes is refused too (Unavailable). A list that times
// out is a gateway that took the call and was slow, a busy host whose
// MicroVMs still run, so it refuses the restart like any other failure.
func FlushSandboxes(ctx context.Context, c Client) error {
	info, infoErr := c.GatewayInfo(ctx)
	if infoErr == nil {
		if d, err := GatewayDriver(info); err == nil && d.StopFlushes {
			return nil
		}
	}
	list, err := c.ListSandboxes(ctx, nil)
	if err != nil {
		if infoErr != nil && ctx.Err() == nil && IsUnavailable(err) {
			return nil
		}
		return fmt.Errorf("%w (they could not be listed: %v)", ErrUnflushed, err)
	}
	var failed []string
	for _, sb := range list {
		if sb == nil || sb.Status.Phase != PhaseReady {
			continue
		}
		res, err := c.Exec(ctx, sb.Name, []string{"/bin/sync"}, ExecOptions{Timeout: sandboxFlushWait, Attempts: 1, MaxOutputBytes: 256})
		if err == nil && res.ExitCode != 0 {
			err = fmt.Errorf("sync(1) exited with status %d", res.ExitCode)
		}
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", sb.Name, err))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%w (%s): a MicroVM stopped without a flush brings back empty what it wrote since its last one; "+
			"stop them first, then try again", ErrUnflushed, strings.Join(failed, "; "))
	}
	return nil
}

// flushGatewaySandboxes is FlushSandboxes on the gateway of opts. A
// gateway that cannot be reached has no sandbox a flush could reach.
func flushGatewaySandboxes(ctx context.Context, opts DiscoverOptions) error {
	reg, err := Discover(opts)
	if err != nil {
		return nil
	}
	c, err := Dial(reg, ClientOptions{RPCTimeout: 10 * time.Second})
	if err != nil {
		return nil
	}
	defer c.Close()
	return FlushSandboxes(ctx, c)
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
// Homebrew it returns nil: the service's wrapper sources a gateway.env
// (XDG, else the one under the Homebrew prefix), but launchd cannot be
// asked which.
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
		return nil, fmt.Errorf("%w: the %s user service is not installed", ErrNoGatewayService, GatewayService)
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
	if !g.BrewFormulaInstalled() {
		return st, nil
	}
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
	// Homebrew may print warnings and hints first ("Warning: running
	// through sudo, using user/* instead of gui/* domain!" in a shell from
	// sudo -iu): the answer is the JSON array after them.
	if err := json.NewDecoder(bytes.NewReader(jsonArrayStart(out))).Decode(&infos); err != nil || len(infos) == 0 {
		return nil, fmt.Errorf("openshell: brew services info %s: unexpected output %q", GatewayFormula, strings.TrimSpace(string(out)))
	}
	i := infos[0]
	st.Installed = i.File != "" || i.Loaded || i.Registered
	st.Active, st.Enabled, st.Status = i.Running, i.Loaded || i.Registered, brewStatusText(i.Status)
	return st, nil
}

// brewStatusText says a `brew services` status in words: "none" is a
// service launchd has not loaded, so not running.
func brewStatusText(status string) string {
	switch status {
	case "none", "":
		return "not running (not loaded)"
	case "error":
		return "failing (see `brew services info " + GatewayFormula + "`)"
	}
	return status
}

// jsonArrayStart is out from its first line that starts a JSON array (all
// of out when none does).
func jsonArrayStart(out []byte) []byte {
	for i := 0; i < len(out); {
		line := out[i:]
		if j := bytes.IndexByte(line, '\n'); j >= 0 {
			line = line[:j+1]
		}
		if t := bytes.TrimLeft(line, " \t"); len(t) > 0 && t[0] == '[' {
			return out[i:]
		}
		i += len(line)
	}
	return out
}

// brewFormulaInstalled reports whether GatewayFormula has a keg under a
// Homebrew prefix: HOMEBREW_PREFIX (which `brew shellenv` sets) or the one
// of the brew on PATH. It reads the file system and runs nothing.
func brewFormulaInstalled() bool {
	prefixes := []string{os.Getenv("HOMEBREW_PREFIX")}
	if brew, err := exec.LookPath("brew"); err == nil {
		prefixes = append(prefixes, filepath.Dir(filepath.Dir(brew)))
		// A brew linked from elsewhere (~/bin/brew) names its prefix
		// through the link.
		if real, err := filepath.EvalSymlinks(brew); err == nil {
			prefixes = append(prefixes, filepath.Dir(filepath.Dir(real)))
		}
	}
	name := path.Base(GatewayFormula)
	for _, p := range prefixes {
		if !filepath.IsAbs(p) {
			continue
		}
		for _, keg := range []string{filepath.Join(p, "opt", name), filepath.Join(p, "Cellar", name)} {
			if info, err := os.Stat(keg); err == nil && info.IsDir() {
				return true
			}
		}
	}
	return false
}

// homebrewPrefix is the Homebrew prefix, found once like `brew --prefix`
// without running brew: HOMEBREW_PREFIX (which `brew shellenv` sets),
// else the prefix of the brew on PATH (the one holding a Cellar, through
// its link when it has none), else /opt/homebrew, Apple silicon's.
var homebrewPrefix = sync.OnceValue(func() string {
	if p := os.Getenv("HOMEBREW_PREFIX"); filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	if brew, err := exec.LookPath("brew"); err == nil && filepath.IsAbs(brew) {
		candidates := []string{brew}
		if real, err := filepath.EvalSymlinks(brew); err == nil {
			candidates = append(candidates, real)
		}
		for _, c := range candidates {
			prefix := filepath.Dir(filepath.Dir(c))
			if info, err := os.Stat(filepath.Join(prefix, "Cellar")); err == nil && info.IsDir() {
				return prefix
			}
		}
	}
	return "/opt/homebrew"
})

// runningDriver asks the gateway of opts which compute driver it runs.
func runningDriver(ctx context.Context, opts DiscoverOptions) (Driver, error) {
	reg, err := Discover(opts)
	if err != nil {
		return Driver{}, err
	}
	c, err := Dial(reg, ClientOptions{RPCTimeout: 10 * time.Second})
	if err != nil {
		return Driver{}, err
	}
	defer c.Close()
	info, err := c.GatewayInfo(ctx)
	if err != nil {
		return Driver{}, fmt.Errorf("openshell: gateway info: %w", err)
	}
	return GatewayDriver(info)
}

// errForeignGatewayFile marks a configuration file another user owns.
var errForeignGatewayFile = errors.New("is owned by another user")

// gatewayFileOwned reports whether a configuration file is the caller's
// (tests stand in for a file another user owns).
var gatewayFileOwned = ownedByCaller

// readGatewayFile reads a configuration file. A missing file returns nil
// data and nil info. Symlinks, non-regular files and files owned by
// another user are refused: the gateway runs as the caller, and editing
// through a link could redirect a write.
func readGatewayFile(path string) ([]byte, fs.FileInfo, error) {
	return readGatewayFileOf(path, false)
}

// readGatewayFileOf is readGatewayFile that, with foreign, also reads a
// file another user owns (to copy it, never to write it).
func readGatewayFileOf(path string, foreign bool) ([]byte, fs.FileInfo, error) {
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
	if !foreign && !gatewayFileOwned(info) {
		return nil, nil, fmt.Errorf("openshell: %s %w", path, errForeignGatewayFile)
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
