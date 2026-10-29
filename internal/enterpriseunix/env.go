// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

// CommandResult is the captured outcome of one external command.
type CommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner executes host administration commands. The production runner only
// runs absolute paths with a fixed minimal environment; tests substitute a
// fake.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (CommandResult, error)
}

// EnvRunner is a Runner that can add environment variables to the fixed
// minimal environment; the lifecycle uses it to run the gateway CLI with
// the same managed pins the guardian service gets.
type EnvRunner interface {
	RunEnv(ctx context.Context, env []string, name string, args ...string) (CommandResult, error)
}

// ErrCommandNotFound reports that none of a command's absolute candidate
// paths exists on the host.
var ErrCommandNotFound = errors.New("command not found")

// commandCandidates lists the only locations a host tool is run from. The
// lifecycle never consults PATH: an administrator's shell or the MDM agent
// may carry an arbitrary one.
var commandCandidates = map[string][]string{
	"systemctl":        {"/usr/bin/systemctl", "/bin/systemctl"},
	"systemd-sysusers": {"/usr/bin/systemd-sysusers", "/bin/systemd-sysusers"},
	"systemd-run":      {"/usr/bin/systemd-run", "/bin/systemd-run"},
	"getent":           {"/usr/bin/getent", "/bin/getent"},
	"journalctl":       {"/usr/bin/journalctl", "/bin/journalctl"},
	"useradd":          {"/usr/sbin/useradd", "/sbin/useradd"},
	"groupadd":         {"/usr/sbin/groupadd", "/sbin/groupadd"},
	"userdel":          {"/usr/sbin/userdel", "/sbin/userdel"},
	"groupdel":         {"/usr/sbin/groupdel", "/sbin/groupdel"},
	"dpkg":             {"/usr/bin/dpkg", "/bin/dpkg"},
	"rpm":              {"/usr/bin/rpm", "/bin/rpm"},
	"restorecon":       {"/usr/sbin/restorecon", "/sbin/restorecon"},
	"semodule":         {"/usr/sbin/semodule", "/sbin/semodule"},
	"launchctl":        {"/bin/launchctl"},
	"dscl":             {"/usr/bin/dscl"},
	"pkgutil":          {"/usr/sbin/pkgutil"},
	"lsof":             {"/usr/sbin/lsof", "/usr/bin/lsof"},
	"ps":               {"/bin/ps", "/usr/bin/ps"},
	"ls":               {"/bin/ls"},
	"chmod":            {"/bin/chmod"},
	// The sandbox lifecycle acts as the user (runuser on Linux, sudo on macOS)
	// and reads the user service manager and group lists.
	"runuser":  {"/usr/sbin/runuser", "/sbin/runuser", "/usr/bin/runuser"},
	"sudo":     {"/usr/bin/sudo"},
	"loginctl": {"/usr/bin/loginctl", "/bin/loginctl"},
	"id":       {"/usr/bin/id", "/bin/id"},
}

// ExecRunner is the production Runner.
type ExecRunner struct {
	// Timeout bounds every command; zero means two minutes.
	Timeout time.Duration
}

// Run executes name (a key of commandCandidates, or an absolute path) with
// args and a clean environment.
func (r ExecRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	return r.RunEnv(ctx, nil, name, args...)
}

// RunEnv is Run with extra KEY=VALUE environment entries.
func (r ExecRunner) RunEnv(ctx context.Context, extra []string, name string, args ...string) (CommandResult, error) {
	path, err := resolveCommand(name)
	if err != nil {
		return CommandResult{ExitCode: -1}, err
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}, extra...)
	cmd.Dir = "/"
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, remaining: 4 << 20}
	cmd.Stderr = &limitedWriter{w: &stderr, remaining: 1 << 20}
	runErr := cmd.Run()
	result := CommandResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return result, fmt.Errorf("%s %s: exit %d: %s", name, strings.Join(args, " "), result.ExitCode, strings.TrimSpace(string(result.Stderr)))
		}
		return result, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), runErr)
	}
	return result, nil
}

func resolveCommand(name string) (string, error) {
	if filepath.IsAbs(name) {
		return name, nil
	}
	for _, candidate := range commandCandidates[name] {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%s: %w", name, ErrCommandNotFound)
}

type limitedWriter struct {
	w         io.Writer
	remaining int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.remaining <= 0 {
		return len(p), nil
	}
	n := len(p)
	if n > l.remaining {
		p = p[:l.remaining]
	}
	l.remaining -= len(p)
	_, err := l.w.Write(p)
	return n, err
}

// TrustKind names a trust check the lifecycle runs on an installed path.
type TrustKind int

const (
	// TrustAdminFile is an administrator-owned input (config, descriptor).
	TrustAdminFile TrustKind = iota
	// TrustRuntimeDir is a directory the service account may own.
	TrustRuntimeDir
	// TrustRulePack is an administrator rule pack: its folders above, and
	// every folder and file in it (see rulePackTrust).
	TrustRulePack
	// TrustRuntimeFile is a policy-tree file the service account may own.
	TrustRuntimeFile
	// TrustAdminDir is an administrator-owned directory and all its
	// ancestors. Host security files are written only below such a path.
	TrustAdminDir
)

// Env binds the lifecycle to one host. Zero values are replaced by
// production defaults in NewEnv.
type Env struct {
	GOOS string
	// Root prefixes every layout path. Production uses "" (the real
	// filesystem); tests use a temporary directory.
	Root   string
	Layout managed.StandaloneLayout

	Runner        Runner
	Services      ServiceManager
	Accounts      AccountManager
	MachinePolicy MachinePolicyManager
	// MacFleetPythonCheck verifies the managed macOS interpreter and PyYAML.
	// Nil uses Fleet's production trust and isolated import checks; tests may
	// substitute a probe for an absent macOS framework on non-macOS hosts.
	MacFleetPythonCheck func() (string, error)
	// LinuxFleetPythonCheck has the same test seam for the distro Python and
	// PyYAML prerequisite of a Fleet-enabled managed Linux deployment.
	LinuxFleetPythonCheck func() (string, error)

	Now     func() time.Time
	Geteuid func() int
	// Lchown changes ownership without following a symlink.
	Lchown func(path string, uid, gid int) error
	// OwnerOf reports a path's uid and gid without following a symlink.
	OwnerOf func(path string) (int, int, error)
	// clearDirFlags clears the macOS immutable and append-only flags of a
	// folder and names the ones it found ("uchg,schg"; "" when none were
	// set), also when clearing them failed. Tests replace it.
	clearDirFlags func(path string) (string, error)
	// dirFlagsCleared is told when ensureDir cleared such a flag; a
	// lifecycle run lists it among its changes.
	dirFlagsCleared func(path, flags string)
	// Fchown changes the owner of an open file: the state folders the service
	// account can write are re-owned through descriptors (settleStateModes).
	Fchown func(f *os.File, uid, gid int) error
	// Trust runs the managed trust checks on a rooted path.
	Trust func(path string, kind TrustKind) error
	// HealthGet fetches the gateway /health document over the hook socket
	// (see gatewayHealth).
	HealthGet func(ctx context.Context) (int, []byte, error)
	// APIHealthGet fetches /health from the TCP API address. Only a gateway
	// that does not answer /health on its hook socket (an earlier release,
	// between a package upgrade and the restart or after a rollback) is
	// probed there, after the connected peer is matched to the service.
	APIHealthGet func(ctx context.Context) (int, []byte, error)
	// HookSocketPeer connects to the hook socket and returns the kernel
	// credentials of the process serving it.
	HookSocketPeer func(ctx context.Context) (peercred.Credentials, error)
	// ReportLaunchCoverage sends a root-only, content-free observation to the
	// gateway audit when a running agent can omit its managed plugin.
	ReportLaunchCoverage func(context.Context, managed.LaunchCoverageReport) error
	// ListenerProof asks the gateway over the protected hook socket to prove
	// it accepts the per-user hook credential named by keyID (its SHA-256).
	// The root lifecycle cannot use the TCP route bound to the user's UID.
	ListenerProof func(ctx context.Context, connectorName, keyID, nonce string) (string, error)
	// DiskSpace reports the available bytes, size and device of the
	// filesystem holding a path (see diskSpace).
	DiskSpace func(path string) (avail, total, device uint64, err error)
	// ProcessExecPath returns the executable path the kernel recorded when
	// process pid started (macOS only; see gatewayProcesses).
	ProcessExecPath func(pid int) (string, error)
	// ProcessImagePath returns the kernel's absolute path of the image
	// process pid runs (macOS only; see absoluteExecPath).
	ProcessImagePath func(pid int) (string, error)
	// DockerEngine connects to the Docker engine socket at the rooted path
	// and returns nil when the engine accepts the connection (see
	// dockerEngineAnswers); status and verify use it for the openshell block
	// on Linux.
	DockerEngine func(ctx context.Context, socket string) error

	// UserUnitSource reads the definition of a sandbox user unit by its
	// embedded file name (default: the embedded unit assets); tests replace it.
	UserUnitSource func(name string) ([]byte, error)
	// SandboxUsers is how the lifecycle acts in user accounts for the sandbox
	// subsystem (default: commands run as the user); tests replace it.
	SandboxUsers SandboxUserOps
	// agentDigest is the SHA-256 of the gateway the plan being applied
	// installs, which tags the macOS LaunchAgent labels (launchAgentLabel);
	// "" outside a plan, where the installed gateway is read.
	agentDigest string
	// boundedHomeLookups is set by status and verify: an account's home is
	// looked up in a bounded child before it is opened in this process, so a
	// home on a stalled mount cannot keep them from answering (GAP-1751).
	boundedHomeLookups bool
	// homeLookups holds each home's bounded lookup answer for this run.
	homeLookups struct {
		sync.Mutex
		answered map[string]bool
	}

	// ProductVersion is the version of the running lifecycle binary.
	ProductVersion string
	// BundleDigester computes the effective policy digest of the config of
	// a signed policy bundle (the gateway ComputeEffectivePolicyFor); nil
	// refuses every bundle (config_invalid).
	BundleDigester enterprisebundle.PolicyDigester
	// RefuseCapabilityLoss makes a bundle apply refuse capability loss
	// before it changes the installed config.
	RefuseCapabilityLoss bool
	// DeferRestart makes a bundle apply refuse, before it changes anything,
	// a bundle whose config change restarts the gateway (restart_deferred,
	// the retry exit code).
	DeferRestart bool
	// bundleFault is a test seam: it runs at each named phase of a bundle
	// apply (received, verified, staged, transaction, applied, committed)
	// and an error fails the apply there; at committed the run stops before
	// the swap, as a crash after the commit would; "private-dir <name>"
	// runs before the bundle store creates its private directory <name>
	// (receipts). Production leaves it nil.
	bundleFault func(phase string) error

	// SelfUnit names the service unit or launchd job this lifecycle run
	// executes inside (the config-apply trigger). The lifecycle never stops
	// or restarts that unit: doing so would kill its own transaction.
	SelfUnit string

	// Yield lowers the priority of the lifecycle run (yieldToHooks) before
	// it does any work; tests leave it nil.
	Yield func()

	LockTimeout  time.Duration
	ReadyTimeout time.Duration
	PollInterval time.Duration
	// GuardianReportTimeout bounds how long a change waits for the hook
	// guardian's report on its targets.
	GuardianReportTimeout time.Duration
	// ReplacedHookCallsTimeout bounds how long a run waits, before it stops
	// the gateway, for the calls the replaced release's shell hooks already
	// run (fenceReplacedHooks).
	ReplacedHookCallsTimeout time.Duration
}

// lifecycleNice is the nice value of a lifecycle run. A config or bundle
// apply builds and verifies a policy generation, in this process and in a
// gateway CLI it starts, while the gateway keeps answering hook calls; on
// a small host that work competed with the gateway and with each hook
// process for the CPU, and hook calls slowed down or timed out for seconds
// during the apply (#1279). The run yields instead; it does not hold the
// gateway up.
const lifecycleNice = 10

// NewEnv returns the production environment for goos.
func NewEnv(goos, productVersion string) (*Env, error) {
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		return nil, err
	}
	env := &Env{
		GOOS:           goos,
		Layout:         layout,
		Runner:         ExecRunner{},
		ProductVersion: productVersion,
		Yield:          yieldToHooks,
	}
	env.fillDefaults()
	env.SelfUnit = selfUnitFromEnv(env.Services, os.Getenv(LifecycleUnitEnv))
	return env, nil
}

// DefaultLockWait is how long a lifecycle run waits for another run to
// finish before it reports busy (exit 75). MDM agents retry a busy run, so
// they get the answer promptly; the config-apply trigger passes a longer
// --lock-wait so a change made during another run is applied after it.
const DefaultLockWait = 5 * time.Second

// MaxLockWait bounds --lock-wait.
const MaxLockWait = 15 * time.Minute

// LifecycleUnitEnv is set by the units that run the lifecycle themselves
// (the config-apply service and launchd job) to their own name.
const LifecycleUnitEnv = "DEFENSECLAW_LIFECYCLE_UNIT"

// selfUnitFromEnv accepts only a unit the service manager manages, so the
// variable can only ever exempt a lifecycle entry point from quiescing.
func selfUnitFromEnv(services ServiceManager, value string) string {
	value = strings.TrimSpace(value)
	if value == "" || services == nil {
		return ""
	}
	for _, unit := range services.Units() {
		if unit.Name == value && (unit.Name == unitApplyService || unit.Name == labelApply) {
			return value
		}
	}
	return ""
}

func (e *Env) fillDefaults() {
	if e.Runner == nil {
		e.Runner = ExecRunner{}
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Geteuid == nil {
		e.Geteuid = os.Geteuid
	}
	if e.Lchown == nil {
		e.Lchown = os.Lchown
	}
	if e.clearDirFlags == nil {
		e.clearDirFlags = clearBlockingFlags
	}
	if e.Fchown == nil {
		e.Fchown = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }
	}
	if e.OwnerOf == nil {
		e.OwnerOf = func(path string) (int, int, error) {
			uid, gid, _, err := statOwnerMode(path)
			return uid, gid, err
		}
	}
	if e.Trust == nil {
		e.Trust = defaultTrust
	}
	if e.HealthGet == nil {
		path, addr := e.P(e.Layout.HookSocketPath), e.Layout.APIAddr
		e.HealthGet = func(ctx context.Context) (int, []byte, error) { return getHealth(ctx, "unix", path, addr) }
	}
	if e.APIHealthGet == nil {
		addr := e.Layout.APIAddr
		goos := e.GOOS
		e.APIHealthGet = func(ctx context.Context) (int, []byte, error) { return getProtectedAPIHealth(ctx, goos, addr) }
	}
	if e.HookSocketPeer == nil {
		path := e.P(e.Layout.HookSocketPath)
		e.HookSocketPeer = func(ctx context.Context) (peercred.Credentials, error) { return hookSocketPeer(ctx, path) }
	}
	if e.ReportLaunchCoverage == nil {
		path := e.P(e.Layout.HookSocketPath)
		e.ReportLaunchCoverage = func(ctx context.Context, report managed.LaunchCoverageReport) error {
			return managed.ReportLaunchCoverage(ctx, path, report)
		}
	}
	if e.ListenerProof == nil {
		e.ListenerProof = func(ctx context.Context, connectorName, keyID, nonce string) (string, error) {
			account, found, err := e.Accounts.Lookup(ctx, e.Layout.ServiceUser)
			if err != nil {
				return "", fmt.Errorf("verify gateway hook socket service account %s: %w", e.Layout.ServiceUser, err)
			}
			if !found || account.UID < 1 {
				return "", fmt.Errorf("gateway hook socket service account %s is unavailable", e.Layout.ServiceUser)
			}
			return listenerProof(ctx, e.P(e.Layout.HookSocketPath), e.Layout.APIAddr, account.UID, connectorName, keyID, nonce)
		}
	}
	if e.ProcessExecPath == nil {
		e.ProcessExecPath = processExecPath
	}
	if e.ProcessImagePath == nil {
		e.ProcessImagePath = processImagePath
	}
	if e.DiskSpace == nil {
		e.DiskSpace = diskSpace
	}
	if e.DockerEngine == nil {
		e.DockerEngine = dialDockerEngine
	}
	if e.Services == nil {
		e.Services = newServiceManager(e)
	}
	if e.Accounts == nil {
		e.Accounts = newAccountManager(e)
	}
	if e.MachinePolicy == nil {
		e.MachinePolicy = newMachinePolicyManager(e)
	}
	if e.LockTimeout <= 0 {
		e.LockTimeout = DefaultLockWait
	}
	if e.ReadyTimeout <= 0 {
		e.ReadyTimeout = 90 * time.Second
	}
	if e.PollInterval <= 0 {
		e.PollInterval = 500 * time.Millisecond
	}
	if e.GuardianReportTimeout <= 0 {
		e.GuardianReportTimeout = 30 * time.Second
	}
	if e.ReplacedHookCallsTimeout <= 0 {
		e.ReplacedHookCallsTimeout = replacedHookCallsBudget
	}
}

// serviceEnvironment is the managed environment the guardian service gets
// (the systemd units and launchd plists set the same pins).
func (e *Env) serviceEnvironment() []string {
	env := []string{
		"DEFENSECLAW_HOME=" + e.Layout.DataDir,
		"DEFENSECLAW_CONFIG=" + e.Layout.ConfigPath,
		managed.DeploymentModeEnv + "=" + managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv + "=" + managed.ProfileStandalone,
		"DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=" + e.Layout.GuardianAuthDir,
	}
	if e.GOOS == "darwin" {
		env = append(env, "DEFENSECLAW_UNIX_SERVICE_ACCOUNT="+e.Layout.ServiceUser)
	}
	return env
}

// runGatewayCLI runs the installed gateway binary with the service
// environment, so its commands load the managed standalone config.
func (e *Env) runGatewayCLI(ctx context.Context, args ...string) (CommandResult, error) {
	gateway := filepath.Join(e.P(e.Layout.BinDir), binGateway)
	if runner, ok := e.Runner.(EnvRunner); ok {
		return runner.RunEnv(ctx, e.serviceEnvironment(), gateway, args...)
	}
	return e.Runner.Run(ctx, gateway, args...)
}

// removeAllTimeout bounds `enterprise hooks remove-all`, which retries a
// per-user worker that timed out with a longer deadline (GAP-0517); the
// default two-minute command bound would cut that retry short.
const removeAllTimeout = 15 * time.Minute

// runGatewayCLILong is runGatewayCLI with a longer bound for the production
// runner.
func (e *Env) runGatewayCLILong(ctx context.Context, timeout time.Duration, args ...string) (CommandResult, error) {
	if runner, ok := e.Runner.(ExecRunner); ok {
		runner.Timeout = timeout
		return runner.RunEnv(ctx, e.serviceEnvironment(), filepath.Join(e.P(e.Layout.BinDir), binGateway), args...)
	}
	return e.runGatewayCLI(ctx, args...)
}

// P maps a canonical layout path onto the rooted filesystem.
func (e *Env) P(path string) string {
	if e.Root == "" {
		return path
	}
	return filepath.Join(e.Root, path)
}

func defaultTrust(path string, kind TrustKind) error {
	switch kind {
	case TrustAdminFile:
		return managed.ValidateTrustedFilePath(path, "managed file")
	case TrustRuntimeDir:
		return managed.ValidateTrustedRuntimeDir(path, "managed runtime directory")
	case TrustRuntimeFile:
		return managed.ValidateTrustedServiceRuntimeFilePath(path, "managed runtime file", "")
	case TrustRulePack:
		return rulePackTrust(path)
	case TrustAdminDir:
		return managed.ValidateTrustedInstallMarkerDir(path, "managed host security directory")
	}
	return fmt.Errorf("unknown trust kind %d", kind)
}

// getHealth probes the gateway health endpoint at address on network
// ("unix" for the hook socket, "tcp" for the loopback API) without proxies;
// host is the request's Host.
func getHealth(ctx context.Context, network, address, host string) (int, []byte, error) {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/health", nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, err
}

// getProtectedAPIHealth is the upgrade fallback for an earlier gateway that
// does not answer /health on its hook socket. Verify the accepted TCP socket
// against the active systemd or launchd service before sending the request or
// accepting a health decision from the listener.
func getProtectedAPIHealth(ctx context.Context, goos, address string) (int, []byte, error) {
	service := unitGateway
	if goos == "darwin" {
		service = labelGateway
	} else if goos != "linux" {
		return 0, nil, fmt.Errorf("gateway API listener unverified on %s", goos)
	}
	client, err := hookexec.NewManagedEnterpriseGatewayHTTPClient(5*time.Second, address, service)
	if err != nil {
		return 0, nil, fmt.Errorf("gateway API listener unverified: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/health", nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("gateway API listener unverified or unavailable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, err
}

// hookSocketPeer dials the hook socket and reads the listener's
// credentials.
func hookSocketPeer(ctx context.Context, path string) (peercred.Credentials, error) {
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", path)
	if err != nil {
		return peercred.Credentials{}, err
	}
	defer conn.Close()
	return peercred.FromConn(conn)
}

// gatewayServing checks that the gateway serves the hook socket, where the
// lifecycle reads its health (gatewayHealth). A /health answer on
// 127.0.0.1:18970 can come from any local process that bound the port while
// the gateway's own listener is down (on macOS while the gateway job
// restarts, on Linux while the socket unit is stopped). The hook socket
// lives in a directory only the service account can write, and the kernel
// reports who is listening on it: the service account, or root. On Linux
// PID 1 holds the socket-activated listener and hands it only to the
// gateway unit; elsewhere the listener must be the gateway process itself.
func (e *Env) gatewayServing(ctx context.Context, gateway Unit, serviceUID int) error {
	peer, err := e.HookSocketPeer(ctx)
	if err != nil {
		return e.hookSocketProblem(err)
	}
	if peer.UID != serviceUID && peer.UID != 0 {
		return fmt.Errorf("the hook socket %s is served by uid %d, not the %s service account (uid %d)", e.Layout.HookSocketPath, peer.UID, e.Layout.ServiceUser, serviceUID)
	}
	if e.GOOS == "linux" && peer.PID == 1 {
		return nil
	}
	if status, err := e.Services.Status(ctx, gateway); err == nil && status.PID > 0 && peer.PID > 0 && status.PID != peer.PID {
		return fmt.Errorf("the hook socket %s is served by pid %d, not the gateway job (pid %d)", e.Layout.HookSocketPath, peer.PID, status.PID)
	}
	return nil
}

// CurrentGOOS is the host OS; the CLI refuses a lifecycle for another OS.
func CurrentGOOS() string { return runtime.GOOS }
