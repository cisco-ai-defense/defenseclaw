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

//go:build unix

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// sandboxOpenShellExecCmd is the exec shim the managed OpenShell gateway
// unit runs in both install modes (D4): defenseclaw-openshell-gateway.service
// on Linux, the com.cisco.defenseclaw.openshell-gateway.<tag> LaunchAgent on macOS.
// Unit files cannot expand $HOME on macOS and the upstream unit's umask
// breaks every MicroVM (UMask 0077, GAP-0009), so the shim sets the umask,
// the root-owned rendered gateway configuration, the account's MicroVM
// identity, the per-user TLS directory and a pinned PATH (the trusted
// e2fsprogs directory first, GAP-0004), then execs the openshell-gateway of
// the install mode: the user's own in ~/.local/bin (setup) or the
// administrator's in /usr/bin or /usr/local/bin (prerequisite).
var sandboxOpenShellExecCmd = &cobra.Command{
	Use:                "sandbox-openshell-exec",
	Short:              "Exec this account's OpenShell gateway under the managed settings",
	Hidden:             true,
	DisableFlagParsing: true,
	SilenceUsage:       true,
	Annotations:        map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
	PersistentPreRunE:  func(*cobra.Command, []string) error { return nil },
	PersistentPostRun:  func(*cobra.Command, []string) {},
	RunE: func(cmd *cobra.Command, args []string) error {
		plan, err := planSandboxOpenShellExec(cmd.Context(), runtime.GOOS, args)
		if err != nil {
			// A missing or untrusted prerequisite (an account that has not
			// installed OpenShell yet, say) is no failure to restart for.
			return withExitCode(err, sandboxPrerequisiteExit)
		}
		// The account's local PKI is written owner-only (the upstream
		// unit generates it under UMask=0077); the gateway itself runs
		// with 0022, which the MicroVM guests need (GAP-0009).
		syscall.Umask(0o077)
		if err := generateOpenShellCerts(plan); err != nil {
			return err
		}
		syscall.Umask(0o022)
		return syscall.Exec(plan.binary, plan.argv, plan.env)
	},
}

func init() {
	rootCmd.AddCommand(sandboxOpenShellExecCmd)
}

// errOpenShellPrerequisiteMissing is the refusal of a missing or untrusted
// OpenShell prerequisite (openshell_prerequisite_missing).
var errOpenShellPrerequisiteMissing = errors.New("openshell_prerequisite_missing")

// openShellExecPlan is what the shim execs.
type openShellExecPlan struct {
	binary string
	argv   []string
	env    []string
	// tlsDir is the account's local OpenShell PKI and certs the
	// generate-certs arguments that create it before the gateway starts,
	// as the upstream unit's ExecStartPre does. It is idempotent: a
	// complete PKI is kept.
	tlsDir string
	certs  []string
}

// openShellServerSAN is the name MicroVM guests reach the gateway by.
const openShellServerSAN = "host.openshell.internal"

// openShellGenerateCerts runs the gateway's generate-certs; a seam for tests.
var openShellGenerateCerts = func(plan openShellExecPlan) error {
	cmd := exec.Command(plan.binary, plan.certs...)
	cmd.Env = plan.env
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

// generateOpenShellCerts creates the account's local OpenShell PKI (0700)
// when it is not complete yet.
func generateOpenShellCerts(plan openShellExecPlan) error {
	if err := os.MkdirAll(plan.tlsDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", plan.tlsDir, err)
	}
	if err := openShellGenerateCerts(plan); err != nil {
		return fmt.Errorf("openshell-gateway generate-certs: %w", err)
	}
	return nil
}

// Seams for tests.
var (
	openShellExecHome             = sandboxAccountHome
	openShellExecTrustedFile      = managed.ValidateTrustedFilePath
	openShellExecTrustedDir       = managed.ValidateTrustedRuntimeDir
	openShellExecSettings         = sandboxOpenShellAdminSettings
	openShellExecAdminBinary      = openshell.AdminBinary
	openShellExecRenderedEnv      = openshell.RenderedEnvironment
	openShellExecVMProbe          = sandboxOpenShellVMProbe
	openShellExecRenderedVMDriver = func(goos, dir string) (string, string) {
		return openshell.RenderedAdminVMDriver(goos, dir, openshell.ExecutableVMDriver,
			func(p string) error { return openShellExecTrustedFile(p, "OpenShell MicroVM driver") })
	}
	// openShellExecUpstreamTelemetry reports whether the account's own
	// floor allows OpenShell's own telemetry (es:GAP-0144).
	openShellExecUpstreamTelemetry = sandboxOpenShellUpstreamTelemetry
)

// planSandboxOpenShellExec checks the managed host and the OpenShell of the
// install mode and returns the exec. args are passed on to openshell-gateway.
func planSandboxOpenShellExec(ctx context.Context, goos string, args []string) (openShellExecPlan, error) {
	if os.Getuid() == 0 {
		return openShellExecPlan{}, errors.New("the OpenShell gateway runs as your own user, not root")
	}
	layout, _, err := sandboxDaemonHost(goos)
	if errors.Is(err, managed.ErrNoRuntimeDescriptor) {
		return openShellExecPlan{}, errNotStandaloneManaged
	}
	if err != nil {
		return openShellExecPlan{}, fmt.Errorf("the managed runtime descriptor is not trusted: %w", err)
	}
	configPath := filepath.Join(layout.ConfigDir, "openshell", "gateway.toml")
	if err := openShellExecTrustedFile(configPath, "OpenShell gateway configuration"); err != nil {
		return openShellExecPlan{}, fmt.Errorf("%w: the administrator's OpenShell gateway configuration %s: %v "+
			"(an administrator renders it with `enterprise %s ensure`)", errOpenShellPrerequisiteMissing, configPath, err, openshell.EnterprisePlatformName(goos))
	}
	home, err := openShellExecHome()
	if err != nil {
		return openShellExecPlan{}, err
	}
	settings := openShellExecSettings(ctx)
	install := settings.Install
	if install == "" {
		// The managed gateway did not answer: an account with an OpenShell
		// of its own runs it (setup mode), any other the administrator's.
		install = config.EnterpriseOpenShellInstallPrerequisite
		if ownFileOnly(filepath.Join(home, ".local", "bin", openshell.GatewayBinary)) == nil {
			install = config.EnterpriseOpenShellInstallSetup
		}
	}
	var binary, binDir string
	if install == config.EnterpriseOpenShellInstallSetup {
		binDir = filepath.Join(home, ".local", "bin")
		binary = filepath.Join(binDir, openshell.GatewayBinary)
		if err := ownFileOnly(binary); err != nil {
			return openShellExecPlan{}, fmt.Errorf("%w: %v", errOpenShellPrerequisiteMissing, err)
		}
	} else {
		// The administrator's OpenShell, never a binary of the account's:
		// root-owned and closed to every other writer (GAP-0186).
		binary, err = openShellExecAdminBinary(goos, openshell.GatewayBinary, func(p string) error {
			return openShellExecTrustedFile(p, "OpenShell gateway")
		})
		if err != nil {
			return openShellExecPlan{}, fmt.Errorf("%w: %v (the administrator installs OpenShell for enterprise.openshell.install: prerequisite)",
				errOpenShellPrerequisiteMissing, err)
		}
		binDir = filepath.Dir(binary)
	}
	if goos == "linux" {
		configPath = openShellExecConfigFor(configPath, home, settings.DriverFallback, binary)
		configPath = openShellExecBridgeFor(configPath, home)
		if install == config.EnterpriseOpenShellInstallPrerequisite {
			if err := openShellExecVMDriver(configPath, goos); err != nil {
				return openShellExecPlan{}, fmt.Errorf("%w: %v (an administrator refreshes it with `enterprise linux ensure`)", errOpenShellPrerequisiteMissing, err)
			}
		}
	}
	path := []string{binDir}
	for _, dir := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		if dir != binDir {
			path = append(path, dir)
		}
	}
	if goos == "darwin" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return openShellExecPlan{}, fmt.Errorf("%w: read the administrator's rendered gateway configuration: %v", errOpenShellPrerequisiteMissing, err)
		}
		rendered, err := openshell.ParseRenderedGateway(data, nil)
		if err != nil || rendered.Validate() != nil {
			return openShellExecPlan{}, fmt.Errorf("%w: invalid administrator's rendered gateway configuration", errOpenShellPrerequisiteMissing)
		}
		if rendered.ComputeDriver == openshell.DriverVM {
			e2fs, err := openShellE2fsprogs(settings.E2fsprogsDir, home)
			if err != nil {
				return openShellExecPlan{}, err
			}
			path = append([]string{e2fs}, path...)
		}
	}
	// The gateway's state folder is DefaultStateHome: the environment
	// below has no XDG_STATE_HOME, and the daemon finds the gateway's
	// files there.
	tlsDir := filepath.Join(openshell.DefaultStateHome(home), "openshell", "tls")
	env := []string{
		"HOME=" + home,
		"PATH=" + strings.Join(path, ":"),
		"OPENSHELL_GATEWAY_CONFIG=" + configPath,
		openshell.EnvLocalTLSDir + "=" + tlsDir,
	}
	for _, keep := range []string{"USER", "LOGNAME", "LANG", "TMPDIR", "XDG_RUNTIME_DIR"} {
		if v, ok := os.LookupEnv(keep); ok {
			env = append(env, keep+"="+v)
		}
	}
	// The administrator's rendered gateway.env carries the settings
	// gateway.toml can't (OpenShell's own telemetry switch, off unless the
	// organization's floor allows it). A file that is there but not
	// trusted refuses the start; a missing one leaves the defaults.
	envPath := filepath.Join(layout.ConfigDir, "openshell", openshell.GatewayEnvFile)
	rendered, err := openShellExecRenderedEnv(envPath)
	if err != nil {
		return openShellExecPlan{}, fmt.Errorf("%w: the administrator's OpenShell gateway environment %s: %v "+
			"(an administrator renders it with `enterprise %s ensure`)", errOpenShellPrerequisiteMissing, envPath, err, openshell.EnterprisePlatformName(goos))
	}
	env = append(env, rendered...)
	if !openShellExecUpstreamTelemetry(ctx) {
		// The rendered file is the host's: the organization's floor. The
		// account's own profile may turn OpenShell's telemetry off
		// (allow_upstream_telemetry: false), and so does a managed gateway
		// that did not answer; it never turns it on (es:GAP-0144). The one
		// entry is replaced, not repeated: getenv reads the first.
		env = slices.DeleteFunc(env, func(kv string) bool { return strings.HasPrefix(kv, openshell.EnvTelemetryEnabled+"=") })
		env = append(env, openshell.EnvTelemetryEnabled+"=false")
	}
	// Every MicroVM runs as the account: the images are built for its uid
	// and gid, which no value in the one rendered file can be (GAP-0254).
	env = append(env, openshell.AccountVMEnvironment(os.Getuid(), os.Getegid())...)
	// On a Mac the gateway asks the Docker engine the harness images were
	// built in: the account's (dockerContextHost). Linux gateways keep the
	// system engine the managed checks judge (GAP-0511).
	if goos == "darwin" {
		if host := dockerContextHost(os.LookupEnv, func() (string, error) { return openShellExecDockerContext(ctx) }); host != "" {
			env = append(env, "DOCKER_HOST="+host)
		}
	}
	argv := append([]string{binary, "--config", configPath}, args...)
	certs := []string{"generate-certs", "--output-dir", tlsDir, "--server-san", openShellServerSAN}
	return openShellExecPlan{binary: binary, argv: argv, env: env, tlsDir: tlsDir, certs: certs}, nil
}

// openShellExecVMDriver checks the driver_dir the gateway will actually
// read. An explicit stale path overrides OpenShell's conventional search,
// even when another trusted driver is installed elsewhere (GAP-0573).
func openShellExecVMDriver(configPath, goos string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read the administrator's rendered gateway configuration %s: %w", configPath, err)
	}
	rendered, err := openshell.ParseRenderedGateway(data, nil)
	if err != nil {
		return err
	}
	if err := rendered.Validate(); err != nil {
		return err
	}
	if rendered.ComputeDriver != openshell.DriverVM {
		return nil
	}
	if _, problem := openShellExecRenderedVMDriver(goos, rendered.DriverDir); problem != "" {
		return errors.New(problem)
	}
	return nil
}

// dockerContextHost is the Docker endpoint the account's gateway is to use:
// the one the account's docker CLI uses, with which DefenseClaw builds the
// harness images. The CLI follows DOCKER_HOST, else the account's current
// Docker context (Colima's socket, Docker Desktop's own), while the gateway,
// which follows only DOCKER_HOST and the shim does not pass the caller's
// environment, asked /var/run/docker.sock. On a Mac that can lead to another
// account's engine: the MicroVM driver did not find the image just built and
// tried to pull it from the reserved registry host (GAP-0613). "" (the
// gateway's default) when the CLI names no unix socket or does not answer.
func dockerContextHost(lookupEnv func(string) (string, bool), contextHost func() (string, error)) string {
	if v, ok := lookupEnv("DOCKER_HOST"); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	host, err := contextHost()
	if host = strings.TrimSpace(host); err != nil || !strings.HasPrefix(host, "unix:///") || strings.ContainsAny(host, "\n\r") {
		return ""
	}
	return host
}

// openShellExecDockerContext asks the account's docker CLI (found as image
// builds find it) for its current context's endpoint; tests replace it.
var openShellExecDockerContext = func(ctx context.Context) (string, error) {
	bin, dirs := image.DockerBinary(runtime.GOOS, exec.LookPath, os.Stat)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
	if len(dirs) > 0 {
		cmd.Env = append(os.Environ(), "PATH="+strings.Join(append([]string{os.Getenv("PATH")}, dirs...), string(os.PathListSeparator)))
	}
	out, err := cmd.Output()
	return string(out), err
}

// openShellE2fsprogs is the e2fsprogs directory the macOS MicroVM driver
// gets first on its PATH (D5): the folder of the administrator's
// enterprise.openshell.e2fsprogs_dir that holds mke2fs and debugfs, found
// by the rule ensure checks (openshell.AdminE2fsprogsToolDir, GAP-0506),
// when it passes the managed trust check. Without an administrator value,
// the account's own build wins before the package fallback; a Homebrew keg
// is never selected (GAP-0004).
// The managed doctor calls the same selection rule.
func openShellE2fsprogs(adminDir, home string) (string, error) {
	dir, problem := openshell.ManagedE2fsprogsToolDir(adminDir, home, os.Getuid(),
		func(path string, file bool) error {
			if file {
				return openShellExecTrustedFile(path, "e2fsprogs tool")
			}
			return openShellExecTrustedDir(path, "e2fsprogs")
		})
	if dir == "" {
		return "", fmt.Errorf("%w: %s (an administrator checks it with `enterprise macos verify`)", errOpenShellPrerequisiteMissing, problem)
	}
	return dir, nil
}

// openShellExecConfigFor is the rendered configuration this account's
// gateway starts with on Linux: the MicroVM configuration, or the docker
// fallback's (gateway-docker.toml, which the lifecycle renders only for
// driver vm or auto with driver_fallback docker) when the account's
// fallback is docker (its profile may have tightened it to none; "" when
// the managed gateway did not answer) and its own KVM probe fails now. The
// gateway restarts only while none of the account's sandboxes runs, so a
// running sandbox never switches driver.
func openShellExecConfigFor(configPath, home, fallback, gatewayExecutable string) string {
	if fallback != config.EnterpriseOpenShellFallbackDocker {
		// none, or no answer: the MicroVM configuration, and the daemon
		// refuses the sandbox with the reason.
		return configPath
	}
	fallbackPath := filepath.Join(filepath.Dir(configPath), openshell.GatewayFallbackTOMLFile)
	if _, err := os.Lstat(fallbackPath); err != nil || openShellExecTrustedFile(fallbackPath, "OpenShell docker fallback configuration") != nil {
		return configPath
	}
	if openShellExecVMProbe(home, configPath, gatewayExecutable).OK {
		return configPath
	}
	return fallbackPath
}

// openShellExecBridgeFor is the 1.0.1 upgrade bridge (GAP-0587): the docker
// configuration without a sandbox_label (gateway-docker-default-namespace.toml,
// which the lifecycle renders only on a host upgraded from a 1.0.1 docker
// record) when configPath starts a docker gateway and the account still
// keeps a sandbox in OpenShell's default namespace, where 1.0.1's managed
// gateway made them, and none in the managed one. Its kept sandboxes then
// list, start, connect and pull as before; an account without one, or once
// it deleted the last one (or a purge did), starts in the managed namespace.
// The gateway's own state folder is ~/.local/state (the shim passes HOME and
// no XDG_STATE_HOME). 1.0.1 upgrade bridge, remove when 1.0.1 is out of
// support.
func openShellExecBridgeFor(configPath, home string) string {
	bridgePath := filepath.Join(filepath.Dir(configPath), openshell.GatewayDefaultNamespaceTOMLFile)
	if _, err := os.Lstat(bridgePath); err != nil || openShellExecTrustedFile(bridgePath, "OpenShell docker configuration of the 1.0.1 upgrade bridge") != nil {
		return configPath
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return configPath
	}
	if rendered, err := openshell.ParseRenderedGateway(data, nil); err != nil || rendered.ComputeDriver != openshell.DriverDocker {
		return configPath
	}
	stateHome := openshell.DefaultStateHome(home)
	if !openshell.DockerNamespaceInUse(stateHome, openshell.DefaultDockerNamespace) ||
		!openShellExecDefaultNamespaceSandboxKept(stateHome) {
		return configPath
	}
	if openshell.DockerNamespaceInUse(stateHome, openshell.ManagedDockerNamespace) {
		// Sandboxes in both namespaces (after a downgrade to 1.0.1 and an
		// upgrade again, say): one gateway serves one namespace, and the
		// managed one wins. Without this line the kept 1.0.1 sandboxes only
		// answered "not found" (rel-1-0-3:GAP-0164).
		fmt.Fprintf(openShellExecWarn, "defenseclaw: the 1.0.1 upgrade bridge is off for this account: it keeps sandboxes in both OpenShell docker namespaces, %q "+
			"(the sandboxes kept under 1.0.1) and %q, and one gateway serves one; the gateway starts in %q, so the sandboxes kept under 1.0.1 "+
			"report not found until no sandbox is left in %q (bring back the work of each with `defenseclaw sandbox pull NAME`, then "+
			"`defenseclaw sandbox delete NAME`; their folders are under %s), and the gateway's next start then uses the bridge\n",
			openshell.DefaultDockerNamespace, openshell.ManagedDockerNamespace, openshell.ManagedDockerNamespace, openshell.ManagedDockerNamespace,
			filepath.Join(stateHome, "openshell", "docker-sandbox-tokens", openshell.ManagedDockerNamespace))
		return configPath
	}
	return bridgePath
}

// openShellExecWarn takes the shim's notices: the gateway unit's journal.
// Tests replace it.
var openShellExecWarn io.Writer = os.Stderr

// openShellExecDefaultNamespaceSandboxKept reports whether a sandbox folder
// of the docker driver in OpenShell's default namespace names a sandbox
// Docker still has. A folder outlives its sandbox when the containers were
// removed outside OpenShell or by a purge, and such a stray folder alone
// kept the account on the bridge after its last kept sandbox was deleted
// (GAP-0677). Not knowing (an unreadable folder, a Docker that does not
// answer) counts as kept, so no kept sandbox is stranded. 1.0.1 upgrade
// bridge, remove when 1.0.1 is out of support.
func openShellExecDefaultNamespaceSandboxKept(stateHome string) bool {
	entries, err := os.ReadDir(filepath.Join(stateHome, "openshell", "docker-sandbox-tokens", openshell.DefaultDockerNamespace))
	if err != nil {
		return true
	}
	live, err := openShellExecDefaultNamespaceSandboxIDs()
	if err != nil {
		return true
	}
	for _, entry := range entries {
		if live[entry.Name()] {
			return true
		}
	}
	return false
}

// openShellExecDefaultNamespaceSandboxIDs lists the sandbox ids of the
// containers OpenShell made in its default namespace, on the system Docker
// engine the Linux gateway drives; tests replace it.
var openShellExecDefaultNamespaceSandboxIDs = func() (map[string]bool, error) {
	bin, _ := image.DockerBinary(runtime.GOOS, exec.LookPath, os.Stat)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "container", "ls", "--all", "--no-trunc",
		"--filter", "label=openshell.ai/managed-by=openshell",
		"--filter", "label=openshell.ai/sandbox-namespace="+openshell.DefaultDockerNamespace,
		"--format", `{{.Label "openshell.ai/sandbox-id"}}`)
	cmd.Env = append(slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "DOCKER_HOST=") || strings.HasPrefix(kv, "DOCKER_CONTEXT=")
	}), "DOCKER_HOST=unix:///var/run/docker.sock")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if id := strings.TrimSpace(line); id != "" {
			ids[id] = true
		}
	}
	return ids, nil
}

// sandboxOpenShellVMProbe is the account's MicroVM probe as the user: CPU
// flags, /dev/kvm read-write, and openshell-driver-vm in the rendered
// driver_dir when set, or in the user's and system directories otherwise,
// followed by the sibling of the executable this launcher will start. This works even
// while the gateway is down before its first start.
func sandboxOpenShellVMProbe(home, configPath, gatewayExecutable string) openshell.VMProbeResult {
	dir := ""
	if data, err := os.ReadFile(configPath); err == nil {
		if rendered, err := openshell.ParseRenderedGateway(data, nil); err == nil {
			dir = rendered.DriverDir
		}
	}
	return openshell.VMProbe{DriverDirs: openshell.UserVMDriverDirs(home, dir, gatewayExecutable)}.Run()
}

// sandboxOpenShellAdminSettings asks the managed gateway for
// enterprise.openshell (the zero value when it is unreachable): the install
// mode, the administrator's e2fsprogs directory and the caller's own docker
// fallback.
func sandboxOpenShellAdminSettings(ctx context.Context) sandboxrelay.EnterpriseOpenShell {
	settings, _ := sandboxOpenShellDaemonSettings(ctx)
	return settings.Enterprise
}

// sandboxOpenShellUpstreamTelemetry reports whether the managed gateway's
// settings for the account allow OpenShell's own telemetry: the floor of
// the account's own profile (sandbox_authority_routes.go sandboxOperational),
// false when the gateway does not answer.
func sandboxOpenShellUpstreamTelemetry(ctx context.Context) bool {
	settings, ok := sandboxOpenShellDaemonSettings(ctx)
	return ok && settings.Operational.UpstreamTelemetry
}

// sandboxOpenShellDaemonSettings asks the managed gateway's hook socket for
// the account's settings; ok is false when it does not answer.
func sandboxOpenShellDaemonSettings(ctx context.Context) (sandboxrelay.DaemonSettings, bool) {
	relay, err := sandboxManagedRelay()
	if err != nil {
		return sandboxrelay.DaemonSettings{}, false
	}
	defer relay.Close()
	settings, err := relay.Settings(ctx)
	if err != nil {
		return sandboxrelay.DaemonSettings{}, false
	}
	return settings, true
}

// sandboxManagedRelay is a client of the managed gateway's hook socket, as
// the account's sandbox daemon dials it; an error on a computer DefenseClaw
// does not manage.
func sandboxManagedRelay() (*sandboxrelay.UnixClient, error) {
	layout, descriptor, err := sandboxDaemonHost(runtime.GOOS)
	if err != nil {
		return nil, err
	}
	socket := descriptor.HookSocket
	if socket == "" {
		socket = layout.HookSocketPath
	}
	var trusted []int
	if descriptor.ServiceUID > 0 {
		trusted = append(trusted, descriptor.ServiceUID)
	}
	return sandboxrelay.NewClient(sandboxrelay.ClientOptions{SocketPath: socket, TrustedOwners: trusted, Timeout: 10 * time.Second})
}

// sandboxManagedAccountPolicy is the managed gateway's policy view of the
// caller's new run of harness (sandboxcli.App.ManagedAccountPolicy), asked
// without the account's sandbox daemon.
func sandboxManagedAccountPolicy(ctx context.Context, harness string) (*sandboxapi.ManagedExplain, error) {
	relay, err := sandboxManagedRelay()
	if err != nil {
		return nil, err
	}
	defer relay.Close()
	conn := config.NormalizeConnectorName(harness)
	view, err := relay.Explain(ctx, sandboxrelay.ExplainRequest{Connector: conn, Harness: conn})
	if err != nil {
		return nil, err
	}
	return &view, nil
}

// ownFileOnly checks that path is a regular file the caller owns that no
// other account can write: an OpenShell the user installed (setup mode).
func ownFileOnly(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || int(st.Uid) != os.Getuid() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is not a file of your own that only you can change", path)
	}
	return nil
}
