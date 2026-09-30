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

// Package sandboxcli implements the `defenseclaw sandbox …` commands: the
// one-time setup, doctor, `run` (preflight, launch banner, terminal attach,
// end-of-session review), the lifecycle and approval commands that drive
// the daemon's sandbox REST API, copy-mode pull, policy and pack
// inspection, overlay image builds, the shell wrappers and teardown.
//
// The daemon is the single writer of sandboxes, providers, bindings,
// approvals and egress rules; the commands here own the terminal, the
// copy-mode workspace, the installer and the user's shell rc files. Every
// external effect goes through a field of App, so the commands are tested
// against a fake REST server, a fake terminal and temporary directories.
package sandboxcli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// CommandName is how messages refer to the CLI.
const CommandName = "defenseclaw sandbox"

// API is the daemon's sandbox REST surface. *sandboxapi.Client implements
// it.
type API interface {
	Status(ctx context.Context) (*sandboxapi.Status, error)
	List(ctx context.Context) ([]sandboxapi.Sandbox, error)
	Get(ctx context.Context, name string) (*sandboxapi.Sandbox, error)
	Create(ctx context.Context, req sandboxapi.CreateRequest) (*sandboxapi.Sandbox, error)
	Delete(ctx context.Context, name string, req sandboxapi.DeleteRequest) (*sandboxapi.DeleteResponse, error)
	Stop(ctx context.Context, name string) (*sandboxapi.Sandbox, error)
	Start(ctx context.Context, name string, req sandboxapi.StartRequest) (*sandboxapi.Sandbox, error)
	Undo(ctx context.Context, name string, req sandboxapi.UndoRequest) (*sandboxapi.UndoResponse, error)
	Review(ctx context.Context, name string, req sandboxapi.ReviewRequest) (*sandboxapi.ReviewResponse, error)
	Accept(ctx context.Context, name string, req sandboxapi.AcceptRequest) (*sandboxapi.Sandbox, error)
	RunLog(ctx context.Context, name string, lines int) (*sandboxapi.RunLog, error)
	ReportWorkspace(ctx context.Context, name string, r sandboxapi.WorkspaceReport) error
	Approvals(ctx context.Context, sandbox string) ([]sandboxapi.Approval, error)
	Decide(ctx context.Context, id string, d sandboxapi.ApprovalDecision) (*sandboxapi.ApprovalResult, error)
	Unblock(ctx context.Context, req sandboxapi.UnblockRequest) (*sandboxapi.UnblockResponse, error)
	Explain(ctx context.Context, req sandboxapi.ExplainRequest) (*sandboxapi.Explain, error)
	Activity(ctx context.Context, q sandboxapi.ActivityQuery, fn func(sandboxapi.ActivityEvent) error) error
}

var _ API = (*sandboxapi.Client)(nil)

// IO is the process's terminal.
type IO struct {
	In       io.Reader
	Out, Err io.Writer
	// TTY reports that In and Out are a terminal (prompts and attach).
	TTY bool
	// OutTTY and ErrTTY report that Out and Err are terminals: what a
	// sandbox prints there (a run log, a headless harness's output) cannot
	// drive them (sandboxOutput).
	OutTTY, ErrTTY bool
	// Color enables ANSI styling of Out.
	Color bool
}

// Terminal runs an interactive openshell invocation as a foreground child
// that owns the terminal, and returns its exit status.
type Terminal interface {
	Run(ctx context.Context, inv openshell.Invocation) (int, error)
}

// Streamer runs a non-interactive openshell invocation with its output on
// stdout and stderr, and returns its exit status.
type Streamer interface {
	Stream(ctx context.Context, inv openshell.Invocation, stdout, stderr io.Writer) (int, error)
}

// App runs the sandbox commands. Zero-valued fields take the real system;
// see defaults.
type App struct {
	Cfg *config.Config
	// ConfigPath is the config.yaml policy and setup changes write.
	ConfigPath string
	// API is the daemon's sandbox API (default: built from Cfg).
	API API
	IO  IO

	Terminal Terminal
	Streamer Streamer
	// ExecProcess replaces the process (nested runs inside a sandbox).
	ExecProcess func(path string, argv, env []string) error
	LookPath    func(string) (string, error)
	Getenv      func(string) string
	Environ     func() []string
	Getwd       func() (string, error)
	Home        func() (string, error)
	// Executable is the DefenseClaw binary the shell wrappers call.
	Executable func() (string, error)
	Now        func() time.Time
	GOOS       string
	// GOARCH is the machine's architecture: a Mac runs sandboxes on Apple
	// silicon only.
	GOARCH string
	// WSL reports a Linux kernel running under Windows (WSL2).
	WSL func() bool
	// Geteuid is the effective uid (sandboxes refuse root).
	Geteuid func() int
	// DiskFree is the free space of the file system holding a path
	// (openshell.DiskFree): the MicroVM driver prepares a disk of about an
	// image's size from each image a sandbox first boots.
	DiskFree func(path string) (uint64, error)
	// DockerEngine is the operating system of the Docker engine the docker
	// CLI talks to (openshell.DockerEngineOS): on a Mac whose gateway runs
	// the docker driver, Docker Desktop's refuses a run up front
	// (dockerDesktopRefusal).
	DockerEngine func(ctx context.Context) (string, error)
	// Sleep waits between polls (tests make it instant).
	Sleep func(context.Context, time.Duration) error
	// HookWindow is how long a harness session may run before its first
	// authenticated hook is overdue and the run warns that the hooks do
	// not reach DefenseClaw (DefaultHookWindow).
	HookWindow time.Duration

	// Host integrations, replaceable in tests. HostDoctor runs the host
	// checks of d (default d.Run).
	HostDoctor func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport
	Images     ImageService
	Workspace  CopyWorkspace
	Gateway    GatewayService
	Installer  func(consent func(*openshell.InstallPlan) (bool, error)) Installer
	OpenShell  func(ctx context.Context) (openshell.Client, *openshell.Registration, error)
	// GitConfig is the value of a git configuration key as the host's git
	// reads it in dir (the repository's, the user's and the system's), ""
	// when unset.
	GitConfig func(ctx context.Context, dir, key string) string

	once   sync.Once
	reader *bufio.Reader
	// pending is an answer a prompt Ctrl-C ended was still reading (the
	// next prompt takes it).
	pending chan lineRead
	// interrupts delivers the user's Ctrl-C while a prompt waits (default:
	// SIGINT); tests replace it.
	interrupts func() (<-chan os.Signal, func())
	// pager shows text longer than the terminal one screen at a time and
	// reports whether it did (default: $PAGER or less on a terminal).
	pager func(text string) bool
	// intr is the interrupt state of the running command (interrupt.go).
	intr *interruption
}

// ErrUnsupported is returned on platforms and setups sandboxes do not run
// on.
var ErrUnsupported = errors.New("OpenShell sandboxes are not supported here")

// ExitError carries a process exit status (a harness's own, or a failed
// check) without printing anything more.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("exit status %d", e.Code)
}

func (e *ExitError) Unwrap() error { return e.Err }

// ExitCode is the status to exit with.
func (e *ExitError) ExitCode() int { return e.Code }

// ExitHooksUnreachable is the exit status of a session that ended without
// one of its hooks reaching DefenseClaw (sysexits EX_UNAVAILABLE): the
// hooks failed closed, so whatever the harness reported, it could do
// nothing. A harness's own non-zero status takes precedence.
const ExitHooksUnreachable = 69

// Silent marks an error whose message was already printed.
type Silent struct{ Err error }

func (s *Silent) Error() string { return s.Err.Error() }
func (s *Silent) Unwrap() error { return s.Err }

func (a *App) defaults() {
	a.once.Do(func() {
		if a.IO.In == nil {
			a.IO.In = os.Stdin
		}
		if a.IO.Out == nil {
			a.IO.Out = os.Stdout
		}
		if a.IO.Err == nil {
			a.IO.Err = os.Stderr
		}
		if a.Terminal == nil {
			a.Terminal = ForegroundTerminal{}
		}
		if a.Streamer == nil {
			a.Streamer = CommandStreamer{}
		}
		if a.ExecProcess == nil {
			a.ExecProcess = execProcess
		}
		if a.LookPath == nil {
			a.LookPath = exec.LookPath
		}
		if a.Getenv == nil {
			a.Getenv = os.Getenv
		}
		if a.Environ == nil {
			a.Environ = os.Environ
		}
		if a.Getwd == nil {
			a.Getwd = os.Getwd
		}
		if a.Home == nil {
			a.Home = os.UserHomeDir
		}
		if a.Executable == nil {
			a.Executable = executable
		}
		if a.Now == nil {
			a.Now = time.Now
		}
		if a.GOOS == "" {
			a.GOOS = runtime.GOOS
		}
		if a.GOARCH == "" {
			a.GOARCH = runtime.GOARCH
		}
		if a.Sleep == nil {
			a.Sleep = sleepCtx
		}
		if a.WSL == nil {
			a.WSL = IsWSL
		}
		if a.Geteuid == nil {
			a.Geteuid = os.Geteuid
		}
		if a.DiskFree == nil {
			a.DiskFree = openshell.DiskFree
		}
		if a.DockerEngine == nil {
			a.DockerEngine = func(ctx context.Context) (string, error) {
				return openshell.DockerEngineOS(ctx, openshell.ExecRunner{})
			}
		}
		if a.ConfigPath == "" && a.Cfg != nil {
			a.ConfigPath = strings.TrimSpace(a.Cfg.ConfigFilePath)
		}
		if a.ConfigPath == "" {
			a.ConfigPath = config.ConfigPath()
		}
		if a.Images == nil {
			a.Images = &builderImages{app: a}
		}
		if a.Workspace == nil {
			a.Workspace = defaultCopyWorkspace{}
		}
		if a.Gateway == nil {
			a.Gateway = &gatewayService{app: a}
		}
		if a.Installer == nil {
			a.Installer = a.defaultInstaller
		}
		if a.OpenShell == nil {
			a.OpenShell = a.dialOpenShell
		}
		if a.HostDoctor == nil {
			a.HostDoctor = func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport { return d.Run(ctx) }
		}
		if a.GitConfig == nil {
			a.GitConfig = a.hostGitConfig
		}
		a.reader = bufio.NewReader(a.IO.In)
		// The ssh shim every openshell invocation runs with falls back to
		// this data directory when the temporary directory cannot hold one
		// that runs.
		openshell.SetSSHShimDataDir(a.dataDir())
	})
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// IsWSL reports whether this Linux kernel is WSL's (its release names
// Microsoft).
func IsWSL() bool {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false
	}
	s := strings.ToLower(string(data))
	return strings.Contains(s, "microsoft") || strings.Contains(s, "wsl")
}

func executable() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		p = real
	}
	return p, nil
}

// api returns the daemon client.
func (a *App) api() (API, error) {
	a.defaults()
	if a.API != nil {
		return a.API, nil
	}
	if a.Cfg == nil {
		return nil, errors.New("no DefenseClaw configuration is loaded; run `defenseclaw setup` first")
	}
	c, err := sandboxapi.ClientForConfig(a.Cfg)
	if err != nil {
		return nil, err
	}
	a.API = c
	return c, nil
}

// CheckSupported refuses platforms and deployments sandboxes do not run on,
// with the reason.
func (a *App) CheckSupported() error {
	a.defaults()
	if err := openshell.CheckPlatform(a.GOOS); err != nil || (a.GOOS == "linux" && a.WSL()) {
		return fmt.Errorf("%w: OpenShell sandboxes run on Linux and macOS only; Windows and WSL2 are not supported", ErrUnsupported)
	}
	if err := openshell.CheckHost(a.GOOS, a.GOARCH); err != nil {
		// A Mac that is not Apple silicon.
		return fmt.Errorf("%w: %s", ErrUnsupported, strings.TrimPrefix(err.Error(), "openshell: "))
	}
	if a.Cfg != nil && managed.IsManagedEnterprise(a.Cfg.DeploymentMode) {
		return fmt.Errorf("%w: sandboxes are not supported in managed_enterprise deployments yet", ErrUnsupported)
	}
	if a.Geteuid() == 0 {
		return fmt.Errorf("%w: run sandboxes as your own user, not root: the OpenShell gateway is a per-user service", ErrUnsupported)
	}
	return nil
}

// cli is the openshell argv builder for the daemon's gateway.
func (a *App) cli(gateway string) openshell.CLI {
	bin := openshell.DefaultBinary
	ws := ""
	if a.Cfg != nil {
		bin = a.Cfg.OpenShell.EffectiveBinary()
		ws = a.Cfg.OpenShell.Gateway.Workspace
		if gateway == "" {
			gateway = a.Cfg.OpenShell.Gateway.Name
		}
	}
	return openshell.CLI{Binary: bin, Gateway: gateway, Workspace: ws}
}

// gatewayName is the OpenShell registration the daemon drives.
func (a *App) gatewayName(ctx context.Context) (string, error) {
	if a.Cfg != nil && a.Cfg.OpenShell.Gateway.Name != "" {
		return a.Cfg.OpenShell.Gateway.Name, nil
	}
	api, err := a.api()
	if err == nil {
		if st, err := api.Status(ctx); err == nil && st.Gateway != nil && st.Gateway.Name != "" {
			return st.Gateway.Name, nil
		}
	}
	reg, err := openshell.Discover(openshell.DiscoverOptions{})
	if err != nil {
		return "", fmt.Errorf("find the OpenShell gateway: %w", err)
	}
	return reg.Name, nil
}

func (a *App) dataDir() string {
	if a.Cfg != nil && a.Cfg.DataDir != "" {
		return a.Cfg.DataDir
	}
	return config.DefaultDataPath()
}

func (a *App) dialOpenShell(ctx context.Context) (openshell.Client, *openshell.Registration, error) {
	opts := openshell.DiscoverOptions{}
	cliOpts := openshell.ClientOptions{}
	if a.Cfg != nil {
		opts.Gateway = a.Cfg.OpenShell.Gateway.Name
		cliOpts.Workspace = a.Cfg.OpenShell.Gateway.Workspace
	}
	reg, err := openshell.Discover(opts)
	if err != nil {
		return nil, reg, err
	}
	c, err := openshell.Dial(reg, cliOpts)
	if err != nil {
		return nil, reg, err
	}
	if _, err := c.Health(ctx); err != nil {
		_ = c.Close()
		return nil, reg, err
	}
	return c, reg, nil
}

// project is the real launch folder.
func (a *App) project() (string, error) {
	wd, err := a.Getwd()
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(wd)
	if err != nil {
		return "", err
	}
	return real, nil
}

// apiError explains a daemon error for people. Admin refusals start with
// "blocked by your organization's DefenseClaw policy".
func apiError(err error) error {
	if err == nil {
		return nil
	}
	var e *sandboxapi.Error
	if !errors.As(err, &e) {
		return err
	}
	switch e.Code {
	case sandboxapi.CodeUnavailable:
		if strings.Contains(e.Message, "daemon is not reachable") {
			return fmt.Errorf("the DefenseClaw daemon is not running (start it with `defenseclaw-gateway start`): %s", e.Detail)
		}
	case sandboxapi.CodeDisabled:
		return fmt.Errorf("%s", e.Message)
	case sandboxapi.CodeAdminViolation:
		return errors.New(violationMessage(e.Violation, e.Message, e.Detail, true))
	case sandboxapi.CodePolicyViolation:
		if e.Violation != nil {
			return errors.New(violationMessage(e.Violation, e.Message, e.Detail, e.Violation.Admin))
		}
	}
	return e
}

// adminLimitMessage opens an organization's clamp: the run goes ahead with
// the organization's value instead of the one asked for.
const adminLimitMessage = "limited by your organization's DefenseClaw policy"

// violationMessage renders a refused setting with why and what to do.
// Admin refusals read "blocked by your organization's DefenseClaw policy:
// <key> — <why> (<openshell.admin constraint>); <next step>", and clamps
// the run goes ahead with "limited by your organization's DefenseClaw
// policy: <key> — <why> (<constraint>); running with <value> instead of
// <asked>".
func violationMessage(v *sandboxapi.Violation, message, detail string, admin bool) string {
	if v != nil && (admin || v.Admin) {
		clamp := !v.Fatal && v.Enforced != ""
		msg := sandboxapi.AdminMessage + ": " + v.Key
		if clamp {
			msg = adminLimitMessage + ": " + v.Key
		}
		if v.Message != "" && !strings.Contains(v.Message, sandboxapi.AdminMessage) {
			msg += " (" + v.Message + ")"
		}
		why := firstNonEmpty(v.Detail, detail)
		if v.Key == "harness" || v.Key == "harness.allowed" {
			why = harnessCommands(why)
		}
		if why != "" && !strings.Contains(msg, why) {
			msg += " — " + why
		}
		if c := v.Constraint; strings.HasPrefix(c, "openshell.admin.") {
			msg += " (" + c + ")"
		}
		switch e := v.Enforced; {
		case e == "" || strings.Contains(why, "the run uses"):
		case clamp && v.Attempted != "" && v.Attempted != e && !strings.HasPrefix(v.Attempted, "("):
			msg += "; running with " + v.Key + " " + e + " instead of " + v.Attempted
		case e != "true" && e != "false":
			msg += "; the run uses " + v.Key + " " + e
		}
		if next := adminNextStep(v, why); next != "" {
			msg += "; " + next
		}
		return msg
	}
	if v != nil && v.Message != "" {
		if d := firstNonEmpty(v.Detail, detail); d != "" && !strings.Contains(v.Message, d) {
			return v.Message + " — " + d
		}
		return v.Message
	}
	if admin && !strings.HasPrefix(message, sandboxapi.AdminMessage) {
		message = sandboxapi.AdminMessage + ": " + message
	}
	if detail != "" {
		return message + ": " + detail
	}
	return message
}

// harnessCommands names the harnesses in a policy's text by the command
// users type (`sandbox run claude`), not their connector names
// (claudecode).
func harnessCommands(text string) string {
	if text == "" {
		return text
	}
	for _, name := range harness.Names() {
		spec, _ := harness.Get(name)
		if spec.Command == name {
			continue
		}
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
		text = re.ReplaceAllString(text, spec.Command)
	}
	return text
}

// wireViolation is a policy refusal the CLI found itself, in the daemon's
// wire form (so it reads like the daemon's).
func wireViolation(v packs.Violation) sandboxapi.Violation {
	return sandboxapi.Violation{
		Key: v.Key, Source: string(v.Source), Attempted: v.Attempted, Enforced: v.Enforced,
		Constraint: v.Constraint, Fatal: v.Fatal, Admin: v.Admin(), Message: v.Message, Detail: v.Detail,
	}
}

// adminNextStep is the way on after an organization's refusal, when why
// does not say it already.
func adminNextStep(v *sandboxapi.Violation, why string) string {
	if v.Enforced != "" {
		// A clamp: the run goes ahead with the organization's value.
		return ""
	}
	switch strings.TrimPrefix(v.Constraint, "openshell.admin.") {
	case "allow_mount", "require_copy_for":
		return "run it with --copy (a sandbox that mounts the folder live must be deleted and run again with --copy)"
	case "allow_host_ports":
		return "run it without --host-port"
	case "max_resources":
		return "ask for less with --cpu or --memory"
	case "allowed_harnesses", "egress_block", "egress_allow_only":
		if !strings.Contains(why, "administrator") {
			return "ask your administrator if you need it"
		}
	}
	return ""
}
