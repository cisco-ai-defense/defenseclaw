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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
)

// Installer errors.
var (
	// ErrDigestMismatch means the downloaded installer is not the pinned
	// script. Nothing was written or run.
	ErrDigestMismatch = errors.New("openshell: installer digest mismatch")
	// ErrInstallDeclined means the operator did not consent.
	ErrInstallDeclined = errors.New("openshell: install declined")
	// ErrBreakingUpgrade means a pre-0.0.37 OpenShell is present and the
	// operator has not confirmed its runtime was cleaned up.
	ErrBreakingUpgrade = errors.New("openshell: an incompatible OpenShell installation must be cleaned up first")
	// ErrStaleCLI means the new CLI was installed but an old one comes
	// first on PATH, so `openshell` still runs the old one.
	ErrStaleCLI = errors.New("openshell: an old openshell CLI shadows the installed one")
	// ErrHomebrewInstall means the installer failed on macOS, where it
	// installs the nvidia/openshell Homebrew formula; Homebrew's output
	// says why.
	ErrHomebrewInstall = errors.New("openshell: Homebrew could not install the nvidia/openshell formula")
	// ErrUnmanagedUpgrade means Upgrade found a supported CLI that NVIDIA's
	// installer did not install, and would not replace.
	ErrUnmanagedUpgrade = errors.New("openshell: DefenseClaw upgrades only an OpenShell that NVIDIA's installer installed")
	// ErrSandboxesRunning means Upgrade ran nothing: on a gateway whose
	// driver's stop keeps only what the sandboxes synced (the MicroVM
	// driver), OpenShell does not report every sandbox stopped. NVIDIA's
	// script restarts the gateway, which stops them with no flush, only
	// after its downloads and the install (PrepareUpgrade).
	ErrSandboxesRunning = errors.New("openshell: the upgrade was not run: its gateway restart stops every MicroVM on the gateway with no flush, " +
		"so DefenseClaw upgrades only once OpenShell reports each sandbox on it stopped")
	// ErrRuntimeImages means Upgrade ran nothing: Docker could not pull the
	// release's supervisor images (Installer.PrepareUpgrade), without which
	// the restarted gateway's docker driver does not start.
	ErrRuntimeImages = errors.New("openshell: Docker could not pull the images the upgraded gateway starts with")
	// ErrHomebrewPrefix means this account cannot write to the Homebrew
	// prefix (HomebrewPrefixError): Homebrew installs formulas only as the
	// account that owns it. Nothing was downloaded or run.
	ErrHomebrewPrefix = errors.New("openshell: this account cannot install Homebrew formulas")
	// ErrSudo means the install could not use sudo, which NVIDIA's
	// installer needs on Linux to install the openshell package. Nothing
	// was installed or downloaded by the script.
	ErrSudo = errors.New("openshell: the install needs sudo")
)

// linuxPackageCLI is where the deb and rpm packages install the CLI.
const linuxPackageCLI = "/usr/bin/openshell"

// installerEnvUnset lists the inherited OPENSHELL_* variables, which would
// change what the pinned installer does behind the plan's back: it reads
// the release, the install method, the CLI it registers the gateway with
// and runs `status` through (OPENSHELL_REGISTER_BIN), snap paths, and a
// test switch that turns the script into a no-op. Only the plan's Env is
// passed.
func installerEnvUnset(environ []string) []string {
	var names []string
	for _, kv := range environ {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "OPENSHELL_") {
			names = append(names, name)
		}
	}
	return names
}

// DigestMismatchError reports the digest actually downloaded.
type DigestMismatchError struct {
	URL, Want, Got string
}

func (e *DigestMismatchError) Error() string {
	return fmt.Sprintf("openshell: %s has sha256 %s, want the pinned %s; refusing to run it", e.URL, e.Got, e.Want)
}

// Unwrap lets errors.Is(err, ErrDigestMismatch) match.
func (e *DigestMismatchError) Unwrap() error { return ErrDigestMismatch }

// ExistingInstall is an OpenShell CLI already on the machine.
type ExistingInstall struct {
	Path       string
	RawVersion string
	// Version is zero when RawVersion could not be parsed.
	Version Version
}

// InstallPlan is exactly what Install will do. It is printed before the
// consent callback runs.
type InstallPlan struct {
	Release    string
	URL        string
	SHA256     string
	ScriptPath string
	// Command is the program and arguments run; Env the variables set.
	Command []string
	Env     []string
	// Existing is the installation found before the install, if any.
	Existing *ExistingInstall
	// BreakingUpgrade marks a pre-0.0.37 (or unidentifiable) installation
	// whose state 0.1.x cannot use.
	BreakingUpgrade bool
	Notes           []string
	// GOOS is the platform the plan was made for.
	GOOS string
	// ConfigDir is the OpenShell configuration directory the script
	// registers the gateway in, as the plan shows it (~ for the home
	// directory).
	ConfigDir string
}

// String renders the plan for the operator.
func (p *InstallPlan) String() string {
	var b bytes.Buffer
	b.WriteString("OpenShell install plan\n")
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  Release\t%s (NVIDIA OpenShell upstream installer)\n", p.Release)
	fmt.Fprintf(tw, "  Script\t%s\n", p.URL)
	fmt.Fprintf(tw, "  SHA-256\t%s (verified)\n", p.SHA256)
	fmt.Fprintf(tw, "  Saved at\t%s\n", p.ScriptPath)
	fmt.Fprintf(tw, "  Command\t%s\n", strings.Join(append(append([]string{}, p.Env...), p.Command...), " "))
	if p.GOOS == "darwin" {
		// What NVIDIA's script changes besides the formula: Homebrew's own
		// auto-update runs before its install, the script writes the
		// release's formula into the tap, and it registers the gateway.
		fmt.Fprintf(tw, "  Privileges\tnone: the script runs Homebrew as you, without sudo\n")
		fmt.Fprintf(tw, "  Changes\tHomebrew may update itself and its taps first (its auto-update, when due; HOMEBREW_NO_AUTO_UPDATE=1 skips it)\n")
		fmt.Fprintf(tw, "  \tthe release's openshell.rb replaces Formula/openshell.rb in the nvidia/openshell tap (created if missing)\n")
		fmt.Fprintf(tw, "  \tthe script installs the nvidia/openshell/openshell formula and starts the gateway with brew services\n")
		fmt.Fprintf(tw, "  \tit registers that gateway as %q in %s, replacing a registration of that name\n", DefaultGatewayName, p.ConfigDir)
	} else {
		fmt.Fprintf(tw, "  Privileges\tthe script uses sudo to install the openshell package, then enables and\n")
		fmt.Fprintf(tw, "  \tstarts the openshell-gateway user service (systemd --user)\n")
	}
	if p.Existing != nil {
		v := p.Existing.RawVersion
		if v == "" {
			v = "unknown version"
		}
		fmt.Fprintf(tw, "  Existing\t%s at %s\n", v, p.Existing.Path)
	}
	_ = tw.Flush()
	for _, n := range p.Notes {
		fmt.Fprintf(&b, "  ! %s\n", n)
	}
	return b.String()
}

// InstallResult reports what Install did.
type InstallResult struct {
	Plan *InstallPlan
	// Installed is false when a supported release was already present;
	// nothing was downloaded or run, and the gateway was not checked
	// (Doctor does that).
	Installed bool
	// CLIVersion is the release `openshell --version` reports afterwards.
	CLIVersion Version
}

// Installer installs the tag-pinned OpenShell release with the upstream
// installer script, after showing the exact plan and getting consent.
type Installer struct {
	// HTTPClient fetches the script (default: netguard.SafeHTTPClient).
	HTTPClient *http.Client
	// URL, SHA256 and Release default to InstallerURL, InstallerSHA256
	// and InstallerTag.
	URL, SHA256, Release string
	// Shell runs the script (default /bin/sh).
	Shell string
	// TempDir is where the private script directory is created.
	TempDir string
	Runner  Runner
	// LookPath and Candidates locate an existing CLI. Candidates default
	// to the paths the upstream installer probes.
	LookPath   func(string) (string, error)
	Candidates []string
	// PackageCLI is the CLI the installed package provides (default
	// /usr/bin/openshell on Linux; empty on macOS, where the script finds
	// Homebrew's itself). The script registers the gateway with it, not
	// with whatever PATH resolves first, and it is checked first after
	// the install.
	PackageCLI string
	// Out receives the plan (default os.Stdout).
	Out io.Writer
	// Consent must approve the printed plan. Required.
	Consent func(*InstallPlan) (bool, error)
	// ConfirmBreakingUpgrade must confirm that a pre-0.0.37 runtime was
	// backed up and cleaned up; only then is
	// OPENSHELL_ACK_BREAKING_UPGRADE=1 passed.
	ConfirmBreakingUpgrade func(*InstallPlan) (bool, error)
	// VerifyGateway checks the gateway after install (default: discover
	// the Discover registration, dial it and health-check it until
	// GatewayWait).
	VerifyGateway func(context.Context) error
	Discover      DiscoverOptions
	GatewayWait   time.Duration
	// MaxScriptBytes caps the download (default 1 MiB).
	MaxScriptBytes int64
	// GOOS is the platform installed on (default runtime.GOOS).
	GOOS string
	// E2fsprogsDirs are where OpenShell's MicroVM driver looks for
	// e2fsprogs on a Mac (Doctor.E2fsprogsDirs; default the Homebrew kegs
	// it knows): the plan says setup installs it next only when it is not
	// there.
	E2fsprogsDirs []string
	// XcodeApp is the Xcode.app Homebrew checks (default XcodeApp), whose
	// version a failed install on a Mac reports (HomebrewInstallError).
	XcodeApp string
	// PrepareUpgrade readies the gateway for the restart of an upgrade to
	// release. It runs after consent, right before Upgrade runs the script,
	// which restarts the gateway only once it has downloaded and installed
	// the release; an error stops the upgrade with nothing run (default:
	// discover the Discover registration, dial it and PrepareUpgrade, with
	// the images gateway.toml leaves to the release: RuntimeImages).
	PrepareUpgrade func(ctx context.Context, release Version) error
	// CountMicroVMs counts the MicroVMs that run as this account, which
	// PrepareUpgrade's default trusts only when it cannot read the
	// gateway's sandboxes (default CountMicroVMs with Runner).
	CountMicroVMs VMCount
	// LockLifecycle takes the lifecycle lock that keeps DefenseClaw from
	// creating or starting a sandbox from PrepareUpgrade's check to the
	// healthy upgraded gateway, minutes later (default:
	// LockGatewayLifecycle on Discover.ConfigDir).
	LockLifecycle func(context.Context) (unlock func(), err error)
	// Geteuid is the caller's uid (default os.Geteuid): root needs no sudo.
	Geteuid func() int
	// HomebrewPrefixProblem says, on a Mac, why Homebrew cannot install a
	// formula as this account (a HomebrewPrefixError), nil when it can
	// (default: the folders Homebrew writes under homebrewPrefix).
	HomebrewPrefixProblem func() error
	// BrewPrefix is the Homebrew prefix NVIDIA's script installs into on a
	// Mac (default: HOMEBREW_PREFIX, else the brew LookPath finds, else
	// /opt/homebrew). Writable reports whether this account can create
	// entries in a directory (default: access(2)).
	BrewPrefix string
	Writable   func(dir string) bool
}

// HomebrewPrefixError is ErrHomebrewPrefix: Path, a folder Homebrew writes
// to tap and install a formula, is not writable by this account; Owner
// owns it.
type HomebrewPrefixError struct {
	Prefix, Path, Owner string
}

func (e *HomebrewPrefixError) Error() string {
	owner := ""
	if e.Owner != "" {
		owner = ", which " + e.Owner + " owns,"
	}
	return fmt.Sprintf("openshell: this account cannot write to %s%s so Homebrew at %s cannot install the nvidia/openshell formula as this account", e.Path, owner, e.Prefix)
}

func (e *HomebrewPrefixError) Is(target error) bool { return target == ErrHomebrewPrefix }

// homebrewPrefixProblem checks the folders under prefix Homebrew writes to
// when it taps a repository (Library/Taps, else Library) and installs a
// formula (Cellar). One that does not exist is not judged.
func homebrewPrefixProblem(prefix string, writable func(string) bool) error {
	for _, candidates := range [][]string{{filepath.Join(prefix, "Library", "Taps"), filepath.Join(prefix, "Library")}, {filepath.Join(prefix, "Cellar")}} {
		for _, dir := range candidates {
			info, err := os.Stat(dir)
			if err != nil || !info.IsDir() {
				continue
			}
			if !writable(dir) {
				return &HomebrewPrefixError{Prefix: prefix, Path: dir, Owner: ownerName(info)}
			}
			break
		}
	}
	return nil
}

func (i *Installer) defaults() {
	if i.GOOS == "" {
		i.GOOS = runtime.GOOS
	}
	if i.E2fsprogsDirs == nil {
		i.E2fsprogsDirs = e2fsprogsDirs
	}
	if i.XcodeApp == "" {
		i.XcodeApp = XcodeApp
	}
	if i.HTTPClient == nil {
		i.HTTPClient = netguard.SafeHTTPClient(2 * time.Minute)
	}
	if i.URL == "" {
		i.URL = InstallerURL
	}
	if i.SHA256 == "" {
		i.SHA256 = InstallerSHA256
	}
	if i.Release == "" {
		i.Release = InstallerTag
	}
	if i.Shell == "" {
		i.Shell = "/bin/sh"
	}
	if i.Runner == nil {
		i.Runner = ExecRunner{}
	}
	if i.LookPath == nil {
		i.LookPath = exec.LookPath
	}
	if i.BrewPrefix == "" && i.GOOS == "darwin" {
		i.BrewPrefix = findHomebrewPrefix(os.Getenv, i.LookPath)
	}
	if i.Writable == nil {
		i.Writable = writableByCaller
	}
	if i.Candidates == nil {
		i.Candidates = []string{"/usr/local/bin/openshell", "/usr/bin/openshell", "/opt/homebrew/bin/openshell"}
		// With HOME unset or relative the join would name a file below
		// the working directory.
		if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
			i.Candidates = append([]string{filepath.Join(home, ".local", "bin", "openshell")}, i.Candidates...)
		}
	}
	if i.PackageCLI == "" && i.GOOS == "linux" {
		i.PackageCLI = linuxPackageCLI
	}
	if i.Out == nil {
		i.Out = os.Stdout
	}
	if i.GatewayWait <= 0 {
		i.GatewayWait = 90 * time.Second
	}
	if i.VerifyGateway == nil {
		i.VerifyGateway = func(ctx context.Context) error { return WaitForGateway(ctx, i.Discover, i.GatewayWait) }
	}
	if i.MaxScriptBytes <= 0 {
		i.MaxScriptBytes = 1 << 20
	}
	if i.CountMicroVMs == nil {
		i.CountMicroVMs = func(ctx context.Context) (int, error) { return CountMicroVMs(ctx, i.Runner) }
	}
	if i.PrepareUpgrade == nil {
		i.PrepareUpgrade = i.prepareUpgrade
	}
	if i.LockLifecycle == nil {
		i.LockLifecycle = func(ctx context.Context) (func(), error) { return LockGatewayLifecycle(ctx, i.Discover.ConfigDir) }
	}
	if i.Geteuid == nil {
		i.Geteuid = os.Geteuid
	}
	if i.HomebrewPrefixProblem == nil {
		i.HomebrewPrefixProblem = func() error { return homebrewPrefixProblem(homebrewPrefix(), dirWritable) }
	}
}

// checkSudo makes sure, before the script runs, that sudo will let it
// install the openshell package (Linux): at once when sudo needs no
// password, else with sudo's own password prompt now, which then lasts
// for the script. A refused or cancelled prompt, or no sudo, is ErrSudo,
// with nothing installed.
func (i *Installer) checkSudo(ctx context.Context) error {
	if i.GOOS != "linux" || i.Geteuid() == 0 {
		return nil
	}
	_, err := i.Runner.Output(ctx, Command{Name: "sudo", Args: []string{"-n", "true"}, Timeout: 15 * time.Second})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, exec.ErrNotFound):
		return fmt.Errorf("%w, which is not installed here", ErrSudo)
	}
	fmt.Fprintln(i.Out, "  sudo asks for your password now, before anything is installed:")
	if err := i.Runner.Run(ctx, Command{Name: "sudo", Args: []string{"-v"}}); err != nil {
		if errors.Is(err, ErrInterrupted) || ctx.Err() != nil {
			return fmt.Errorf("%w: cancelled at sudo's password prompt", ErrSudo)
		}
		return fmt.Errorf("%w, which did not accept this account (%v)", ErrSudo, err)
	}
	return nil
}

// Install runs the flow: detect an existing CLI, download the pinned
// script into a private directory and verify its digest (nothing touches
// disk before that), print the plan, get consent (and, for a pre-0.0.37
// install, a separate confirmation), run the script with
// OPENSHELL_VERSION pinned, then verify `openshell --version` and the
// gateway. A supported CLI is kept as it is: nothing is downloaded or run.
// One older than SupportedMin (a legacy release, LegacyMin, or an older
// one the installer upgrades in place) is upgraded in place, as Upgrade
// does: PrepareUpgrade runs first, so a MicroVM that OpenShell does not
// report stopped defers the upgrade with nothing run.
func (i *Installer) Install(ctx context.Context) (*InstallResult, error) {
	return i.install(ctx, false)
}

// Upgrade is Install, but a supported CLI older than Release is upgraded
// in place too: NVIDIA's installer installs the release's package (on a
// Mac, reinstalls the Homebrew formula), then restarts the gateway, so
// PrepareUpgrade runs first. It never downgrades (a CLI of Release or
// later is kept), and it refuses a CLI the install would not replace, one
// installed another way than NVIDIA's installer (ErrUnmanagedUpgrade):
// that one is upgraded the way it was installed.
func (i *Installer) Upgrade(ctx context.Context) (*InstallResult, error) {
	return i.install(ctx, true)
}

func (i *Installer) install(ctx context.Context, upgrade bool) (*InstallResult, error) {
	i.defaults()
	if err := CheckPlatform(i.GOOS); err != nil {
		return nil, err
	}
	if i.Consent == nil {
		return nil, errors.New("openshell: install needs a consent callback")
	}
	if u, err := url.Parse(i.URL); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("openshell: installer URL must be https, got %q", i.URL)
	}
	existing := i.findExisting(ctx)
	plan := &InstallPlan{Release: i.Release, URL: i.URL, SHA256: i.SHA256, Existing: existing, GOOS: i.GOOS, ConfigDir: i.configDir()}
	target, targetErr := ParseVersion(i.Release)
	if existing != nil && existing.Version != (Version{}) {
		v := existing.Version
		if aboveWindow(v) {
			return nil, &ErrUnsupportedVersion{Found: v}
		}
		if CheckSupported(v) == nil && (!upgrade || targetErr != nil || v.Compare(target) >= 0) {
			return &InstallResult{Plan: plan, CLIVersion: v}, nil
		}
		if Legacy(v) || CheckSupported(v) == nil {
			if i.staleCLIRemoval(existing) != "" {
				// The package (the formula) would install the release
				// beside it, and the old CLI would still answer.
				return nil, fmt.Errorf("%w: OpenShell %s at %s was installed another way, which NVIDIA's installer does not replace; upgrade it to %s the way you installed it",
					ErrUnmanagedUpgrade, v, existing.Path, target)
			}
		}
	}
	plan.BreakingUpgrade = existing != nil && (existing.Version == (Version{}) || existing.Version.Compare(mustParse(breakingReleaseFloor)) < 0)
	// upgrading: an OpenShell the script upgrades in place, whose gateway
	// it restarts once the release is installed: a supported CLI older
	// than the release (Upgrade), and any older than SupportedMin, legacy
	// or not, that is not a pre-0.0.37 one (whose runtime the user cleaned
	// up first: ConfirmBreakingUpgrade).
	upgrading := existing != nil && !plan.BreakingUpgrade
	if i.GOOS == "darwin" {
		// NVIDIA's script taps and installs with Homebrew as this account.
		if err := i.HomebrewPrefixProblem(); err != nil {
			return nil, err
		}
	}

	// The script runs Homebrew as you: a prefix that belongs to another
	// account fails it partway with a permission error, so say so first.
	if err := i.checkBrewWritable(); err != nil {
		return nil, err
	}
	script, err := i.download(ctx)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(i.TempDir, "defenseclaw-openshell-install-")
	if err != nil {
		return nil, fmt.Errorf("openshell: create installer directory: %w", err)
	}
	defer os.RemoveAll(dir)
	plan.ScriptPath = filepath.Join(dir, "install.sh")
	if err := writeExclusive(plan.ScriptPath, script); err != nil {
		return nil, err
	}

	plan.Command = []string{i.Shell, plan.ScriptPath}
	plan.Env = []string{"OPENSHELL_VERSION=" + i.Release}
	if tls := i.brewTLSDir(); tls != "" {
		// The CLI the script registers the gateway with looks for the
		// gateway's client certificates only under /opt/homebrew and
		// /usr/local, and failed with "mTLS certificates ... were not found"
		// after the formula was installed and the gateway running.
		plan.Env = append(plan.Env, EnvLocalTLSDir+"="+tls)
		plan.Notes = append(plan.Notes,
			fmt.Sprintf("Homebrew is at %s, not at /opt/homebrew or /usr/local: %s tells the OpenShell CLI where the gateway's client certificates are", tildePath(i.BrewPrefix), EnvLocalTLSDir),
			"Homebrew has no prebuilt packages for that prefix, so it may build dependencies from source, which can take many minutes (it prints its progress)")
	}
	if i.PackageCLI != "" {
		// Without it the script registers the gateway with, and checks its
		// status through, whichever openshell comes first on PATH.
		plan.Env = append(plan.Env, "OPENSHELL_REGISTER_BIN="+i.PackageCLI)
	}
	if existing != nil && !plan.BreakingUpgrade {
		plan.Notes = append(plan.Notes, fmt.Sprintf("upgrades the installed %s to %s in place", existing.RawVersion, i.Release))
	}
	switch {
	case upgrading && i.GOOS == "darwin":
		// A Mac runs sandboxes in MicroVMs, which the restart stops.
		plan.Notes = append(plan.Notes, "the script restarts the OpenShell gateway once the release is installed, which stops every MicroVM sandbox on it",
			"before the script: nothing runs while a MicroVM sandbox does (the restart would stop it without a flush)")
	case upgrading:
		plan.Notes = append(plan.Notes, "the script restarts the OpenShell gateway once the release is installed, which drops the connections of every sandbox on it",
			"before the script: on the docker driver, Docker pulls the release's supervisor images from ghcr.io (the restarted gateway does not start without them); "+
				"on the MicroVM driver, nothing runs while a sandbox does (the restart would stop it without a flush)")
	}
	if i.GOOS == "darwin" && e2fsprogsIn(i.E2fsprogsDirs) == "" {
		// Setup offers it once OpenShell is installed only where the
		// doctor does not find it: a Mac that has it gets no note.
		next := "setup offers it next"
		if driverSkipsHomebrew(i.BrewPrefix, i.E2fsprogsDirs) {
			next = "the driver does not look in a Homebrew at " + tildePath(i.BrewPrefix) + ", so an administrator installs it under /opt/homebrew or /usr/local"
		}
		plan.Notes = append(plan.Notes, "a Mac runs sandboxes in OpenShell MicroVMs, whose driver also needs e2fsprogs, "+
			"which the formula does not install ("+InstallE2fsprogsCommand+"; "+next+")")
	}
	if plan.BreakingUpgrade {
		plan.Env = append(plan.Env, "OPENSHELL_ACK_BREAKING_UPGRADE=1")
		plan.Notes = append(plan.Notes,
			fmt.Sprintf("the installed OpenShell predates %s; 0.1 cannot use its gateway state or sandboxes", breakingReleaseFloor),
			"before continuing, back up anything you need from existing sandboxes, then with the OLD CLI run:",
			"    openshell sandbox delete --all && openshell gateway destroy",
			"(the 0.1 CLI no longer has `gateway destroy`); continuing tells the installer this cleanup is done")
		if rm := i.staleCLIRemoval(existing); rm != "" {
			plan.Notes = append(plan.Notes,
				"then remove the old CLI, which the package does not replace and which would shadow the new one on PATH:",
				"    "+rm)
		}
	}
	fmt.Fprint(i.Out, plan.String())

	if plan.BreakingUpgrade {
		if i.ConfirmBreakingUpgrade == nil {
			return nil, fmt.Errorf("%w: found %s at %s", ErrBreakingUpgrade, existingVersion(existing), existing.Path)
		}
		ok, err := i.ConfirmBreakingUpgrade(plan)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: found %s at %s", ErrBreakingUpgrade, existingVersion(existing), existing.Path)
		}
	}
	ok, err := i.Consent(plan)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInstallDeclined
	}
	if err := i.checkSudo(ctx); err != nil {
		return nil, err
	}
	if upgrading {
		// Held until the upgraded gateway is healthy: NVIDIA's script
		// restarts it minutes after the check, and a sandbox DefenseClaw
		// started meanwhile would be stopped by that restart unflushed.
		unlock, lerr := i.LockLifecycle(ctx)
		if lerr != nil {
			return nil, lerr
		}
		defer unlock()
		if err := i.PrepareUpgrade(ctx, target); err != nil {
			return nil, err
		}
	}

	// An old keg is already present during an upgrade. Only a change made
	// by this invocation shows that the formula installation completed.
	kegBefore := formulaKegState(i.BrewPrefix)
	command := Command{Name: plan.Command[0], Args: plan.Command[1:], Env: plan.Env, Unset: installerEnvUnset(os.Environ())}
	var runErr error
	if i.GOOS == "darwin" && os.Getenv("TMUX") != "" {
		// NVIDIA's installer can return success after brew services refuses
		// tmux, then leave no registration. Capture this one path so its raw
		// usage dump does not reach the terminal.
		command.Timeout = 30 * time.Minute
		var output []byte
		output, runErr = i.Runner.Output(ctx, command)
		if bytes.Contains(output, []byte("brew services` cannot run under tmux")) ||
			bytes.Contains(output, []byte("brew services cannot run under tmux")) {
			// A separately started gateway may already answer; check once with
			// a short deadline instead of the normal 90-second install wait.
			probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			if i.VerifyGateway(probeCtx) == nil {
				after, err := i.installedCLI(ctx)
				if err == nil {
					return &InstallResult{Plan: plan, Installed: true, CLIVersion: after.Version}, nil
				}
			}
			return nil, ErrBrewServicesTmux
		}
		_, _ = i.Out.Write(output)
	} else {
		runErr = i.Runner.Run(ctx, command)
	}
	if err := runErr; err != nil {
		if errors.Is(err, ErrInterrupted) {
			return nil, fmt.Errorf("openshell: the installer was interrupted and may have done part of its work; "+
				"`defenseclaw sandbox doctor` shows what is there, and `defenseclaw sandbox setup` runs it again: %w", err)
		}
		if i.GOOS == "darwin" && ctx.Err() == nil {
			// Homebrew printed why. Most often it would not build the
			// formula (NVIDIA's tap has no bottle for this macOS) with an
			// Xcode or Command Line Tools older than the oldest it builds
			// with on this macOS (homebrewMinimums): the error says which
			// are here.
			return nil, &HomebrewInstallError{Err: err, Tools: probeDeveloperTools(ctx, i.Runner, i.XcodeApp), FormulaInstalled: formulaKegState(i.BrewPrefix) != kegBefore}
		}
		return nil, fmt.Errorf("openshell: installer failed: %w", err)
	}

	after, err := i.installedCLI(ctx)
	if err != nil {
		return nil, err
	}
	if upgrading && after.Version.Compare(target) < 0 {
		return nil, fmt.Errorf("openshell: the installer finished, but the CLI at %s still reports %q, not %s", after.Path, after.RawVersion, target)
	}
	if err := i.VerifyGateway(ctx); err != nil {
		return nil, fmt.Errorf("openshell: %s installed but the gateway is not healthy: %w", after.Version, err)
	}
	return &InstallResult{Plan: plan, Installed: true, CLIVersion: after.Version}, nil
}

// InstallE2fsprogs installs e2fsprogs with Homebrew
// (InstallE2fsprogsCommand): OpenShell's MicroVM driver formats every
// MicroVM's disks with its mke2fs and debugfs. The caller has the user's
// consent.
func (i *Installer) InstallE2fsprogs(ctx context.Context) error {
	i.defaults()
	if err := i.checkBrewWritable(); err != nil {
		return err
	}
	return brewTerminal(ctx, i.Runner, "install", "e2fsprogs")
}

// brewTLSDir is the certificates directory the script's registration
// needs on a Mac whose Homebrew prefix the CLI does not search ("" if none).
func (i *Installer) brewTLSDir() string {
	if i.GOOS != "darwin" {
		return ""
	}
	return brewTLSDir(i.BrewPrefix)
}

// checkBrewWritable refuses, on a Mac, a Homebrew prefix this account
// cannot write (HomebrewNotWritableError).
func (i *Installer) checkBrewWritable() error {
	if i.GOOS != "darwin" {
		return nil
	}
	return checkHomebrewWritable(i.BrewPrefix, i.Writable)
}

// ResignVMDriver reruns the nvidia/openshell formula's post-install step
// (ResignVMDriverCommand), which signs its MicroVM driver for Apple's
// Hypervisor, without the rebuild `brew reinstall` needs where NVIDIA's
// tap has no bottle. The caller has the user's consent.
func (i *Installer) ResignVMDriver(ctx context.Context) error {
	i.defaults()
	return brew(ctx, i.Runner, "postinstall", GatewayFormula)
}

// prepareUpgrade is PrepareUpgrade on the gateway of i.Discover, whose
// gateway.toml (in Discover.ConfigDir) may name its own runtime images. One
// DefenseClaw finds no registration of, or cannot connect to, refuses the
// upgrade unless no MicroVM runs as this account (unreachableRefusal): the
// script's restart would end every one.
func (i *Installer) prepareUpgrade(ctx context.Context, release Version) error {
	reg, err := Discover(i.Discover)
	if err != nil {
		return unreachableRefusal(ctx, ErrSandboxesRunning, fmt.Errorf("no usable registration: %w", err), i.CountMicroVMs, "upgrade")
	}
	c, err := Dial(reg, ClientOptions{RPCTimeout: 10 * time.Second})
	if err != nil {
		return unreachableRefusal(ctx, ErrSandboxesRunning, fmt.Errorf("no connection: %w", err), i.CountMicroVMs, "upgrade")
	}
	defer c.Close()
	return PrepareUpgrade(ctx, c, func(ctx context.Context) error {
		st, _ := (&GatewayConfigurator{Dir: i.Discover.ConfigDir, GOOS: i.GOOS, Runner: i.Runner}).Read()
		return PullRuntimeImages(ctx, i.Runner, st.RuntimeImages(release))
	}, i.CountMicroVMs)
}

// PrepareUpgrade readies the gateway c talks to for the restart of an
// in-place upgrade, which NVIDIA's script makes only once it has
// downloaded and installed the release, minutes after anything run before
// it:
//   - On the docker driver, whose restart keeps the sandboxes running, it
//     runs pull (PullRuntimeImages): the restarted gateway pulls the
//     release's supervisor images unless they are local, and does not
//     start without them.
//   - Elsewhere (the MicroVM driver, or a gateway whose driver
//     GetGatewayInfo did not name) the restart stops every sandbox with no
//     flush. The upgrade is refused (ErrSandboxesRunning, naming each with
//     the exact way to stop it: StopWayOn) unless OpenShell reports every
//     sandbox on the gateway stopped, deleting, or in the error state with
//     its VM gone (HoldsGateway), and so is a list that fails. Nothing is
//     stopped or run in a sandbox, and nothing is inferred from time. A
//     gateway that answers neither call refuses too, unless vms shows that
//     no MicroVM runs as this account (unreachableRefusal).
//
// The caller holds the lifecycle lock (LockGatewayLifecycle) from this
// check until the upgraded gateway is healthy, so DefenseClaw starts no
// sandbox while the script runs; another OpenShell client is not held
// back.
func PrepareUpgrade(ctx context.Context, c Client, pull func(context.Context) error, vms VMCount) error {
	info, infoErr := c.GatewayInfo(ctx)
	if infoErr == nil {
		if d, err := GatewayDriver(info); err == nil && d.StopFlushes {
			if d.Name == DriverDocker {
				return pull(ctx)
			}
			return nil
		}
	}
	list, err := c.ListSandboxes(ctx, nil)
	if err != nil {
		if infoErr != nil && ctx.Err() == nil && IsUnavailable(err) {
			return unreachableRefusal(ctx, ErrSandboxesRunning, err, vms, "upgrade")
		}
		return fmt.Errorf("%w (the sandboxes on it could not be listed: %v); then upgrade", ErrSandboxesRunning, err)
	}
	return stoppedRefusal(ErrSandboxesRunning, list, func() string { return restartGatewayRelease(ctx, c) }, "upgrade")
}

// runtimeImageRepository holds the images OpenShell's docker driver runs
// its supervisor from, tagged with the release.
const runtimeImageRepository = "ghcr.io/nvidia/openshell"

// RuntimeImages are the images the docker driver of a gateway of release
// needs before it starts (OpenShell's ensure_runtime_image, which pulls
// one that is not local): the release's supervisor image and its sandbox
// runtime image, but those gateway.toml replaces ([openshell.drivers.docker]
// supervisor_image, sandbox_runtime_image, or supervisor_bin, a sandbox
// binary on the host). A nil s is a gateway with no configuration.
func (s *GatewayConfigState) RuntimeImages(release Version) []string {
	var d dockerRuntime
	if s != nil {
		d = s.docker
	}
	var images []string
	if strings.TrimSpace(d.SupervisorImage) == "" {
		images = append(images, runtimeImageRepository+"/supervisor:"+release.String())
	}
	if strings.TrimSpace(d.SandboxRuntimeImage) == "" && strings.TrimSpace(d.SupervisorBin) == "" {
		images = append(images, runtimeImageRepository+"/sandbox:"+release.String())
	}
	return images
}

// PullRuntimeImages has Docker pull each of images that is not local
// (RuntimeImages), so that the upgraded gateway's docker driver finds them
// as it starts. A pull that fails, most often because Docker cannot reach
// ghcr.io, is ErrRuntimeImages: the restarted gateway would not start.
func PullRuntimeImages(ctx context.Context, run Runner, images []string) error {
	for _, img := range images {
		if _, err := run.Output(ctx, Command{Name: "docker", Args: []string{"image", "inspect", "--format", "{{.Id}}", img}, Timeout: 30 * time.Second}); err == nil {
			continue
		}
		if out, err := run.Output(ctx, Command{Name: "docker", Args: []string{"pull", img}, Timeout: 10 * time.Minute}); err != nil {
			return fmt.Errorf("%w (docker pull %s: %v: %s): let Docker reach ghcr.io, or load the image, then upgrade",
				ErrRuntimeImages, img, err, lastLine(out))
		}
	}
	return nil
}

// configDir is the OpenShell configuration directory the gateway is
// registered in (Discover.ConfigDir, else UserConfigDir), with the home
// directory as ~.
func (i *Installer) configDir() string {
	dir := i.Discover.ConfigDir
	if dir == "" {
		var err error
		if dir, err = UserConfigDir(); err != nil {
			return "~/.config/openshell"
		}
	}
	return tildePath(dir)
}

// tildePath shows the home directory in p as ~.
func tildePath(p string) string {
	if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
		if rel, err := filepath.Rel(home, p); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.Join("~", rel)
		}
	}
	return p
}

func existingVersion(e *ExistingInstall) string {
	if e == nil || e.RawVersion == "" {
		return "an OpenShell of unknown version"
	}
	return e.RawVersion
}

// download fetches the script into memory and verifies its digest.
func (i *Installer) download(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, i.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("openshell: installer request: %w", err)
	}
	resp, err := i.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openshell: download %s: %w", i.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openshell: download %s: HTTP %d", i.URL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, i.MaxScriptBytes+1))
	if err != nil {
		return nil, fmt.Errorf("openshell: download %s: %w", i.URL, err)
	}
	if int64(len(body)) > i.MaxScriptBytes {
		return nil, fmt.Errorf("openshell: %s exceeds %d bytes", i.URL, i.MaxScriptBytes)
	}
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, i.SHA256) {
		return nil, &DigestMismatchError{URL: i.URL, Want: i.SHA256, Got: got}
	}
	return body, nil
}

func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("openshell: write installer: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("openshell: write installer: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("openshell: write installer: %w", err)
	}
	return nil
}

// findExisting locates a native (non-snap) openshell CLI and asks it for
// its version, the way the upstream installer does.
func (i *Installer) findExisting(ctx context.Context) *ExistingInstall {
	for _, p := range append([]string{i.onPath()}, i.Candidates...) {
		if e := i.probeCLI(ctx, p); e != nil {
			return e
		}
	}
	return nil
}

// installedCLI finds the supported CLI the install provided, the package's
// first, and refuses one that PATH hides behind an older CLI.
func (i *Installer) installedCLI(ctx context.Context) (*ExistingInstall, error) {
	probed := map[string]*ExistingInstall{}
	probe := func(p string) *ExistingInstall {
		if e, ok := probed[p]; ok {
			return e
		}
		probed[p] = i.probeCLI(ctx, p)
		return probed[p]
	}
	pathCLI := i.onPath()
	onPath := probe(pathCLI)
	var first, supported *ExistingInstall
	for _, p := range append([]string{i.PackageCLI, pathCLI}, i.Candidates...) {
		e := probe(p)
		if e == nil {
			continue
		}
		if first == nil {
			first = e
		}
		if CheckSupported(e.Version) == nil {
			supported = e
			break
		}
	}
	switch {
	case first == nil:
		return nil, errors.New("openshell: the installer finished but no openshell CLI was found")
	case supported == nil:
		return nil, fmt.Errorf("openshell: after install the CLI at %s reports %q: %w", first.Path, first.RawVersion, CheckSupported(first.Version))
	case onPath != nil && !sameFile(onPath.Path, supported.Path) && CheckSupported(onPath.Version) != nil:
		return nil, fmt.Errorf("%w: OpenShell %s is installed at %s, but %s comes first on PATH and reports %q; remove it (%s) so that openshell runs the new CLI",
			ErrStaleCLI, supported.Version, supported.Path, onPath.Path, onPath.RawVersion, removeCommand(onPath.Path))
	}
	return supported, nil
}

// staleCLIRemoval is the command that removes an old CLI the install will
// not replace, or "" when the package installs over it.
func (i *Installer) staleCLIRemoval(e *ExistingInstall) string {
	if e == nil || e.Path == "" {
		return ""
	}
	if i.PackageCLI != "" {
		if sameFile(e.Path, i.PackageCLI) {
			return ""
		}
	} else if home, err := os.UserHomeDir(); err != nil || !strings.HasPrefix(e.Path, home+string(filepath.Separator)) || i.homebrewCLI(e.Path) {
		// Homebrew replaces its own CLI, also in a Homebrew of your own
		// under the home directory (GAP-0391: the formula 0.1.1 in
		// ~/homebrew was refused as installed another way); only a
		// tarball install in the home directory is left behind.
		return ""
	}
	return removeCommand(e.Path)
}

// homebrewCLI reports whether path is the openshell that the Homebrew at
// BrewPrefix links into its bin directory, which a reinstall of the
// formula replaces.
func (i *Installer) homebrewCLI(path string) bool {
	return i.GOOS == "darwin" && filepath.IsAbs(i.BrewPrefix) &&
		filepath.Clean(path) == filepath.Join(filepath.Clean(i.BrewPrefix), "bin", DefaultBinary)
}

func removeCommand(path string) string {
	cmd := "rm " + shellQuote(path)
	if info, err := os.Lstat(path); err == nil && !ownedByCaller(info) {
		cmd = "sudo " + cmd
	}
	return cmd
}

// onPath is the openshell PATH resolves, unless it is the snap's.
func (i *Installer) onPath() string {
	if p, err := i.LookPath(DefaultBinary); err == nil && !strings.HasPrefix(p, "/snap/") {
		return p
	}
	return ""
}

// probeCLI asks the executable at p for its version; nil when there is
// none. A relative p is never run: it would resolve against the working
// directory.
func (i *Installer) probeCLI(ctx context.Context, p string) *ExistingInstall {
	if p == "" || !filepath.IsAbs(p) {
		return nil
	}
	info, err := os.Stat(p)
	if err != nil || info.IsDir() || info.Mode().Perm()&0o111 == 0 {
		return nil
	}
	out, _ := i.Runner.Output(ctx, Command{Name: p, Args: []string{"--version"}, Timeout: 30 * time.Second})
	first, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	e := &ExistingInstall{Path: p, RawVersion: strings.TrimSpace(first)}
	e.Version, _ = VersionFromOutput(e.RawVersion)
	return e
}

func sameFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	return err == nil && os.SameFile(ai, bi)
}

var semverToken = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.+~-]+)?$`)

// VersionFromOutput extracts the release from a `--version` line the way
// the upstream installer does: the first whitespace-separated token that
// looks like a semantic version ("openshell 0.1.1 (abc123)" is 0.1.1).
func VersionFromOutput(line string) (Version, error) {
	for _, f := range strings.Fields(line) {
		if semverToken.MatchString(f) {
			return ParseVersion(f)
		}
	}
	return Version{}, fmt.Errorf("openshell: no version in %q", line)
}

// WaitForGateway polls the local gateway until it answers healthy with a
// supported release, or wait elapses. Registration problems that polling
// cannot fix (remote gateway, bad credentials) return at once.
func WaitForGateway(ctx context.Context, opts DiscoverOptions, wait time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	var last error
	for {
		last = probeGateway(ctx, opts)
		if last == nil {
			return nil
		}
		if errors.Is(last, ErrRemoteGateway) || errors.Is(last, ErrInsecureCredentials) || errors.Is(last, ErrInsecureRegistration) ||
			errors.Is(last, ErrUnsupportedAuthMode) || errors.Is(last, ErrUnauthenticatedGateway) || errors.Is(last, ErrUnsupportedPlatform) {
			return last
		}
		var unsupported *ErrUnsupportedVersion
		if errors.As(last, &unsupported) {
			return last
		}
		if err := sleepContext(ctx, 2*time.Second); err != nil {
			return fmt.Errorf("gateway did not become healthy within %s: %w", wait, last)
		}
	}
}

func probeGateway(ctx context.Context, opts DiscoverOptions) error {
	reg, err := Discover(opts)
	if err != nil {
		return err
	}
	c, err := Dial(reg, ClientOptions{RPCTimeout: 5 * time.Second})
	if err != nil {
		return err
	}
	defer c.Close()
	h, err := c.Health(ctx)
	if err != nil {
		return err
	}
	if !h.Healthy {
		return errors.New("gateway reports unhealthy")
	}
	return h.CheckVersion()
}
