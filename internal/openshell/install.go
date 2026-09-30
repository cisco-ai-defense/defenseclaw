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
}

func (i *Installer) defaults() {
	if i.GOOS == "" {
		i.GOOS = runtime.GOOS
	}
	if i.E2fsprogsDirs == nil {
		i.E2fsprogsDirs = e2fsprogsDirs
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
}

// Install runs the flow: detect an existing CLI, download the pinned
// script into a private directory and verify its digest (nothing touches
// disk before that), print the plan, get consent (and, for a pre-0.0.37
// install, a separate confirmation), run the script with
// OPENSHELL_VERSION pinned, then verify `openshell --version` and the
// gateway.
func (i *Installer) Install(ctx context.Context) (*InstallResult, error) {
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
	if existing != nil && existing.Version != (Version{}) {
		v := existing.Version
		if err := CheckSupported(v); err == nil {
			return &InstallResult{Plan: plan, CLIVersion: v}, nil
		}
		if v.Compare(mustParse(SupportedBelow)) >= 0 {
			return nil, &ErrUnsupportedVersion{Found: v}
		}
	}
	plan.BreakingUpgrade = existing != nil && (existing.Version == (Version{}) || existing.Version.Compare(mustParse(breakingReleaseFloor)) < 0)

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
	if i.PackageCLI != "" {
		// Without it the script registers the gateway with, and checks its
		// status through, whichever openshell comes first on PATH.
		plan.Env = append(plan.Env, "OPENSHELL_REGISTER_BIN="+i.PackageCLI)
	}
	if existing != nil && !plan.BreakingUpgrade {
		plan.Notes = append(plan.Notes, fmt.Sprintf("upgrades the installed %s to %s in place", existing.RawVersion, i.Release))
	}
	if i.GOOS == "darwin" && e2fsprogsIn(i.E2fsprogsDirs) == "" {
		// Setup offers it once OpenShell is installed only where the
		// doctor does not find it: a Mac that has it gets no note.
		plan.Notes = append(plan.Notes, "a Mac runs sandboxes in OpenShell MicroVMs, whose driver also needs e2fsprogs, "+
			"which the formula does not install ("+InstallE2fsprogsCommand+"; setup offers it next)")
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

	if err := i.Runner.Run(ctx, Command{Name: plan.Command[0], Args: plan.Command[1:], Env: plan.Env, Unset: installerEnvUnset(os.Environ())}); err != nil {
		if i.GOOS == "darwin" && ctx.Err() == nil {
			// Homebrew printed why. Most often it would not build the
			// formula (NVIDIA's tap has no bottle for this macOS) with an
			// Xcode or Command Line Tools older than the newest release.
			return nil, fmt.Errorf("%w (%w)", ErrHomebrewInstall, err)
		}
		return nil, fmt.Errorf("openshell: installer failed: %w", err)
	}

	after, err := i.installedCLI(ctx)
	if err != nil {
		return nil, err
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
	return brew(ctx, i.Runner, "install", "e2fsprogs")
}

// ResignVMDriver reruns the nvidia/openshell formula's post-install step
// (ResignVMDriverCommand), which signs its MicroVM driver for Apple's
// Hypervisor, without the rebuild `brew reinstall` needs where NVIDIA's
// tap has no bottle. The caller has the user's consent.
func (i *Installer) ResignVMDriver(ctx context.Context) error {
	i.defaults()
	return brew(ctx, i.Runner, "postinstall", GatewayFormula)
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
	if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
		if rel, err := filepath.Rel(home, dir); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.Join("~", rel)
		}
	}
	return dir
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
	} else if home, err := os.UserHomeDir(); err != nil || !strings.HasPrefix(e.Path, home+string(filepath.Separator)) {
		// Homebrew replaces its own CLI; only a tarball install in the
		// home directory is left behind.
		return ""
	}
	return removeCommand(e.Path)
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
