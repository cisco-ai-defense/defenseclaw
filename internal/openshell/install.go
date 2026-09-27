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
)

// installerEnvUnset are inherited variables that would change what the
// pinned installer does behind the plan's back.
var installerEnvUnset = []string{"OPENSHELL_VERSION", "OPENSHELL_ACK_BREAKING_UPGRADE", "OPENSHELL_INSTALL_METHOD"}

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
		fmt.Fprintf(tw, "  Privileges\tthe script installs the nvidia/openshell Homebrew formula and starts\n")
		fmt.Fprintf(tw, "  \tthe gateway with brew services\n")
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
}

func (i *Installer) defaults() {
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
		home, _ := os.UserHomeDir()
		i.Candidates = []string{filepath.Join(home, ".local", "bin", "openshell"), "/usr/local/bin/openshell", "/usr/bin/openshell", "/opt/homebrew/bin/openshell"}
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
	if err := CheckPlatform(runtime.GOOS); err != nil {
		return nil, err
	}
	if i.Consent == nil {
		return nil, errors.New("openshell: install needs a consent callback")
	}
	if u, err := url.Parse(i.URL); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("openshell: installer URL must be https, got %q", i.URL)
	}
	existing := i.findExisting(ctx)
	plan := &InstallPlan{Release: i.Release, URL: i.URL, SHA256: i.SHA256, Existing: existing, GOOS: runtime.GOOS}
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
	if existing != nil && !plan.BreakingUpgrade {
		plan.Notes = append(plan.Notes, fmt.Sprintf("upgrades the installed %s to %s in place", existing.RawVersion, i.Release))
	}
	if plan.BreakingUpgrade {
		plan.Env = append(plan.Env, "OPENSHELL_ACK_BREAKING_UPGRADE=1")
		plan.Notes = append(plan.Notes,
			fmt.Sprintf("the installed OpenShell predates %s; 0.1 cannot use its gateway state or sandboxes", breakingReleaseFloor),
			"before continuing, back up anything you need from existing sandboxes, then with the OLD CLI run:",
			"    openshell sandbox delete --all && openshell gateway destroy",
			"(the 0.1 CLI no longer has `gateway destroy`); continuing tells the installer this cleanup is done")
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

	if err := i.Runner.Run(ctx, Command{Name: plan.Command[0], Args: plan.Command[1:], Env: plan.Env, Unset: installerEnvUnset}); err != nil {
		return nil, fmt.Errorf("openshell: installer failed: %w", err)
	}

	after := i.findExisting(ctx)
	if after == nil {
		return nil, errors.New("openshell: the installer finished but no openshell CLI was found")
	}
	if err := CheckSupported(after.Version); err != nil {
		return nil, fmt.Errorf("openshell: after install the CLI at %s reports %q: %w", after.Path, after.RawVersion, err)
	}
	if err := i.VerifyGateway(ctx); err != nil {
		return nil, fmt.Errorf("openshell: %s installed but the gateway is not healthy: %w", after.Version, err)
	}
	return &InstallResult{Plan: plan, Installed: true, CLIVersion: after.Version}, nil
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
	var candidates []string
	if p, err := i.LookPath(DefaultBinary); err == nil && !strings.HasPrefix(p, "/snap/") {
		candidates = append(candidates, p)
	}
	candidates = append(candidates, i.Candidates...)
	for _, p := range candidates {
		info, err := os.Stat(p)
		if err != nil || info.IsDir() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		out, _ := i.Runner.Output(ctx, Command{Name: p, Args: []string{"--version"}, Timeout: 30 * time.Second})
		first, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
		e := &ExistingInstall{Path: p, RawVersion: strings.TrimSpace(first)}
		e.Version, _ = VersionFromOutput(e.RawVersion)
		return e
	}
	return nil
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
