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

package sandboxfeed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type fakeHeader struct{ header Header }

func (f fakeHeader) Header() Header { return f.header }
func (f fakeHeader) Close() error   { return nil }

// lifecycleEnv is a Lifecycle on a temporary root whose commands are
// recorded: the staged helper answers --version and --sandbox-feed --check
// as the test says, systemctl succeeds.
type lifecycleEnv struct {
	l        *Lifecycle
	root     string
	helper   string
	calls    []string
	version  string
	checkErr error
	dialErr  error
	header   Header
}

func newLifecycleEnv(t *testing.T) *lifecycleEnv {
	t.Helper()
	e := &lifecycleEnv{root: t.TempDir(), version: "1.2.3", header: Header{Protocol: ProtocolVersion, Build: "1.2.3", Tetragon: TetragonConnected}}
	e.helper = filepath.Join(t.TempDir(), HelperName)
	if err := os.WriteFile(e.helper, []byte("helper build dccert-block-marker"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.l = &Lifecycle{
		Root:    e.root,
		Geteuid: func() int { return 0 },
		Wait:    time.Second,
		Run: func(_ context.Context, name string, args ...string) (string, error) {
			call := strings.TrimSpace(filepath.Base(name) + " " + strings.Join(args, " "))
			e.calls = append(e.calls, call)
			switch {
			case slices.Equal(args, []string{"--version"}):
				return "defenseclaw-sensor-helper version " + e.version + " (commit=abc)", nil
			case slices.Equal(args, []string{"--sandbox-feed", "--check"}):
				if e.checkErr != nil {
					return "tetragon_tcp_api: Tetragon serves its API on \"localhost:54321\"", e.checkErr
				}
				return "Tetragon v1.7.1 on /var/run/tetragon/tetragon.sock; Docker Engine answers", nil
			case name == "systemctl" && len(args) > 0 && args[0] == "is-active":
				return "active", nil
			}
			return "", nil
		},
		Dial: func(context.Context, string) (FeedHeader, error) {
			if e.dialErr != nil {
				return nil, e.dialErr
			}
			return fakeHeader{e.header}, nil
		},
	}
	return e
}

func (e *lifecycleEnv) installed(p string) string { return filepath.Join(e.root, p) }

func TestInstallCopiesChecksAndStarts(t *testing.T) {
	e := newLifecycleEnv(t)
	result, err := e.l.Install(context.Background(), e.helper, "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if result.Updated || result.Version != "1.2.3" || result.Protocol != ProtocolVersion || result.Tetragon != TetragonConnected ||
		!strings.Contains(result.Check, "Tetragon v1.7.1") {
		t.Fatalf("result = %+v", result)
	}
	info, err := os.Stat(e.installed(InstalledBinary))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("installed binary: %v %v", info, err)
	}
	if data, _ := os.ReadFile(e.installed(InstalledBinary)); string(data) != "helper build dccert-block-marker" {
		t.Fatalf("installed binary holds %q", data)
	}
	unit, err := os.ReadFile(e.installed(UnitPath))
	if err != nil || string(unit) != UnitFile() {
		t.Fatalf("unit = %q, %v", unit, err)
	}
	want := []string{
		"." + HelperName + ".new --version", "." + HelperName + ".new --sandbox-feed --check",
		"systemctl daemon-reload", "systemctl enable " + UnitName, "systemctl restart " + UnitName,
	}
	if !slices.Equal(e.calls, want) {
		t.Fatalf("calls = %q\nwant %q", e.calls, want)
	}
	if staged, _ := filepath.Glob(filepath.Join(e.root, InstallDir, ".*")); len(staged) != 0 {
		t.Fatalf("staged copies left: %v", staged)
	}
	// Again: an update.
	if result, err := e.l.Install(context.Background(), e.helper, "1.2.3"); err != nil || !result.Updated {
		t.Fatalf("second install = %+v, %v", result, err)
	}
}

// A check that fails, a helper of another release, or a caller that is not
// root changes nothing.
func TestInstallRefusals(t *testing.T) {
	e := newLifecycleEnv(t)
	e.checkErr = errors.New("exit status 1")
	if _, err := e.l.Install(context.Background(), e.helper, "1.2.3"); err == nil || !strings.Contains(err.Error(), "tetragon_tcp_api") {
		t.Fatalf("a failed check = %v", err)
	}
	e.checkErr = nil
	e.version = "1.2.2"
	if _, err := e.l.Install(context.Background(), e.helper, "1.2.3"); err == nil || !strings.Contains(err.Error(), `"1.2.2"`) {
		t.Fatalf("another release = %v", err)
	}
	for _, p := range []string{InstalledBinary, UnitPath} {
		if _, err := os.Stat(e.installed(p)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s exists after a refusal", p)
		}
	}
	if slices.ContainsFunc(e.calls, func(c string) bool { return strings.HasPrefix(c, "systemctl") }) {
		t.Fatalf("systemctl ran after a refusal: %q", e.calls)
	}
	if staged, _ := filepath.Glob(filepath.Join(e.root, InstallDir, ".*")); len(staged) != 0 {
		t.Fatalf("staged copies left: %v", staged)
	}
	e.l.Geteuid = func() int { return 1000 }
	if _, err := e.l.Install(context.Background(), e.helper, "1.2.3"); !errors.Is(err, ErrNotRoot) {
		t.Fatalf("not root = %v", err)
	}
	if _, err := e.l.Uninstall(context.Background()); !errors.Is(err, ErrNotRoot) {
		t.Fatalf("uninstall not root = %v", err)
	}
	e.l.Geteuid = func() int { return 0 }
	if _, err := e.l.Install(context.Background(), filepath.Join(t.TempDir(), "absent"), "1.2.3"); err == nil {
		t.Fatal("a missing helper was installed")
	}
	// A dev build installs whatever the helper says it is.
	e.version = "dev"
	if _, err := e.l.Install(context.Background(), e.helper, "dev"); err != nil {
		t.Fatalf("dev build: %v", err)
	}
}

func TestUninstallRemovesWhatInstallWrote(t *testing.T) {
	e := newLifecycleEnv(t)
	if _, err := e.l.Install(context.Background(), e.helper, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	e.calls = nil
	removed, err := e.l.Uninstall(context.Background())
	if err != nil || !slices.Equal(removed, []string{UnitPath, InstalledBinary}) {
		t.Fatalf("removed %q, %v", removed, err)
	}
	if !slices.Equal(e.calls, []string{"systemctl disable --now " + UnitName, "systemctl daemon-reload"}) {
		t.Fatalf("calls = %q", e.calls)
	}
	if _, err := os.Stat(filepath.Join(e.root, InstallDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the empty install directory stayed")
	}
	e.calls = nil
	if removed, err := e.l.Uninstall(context.Background()); err != nil || len(removed) != 0 || len(e.calls) != 0 {
		t.Fatalf("second uninstall removed %q, calls %q, %v", removed, e.calls, err)
	}
}

func TestStatusSaysWhenTheFeedNeedsAnUpdate(t *testing.T) {
	e := newLifecycleEnv(t)
	e.dialErr = ErrNotInstalled
	if s := e.l.Status(context.Background(), "1.2.3"); s.Installed || s.Reachable || s.Reason != ReasonNotInstalled || s.UpdateNeeded {
		t.Fatalf("not installed = %+v", s)
	}
	e.dialErr = nil
	if _, err := e.l.Install(context.Background(), e.helper, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	s := e.l.Status(context.Background(), "1.2.3")
	if !s.Installed || s.Active != "active" || s.Version != "1.2.3" || !s.Reachable || s.Build != "1.2.3" || s.UpdateNeeded ||
		s.GatewayProtocol != ProtocolVersion {
		t.Fatalf("installed = %+v", s)
	}
	// An upgraded gateway, an older feed.
	if s := e.l.Status(context.Background(), "1.3.0"); !s.UpdateNeeded {
		t.Fatalf("older feed = %+v", s)
	}
	// A feed of another protocol.
	e.dialErr = &SkewError{Server: ProtocolVersion + 1, Client: ProtocolVersion, Build: "2.0.0"}
	if s := e.l.Status(context.Background(), "1.2.3"); !s.UpdateNeeded || s.Reason != ReasonVersionSkew || s.Build != "2.0.0" {
		t.Fatalf("skew = %+v", s)
	}
	// A reader outside the docker group sees the unit, not the stream.
	e.dialErr = ErrNotPermitted
	if s := e.l.Status(context.Background(), "1.2.3"); !s.Installed || s.Reachable || s.Reason != ReasonNotPermitted {
		t.Fatalf("not permitted = %+v", s)
	}
	// An installed feed without a socket is stopped: it does not answer,
	// it is not missing (GAP-0091).
	e.dialErr = ErrNotInstalled
	if s := e.l.Status(context.Background(), "1.2.3"); !s.Installed || s.Reachable || s.Reason != ReasonUnavailable {
		t.Fatalf("stopped = %+v", s)
	}
}

func TestOlder(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"1.0.9", "1.0.10", true}, {"1.0.10", "1.0.9", false}, {"v1.0.0", "1.0.0", false}, {"dev", "1.0.0", false},
		{"1.0.0", "dev", false}, {"", "1.0.0", false}, {"1.0.0-rc.1", "1.0.0", true},
	} {
		if got := Older(c.a, c.b); got != c.want {
			t.Errorf("Older(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// The unit holds only what the feed needs: root, CAP_CHOWN for its socket's
// group, AF_UNIX, its runtime directory, and the helper in feed mode.
func TestUnitFile(t *testing.T) {
	unit := UnitFile()
	for _, want := range []string{
		"ExecStart=" + InstalledBinary + " --sandbox-feed\n", "User=root\n", "CapabilityBoundingSet=CAP_CHOWN\n",
		"RestrictAddressFamilies=AF_UNIX\n", "RuntimeDirectory=defenseclaw-sandbox-feed\n", "RuntimeDirectoryMode=0750\n",
		"ProtectSystem=strict\n", "ProtectHome=true\n", "NoNewPrivileges=true\n", "WantedBy=multi-user.target\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q", want)
		}
	}
	if filepath.Dir(DefaultSocketPath) != "/run/defenseclaw-sandbox-feed" {
		t.Fatalf("the socket %s is not in the unit's runtime directory", DefaultSocketPath)
	}
}
