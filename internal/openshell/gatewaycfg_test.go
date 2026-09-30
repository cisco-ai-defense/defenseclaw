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
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

const operatorTOML = `# Local gateway, managed by hand.
[openshell]
version = 2

[openshell.drivers.docker]
network = "openshell" # keep
enable_bind_mounts = false
`

var (
	bindMounts   = openshell.GatewayChanges{EnableBindMounts: true}
	telemetryOff = openshell.GatewayChanges{Env: map[string]string{openshell.EnvTelemetryEnabled: "false"}}
	bothChanges  = openshell.GatewayChanges{EnableBindMounts: true, Env: map[string]string{openshell.EnvTelemetryEnabled: "false"}}
)

type gatewayFixture struct {
	dir      string
	runner   *openshelltest.Runner
	cfg      *openshell.GatewayConfigurator
	verified int
	verify   error
	// preflighted records the candidate content seen by preflight.
	preflighted []string
	// unit and manager are what systemd reports about the service and
	// the user manager's environment; by default the unit reads dir's
	// gateway.env and discovers dir's gateway.toml.
	unit, manager string
	// probe answers ProbeClientAuth; probes counts the calls.
	probe  func() error
	probes int
	// flush answers FlushSandboxes; flushes counts the calls.
	flush   error
	flushes int
}

// systemdUnit renders `systemctl --user show openshell-gateway` output
// for a loaded unit that reads envFile.
func systemdUnit(active, fileState string, started time.Time, envFile string) string {
	out := fmt.Sprintf("LoadState=loaded\nActiveState=%s\nSubState=running\nUnitFileState=%s\n", active, fileState)
	if !started.IsZero() {
		out += "ActiveEnterTimestamp=" + started.UTC().Format("Mon 2006-01-02 15:04:05.000000 MST") + "\n"
	}
	out += "Environment=OPENSHELL_LOCAL_TLS_DIR=/home/dev/.local/state/openshell/tls\n"
	if envFile != "" {
		out += "EnvironmentFiles=" + envFile + " (ignore_errors=yes)\n"
	}
	return out
}

// systemdManager renders `systemctl --user show-environment` output whose
// XDG_CONFIG_HOME holds configDir.
func systemdManager(configDir string) string {
	return "HOME=/home/dev\nXDG_CONFIG_HOME=" + filepath.Dir(configDir) + "\nPATH=/usr/bin:/bin\n"
}

func newGatewayFixture(t *testing.T) *gatewayFixture {
	t.Helper()
	skipOnWindows(t)
	f := &gatewayFixture{dir: filepath.Join(realTempDir(t), "openshell"), runner: &openshelltest.Runner{}}
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Bind mounts are enabled only for a usable mTLS registration.
	writeRegistration(t, f.dir, "openshell", nil, nil)
	f.runner.OnFunc("openshell-gateway config preflight", func(_ context.Context, c openshell.Command) ([]byte, error) {
		data, err := os.ReadFile(c.Args[3])
		if err != nil {
			t.Errorf("preflight path unreadable: %v", err)
		}
		f.preflighted = append(f.preflighted, string(data))
		return nil, nil
	})
	f.runner.On("systemctl --user restart openshell-gateway", "", nil)
	f.unit = systemdUnit("active", "enabled", time.Date(2026, 9, 26, 18, 0, 0, 0, time.UTC), filepath.Join(f.dir, "gateway.env"))
	f.manager = systemdManager(f.dir)
	f.runner.OnFunc("systemctl --user show openshell-gateway", func(context.Context, openshell.Command) ([]byte, error) { return []byte(f.unit), nil })
	f.runner.OnFunc("systemctl --user show-environment", func(context.Context, openshell.Command) ([]byte, error) { return []byte(f.manager), nil })
	f.probe = func() error { return nil }
	f.cfg = &openshell.GatewayConfigurator{
		Dir:             f.dir,
		GOOS:            "linux",
		BrewPrefix:      filepath.Join(filepath.Dir(f.dir), "homebrew"),
		Runner:          f.runner,
		VerifyGateway:   func(context.Context) error { f.verified++; return f.verify },
		ProbeClientAuth: func(context.Context, *openshell.Registration) error { f.probes++; return f.probe() },
		FlushSandboxes:  func(context.Context) error { f.flushes++; return f.flush },
		Now:             func() time.Time { return time.Date(2026, 9, 26, 19, 0, 0, 0, time.UTC) },
		// The tests' preflight answers to the bare name, whatever this
		// machine's PATH holds.
		LookPath: func(string) (string, error) { return "", exec.ErrNotFound },
	}
	return f
}

func (f *gatewayFixture) write(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(content), 0o664); err != nil {
		t.Fatal(err)
	}
}

func (f *gatewayFixture) read(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (f *gatewayFixture) backups() []string {
	m, _ := filepath.Glob(filepath.Join(f.dir, "*.bak"))
	return m
}

func (f *gatewayFixture) restarts() int {
	n := 0
	for _, c := range f.runner.Calls() {
		if openshelltest.Argv(c) == "systemctl --user restart openshell-gateway" {
			n++
		}
	}
	return n
}

func (f *gatewayFixture) plan(t *testing.T, ch openshell.GatewayChanges) *openshell.GatewayPlan {
	t.Helper()
	plan, err := f.cfg.Plan(context.Background(), ch)
	if err != nil {
		t.Fatalf("Plan(%+v) = %v", ch, err)
	}
	return plan
}

func (f *gatewayFixture) apply(plan *openshell.GatewayPlan) (*openshell.GatewayApplyResult, error) {
	return f.cfg.Apply(context.Background(), plan)
}

// untouched fails unless gateway.toml still reads want and nothing was
// backed up or restarted.
func (f *gatewayFixture) untouched(t *testing.T, want string) {
	t.Helper()
	if f.read(t, "gateway.toml") != want || f.restarts() != 0 || len(f.backups()) != 0 {
		t.Fatalf("restarts %d, backups %v, gateway.toml:\n%s", f.restarts(), f.backups(), f.read(t, "gateway.toml"))
	}
}

func TestGatewayConfigCreate(t *testing.T) {
	f := newGatewayFixture(t)
	st, err := f.cfg.Read()
	if err != nil || st.TOMLExists || st.BindMounts.Enabled() || !st.BindMounts.ResourceAdmission || !st.TelemetryEnabled() {
		t.Fatalf("fresh state = %+v, %v", st, err)
	}
	plan := f.plan(t, bothChanges)
	text := plan.String()
	if strings.Contains(text, "backup") {
		t.Errorf("a plan that only creates files promises a backup:\n%s", text)
	}
	for _, want := range []string{"create " + filepath.Join(f.dir, "gateway.toml"), "+ enable_bind_mounts = true", "set [openshell.drivers.docker.resource_admission] enabled = false",
		"create " + filepath.Join(f.dir, "gateway.env"), "OPENSHELL_TELEMETRY_ENABLED=false", "systemctl --user restart openshell-gateway"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan lacks %q:\n%s", want, text)
		}
	}
	res, err := f.apply(plan)
	if err != nil || !res.Restarted || f.restarts() != 1 || f.verified != 1 || len(res.Files) != 2 {
		t.Fatalf("Apply = %+v, %v; restarts=%d verified=%d", res, err, f.restarts(), f.verified)
	}
	for _, af := range res.Files {
		if af.Backup != "" {
			t.Fatalf("created file got a backup: %+v", af)
		}
		expectMode(t, af.Path, 0o600)
	}
	if toml := f.read(t, "gateway.toml"); !strings.Contains(toml, "version = 2") || len(f.preflighted) != 1 || f.preflighted[0] != toml {
		t.Fatalf("gateway.toml:\n%s\npreflight saw %q", toml, f.preflighted)
	}
	if left, _ := filepath.Glob(filepath.Join(f.dir, ".defenseclaw-preflight-*")); len(left) != 0 {
		t.Fatalf("preflight temp files left: %v", left)
	}
	if st, err := f.cfg.Read(); err != nil || !st.BindMounts.Enabled() || st.TelemetryEnabled() {
		t.Fatalf("state after apply = %+v, %v", st, err)
	}
	again := f.plan(t, bothChanges)
	if !again.Empty() {
		t.Fatalf("second plan = %s", again)
	}
	if res, err := f.apply(again); err != nil || res.Restarted || f.restarts() != 1 {
		t.Fatalf("empty apply restarted: %+v %v", res, err)
	}
	for value, enabled := range map[string]bool{"0": false, "true": true, "garbage": true} {
		if st := (&openshell.GatewayConfigState{Env: map[string]string{openshell.EnvTelemetryEnabled: value}}); st.TelemetryEnabled() != enabled {
			t.Errorf("%s=%s: enabled = %v", openshell.EnvTelemetryEnabled, value, !enabled)
		}
	}
}

func TestGatewayConfigEditKeepsCommentsAndBacksUp(t *testing.T) {
	f := newGatewayFixture(t)
	f.write(t, "gateway.toml", operatorTOML)
	f.write(t, "gateway.env", "# secrets below\nOPENSHELL_DB_URL=postgres://u:hunter2@db/os\n")
	plan := f.plan(t, bothChanges)
	if text := plan.String(); strings.Contains(text, "hunter2") || !strings.Contains(text, "- enable_bind_mounts = false\n      + enable_bind_mounts = true") ||
		!strings.Contains(text, "edit "+filepath.Join(f.dir, "gateway.env")+" (a timestamped backup is kept)") {
		t.Fatalf("plan:\n%s", text)
	}
	if _, err := f.apply(plan); err != nil {
		t.Fatal(err)
	}
	got := f.read(t, "gateway.toml")
	for _, want := range []string{"# Local gateway, managed by hand.", `network = "openshell" # keep`, "enable_bind_mounts = true", "allow_driver_config = true", "enabled = false"} {
		if !strings.Contains(got, want) {
			t.Errorf("edited gateway.toml lacks %q:\n%s", want, got)
		}
	}
	if env := f.read(t, "gateway.env"); env != "# secrets below\nOPENSHELL_DB_URL=postgres://u:hunter2@db/os\nOPENSHELL_TELEMETRY_ENABLED=false\n" {
		t.Fatalf("gateway.env = %q", env)
	}
	backups := f.backups()
	if len(backups) != 2 {
		t.Fatalf("backups = %v", backups)
	}
	for _, b := range backups {
		expectMode(t, b, 0o600)
		if data, _ := os.ReadFile(b); strings.HasPrefix(filepath.Base(b), "gateway.toml.defenseclaw-20260926T190000Z") && string(data) != operatorTOML {
			t.Errorf("toml backup = %q", data)
		}
	}
}

func TestGatewayConfigApplyGuards(t *testing.T) {
	t.Run("changed since plan", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", operatorTOML)
		plan := f.plan(t, bindMounts)
		f.write(t, "gateway.toml", operatorTOML+"# edited meanwhile\n")
		if _, err := f.apply(plan); !errors.Is(err, openshell.ErrConfigChanged) {
			t.Fatalf("err = %v", err)
		}
		f.untouched(t, operatorTOML+"# edited meanwhile\n")
	})
	t.Run("preflight rejects the edit", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", operatorTOML)
		f.runner.OnFunc("openshell-gateway config preflight", func(_ context.Context, c openshell.Command) ([]byte, error) {
			if strings.Contains(c.Args[3], ".defenseclaw-preflight-") {
				return []byte("category=malformed"), errors.New("exit status 1")
			}
			return nil, nil
		})
		_, err := f.apply(f.plan(t, bindMounts))
		if !errors.Is(err, openshell.ErrPreflight) || !strings.Contains(err.Error(), "DefenseClaw's change") || !strings.Contains(err.Error(), "category=malformed") {
			t.Fatalf("err = %v", err)
		}
		f.untouched(t, operatorTOML)
	})
	t.Run("original already fails preflight", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", operatorTOML)
		f.runner.On("openshell-gateway config preflight", "category=missing_version", errors.New("exit status 1"))
		if _, err := f.apply(f.plan(t, bindMounts)); !errors.Is(err, openshell.ErrPreflight) || !strings.Contains(err.Error(), "already fails preflight") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("symlinked config refused", func(t *testing.T) {
		f := newGatewayFixture(t)
		target := filepath.Join(t.TempDir(), "elsewhere.toml")
		writeFile(t, target, operatorTOML, 0o600)
		if err := os.Symlink(target, filepath.Join(f.dir, "gateway.toml")); err != nil {
			t.Fatal(err)
		}
		if _, err := f.cfg.Plan(context.Background(), bindMounts); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unsafe TOML shape", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", "[openshell]\nversion = 2\ndrivers = { docker = { enable_bind_mounts = false } }\n")
		if _, err := f.cfg.Plan(context.Background(), bindMounts); !errors.Is(err, openshell.ErrTOMLEdit) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestGatewayConfigRollback(t *testing.T) {
	t.Run("unhealthy after restart", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", operatorTOML)
		f.verify = errors.New("connection refused")
		if _, err := f.apply(f.plan(t, bothChanges)); err == nil || !strings.Contains(err.Error(), "did not come back") {
			t.Fatalf("err = %v", err)
		}
		if _, err := os.Stat(filepath.Join(f.dir, "gateway.env")); f.read(t, "gateway.toml") != operatorTOML || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("not rolled back: created gateway.env %v", err)
		}
		if f.restarts() != 2 {
			t.Fatalf("restarts = %d, want the change and the rollback", f.restarts())
		}
	})
	t.Run("restart fails then recovers", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", operatorTOML)
		n := 0
		f.runner.OnFunc("systemctl --user restart openshell-gateway", func(context.Context, openshell.Command) ([]byte, error) {
			if n++; n == 1 {
				return []byte("Job failed"), errors.New("exit status 1")
			}
			return nil, nil
		})
		_, err := f.apply(f.plan(t, bindMounts))
		if err == nil || !strings.Contains(err.Error(), "previous configuration was restored") || !strings.Contains(err.Error(), "Job failed") {
			t.Fatalf("err = %v", err)
		}
		if f.read(t, "gateway.toml") != operatorTOML || n != 2 {
			t.Fatalf("restored=%v restarts=%d", f.read(t, "gateway.toml") == operatorTOML, n)
		}
	})
	// doctor --fix on a Mac without the Homebrew formula: `brew services
	// restart` refused, the gateway was never stopped, and the error said
	// it "did not come back" (manual test M10).
	t.Run("restart refused, gateway still up", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.cfg.GOOS = "darwin"
		f.write(t, "gateway.toml", operatorTOML)
		refused := 0
		f.runner.OnFunc("brew services restart nvidia/openshell/openshell", func(context.Context, openshell.Command) ([]byte, error) {
			refused++
			return []byte("Error: Formula `openshell` is not installed."), errors.New("brew: exit status 1")
		})
		_, err := f.apply(f.plan(t, bindMounts))
		want := "openshell: restart the gateway: brew: exit status 1: Error: Formula `openshell` is not installed.; " +
			"the gateway could not be restarted, so it still runs on its old configuration (the previous files were restored)"
		if err == nil || err.Error() != want {
			t.Fatalf("err = %v\nwant %s", err, want)
		}
		if f.read(t, "gateway.toml") != operatorTOML || refused != 2 || f.verified != 1 {
			t.Fatalf("restored=%v, restarts refused %d, health checks %d", f.read(t, "gateway.toml") == operatorTOML, refused, f.verified)
		}
		// Down after all: it did not come back.
		f.verify = errors.New("connection refused")
		if _, err := f.apply(f.plan(t, bindMounts)); err == nil || !strings.Contains(err.Error(), "did not come back") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("explicit rollback", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", operatorTOML)
		res, err := f.apply(f.plan(t, bindMounts))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.cfg.Rollback(context.Background(), res); err != nil || f.read(t, "gateway.toml") != operatorTOML || f.restarts() != 2 {
			t.Fatalf("rollback did not restore and restart: %v", err)
		}
	})
}

var errProbe = errors.New("could not confirm the gateway requires a client certificate: i/o timeout")

// TestGatewayConfigRefusesBindMountsOnExposedGateway covers the gateway
// the configurator edits, not just the CLI's registration: a registration
// that is not private mTLS, settings that let in clients without the
// registration's certificate (from gateway.env, the unit, the user manager
// or gateway.toml), a registration that reaches another gateway than the
// service, and the live client-certificate probe.
func TestGatewayConfigRefusesBindMountsOnExposedGateway(t *testing.T) {
	const addTLS = "[openshell]\nversion = 2\n\n[openshell.gateway]\n"
	env := func(content string) func(*testing.T, *gatewayFixture) {
		return func(t *testing.T, f *gatewayFixture) { f.write(t, "gateway.env", content) }
	}
	toml := func(content string) func(*testing.T, *gatewayFixture) {
		return func(t *testing.T, f *gatewayFixture) { f.write(t, "gateway.toml", addTLS+content) }
	}
	reg := func(path string, mode os.FileMode) func(*testing.T, *gatewayFixture) {
		return func(t *testing.T, f *gatewayFixture) {
			chmod(t, filepath.Join(f.dir, "gateways", "openshell", path), mode)
		}
	}
	exposed := openshell.ErrGatewayExposed
	cases := []struct {
		name  string
		setup func(t *testing.T, f *gatewayFixture)
		want  error // nil: bind mounts are allowed
	}{
		{name: "stock gateway"},
		{name: "plaintext registration", want: openshell.ErrUnauthenticatedGateway, setup: func(t *testing.T, f *gatewayFixture) {
			writeRegistration(t, f.dir, "openshell", map[string]any{"gateway_endpoint": "http://127.0.0.1:17670", "auth_mode": "plaintext"}, nil)
		}},
		{name: "no registration", want: openshell.ErrNoGateway, setup: func(t *testing.T, f *gatewayFixture) {
			if err := os.RemoveAll(filepath.Join(f.dir, "gateways")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "world-writable metadata", want: openshell.ErrInsecureRegistration, setup: reg("metadata.json", 0o666)},
		{name: "readable key", want: openshell.ErrInsecureCredentials, setup: reg("mtls/tls.key", 0o644)},
		{name: "TLS disabled in gateway.env", want: exposed, setup: env("OPENSHELL_DISABLE_TLS=true\n")},
		{name: "TLS disabled with a flag value", want: exposed, setup: env("OPENSHELL_DISABLE_TLS=1\n")},
		{name: "TLS explicitly kept", setup: env("OPENSHELL_DISABLE_TLS=false\n")},
		{name: "mTLS auth off", want: exposed, setup: env("OPENSHELL_ENABLE_MTLS_AUTH=false\n")},
		{name: "OIDC issuer", want: exposed, setup: env("OPENSHELL_OIDC_ISSUER=https://idp.example.com/realms/os\n")},
		{name: "listens on every interface", want: exposed, setup: env("OPENSHELL_BIND_ADDRESS=0.0.0.0\n")},
		{name: "empty listener settings are unset", setup: env("OPENSHELL_BIND_ADDRESS=\nOPENSHELL_SERVER_PORT=\nOPENSHELL_OIDC_ISSUER=\n")},
		{name: "IPv6 loopback listener", setup: env("OPENSHELL_BIND_ADDRESS=::1\n")},
		{name: "user manager disables TLS", want: exposed, setup: func(t *testing.T, f *gatewayFixture) { f.manager += "OPENSHELL_DISABLE_TLS=yes\n" }},
		{name: "unit Environment= binds beyond loopback", want: exposed, setup: func(t *testing.T, f *gatewayFixture) {
			f.unit += "Environment=OPENSHELL_BIND_ADDRESS=192.168.1.20\n"
		}},
		{name: "gateway.toml disables TLS", want: exposed, setup: toml("disable_tls = true\n")},
		{name: "gateway.env overrides gateway.toml", setup: func(t *testing.T, f *gatewayFixture) {
			toml("disable_tls = true\n")(t, f)
			env("OPENSHELL_DISABLE_TLS=false\n")(t, f)
		}},
		{name: "gateway.toml listens on every interface", want: exposed, setup: toml("bind_address = \"0.0.0.0:17670\"\n")},
		{name: "gateway.toml loopback listener", setup: toml("bind_address = \"127.0.0.1:17670\"\n")},
		{name: "gateway.toml mTLS auth off", want: exposed, setup: toml("\n[openshell.gateway.mtls_auth]\nenabled = false\n")},
		{name: "gateway.toml OIDC", want: exposed, setup: toml("\n[openshell.gateway.oidc]\nissuer = \"https://idp.example.com\"\naudience = \"openshell-cli\"\n")},
		{name: "gateway.toml lets unauthenticated users in", want: exposed, setup: toml("\n[openshell.gateway.auth]\nallow_unauthenticated_users = true\n")},
		{name: "service on another port", want: openshell.ErrGatewayMismatch, setup: env("OPENSHELL_SERVER_PORT=18443\n")},
		{name: "registration reaches another gateway", want: openshell.ErrGatewayMismatch, setup: func(t *testing.T, f *gatewayFixture) {
			// The active registration is a separate mTLS gateway while
			// the package service, which DefenseClaw edits, runs plaintext.
			writeRegistration(t, f.dir, "dev", map[string]any{"gateway_endpoint": "https://127.0.0.1:18080", "auth_mode": "mtls"}, nil)
			writeFile(t, filepath.Join(f.dir, "active_gateway"), "dev\n", 0o600)
			f.write(t, "gateway.env", "OPENSHELL_SERVER_PORT=17670\n")
		}},
		{name: "probe finds no client authentication", want: exposed, setup: func(t *testing.T, f *gatewayFixture) {
			f.probe = func() error { return fmt.Errorf("%w: accepted a TLS session", openshell.ErrGatewayExposed) }
		}},
		{name: "probe inconclusive", want: errProbe, setup: func(t *testing.T, f *gatewayFixture) { f.probe = func() error { return errProbe } }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGatewayFixture(t)
			if tc.setup != nil {
				tc.setup(t, f)
			}
			plan, err := f.cfg.Plan(context.Background(), bindMounts)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Plan = %v", err)
				}
				// Plan, Apply before writing, and Apply on the restarted gateway.
				if _, err := f.apply(plan); err != nil || f.probes != 3 {
					t.Fatalf("Apply = %v after %d probes", err, f.probes)
				}
				return
			}
			if !errors.Is(err, openshell.ErrBindMountsRefused) || !errors.Is(err, tc.want) {
				t.Fatalf("Plan = %v, want %v", err, tc.want)
			}
			// Changes that grant nothing still go through.
			f.plan(t, telemetryOff)
		})
	}

	t.Run("restarted gateway lets clients without a certificate in", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", operatorTOML)
		plan := f.plan(t, bindMounts)
		f.probe = func() error {
			if f.restarts() > 0 {
				return fmt.Errorf("%w: accepted a TLS session", openshell.ErrGatewayExposed)
			}
			return nil
		}
		if _, err := f.apply(plan); !errors.Is(err, openshell.ErrBindMountsRefused) || !strings.Contains(err.Error(), "previous configuration was restored") {
			t.Fatalf("Apply = %v", err)
		}
		if f.read(t, "gateway.toml") != operatorTOML || f.restarts() != 2 {
			t.Fatalf("restored=%v restarts=%d", f.read(t, "gateway.toml") == operatorTOML, f.restarts())
		}
	})
}

// TestGatewayConfigRechecksBeforeApply covers a gateway that changes
// between the plan and its application: Apply refuses before it writes.
func TestGatewayConfigRechecksBeforeApply(t *testing.T) {
	for _, tc := range []struct {
		name    string
		changes openshell.GatewayChanges
		mutate  func(t *testing.T, f *gatewayFixture)
		want    error
	}{
		{"registration downgraded", bindMounts, func(t *testing.T, f *gatewayFixture) {
			writeRegistration(t, f.dir, "openshell", map[string]any{"gateway_endpoint": "http://127.0.0.1:17670", "auth_mode": "none"}, nil)
		}, openshell.ErrBindMountsRefused},
		{"gateway exposed", bindMounts, func(t *testing.T, f *gatewayFixture) { f.write(t, "gateway.env", "OPENSHELL_DISABLE_TLS=true\n") }, openshell.ErrGatewayExposed},
		{"service reads another configuration", telemetryOff, func(t *testing.T, f *gatewayFixture) { f.manager = "HOME=/home/dev\n" }, openshell.ErrGatewayMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGatewayFixture(t)
			plan := f.plan(t, tc.changes)
			tc.mutate(t, f)
			if _, err := f.apply(plan); !errors.Is(err, tc.want) {
				t.Fatalf("Apply = %v, want %v", err, tc.want)
			}
			// The file the plan would have created.
			name := "gateway.env"
			if tc.changes.EnableBindMounts {
				name = "gateway.toml"
			}
			if _, err := os.Stat(filepath.Join(f.dir, name)); !errors.Is(err, os.ErrNotExist) || f.restarts() != 0 {
				t.Fatalf("Apply wrote %s or restarted after refusing (stat %v, restarts %d)", name, err, f.restarts())
			}
		})
	}
}

// TestGatewayConfigFollowsTheService covers a DefenseClaw environment that
// differs from the systemd user manager's: the configurator refuses to
// edit files the gateway service never loads.
func TestGatewayConfigFollowsTheService(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(f *gatewayFixture)
		want  string
	}{
		{"unit reads another gateway.env", func(f *gatewayFixture) {
			f.unit = systemdUnit("active", "enabled", time.Time{}, "/home/dev/.config/openshell/gateway.env")
			f.manager = "HOME=/home/dev\n"
		}, "reads its environment from /home/dev/.config/openshell/gateway.env"},
		{"unit reads no gateway.env", func(f *gatewayFixture) { f.unit = systemdUnit("active", "enabled", time.Time{}, "") }, "from no file"},
		{"manager discovers another gateway.toml", func(f *gatewayFixture) { f.manager = "HOME=/home/dev\n" }, "home/dev/.config/openshell/gateway.toml, not"},
		{"unit points at another gateway.toml", func(f *gatewayFixture) {
			f.unit += "Environment=OPENSHELL_GATEWAY_CONFIG=/etc/openshell/gateway.toml\n"
		}, "etc/openshell/gateway.toml, not"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGatewayFixture(t)
			tc.setup(f)
			for _, ch := range []openshell.GatewayChanges{bindMounts, telemetryOff} {
				if _, err := f.cfg.Plan(context.Background(), ch); !errors.Is(err, openshell.ErrGatewayMismatch) || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("Plan(%+v) = %v, want %q", ch, err, tc.want)
				}
			}
		})
	}
	t.Run("unit not installed", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.unit = "LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\n"
		f.write(t, "gateway.toml", operatorTOML)
		// Apply restarts through the unit: it refuses before it writes
		// (TestGatewayConfigWritesForAGatewayRunAnotherWay writes).
		if _, err := f.apply(f.plan(t, bindMounts)); !errors.Is(err, openshell.ErrNoGatewayService) {
			t.Fatalf("Apply = %v, want ErrNoGatewayService", err)
		}
		f.untouched(t, operatorTOML)
	})
	t.Run("Homebrew has no gateway.env to check", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.cfg.GOOS = "darwin"
		f.unit, f.manager = "garbage", "garbage"
		f.plan(t, bindMounts)
		if f.runner.Called("systemctl") {
			t.Fatal("asked systemd about a Homebrew service")
		}
	})
}

// TestGatewayConfigWritesForAGatewayRunAnotherWay: on Linux with OpenShell
// from the release binaries and its gateway started by hand, setup refused
// that OpenShell, and before that failed planning the change ("the
// openshell-gateway user service is not installed"), though sandboxes ran
// on the gateway (RT U1). Plan plans the files DefenseClaw reads, checking
// bind mounts against the gateway that answers; Write writes them without
// a restart and without a pending-restart mark nothing would clear; and
// Rollback restores them, saying the gateway is the user's to restart.
func TestGatewayConfigWritesForAGatewayRunAnotherWay(t *testing.T) {
	f := newGatewayFixture(t)
	f.unit = "LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\n"
	f.write(t, "gateway.toml", operatorTOML)
	plan := f.plan(t, bothChanges)
	if f.probes != 1 || len(plan.Files) != 2 {
		t.Fatalf("plan %+v, probes %d", plan.Files, f.probes)
	}
	plan.Manual = true
	text := plan.String()
	if !strings.Contains(text, "then you restart the gateway, the way you started it, so it loads the change (DefenseClaw cannot restart it); "+
		"restarting it stops every sandbox on it\n") || strings.Contains(text, "systemctl") {
		t.Fatalf("plan:\n%s", text)
	}
	// The restart of a MicroVM gateway it does not make, DefenseClaw
	// cannot flush first: the plan says to stop its sandboxes, which
	// flushes them (fu2 review 5). A switch from docker stops docker
	// sandboxes, which keep what they wrote.
	files := []*openshell.FileChange{{Path: "/cfg/gateway.toml", Summary: []string{"sandbox_uid = 501"}}}
	for _, tc := range []struct {
		from, to openshell.ComputeDriver
		want     string
	}{
		{openshell.DriverVM, openshell.DriverVM, "so it loads the change (DefenseClaw cannot restart it); restarting it stops every sandbox on it: " +
			"first stop the MicroVM sandboxes running on it with `defenseclaw sandbox stop NAME`, which flushes their disks, or what they wrote since their last sync is lost\n"},
		{openshell.DriverDocker, openshell.DriverVM, "on the vm compute driver (DefenseClaw cannot restart it), which stops every sandbox on it; " +
			"sandboxes made on the docker driver cannot start again"},
	} {
		p := &openshell.GatewayPlan{Files: files, Manual: true, ComputeDriver: tc.to, FromDriver: tc.from}
		if text := p.String(); !strings.Contains(text, tc.want) || tc.from == openshell.DriverDocker && strings.Contains(text, "flushes") {
			t.Fatalf("%s to %s plan:\n%s", tc.from, tc.to, text)
		}
	}
	res, err := f.cfg.Write(context.Background(), plan)
	if err != nil || res.Restarted || len(res.Files) != 2 || f.restarts() != 0 || f.flushes != 0 || f.probes != 2 {
		t.Fatalf("Write = %+v, %v; restarts %d, flushes %d, probes %d", res, err, f.restarts(), f.flushes, f.probes)
	}
	if !strings.Contains(f.read(t, "gateway.toml"), "enable_bind_mounts = true") || f.read(t, "gateway.env") != "OPENSHELL_TELEMETRY_ENABLED=false\n" {
		t.Fatalf("gateway.toml:\n%s\ngateway.env:\n%s", f.read(t, "gateway.toml"), f.read(t, "gateway.env"))
	}
	if st, err := f.cfg.Read(); err != nil || !st.RestartPendingSince.IsZero() {
		t.Fatalf("Write left a pending-restart mark: %+v, %v", st, err)
	}
	// Bind mounts on a gateway others can reach are refused before anything is written.
	f.write(t, "gateway.toml", operatorTOML)
	exposed := f.plan(t, bindMounts)
	f.probe = func() error { return openshell.ErrGatewayExposed }
	if _, err := f.cfg.Write(context.Background(), exposed); !errors.Is(err, openshell.ErrBindMountsRefused) || f.read(t, "gateway.toml") != operatorTOML {
		t.Fatalf("Write on an exposed gateway = %v", err)
	}
	if err := f.cfg.Rollback(context.Background(), res); !errors.Is(err, openshell.ErrNoGatewayService) || f.restarts() != 0 || f.flushes != 0 {
		t.Fatalf("Rollback = %v; restarts %d, flushes %d", err, f.restarts(), f.flushes)
	}
	if f.read(t, "gateway.toml") != operatorTOML {
		t.Fatalf("gateway.toml not restored:\n%s", f.read(t, "gateway.toml"))
	}
	if _, err := os.Stat(filepath.Join(f.dir, "gateway.env")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created gateway.env not removed: %v", err)
	}
}

// TestGatewayConfigPreflightsWithTheGatewayNextToTheCLI: an OpenShell run by
// hand from a prefix that is not on PATH has no openshell-gateway there, and
// Write's preflight failed to run the bare name. The gateway next to the
// OpenShell CLI preflights instead, and the one on PATH still comes first.
func TestGatewayConfigPreflightsWithTheGatewayNextToTheCLI(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "prefix", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	gateway := filepath.Join(bin, "openshell-gateway")
	for _, name := range []string{"openshell", "openshell-gateway"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f := newGatewayFixture(t)
	f.cfg.CLI = "openshell"
	f.cfg.LookPath = func(name string) (string, error) {
		if name == "openshell" {
			return filepath.Join(bin, "openshell"), nil
		}
		return "", exec.ErrNotFound
	}
	f.runner.On(gateway+" config preflight", "", nil)
	f.write(t, "gateway.toml", operatorTOML)
	plan := f.plan(t, bindMounts)
	if _, err := f.apply(plan); err != nil || !f.runner.Called(gateway+" config preflight") {
		t.Fatalf("apply = %v; calls %v", err, f.runner.Calls())
	}

	onPath := newGatewayFixture(t)
	onPath.cfg.LookPath = func(name string) (string, error) { return filepath.Join(bin, name), nil }
	onPath.write(t, "gateway.toml", operatorTOML)
	if _, err := onPath.apply(onPath.plan(t, bindMounts)); err != nil || onPath.runner.Called(gateway+" config preflight") {
		t.Fatalf("with the gateway on PATH: %v; calls %v", err, onPath.runner.Calls())
	}
}

// TestGatewayConfigTrustsTheProbeWithoutAServiceEnvironment (fu2 review
// 3): on Linux, a private gateway started by hand with
// OPENSHELL_SERVER_PORT=8080 and registered at :8080 was refused bind
// mounts ("…but the openshell-gateway service listens on port 17670"): with
// no unit, its port is in an environment DefenseClaw cannot read, and the
// default was compared. Without a service environment the registration and
// the client-auth probe of the gateway it reaches decide; a gateway.toml
// that opens the gateway to others is still refused.
func TestGatewayConfigTrustsTheProbeWithoutAServiceEnvironment(t *testing.T) {
	setup := func(t *testing.T, toml string) *gatewayFixture {
		f := newGatewayFixture(t)
		f.unit = "LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\n"
		writeRegistration(t, f.dir, "openshell", map[string]any{"name": "openshell", "gateway_endpoint": "https://127.0.0.1:8080",
			"is_remote": false, "gateway_port": 8080, "auth_mode": "mtls"}, nil)
		f.write(t, "gateway.toml", toml)
		return f
	}
	f := setup(t, operatorTOML)
	plan := f.plan(t, bindMounts)
	if f.probes != 1 || !plan.BindMounts {
		t.Fatalf("plan %+v, probes %d", plan, f.probes)
	}
	plan.Manual = true
	if _, err := f.cfg.Write(context.Background(), plan); err != nil || !strings.Contains(f.read(t, "gateway.toml"), "enable_bind_mounts = true") {
		t.Fatalf("Write = %v\n%s", err, f.read(t, "gateway.toml"))
	}
	// Listening beyond this machine is refused, whatever the port.
	exposed := strings.Replace(operatorTOML, "[openshell.drivers.docker]", "[openshell.gateway]\nbind_address = \"0.0.0.0:8080\"\n\n[openshell.drivers.docker]", 1)
	f = setup(t, exposed)
	if _, err := f.cfg.Plan(context.Background(), bindMounts); !errors.Is(err, openshell.ErrBindMountsRefused) || !errors.Is(err, openshell.ErrGatewayExposed) {
		t.Fatalf("Plan on a gateway listening beyond loopback = %v", err)
	}
	// The probe still refuses a gateway that lets in a client without the certificate.
	f = setup(t, operatorTOML)
	f.probe = func() error { return openshell.ErrGatewayExposed }
	if _, err := f.cfg.Plan(context.Background(), bindMounts); !errors.Is(err, openshell.ErrBindMountsRefused) {
		t.Fatalf("Plan on an exposed gateway = %v", err)
	}
	// Homebrew's service has an environment DefenseClaw cannot read either,
	// but it is the gateway DefenseClaw edits: a registration on another
	// port reaches another gateway, which the probe would judge instead.
	f = setup(t, operatorTOML)
	f.cfg.GOOS = "darwin"
	f.cfg.BrewFormulaInstalled = func() bool { return true }
	if _, err := f.cfg.Plan(context.Background(), bindMounts); !errors.Is(err, openshell.ErrGatewayMismatch) || f.probes != 0 {
		t.Fatalf("Plan on Homebrew's gateway with a registration on another port = %v (probes %d)", err, f.probes)
	}
}

// TestGatewayConfigRecordsPendingRestart covers a restart that never
// happens after the files were written: the pending mark stays until a
// restart succeeds, on every platform.
func TestGatewayConfigRecordsPendingRestart(t *testing.T) {
	f := newGatewayFixture(t)
	f.write(t, "gateway.toml", operatorTOML)
	f.runner.On("systemctl --user restart openshell-gateway", "Job failed", errors.New("exit status 1"))
	// systemd stopped the gateway and could not start it again.
	f.verify = errors.New("connection refused")
	if _, err := f.apply(f.plan(t, bindMounts)); err == nil || !strings.Contains(err.Error(), "did not come back") {
		t.Fatalf("Apply = %v", err)
	}
	f.verify = nil
	if st, err := f.cfg.Read(); err != nil || st.RestartPendingSince.IsZero() {
		t.Fatalf("no pending restart recorded: %+v, %v", st, err)
	}
	f.runner.On("systemctl --user restart openshell-gateway", "", nil)
	if err := f.cfg.Restart(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.cfg.Read(); !st.RestartPendingSince.IsZero() {
		t.Fatal("a successful restart left the pending mark")
	}

	// A write that fails before any restart restores the files the gateway
	// still runs on, so nothing is pending.
	f = newGatewayFixture(t)
	f.write(t, "gateway.toml", operatorTOML)
	plan := f.plan(t, bindMounts)
	for i := 0; i < 100; i++ {
		name := "gateway.toml.defenseclaw-20260926T190000Z.bak"
		if i > 0 {
			name = fmt.Sprintf("gateway.toml.defenseclaw-20260926T190000Z-%d.bak", i)
		}
		f.write(t, name, "taken")
	}
	if _, err := f.apply(plan); err == nil || !strings.Contains(err.Error(), "too many backups") {
		t.Fatalf("Apply = %v", err)
	}
	if st, _ := f.cfg.Read(); !st.RestartPendingSince.IsZero() || f.restarts() != 0 || f.read(t, "gateway.toml") != operatorTOML {
		t.Fatalf("pending = %v, restarts = %d", st.RestartPendingSince, f.restarts())
	}
}

// TestGatewayConfigThroughSymlinkedDir covers a config directory that a
// dotfile manager links elsewhere: reads, the plan, backups, the preflight
// copy and the rollback all use the real directory, and the link stays.
func TestGatewayConfigThroughSymlinkedDir(t *testing.T) {
	f := newGatewayFixture(t)
	f.write(t, "gateway.toml", operatorTOML)
	f.write(t, "gateway.env", "OPENSHELL_LOG=info\n")
	link := filepath.Join(t.TempDir(), "openshell")
	if err := os.Symlink(f.dir, link); err != nil {
		t.Fatal(err)
	}
	f.cfg.Dir = link
	st, err := f.cfg.Read()
	if err != nil || st.TOMLPath != filepath.Join(f.dir, "gateway.toml") || st.EnvPath != filepath.Join(f.dir, "gateway.env") || !st.TOMLExists || !st.EnvExists || f.cfg.Dir != f.dir {
		t.Fatalf("state = %+v, %v (dir %s)", st, err, f.cfg.Dir)
	}
	plan := f.plan(t, bothChanges)
	if len(plan.Files) != 2 || plan.Files[0].Path != st.TOMLPath || plan.Files[1].Path != st.EnvPath {
		t.Fatalf("plan = %s", plan)
	}
	res, err := f.apply(plan)
	if err != nil || len(f.backups()) != 2 || len(f.preflighted) != 1 {
		t.Fatalf("Apply = %v; backups %v, preflights %d", err, f.backups(), len(f.preflighted))
	}
	if st, err := f.cfg.Read(); err != nil || !st.BindMounts.Enabled() || st.TelemetryEnabled() {
		t.Fatalf("applied state = %+v, %v", st, err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was replaced: %v, %v", info, err)
	}
	if err := f.cfg.Rollback(context.Background(), res); err != nil || f.read(t, "gateway.toml") != operatorTOML || f.read(t, "gateway.env") != "OPENSHELL_LOG=info\n" {
		t.Fatalf("rollback did not restore the files: %v", err)
	}
}

func TestGatewayConfigPathFromEnv(t *testing.T) {
	f := newGatewayFixture(t)
	alt := filepath.Join(realTempDir(t), "alt.toml")
	f.write(t, "gateway.env", "OPENSHELL_GATEWAY_CONFIG="+alt+"\n")
	// The plan edits the gateway.toml gateway.env names, even before it exists.
	if plan := f.plan(t, bindMounts); len(plan.Files) != 1 || plan.Files[0].Path != alt {
		t.Fatalf("plan = %s", plan)
	}
	writeFile(t, alt, "[openshell]\nversion = 2\n", 0o600)
	if p, err := f.cfg.TOMLPath(); err != nil || p != alt {
		t.Fatalf("TOMLPath = %q, %v", p, err)
	}
	// A linked directory in OPENSHELL_GATEWAY_CONFIG resolves too.
	link := filepath.Join(t.TempDir(), "conf")
	if err := os.Symlink(filepath.Dir(alt), link); err != nil {
		t.Fatal(err)
	}
	f.write(t, "gateway.env", "OPENSHELL_GATEWAY_CONFIG="+filepath.Join(link, "alt.toml")+"\n")
	if p, err := f.cfg.TOMLPath(); err != nil || p != alt {
		t.Fatalf("TOMLPath through a link = %q, %v", p, err)
	}
	if st, err := f.cfg.Read(); err != nil || !st.TOMLExists {
		t.Fatalf("Read through a link = %+v, %v", st, err)
	}
}

func TestGatewayServiceState(t *testing.T) {
	t.Run("systemd", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.unit = "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n" +
			"ActiveEnterTimestamp=Sat 2026-09-26 16:18:34.451059 UTC\n" +
			`Environment=OPENSHELL_LOCAL_TLS_DIR=/home/dev/.local/state/openshell/tls "OPENSHELL_LOG=info debug" LANG=C.UTF-8` + "\n" +
			"EnvironmentFiles=/home/dev/.config/openshell/gateway.env (ignore_errors=yes)\n" +
			"EnvironmentFiles=/etc/openshell/extra.env (ignore_errors=no)\n"
		f.manager = "HOME=/home/dev\nOPENSHELL_LOG=warn\nOPENSHELL_ODD=$'a\\'b'\nSSH_AUTH_SOCK=/tmp/agent\n"
		st, err := f.cfg.ServiceState(context.Background())
		// systemd reports the start to the microsecond.
		if err != nil || !st.Installed || !st.Active || !st.Enabled || st.Status != "active (running)" ||
			!st.StartedAt.Equal(time.Date(2026, 9, 26, 16, 18, 34, 451059000, time.UTC)) {
			t.Fatalf("state = %+v, %v", st, err)
		}
		if strings.Join(st.EnvironmentFiles, ",") != "/home/dev/.config/openshell/gateway.env,/etc/openshell/extra.env" {
			t.Fatalf("environment files = %q", st.EnvironmentFiles)
		}
		want := map[string]string{"HOME": "/home/dev", "OPENSHELL_LOCAL_TLS_DIR": "/home/dev/.local/state/openshell/tls", "OPENSHELL_LOG": "info debug", "OPENSHELL_ODD": "a'b"}
		if fmt.Sprint(st.Environment) != fmt.Sprint(want) {
			t.Fatalf("environment = %v, want %v", st.Environment, want)
		}
	})
	t.Run("systemd unit only linked or enabled until reboot", func(t *testing.T) {
		for _, state := range []string{"linked", "linked-runtime", "enabled-runtime", "disabled", "static"} {
			f := newGatewayFixture(t)
			f.unit = systemdUnit("active", state, time.Time{}, "")
			if st, err := f.cfg.ServiceState(context.Background()); err != nil || st.Enabled || !st.Active {
				t.Fatalf("UnitFileState=%s: state = %+v, %v", state, st, err)
			}
		}
	})
	t.Run("systemd unit missing", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.unit = "LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\nActiveEnterTimestamp=\n"
		if st, err := f.cfg.ServiceState(context.Background()); err != nil || st.Installed || st.Active || !st.StartedAt.IsZero() {
			t.Fatalf("state = %+v, %v", st, err)
		}
	})
	t.Run("homebrew", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.cfg.GOOS = "darwin"
		f.cfg.BrewFormulaInstalled = func() bool { return true }
		f.runner.On("brew services info nvidia/openshell/openshell --json", `[{"name":"openshell","running":true,"loaded":true,"status":"started","file":"/Users/u/Library/LaunchAgents/homebrew.mxcl.openshell.plist"}]`, nil)
		f.runner.On("brew services restart nvidia/openshell/openshell", "", nil)
		if st, err := f.cfg.ServiceState(context.Background()); err != nil || !st.Active || !st.Installed || st.Manager != "brew" {
			t.Fatalf("state = %+v, %v", st, err)
		}
		if err := f.cfg.Restart(context.Background()); err != nil || !f.runner.Called("brew services restart nvidia/openshell/openshell") {
			t.Fatalf("restart: %v", err)
		}
	})
	// Without the formula there is no service to ask brew about, and brew
	// took about 40 s to say so on a Mac (manual test M4): the Homebrew
	// prefix answers instead.
	t.Run("homebrew without the formula", func(t *testing.T) {
		prefix := t.TempDir()
		t.Setenv("HOMEBREW_PREFIX", prefix)
		t.Setenv("PATH", t.TempDir())
		f := newGatewayFixture(t)
		f.cfg.GOOS = "darwin"
		f.runner.On("brew services info nvidia/openshell/openshell --json", `[{"running":true,"loaded":true,"status":"started","file":"/x.plist"}]`, nil)
		if st, err := f.cfg.ServiceState(context.Background()); err != nil || st.Installed || st.Manager != "brew" || f.runner.Called("brew") {
			t.Fatalf("state = %+v, %v; brew asked: %t", st, err, f.runner.Called("brew"))
		}
		if err := os.MkdirAll(filepath.Join(prefix, "opt", "openshell"), 0o755); err != nil {
			t.Fatal(err)
		}
		if st, err := f.cfg.ServiceState(context.Background()); err != nil || !st.Installed || !f.runner.Called("brew services info") {
			t.Fatalf("with the formula: state = %+v, %v", st, err)
		}
	})
}
