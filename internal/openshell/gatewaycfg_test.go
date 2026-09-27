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
		Runner:          f.runner,
		VerifyGateway:   func(context.Context) error { f.verified++; return f.verify },
		ProbeClientAuth: func(context.Context, *openshell.Registration) error { f.probes++; return f.probe() },
		Now:             func() time.Time { return time.Date(2026, 9, 26, 19, 0, 0, 0, time.UTC) },
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

func (f *gatewayFixture) backups(t *testing.T) []string {
	t.Helper()
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

func TestGatewayConfigCreate(t *testing.T) {
	f := newGatewayFixture(t)
	st, err := f.cfg.Read()
	if err != nil || st.TOMLExists || st.BindMounts.Enabled() || !st.BindMounts.ResourceAdmission || !st.TelemetryEnabled() {
		t.Fatalf("fresh state = %+v, %v", st, err)
	}
	plan, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true, Env: map[string]string{openshell.EnvTelemetryEnabled: "false"}})
	if err != nil {
		t.Fatal(err)
	}
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
	res, err := f.cfg.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Restarted || f.restarts() != 1 || f.verified != 1 || len(res.Files) != 2 {
		t.Fatalf("result = %+v restarts=%d verified=%d", res, f.restarts(), f.verified)
	}
	for _, af := range res.Files {
		if af.Backup != "" {
			t.Fatalf("created file got a backup: %+v", af)
		}
		info, err := os.Stat(af.Path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v mode %v", af.Path, err, info.Mode())
		}
	}
	if !strings.Contains(f.read(t, "gateway.toml"), "version = 2") {
		t.Fatalf("new gateway.toml lacks the schema version:\n%s", f.read(t, "gateway.toml"))
	}
	if len(f.preflighted) != 1 || f.preflighted[0] != f.read(t, "gateway.toml") {
		t.Fatalf("preflight saw %q", f.preflighted)
	}
	if left, _ := filepath.Glob(filepath.Join(f.dir, ".defenseclaw-preflight-*")); len(left) != 0 {
		t.Fatalf("preflight temp files left: %v", left)
	}
	st, err = f.cfg.Read()
	if err != nil || !st.BindMounts.Enabled() || st.TelemetryEnabled() {
		t.Fatalf("state after apply = %+v, %v", st, err)
	}
	again, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true, Env: map[string]string{openshell.EnvTelemetryEnabled: "false"}})
	if err != nil || !again.Empty() {
		t.Fatalf("second plan = %+v, %v", again, err)
	}
	if res, err := f.cfg.Apply(context.Background(), again); err != nil || res.Restarted || f.restarts() != 1 {
		t.Fatalf("empty apply restarted: %+v %v", res, err)
	}
}

func TestGatewayConfigEditKeepsCommentsAndBacksUp(t *testing.T) {
	f := newGatewayFixture(t)
	f.write(t, "gateway.toml", operatorTOML)
	f.write(t, "gateway.env", "# secrets below\nOPENSHELL_DB_URL=postgres://u:hunter2@db/os\n")
	plan, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true, Env: map[string]string{openshell.EnvTelemetryEnabled: "false"}})
	if err != nil {
		t.Fatal(err)
	}
	if text := plan.String(); strings.Contains(text, "hunter2") || !strings.Contains(text, "- enable_bind_mounts = false\n      + enable_bind_mounts = true") ||
		!strings.Contains(text, "edit "+filepath.Join(f.dir, "gateway.env")+" (a timestamped backup is kept)") {
		t.Fatalf("plan:\n%s", text)
	}
	if _, err := f.cfg.Apply(context.Background(), plan); err != nil {
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
	backups := f.backups(t)
	if len(backups) != 2 {
		t.Fatalf("backups = %v", backups)
	}
	for _, b := range backups {
		data, _ := os.ReadFile(b)
		info, _ := os.Stat(b)
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", b, info.Mode())
		}
		if strings.HasPrefix(filepath.Base(b), "gateway.toml.defenseclaw-20260926T190000Z") && string(data) != operatorTOML {
			t.Errorf("toml backup = %q", data)
		}
	}
}

func TestGatewayConfigApplyGuards(t *testing.T) {
	t.Run("changed since plan", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", operatorTOML)
		plan, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true})
		if err != nil {
			t.Fatal(err)
		}
		f.write(t, "gateway.toml", operatorTOML+"# edited meanwhile\n")
		if _, err := f.cfg.Apply(context.Background(), plan); !errors.Is(err, openshell.ErrConfigChanged) {
			t.Fatalf("err = %v", err)
		}
		if f.restarts() != 0 || len(f.backups(t)) != 0 {
			t.Fatal("a stale plan was applied")
		}
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
		plan, _ := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true})
		_, err := f.cfg.Apply(context.Background(), plan)
		if !errors.Is(err, openshell.ErrPreflight) || !strings.Contains(err.Error(), "DefenseClaw's change") || !strings.Contains(err.Error(), "category=malformed") {
			t.Fatalf("err = %v", err)
		}
		if f.read(t, "gateway.toml") != operatorTOML || len(f.backups(t)) != 0 || f.restarts() != 0 {
			t.Fatal("a rejected edit was written")
		}
	})
	t.Run("original already fails preflight", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", operatorTOML)
		f.runner.On("openshell-gateway config preflight", "category=missing_version", errors.New("exit status 1"))
		plan, _ := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true})
		if _, err := f.cfg.Apply(context.Background(), plan); !errors.Is(err, openshell.ErrPreflight) || !strings.Contains(err.Error(), "already fails preflight") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("symlinked config refused", func(t *testing.T) {
		f := newGatewayFixture(t)
		target := filepath.Join(t.TempDir(), "elsewhere.toml")
		if err := os.WriteFile(target, []byte(operatorTOML), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(f.dir, "gateway.toml")); err != nil {
			t.Fatal(err)
		}
		if _, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unsafe TOML shape", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", "[openshell]\nversion = 2\ndrivers = { docker = { enable_bind_mounts = false } }\n")
		if _, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true}); !errors.Is(err, openshell.ErrTOMLEdit) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestGatewayConfigRollback(t *testing.T) {
	t.Run("unhealthy after restart", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", operatorTOML)
		f.verify = errors.New("connection refused")
		plan, _ := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true, Env: map[string]string{openshell.EnvTelemetryEnabled: "false"}})
		_, err := f.cfg.Apply(context.Background(), plan)
		if err == nil || !strings.Contains(err.Error(), "did not come back") {
			t.Fatalf("err = %v", err)
		}
		if f.read(t, "gateway.toml") != operatorTOML {
			t.Fatal("gateway.toml was not restored")
		}
		if _, err := os.Stat(filepath.Join(f.dir, "gateway.env")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("created gateway.env survived the rollback: %v", err)
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
			n++
			if n == 1 {
				return []byte("Job failed"), errors.New("exit status 1")
			}
			return nil, nil
		})
		plan, _ := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true})
		_, err := f.cfg.Apply(context.Background(), plan)
		if err == nil || !strings.Contains(err.Error(), "previous configuration was restored") || !strings.Contains(err.Error(), "Job failed") {
			t.Fatalf("err = %v", err)
		}
		if f.read(t, "gateway.toml") != operatorTOML || n != 2 {
			t.Fatalf("restored=%v restarts=%d", f.read(t, "gateway.toml") == operatorTOML, n)
		}
	})
	t.Run("explicit rollback", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", operatorTOML)
		plan, _ := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true})
		res, err := f.cfg.Apply(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.cfg.Rollback(context.Background(), res); err != nil {
			t.Fatal(err)
		}
		if f.read(t, "gateway.toml") != operatorTOML || f.restarts() != 2 {
			t.Fatal("rollback did not restore and restart")
		}
	})
}

func TestGatewayConfigRefusesBindMountsWithoutPrivateGateway(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *gatewayFixture)
		want  error
	}{
		{name: "plaintext registration", want: openshell.ErrUnauthenticatedGateway, setup: func(t *testing.T, f *gatewayFixture) {
			writeRegistration(t, f.dir, "openshell", map[string]any{"gateway_endpoint": "http://127.0.0.1:17670", "auth_mode": "plaintext"}, nil)
		}},
		{name: "no registration", want: openshell.ErrNoGateway, setup: func(t *testing.T, f *gatewayFixture) {
			if err := os.RemoveAll(filepath.Join(f.dir, "gateways")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "world-writable metadata", want: openshell.ErrInsecureRegistration, setup: func(t *testing.T, f *gatewayFixture) {
			chmod(t, filepath.Join(f.dir, "gateways", "openshell", "metadata.json"), 0o666)
		}},
		{name: "readable key", want: openshell.ErrInsecureCredentials, setup: func(t *testing.T, f *gatewayFixture) {
			chmod(t, filepath.Join(f.dir, "gateways", "openshell", "mtls", "tls.key"), 0o644)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGatewayFixture(t)
			tc.setup(t, f)
			if _, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true}); !errors.Is(err, openshell.ErrBindMountsRefused) || !errors.Is(err, tc.want) {
				t.Fatalf("Plan = %v, want %v", err, tc.want)
			}
			// Changes that grant nothing still go through.
			if _, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{Env: map[string]string{openshell.EnvTelemetryEnabled: "false"}}); err != nil {
				t.Fatalf("telemetry Plan = %v", err)
			}
		})
	}

	t.Run("registration downgraded between plan and apply", func(t *testing.T) {
		f := newGatewayFixture(t)
		plan, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true})
		if err != nil {
			t.Fatal(err)
		}
		writeRegistration(t, f.dir, "openshell", map[string]any{"gateway_endpoint": "http://127.0.0.1:17670", "auth_mode": "none"}, nil)
		if _, err := f.cfg.Apply(context.Background(), plan); !errors.Is(err, openshell.ErrBindMountsRefused) {
			t.Fatalf("Apply = %v", err)
		}
		if _, err := os.Stat(filepath.Join(f.dir, "gateway.toml")); !errors.Is(err, os.ErrNotExist) || f.restarts() != 0 {
			t.Fatalf("Apply wrote or restarted after refusing (stat %v, restarts %d)", err, f.restarts())
		}
	})
}

// TestGatewayConfigRefusesBindMountsOnExposedGateway covers the gateway
// the configurator edits, not just the CLI's registration: settings that
// let in clients without the registration's certificate (from gateway.env,
// the unit, the user manager or gateway.toml), a registration that reaches
// another gateway than the service, and the live client-certificate probe.
func TestGatewayConfigRefusesBindMountsOnExposedGateway(t *testing.T) {
	const addTLS = "[openshell]\nversion = 2\n\n[openshell.gateway]\n"
	cases := []struct {
		name  string
		setup func(t *testing.T, f *gatewayFixture)
		want  error // nil: bind mounts are allowed
	}{
		{name: "stock gateway"},
		{name: "TLS disabled in gateway.env", want: openshell.ErrGatewayExposed, setup: func(t *testing.T, f *gatewayFixture) {
			f.write(t, "gateway.env", "OPENSHELL_DISABLE_TLS=true\n")
		}},
		{name: "TLS disabled with a flag value", want: openshell.ErrGatewayExposed, setup: func(t *testing.T, f *gatewayFixture) {
			f.write(t, "gateway.env", "OPENSHELL_DISABLE_TLS=1\n")
		}},
		{name: "TLS explicitly kept", setup: func(t *testing.T, f *gatewayFixture) {
			f.write(t, "gateway.env", "OPENSHELL_DISABLE_TLS=false\n")
		}},
		{name: "mTLS auth off", want: openshell.ErrGatewayExposed, setup: func(t *testing.T, f *gatewayFixture) {
			f.write(t, "gateway.env", "OPENSHELL_ENABLE_MTLS_AUTH=false\n")
		}},
		{name: "OIDC issuer", want: openshell.ErrGatewayExposed, setup: func(t *testing.T, f *gatewayFixture) {
			f.write(t, "gateway.env", "OPENSHELL_OIDC_ISSUER=https://idp.example.com/realms/os\n")
		}},
		{name: "listens on every interface", want: openshell.ErrGatewayExposed, setup: func(t *testing.T, f *gatewayFixture) {
			f.write(t, "gateway.env", "OPENSHELL_BIND_ADDRESS=0.0.0.0\n")
		}},
		{name: "empty listener settings are unset", setup: func(t *testing.T, f *gatewayFixture) {
			f.write(t, "gateway.env", "OPENSHELL_BIND_ADDRESS=\nOPENSHELL_SERVER_PORT=\nOPENSHELL_OIDC_ISSUER=\n")
		}},
		{name: "IPv6 loopback listener", setup: func(t *testing.T, f *gatewayFixture) {
			f.write(t, "gateway.env", "OPENSHELL_BIND_ADDRESS=::1\n")
		}},
		{name: "user manager disables TLS", want: openshell.ErrGatewayExposed, setup: func(t *testing.T, f *gatewayFixture) {
			f.manager += "OPENSHELL_DISABLE_TLS=yes\n"
		}},
		{name: "unit Environment= binds beyond loopback", want: openshell.ErrGatewayExposed, setup: func(t *testing.T, f *gatewayFixture) {
			f.unit += "Environment=OPENSHELL_BIND_ADDRESS=192.168.1.20\n"
		}},
		{name: "gateway.toml disables TLS", want: openshell.ErrGatewayExposed, setup: func(t *testing.T, f *gatewayFixture) {
			f.write(t, "gateway.toml", addTLS+"disable_tls = true\n")
		}},
		{name: "gateway.env overrides gateway.toml", setup: func(t *testing.T, f *gatewayFixture) {
			f.write(t, "gateway.toml", addTLS+"disable_tls = true\n")
			f.write(t, "gateway.env", "OPENSHELL_DISABLE_TLS=false\n")
		}},
		{name: "gateway.toml listens on every interface", want: openshell.ErrGatewayExposed, setup: func(t *testing.T, f *gatewayFixture) {
			f.write(t, "gateway.toml", addTLS+"bind_address = \"0.0.0.0:17670\"\n")
		}},
		{name: "gateway.toml loopback listener", setup: func(t *testing.T, f *gatewayFixture) {
			f.write(t, "gateway.toml", addTLS+"bind_address = \"127.0.0.1:17670\"\n")
		}},
		{name: "gateway.toml mTLS auth off", want: openshell.ErrGatewayExposed, setup: func(t *testing.T, f *gatewayFixture) {
			f.write(t, "gateway.toml", addTLS+"\n[openshell.gateway.mtls_auth]\nenabled = false\n")
		}},
		{name: "gateway.toml OIDC", want: openshell.ErrGatewayExposed, setup: func(t *testing.T, f *gatewayFixture) {
			f.write(t, "gateway.toml", addTLS+"\n[openshell.gateway.oidc]\nissuer = \"https://idp.example.com\"\naudience = \"openshell-cli\"\n")
		}},
		{name: "gateway.toml lets unauthenticated users in", want: openshell.ErrGatewayExposed, setup: func(t *testing.T, f *gatewayFixture) {
			f.write(t, "gateway.toml", addTLS+"\n[openshell.gateway.auth]\nallow_unauthenticated_users = true\n")
		}},
		{name: "service on another port", want: openshell.ErrGatewayMismatch, setup: func(t *testing.T, f *gatewayFixture) {
			f.write(t, "gateway.env", "OPENSHELL_SERVER_PORT=18443\n")
		}},
		{name: "registration reaches another gateway", want: openshell.ErrGatewayMismatch, setup: func(t *testing.T, f *gatewayFixture) {
			// The active registration is a separate mTLS gateway while
			// the package service, which DefenseClaw edits, runs plaintext.
			writeRegistration(t, f.dir, "dev", map[string]any{"gateway_endpoint": "https://127.0.0.1:18080", "auth_mode": "mtls"}, nil)
			writeFile(t, filepath.Join(f.dir, "active_gateway"), "dev\n", 0o600)
			f.write(t, "gateway.env", "OPENSHELL_SERVER_PORT=17670\n")
		}},
		{name: "probe finds no client authentication", want: openshell.ErrGatewayExposed, setup: func(t *testing.T, f *gatewayFixture) {
			f.probe = func() error { return fmt.Errorf("%w: accepted a TLS session", openshell.ErrGatewayExposed) }
		}},
		{name: "probe inconclusive", want: errProbe, setup: func(t *testing.T, f *gatewayFixture) {
			f.probe = func() error { return errProbe }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGatewayFixture(t)
			if tc.setup != nil {
				tc.setup(t, f)
			}
			plan, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true})
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Plan = %v", err)
				}
				if _, err := f.cfg.Apply(context.Background(), plan); err != nil {
					t.Fatalf("Apply = %v", err)
				}
				// Plan, Apply before writing, and Apply on the restarted gateway.
				if f.probes != 3 {
					t.Fatalf("probed %d times", f.probes)
				}
				return
			}
			if !errors.Is(err, openshell.ErrBindMountsRefused) || !errors.Is(err, tc.want) {
				t.Fatalf("Plan = %v, want %v", err, tc.want)
			}
			// Changes that grant nothing still go through.
			if _, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{Env: map[string]string{openshell.EnvTelemetryEnabled: "false"}}); err != nil {
				t.Fatalf("telemetry Plan = %v", err)
			}
		})
	}

	t.Run("gateway exposed between plan and apply", func(t *testing.T) {
		f := newGatewayFixture(t)
		plan, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true})
		if err != nil {
			t.Fatal(err)
		}
		f.write(t, "gateway.env", "OPENSHELL_DISABLE_TLS=true\n")
		if _, err := f.cfg.Apply(context.Background(), plan); !errors.Is(err, openshell.ErrGatewayExposed) {
			t.Fatalf("Apply = %v", err)
		}
		if _, err := os.Stat(filepath.Join(f.dir, "gateway.toml")); !errors.Is(err, os.ErrNotExist) || f.restarts() != 0 {
			t.Fatalf("Apply wrote or restarted after refusing (stat %v, restarts %d)", err, f.restarts())
		}
	})
	t.Run("restarted gateway lets clients without a certificate in", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", operatorTOML)
		plan, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true})
		if err != nil {
			t.Fatal(err)
		}
		f.probe = func() error {
			if f.restarts() > 0 {
				return fmt.Errorf("%w: accepted a TLS session", openshell.ErrGatewayExposed)
			}
			return nil
		}
		_, err = f.cfg.Apply(context.Background(), plan)
		if !errors.Is(err, openshell.ErrBindMountsRefused) || !strings.Contains(err.Error(), "previous configuration was restored") {
			t.Fatalf("Apply = %v", err)
		}
		if f.read(t, "gateway.toml") != operatorTOML || f.restarts() != 2 {
			t.Fatalf("restored=%v restarts=%d", f.read(t, "gateway.toml") == operatorTOML, f.restarts())
		}
	})
}

var errProbe = errors.New("could not confirm the gateway requires a client certificate: i/o timeout")

// TestGatewayConfigFollowsTheService covers a DefenseClaw environment that
// differs from the systemd user manager's: the configurator refuses to
// edit files the gateway service never loads.
func TestGatewayConfigFollowsTheService(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *gatewayFixture)
		want  string
	}{
		{name: "unit reads another gateway.env", want: "reads its environment from /home/dev/.config/openshell/gateway.env", setup: func(t *testing.T, f *gatewayFixture) {
			f.unit = systemdUnit("active", "enabled", time.Time{}, "/home/dev/.config/openshell/gateway.env")
			f.manager = "HOME=/home/dev\n"
		}},
		{name: "unit reads no gateway.env", want: "from no file", setup: func(t *testing.T, f *gatewayFixture) {
			f.unit = systemdUnit("active", "enabled", time.Time{}, "")
		}},
		{name: "manager discovers another gateway.toml", want: "home/dev/.config/openshell/gateway.toml, not", setup: func(t *testing.T, f *gatewayFixture) {
			f.manager = "HOME=/home/dev\n"
		}},
		{name: "unit points at another gateway.toml", want: "etc/openshell/gateway.toml, not", setup: func(t *testing.T, f *gatewayFixture) {
			f.unit += "Environment=OPENSHELL_GATEWAY_CONFIG=/etc/openshell/gateway.toml\n"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGatewayFixture(t)
			tc.setup(t, f)
			for _, ch := range []openshell.GatewayChanges{{EnableBindMounts: true}, {Env: map[string]string{openshell.EnvTelemetryEnabled: "false"}}} {
				if _, err := f.cfg.Plan(context.Background(), ch); !errors.Is(err, openshell.ErrGatewayMismatch) || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("Plan(%+v) = %v, want %q", ch, err, tc.want)
				}
			}
		})
	}
	t.Run("service changed between plan and apply", func(t *testing.T) {
		f := newGatewayFixture(t)
		plan, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{Env: map[string]string{openshell.EnvTelemetryEnabled: "false"}})
		if err != nil {
			t.Fatal(err)
		}
		f.manager = "HOME=/home/dev\n"
		if _, err := f.cfg.Apply(context.Background(), plan); !errors.Is(err, openshell.ErrGatewayMismatch) {
			t.Fatalf("Apply = %v", err)
		}
		if _, err := os.Stat(filepath.Join(f.dir, "gateway.env")); !errors.Is(err, os.ErrNotExist) || f.restarts() != 0 {
			t.Fatalf("Apply wrote or restarted (stat %v, restarts %d)", err, f.restarts())
		}
	})
	t.Run("unit not installed", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.unit = "LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\n"
		if _, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true}); err == nil || !strings.Contains(err.Error(), "not installed") {
			t.Fatalf("Plan = %v", err)
		}
	})
	t.Run("gateway.toml named in gateway.env", func(t *testing.T) {
		f := newGatewayFixture(t)
		alt := filepath.Join(realTempDir(t), "alt.toml")
		f.write(t, "gateway.env", "OPENSHELL_GATEWAY_CONFIG="+alt+"\n")
		if plan, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true}); err != nil || plan.Files[0].Path != alt {
			t.Fatalf("Plan = %+v, %v", plan, err)
		}
	})
	t.Run("Homebrew has no gateway.env to check", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.cfg.GOOS = "darwin"
		f.unit, f.manager = "garbage", "garbage"
		if _, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true}); err != nil {
			t.Fatalf("Plan = %v", err)
		}
		if f.runner.Called("systemctl") {
			t.Fatal("asked systemd about a Homebrew service")
		}
	})
}

// TestGatewayConfigRecordsPendingRestart covers a restart that never
// happens after the files were written: the pending mark stays until a
// restart succeeds, on every platform.
func TestGatewayConfigRecordsPendingRestart(t *testing.T) {
	f := newGatewayFixture(t)
	f.write(t, "gateway.toml", operatorTOML)
	f.runner.On("systemctl --user restart openshell-gateway", "Job failed", errors.New("exit status 1"))
	plan, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.cfg.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "did not come back") {
		t.Fatalf("Apply = %v", err)
	}
	st, err := f.cfg.Read()
	if err != nil || st.RestartPendingSince.IsZero() {
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
	plan, _ = f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true})
	for i := 0; i < 100; i++ {
		name := "gateway.toml.defenseclaw-20260926T190000Z.bak"
		if i > 0 {
			name = fmt.Sprintf("gateway.toml.defenseclaw-20260926T190000Z-%d.bak", i)
		}
		f.write(t, name, "taken")
	}
	if _, err := f.cfg.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "too many backups") {
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
	if err != nil {
		t.Fatalf("Read = %v", err)
	}
	if st.TOMLPath != filepath.Join(f.dir, "gateway.toml") || st.EnvPath != filepath.Join(f.dir, "gateway.env") || !st.TOMLExists || !st.EnvExists || f.cfg.Dir != f.dir {
		t.Fatalf("state = %+v (dir %s)", st, f.cfg.Dir)
	}
	plan, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true, Env: map[string]string{openshell.EnvTelemetryEnabled: "false"}})
	if err != nil {
		t.Fatalf("Plan = %v", err)
	}
	if len(plan.Files) != 2 || plan.Files[0].Path != st.TOMLPath || plan.Files[1].Path != st.EnvPath {
		t.Fatalf("plan = %s", plan)
	}
	res, err := f.cfg.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply = %v", err)
	}
	if got := f.backups(t); len(got) != 2 || len(f.preflighted) != 1 {
		t.Fatalf("backups %v, preflights %d", got, len(f.preflighted))
	}
	if st, err := f.cfg.Read(); err != nil || !st.BindMounts.Enabled() || st.TelemetryEnabled() {
		t.Fatalf("applied state = %+v, %v", st, err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was replaced: %v, %v", info, err)
	}
	if err := f.cfg.Rollback(context.Background(), res); err != nil {
		t.Fatalf("Rollback = %v", err)
	}
	if f.read(t, "gateway.toml") != operatorTOML || f.read(t, "gateway.env") != "OPENSHELL_LOG=info\n" {
		t.Fatal("rollback did not restore the files")
	}
}

func TestGatewayConfigPathFromEnv(t *testing.T) {
	f := newGatewayFixture(t)
	alt := filepath.Join(realTempDir(t), "alt.toml")
	if err := os.WriteFile(alt, []byte("[openshell]\nversion = 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.write(t, "gateway.env", "OPENSHELL_GATEWAY_CONFIG="+alt+"\n")
	if p, err := f.cfg.TOMLPath(); err != nil || p != alt {
		t.Fatalf("TOMLPath = %q, %v", p, err)
	}
	plan, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true})
	if err != nil || len(plan.Files) != 1 || plan.Files[0].Path != alt {
		t.Fatalf("plan = %+v, %v", plan, err)
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
		if err != nil {
			t.Fatal(err)
		}
		// systemd reports the start to the microsecond.
		if !st.Installed || !st.Active || !st.Enabled || st.Status != "active (running)" ||
			!st.StartedAt.Equal(time.Date(2026, 9, 26, 16, 18, 34, 451059000, time.UTC)) {
			t.Fatalf("state = %+v", st)
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
			st, err := f.cfg.ServiceState(context.Background())
			if err != nil || st.Enabled || !st.Active {
				t.Fatalf("UnitFileState=%s: state = %+v, %v", state, st, err)
			}
		}
	})
	t.Run("systemd unit missing", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.runner.On("systemctl --user show openshell-gateway", "LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\nActiveEnterTimestamp=\n", nil)
		st, err := f.cfg.ServiceState(context.Background())
		if err != nil || st.Installed || st.Active || !st.StartedAt.IsZero() {
			t.Fatalf("state = %+v, %v", st, err)
		}
	})
	t.Run("homebrew", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.cfg.GOOS = "darwin"
		f.runner.On("brew services info nvidia/openshell/openshell --json", `[{"name":"openshell","running":true,"loaded":true,"status":"started","file":"/Users/u/Library/LaunchAgents/homebrew.mxcl.openshell.plist"}]`, nil)
		f.runner.On("brew services restart nvidia/openshell/openshell", "", nil)
		st, err := f.cfg.ServiceState(context.Background())
		if err != nil || !st.Active || !st.Installed || st.Manager != "brew" {
			t.Fatalf("state = %+v, %v", st, err)
		}
		if err := f.cfg.Restart(context.Background()); err != nil || !f.runner.Called("brew services restart nvidia/openshell/openshell") {
			t.Fatalf("restart: %v", err)
		}
	})
}

func TestGatewayTelemetrySetting(t *testing.T) {
	for value, enabled := range map[string]bool{"false": false, "0": false, "true": true, "garbage": true} {
		st := &openshell.GatewayConfigState{Env: map[string]string{openshell.EnvTelemetryEnabled: value}}
		if st.TelemetryEnabled() != enabled {
			t.Errorf("%s=%s: enabled = %v", openshell.EnvTelemetryEnabled, value, !enabled)
		}
	}
}
