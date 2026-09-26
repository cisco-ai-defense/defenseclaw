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
}

func newGatewayFixture(t *testing.T) *gatewayFixture {
	t.Helper()
	skipOnWindows(t)
	f := &gatewayFixture{dir: filepath.Join(t.TempDir(), "openshell"), runner: &openshelltest.Runner{}}
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f.runner.OnFunc("openshell-gateway config preflight", func(_ context.Context, c openshell.Command) ([]byte, error) {
		data, err := os.ReadFile(c.Args[3])
		if err != nil {
			t.Errorf("preflight path unreadable: %v", err)
		}
		f.preflighted = append(f.preflighted, string(data))
		return nil, nil
	})
	f.runner.On("systemctl --user restart openshell-gateway", "", nil)
	f.cfg = &openshell.GatewayConfigurator{
		Dir:           f.dir,
		GOOS:          "linux",
		Runner:        f.runner,
		VerifyGateway: func(context.Context) error { f.verified++; return f.verify },
		Now:           func() time.Time { return time.Date(2026, 9, 26, 19, 0, 0, 0, time.UTC) },
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
	plan, err := f.cfg.Plan(openshell.GatewayChanges{EnableBindMounts: true, Env: map[string]string{openshell.EnvTelemetryEnabled: "false"}})
	if err != nil {
		t.Fatal(err)
	}
	text := plan.String()
	for _, want := range []string{"create " + filepath.Join(f.dir, "gateway.toml"), "+ enable_bind_mounts = true", "[openshell.drivers.docker.resource_admission] enabled = false",
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
	again, err := f.cfg.Plan(openshell.GatewayChanges{EnableBindMounts: true, Env: map[string]string{openshell.EnvTelemetryEnabled: "false"}})
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
	plan, err := f.cfg.Plan(openshell.GatewayChanges{EnableBindMounts: true, Env: map[string]string{openshell.EnvTelemetryEnabled: "false"}})
	if err != nil {
		t.Fatal(err)
	}
	if text := plan.String(); strings.Contains(text, "hunter2") || !strings.Contains(text, "- enable_bind_mounts = false") {
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
		plan, err := f.cfg.Plan(openshell.GatewayChanges{EnableBindMounts: true})
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
		plan, _ := f.cfg.Plan(openshell.GatewayChanges{EnableBindMounts: true})
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
		plan, _ := f.cfg.Plan(openshell.GatewayChanges{EnableBindMounts: true})
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
		if _, err := f.cfg.Plan(openshell.GatewayChanges{EnableBindMounts: true}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unsafe TOML shape", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", "[openshell]\nversion = 2\ndrivers = { docker = { enable_bind_mounts = false } }\n")
		if _, err := f.cfg.Plan(openshell.GatewayChanges{EnableBindMounts: true}); !errors.Is(err, openshell.ErrTOMLEdit) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestGatewayConfigRollback(t *testing.T) {
	t.Run("unhealthy after restart", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", operatorTOML)
		f.verify = errors.New("connection refused")
		plan, _ := f.cfg.Plan(openshell.GatewayChanges{EnableBindMounts: true, Env: map[string]string{openshell.EnvTelemetryEnabled: "false"}})
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
		plan, _ := f.cfg.Plan(openshell.GatewayChanges{EnableBindMounts: true})
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
		plan, _ := f.cfg.Plan(openshell.GatewayChanges{EnableBindMounts: true})
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

func TestGatewayConfigPathFromEnv(t *testing.T) {
	f := newGatewayFixture(t)
	alt := filepath.Join(t.TempDir(), "alt.toml")
	if err := os.WriteFile(alt, []byte("[openshell]\nversion = 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.write(t, "gateway.env", "OPENSHELL_GATEWAY_CONFIG="+alt+"\n")
	if p, err := f.cfg.TOMLPath(); err != nil || p != alt {
		t.Fatalf("TOMLPath = %q, %v", p, err)
	}
	plan, err := f.cfg.Plan(openshell.GatewayChanges{EnableBindMounts: true})
	if err != nil || len(plan.Files) != 1 || plan.Files[0].Path != alt {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
}

func TestGatewayServiceState(t *testing.T) {
	t.Run("systemd", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.runner.On("systemctl --user show openshell-gateway", "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nActiveEnterTimestamp=@1790439514\n", nil)
		st, err := f.cfg.ServiceState(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !st.Installed || !st.Active || !st.Enabled || st.Status != "active (running)" || st.StartedAt.Unix() != 1790439514 {
			t.Fatalf("state = %+v", st)
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
