// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestCascadeLaneHotReloadEveryLane (s7-nscfg): for every registered lane, a
// hot reload to a value the lane refuses fails, keeps the last good config and
// the lane its last value; a good value applies. Readers run beside the
// reloads so the -race build checks the swap.
func TestCascadeLaneHotReloadEveryLane(t *testing.T) {
	cases := map[string]struct {
		start, startMode string
		bad              []string
		good, goodMode   string
	}{
		"effects":     {"Off", "off", []string{"on", "ON", "\"\"", "garbage", "1", "true", "null"}, "\" Shadow \"", "shadow"},
		"secret_flow": {"Off", "off", []string{"on", "ON", "\"\"", "garbage", "1", "true", "null"}, "Shadow", "shadow"},
		"nonshell":    {"Shadow", "shadow", []string{"\"\"", "garbage", "1", "true", "null", "yes"}, "ON", "on"},
	}
	for _, lane := range config.CascadeLaneNames() {
		c, ok := cases[lane]
		if !ok {
			t.Fatalf("lane %s has no reload case", lane)
		}
		t.Run(lane, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", dir)
			path := filepath.Join(dir, config.DefaultConfigName)
			write := func(v string) {
				raw := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  mode: observe\n  cascade:\n    lanes:\n      " + lane + ": " + v + "\nobservability: {}\n"
				if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			mode := func(cfg *config.Config) string {
				l := cfg.Guardrail.Cascade.Lanes
				switch lane {
				case "effects":
					return l.EffectsMode()
				case "secret_flow":
					return l.SecretFlowMode()
				}
				return l.NonShellMode()
			}
			write(c.start)
			initial, err := config.LoadRuntimeV8File(path)
			if err != nil {
				t.Fatalf("initial %s: %v", c.start, err)
			}
			var applied atomic.Int32
			mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
				applied.Add(1)
				return nil
			})
			stop := make(chan struct{})
			var wg sync.WaitGroup
			var seen sync.Map
			for range 4 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-stop:
							return
						default:
							seen.Store(mode(mgr.Current()), true)
						}
					}
				}()
			}
			for _, bad := range c.bad {
				write(bad)
				if err := mgr.Reload(context.Background(), "test"); err == nil {
					t.Errorf("%s=%s: reload accepted", lane, bad)
				}
				if got := mode(mgr.Current()); got != c.startMode {
					t.Errorf("%s=%s: after a refused reload lane = %q, want %q (last good)", lane, bad, got, c.startMode)
				}
			}
			if n := applied.Load(); n != 0 {
				t.Errorf("apply ran %d times for refused configs", n)
			}
			write(c.good)
			if err := mgr.Reload(context.Background(), "test"); err != nil {
				t.Fatalf("reload %s: %v", c.good, err)
			}
			close(stop)
			wg.Wait()
			if got := mode(mgr.Current()); got != c.goodMode {
				t.Errorf("after reload %s lane = %q, want %q", c.good, got, c.goodMode)
			}
			if applied.Load() != 1 {
				t.Errorf("apply ran %d times, want 1", applied.Load())
			}
			seen.Range(func(k, _ any) bool {
				if m := k.(string); m != c.startMode && m != c.goodMode {
					t.Errorf("a reader saw lane %q, only %q or %q are valid", m, c.startMode, c.goodMode)
				}
				return true
			})
		})
	}
}

// TestNonShellLaneInertOnManagedEnterprise (s7-nscfg): a managed enterprise
// install never runs the non-shell lane, whatever guardrail.cascade.lanes.nonshell
// says (no admin lock is needed: no value turns it on there). The same request
// with the lane on is live outside managed mode.
func TestNonShellLaneInertOnManagedEnterprise(t *testing.T) {
	req := nonShellReq("mcp__acme__read_file", `{"path":"/home/u/.ssh/id_rsa"}`, true)
	shell, _ := json.Marshal(map[string]string{"command": "vault token lookup"})
	shellReq := nonShellReq("Bash", string(shell), true)
	if len(nonShellToolFindings(nonShellLaneCtx("on"), req, nil, "")) == 0 {
		t.Fatal("outside managed mode the lane is live")
	}
	withManagedEnterprise(t, true)
	for _, mode := range []string{"", "on", "ON", "shadow", "off"} {
		ctx := nonShellLaneCtx(mode)
		if got := nonShellToolFindings(ctx, req, nil, ""); len(got) != 0 {
			t.Errorf("managed, lane %q: MCP lane added %+v", mode, got)
		}
		if got := shellToolFindings(ctx, shellReq, nil); len(got) != 0 {
			t.Errorf("managed, lane %q: shell table added %+v", mode, got)
		}
	}
}
