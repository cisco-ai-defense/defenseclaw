// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

func TestConfigManagerRejectedCandidateIsInDurableAudit(t *testing.T) {
	for _, reason := range []string{"schema", "pinned-pack", "runtime-graph", "shutdown"} {
		t.Run(reason, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			raw := "config_version: 9\ndata_dir: " + dir + "\nguardrail: {mode: observe}\n"
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			initial, err := config.LoadRuntimeV8File(path)
			if err != nil {
				t.Fatal(err)
			}
			runtime, capture := newProxyGeneratedRuntimeWithPolicies(t, "always_on", config.ObservabilityV8BucketPolicySource{}, nil, true,
				func(store *audit.Store, engine *redaction.Engine) runtimegraph.Reporter {
					reporter, err := observabilityruntime.NewReloadReporter(store, engine, nil, "reload-rejection-test", "test")
					if err != nil {
						t.Fatal(err)
					}
					return reporter
				})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
				if reason == "runtime-graph" {
					candidate := runtimegraph.ConfigFromPlan(runtime.Active().Plan(), false)
					candidate.PlanDigest = "invalid"
					_, graphErr := runtime.Reload(ctx, candidate)
					if graphErr == nil {
						t.Fatal("invalid graph accepted")
					}
					return fmt.Errorf("graph refused: %w", graphErr)
				}
				if reason == "shutdown" {
					cancel()
					return ctx.Err()
				}
				return errors.New("pinned pack digest mismatch: private-canary")
			})
			mgr.bindObservabilityV8(runtime)
			active, generation := mgr.Current(), mgr.gen.Load()
			candidate := strings.Replace(raw, "mode: observe", "mode: action", 1)
			if reason == "schema" {
				candidate = strings.Replace(candidate, "mode: action", "mode: action, block_at: SUPER", 1)
			}
			if err := os.WriteFile(path, []byte(candidate), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := mgr.Reload(ctx, "test"); err == nil {
				t.Fatal("invalid candidate accepted")
			}
			if !reflect.DeepEqual(mgr.Current(), active) || mgr.gen.Load() != generation {
				t.Fatal("rejection replaced the active policy")
			}
			if err := runtime.FlushReports(t.Context()); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", capture.store.DatabasePath())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var count int
			want := 1
			if reason == "shutdown" {
				want = 0
			}
			if err := db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE event_name = 'config.reload.rejected'").Scan(&count); err != nil || count != want {
				t.Fatalf("durable config.reload.rejected rows = %d, %v", count, err)
			}
		})
	}
}
