// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestJudgeBodiesReadyWaitsForV8Authority(t *testing.T) {
	t.Run("emits once after canonical binding", func(t *testing.T) {
		fixture := newSidecarV8BootstrapFixture(t, 8, "")
		fixture.sidecar.judgeBodiesReadyPending = deferJudgeBodiesReady(fixture.logger)
		fixture.sidecar.judgeBodiesReadyDetails = "path=/private/private-must-not-escape.db"
		if events, err := fixture.store.ListEvents(10); err != nil || len(events) != 0 {
			t.Fatalf("v8 readiness escaped before binding: %#v err=%v", events, err)
		}
		if err := fixture.sidecar.EmitPostBootstrapPlatformHealth(); err == nil {
			t.Fatal("unbound v8 readiness unexpectedly succeeded")
		}
		bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
			t.Context(), fixture.configPath, fixture.raw,
		)
		if err != nil || !bound {
			t.Fatalf("bootstrap bound=%t err=%v", bound, err)
		}
		if err := fixture.sidecar.EmitPostBootstrapPlatformHealth(); err != nil {
			t.Fatal(err)
		}
		if err := fixture.sidecar.EmitPostBootstrapPlatformHealth(); err != nil {
			t.Fatalf("idempotent post-bootstrap readiness: %v", err)
		}
		count, mandatory, leaked := platformHealthRows(
			t, fixture.store.DatabasePath(), string(audit.ActionGatewayJudgeBodiesReady), "subsystem.ready",
		)
		if count != 1 || mandatory != 1 || leaked != 1 {
			t.Fatalf("canonical default-unredacted readiness count=%d mandatory=%d source=%d", count, mandatory, leaked)
		}
		if legacy := legacyPlatformHealthRows(
			t, fixture.store.DatabasePath(), string(audit.ActionGatewayJudgeBodiesReady),
		); legacy != 0 {
			t.Fatalf("v8 readiness legacy rows=%d", legacy)
		}
	})
}

func TestJudgeTerminalHealthEmitsBeforeOwnedRuntimeRetires(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, fixture.raw,
	)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t err=%v", bound, err)
	}
	for _, action := range []audit.Action{
		audit.ActionGatewayJudgeStoreDrainTimeout,
		audit.ActionGatewayJudgeBodiesCloseError,
	} {
		if err := fixture.logger.LogEvent(audit.Event{
			Action: string(action), Actor: "defenseclaw-gateway",
			Severity: "ERROR", Details: "error=private-must-not-escape",
		}); err != nil {
			t.Fatalf("emit %s before retirement: %v", action, err)
		}
		count, mandatory, leaked := platformHealthRows(
			t, fixture.store.DatabasePath(), string(action), "subsystem.degraded",
		)
		wantMandatory := 0
		if action == audit.ActionGatewayJudgeBodiesCloseError {
			wantMandatory = 1
		}
		if count != 1 || mandatory != wantMandatory || leaked != 1 {
			t.Fatalf("%s default-unredacted count=%d mandatory=%d source=%d", action, count, mandatory, leaked)
		}
		if legacy := legacyPlatformHealthRows(t, fixture.store.DatabasePath(), string(action)); legacy != 0 {
			t.Fatalf("%s legacy rows=%d", action, legacy)
		}
	}
	if err := fixture.sidecar.closeOwnedObservabilityV8Runtime(); err != nil {
		t.Fatal(err)
	}
	if !fixture.store.Ready() || fixture.sidecar.observabilityV8Emitter() != nil {
		t.Fatalf("retirement emitter=%T store-ready=%t", fixture.sidecar.observabilityV8Emitter(), fixture.store.Ready())
	}
	if err := fixture.logger.LogEvent(audit.Event{
		Action: string(audit.ActionGatewayJudgeStoreDrainTimeout), Severity: "ERROR",
	}); err == nil {
		t.Fatal("post-retirement platform health resurrected a legacy write")
	}
	count, _, _ := platformHealthRows(
		t, fixture.store.DatabasePath(), string(audit.ActionGatewayJudgeStoreDrainTimeout), "subsystem.degraded",
	)
	if count != 1 {
		t.Fatalf("post-retirement row count=%d, want 1", count)
	}
}

func platformHealthRows(t *testing.T, path, action, eventName string) (count, mandatory, leaked int) {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	err = database.QueryRowContext(context.Background(), `
		SELECT COUNT(*), COALESCE(MAX(mandatory), 0),
		       COALESCE(SUM(CASE WHEN projected_record_json LIKE '%private-must-not-escape%' THEN 1 ELSE 0 END), 0)
		FROM audit_events
		WHERE bucket = 'platform.health' AND action = ? AND event_name = ?`, action, eventName,
	).Scan(&count, &mandatory, &leaked)
	if err != nil {
		t.Fatal(err)
	}
	return count, mandatory, leaked
}

func legacyPlatformHealthRows(t *testing.T, path, action string) (count int) {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	if err := database.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM audit_events
		WHERE action = ? AND (bucket IS NULL OR bucket = '')`, action,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
