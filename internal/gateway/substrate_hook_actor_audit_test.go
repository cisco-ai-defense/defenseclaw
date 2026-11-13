// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-0121: the audit row of a hook whose additive check panicked (result
// panic) carries the verified actor, the run mode and the person like every
// other hook row. A regression guard: the row is written from
// hookRequestAuditExtra, which the recovered-panic finalization shares with
// the normal one.
func TestSubstratePanicHookRowCarriesTheVerifiedActorGAP0121(t *testing.T) {
	injectHealthyAllowForProfile(t, "claudecode")
	injectStagePanic(t, everyCallAt("chain"))
	store, logger := testStoreAndLogger(t)
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode, cfg.Guardrail.Connector = "action", "closed", "claudecode"
	server := &APIServer{scannerCfg: cfg, store: store, logger: logger}

	key, err := sandboxreg.SubstrateKey("eng-web", subUID2)
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.Registration{Key: key, Atespace: "eng-web", Name: "bob-1", UID: subUID2, Connector: "claudecode",
		Template: "eng-web/claude", Unattended: true, Person: ownerOf(bob)}
	ctx := withSubstrateActor(context.Background(), verifiedSubstrateActor("eng-web", "bob-1", subUID2, "actor/eng-web/bob-1", key))
	ctx = context.WithValue(ctx, substrateRegistrationKey{}, reg)

	const session = "gap0121-panic"
	payload, _ := panicTestPayload("claudecode", "PreToolUse", t.TempDir())
	payload["session_id"] = session
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handleAgentHook("claudecode").ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	row := newestHookDecision(t, store, session)
	if row.Structured["result"] != "panic" {
		t.Fatalf("result = %v, want the recovered-panic row; row=%+v", row.Structured["result"], row.Structured)
	}
	seen := row.Details + fmt.Sprint(row.Structured)
	for _, want := range []string{subUID2, "eng-web", "bob-1", "unattended"} {
		if !strings.Contains(seen, want) {
			t.Errorf("the panic row of a Substrate actor does not carry %q: %s", want, seen)
		}
	}
}

// A verified actor whose registration is not on the request still names
// itself on the row from what the gateway verified (atespace, name, UID); the
// person and run mode come only from the registration.
func TestSubstrateHookAuditExtraFromTheVerifiedActorAloneGAP0121(t *testing.T) {
	key, err := sandboxreg.SubstrateKey("eng-web", subUID2)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withSubstrateActor(context.Background(), verifiedSubstrateActor("eng-web", "bob-1", subUID2, "actor/eng-web/bob-1", key))
	extra := substrateHookAuditExtra(ctx)
	for k, want := range map[string]string{"sandbox_runtime": "substrate", "substrate_atespace": "eng-web",
		"substrate_actor": "bob-1", "substrate_actor_uid": subUID2} {
		if extra[k] != want {
			t.Errorf("%s = %q, want %q", k, extra[k], want)
		}
	}
	if _, ok := extra["substrate_run_mode"]; ok {
		t.Error("a run mode without a registration")
	}
	// An actor the verifier did not seal adds nothing.
	unsealed := context.WithValue(context.Background(), substrateActorKey{}, substrateActor{Atespace: "eng-web", Name: "bob-1", UID: subUID2})
	if substrateHookAuditExtra(unsealed) != nil {
		t.Fatal("an unsealed actor named itself on the row")
	}
}
