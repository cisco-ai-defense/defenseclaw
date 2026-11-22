// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// waitHookCapacity waits for the finalization of the calls served so far to
// reach the counter.
func waitHookCapacity(t *testing.T, want HookCapacityCounts) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := hookCapacity.snapshot().Window
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("window = %+v, want %+v", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The wiring through the hook handler and finalization on a managed host in
// the default closed mode (S8 review P3-1): an acknowledged receipt is an
// answered call, a late receipt a deadline deny, an offered answer with no
// receipt nothing, and a script call whose client left a deadline deny.
func TestHookCapacityManagedFinalizeWiring(t *testing.T) {
	withHookCapacity(t, time.Now())
	f := newManagedHookAuditFixture(t, nil)
	f.offer(t, "cap-ack", hookexec.HookDeliveryReceiptAck)
	waitHookCapacity(t, HookCapacityCounts{Answered: 1})
	f.offer(t, "cap-late", hookexec.HookDeliveryReceiptLate)
	waitHookCapacity(t, HookCapacityCounts{Answered: 1, DeadlineDenies: 1})
	f.offer(t, "cap-no-receipt", "")
	serveScriptHookBody(t, f, managedHookBody("cap-left", "PreToolUse"), true)
	waitHookCapacity(t, HookCapacityCounts{Answered: 1, DeadlineDenies: 2})
	if got := f.audited(t, "cap-no-receipt")["cap-no-receipt"]; got != "unconfirmed/no_answer" {
		t.Fatalf("control: the offered call without a receipt audited %q", got)
	}
}

// A caller gone before admission counts by the fail mode, and a call the
// admission limits refuse counts once as shed however often its hook sends
// it again, with or without a tool id (S8 review P3-1, P3-5).
func TestHookCapacityCallerGoneAndShedWiring(t *testing.T) {
	withHookCapacity(t, time.Now())
	f := newManagedHookAuditFixture(t, nil)
	serveGoneOnSocket(t, f, machinePolicyAuthorizer(), goneRequest(t, managedHookBody("cap-gone", "PreToolUse"), AgentIdentity{}, nil))
	waitHookCapacity(t, HookCapacityCounts{DeadlineDenies: 1})

	f.api.hookCallerLimits = hookCallerLimiter{rate: 1, burst: 1}
	if reply := serveShedOnSocket(f, machinePolicyAuthorizer(), managedHookBody("cap-first", "PreToolUse")); reply.Code != http.StatusOK {
		t.Fatalf("the first call was refused: %d", reply.Code)
	}
	noToolID := `{"hook_event_name":"PreToolUse","session_id":"cap-noid","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"echo ok"}}`
	for attempt := 0; attempt < 3; attempt++ {
		for _, body := range []string{managedHookBody("cap-shed", "PreToolUse"), noToolID} {
			if reply := serveShedOnSocket(f, machinePolicyAuthorizer(), body); reply.Code != http.StatusTooManyRequests {
				t.Fatalf("attempt %d: status %d, want the 429 refusal", attempt, reply.Code)
			}
		}
	}
	waitHookCapacity(t, HookCapacityCounts{DeadlineDenies: 1, Shed: 2})
	if rows := shedRows(t, f, "cap-noid"); len(rows) != 3 {
		t.Fatalf("rows of the call without a tool id = %d, want one per send as before", len(rows))
	}
}

// The machine-wide hook load is for administrators (policy-privacy rule): an
// ordinary account on the managed hook socket does not get it in /health,
// root does, and /status (gateway credential) always has it. A per-user
// /health needs no credential, so it never carries it; /status does (S8
// review P3-1, P3-2).
func TestHookCapacityHealthIsAdministratorOnly(t *testing.T) {
	withHookCapacity(t, time.Now())
	hookCapacity.note(hookCapacityDeadlineDeny, time.Time{}, 1)
	get := func(handler http.HandlerFunc, ctx context.Context) string {
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx))
		return response.Body.String()
	}
	standalone := &config.Config{DeploymentMode: "managed_enterprise"}
	standalone.Enterprise.Profile = managed.ProfileStandalone
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, standalone)
	user := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1004, Name: "cap-alice"})
	root := withManagedHookPeer(context.Background(), managedHookPeer{UID: 0})
	if body := get(api.handleHealth, user); strings.Contains(body, `"hook_capacity"`) {
		t.Fatalf("an ordinary account read the hook load in /health: %s", body)
	}
	for name, body := range map[string]string{
		"managed /health as root": get(api.handleHealth, root),
		"managed /status":         get(api.handleStatus, context.Background()),
	} {
		if !strings.Contains(body, `"hook_capacity"`) || !strings.Contains(body, `"deadline_denies":1`) {
			t.Fatalf("%s lacks hook_capacity: %s", name, body)
		}
	}
	perUser := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, &config.Config{})
	if body := get(perUser.handleHealth, context.Background()); strings.Contains(body, `"hook_capacity"`) {
		t.Fatalf("per-user /health, which needs no credential, carries the hook load: %s", body)
	}
	if body := get(perUser.handleStatus, context.Background()); !strings.Contains(body, `"hook_capacity"`) {
		t.Fatalf("per-user /status lacks hook_capacity: %s", body)
	}
}
