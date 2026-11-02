// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// rel-1-0-6 GAP-0340 (the GAP-0186 class): OpenShell's own "Conflict: ..."
// text reached the person on a stop of a MicroVM it was still bringing up
// and on the disk sync before a stop. Both now say what happened and what to
// do, and keep none of OpenShell's words.
func TestStopAndSyncConflictsReadInDefenseClawWords(t *testing.T) {
	stop := upstream("stop sandbox vs9-vm2", errors.New(
		`openshell: stop sandbox "vs9-vm2": Conflict: sandbox must be Ready, Error, or in an automatic restart to stop (current phase: Provisioning)`))
	var e *sandboxapi.Error
	if !errors.As(stop, &e) || e.Code != sandboxapi.CodeConflict {
		t.Fatalf("stop refusal = %#v", stop)
	}
	text := e.Error()
	for _, want := range []string{"sandbox vs9-vm2 was not stopped", "OpenShell is still bringing it up (phase: provisioning)",
		"`defenseclaw sandbox list` shows it Ready", "stop it again", "`defenseclaw sandbox doctor`"} {
		if !strings.Contains(text, want) {
			t.Fatalf("stop refusal %q lacks %q", text, want)
		}
	}
	rawSync := errors.New(`openshell: exec "/bin/sync" in "vs9-vm2": Conflict: sandbox is not ready`)
	for name, err := range map[string]error{
		"unsynced stop":  unsyncedStopRefusal("vs9-vm2", rawSync),
		"contained stop": containedStopRefusal("vs9-vm2", rawSync, nil),
		"exec step":      upstream("exec in sandbox vs9-vm2", rawSync),
	} {
		if !errors.As(err, &e) {
			t.Fatalf("%s: %T", name, err)
		}
		msg := e.Error()
		if !strings.Contains(strings.ToLower(msg), "bringing") || !strings.Contains(msg, "defenseclaw sandbox list") {
			t.Fatalf("%s: %q does not say what to do", name, msg)
		}
	}
	for _, err := range []error{stop, unsyncedStopRefusal("vs9-vm2", rawSync), upstream("exec in sandbox vs9-vm2", rawSync)} {
		errors.As(err, &e)
		for _, raw := range []string{"Conflict", "conflict:", "openshell:", "OpenShell: stop sandbox", "must be Ready, Error"} {
			if strings.Contains(e.Error(), raw) {
				t.Fatalf("raw OpenShell text %q reached the person: %q", raw, e.Error())
			}
		}
	}
	// Any other error keeps its words and its code.
	other := upstream("stop sandbox vs9-vm2", errors.New("openshell: stop sandbox: disk quota exceeded"))
	if !errors.As(other, &e) || e.Code != sandboxapi.CodeUpstream || !strings.Contains(e.Error(), "disk quota exceeded") {
		t.Fatalf("another error was changed: %#v", other)
	}
}

// rel-1-0-6:GAP-0446 (review round 2): OpenShell holds the same "previous
// driver operation" claim during every healthy create or start, so its
// refusal first reads as "still finishing, retry", with nothing destructive
// and none of OpenShell's words, on start, stop and delete alike.
func TestPendingDriverOperationFirstSaysStillFinishingAndRetry(t *testing.T) {
	for op, raw := range map[string]string{
		"delete sandbox vs10c-x":            `openshell: delete sandbox "vs10c-x": Conflict: previous driver operation is still pending; retry and deletion are blocked`,
		"start sandbox vs10c-x":             `openshell: start sandbox "vs10c-x": Conflict: previous driver operation may still complete; retry and deletion are blocked`,
		"stop sandbox vs10c-x":              `openshell: stop sandbox "vs10c-x": FailedPrecondition: previous driver operation is still pending; retry and deletion are blocked`,
		"wait for sandbox vs10c-x deletion": `openshell: wait: FailedPrecondition: previous driver operation may still complete; retry and deletion are blocked`,
	} {
		var e *sandboxapi.Error
		if err := upstream(op, errors.New(raw)); !errors.As(err, &e) || e.Code != sandboxapi.CodeConflict {
			t.Fatalf("%s: refusal = %#v", op, err)
		}
		text := e.Error()
		for _, want := range []string{"sandbox vs10c-x is busy", "OpenShell is still finishing a create or start",
			"wait a minute and run the command again", "`defenseclaw sandbox list`", "after a few minutes"} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s: %q lacks %q", op, text, want)
			}
		}
		for _, never := range []string{"Conflict", "FailedPrecondition", "openshell:", "retry and deletion are blocked",
			"openshell.db", "systemctl", "docker rm", "is stuck"} {
			if strings.Contains(text, never) {
				t.Fatalf("%s: %q must not say %q while OpenShell may still finish", op, text, never)
			}
		}
	}
}

// The delete gives the recovery only once the operation is provably stuck:
// OpenShell kept the sandbox in its error state and refused it for
// pendingStuckAfter as this daemon saw. A provisioning or starting sandbox
// (a slow image pull) never gets it, however long it takes, and the
// database move comes last, with what it loses. A managed account gets its
// administrator only.
func TestPendingDriverOperationRecoveryOnlyWhenProvablyStuck(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	m := &Manager{now: func() time.Time { return now }}
	text := func(phase openshell.SandboxPhase, managed bool) string {
		var e *sandboxapi.Error
		if err := m.pendingRefusal("vs10c-x", phase, managed); !errors.As(err, &e) || e.Code != sandboxapi.CodeConflict {
			t.Fatalf("refusal = %#v", err)
		}
		return e.Error()
	}
	for i := 0; i < 4; i++ {
		if got := text(openshell.PhaseProvisioning, false); !strings.Contains(got, "is busy") || strings.Contains(got, "openshell.db") {
			t.Fatalf("provisioning after %d min: %q", i*5, got)
		}
		now = now.Add(5 * time.Minute)
	}
	if got := text(openshell.PhaseError, false); !strings.Contains(got, "is busy") {
		t.Fatalf("first refusal in error: %q", got)
	}
	now = now.Add(pendingStuckAfter - time.Second)
	if got := text(openshell.PhaseError, false); !strings.Contains(got, "is busy") {
		t.Fatalf("just under the bound: %q", got)
	}
	now = now.Add(time.Second)
	stuck := text(openshell.PhaseError, false)
	for _, want := range []string{"sandbox vs10c-x is stuck", "for 3 minutes OpenShell has kept it in its error state",
		"never finished", "Last resort", "loses OpenShell's record of every sandbox on this gateway",
		"systemctl --user stop openshell-gateway", "openshell.db-wal", "`docker ps -a --filter name=--vs10c-x-`",
		"`defenseclaw sandbox delete vs10c-x`"} {
		if !strings.Contains(stuck, want) {
			t.Fatalf("stuck refusal %q lacks %q", stuck, want)
		}
	}
	if strings.Index(stuck, "Last resort") > strings.Index(stuck, "openshell.db") ||
		strings.Index(stuck, "pull or delete your other sandboxes") > strings.Index(stuck, "openshell.db") {
		t.Fatalf("the database move is not the last resort: %q", stuck)
	}
	managed := text(openshell.PhaseError, true)
	if !strings.Contains(managed, "is stuck") || !strings.Contains(managed, "help desk") ||
		strings.Contains(managed, "systemctl") || strings.Contains(managed, "openshell.db") || strings.Contains(managed, "docker") {
		t.Fatalf("managed stuck refusal = %q, want the administrator only", managed)
	}
	// Leaving the error state starts the count over.
	_ = text(openshell.PhaseStarting, false)
	if got := text(openshell.PhaseError, false); !strings.Contains(got, "is busy") {
		t.Fatalf("after a phase change: %q", got)
	}
	m.forgetPending("vs10c-x")
	if got := text(openshell.PhaseError, false); !strings.Contains(got, "is busy") {
		t.Fatalf("after a delete: %q", got)
	}
}
