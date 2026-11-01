// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"errors"
	"strings"
	"testing"

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

// rel-1-0-6:GAP-0446: a sandbox whose OpenShell gateway was killed in the
// middle of a create or start keeps a driver claim OpenShell never settles,
// and every start, stop and delete of it was refused with OpenShell's raw
// "Conflict: previous driver operation is still pending" text. The refusal
// now says the sandbox is stuck and does not run, and gives the step that
// clears it, in DefenseClaw's words.
func TestPendingDriverOperationReadsAsAStuckSandboxWithItsClearStep(t *testing.T) {
	for op, raw := range map[string]string{
		"delete sandbox vs10c-x": `openshell: delete sandbox "vs10c-x": Conflict: previous driver operation is still pending; retry and deletion are blocked`,
		"start sandbox vs10c-x":  `openshell: start sandbox "vs10c-x": Conflict: previous driver operation may still complete; retry and deletion are blocked`,
		"stop sandbox vs10c-x":   `openshell: stop sandbox "vs10c-x": FailedPrecondition: previous driver operation is still pending; retry and deletion are blocked`,
	} {
		var e *sandboxapi.Error
		if err := upstream(op, errors.New(raw)); !errors.As(err, &e) || e.Code != sandboxapi.CodeConflict {
			t.Fatalf("%s: refusal = %#v", op, err)
		}
		text := e.Error()
		for _, want := range []string{
			"sandbox vs10c-x is stuck", "DefenseClaw cannot run anything in it", "systemctl --user stop openshell-gateway",
			"~/.local/state/openshell/gateway/openshell.db", "openshell.db-wal", "systemctl --user start openshell-gateway",
			"`docker ps -a --filter name=--vs10c-x-`", "`docker rm -f`",
			"`defenseclaw sandbox delete vs10c-x`", "forget every sandbox", "administrator",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s: %q lacks %q", op, text, want)
			}
		}
		for _, leak := range []string{"Conflict", "FailedPrecondition", "openshell:", "OpenShell: delete sandbox", "retry and deletion are blocked"} {
			if strings.Contains(text, leak) {
				t.Fatalf("%s: raw OpenShell text %q reached the person: %q", op, leak, text)
			}
		}
	}
}
