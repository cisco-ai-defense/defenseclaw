// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"strings"
	"testing"
)

const testWarning = "this agent signs in to a vendor account; the token is kept in every snapshot"

// GAP-0151: the relay's warning stays on the launcher's row, where a
// full-screen agent cannot draw, while no ask is shown; an ask wins the row.
func TestWarningStaysOnTheLaunchersRow(t *testing.T) {
	r := newUIRig()
	r.u.setNotice("DefenseClaw warning: " + testWarning)
	if got := r.row(); !strings.HasPrefix(got, "DefenseClaw warning: this agent signs in") {
		t.Fatalf("row %q, want the warning", got)
	}
	r.u.update([]Ask{myAsk("k1")})
	if got := r.row(); strings.Contains(got, "DefenseClaw warning") || !strings.Contains(got, "k1") {
		t.Fatalf("row with an ask pending: %q", got)
	}
	r.u.update(nil)
	if got := r.row(); !strings.HasPrefix(got, "DefenseClaw warning: ") {
		t.Fatalf("row after the ask: %q", got)
	}
}

// GAP-0151: the warning of the relay's hello is printed again when the
// terminal is the person's after the attachment.
func TestRelayWarningIsShownAfterTheAttachment(t *testing.T) {
	r := newRig(t, nil)
	r.relay.warning = testWarning
	run := r.start(r.options())
	waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	r.typ("\x1d")
	got := r.wait(run)
	if got.err != nil || !got.res.Detached {
		t.Fatalf("%+v %v", got.res, got.err)
	}
	if !strings.Contains(r.errb.String(), "Warning: "+testWarning) {
		t.Fatalf("no warning after the attachment: %q", r.errb.String())
	}
}

// A relay without a warning adds no line.
func TestNoRelayWarningNoLine(t *testing.T) {
	r := newRig(t, nil)
	run := r.start(r.options())
	waitFor(t, "screen 1", func() bool { return strings.Contains(r.out.String(), "screen:1") })
	r.typ("\x1d")
	r.wait(run)
	if strings.Contains(r.errb.String(), "Warning:") {
		t.Fatalf("a warning line with no warning: %q", r.errb.String())
	}
}
