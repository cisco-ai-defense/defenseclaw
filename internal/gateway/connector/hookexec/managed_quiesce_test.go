// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// GAP-0993: on a managed standalone host whose administrator chose open
// (outage-only), a hook call during the documented package upgrade met the
// stopped gateway service and answered the open allow: the Hermes hook let
// tool calls run while Setup replaced the release. The enterprise lifecycle
// disables every DefenseClaw service before it stops it, so a stopped
// service with its start type disabled (or unreadable) is a package
// transition, not an outage: every managed tool hook form answers it as
// fail mode closed does. An ordinary outage (start type automatic) keeps
// the administrator's open (control).
func TestManagedHookAnswersClosedWhileTheLifecycleHasQuiescedTheGateway(t *testing.T) {
	quiesced := fmt.Errorf("%w: %w: %w (state=1 pid=0 start type disabled)",
		errManagedGatewayPeerUnverified, errManagedGatewayNotRunning, errManagedGatewayQuiesced)
	outage := fmt.Errorf("%w: %w (state=1 pid=0)", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
	answer := func(t *testing.T, form nativeHookForm, failMode string, err error) (int, string, string) {
		var stdout, stderr bytes.Buffer
		opts := withDefaults(Options{
			Connector:         form.connector,
			Event:             form.event,
			HookSurface:       form.surface,
			ManagedEnterprise: true,
			ManagedStandalone: true,
			FailMode:          failMode,
			Home:              t.TempDir(),
			Stdin:             strings.NewReader(""),
			Stdout:            &stdout,
			Stderr:            &stderr,
		})
		sp, ok := specFor(form.connector)
		if !ok {
			t.Fatalf("no spec for %s", form.connector)
		}
		code := failUnreachable(withManagedOutage(opts, err), sp, managedPeerFailMode(opts, failMode, err), managedPeerFailureReason(opts, err))
		return code, stdout.String(), stderr.String()
	}
	for _, form := range nativeToolHookForms {
		t.Run(form.String(), func(t *testing.T) {
			if ManagedOutageFailsOpen(Options{ManagedEnterprise: true, FailMode: "open"}, quiesced) {
				t.Fatal("a quiesced gateway counts as an outage")
			}
			closedCode, closedOut, _ := answer(t, form, "closed", outage)
			code, stdout, stderr := answer(t, form, "open", quiesced)
			if got, want := nativeAnswerBlocks(code, stdout), nativeAnswerBlocks(closedCode, closedOut); got != want || !want {
				t.Fatalf("admin open, quiesced gateway: exit %d stdout %q stderr %q blocks=%v, want the closed answer (blocks=%v)",
					code, stdout, stderr, got, want)
			}
		})
	}
	t.Run("hermes ordinary outage keeps the administrator's open", func(t *testing.T) {
		code, stdout, stderr := answer(t, nativeHookForm{"hermes", "pre_tool_call", ""}, "open", outage)
		if nativeAnswerBlocks(code, stdout) {
			t.Fatalf("admin open, ordinary outage: exit %d stdout %q stderr %q, want the call to run", code, stdout, stderr)
		}
	})
}
