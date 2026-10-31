// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// GAP-2437: a gateway killed under a MicroVM stop on macOS leaves the
// sandbox's supervisor owned by the gateway that replaced it, and the sync
// fails with OpenShell's relay text. The refusal the person reads words that
// as a lost gateway, with the way on, instead of OpenShell's own text.
func TestUnsyncedStopRefusalWordsARelayFailureAfterGatewayLoss(t *testing.T) {
	relay := errors.New(`openshell: exec "/bin/sync" in "sx1": Unavailable: supervisor relay failed: ` +
		`code: 'The system is not in a state required for the operation's execution', message: "sandbox is owned by gateway replica"`)
	for name, err := range map[string]error{
		"stop":           unsyncedStopRefusal("sx1", relay),
		"contained stop": containedStopRefusal("sx1", relay, nil),
	} {
		var e *sandboxapi.Error
		if !errors.As(err, &e) {
			t.Fatalf("%s: %T", name, err)
		}
		if !strings.Contains(e.Message, "the connection to the OpenShell gateway closed; `defenseclaw sandbox doctor` checks it") {
			t.Fatalf("%s: message %q lacks the managed wording", name, e.Message)
		}
		for _, raw := range []string{"supervisor relay", "owned by gateway", "code:", "Unavailable"} {
			if strings.Contains(e.Message, raw) {
				t.Fatalf("%s: OpenShell text %q reached the person: %q", name, raw, e.Message)
			}
		}
		if e.Code != sandboxapi.CodeUnsynced {
			t.Fatalf("%s: code %q", name, e.Code)
		}
	}
}
