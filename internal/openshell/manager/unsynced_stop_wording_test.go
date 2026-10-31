// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// GAP-0186: the OpenShell gateway lost while a stop synced the MicroVM's
// disk put gRPC's own text in the refusal the person reads; it now says the
// connection to the gateway closed and how to go on, and any other sync
// failure keeps its words.
func TestUnsyncedStopRefusalWordsALostGateway(t *testing.T) {
	lost := errors.New("openshell: exec /bin/sync in sx1: Cancelled: grpc: the client connection is closing")
	other := errors.New("openshell: exec /bin/sync in sx1: exit status 1: sync: I/O error")
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"stop", unsyncedStopRefusal("sx1", lost)},
		{"contained stop", containedStopRefusal("sx1", lost, nil)},
	} {
		var e *sandboxapi.Error
		if !errors.As(tc.err, &e) {
			t.Fatalf("%s: %T", tc.name, tc.err)
		}
		if !strings.Contains(e.Message, "the connection to the OpenShell gateway closed; `defenseclaw sandbox doctor` checks it") {
			t.Fatalf("%s: message %q lacks the managed wording", tc.name, e.Message)
		}
		if strings.Contains(strings.ToLower(e.Message), "grpc") || strings.Contains(e.Message, "client connection is closing") {
			t.Fatalf("%s: raw gRPC text reached the person: %q", tc.name, e.Message)
		}
		if e.Code != sandboxapi.CodeUnsynced {
			t.Fatalf("%s: code %q", tc.name, e.Code)
		}
	}
	var e *sandboxapi.Error
	if !errors.As(unsyncedStopRefusal("sx1", other), &e) || !strings.Contains(e.Message, "sync: I/O error") {
		t.Fatalf("another sync failure lost its words: %v", e)
	}
}
