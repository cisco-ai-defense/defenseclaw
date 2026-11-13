// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"testing"
)

// GAP-0157 residual: only the alerts of a refused client certificate say the
// router refused the gateway's identity; any other remote TLS alert keeps its
// own error.
func TestRouterTLSRefusalNamesOnlyIdentityAlerts(t *testing.T) {
	for alert, identity := range map[string]bool{
		"remote error: tls: bad certificate":                true,
		"remote error: tls: certificate required":           true,
		"remote error: tls: access denied":                  true,
		"remote error: tls: unknown certificate":            true,
		"remote error: tls: protocol version not supported": false,
		"remote error: tls: internal error":                 false,
		"remote error: tls: handshake failure":              false,
	} {
		err := errors.New(alert)
		got := routerTLSRefusal(err)
		if is := errors.Is(got, errRouterRefusedIdentity); is != identity {
			t.Errorf("%q: identity refusal = %v, want %v", alert, is, identity)
		}
		if !identity && got != err {
			t.Errorf("%q changed to %v", alert, got)
		}
	}
	if routerTLSRefusal(nil) != nil {
		t.Error("nil became an error")
	}
}
