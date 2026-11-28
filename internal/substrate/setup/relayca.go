// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"fmt"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
)

// DefaultRelayCASecret is the relay CA Secret's name when the plan names
// none (chart value gateway.relayCASecret).
const DefaultRelayCASecret = "defenseclaw-relay-ca"

// The relay CA Secret's keys: the gateway signs each relay's TLS serving
// certificate with ca-key.pem (the actor listener's /relay/cert route) and
// verifies the relay against ca.pem on every attach (B3.5).
const (
	RelayCACertKey = "ca.pem"
	RelayCAKeyKey  = "ca-key.pem"
)

// EnsureRelayCA creates the relay CA Secret when it does not exist (the
// relay-session hook, pre-install and pre-upgrade). It is a key of its own,
// not the session-token key (D3-9). An existing Secret is never replaced:
// running relays hold certificates it signed. Like the session key it is
// not a release resource, so uninstall keeps it. The key is never printed.
func EnsureRelayCA(ctx context.Context, plan ChartPlan, api SecretAPI) (StepReport, error) {
	r := StepReport{Step: "relay-session"}
	name := plan.relayCASecret()
	ok, err := api.SecretExists(ctx, plan.Namespace, name)
	if err != nil {
		return r, fmt.Errorf("relay CA: %w", err)
	}
	if ok {
		r.note("the relay CA Secret %s exists; kept", name)
		return r, nil
	}
	certPEM, keyPEM, err := relaytls.GenerateCA(time.Now())
	if err != nil {
		return r, fmt.Errorf("relay CA: %w", err)
	}
	if err := api.CreateSecret(ctx, plan.Namespace, name, map[string][]byte{RelayCACertKey: certPEM, RelayCAKeyKey: keyPEM}); err != nil {
		return r, fmt.Errorf("relay CA: %w", err)
	}
	r.note("created the relay CA Secret %s (key not shown)", name)
	return r, nil
}

func (p ChartPlan) relayCASecret() string {
	if p.RelayCASecret != "" {
		return p.RelayCASecret
	}
	return DefaultRelayCASecret
}
