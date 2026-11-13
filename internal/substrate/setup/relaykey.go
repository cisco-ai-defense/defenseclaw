// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// DefaultRelaySessionSecret is the relay session key Secret's name when the
// plan names none (chart value gateway.relaySessionSecret).
const DefaultRelaySessionSecret = "defenseclaw-relay-session"

// The relay session key Secret's keys: the gateway signs attach session
// tokens with the private half, and `template build --session-key` bakes
// the public half into every image so the relay can check them.
const (
	RelaySessionPrivateKey = "private.pem"
	RelaySessionPublicKey  = "public.pem"
)

// EnsureRelaySessionKey creates the relay session key Secret with a new
// P-256 key pair when it does not exist (the chart's pre-install and
// pre-upgrade hook). Without it the gateway signs no session token and
// nobody can attach. An existing Secret is never replaced: images built
// with its public half keep working across upgrades. Like the chain key it
// is not a release resource, so uninstall keeps it (PurgeSteps names it).
// The private key is never printed.
func EnsureRelaySessionKey(ctx context.Context, plan ChartPlan, api SecretAPI) (StepReport, error) {
	r := StepReport{Step: "relay-session"}
	name := plan.relaySessionSecret()
	ok, err := api.SecretExists(ctx, plan.Namespace, name)
	if err != nil {
		return r, fmt.Errorf("relay session key: %w", err)
	}
	if ok {
		r.note("the relay session key Secret %s exists; kept", name)
		return r, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return r, err
	}
	priv, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return r, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return r, err
	}
	if err := api.CreateSecret(ctx, plan.Namespace, name, map[string][]byte{
		RelaySessionPrivateKey: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv}),
		RelaySessionPublicKey:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}),
	}); err != nil {
		return r, fmt.Errorf("relay session key: %w", err)
	}
	r.note("created the relay session key Secret %s (private key not shown); build images with its %s: "+
		"kubectl -n %s get secret %s -o jsonpath='{.data.public\\.pem}' | base64 -d", name, RelaySessionPublicKey, plan.Namespace, name)
	return r, nil
}

func (p ChartPlan) relaySessionSecret() string {
	if p.RelaySessionSecret != "" {
		return p.RelaySessionSecret
	}
	return DefaultRelaySessionSecret
}
