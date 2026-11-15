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
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// ChainKeySecret is the value-lineage key every gateway replica shares
// (key "key"): without one, each replica keys value joins its own way and a
// chain split across replicas is never matched (A13).
const ChainKeySecret = "defenseclaw-chain-key"

// CalloutTokenSecret is the callout's service token for the tool verdict
// route on the admin listener (key "token"). The chart mounts it into the
// callout and the gateway, so the MCP tool rules run at egress by default
// (GAP-0015).
const CalloutTokenSecret = "defenseclaw-callout-judge"

// SecretAPI is what EnsureChainKey needs of the Kubernetes API.
type SecretAPI interface {
	SecretExists(ctx context.Context, namespace, name string) (bool, error)
	CreateSecret(ctx context.Context, namespace, name string, data map[string][]byte) error
}

// EnsureChainKey creates the chain key Secret and the callout token Secret
// with 32 random bytes each when they do not exist (the chart's
// pre-install and pre-upgrade hook). An existing one is never replaced, so
// upgrades keep chain joins and the callout's verdict route working.
// Values are never printed.
func EnsureChainKey(ctx context.Context, plan ChartPlan, api SecretAPI) (StepReport, error) {
	r := StepReport{Step: "chain-key"}
	for _, s := range []struct{ name, key, what string }{
		{ChainKeySecret, "key", "chain key"},
		{CalloutTokenSecret, "token", "callout token"},
	} {
		ok, err := api.SecretExists(ctx, plan.Namespace, s.name)
		if err != nil {
			return r, fmt.Errorf("%s: %w", s.what, err)
		}
		if ok {
			r.note("the %s Secret %s exists; kept", s.what, s.name)
			continue
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return r, err
		}
		if err := api.CreateSecret(ctx, plan.Namespace, s.name, map[string][]byte{s.key: []byte(hex.EncodeToString(b))}); err != nil {
			return r, fmt.Errorf("%s: %w", s.what, err)
		}
		r.note("created the %s Secret %s (value not shown)", s.what, s.name)
	}
	return r, nil
}
