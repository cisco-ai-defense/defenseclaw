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

// SecretAPI is what EnsureChainKey needs of the Kubernetes API.
type SecretAPI interface {
	SecretExists(ctx context.Context, namespace, name string) (bool, error)
	CreateSecret(ctx context.Context, namespace, name string, data map[string][]byte) error
}

// EnsureChainKey creates the chain key Secret with 32 random bytes when it
// does not exist (the chart's pre-install and pre-upgrade hook). An
// existing key is never replaced, so upgrades keep chain joins working.
// The value is never printed.
func EnsureChainKey(ctx context.Context, plan ChartPlan, api SecretAPI) (StepReport, error) {
	r := StepReport{Step: "chain-key"}
	ok, err := api.SecretExists(ctx, plan.Namespace, ChainKeySecret)
	if err != nil {
		return r, fmt.Errorf("chain key: %w", err)
	}
	if ok {
		r.note("the chain key Secret %s exists; kept", ChainKeySecret)
		return r, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return r, err
	}
	if err := api.CreateSecret(ctx, plan.Namespace, ChainKeySecret, map[string][]byte{"key": []byte(hex.EncodeToString(b))}); err != nil {
		return r, fmt.Errorf("chain key: %w", err)
	}
	r.note("created the chain key Secret %s (value not shown)", ChainKeySecret)
	return r, nil
}
