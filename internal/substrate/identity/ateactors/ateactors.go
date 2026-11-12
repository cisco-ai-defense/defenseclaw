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

// Package ateactors adapts the Substrate control API client to the
// identity verifier's live-actor lookup. It is apart from identity so the
// gateway links the verifier without the vendored Substrate protos.
package ateactors

import (
	"context"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// ATEAPILookup reads live actors through the control API client.
func ATEAPILookup(c ateapi.Client) identity.ActorLookup {
	return identity.ActorLookupFunc(func(ctx context.Context, atespace, name string) (identity.LiveActor, error) {
		a, err := c.GetActor(ctx, ateapi.Ref(atespace, name))
		if err != nil {
			if ateapi.IsNotFound(err) {
				return identity.LiveActor{}, identity.ErrActorNotFound
			}
			return identity.LiveActor{}, err
		}
		state := strings.TrimPrefix(a.GetStatus().GetState().String(), "ACTOR_STATE_")
		return identity.LiveActor{UID: a.GetMetadata().GetUid(), State: identity.ActorState(state)}, nil
	})
}
