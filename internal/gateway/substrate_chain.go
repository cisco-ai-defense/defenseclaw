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

package gateway

import (
	"context"
	"errors"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/intentstore"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
)

// Tool-chain state of Agent Substrate actors (PLAN §5.4, lane A13). A host
// and an OpenShell sandbox keep their windows in the gateway's own audit
// store, as before. A gateway replica on Substrate is stateless: a verified
// actor's session window and actor window (the #1391 root slot, keyed on
// the actor UID, so rotating session ids cannot empty it) are on the leader
// (internal/substrate/chainstate), reached through SubstrateConfig.Chains.

// toolChainStore is the repository method set the hook chain stage uses:
// *audit.ToolChainRepository locally, *chainstate.Binding on the leader.
type toolChainStore interface {
	Observe(context.Context, audit.ToolChainObserveInput) (audit.ToolChainObserveResult, error)
	ResolvePending(context.Context, audit.ToolChainResolvePendingInput) (audit.ToolChainResolvePendingResult, error)
	PreparePending(context.Context, audit.ToolChainPreparePendingInput) (audit.ToolChainPreparePendingResult, error)
	DiscardPendingForEventSession(context.Context, audit.ToolChainDiscardPendingForEventSessionInput) (audit.ToolChainDiscardPendingForEventSessionResult, error)
	ResetForTerminalEventSession(context.Context, audit.ToolChainResetForTerminalEventSessionInput) (audit.ToolChainResetForTerminalEventSessionResult, error)
	AttachFinalization(ctx context.Context, receiptIDs []string, evaluationID, auditEventID string) error
}

var (
	_ toolChainStore = (*audit.ToolChainRepository)(nil)
	_ toolChainStore = (*chainstate.Binding)(nil)
)

// toolChainStores returns the session window and the root window (nil when
// there is none) of a hook call. ok is false when there is no chain state
// for the call: the chain lane then adds nothing, as with no store.
func (a *APIServer) toolChainStores(ctx context.Context, req agentHookRequest) (session, root toolChainStore, ok bool) {
	if actor, isActor := substrateActorFrom(ctx); isActor {
		st := a.substrateState()
		if st == nil || st.cfg.Chains == nil {
			return nil, nil, false
		}
		who := chainstate.Actor{Atespace: actor.Atespace, UID: actor.UID}
		received := time.Now()
		s, err := st.cfg.Chains.Bind(who, chainstate.ScopeSession, req.ConnectorName, req.SessionID, req.HookEventName, received)
		if err != nil {
			return nil, nil, false
		}
		r, err := st.cfg.Chains.Bind(who, chainstate.ScopeActor, req.ConnectorName, req.SessionID, req.HookEventName, received)
		if err != nil {
			return nil, nil, false
		}
		return s, r, true
	}
	repository, err := a.store.ToolChainRepository()
	if err != nil {
		return nil, nil, false
	}
	// A nil *audit.ToolChainRepository must stay a nil interface.
	if rootRepository := a.toolChainRootRepository(ctx, req); rootRepository != nil {
		return repository, rootRepository, true
	}
	return repository, nil, true
}

// substrateChainActor is the verified actor of a call, for the leader's
// intent store.
func substrateChainActor(ctx context.Context) (chainstate.Actor, bool) {
	actor, ok := substrateActorFrom(ctx)
	if !ok {
		return chainstate.Actor{}, false
	}
	return chainstate.Actor{Atespace: actor.Atespace, UID: actor.UID}, true
}

// useSubstrateChains points the judges' session intent at the leader (nil
// restores process-local intent). Each judge role has its own namespace on
// the leader, as each judge has its own store on a host; a call that is not
// an actor's keeps a process-local store per judge.
func useSubstrateChains(client *chainstate.Client) {
	if client == nil {
		setJudgeIntentStores(nil)
		return
	}
	setJudgeIntentStores(func(role string) intentstore.Store {
		return &chainstate.IntentStore{
			Client:    client,
			Namespace: role,
			ActorOf:   substrateChainActor,
			Fallback: intentstore.NewProcess(intentstore.Limits{
				MaxSessions: maxToolJudgeContextSessions,
				MaxPrior:    maxToolJudgePriorEvents,
				TTL:         toolJudgeContextTTL,
			}),
		}
	})
}

// SetToolValueLineageKey replaces the process-random key of the value
// lineage digests (the value joins of chains such as
// sensitive_read_value_then_external_literal_transmit) with a key every
// replica shares. Replicas with their own random keys could never join a
// value one replica saw with a value another sees. Call it before serving.
func SetToolValueLineageKey(material []byte) error {
	if len(material) < toolValueLineageKeyBytes {
		return errors.New("gateway: the value lineage key needs at least 32 bytes")
	}
	var key toolValueLineageProcessKey
	copy(key.material[:], material[:toolValueLineageKeyBytes])
	if toolValueLineageZeroKey(key.material) {
		return errors.New("gateway: the value lineage key is all zero")
	}
	key.available = true
	activeToolValueLineageProcessKey = key
	return nil
}
