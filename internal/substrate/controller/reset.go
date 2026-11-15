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

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// ResetConfigMap holds the pending policy_conflict resets: an admin asks on
// the admin listener (`defenseclaw substrate policy reset <actor>`), the
// gateway writes the request here, and the controller, which holds the
// conflict state, applies it on its next pass and removes it. The entry
// names who asked, so the reset is audited twice (request and apply).
const ResetConfigMap = "defenseclaw-policy-resets"

// resetMaxAge drops a request for an actor the controller never sees.
const resetMaxAge = time.Hour

// ResetStore is the part of the Kubernetes API the reset path uses
// (setup.Kube implements it).
type ResetStore interface {
	GetConfigMap(ctx context.Context, namespace, name string) (*setup.ConfigMap, error)
	UpdateConfigMap(ctx context.Context, cm *setup.ConfigMap) error
	CreateConfigMap(ctx context.Context, cm *setup.ConfigMap) error
}

// ResetRequest is one admin's request to clear an actor's policy_conflict.
type ResetRequest struct {
	Atespace string    `json:"atespace"`
	Actor    string    `json:"actor"`
	By       string    `json:"by"`
	Reason   string    `json:"reason,omitempty"`
	At       time.Time `json:"at"`
}

func resetKey(atespace, actor string) string {
	sum := sha256.Sum256([]byte(atespace + "/" + actor))
	return "r-" + hex.EncodeToString(sum[:10])
}

// ErrResetInvalid refuses a request without an actor or a requester.
var ErrResetInvalid = errors.New("policy reset: atespace, actor and by are required")

// RequestReset records an admin's reset request for the controller. A
// second request for the same actor replaces the first.
func RequestReset(ctx context.Context, store ResetStore, namespace string, req ResetRequest) error {
	if req.Atespace == "" || req.Actor == "" || strings.TrimSpace(req.By) == "" {
		return ErrResetInvalid
	}
	if req.At.IsZero() {
		req.At = time.Now().UTC()
	}
	if len(req.Reason) > 512 {
		req.Reason = req.Reason[:512]
	}
	val, err := json.Marshal(req)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 3; attempt++ {
		cm, err := store.GetConfigMap(ctx, namespace, ResetConfigMap)
		if err != nil {
			return fmt.Errorf("policy reset: %w", err)
		}
		if cm == nil {
			err = store.CreateConfigMap(ctx, &setup.ConfigMap{Namespace: namespace, Name: ResetConfigMap,
				Data: map[string]string{resetKey(req.Atespace, req.Actor): string(val)}})
		} else {
			if cm.Data == nil {
				cm.Data = map[string]string{}
			}
			cm.Data[resetKey(req.Atespace, req.Actor)] = string(val)
			err = store.UpdateConfigMap(ctx, cm)
		}
		if err == nil {
			return nil
		}
		if attempt == 2 {
			return fmt.Errorf("policy reset: %w", err)
		}
	}
	return nil
}

// applyResets reads the pending requests, clears the conflict of each actor
// it knows (the next write is DefenseClaw's full policy, and drift handling
// starts over), emits the audited event, and removes handled requests.
func (c *Controller) applyResets(ctx context.Context) {
	if c.o.Resets == nil {
		return
	}
	cm, err := c.o.Resets.GetConfigMap(ctx, c.o.Namespace, ResetConfigMap)
	if err != nil || cm == nil || len(cm.Data) == 0 {
		return
	}
	now := c.o.Now()
	byKey := map[string]*actorState{}
	c.mu.Lock()
	for _, st := range c.actors {
		byKey[st.key] = st
	}
	c.mu.Unlock()
	keys := make([]string, 0, len(cm.Data))
	for k := range cm.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	changed := false
	for _, k := range keys {
		var req ResetRequest
		if err := json.Unmarshal([]byte(cm.Data[k]), &req); err != nil || req.Atespace == "" || req.Actor == "" {
			delete(cm.Data, k)
			changed = true
			continue
		}
		st := byKey[req.Atespace+"/"+req.Actor]
		if st == nil {
			if now.Sub(req.At) > resetMaxAge {
				delete(cm.Data, k)
				changed = true
			}
			continue
		}
		st.mu.Lock()
		was := st.conflict
		st.conflict, st.reverts, st.lastForeign = false, nil, time.Time{}
		uid := st.uid
		st.mu.Unlock()
		ev := Event{Type: EventConflictReset, Severity: SeverityWarn, Atespace: req.Atespace, Actor: req.Actor, ActorUID: uid,
			Detail: map[string]any{"by": req.By, "reason": req.Reason, "requested_at": req.At, "was_in_conflict": was}}
		if was {
			ev.Message = "policy_conflict cleared by an admin: DefenseClaw's policy is written again and drift handling starts over"
		} else {
			ev.Message = "policy reset requested by an admin for an actor not in policy_conflict: nothing to clear"
		}
		c.emit(ev)
		delete(cm.Data, k)
		changed = true
	}
	if changed {
		// A concurrent request makes this fail (resource version); the
		// handled entries are applied again next pass, which is harmless.
		_ = c.o.Resets.UpdateConfigMap(ctx, cm)
	}
}
