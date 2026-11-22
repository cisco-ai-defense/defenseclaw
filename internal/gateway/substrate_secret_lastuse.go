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
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/egressspec"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
)

// SubstrateSecretUses reads when actors last reached each host
// (telemetryrelay.UseReader, the leader's host-use map).
type SubstrateSecretUses interface {
	HostUses(ctx context.Context, actors []telemetryrelay.ActorRef) ([]telemetryrelay.HostUse, error)
}

// substrateSecretUseTimeout bounds the read; past it, list and test answer
// without a last use.
const substrateSecretUseTimeout = 2 * time.Second

// substrateHostUses reads the host uses of the caller's agents, newest
// first (nil when there is no reader or it did not answer).
func (st *substrateState) substrateHostUses(ctx context.Context, regs []registry.Registration) []telemetryrelay.HostUse {
	if st == nil || st.cfg.SecretUses == nil || len(regs) == 0 {
		return nil
	}
	actors := make([]telemetryrelay.ActorRef, 0, len(regs))
	for _, reg := range regs {
		if reg.UID != "" && !reg.Deleted {
			actors = append(actors, telemetryrelay.ActorRef{Atespace: reg.Atespace, UID: reg.UID})
		}
	}
	ctx, cancel := context.WithTimeout(ctx, substrateSecretUseTimeout)
	defer cancel()
	uses, err := st.cfg.SecretUses.HostUses(ctx, actors)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[substrate] secrets: last use not read: %v\n", err)
		return nil
	}
	return uses
}

// substrateSecretLastUse is the newest use of the secret by one of the
// caller's agents: an allowed request, by an agent the secret is for, to
// a host Substrate's egress adds it on (an echo host only with
// allow_echo), while it was in force (an own binding: after it was added
// and before it expired). That is exactly when the egress gateway swaps
// the value in. Nothing about the value is read. uses are newest first.
func substrateSecretLastUse(e substrateSecretEntry, status string, regs []registry.Registration, uses []telemetryrelay.HostUse,
	noSwap []string, now time.Time) (telemetryrelay.HostUse, string, bool) {
	expired := e.binding != nil && e.binding.Expired(now)
	if len(uses) == 0 || (!substrateSecretUsable(status) && !expired) {
		return telemetryrelay.HostUse{}, "", false
	}
	agents := map[telemetryrelay.ActorRef]string{}
	for _, reg := range regs {
		if reg.UID != "" && !reg.Deleted && substrateSecretForActor(e, reg) == "" {
			agents[telemetryrelay.ActorRef{Atespace: reg.Atespace, UID: reg.UID}] = reg.Name
		}
	}
	var hosts []string
	for _, h := range e.sec.Inject.Hosts {
		if e.sec.Inject.AllowEcho || len(egressspec.EchoHostsCoveredWith(h, noSwap)) == 0 {
			hosts = append(hosts, h)
		}
	}
	for _, u := range uses {
		name, ok := agents[telemetryrelay.ActorRef{Atespace: u.Atespace, UID: u.UID}]
		if !ok || !substrateHostCovered(hosts, u.Host) {
			continue
		}
		if b := e.binding; b != nil && (u.At.Before(b.Created) || (!b.Expires.IsZero() && !u.At.Before(b.Expires))) {
			continue
		}
		return u, name, true
	}
	return telemetryrelay.HostUse{}, "", false
}

// substrateHostCovered reports whether host matches one of the patterns:
// an exact name, or a leading "*." for any subdomain (not the apex), the
// forms the callout matches bound hosts with.
func substrateHostCovered(patterns []string, host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, p := range patterns {
		p = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
		if rest, wild := strings.CutPrefix(p, "*."); wild {
			if strings.HasSuffix(host, "."+rest) {
				return true
			}
		} else if p == host {
			return true
		}
	}
	return false
}

// addSubstrateSecretLastUse puts the last use into a list or test view:
// when, on which host and by which of the caller's agents.
func addSubstrateSecretLastUse(v map[string]any, u telemetryrelay.HostUse, agent string) {
	v["last_used"] = u.At.UTC()
	v["last_used_host"] = u.Host
	v["last_used_agent"] = agent
}
