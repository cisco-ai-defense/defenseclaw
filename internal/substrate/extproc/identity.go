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

package extproc

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// The ext_proc attribute that carries the actor identity: Envoy's
// per-filter attribute map, keyed by the filter name, holds the
// dev.ate.actor.identity filter state the egress gateway sets.
const (
	identityAttributeFilter = "envoy.filters.http.ext_proc"
	identityAttributeKey    = "filter_state['dev.ate.actor.identity']"
	workerForActorSegment   = "worker-for-actor"
	// DefaultActorTrustDomain is the SPIFFE trust domain of actor
	// identities on Substrate v1.0.0.
	DefaultActorTrustDomain = "substrate-actor.local"
	// DefaultEgressPeer is the SPIFFE ID the egress gateway presents to the
	// callout (its service account).
	DefaultEgressPeer = "spiffe://cluster.local/ns/ate-system/sa/atenet-egress"
)

// ErrNoIdentity reports a request whose ext_proc attributes carry no actor
// identity, or one that does not parse.
var ErrNoIdentity = errors.New("extproc: no actor identity")

// Atespace and actor names: printable, bounded, no separators, so a name
// can't smuggle a path segment into a key or a refusal.
var actorNamePattern = lazyregexp.New(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)

// actorFromAttributes reads the actor identity from the first message's
// attributes.
func actorFromAttributes(attrs map[string]*structpb.Struct, trustDomain string) (ActorRef, error) {
	st := attrs[identityAttributeFilter]
	if st == nil {
		return ActorRef{}, fmt.Errorf("%w: no %s attributes", ErrNoIdentity, identityAttributeFilter)
	}
	v := st.GetFields()[identityAttributeKey]
	if v == nil {
		return ActorRef{}, fmt.Errorf("%w: no %s", ErrNoIdentity, identityAttributeKey)
	}
	s, ok := v.GetKind().(*structpb.Value_StringValue)
	if !ok {
		return ActorRef{}, fmt.Errorf("%w: %s is not a string", ErrNoIdentity, identityAttributeKey)
	}
	return ParseActorSPIFFE(s.StringValue, trustDomain)
}

// ParseActorSPIFFE parses spiffe://<trustDomain>/worker-for-actor/<atespace>/<name>.
// An empty trustDomain means DefaultActorTrustDomain. Any other shape, an
// actor/ subject included, is refused: the egress gateway only ever sets the
// worker-for-actor form.
func ParseActorSPIFFE(id, trustDomain string) (ActorRef, error) {
	if trustDomain == "" {
		trustDomain = DefaultActorTrustDomain
	}
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "spiffe" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ActorRef{}, fmt.Errorf("%w: not a SPIFFE ID", ErrNoIdentity)
	}
	if !strings.EqualFold(u.Host, trustDomain) {
		return ActorRef{}, fmt.Errorf("%w: trust domain %q, want %q", ErrNoIdentity, u.Host, trustDomain)
	}
	parts := strings.Split(strings.TrimPrefix(u.EscapedPath(), "/"), "/")
	if len(parts) != 3 || parts[0] != workerForActorSegment {
		return ActorRef{}, fmt.Errorf("%w: path is not /%s/<atespace>/<name>", ErrNoIdentity, workerForActorSegment)
	}
	if !actorNamePattern.MatchString(parts[1]) || !actorNamePattern.MatchString(parts[2]) {
		return ActorRef{}, fmt.Errorf("%w: invalid atespace or actor name", ErrNoIdentity)
	}
	return ActorRef{Atespace: parts[1], Name: parts[2]}, nil
}
