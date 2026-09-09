// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package sensor

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/catalog"
	"github.com/defenseclaw/defenseclaw/internal/sensor/dnscapture"
	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
)

// reverseCacheTTL bounds how long a resolved name is trusted.
//
// Addresses behind a provider are shared and reassigned. A name held forever
// would eventually attribute an unrelated peer to a provider, which is the one
// failure mode worse than not naming it at all.
const reverseCacheTTL = 10 * time.Minute

// reverseTimeout bounds a single lookup. The poll loop must not stall on a
// slow resolver, because a stalled poll looks exactly like a quiet host.
const reverseTimeout = 2 * time.Second

// maxReverseCacheEntries bounds the cache so a host talking to many peers
// cannot grow it without limit.
const maxReverseCacheEntries = 4096

type cachedName struct {
	hostname   string
	confidence float64
	source     string
	expires    time.Time
}

// ReverseResolver names a peer from a PTR record, checked against the catalog.
//
// This is the weakest of the three attribution sources and is priced as such.
// A PTR record is controlled by whoever owns the address and frequently names
// infrastructure rather than the service; it is used because it is available
// without privilege, and because a weak name is more useful than no name.
//
// The DNS capture plane supersedes it when enabled: an answer to a lookup the
// process actually made is an observation rather than an inference.
type ReverseResolver struct {
	providers *catalog.Catalog
	resolver  *net.Resolver

	mu    sync.Mutex
	cache map[string]cachedName
	now   func() time.Time
}

// NewReverseResolver builds a resolver over the provider catalog.
func NewReverseResolver(providers *catalog.Catalog) *ReverseResolver {
	return &ReverseResolver{
		providers: providers,
		resolver:  net.DefaultResolver,
		cache:     make(map[string]cachedName, 128),
		now:       time.Now,
	}
}

// Resolve names a connection's peer.
func (r *ReverseResolver) Resolve(connection netprobe.Connection) (string, float64, string) {
	if connection.RemoteIP == nil || !connection.Public() {
		return "", 0, ""
	}
	address := connection.RemoteIP.String()

	r.mu.Lock()
	entry, ok := r.cache[address]
	now := r.now()
	if ok && now.Before(entry.expires) {
		r.mu.Unlock()
		return entry.hostname, entry.confidence, entry.source
	}
	r.mu.Unlock()

	hostname, confidence, source := r.lookup(address)

	r.mu.Lock()
	if len(r.cache) >= maxReverseCacheEntries {
		// Drop everything rather than evicting one entry. The cache is a
		// latency optimisation, not state anything depends on, and a full
		// clear is bounded work where an LRU would be a data structure to
		// maintain for no correctness gain.
		r.cache = make(map[string]cachedName, 128)
	}
	// A miss is cached too. Re-querying a peer that has no PTR record on every
	// poll would be the resolver's most expensive behaviour, and the answer
	// does not change within the TTL.
	r.cache[address] = cachedName{
		hostname: hostname, confidence: confidence, source: source,
		expires: now.Add(reverseCacheTTL),
	}
	r.mu.Unlock()
	return hostname, confidence, source
}

func (r *ReverseResolver) lookup(address string) (string, float64, string) {
	ctx, cancel := context.WithTimeout(context.Background(), reverseTimeout)
	defer cancel()
	names, err := r.resolver.LookupAddr(ctx, address)
	if err != nil || len(names) == 0 {
		return "", 0, ""
	}
	// Prefer a name the catalog recognises. A single address can have several
	// PTR records, and the one that matches a known provider is the one worth
	// reporting.
	for _, name := range names {
		hostname := strings.TrimSuffix(strings.ToLower(name), ".")
		if hostname == "" {
			continue
		}
		if _, known := r.providers.Lookup(hostname); known {
			return hostname, ConfidenceCatalogAddress, "reverse_dns_catalog_match"
		}
	}
	hostname := strings.TrimSuffix(strings.ToLower(names[0]), ".")
	if hostname == "" {
		return "", 0, ""
	}
	return hostname, ConfidenceReverseDNS, "reverse_dns"
}

// StaticResolver names peers from a fixed table. It exists so the poll loop
// can be exercised deterministically, and so a deployment that resolves peers
// out of band can supply its own mapping.
type StaticResolver struct {
	Names map[string]string
	// Confidence and Source describe how the table was built. They default to
	// the reverse-DNS values rather than to certainty, because a caller that
	// does not say has not earned a direct-observation weight.
	Confidence float64
	Source     string
}

// Resolve implements Resolver.
func (s StaticResolver) Resolve(connection netprobe.Connection) (string, float64, string) {
	if connection.RemoteIP == nil {
		return "", 0, ""
	}
	hostname, ok := s.Names[connection.RemoteIP.String()]
	if !ok || hostname == "" {
		return "", 0, ""
	}
	confidence, source := s.Confidence, s.Source
	if confidence <= 0 {
		confidence = ConfidenceReverseDNS
	}
	if source == "" {
		source = "static"
	}
	return hostname, confidence, source
}

// CapturingResolver names a peer from a captured DNS answer when one exists,
// and falls back to reverse DNS when it does not.
//
// The ordering is the point. A captured answer is a direct observation of the
// name this host actually resolved to that address; a PTR record is controlled
// by whoever owns the address and frequently names infrastructure rather than
// the service. Preferring the observation is what earns the full-confidence
// weight, and the fallback is what keeps the plane useful before the cache has
// seen anything.
type CapturingResolver struct {
	cache    *dnscapture.Cache
	fallback Resolver
}

// NewCapturingResolver layers a DNS-answer cache over a fallback resolver.
func NewCapturingResolver(cache *dnscapture.Cache, fallback Resolver) *CapturingResolver {
	return &CapturingResolver{cache: cache, fallback: fallback}
}

// Resolve implements Resolver.
func (r *CapturingResolver) Resolve(connection netprobe.Connection) (string, float64, string) {
	if connection.RemoteIP == nil || !connection.Public() {
		return "", 0, ""
	}
	if r.cache != nil {
		if hostname, ok := r.cache.Lookup(connection.RemoteIP.String()); ok {
			return hostname, ConfidenceDNSAnswer, "dns_answer"
		}
	}
	if r.fallback == nil {
		return "", 0, ""
	}
	return r.fallback.Resolve(connection)
}
