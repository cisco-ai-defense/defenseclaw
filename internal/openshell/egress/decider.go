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

package egress

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
)

// Mode is how the Decider treats a destination no rule covers.
type Mode string

const (
	// ModeOpen allows by default and blocks the blocklist feed (the "open"
	// profile).
	ModeOpen Mode = "open"
	// ModeAllowlist blocks by default and allows the curated allowlist feed
	// (the "balanced" profile).
	ModeAllowlist Mode = "allowlist"
)

func (m Mode) valid() bool { return m == ModeOpen || m == ModeAllowlist }

// ParseMode parses "open" or "allowlist".
func ParseMode(s string) (Mode, error) {
	m := Mode(strings.ToLower(strings.TrimSpace(s)))
	if !m.valid() {
		return "", fmt.Errorf("egress: unknown mode %q (want %q or %q)", s, ModeOpen, ModeAllowlist)
	}
	return m, nil
}

// ModeForProfile maps an OpenShell network profile to the proxy mode. The
// strict profile runs without the egress proxy, reported as enabled=false.
// An empty profile is the default, open.
func ModeForProfile(profile string) (mode Mode, enabled bool, err error) {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "", "open":
		return ModeOpen, true, nil
	case "balanced":
		return ModeAllowlist, true, nil
	case "strict":
		return "", false, nil
	}
	return "", false, fmt.Errorf("egress: unknown network profile %q (want open, balanced or strict)", profile)
}

// Source says which layer produced a decision.
type Source string

const (
	// SourceGuard is destination validation, the SSRF policy and the port
	// list. Guard blocks are never unblockable.
	SourceGuard Source = "guard"
	// SourceOperator is the operator block and allow lists.
	SourceOperator Source = "operator"
	// SourceUnblock is a per-sandbox or persistent unblock decision.
	SourceUnblock Source = "unblock"
	// SourceFeed is the blocklist or allowlist feed.
	SourceFeed Source = "feed"
	// SourceDefault is the mode default: allow in open mode, block in
	// allowlist mode.
	SourceDefault Source = "default"
	// SourceLimit is a concurrency, rate or large-upload limit.
	SourceLimit Source = "limit"
)

// Decision is the verdict for one destination.
type Decision struct {
	Allowed bool
	// Host is the normalized destination (sanitized when invalid).
	Host string
	Port int
	// Mode is the mode the decision was made in.
	Mode Mode
	// Category says why the destination was blocked; for allowlist matches
	// it is the allowlist entry's category.
	Category Category
	Reason   string
	// Rule is the pattern that matched, if any.
	Rule   string
	Source Source
	// Feed, FeedVersion and Entry identify the feed entry that matched, if
	// any.
	Feed        string
	FeedVersion string
	Entry       string
	// Unblockable reports whether an unblock decision can lift the block.
	Unblockable bool
}

// Unblock lifts a block for one sandbox, or for every sandbox when
// SandboxID is empty (a persistent "always" decision). Unblocks override the
// blocklist feed, allowlist-mode defaults and the large-upload block, but
// never guard or operator blocks.
type Unblock struct {
	// Pattern is an exact host, a "*." wildcard, an IP literal or a CIDR.
	Pattern   string
	SandboxID string
	CreatedAt time.Time
}

// Unblocks supplies unblock decisions to the Decider. The sandbox manager
// owns persistence; MemoryUnblocks is the in-memory index it can load
// persisted decisions into. Implementations must be safe for concurrent use
// and fast: Decide calls Unblocked for every blocked-by-feed or
// not-allowlisted destination.
type Unblocks interface {
	// Unblocked reports an unblock covering the normalized host for p.
	Unblocked(p Principal, host string) (Unblock, bool)
}

// DeciderOptions configures a Decider. The zero value is the open profile
// with the built-in feeds and ports 80 and 443.
type DeciderOptions struct {
	// Mode applies to principals that do not carry their own. Default open.
	Mode Mode
	// Ports is the destination port allowlist. Default DefaultPorts().
	Ports []int
	// Blocklists and Allowlists are the feeds to apply; the first matching
	// feed wins. Nil uses the built-in feed; an empty non-nil slice uses
	// none.
	Blocklists []*Feed
	Allowlists []*Feed
	// Block and Allow are operator patterns (openshell.egress.block/allow,
	// firewall deny rules): exact hosts, "*." wildcards, IP literals or
	// CIDRs. Block wins over everything except the guard; Allow overrides
	// the blocklist feed and allowlist-mode defaults. CIDR blocks are also
	// enforced against the resolved address at dial time.
	Block []string
	Allow []string
	// Unblocks supplies unblock decisions; nil means none.
	Unblocks Unblocks
}

// Decider decides whether a principal may reach a destination. It is
// immutable and safe for concurrent use; build a new one to change options.
type Decider struct {
	mode       Mode
	ports      []int
	portSet    map[int]bool
	blocklists []*Feed
	allowlists []*Feed
	block      *hostSet[struct{}]
	allow      *hostSet[struct{}]
	unblocks   Unblocks
}

// DefaultPorts returns the default destination ports, 80 and 443.
func DefaultPorts() []int { return []int{80, 443} }

// guardPolicy is the netguard address policy for sandbox egress: private
// networks and CGNAT stay prohibited regardless of the operator's
// private-upstream allowlist or DEFENSECLAW_ALLOW_CGNAT, which exist for the
// daemon's own upstreams and must never widen what a sandbox can reach.
var guardPolicy = netguard.V8NetworkSafetyPolicy{}

// reservedNames are names that resolve to this machine or its private
// network by definition, refused before any DNS lookup. host.openshell.internal
// (the sandbox's view of host loopback) falls under *.internal.
var reservedNames = func() *hostSet[struct{}] {
	set := newHostSet[struct{}]()
	for _, raw := range []string{
		"localhost", "*.localhost",
		"*.internal",    // ICANN private-use TLD: host.openshell.internal, metadata.google.internal
		"*.local",       // mDNS
		"*.localdomain", // distro defaults
		"*.home.arpa",   // RFC 8375 home networks
		"*.lan", "*.home", "*.corp", "*.intranet", "*.private",
	} {
		p, err := parsePattern(raw)
		if err != nil {
			panic(fmt.Sprintf("egress: reserved name %q: %v", raw, err))
		}
		set.add(p, struct{}{})
	}
	return set
}()

// NewDecider validates opts and builds a Decider.
func NewDecider(opts DeciderOptions) (*Decider, error) {
	d := &Decider{mode: ModeOpen, unblocks: opts.Unblocks}
	if opts.Mode != "" {
		mode, err := ParseMode(string(opts.Mode))
		if err != nil {
			return nil, err
		}
		d.mode = mode
	}
	ports, err := normalizePorts(opts.Ports)
	if err != nil {
		return nil, err
	}
	d.ports = ports
	d.portSet = make(map[int]bool, len(ports))
	for _, port := range ports {
		d.portSet[port] = true
	}

	if d.blocklists, err = feedList(opts.Blocklists, FeedKindBlocklist, BuiltinBlocklist); err != nil {
		return nil, err
	}
	if d.allowlists, err = feedList(opts.Allowlists, FeedKindAllowlist, BuiltinAllowlist); err != nil {
		return nil, err
	}

	if d.block, err = operatorSet("block", opts.Block); err != nil {
		return nil, err
	}
	if d.allow, err = operatorSet("allow", opts.Allow); err != nil {
		return nil, err
	}
	return d, nil
}

func feedList(in []*Feed, kind string, builtin func() (*Feed, error)) ([]*Feed, error) {
	if in == nil {
		feed, err := builtin()
		if err != nil {
			return nil, err
		}
		return []*Feed{feed}, nil
	}
	out := make([]*Feed, 0, len(in))
	for _, feed := range in {
		if feed == nil || feed.index == nil {
			return nil, fmt.Errorf("egress: %s feeds must come from ParseFeed", kind)
		}
		if feed.Kind != kind {
			return nil, fmt.Errorf("egress: feed %q has kind %q, want %q", feed.Name, feed.Kind, kind)
		}
		out = append(out, feed)
	}
	return out, nil
}

func matchFeeds(feeds []*Feed, host string, addr netip.Addr) (FeedMatch, bool) {
	for _, feed := range feeds {
		if m, ok := feed.match(host, addr); ok {
			return m, true
		}
	}
	return FeedMatch{}, false
}

func normalizePorts(in []int) ([]int, error) {
	if len(in) == 0 {
		return DefaultPorts(), nil
	}
	out := make([]int, 0, len(in))
	for _, port := range in {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("egress: port %d out of range", port)
		}
		if !slices.Contains(out, port) {
			out = append(out, port)
		}
	}
	slices.Sort(out)
	return out, nil
}

func operatorSet(name string, patterns []string) (*hostSet[struct{}], error) {
	set := newHostSet[struct{}]()
	for _, raw := range patterns {
		p, err := parsePattern(raw)
		if err != nil {
			return nil, fmt.Errorf("egress: operator %s list: %w", name, err)
		}
		set.add(p, struct{}{})
	}
	return set, nil
}

// Mode returns the default mode.
func (d *Decider) Mode() Mode { return d.mode }

// Ports returns the destination port allowlist.
func (d *Decider) Ports() []int { return slices.Clone(d.ports) }

// FeedInfo identifies a feed a Decider applies.
type FeedInfo struct {
	Kind    string
	Name    string
	Version string
	Digest  string
}

// Feeds returns the blocklist feeds, then the allowlist feeds, in the order
// they apply.
func (d *Decider) Feeds() []FeedInfo {
	out := make([]FeedInfo, 0, len(d.blocklists)+len(d.allowlists))
	for _, feed := range slices.Concat(d.blocklists, d.allowlists) {
		out = append(out, FeedInfo{Kind: feed.Kind, Name: feed.Name, Version: feed.Version, Digest: feed.Digest})
	}
	return out
}

// Decide returns the verdict for p reaching host:port. host may be a DNS
// name or an IP literal (bracketed or not). Layers apply in order: guard
// (validation, SSRF policy, ports), operator block, unblock decisions,
// operator allow, blocklist feed, then the mode default (open allows,
// allowlist allows only allowlist feed matches).
//
// Decide never resolves DNS: the SSRF policy for names is enforced against
// every resolved address at dial time.
func (d *Decider) Decide(p Principal, host string, port int) Decision {
	mode := d.mode
	if p.Mode.valid() {
		mode = p.Mode
	}
	h, addr, err := normalizeHost(host)
	if err != nil {
		return blocked(Decision{Host: sanitizeHost(host), Port: port, Mode: mode}, CategoryInvalidDestination, SourceGuard, "")
	}
	dec := Decision{Host: h, Port: port, Mode: mode}
	if port < 1 || port > 65535 {
		return blocked(dec, CategoryInvalidDestination, SourceGuard, "")
	}
	if reason, private := guardRefusal(h, addr); private {
		dec = blocked(dec, CategoryPrivateNetwork, SourceGuard, "")
		dec.Reason = reason
		return dec
	}
	if !d.portSet[port] {
		dec = blocked(dec, CategoryPortNotAllowed, SourceGuard, "")
		dec.Reason = fmt.Sprintf("%s Allowed ports: %s.", CategoryPortNotAllowed.Reason(), joinPorts(d.ports))
		return dec
	}
	if item, ok := d.block.match(h, addr); ok {
		return blocked(dec, CategoryOperatorBlock, SourceOperator, item.pattern)
	}
	if d.unblocks != nil {
		if u, ok := d.unblocks.Unblocked(p, h); ok {
			dec.Allowed, dec.Source, dec.Rule = true, SourceUnblock, u.Pattern
			return dec
		}
	}
	if item, ok := d.allow.match(h, addr); ok {
		dec.Allowed, dec.Source, dec.Rule = true, SourceOperator, item.pattern
		return dec
	}
	if m, ok := matchFeeds(d.blocklists, h, addr); ok {
		dec = blocked(dec, m.Entry.Category, SourceFeed, m.Pattern)
		dec.Reason, dec.Unblockable = m.Entry.Reason, true
		dec.Feed, dec.FeedVersion, dec.Entry = m.Feed.Name, m.Feed.Version, m.Entry.Name
		return dec
	}
	if mode == ModeOpen {
		dec.Allowed, dec.Source = true, SourceDefault
		return dec
	}
	if m, ok := matchFeeds(d.allowlists, h, addr); ok {
		dec.Allowed, dec.Source, dec.Rule, dec.Category = true, SourceFeed, m.Pattern, m.Entry.Category
		dec.Feed, dec.FeedVersion, dec.Entry = m.Feed.Name, m.Feed.Version, m.Entry.Name
		return dec
	}
	dec = blocked(dec, CategoryNotAllowlisted, SourceDefault, "")
	dec.Unblockable = true
	return dec
}

func blocked(dec Decision, category Category, source Source, rule string) Decision {
	dec.Allowed = false
	dec.Category = category
	dec.Reason = category.Reason()
	dec.Source = source
	dec.Rule = rule
	return dec
}

// guardRefusal applies the destination-level SSRF policy: IP literals go
// through the netguard address policy, names are refused when they are
// host-internal by definition. Names that resolve to private addresses are
// caught at dial time.
func guardRefusal(host string, addr netip.Addr) (string, bool) {
	if addr.IsValid() {
		if addr.Zone() != "" {
			return "Zoned IPv6 addresses are link-scoped and never public.", true
		}
		if err := guardPolicy.ValidateIP(net.IP(addr.AsSlice())); err != nil {
			return "The address is private, loopback, link-local, carrier-grade NAT, metadata, reserved or otherwise not publicly routable.", true
		}
		return "", false
	}
	if !strings.Contains(host, ".") {
		return "Single-label names resolve through the host's DNS search domains to internal machines.", true
	}
	if _, ok := reservedNames.match(host, addr); ok {
		return "The name is host-internal: localhost, .internal (including host.openshell.internal), .local and similar names reach this machine or its private network.", true
	}
	return "", false
}

func joinPorts(ports []int) string {
	parts := make([]string, len(ports))
	for i, port := range ports {
		parts[i] = strconv.Itoa(port)
	}
	return strings.Join(parts, ", ")
}

// sanitizeHost makes an arbitrary client-supplied host safe to echo in
// events and response bodies: printable ASCII only, bounded length.
func sanitizeHost(raw string) string {
	const limit = maxHostLen + 8
	var b strings.Builder
	for i := 0; i < len(raw) && b.Len() < limit; i++ {
		c := raw[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			b.WriteByte('?')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// MemoryUnblocks is a concurrency-safe in-memory Unblocks index. The sandbox
// manager loads persisted decisions into it and updates it as the user
// unblocks destinations.
type MemoryUnblocks struct {
	mu      sync.RWMutex
	entries []unblockEntry
}

type unblockEntry struct {
	unblock Unblock
	pattern pattern
}

// NewMemoryUnblocks returns an index holding initial.
func NewMemoryUnblocks(initial ...Unblock) (*MemoryUnblocks, error) {
	m := &MemoryUnblocks{}
	if err := m.Replace(initial); err != nil {
		return nil, err
	}
	return m, nil
}

func parseUnblock(u Unblock) (unblockEntry, error) {
	p, err := parsePattern(u.Pattern)
	if err != nil {
		return unblockEntry{}, err
	}
	u.Pattern = p.raw
	u.SandboxID = strings.TrimSpace(u.SandboxID)
	return unblockEntry{unblock: u, pattern: p}, nil
}

// Add records u, replacing an existing unblock with the same scope and
// pattern.
func (m *MemoryUnblocks) Add(u Unblock) error {
	entry, err := parseUnblock(u)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.entries {
		if m.entries[i].unblock.SandboxID == entry.unblock.SandboxID && m.entries[i].unblock.Pattern == entry.unblock.Pattern {
			m.entries[i] = entry
			return nil
		}
	}
	m.entries = append(m.entries, entry)
	return nil
}

// Remove deletes the unblock with the given scope and pattern and reports
// whether it existed. An empty sandboxID addresses a persistent unblock.
func (m *MemoryUnblocks) Remove(sandboxID, patternText string) bool {
	p, err := parsePattern(patternText)
	if err != nil {
		return false
	}
	sandboxID = strings.TrimSpace(sandboxID)
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.entries {
		if m.entries[i].unblock.SandboxID == sandboxID && m.entries[i].unblock.Pattern == p.raw {
			m.entries = slices.Delete(m.entries, i, i+1)
			return true
		}
	}
	return false
}

// RemoveSandbox deletes every unblock scoped to sandboxID (for example when
// the sandbox is deleted) and returns how many were removed.
func (m *MemoryUnblocks) RemoveSandbox(sandboxID string) int {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	before := len(m.entries)
	m.entries = slices.DeleteFunc(m.entries, func(e unblockEntry) bool { return e.unblock.SandboxID == sandboxID })
	return before - len(m.entries)
}

// Replace swaps in a complete set of unblocks. Nothing changes when any of
// them is invalid.
func (m *MemoryUnblocks) Replace(list []Unblock) error {
	entries := make([]unblockEntry, 0, len(list))
	for _, u := range list {
		entry, err := parseUnblock(u)
		if err != nil {
			return err
		}
		entries = append(entries, entry)
	}
	m.mu.Lock()
	m.entries = entries
	m.mu.Unlock()
	return nil
}

// List returns the recorded unblocks with canonical patterns.
func (m *MemoryUnblocks) List() []Unblock {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Unblock, len(m.entries))
	for i, e := range m.entries {
		out[i] = e.unblock
	}
	return out
}

// Unblocked implements Unblocks. A sandbox-scoped unblock matches only a
// principal with the same non-empty SandboxID; sandbox-scoped matches are
// preferred over persistent ones.
func (m *MemoryUnblocks) Unblocked(p Principal, host string) (Unblock, bool) {
	h, addr, err := normalizeHost(host)
	if err != nil {
		return Unblock{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var persistent *Unblock
	for i := range m.entries {
		e := &m.entries[i]
		if !e.pattern.matches(h, addr) {
			continue
		}
		switch e.unblock.SandboxID {
		case "":
			if persistent == nil {
				persistent = &e.unblock
			}
		case p.SandboxID:
			return e.unblock, true
		}
	}
	if persistent != nil {
		return *persistent, true
	}
	return Unblock{}, false
}
