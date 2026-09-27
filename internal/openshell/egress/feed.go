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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	feeds "github.com/defenseclaw/defenseclaw/policies/sandbox/egress"
)

// Category labels why a destination was blocked (or, for allowlist matches,
// why it was allowed). The set is closed because it labels telemetry.
type Category string

// Blocklist feed categories.
const (
	CategoryPasteSite      Category = "paste_site"
	CategoryFileDrop       Category = "file_drop"
	CategoryWebhookCatcher Category = "webhook_catcher"
	CategoryTunnel         Category = "tunnel"
	CategoryAnonymizer     Category = "anonymizer"
)

// Allowlist feed categories.
const (
	CategoryPackageRegistry Category = "package_registry"
	CategorySourceHosting   Category = "source_hosting"
	CategoryToolchain       Category = "toolchain"
	CategoryDocumentation   Category = "documentation"
)

// Categories produced by the proxy itself rather than a feed.
const (
	// CategoryHostInternal is this machine and what only it can reach:
	// loopback, its own addresses, host-internal names such as localhost and
	// host.openshell.internal, link-local and cloud metadata addresses, and
	// multicast, reserved and address-translation ranges. Nothing opens it.
	CategoryHostInternal Category = "host_internal"
	// CategoryPrivateNetwork is the private network around this machine:
	// RFC 1918, carrier-grade NAT and IPv6 unique local addresses, the other
	// hosts on its public subnets, and intranet names (.corp, .lan and
	// similar). Only an operator allow rule opens it.
	CategoryPrivateNetwork     Category = "private_network"
	CategoryPortNotAllowed     Category = "port_not_allowed"
	CategoryInvalidDestination Category = "invalid_destination"
	// CategoryAdminBlock is openshell.admin.egress_block and
	// CategoryAdminAllowOnly a destination outside a non-empty
	// openshell.admin.egress_allow_only: the organization's policy, which
	// nothing but the administrator lifts.
	CategoryAdminBlock     Category = "admin_block"
	CategoryAdminAllowOnly Category = "admin_allow_only"
	CategoryOperatorBlock  Category = "operator_block"
	CategoryNotAllowlisted Category = "not_allowlisted"
	CategoryRateLimited    Category = "rate_limited"
	CategoryLargeUpload    Category = "large_upload"
	CategoryIPLiteral      Category = "ip_literal"
)

var categoryReasons = map[Category]string{
	CategoryPasteSite:      "Public paste sites publish whatever is posted to anyone with the link, a common way to exfiltrate code and secrets.",
	CategoryFileDrop:       "Anonymous file-drop services accept uploads without an account and hand out public download links.",
	CategoryWebhookCatcher: "Webhook catchers record every request sent to them for whoever holds the URL, a common exfiltration sink.",
	CategoryTunnel:         "Tunnel services expose or relay traffic through public endpoints, bypassing network controls.",
	CategoryAnonymizer:     "Anonymizers hide where traffic goes.",

	CategoryPackageRegistry: "Package registry.",
	CategorySourceHosting:   "Source code hosting.",
	CategoryToolchain:       "Toolchain download.",
	CategoryDocumentation:   "Reference documentation.",

	CategoryHostInternal:       "Sandboxes never reach this machine (loopback, its own addresses, localhost and host.openshell.internal), link-local and cloud metadata addresses, or reserved addresses.",
	CategoryPrivateNetwork:     "Sandboxes reach private networks (RFC 1918, carrier-grade NAT and unique local addresses, this machine's own subnets, intranet names) only where the operator allowed them.",
	CategoryPortNotAllowed:     "The egress proxy only relays the configured web ports.",
	CategoryInvalidDestination: "The request target is not a valid host and port.",
	CategoryAdminBlock:         "This destination is blocked by your organization's DefenseClaw policy.",
	CategoryAdminAllowOnly:     "This destination is blocked by your organization's DefenseClaw policy, which allows only the destinations it lists.",
	CategoryOperatorBlock:      "The operator blocked this destination in DefenseClaw configuration.",
	CategoryNotAllowlisted:     "This sandbox's network profile only allows destinations on its allowlist.",
	CategoryRateLimited:        "This sandbox has too many connections open or is opening them too fast.",
	CategoryLargeUpload:        "Large upload to a destination this sandbox had not contacted before.",
	CategoryIPLiteral:          "An IP address hides which site it belongs to, so the blocklist cannot apply; the open profile reaches IP addresses only after an unblock.",
}

// Reason returns the default human-readable explanation for c.
func (c Category) Reason() string { return categoryReasons[c] }

// Feed kinds.
const (
	FeedKindBlocklist = "blocklist"
	FeedKindAllowlist = "allowlist"
)

const (
	feedSchemaVersion = 1
	maxFeedBytes      = 1 << 20
)

var feedCategories = map[string]map[Category]bool{
	FeedKindBlocklist: {
		CategoryPasteSite: true, CategoryFileDrop: true, CategoryWebhookCatcher: true,
		CategoryTunnel: true, CategoryAnonymizer: true,
	},
	FeedKindAllowlist: {
		CategoryPackageRegistry: true, CategorySourceHosting: true, CategoryToolchain: true,
		CategoryDocumentation: true,
	},
}

var (
	feedVersionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$`)
	feedNamePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// ErrInvalidFeed reports a feed file that fails schema validation.
var ErrInvalidFeed = errors.New("egress: invalid feed")

// Feed is a parsed and validated egress feed: a named, versioned list of
// categorized host patterns.
type Feed struct {
	Kind    string
	Name    string
	Version string
	// Digest is the hex SHA-256 of the feed document, for provenance.
	Digest  string
	Entries []FeedEntry

	index *hostSet[int]
}

// FeedEntry is one service in a feed.
type FeedEntry struct {
	Name     string
	Category Category
	// Reason is the entry's explanation, defaulting to the category reason.
	Reason string
	// Hosts are the canonical patterns (see parsePattern).
	Hosts []string
}

// FeedMatch is the feed, entry and pattern that matched a destination.
type FeedMatch struct {
	Feed    *Feed
	Entry   FeedEntry
	Pattern string
}

type feedFile struct {
	SchemaVersion int             `yaml:"schema_version"`
	Kind          string          `yaml:"kind"`
	Name          string          `yaml:"name"`
	FeedVersion   string          `yaml:"feed_version"`
	Entries       []feedEntryFile `yaml:"entries"`
}

type feedEntryFile struct {
	Name     string   `yaml:"name"`
	Category string   `yaml:"category"`
	Reason   string   `yaml:"reason"`
	Hosts    []string `yaml:"hosts"`
}

// ParseFeed decodes and validates a feed document. Unknown keys, unknown
// categories for the feed kind, invalid patterns and a pattern listed twice
// are all errors, so a bad feed fails at load rather than matching nothing.
func ParseFeed(data []byte) (*Feed, error) {
	if len(data) > maxFeedBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalidFeed, maxFeedBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var file feedFile
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFeed, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: more than one YAML document", ErrInvalidFeed)
	}
	if file.SchemaVersion != feedSchemaVersion {
		return nil, fmt.Errorf("%w: schema_version %d, want %d", ErrInvalidFeed, file.SchemaVersion, feedSchemaVersion)
	}
	allowed, ok := feedCategories[file.Kind]
	if !ok {
		return nil, fmt.Errorf("%w: kind %q, want %q or %q", ErrInvalidFeed, file.Kind, FeedKindBlocklist, FeedKindAllowlist)
	}
	if !feedNamePattern.MatchString(file.Name) {
		return nil, fmt.Errorf("%w: name %q (lower-case letters, digits, '.', '_' and '-')", ErrInvalidFeed, file.Name)
	}
	if !feedVersionPattern.MatchString(file.FeedVersion) {
		return nil, fmt.Errorf("%w: feed_version %q", ErrInvalidFeed, file.FeedVersion)
	}
	if len(file.Entries) == 0 {
		return nil, fmt.Errorf("%w: no entries", ErrInvalidFeed)
	}

	digest := sha256.Sum256(data)
	feed := &Feed{
		Kind: file.Kind, Name: file.Name, Version: file.FeedVersion, Digest: hex.EncodeToString(digest[:]),
		index: newHostSet[int](),
	}
	for i, raw := range file.Entries {
		name := strings.TrimSpace(raw.Name)
		if name == "" {
			return nil, fmt.Errorf("%w: entry %d: missing name", ErrInvalidFeed, i)
		}
		category := Category(strings.TrimSpace(raw.Category))
		if !allowed[category] {
			return nil, fmt.Errorf("%w: entry %q: category %q is not a %s category", ErrInvalidFeed, name, raw.Category, file.Kind)
		}
		if len(raw.Hosts) == 0 {
			return nil, fmt.Errorf("%w: entry %q: no hosts", ErrInvalidFeed, name)
		}
		entry := FeedEntry{Name: name, Category: category, Reason: strings.TrimSpace(raw.Reason)}
		if entry.Reason == "" {
			entry.Reason = category.Reason()
		}
		for _, host := range raw.Hosts {
			p, err := parsePattern(host)
			if err != nil {
				return nil, fmt.Errorf("%w: entry %q: %v", ErrInvalidFeed, name, err)
			}
			if !feed.index.add(p, len(feed.Entries)) {
				return nil, fmt.Errorf("%w: entry %q: pattern %q listed twice", ErrInvalidFeed, name, p.raw)
			}
			entry.Hosts = append(entry.Hosts, p.raw)
		}
		feed.Entries = append(feed.Entries, entry)
	}
	return feed, nil
}

// match looks up an already-normalized destination.
func (f *Feed) match(host string, addr netip.Addr) (FeedMatch, bool) {
	if f == nil || f.index == nil {
		return FeedMatch{}, false
	}
	item, ok := f.index.match(host, addr)
	if !ok {
		return FeedMatch{}, false
	}
	return FeedMatch{Feed: f, Entry: f.Entries[item.value], Pattern: item.pattern}, true
}

// Match reports the feed entry covering host, which may be a DNS name or an
// IP literal in any spelling normalizeHost accepts.
func (f *Feed) Match(host string) (FeedMatch, bool) {
	h, addr, err := normalizeHost(host)
	if err != nil {
		return FeedMatch{}, false
	}
	return f.match(h, addr)
}

var (
	builtinOnce      sync.Once
	builtinBlocklist *Feed
	builtinAllowlist *Feed
	builtinErr       error
)

func loadBuiltinFeeds() {
	builtinOnce.Do(func() {
		builtinBlocklist, builtinErr = parseBuiltin(feeds.BlocklistYAML(), FeedKindBlocklist)
		if builtinErr != nil {
			return
		}
		builtinAllowlist, builtinErr = parseBuiltin(feeds.AllowlistYAML(), FeedKindAllowlist)
	})
}

func parseBuiltin(data []byte, kind string) (*Feed, error) {
	feed, err := ParseFeed(data)
	if err != nil {
		return nil, fmt.Errorf("built-in %s feed: %w", kind, err)
	}
	if feed.Kind != kind {
		return nil, fmt.Errorf("%w: built-in %s feed declares kind %q", ErrInvalidFeed, kind, feed.Kind)
	}
	return feed, nil
}

// BuiltinBlocklist returns the embedded blocklist feed
// (policies/sandbox/egress/blocklist.yaml). The feed is parsed once and
// shared; callers must not modify it.
func BuiltinBlocklist() (*Feed, error) {
	loadBuiltinFeeds()
	return builtinBlocklist, builtinErr
}

// BuiltinAllowlist returns the embedded balanced-profile allowlist feed
// (policies/sandbox/egress/allowlist.yaml). The feed is parsed once and
// shared; callers must not modify it.
func BuiltinAllowlist() (*Feed, error) {
	loadBuiltinFeeds()
	return builtinAllowlist, builtinErr
}
