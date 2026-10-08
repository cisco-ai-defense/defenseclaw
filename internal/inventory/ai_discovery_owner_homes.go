// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// cleanDiscoveryHomes trims, cleans and dedupes the operator's home_dirs.
func cleanDiscoveryHomes(homes []string) []string {
	var out []string
	for _, home := range homes {
		home = strings.TrimSpace(home)
		if home == "" {
			continue
		}
		home = filepath.Clean(home)
		if home == "." || discoveryHomeListed(out, home) {
			continue
		}
		out = append(out, home)
	}
	return out
}

// applyPlatformHomeOwners makes the platform's profiles the scan's homes,
// followed by the operator's extra folders. An empty answer (the registry
// unreadable, or a platform without a profile list) keeps the current list.
func (o *AIDiscoveryOptions) applyPlatformHomeOwners(owners []discoveryHomeOwner) {
	if len(owners) == 0 {
		return
	}
	homes := make([]string, 0, len(owners)+len(o.extraHomes))
	for _, owner := range owners {
		homes = append(homes, owner.Home)
	}
	for _, extra := range o.extraHomes {
		if !discoveryHomeListed(homes, extra) {
			homes = append(homes, extra)
		}
	}
	o.homeOwners, o.HomeDirs = owners, homes
	o.HomeDir = homes[0]
}

func sameDiscoveryHome(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func discoveryHomeListed(homes []string, home string) bool {
	for _, listed := range homes {
		if sameDiscoveryHome(listed, home) {
			return true
		}
	}
	return false
}

// connectorEmailReader reads one connector's account address from a profile;
// tests replace it.
var connectorEmailReader = useridentity.ProfileEmailForConnector

// emailConnector is the connector whose account file a signal's address
// comes from, or "" when its connector keeps none in the profile.
func emailConnector(connector string) string {
	switch normalizeAIID(connector) {
	case "claudecode", "claude-code":
		return "claudecode"
	case "codex":
		return "codex"
	}
	return ""
}

// ownerEmails is the lookup a managed Windows scan takes each profile
// owner's connector address from. The gateway service may read only the
// agent folders it was granted, and Claude Code keeps its account in the
// profile root, so the SYSTEM hook enumerator reads both connectors' files
// and publishes the addresses in the owner's identity record; the gateway
// installs a lookup of those records here (SetOwnerEmailLookup).
var ownerEmails struct {
	sync.Mutex
	generation uint64
	lookup     func(sid, connector string) string
}

// SetOwnerEmailLookup installs lookup for later scans. The returned function
// removes it again unless a later call replaced it.
func SetOwnerEmailLookup(lookup func(sid, connector string) string) func() {
	ownerEmails.Lock()
	defer ownerEmails.Unlock()
	ownerEmails.generation++
	generation := ownerEmails.generation
	ownerEmails.lookup = lookup
	return func() {
		ownerEmails.Lock()
		defer ownerEmails.Unlock()
		if ownerEmails.generation == generation {
			ownerEmails.lookup = nil
		}
	}
}

// stampOwnerEmails puts each managed Windows signal's connector address on
// it, the one published for its owner's profile: a signal without an owner
// gets none, and no signal gets another account's.
func (s *ContinuousDiscoveryService) stampOwnerEmails(signals []AISignal) {
	if !s.opts.IncludeUserEmail || s.opts.SecureClient || len(s.opts.homeOwners) == 0 {
		return
	}
	ownerEmails.Lock()
	lookup := ownerEmails.lookup
	ownerEmails.Unlock()
	if lookup == nil {
		return
	}
	read := map[string]string{}
	for i := range signals {
		sig := &signals[i]
		connector := emailConnector(sig.SupportedConnector)
		if connector == "" || sig.UserEmail != "" {
			continue
		}
		owner, ok := s.homeOwnerForSID(sig.UserID)
		if !ok {
			continue
		}
		key := strings.ToUpper(owner.UserID) + "\x00" + connector
		email, done := read[key]
		if !done {
			if email = lookup(owner.UserID, connector); !useridentity.ValidEmail(email) {
				email = ""
			}
			read[key] = email
		}
		sig.UserEmail = email
	}
}

// stampConnectorEmails puts the Claude Code or Codex account address on
// each signal of that connector when ai_discovery.include_user_email is on,
// reading it from the profile homeFor names for the signal. The per-user
// scan uses it on the home it scans, as the account that owns it. Each
// profile and connector is read once per scan. A file that exists but cannot
// be read, or leads outside the profile, gets a named warning rather than
// silence.
func (s *ContinuousDiscoveryService) stampConnectorEmails(signals []AISignal, homeFor func(AISignal) string) {
	if !s.opts.IncludeUserEmail || s.opts.SecureClient {
		return
	}
	type key struct{ connector, home string }
	read := map[key]string{}
	for i := range signals {
		sig := &signals[i]
		connector := emailConnector(sig.SupportedConnector)
		if connector == "" || sig.UserEmail != "" {
			continue
		}
		home := strings.TrimSpace(homeFor(*sig))
		if home == "" {
			continue
		}
		k := key{connector, home}
		email, done := read[k]
		if !done {
			var err error
			if email, err = connectorEmailReader(connector, home); err != nil {
				email = ""
				s.noteUnreadableEmail(connector, err)
			}
			read[k] = email
		}
		sig.UserEmail = email
	}
}

// noteUnreadableEmail records why a connector account file gave no address:
// a per-user scan hands it to the guardian in its report's notes, which the
// guardian logs.
func (s *ContinuousDiscoveryService) noteUnreadableEmail(connector string, err error) {
	if !errors.Is(err, useridentity.ErrEmailFileUnreadable) {
		return
	}
	if s.emailNotes == nil {
		s.emailNotes = map[string]string{}
	}
	s.emailNotes["user_email:"+connector] = connector + ": " + err.Error()
}
