// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// standaloneExcludeUsers is enterprise.enrollment.exclude_users on the
// standalone profile; the Secure Client profile keeps its profile list.
func standaloneExcludeUsers(cfg *config.Config) []string {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return nil
	}
	return append([]string(nil), cfg.Enterprise.Enrollment.ExcludeUsers...)
}

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

// applyPlatformHomeOwners makes the platform's profiles, less those of
// excluded accounts, the scan's homes, followed by the operator's extra
// folders. A folder inside an excluded profile is not scanned: exclusion
// wins. An empty answer (the registry unreadable, or a platform without a
// profile list) keeps the current list.
func (o *AIDiscoveryOptions) applyPlatformHomeOwners(owners []discoveryHomeOwner) {
	if owners == nil || (o.SecureClient && len(owners) == 0) {
		return
	}
	kept, excluded := splitExcludedHomeOwners(owners, o.ExcludeUsers)
	homes := make([]string, 0, len(kept)+len(o.extraHomes))
	for _, owner := range kept {
		homes = append(homes, owner.Home)
	}
	for _, extra := range o.extraHomes {
		if discoveryHomeListed(homes, extra) || insideDiscoveryHomeOf(excluded, extra) {
			continue
		}
		homes = append(homes, extra)
	}
	o.homeOwners, o.excludedOwners, o.HomeDirs = kept, excluded, homes
	if len(homes) > 0 {
		o.HomeDir = homes[0]
	} else {
		o.HomeDir = ""
	}
}

// splitExcludedHomeOwners separates the profiles whose account
// enterprise.enrollment.exclude_users names. An entry matches the account's
// SID, its profile folder's name, its account name or DOMAIN\name, ignoring
// case, as the hook enumerator decides it.
func splitExcludedHomeOwners(owners []discoveryHomeOwner, exclude []string) (kept, excluded []discoveryHomeOwner) {
	if len(exclude) == 0 {
		return owners, nil
	}
	kept = make([]discoveryHomeOwner, 0, len(owners))
	for _, owner := range owners {
		if homeOwnerExcluded(owner, exclude) {
			excluded = append(excluded, owner)
			continue
		}
		kept = append(kept, owner)
	}
	return kept, excluded
}

func homeOwnerExcluded(owner discoveryHomeOwner, exclude []string) bool {
	names := []string{owner.UserID, filepath.Base(filepath.Clean(owner.Home)), owner.UserName}
	if owner.Domain != "" && owner.UserName != "" {
		names = append(names, owner.Domain+`\`+owner.UserName)
	}
	for _, entry := range exclude {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		for _, name := range names {
			if name = strings.TrimSpace(name); name != "" && strings.EqualFold(entry, name) {
				return true
			}
		}
	}
	return false
}

// excludedAccountSID reports a SID of an excluded profile.
func (s *ContinuousDiscoveryService) excludedAccountSID(sid string) bool {
	sid = strings.TrimSpace(sid)
	for _, owner := range s.opts.excludedOwners {
		if sid != "" && strings.EqualFold(strings.TrimSpace(owner.UserID), sid) {
			return true
		}
	}
	return false
}

// withoutExcludedAccounts drops the processes that run in the session of an
// excluded account, so an excluded user's running agent is not reported as
// a machine-wide one (GAP-1024).
func (s *ContinuousDiscoveryService) withoutExcludedAccounts(procs []processInfo) []processInfo {
	if len(s.opts.excludedOwners) == 0 {
		return procs
	}
	var accounts map[int]ProcessAccount
	out := procs[:0]
	for _, proc := range procs {
		if s.excludedAccountSID(proc.SessionOwnerID) || s.excludedAccountSID(proc.OwnerID) {
			continue
		}
		if proc.SessionOwnerID == "" && proc.Connector != "" {
			if accounts == nil {
				accounts = brokeredProcessAccounts()
			}
			if account, ok := accounts[proc.PID]; ok &&
				windowsProcessBasename(account.Name) == windowsProcessBasename(proc.Comm) {
				excluded := false
				for _, owner := range s.opts.excludedOwners {
					if processAccountMatchesOwner(account.User, owner, false) {
						excluded = true
						break
					}
				}
				if excluded {
					continue
				}
			}
		}
		out = append(out, proc)
	}
	return out
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

// insideDiscoveryHomeOf reports whether path is one of the owners' homes or
// lies below one.
func insideDiscoveryHomeOf(owners []discoveryHomeOwner, path string) bool {
	for _, owner := range owners {
		home := filepath.Clean(owner.Home)
		if sameDiscoveryHome(home, path) {
			return true
		}
		prefix := strings.TrimRight(home, `\/`) + string(filepath.Separator)
		candidate := filepath.Clean(path)
		if len(candidate) > len(prefix) && sameDiscoveryHome(candidate[:len(prefix)-1], home) {
			return true
		}
	}
	return false
}

// profilePathThroughLink reports whether a path below a scanned root goes
// through a link or junction (discoveryPathThroughLink); tests replace it.
var profilePathThroughLink = discoveryPathThroughLink

// profileLinkRefused reports a path a managed Windows scan must not read: it
// lies in a scanned profile or ai_discovery.home_dirs folder and goes
// through a link, junction or mount point below it. The gateway service may
// read every enrolled account's agent folders, so a standard user who made
// their .codex a junction to another account's .codex had that account's
// Codex config and MCP servers listed under their own SID (GAP-1097). This
// is the no-follow rule of GAP-0694, which the hook enumerator applies to
// its grants (GAP-0197) and the IDE inventory to its reads (GAP-0396). Each
// refused path is warned about once. The Secure Client profile and every
// per-user scan (no profile owners) keep their reads.
func (s *ContinuousDiscoveryService) profileLinkRefused(path string) bool {
	if s == nil || s.opts.SecureClient || len(s.opts.homeOwners) == 0 {
		return false
	}
	root, owner, ok := s.scannedRootFor(path)
	if !ok || !profilePathThroughLink(root, path) {
		return false
	}
	key := strings.ToLower(filepath.Clean(path))
	if s.linkWarned == nil {
		s.linkWarned = map[string]bool{}
	}
	if !s.linkWarned[key] {
		s.linkWarned[key] = true
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." {
			rel = filepath.Base(path)
		}
		if owner == "" {
			owner = "ai_discovery.home_dirs entry"
		}
		fmt.Fprintf(os.Stderr, "[ai-discovery] WARN ai_discovery_link_refused: %s: %s goes through a link or junction; not read\n",
			owner, filepath.ToSlash(rel))
	}
	return true
}

// scannedRootFor returns the scanned root that holds path and its owner's
// SID: the profile that holds it, else the ai_discovery.home_dirs folder.
func (s *ContinuousDiscoveryService) scannedRootFor(path string) (string, string, bool) {
	if owner, ok := s.homeOwnerForPath(path); ok {
		return filepath.Clean(owner.Home), owner.UserID, true
	}
	best := ""
	for _, extra := range s.opts.extraHomes {
		if insideDiscoveryHomeOf([]discoveryHomeOwner{{Home: extra}}, path) && len(extra) > len(best) {
			best = filepath.Clean(extra)
		}
	}
	return best, "", best != ""
}

// dropLinkedExtraHomes leaves out of the scan an ai_discovery.home_dirs
// folder that is itself a link or junction, or is reached through one below
// the profile that holds it.
func (s *ContinuousDiscoveryService) dropLinkedExtraHomes() {
	if s.opts.SecureClient || len(s.opts.homeOwners) == 0 || len(s.opts.extraHomes) == 0 {
		return
	}
	kept := make([]string, 0, len(s.opts.HomeDirs))
	droppedHomeDir := false
	for _, home := range s.opts.HomeDirs {
		if _, profile := s.homeOwnerForPathExact(home); !profile && discoveryHomeListed(s.opts.extraHomes, home) &&
			s.profileLinkRefused(home) {
			droppedHomeDir = droppedHomeDir || sameDiscoveryHome(home, s.opts.HomeDir)
			continue
		}
		kept = append(kept, home)
	}
	s.opts.HomeDirs = kept
	if droppedHomeDir {
		// "~" and the per-user folder variables resolve against HomeDir.
		s.opts.HomeDir, _ = platformDiscoveryHomeDir()
		if len(kept) > 0 {
			s.opts.HomeDir = kept[0]
		}
	}
}

// homeOwnerForPathExact returns the profile owner whose home is path itself.
func (s *ContinuousDiscoveryService) homeOwnerForPathExact(path string) (discoveryHomeOwner, bool) {
	for _, owner := range s.opts.homeOwners {
		if sameDiscoveryHome(owner.Home, path) {
			return owner, true
		}
	}
	return discoveryHomeOwner{}, false
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
