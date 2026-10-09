// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"errors"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// ProcessAccount is the account a process runs as, read by a broker that
// can open every process's token.
type ProcessAccount struct {
	Name string // executable basename
	User string // account name
}

// processAccounts names process owners for a managed Windows scan. The
// gateway service's restricted token can neither open another account's
// process nor ask Remote Desktop Services who is signed in to a session, so
// a machine-wide agent (VS Code's copilot-runtime.exe) gets its owner from
// the LocalSystem sensor helper instead (GAP-2043).
var processAccounts struct {
	sync.Mutex
	generation uint64
	lookup     func() map[int]ProcessAccount
}

// SetProcessAccountLookup installs lookup for later scans. The returned
// function removes it again unless a later call replaced it.
func SetProcessAccountLookup(lookup func() map[int]ProcessAccount) func() {
	processAccounts.Lock()
	defer processAccounts.Unlock()
	processAccounts.generation++
	generation := processAccounts.generation
	processAccounts.lookup = lookup
	return func() {
		processAccounts.Lock()
		defer processAccounts.Unlock()
		if processAccounts.generation == generation {
			processAccounts.lookup = nil
		}
	}
}

func brokeredProcessAccounts() map[int]ProcessAccount {
	processAccounts.Lock()
	lookup := processAccounts.lookup
	processAccounts.Unlock()
	if lookup == nil {
		return nil
	}
	return lookup()
}

// discoveryAccountName names the account of a profile owner; tests replace it.
var discoveryAccountName = platformDiscoveryAccountName

// refreshHomeOwnerNames names each profile's account again at the start of
// a scan. An account renamed while the gateway runs (Rename-LocalUser keeps
// its SID and profile folder) otherwise kept the name it had when the
// gateway started in discovery and the IDE inventory, and --user with the
// new name found none of its rows, until a restart (GAP-0702).
func (s *ContinuousDiscoveryService) refreshHomeOwnerNames() {
	if s.opts.SecureClient {
		// Secure Client keeps main's names, read once at start.
		return
	}
	for i := range s.opts.homeOwners {
		owner := &s.opts.homeOwners[i]
		if name := strings.TrimSpace(discoveryAccountName(owner.UserID, owner.Home)); name != "" {
			owner.UserName = name
		}
	}
}

// homeOwnerForAccount returns the one profile owner whose account is user.
func (s *ContinuousDiscoveryService) homeOwnerForAccount(user string) (discoveryHomeOwner, bool) {
	var found discoveryHomeOwner
	matches := 0
	for _, owner := range s.opts.homeOwners {
		if owner.Home != "" && processAccountMatchesOwner(user, owner, s.opts.SecureClient) {
			found = owner
			matches++
		}
	}
	// A short brokered name cannot distinguish an excluded domain account
	// from an enrolled local account with the same name.
	if !s.opts.SecureClient {
		for _, owner := range s.opts.excludedOwners {
			if processAccountMatchesOwner(user, owner, false) {
				matches++
			}
		}
	}
	return found, matches == 1
}

func processAccountMatchesOwner(user string, owner discoveryHomeOwner, secureClient bool) bool {
	user = strings.TrimSpace(user)
	domain := ""
	if i := strings.LastIndex(user, `\`); i >= 0 {
		domain, user = user[:i], user[i+1:]
	}
	if user == "" || !strings.EqualFold(strings.TrimSpace(owner.UserName), user) {
		return false
	}
	return secureClient || domain == "" || strings.EqualFold(strings.TrimSpace(owner.Domain), domain)
}

// discoveryHomeOwner names the account that owns one profile root of a
// service-context scan. On managed Windows the gateway service reads every
// enrolled user's agent folders itself (the hook enumerator grants it read
// access to them), so whatever it finds under a profile belongs to that
// profile's account.
type discoveryHomeOwner struct {
	Home     string
	UserID   string // the account's SID
	UserName string
	// Domain is the account's domain (the computer's name for a local
	// account), for enterprise.enrollment entries written DOMAIN\name.
	Domain string
}

// homeOwnerForPath returns the owner of the profile root that holds path.
// Comparison ignores case, as Windows paths do.
func (s *ContinuousDiscoveryService) homeOwnerForPath(path string) (discoveryHomeOwner, bool) {
	path = strings.TrimSpace(path)
	if s == nil || path == "" || len(s.opts.homeOwners) == 0 {
		return discoveryHomeOwner{}, false
	}
	path = filepath.Clean(path)
	var best discoveryHomeOwner
	for _, owner := range s.opts.homeOwners {
		home := strings.TrimRight(filepath.Clean(strings.TrimSpace(owner.Home)), `\/`)
		if home == "" || home == "." || len(home) <= len(strings.TrimRight(best.Home, `\/`)) {
			continue
		}
		prefix := home + string(filepath.Separator)
		if strings.EqualFold(path, home) ||
			(len(path) > len(prefix) && strings.EqualFold(path[:len(prefix)], prefix)) {
			best = owner
		}
	}
	return best, best.Home != ""
}

// homeOwnerForSID returns the profile owner whose account is sid.
func (s *ContinuousDiscoveryService) homeOwnerForSID(sid string) (discoveryHomeOwner, bool) {
	sid = strings.TrimSpace(sid)
	if s == nil || sid == "" {
		return discoveryHomeOwner{}, false
	}
	for _, owner := range s.opts.homeOwners {
		if owner.Home != "" && strings.EqualFold(strings.TrimSpace(owner.UserID), sid) {
			return owner, true
		}
	}
	return discoveryHomeOwner{}, false
}

// stampHomeOwner attributes sig to the account whose profile holds path.
func (s *ContinuousDiscoveryService) stampHomeOwner(sig *AISignal, path string) {
	if sig == nil || sig.UserID != "" {
		return
	}
	if owner, ok := s.homeOwnerForPath(path); ok {
		sig.UserID, sig.UserName = owner.UserID, owner.UserName
	}
}

// attributeProcessOwners uses the process session SID or a brokered token
// account for standalone managed Windows signals. The executable path is only
// evidence of where a binary lives; another user may run it, so it cannot
// establish the process owner or a verified directory identity. Secure Client
// keeps origin/main's image-path attribution. Node helpers inherit only an
// already attributed parent.
func (s *ContinuousDiscoveryService) attributeProcessOwners(procs []processInfo) {
	if len(s.opts.homeOwners) == 0 {
		return
	}
	byPID := make(map[int]int, len(procs))
	for i := range procs {
		byPID[procs[i].PID] = i
		owner, ok := s.homeOwnerForSID(procs[i].SessionOwnerID)
		if s.opts.SecureClient {
			owner, ok = s.homeOwnerForPath(procs[i].Image)
			if !ok {
				owner, ok = s.homeOwnerForSID(procs[i].SessionOwnerID)
			}
		}
		if ok {
			procs[i].OwnerID, procs[i].OwnerName = owner.UserID, owner.UserName
		}
	}
	var accounts map[int]ProcessAccount
	asked := false
	for i := range procs {
		if procs[i].OwnerID != "" || procs[i].Connector == "" {
			continue
		}
		if !asked {
			accounts, asked = brokeredProcessAccounts(), true
		}
		account, ok := accounts[procs[i].PID]
		if !ok || windowsProcessBasename(account.Name) != windowsProcessBasename(procs[i].Comm) {
			continue
		}
		if owner, ok := s.homeOwnerForAccount(account.User); ok {
			procs[i].OwnerID, procs[i].OwnerName = owner.UserID, owner.UserName
		}
	}
	for i := range procs {
		if procs[i].OwnerID != "" || normalizedWindowsProcessName(procs[i].Comm) != "node" {
			continue
		}
		seen := map[int]bool{procs[i].PID: true}
		for j, ok := byPID[procs[i].PPID]; ok && !seen[procs[j].PID]; j, ok = byPID[procs[j].PPID] {
			seen[procs[j].PID] = true
			if procs[j].OwnerID != "" {
				procs[i].OwnerID, procs[i].OwnerName = procs[j].OwnerID, procs[j].OwnerName
				break
			}
		}
	}
}

// discoveryAccessSkipped reports a read error that is not a failure of the
// scan: macOS privacy protection, and on a service-context scan a user
// profile folder the gateway service was never granted (it may read only the
// agent folders). Counting those made every managed Windows scan partial.
func (s *ContinuousDiscoveryService) discoveryAccessSkipped(err error) bool {
	if err == nil {
		return false
	}
	if macOSPrivacyDenied(runtime.GOOS, err) {
		var pathErr *fs.PathError
		if s != nil && !s.opts.SecureClient && errors.As(err, &pathErr) {
			s.tccSkipped = true
			if s.tccSkippedPaths == nil {
				s.tccSkippedPaths = make(map[string]bool)
			}
			s.tccSkippedPaths[hashPath(filepath.Clean(pathErr.Path))] = true
		}
		return true
	}
	return s != nil && len(s.opts.homeOwners) > 0 && errors.Is(err, fs.ErrPermission)
}

// perUserDiscoveryVariableTails maps the per-user folders a catalog path can
// start with to their place in a profile.
var perUserDiscoveryVariableTails = map[string]string{
	"HOME":         "",
	"USERPROFILE":  "",
	"APPDATA":      "AppData/Roaming",
	"LOCALAPPDATA": "AppData/Local",
}

// profileRelativeCandidate rewrites a catalog path that starts with a
// per-user folder variable ($LOCALAPPDATA/hermes/config.yaml) to the same
// place under every scanned profile (~/AppData/Local/hermes/config.yaml) on a
// service-context scan. Expanding the variable resolved the service
// account's own folder, so Hermes (%LOCALAPPDATA%\hermes) and Devin
// (%APPDATA%\devin) were never found for any user.
func (s *ContinuousDiscoveryService) profileRelativeCandidate(candidate string) (string, bool) {
	if s == nil || len(s.opts.homeOwners) == 0 || !strings.HasPrefix(candidate, "$") {
		return "", false
	}
	rest := candidate[1:]
	var name string
	if strings.HasPrefix(rest, "{") {
		end := strings.Index(rest, "}")
		if end < 0 {
			return "", false
		}
		name, rest = rest[1:end], rest[end+1:]
	} else {
		end := 0
		for end < len(rest) && (rest[end] == '_' || rest[end] >= 'A' && rest[end] <= 'Z' ||
			rest[end] >= 'a' && rest[end] <= 'z' || rest[end] >= '0' && rest[end] <= '9') {
			end++
		}
		name, rest = rest[:end], rest[end:]
	}
	tail, ok := perUserDiscoveryVariableTails[strings.ToUpper(name)]
	if !ok || (rest != "" && rest[0] != '/' && rest[0] != '\\') {
		return "", false
	}
	if tail == "" {
		return "~" + rest, true
	}
	return "~/" + tail + rest, true
}
