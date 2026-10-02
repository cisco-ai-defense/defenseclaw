// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"errors"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
)

// discoveryHomeOwner names the account that owns one profile root of a
// service-context scan. On managed Windows the gateway service reads every
// enrolled user's agent folders itself (the hook enumerator grants it read
// access to them), so whatever it finds under a profile belongs to that
// profile's account.
type discoveryHomeOwner struct {
	Home     string
	UserID   string // the account's SID
	UserName string
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

// stampHomeOwner attributes sig to the account whose profile holds path.
func (s *ContinuousDiscoveryService) stampHomeOwner(sig *AISignal, path string) {
	if sig == nil || sig.UserID != "" {
		return
	}
	if owner, ok := s.homeOwnerForPath(path); ok {
		sig.UserID, sig.UserName = owner.UserID, owner.UserName
	}
}

// attributeProcessOwners gives each process the account whose profile holds
// its executable. The service cannot open other accounts' processes, so the
// token owner is unknown, but the image path is not: per-user agents run
// from the user's profile (~\.local\bin\claude.exe, ~\.codex\...\codex.exe).
// A node process outside every profile takes the owner of the nearest
// attributed ancestor, the agent that launched it.
func (s *ContinuousDiscoveryService) attributeProcessOwners(procs []processInfo) {
	if len(s.opts.homeOwners) == 0 {
		return
	}
	byPID := make(map[int]int, len(procs))
	for i := range procs {
		byPID[procs[i].PID] = i
		if owner, ok := s.homeOwnerForPath(procs[i].Image); ok {
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
