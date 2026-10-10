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

package sensor

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

// How a finding was tied to an account (Finding.Attribution).
const (
	// AttributionProcessOwner is the owner the process probe read: the
	// process token, the Win32_Process owner, or the POSIX process owner.
	AttributionProcessOwner = "process_owner"
	// AttributionSession is the user signed in to the Windows session the
	// process runs in.
	AttributionSession = "session"
	// AttributionEnrolledProfile is the enrolled account whose profile holds
	// the configuration files the agent wrote.
	AttributionEnrolledProfile = "enrolled_profile"
	// AttributionUnattributed is a host-wide finding no lookup could tie to
	// an account. It is never filled in with another account's identity.
	AttributionUnattributed = "unattributed"
)

// Account is one enrolled account of the enrolled-user table.
type Account struct {
	// Name is DOMAIN\name, or COMPUTER\name for a local Windows account.
	Name string
	SID  string
	// Home is the account's profile folder.
	Home string
}

// OwnerLookups are the account sources consulted after the owner the
// process probe read itself. A nil lookup is skipped.
type OwnerLookups struct {
	// SessionUser names the account signed in to a Windows session, or
	// returns empty strings.
	SessionUser func(session uint32) (name, sid string)
	// Accounts returns the enrolled-user table.
	Accounts func() []Account
}

// owner is the account a finding is attributed to, or why it is not.
type owner struct {
	User, SID, Attribution, Reason string
}

// ownerResolver attributes the findings of one poll. None of its lookups
// needs more than the gateway service already has: the managed Windows
// service account holds only SeChangeNotifyPrivilege, and nothing here
// widens an ACL to make a lookup succeed.
type ownerResolver struct {
	lookups  OwnerLookups
	byPID    map[int]procprobe.Process
	accounts []Account
	sessions map[uint32]owner
}

func newOwnerResolver(lookups OwnerLookups, processes []procprobe.Process) *ownerResolver {
	resolver := &ownerResolver{
		lookups:  lookups,
		byPID:    make(map[int]procprobe.Process, len(processes)),
		sessions: map[uint32]owner{},
	}
	for _, process := range processes {
		resolver.byPID[process.PID] = process
	}
	if lookups.Accounts != nil {
		resolver.accounts = lookups.Accounts()
	}
	return resolver
}

// resolve attributes a finding whose processes are pids (the finding's own
// process first, then the rest of its agent session) and whose agent wrote
// configPaths. In order: (a) the owner the probe read for one of the
// processes, (b) the user signed in to the Windows session one of them
// runs in, (c) the one enrolled account whose profile holds the agent's
// configuration files. A finding none of them names is unattributed and
// host-wide.
func (r *ownerResolver) resolve(pids []int, configPaths []string) owner {
	seen := false
	for _, pid := range pids {
		process, ok := r.byPID[pid]
		if !ok {
			continue
		}
		seen = true
		if process.UserSID != "" || process.User != "" {
			return r.named(process.User, process.UserSID, AttributionProcessOwner)
		}
	}
	if r.lookups.SessionUser != nil {
		for _, pid := range pids {
			if process, ok := r.byPID[pid]; ok && process.SessionID != 0 {
				if found := r.sessionOwner(process.SessionID); found.SID != "" {
					return found
				}
			}
		}
	}
	if found, ok := r.profileOwner(configPaths); ok {
		return found
	}
	reason := "the process owner could not be read (process token, Win32_Process owner and session user) " +
		"and no enrolled profile holds the agent's configuration"
	if !seen {
		reason = "the finding's processes are no longer in the process table " +
			"and no enrolled profile holds the agent's configuration"
	}
	return owner{Attribution: AttributionUnattributed, Reason: reason}
}

// named qualifies an owner with the enrolled table's DOMAIN\name for its
// SID, which also names an owner whose SID the LSA could not translate.
func (r *ownerResolver) named(user, sid, attribution string) owner {
	for _, account := range r.accounts {
		if sid != "" && account.Name != "" && strings.EqualFold(account.SID, sid) {
			user = account.Name
			break
		}
	}
	return owner{User: user, SID: sid, Attribution: attribution}
}

func (r *ownerResolver) sessionOwner(session uint32) owner {
	if cached, ok := r.sessions[session]; ok {
		return cached
	}
	name, sid := r.lookups.SessionUser(session)
	found := owner{}
	if sid != "" {
		found = r.named(name, sid, AttributionSession)
	}
	r.sessions[session] = found
	return found
}

// profileOwner is the enrolled account whose profile holds the agent's
// configuration files. Paths in more than one profile name no account, and
// paths outside every profile (a project's AGENTS.md) say nothing.
func (r *ownerResolver) profileOwner(paths []string) (owner, bool) {
	var found *Account
	for _, path := range paths {
		account := r.accountForPath(path)
		switch {
		case account == nil:
			continue
		case found != nil && !strings.EqualFold(found.SID, account.SID):
			return owner{}, false
		}
		found = account
	}
	if found == nil || found.SID == "" {
		return owner{}, false
	}
	return owner{User: found.Name, SID: found.SID, Attribution: AttributionEnrolledProfile}, true
}

// accountForPath returns the account whose profile folder holds path, the
// deepest one when profiles nest. Comparison ignores case and separator
// style, as Windows paths do.
func (r *ownerResolver) accountForPath(path string) *Account {
	path = normalizeOwnerPath(path)
	var best *Account
	bestLength := 0
	for index := range r.accounts {
		home := strings.TrimRight(normalizeOwnerPath(r.accounts[index].Home), "/")
		if home == "" || len(home) <= bestLength {
			continue
		}
		if path == home || strings.HasPrefix(path, home+"/") {
			best, bestLength = &r.accounts[index], len(home)
		}
	}
	return best
}

func normalizeOwnerPath(path string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path), `\`, "/"))
}
