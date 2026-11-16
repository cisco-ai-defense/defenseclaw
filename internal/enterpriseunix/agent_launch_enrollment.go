// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// launchEnrollment is the set of accounts whose agent launches count toward
// managed coverage: the accounts the deployment enrolls. An account that
// enterprise.enrollment excludes or exempts, or that no filter admits, is
// not protected by design, so its launches neither lower status and verify
// nor reach the audit. When the published enrollment cannot be read, every
// account is treated as enrolled.
type launchEnrollment struct {
	// known: the enumerator's published enrollment was read.
	known bool
	uids  map[int]bool
	// users and homes are manifest targets that name no uid.
	users, homes map[string]bool
	// notEnrolled are exclude_users and exempt_users entries: an account
	// name or a decimal uid, as the enumerator matches them.
	notEnrolled map[string]bool
}

// launchEnrollment reads who the deployment enrolls: the enabled targets of
// the manifest and, outside manifest enrollment, every account the
// enumerator found eligible (its eligible and identity-only accounts). A
// machine-policy connector gets no rows while unenrolled users are
// inspected, so the rows alone do not name every enrolled account. Under manifest enrollment the enumerator is idle and the
// eligible-accounts record is stale: the manifest is the enrollment.
func (env *Env) launchEnrollment(cfg *config.Config) launchEnrollment {
	e := launchEnrollment{uids: map[int]bool{}, users: map[string]bool{}, homes: map[string]bool{}, notEnrolled: map[string]bool{}}
	if cfg == nil {
		return e
	}
	enrollment := cfg.Enterprise.Enrollment
	for _, name := range append(append([]string{}, enrollment.ExcludeUsers...), enrollment.ExemptUsers...) {
		if name = strings.TrimSpace(name); name != "" {
			e.notEnrolled[name] = true
		}
	}
	manifest, err := enterprisehooks.LoadStandaloneManifest(env.P(env.Layout.ManifestPath))
	if err != nil {
		return e
	}
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		switch user, home := strings.TrimSpace(target.User), strings.TrimSpace(target.UserHome); {
		case target.UID != nil:
			e.uids[*target.UID] = true
		case user != "":
			e.users[user] = true
		case filepath.IsAbs(home):
			e.homes[filepath.Clean(home)] = true
		}
	}
	if strings.EqualFold(strings.TrimSpace(enrollment.Mode), config.EnterpriseEnrollmentManifest) {
		e.known = true
		return e
	}
	data, err := readBounded(env.P(enterprisehooks.UnixEligibleAccountsPath(env.Layout.ManifestPath)), maxInputBytes)
	if err != nil {
		return e
	}
	type account struct {
		UID int `json:"uid"`
	}
	var record struct {
		Version      int       `json:"version"`
		Accounts     []account `json:"accounts"`
		IdentityOnly []account `json:"identity_only"`
	}
	if json.Unmarshal(data, &record) != nil || record.Version != 1 {
		return e
	}
	for _, account := range append(record.Accounts, record.IdentityOnly...) {
		if account.UID > 0 {
			e.uids[account.UID] = true
		}
	}
	e.known = true
	return e
}

// covers reports whether the process owner uid is an enrolled account.
// account resolves its name and home, only when an entry needs them.
func (e launchEnrollment) covers(uid int, account func() (string, string)) bool {
	if e.notEnrolled[strconv.Itoa(uid)] {
		return false
	}
	byUID := !e.known || e.uids[uid]
	byName := e.known && !byUID && len(e.users)+len(e.homes) > 0
	if len(e.notEnrolled) == 0 && !byName {
		return byUID
	}
	user, home := account()
	if e.notEnrolled[user] {
		return false
	}
	return byUID || e.users[user] || (home != "" && e.homes[filepath.Clean(home)])
}
