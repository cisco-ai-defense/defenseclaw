//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// include_users makes an account a candidate and skips its uid and shell
// checks, but rows are per installed agent. A local account named there
// with no agent installed was left out with no account-level reason, so it
// looked as if include_users ignored local accounts on a directory-bound
// Mac (rel-1-0-6:GAP-0290). It is now named in the skipped list. An
// included account with an agent is enrolled even outside the uid range;
// an account outside it that include_users does not name is not.
func TestEnumerateUnixIncludeUsersNamesAnIncludedAccountWithoutAgent(t *testing.T) {
	for _, tc := range []struct {
		name     string
		inRange  bool
		wantRows string
		noted    []string
	}{
		// Every account in the interactive range: the automatic filters
		// pass them all, so rows follow the installed agents.
		{name: "in range", inRange: true, wantRows: "named/codex,unnamed/codex", noted: []string{"bare"}},
		// Every account below the range, as a macOS local account below 501:
		// only include_users makes one a candidate.
		{name: "below range", inRange: false, wantRows: "named/codex", noted: []string{"bare"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := trustedTestDir(t)
			homes := filepath.Join(root, "Users")
			if err := os.MkdirAll(homes, 0o755); err != nil {
				t.Fatal(err)
			}
			uid, gid := os.Getuid(), os.Getgid()
			names := []string{"bare", "named", "other", "unnamed"}
			accounts := map[string]unixidentity.Account{}
			for _, name := range names {
				accounts[name] = unixidentity.Account{Name: name, UID: uid, GID: gid, Home: makeHome(t, homes, name), Shell: "/bin/zsh"}
			}
			installed := map[string]bool{"named": true, "unnamed": true}
			uidMin := uid
			if !tc.inRange {
				uidMin = uid + 1
			}
			opts := UnixEnumerateOptions{
				Resolver:  &fakeResolver{accounts: accounts, listed: names},
				HomeRoots: []string{homes},
				UIDMin:    uidMin, UIDMax: uid + 2,
				DiscoverSurfaces: func(_ context.Context, account unixidentity.Account, _ []string) (UnixDiscovery, error) {
					if installed[account.Name] {
						return UnixDiscovery{Versions: map[string]string{"codex": "0.150.0"}}, nil
					}
					return UnixDiscovery{Reasons: map[string]string{"codex": "no codex installation found for this user"}}, nil
				},
			}
			cfg := enumeratorConfig("codex")
			cfg.Enterprise.Enrollment.IncludeUsers = []string{"named", "bare"}
			manifest, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, target := range manifest.Targets {
				got = append(got, target.User+"/"+target.Connector)
			}
			if strings.Join(got, ",") != tc.wantRows {
				t.Fatalf("rows = %v, want %s (skipped: %v)", got, tc.wantRows, report.Skipped)
			}
			const note = ": named in enterprise.enrollment.include_users but not enrolled: no installation of codex found for this account; it is enrolled on the next cycle after one is installed in it"
			var noted []string
			for _, skipped := range report.Skipped {
				if strings.Contains(skipped, "include_users") {
					noted = append(noted, skipped)
				}
			}
			var want []string
			for _, name := range tc.noted {
				want = append(want, name+note)
			}
			if strings.Join(noted, "|") != strings.Join(want, "|") {
				t.Fatalf("include_users notes = %q, want %q", noted, want)
			}
		})
	}
}

// A worker that failed, or a cycle whose discovery time ran out, inspected
// nothing: an included account must not be told it has no agent installed
// while it is reported as install_scan_incomplete.
func TestEnumerateUnixIncludeUsersNoteNeedsAnInspectedAccount(t *testing.T) {
	for _, tc := range []struct {
		name     string
		budget   time.Duration
		discover UnixDiscoverSurfacesFunc
	}{
		{name: "worker error", discover: func(context.Context, unixidentity.Account, []string) (UnixDiscovery, error) {
			return UnixDiscovery{}, errors.New("worker exited with status 1")
		}},
		// The budget is spent before the first account is inspected, so the
		// wrapper answers errUnixDiscoveryBudgetSpent without calling discover.
		{name: "budget spent", budget: time.Nanosecond, discover: func(context.Context, unixidentity.Account, []string) (UnixDiscovery, error) {
			return UnixDiscovery{Reasons: map[string]string{"codex": "no codex installation found for this user"}}, nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := trustedTestDir(t)
			homes := filepath.Join(root, "Users")
			if err := os.MkdirAll(homes, 0o755); err != nil {
				t.Fatal(err)
			}
			uid, gid := os.Getuid(), os.Getgid()
			accounts := map[string]unixidentity.Account{
				"bare": {Name: "bare", UID: uid, GID: gid, Home: makeHome(t, homes, "bare"), Shell: "/bin/zsh"},
			}
			opts := UnixEnumerateOptions{
				Resolver:         &fakeResolver{accounts: accounts, listed: []string{"bare"}},
				HomeRoots:        []string{homes},
				UIDMin:           uid,
				UIDMax:           uid + 1,
				DiscoveryBudget:  tc.budget,
				DiscoverSurfaces: tc.discover,
			}
			cfg := enumeratorConfig("codex")
			cfg.Enterprise.Enrollment.IncludeUsers = []string{"bare"}
			manifest, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
			if err != nil {
				t.Fatal(err)
			}
			if len(manifest.Targets) != 0 {
				t.Fatalf("rows = %v, want none", manifest.Targets)
			}
			for _, skipped := range report.Skipped {
				if strings.Contains(skipped, "include_users") {
					t.Fatalf("an account that was not inspected got the include_users note: %q", skipped)
				}
			}
			incomplete := false
			for _, agent := range report.Unprotected {
				if agent.User == "bare" && agent.Code == UnprotectedCodeInstallScanIncomplete {
					incomplete = true
				}
			}
			if !incomplete {
				t.Fatalf("the account must stay reported as install_scan_incomplete: %+v", report.Unprotected)
			}
		})
	}
}
