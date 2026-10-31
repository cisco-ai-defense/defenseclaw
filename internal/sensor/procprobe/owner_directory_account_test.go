// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package procprobe

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// directoryAccounts answers like NSS on an AD-joined host with SSSD: the
// directory account's uid is not in /etc/passwd, its name is qualified.
type directoryAccounts struct {
	unixidentity.Resolver
	accounts map[int]unixidentity.Account
	offline  bool
	calls    int
}

func (d *directoryAccounts) LookupUID(uid int) (unixidentity.Account, error) {
	d.calls++
	if d.offline {
		return unixidentity.Account{}, errors.New("sssd does not answer")
	}
	if account, ok := d.accounts[uid]; ok {
		return account, nil
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

func useDirectoryAccounts(t *testing.T, accounts *directoryAccounts) {
	t.Helper()
	previous := ownerAccounts
	ownerAccounts = func(context.Context) unixidentity.Resolver { return accounts }
	userCache = sync.Map{}
	t.Cleanup(func() { ownerAccounts = previous; userCache = sync.Map{} })
}

// rel-1-0-6 GAP-0184: the process of an AD account (SSSD, uid 94404116, not
// in /etc/passwd) had no owner because the static gateway read /etc/passwd
// only, so its runtime finding was unattributed. The owner is now named
// through the account database (NSS).
func TestProcessOwnerOfADirectoryAccountIsNamedThroughNSS(t *testing.T) {
	const adUID = 94404116
	accounts := &directoryAccounts{accounts: map[int]unixidentity.Account{
		adUID:       {Name: "eng1@corp.example", UID: adUID, GID: adUID, Home: "/home/eng1@corp.example"},
		os.Getuid(): {Name: "lane-local", UID: os.Getuid(), Home: "/home/lane-local"},
	}}
	useDirectoryAccounts(t, accounts)
	now := time.Now()
	if got := ownerName(adUID, now); got != "eng1@corp.example" {
		t.Fatalf("owner of AD uid %d = %q, want the name NSS gives", adUID, got)
	}
	// A process directory owned by this test's uid goes the same way.
	if got := ownerOf(t.TempDir()); got != "lane-local" {
		t.Fatalf("ownerOf(dir of uid %d) = %q, want the account database's name", os.Getuid(), got)
	}
	calls := accounts.calls
	_ = ownerName(adUID, now.Add(time.Hour))
	if accounts.calls != calls {
		t.Fatal("a found owner was looked up again; it is cached")
	}
	if got := ownerName(12345678, now); got != "" {
		t.Fatalf("owner of a uid no account holds = %q, want none", got)
	}
}

// A directory that does not answer names no owner now and is asked again
// after ownerRetryAfter; an answer is never replaced by another account.
func TestProcessOwnerLookupRetriesAnOfflineDirectory(t *testing.T) {
	const adUID = 94404117
	accounts := &directoryAccounts{offline: true, accounts: map[int]unixidentity.Account{
		adUID: {Name: "eng2@corp.example", UID: adUID, Home: "/home/eng2@corp.example"},
	}}
	useDirectoryAccounts(t, accounts)
	now := time.Now()
	if got := ownerName(adUID, now); got != "" {
		t.Fatalf("owner while the directory is offline = %q, want none", got)
	}
	accounts.offline = false
	if got := ownerName(adUID, now.Add(ownerRetryAfter/2)); got != "" {
		t.Fatalf("owner before the retry = %q, want the cached miss", got)
	}
	if got := ownerName(adUID, now.Add(ownerRetryAfter+time.Second)); got != "eng2@corp.example" {
		t.Fatalf("owner after the retry = %q, want the directory's answer", got)
	}
}
