// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// enterpriseHookPeerHomesFileMax and enterpriseHookPeerAccountsMax bound the
// gateway homes file the guardian reads, as the gateway bounds it
// (managedHookPeerHomesFileMax), and the accounts it takes from it
// (managedHookPeerHomesMax).
const (
	enterpriseHookPeerHomesFileMax = 4 << 20
	enterpriseHookPeerAccountsMax  = 16384
)

// enterpriseHookGatewayPeerAccounts lists the accounts whose hook calls the
// managed gateway has served (the uids of its managed_peer_homes.json in
// dataDir) and whose account incarnation does not tell one account of a
// name, uid and home path from another (not a SID: a local or LDAP
// account). On a host whose gateway accepts every account (a machine-policy
// connector) the guardian enrolls none of them, so it wrote no identity
// record, and the gateway had no proof of their homes: a local account
// deleted and created again under the same name and uid got the agent
// identities of the account before it, which the first inventory view also
// listed (FC-BLK-167-ER, GAP-0422). The file only names which uids the
// guardian resolves; every fact comes from the account database and the
// guardian's own stat of the home. Tests replace it.
//
// The account lookups run again only when the homes file or the local
// account database (enterpriseHookLocalAccountsStamp) changes, or once per
// enterpriseHookIdentitySpoolInterval; each tick only stats the homes, so a
// recreated home still changes the key at the next tick. The gateway does
// not rewrite the homes file when a served account is deleted, so without
// the account database stamp a deleted local account stayed listed from the
// cache until the interval: every pass failed its lookup and the failed
// pass kept its record (GAP-1864, RHEL leg). A uid the lookup budget did not
// reach, or whose lookup or home stat failed this time, keeps its last
// answer, so the spool fingerprint does not flap on a host with many served
// accounts (GAP-1866).
var enterpriseHookGatewayPeerAccounts = func(dataDir string) []enterpriseHookPeerAccount {
	if strings.TrimSpace(dataDir) == "" {
		return nil
	}
	path := filepath.Join(dataDir, "managed_peer_homes.json")
	info, err := os.Stat(path)
	if err != nil {
		enterpriseHookPeerListing.reset()
		return nil
	}
	stamp := enterpriseHookLocalAccountsStamp()
	l := &enterpriseHookPeerListing
	l.Lock()
	defer l.Unlock()
	if l.path != path || l.size != info.Size() || !l.mtime.Equal(info.ModTime()) || l.stamp != stamp ||
		time.Since(l.at) >= enterpriseHookIdentitySpoolInterval || time.Since(l.at) < 0 {
		last := l.accounts
		if l.path != path {
			last = nil
		}
		l.accounts = enterpriseHookResolveGatewayPeers(path, last)
		l.path, l.size, l.mtime, l.stamp, l.at = path, info.Size(), info.ModTime(), stamp, time.Now()
	}
	uids := make([]int, 0, len(l.accounts))
	for uid := range l.accounts {
		uids = append(uids, uid)
	}
	sort.Ints(uids)
	peers := make([]enterpriseHookPeerAccount, 0, len(uids))
	for _, uid := range uids {
		peer := l.accounts[uid]
		if inode := enterpriseHookHomeInode(peer.home); inode != 0 {
			peer.HomeInode = inode
			l.accounts[uid] = peer
		}
		peers = append(peers, peer.enterpriseHookPeerAccount)
	}
	return peers
}

// enterpriseHookPeerListing keeps the last answer of each served account
// (enterpriseHookGatewayPeerAccounts).
var enterpriseHookPeerListing enterpriseHookPeerCache

type enterpriseHookPeerCache struct {
	sync.Mutex
	path     string
	size     int64
	mtime    time.Time
	stamp    string
	at       time.Time
	accounts map[int]enterpriseHookCachedPeer
}

type enterpriseHookCachedPeer struct {
	enterpriseHookPeerAccount
	home string
}

func (l *enterpriseHookPeerCache) reset() {
	l.Lock()
	defer l.Unlock()
	l.path, l.accounts = "", nil
}

// enterpriseHookResolveGatewayPeers resolves the uids of the homes file at
// path. A uid the account database answers no account holds is dropped; one
// it did not answer for keeps its entry in last. Tests replace it.
var enterpriseHookResolveGatewayPeers = func(path string, last map[int]enterpriseHookCachedPeer) map[int]enterpriseHookCachedPeer {
	data, err := safefile.ReadRegularFileBounded(path, enterpriseHookPeerHomesFileMax)
	if err != nil {
		return last
	}
	var stored map[string]json.RawMessage
	if json.Unmarshal(data, &stored) != nil {
		return last
	}
	legacyFile := true
	if raw, ok := stored["format"]; ok {
		var format struct {
			Format int `json:"format"`
		}
		legacyFile = json.Unmarshal(raw, &format) == nil && format.Format < 1
	}
	var savedAt int64
	if info, statErr := os.Stat(path); statErr == nil {
		savedAt = info.ModTime().UnixNano()
	}
	// The file's mtime is the last time a gateway wrote it for any uid:
	// 1.0.3 and 1.0.4 write no first_seen and save the file at another
	// account's first hook, which can come after an account was deleted and
	// created again. The uid's last hook in the agent ledger bounds the
	// sighting too, as the gateway bounds it (loadHomesLocked, GAP-1947): an
	// account created after that hook did not make it, so it is no 1.0.3
	// holder and the first map does not bind it (GAP-2024). Read once, and
	// only when an entry needs it. A uid with no row there ran no hook in
	// the ledger's row window, whose start then bounds it (GAP-2069); the
	// window is the configured retention the prune uses (GAP-2106).
	var lastHooks map[int]int64
	var rowWindow time.Duration
	lastHooksRead := false
	lastHook := func(uid int) int64 {
		now := time.Now()
		if !lastHooksRead {
			lastHooks, lastHooksRead = enterpriseHookAgentLastHooks(filepath.Dir(path)), true
			if lastHooks != nil {
				rowWindow = inventory.AgentLedgerRowWindow(enterpriseHookAgentLedgerRetentionDays(), now)
			}
		}
		return inventory.AgentLedgerSightingBound(lastHooks, uid, now, rowWindow)
	}
	// preToken reports whether the account that holds uid now, whose home
	// is home, is the one a build before 1.0.4 saw hold it, with no 1.0.4
	// gateway serving the uid since then (enterpriseHookPeerAccount.PreToken).
	preToken := func(uid int, home string) bool {
		var entry struct {
			BaseIncarnation string `json:"base_incarnation"`
			LegacyHolder    bool   `json:"legacy_holder"`
			PreTokenHolder  bool   `json:"pre_token_holder"`
			FirstSeen       int64  `json:"first_seen"`
		}
		if json.Unmarshal(stored[strconv.Itoa(uid)], &entry) != nil {
			return false
		}
		unserved := entry.PreTokenHolder || (legacyFile || entry.LegacyHolder) && strings.TrimSpace(entry.BaseIncarnation) == ""
		if !unserved {
			return false
		}
		// A home created after the gateway last saw the uid's holder
		// belongs to an account created after it, which held no 1.0.3
		// agent identity (GAP-1977). The 2 s slack is the gateway's
		// (homeProofCreatedSlack).
		seen := entry.FirstSeen
		if seen <= 0 {
			seen = savedAt
			if at := lastHook(uid); at > 0 && (seen <= 0 || at < seen) {
				seen = at
			}
		}
		birth, known := enterprisehooks.HomeBirth(home)
		return !known || seen <= 0 || birth <= seen+int64(2*time.Second)
	}
	uids := make([]int, 0, len(stored))
	for key := range stored {
		if uid, err := strconv.Atoi(key); err == nil && uid > 0 && strconv.Itoa(uid) == key {
			uids = append(uids, uid)
		}
	}
	sort.Ints(uids)
	if len(uids) > enterpriseHookPeerAccountsMax {
		uids = uids[:enterpriseHookPeerAccountsMax]
	}
	resolved := make(map[int]enterpriseHookCachedPeer, len(uids))
	keep := func(uid int) {
		if peer, ok := last[uid]; ok {
			peer.PreToken = peer.PreToken && preToken(uid, peer.home)
			resolved[uid] = peer
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resolver, err := unixidentity.NewNSSResolver(ctx)
	for _, uid := range uids {
		if err != nil || ctx.Err() != nil {
			keep(uid)
			continue
		}
		account, lookupErr := resolver.LookupUID(uid)
		switch {
		case errors.Is(lookupErr, unixidentity.ErrNotFound):
			continue
		case lookupErr != nil || account.UID != uid || account.Name == "":
			keep(uid)
			continue
		}
		incarnation, known := resolver.AccountIncarnation(uid, account.Name)
		switch {
		case !known:
			keep(uid)
			continue
		case strings.HasPrefix(incarnation, "sid:"):
			continue
		}
		peer := enterpriseHookCachedPeer{enterpriseHookPeerAccount{UID: uid, User: account.Name, HomeInode: enterpriseHookHomeInode(account.Home),
			PreToken: preToken(uid, account.Home)}, account.Home}
		if previous, ok := last[uid]; ok && peer.HomeInode == 0 && previous.User == peer.User {
			peer.HomeInode = previous.HomeInode
		}
		resolved[uid] = peer
	}
	return resolved
}

// enterpriseHookAgentLastHooks is, per uid, the last hook the gateway's
// agent ledger in dataDir recorded (inventory.ReadAgentLastHooks, read only);
// nil when it cannot be read. Tests replace it.
var enterpriseHookAgentLastHooks = func(dataDir string) map[int]int64 {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	hooks, err := inventory.ReadAgentLastHooks(ctx, filepath.Join(dataDir, "inventory.db"))
	if err != nil {
		return nil
	}
	return hooks
}

// enterpriseHookAgentLedgerRetentionDays is the effective
// observability.local.retention_days of the machine config, the window the
// gateway's ledger prune keeps rows for (GAP-2106); the default when the
// config cannot be compiled. Tests replace it.
var enterpriseHookAgentLedgerRetentionDays = func() int {
	loaded, err := loadConfigV8Source(config.ConfigPath(), config.DefaultDataPath(), "", true)
	if err != nil || loaded == nil || loaded.compiled == nil || loaded.compiled.Plan == nil {
		return config.ObservabilityV8DefaultRetentionDays
	}
	return loaded.compiled.Plan.Snapshot().Local.RetentionDays
}

// enterpriseHookHomeRoots are the directories that hold the homes of the
// accounts the last identity spool listed: the reconcile's rows and the
// served accounts (enterpriseHookNoteHomeRoots).
var enterpriseHookHomeRoots atomic.Pointer[[]string]

// enterpriseHookNoteHomeRoots records the directories that hold the homes of
// the reconcile's rows and of the served accounts the last listing named.
func enterpriseHookNoteHomeRoots(rows []enterpriseHookReconcileRow) {
	set := map[string]bool{}
	note := func(home string) {
		if filepath.IsAbs(home) && filepath.Clean(home) != "/" {
			set[filepath.Dir(filepath.Clean(home))] = true
		}
	}
	for _, row := range rows {
		note(row.UserHome)
	}
	l := &enterpriseHookPeerListing
	l.Lock()
	for _, peer := range l.accounts {
		note(peer.home)
	}
	l.Unlock()
	roots := make([]string, 0, len(set))
	for root := range set {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	enterpriseHookHomeRoots.Store(&roots)
}

// enterpriseHookHomeRootsStamp is the modification time and inode of each
// directory in enterpriseHookHomeRoots. A directory (SSSD, LDAP) account
// without a SID deleted and created again under the same name, uid and home
// path changes no file the gateway can read, and its earlier holder's home
// proof stayed current until the guardian's next one-minute tick. Removing
// and creating its home changes the directory that holds it, so the watch
// loop reconciles within seconds and the pass rewrites the record with the
// new home's proof (GAP-2028). Tests replace it.
var enterpriseHookHomeRootsStamp = func() string {
	roots := enterpriseHookHomeRoots.Load()
	if roots == nil {
		return ""
	}
	var stamp strings.Builder
	for _, root := range *roots {
		stamp.WriteString(";")
		info, err := os.Stat(root)
		if err != nil {
			continue
		}
		stamp.WriteString(strconv.FormatInt(info.ModTime().UnixNano(), 10))
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			stamp.WriteString("/" + strconv.FormatUint(uint64(st.Ino), 10))
		}
	}
	return stamp.String()
}

// enterpriseHookAccountIncarnationLookup names the account that holds a uid
// now, by unixidentity's AccountIncarnation (the SID SSSD or winbind holds
// for a directory account), for one reconcile tick; nil when NSS cannot be
// read. Tests replace it.
var enterpriseHookAccountIncarnationLookup = func(ctx context.Context) func(uid int, user string) (string, bool) {
	resolver, err := unixidentity.NewNSSResolver(ctx)
	if err != nil {
		return nil
	}
	return resolver.AccountIncarnation
}

// enterpriseHookLocalAccountsStamp is enterprisehooks.LocalAccountsStamp.
// Tests replace it.
var enterpriseHookLocalAccountsStamp = func() string { return enterprisehooks.LocalAccountsStamp() }

// enterpriseHookHomeInode is the inode of home, 0 when it is not an
// absolute path to a directory the guardian can stat.
func enterpriseHookHomeInode(home string) uint64 {
	if !filepath.IsAbs(home) {
		return 0
	}
	info, err := os.Stat(home)
	if err != nil || !info.IsDir() {
		return 0
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}
