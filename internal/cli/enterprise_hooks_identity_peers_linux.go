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
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

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
var enterpriseHookGatewayPeerAccounts = func(dataDir string) []enterpriseHookPeerAccount {
	if strings.TrimSpace(dataDir) == "" {
		return nil
	}
	data, err := safefile.ReadRegularFileBounded(filepath.Join(dataDir, "managed_peer_homes.json"), enterpriseHookPeerHomesFileMax)
	if err != nil {
		return nil
	}
	var stored map[string]json.RawMessage
	if json.Unmarshal(data, &stored) != nil {
		return nil
	}
	uids := make([]int, 0, len(stored))
	for key := range stored {
		if uid, err := strconv.Atoi(key); err == nil && uid > 0 && strconv.Itoa(uid) == key {
			uids = append(uids, uid)
		}
	}
	if len(uids) == 0 {
		return nil
	}
	sort.Ints(uids)
	if len(uids) > enterpriseHookPeerAccountsMax {
		uids = uids[:enterpriseHookPeerAccountsMax]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resolver, err := unixidentity.NewNSSResolver(ctx)
	if err != nil {
		return nil
	}
	var peers []enterpriseHookPeerAccount
	for _, uid := range uids {
		if ctx.Err() != nil {
			break
		}
		account, err := resolver.LookupUID(uid)
		if err != nil || account.UID != uid || account.Name == "" {
			continue
		}
		if incarnation, known := resolver.AccountIncarnation(uid, account.Name); !known || strings.HasPrefix(incarnation, "sid:") {
			continue
		}
		peers = append(peers, enterpriseHookPeerAccount{UID: uid, User: account.Name, HomeInode: enterpriseHookHomeInode(account.Home)})
	}
	return peers
}

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
