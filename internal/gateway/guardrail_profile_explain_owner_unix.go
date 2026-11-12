// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// profileExplainAccountID resolves an explain --user spelling to its uid
// for the per-user owner check (perUserExplainRefusal) and nothing else:
// no directory facts, no same-name search and no cache entry for another
// account. A qualified spelling NSS answers under another name is matched
// with directory facts only when the answer is the owner's own uid.
var profileExplainAccountID = func(name, ownerID string) (string, error) {
	name = strings.TrimSpace(name)
	if uid, err := strconv.Atoi(name); err == nil && uid >= 0 {
		return strconv.Itoa(uid), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), profileExplainLookupTimeout)
	defer cancel()
	account, err := unixidentity.LookupAdminAccountSpelling(profileExplainResolver(ctx), name, func(uid int) (useridentity.DirectoryFacts, bool) {
		if strconv.Itoa(uid) != ownerID {
			return useridentity.DirectoryFacts{}, false
		}
		facts, err := profileExplainDirectoryFacts(ownerID)
		return facts, err == nil
	})
	if err != nil {
		return "", err
	}
	return strconv.Itoa(account.UID), nil
}
