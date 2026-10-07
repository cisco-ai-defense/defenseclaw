// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// peerDirectoryLookupTimeout bounds one background resolution (the getent
// calls), well beyond the hot-path budget a waiting request uses. A cold SSSD
// names a group in about 30 ms, so an account in 400 groups needs up to twelve
// seconds when SSSD answers one lookup at a time; a lookup that still runs
// out fails as a whole and is retried (GAP-0138). `guardrail profile
// explain` waits for this lookup, so its client timeout stays above it.
const peerDirectoryLookupTimeout = 20 * time.Second

// resolvePeerDirectoryFacts resolves a verified uid's facts through NSS and
// merges the guardian's identity spool record for it.
func resolvePeerDirectoryFacts(key string) (useridentity.DirectoryFacts, error) {
	uid, err := strconv.Atoi(key)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	now := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), peerDirectoryLookupTimeout)
	defer cancel()
	resolver, err := unixidentity.NewNSSResolver(ctx)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	account, err := resolver.LookupUID(uid)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	facts, err := resolver.DirectoryFactsForUID(uid, now)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	if record, ok := readIdentitySpoolFactsForAccount(key, account.Name, now); ok {
		facts = mergeSpoolFacts(facts, record.Facts)
	}
	return facts, nil
}
