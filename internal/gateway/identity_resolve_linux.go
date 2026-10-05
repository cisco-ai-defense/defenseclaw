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
// calls), well beyond the hot-path budget a waiting request uses.
const peerDirectoryLookupTimeout = 10 * time.Second

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
	facts, err := resolver.DirectoryFactsForUID(uid, now)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	if record, ok := readIdentitySpoolFacts(key, now); ok {
		facts = mergeSpoolFacts(facts, record.Facts)
	}
	return facts, nil
}
