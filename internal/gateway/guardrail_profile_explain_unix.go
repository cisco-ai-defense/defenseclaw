// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// profileExplainLookupTimeout bounds the NSS account lookup of explain.
const profileExplainLookupTimeout = 10 * time.Second

// profileExplainAccount names an account (name or uid) through NSS, so
// directory accounts resolve even where os/user reads only the local files.
func profileExplainAccount(name string) (id, userName string, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), profileExplainLookupTimeout)
	defer cancel()
	resolver, err := unixidentity.NewNSSResolver(ctx)
	if err != nil {
		return "", "", false
	}
	account, err := resolver.LookupUser(name)
	if err != nil {
		uid, convErr := strconv.Atoi(name)
		if convErr != nil {
			return "", "", false
		}
		if account, err = resolver.LookupUID(uid); err != nil {
			return "", "", false
		}
	}
	return strconv.Itoa(account.UID), sanitizeLLMEventUser(account.Name), true
}

// profileExplainDirectoryFacts resolves the facts a verified request from
// uid carries: NSS plus the guardian identity spool.
func profileExplainDirectoryFacts(id string) (useridentity.DirectoryFacts, error) {
	return resolvePeerDirectoryFacts(id)
}
