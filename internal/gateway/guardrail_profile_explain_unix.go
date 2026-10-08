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

// profileExplainLookupTimeout bounds the account lookup of explain.
const profileExplainLookupTimeout = 10 * time.Second

// profileExplainAccount names an account (name or uid) through the platform
// resolver the hook path uses: NSS on Linux, so directory accounts resolve
// even where os/user reads only the local files, and Open Directory on macOS,
// which has no getent.
var profileExplainAccount = func(name string) (id, userName string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), profileExplainLookupTimeout)
	defer cancel()
	resolver := unixidentity.Default(ctx)
	// name@domain and DOMAIN\name resolve as getent resolves them, when the
	// answer is the same account (GAP-0711).
	account, err := unixidentity.LookupAccountSpelling(resolver, name, func(uid int) (useridentity.DirectoryFacts, bool) {
		facts, err := profileExplainDirectoryFacts(strconv.Itoa(uid))
		return facts, err == nil
	})
	if err != nil {
		uid, convErr := strconv.Atoi(name)
		if convErr != nil {
			return "", "", err
		}
		if account, err = resolver.LookupUID(uid); err != nil {
			return "", "", err
		}
	}
	return strconv.Itoa(account.UID), sanitizeLLMEventUser(account.Name), nil
}

// profileExplainUnresolved resolves an account the platform resolver cannot
// name through the OS account database (os/user), with its error.
func profileExplainUnresolved(name string, _ error) (profileSubject, error) {
	return lookupLocalProfileSubject(name)
}

// profileExplainDirectoryFacts resolves the facts a verified request from
// uid carries: the account database plus the guardian identity spool.
var profileExplainDirectoryFacts = func(id string) (useridentity.DirectoryFacts, error) {
	return resolvePeerDirectoryFacts(id)
}
