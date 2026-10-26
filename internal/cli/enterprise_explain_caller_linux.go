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
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// enterpriseExplainCallerFacts resolves the account profile-explain names
// as the caller, root, through NSS: getpwnam or getpwuid, the account's
// groups, and the directory proofs only root can run (sssctl, sssd.conf).
// It returns the caller_facts value for the explain route, "" when the
// caller is not root or NSS does not resolve the account; the gateway's own
// lookup is the fallback (GAP-0500). Tests replace it.
var enterpriseExplainCallerFacts = func(user string) string {
	user = strings.TrimSpace(user)
	if user == "" || os.Geteuid() != 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resolver, err := unixidentity.NewNSSResolver(ctx)
	if err != nil {
		return ""
	}
	var account unixidentity.Account
	if uid, convErr := strconv.Atoi(user); convErr == nil && uid >= 0 {
		account, err = resolver.LookupUID(uid)
	} else {
		account, err = resolver.LookupUser(user)
	}
	if err != nil || account.Name == "" {
		return ""
	}
	facts, err := resolver.DirectoryFactsForUID(account.UID, time.Now())
	if err != nil {
		return ""
	}
	value, err := gateway.EncodeProfileExplainCallerFacts(gateway.ProfileExplainCallerFacts{UID: account.UID, Name: account.Name, Facts: facts})
	if err != nil {
		return ""
	}
	return value
}

// enterpriseIdentityViewHolderProof is the holder_proof of the agent
// identity view for the account user names: <uid>:<the proof of its home>
// (enterprisehooks.LegacyAgentOwnerToken), which the caller, root, reads
// through NSS and stat as the guardian does. The gateway cannot stat a home
// under ProtectHome, and the guardian rewrites its identity records at its
// next pass, so the first view after a local account was deleted and created
// again under the same name and uid listed the agent identities of the
// account before it (T8r, GAP-0422), by its name or its uid (GAP-1876). ""
// when the caller is not root, user is a SID, NSS does not resolve it, or its
// account incarnation is a SID, which tells accounts apart already. Tests
// replace it.
var enterpriseIdentityViewHolderProof = func(user string) string {
	user = strings.TrimSpace(user)
	kind := useridentity.KindForID(user)
	if user == "" || os.Geteuid() != 0 || kind != "" && kind != useridentity.KindPOSIXUID {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resolver, err := unixidentity.NewNSSResolver(ctx)
	if err != nil {
		return ""
	}
	var account unixidentity.Account
	if kind == useridentity.KindPOSIXUID {
		uid, convErr := strconv.Atoi(user)
		if convErr != nil {
			return ""
		}
		account, err = resolver.LookupUID(uid)
	} else {
		account, err = resolver.LookupUser(user)
	}
	if err != nil || account.UID <= 0 || account.Name == "" {
		return ""
	}
	incarnation, known := resolver.AccountIncarnation(account.UID, account.Name)
	if !known || strings.HasPrefix(incarnation, "sid:") {
		return ""
	}
	token := enterprisehooks.LegacyAgentOwnerToken(incarnation, account.Home)
	if !strings.HasPrefix(token, "home:") {
		return ""
	}
	return strconv.Itoa(account.UID) + ":" + token
}
