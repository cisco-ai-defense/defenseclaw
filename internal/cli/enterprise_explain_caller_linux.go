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

	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
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
