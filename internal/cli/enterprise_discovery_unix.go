//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// pinEnterpriseDiscoveryEnv points root's discovery view at the standalone
// deployment's config, as the policy commands do (GAP-1144).
func pinEnterpriseDiscoveryEnv() error { return pinStandaloneManagedEnv() }

// platformDiscoveryAccountIDs resolves a qualified --user to its uid the way
// profile-explain and policy show do: NSS, taking an answer in another
// spelling only when it is the same account (unixidentity.LookupAccountSpelling).
func platformDiscoveryAccountIDs(user string) []string {
	user = strings.TrimSpace(user)
	if !useridentity.QualifiedAccountName(user) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	account, err := unixidentity.LookupAccountSpelling(unixidentity.Default(ctx), user, unixidentity.DirectoryFactsFunc(ctx))
	if err != nil {
		return nil
	}
	return []string{strconv.Itoa(account.UID)}
}

// platformDiscoveryAccountName names Windows accounts only.
func platformDiscoveryAccountName(string) string { return "" }
