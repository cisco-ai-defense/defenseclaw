//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// userScopedIdentityName names the account a per-user credential is bound
// to through the same platform account database the hook socket uses.
var userScopedIdentityName = func(identity string) string {
	if useridentity.KindForID(identity) != useridentity.KindPOSIXUID {
		return ""
	}
	uid, err := strconv.Atoi(identity)
	if err != nil {
		return ""
	}
	return managedHookPeerName(uid)
}

// userScopedIdentityForName is the uid of the account an account name names
// now through the platform account database, or false when none has it.
var userScopedIdentityForName = func(name string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	account, err := unixidentity.Default(ctx).LookupUser(strings.TrimSpace(name))
	if err != nil {
		return "", false
	}
	return connector.CanonicalUserScopedIdentity(strconv.Itoa(account.UID))
}

// userScopedIdentityHome is the home of the account a per-user credential is
// bound to, resolved like a hook-socket caller's home, or "".
var userScopedIdentityHome = func(identity string) string {
	if useridentity.KindForID(identity) != useridentity.KindPOSIXUID {
		return ""
	}
	uid, err := strconv.Atoi(identity)
	if err != nil {
		return ""
	}
	return managedHookPeerHome(uid)
}

// agentIdentityAccountName names the account that holds a uid for the uid's
// agent identity: the account database's name, or while a lookup fails (a
// directory outage) the last name the uid resolved to, which a managed
// gateway keeps across restarts with the uid's home (GAP-0314). "" for a
// uid that never resolved.
var agentIdentityAccountName = func(identity string) string {
	if useridentity.KindForID(identity) != useridentity.KindPOSIXUID {
		return ""
	}
	uid, err := strconv.Atoi(identity)
	if err != nil {
		return ""
	}
	if name := userScopedIdentityName(identity); name != "" {
		managedHookPeerHomes.rememberName(uid, name)
		return name
	}
	return managedHookPeerHomes.lastName(uid)
}

// agentIdentityAccountToken is the account token an agent identity row of
// a uid is recorded with (managedHookPeerHomeCache.rowToken), "" for a SID
// or a uid no token was ever known for. Tests replace it.
var agentIdentityAccountToken = func(identity string) string {
	if useridentity.KindForID(identity) != useridentity.KindPOSIXUID {
		return ""
	}
	uid, err := strconv.Atoi(identity)
	if err != nil {
		return ""
	}
	return managedHookPeerHomes.rowToken(uid)
}

// agentIdentityVerifiedAccountToken names only the account proven to hold the
// uid now. Inventory must not use rowToken's last-known fallback as proof of
// ownership when the account lookup is unavailable.
var agentIdentityVerifiedAccountToken = func(identity string) string {
	if useridentity.KindForID(identity) != useridentity.KindPOSIXUID {
		return ""
	}
	uid, err := strconv.Atoi(identity)
	if err != nil {
		return ""
	}
	token, known := managedHookPeerHomes.accountToken(uid)
	if !known {
		return ""
	}
	return token
}

// agentIdentityHolderHistory is the last account token of a uid and whether
// another account is known to have held it (managedHookPeerHomeCache.holderHistory).
// Tests replace it.
var agentIdentityHolderHistory = func(identity string) (string, bool) {
	if useridentity.KindForID(identity) != useridentity.KindPOSIXUID {
		return "", false
	}
	uid, err := strconv.Atoi(identity)
	if err != nil {
		return "", false
	}
	return managedHookPeerHomes.holderHistory(uid)
}

// agentIdentityIncarnation is the account incarnation a uid's agent identity
// is keyed on besides its account name (managedHookPeerHomeCache.agentIncarnation):
// "" for the first account this gateway saw hold the uid. Tests replace it.
var agentIdentityIncarnation = func(identity string) string {
	if useridentity.KindForID(identity) != useridentity.KindPOSIXUID {
		return ""
	}
	uid, err := strconv.Atoi(identity)
	if err != nil {
		return ""
	}
	return managedHookPeerHomes.agentIncarnation(uid)
}
