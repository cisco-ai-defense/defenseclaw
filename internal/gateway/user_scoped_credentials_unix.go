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
	"strconv"

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
