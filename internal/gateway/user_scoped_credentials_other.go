//go:build !linux && !darwin

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

import "github.com/defenseclaw/defenseclaw/internal/useridentity"

// userScopedIdentityName names the account a per-user credential is bound
// to: the SID's account on Windows.
var userScopedIdentityName = useridentity.NameForID

// userScopedIdentityHome is the profile directory of the account a per-user
// credential is bound to (the SID's ProfileList entry on Windows), or "".
var userScopedIdentityHome = useridentity.HomeForID

// setManagedHookPeerHomeStore persists nothing on Windows: a profile path
// comes from the SID's ProfileList entry, not from a directory lookup.
func setManagedHookPeerHomeStore(string) {}
