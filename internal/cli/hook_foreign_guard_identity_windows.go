//go:build windows

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
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// currentHookAccountIdentity is the hook's account as the gateway names a
// caller authenticated by its per-user credential: the token user's SID.
func currentHookAccountIdentity() (string, bool) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		return "", false
	}
	return connector.CanonicalUserScopedIdentity(user.User.Sid.String())
}
