// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

func identityRefreshPlatformPrivileged() bool { return windowsEnterpriseIsElevated() }

// identityRefreshPlatformResolveUser resolves --user through the LSA.
func identityRefreshPlatformResolveUser(user string) (string, string, error) {
	id, name, err := gateway.LookupWindowsAccount(user)
	if err != nil {
		return "", "", fmt.Errorf("no account %q on this computer (%v); --user takes the account name, DOMAIN\\name, .\\name or the SID", user, err)
	}
	return id, name, nil
}

// identityRefreshPlatformFlushOSCache flushes nothing: an account takes its
// groups from its sign-in token, which changes at its next sign-in only.
func identityRefreshPlatformFlushOSCache(string) (identityRefreshFlush, *enterprisestatus.Message) {
	return identityRefreshFlush{Flushed: "none", Reason: "windows_token_groups"}, nil
}
