// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "github.com/defenseclaw/defenseclaw/internal/enterprisehooks"

func enterpriseHookAccountOwnedDataDirLinkPlatform(home, sid string) bool {
	return enterprisehooks.WindowsAccountOwnedDataDirLink(home, sid)
}

func enterpriseHookForeignDataDirLinkPlatform(home, sid string) bool {
	return enterprisehooks.WindowsForeignOwnedDataDirLink(home, sid)
}
