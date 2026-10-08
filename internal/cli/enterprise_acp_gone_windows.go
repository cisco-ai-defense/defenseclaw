//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// removeEnterpriseACPUserCopyAsUser removes one recorded user copy as its
// signed-in user (GAP-0718); false while the user is signed out. A profile
// folder that is gone leaves nothing to remove.
func removeEnterpriseACPUserCopyAsUser(entry acp.EnterpriseUserCopyCleanup) (bool, error) {
	home := filepath.Clean(strings.TrimSpace(entry.UserHome))
	if !filepath.IsAbs(home) {
		return false, fmt.Errorf("user home %q is not absolute", entry.UserHome)
	}
	expected, err := acp.EnterpriseUserTokenPath(filepath.Join(home, ".defenseclaw"), entry.ClientID, entry.AgentID)
	if relative, relErr := filepath.Rel(home, entry.TokenFile); err != nil || relErr != nil ||
		relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) ||
		!strings.EqualFold(filepath.Base(entry.TokenFile), filepath.Base(expected)) {
		return false, fmt.Errorf("%s is not an ACP token copy in %s", entry.TokenFile, home)
	}
	if _, err := os.Lstat(home); errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	err = enterprisehooks.RunAsTarget(enterprisehooks.TargetCredentials{UserHome: home, UID: -1, GID: -1, SID: entry.SID}, func() error {
		return removeEnterpriseACPUserTokenCopy(entry.TokenFile)
	})
	if enterpriseACPSignedOut(err) {
		return false, nil
	}
	return err == nil, err
}

// enterpriseACPLookupWindowsAccount is replaceable in tests.
var enterpriseACPLookupWindowsAccount = gateway.LookupWindowsAccount

// enterpriseACPDescribePrincipal names the account of a sid:S principal
// through the LSA and its profile through ProfileList.
var enterpriseACPDescribePrincipal = func(principal string) (enterpriseACPAccount, error) {
	kind, sid, _ := strings.Cut(principal, ":")
	if kind != "sid" || sid == "" {
		return enterpriseACPAccount{}, fmt.Errorf("%s names no account", principal)
	}
	_, name, err := enterpriseACPLookupWindowsAccount(sid)
	if err != nil {
		if !enterpriseACPUnknownAccount(err) {
			return enterpriseACPAccount{}, err
		}
		// ERROR_NONE_MAPPED is the LSA's definitive deleted-account result.
		return enterpriseACPAccount{sid: sid, uid: -1, gid: -1}, nil
	}
	return enterpriseACPAccount{exists: true, name: name, home: useridentity.HomeForID(sid), sid: sid, uid: -1, gid: -1}, nil
}

// enterpriseACPHomeForUID: --uid applies only on Linux and macOS.
var enterpriseACPHomeForUID = func(int) (string, bool, error) {
	return "", false, errors.New("--uid applies only on Linux and macOS")
}
