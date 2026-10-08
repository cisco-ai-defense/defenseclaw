//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// enterpriseACPDescribePrincipal names the account of a sid:S principal
// through the LSA and its profile through ProfileList.
var enterpriseACPDescribePrincipal = func(principal string) (enterpriseACPAccount, error) {
	kind, sid, _ := strings.Cut(principal, ":")
	if kind != "sid" || sid == "" {
		return enterpriseACPAccount{}, fmt.Errorf("%s names no account", principal)
	}
	_, name, err := gateway.LookupWindowsAccount(sid)
	if err != nil {
		// The LSA cannot name a deleted account's SID.
		return enterpriseACPAccount{sid: sid, uid: -1, gid: -1}, nil
	}
	return enterpriseACPAccount{exists: true, name: name, home: useridentity.HomeForID(sid), sid: sid, uid: -1, gid: -1}, nil
}

// enterpriseACPHomeForUID: --uid applies only on Linux and macOS.
var enterpriseACPHomeForUID = func(int) (string, bool, error) {
	return "", false, errors.New("--uid applies only on Linux and macOS")
}
