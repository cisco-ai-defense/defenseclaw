// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// outageAccountHome is this account's home folder from the account database
// (getpwuid), never from HOME: the folder the installer's default
// DEFENSECLAW_HOME (~/.defenseclaw) is in. It is "" when the lookup fails
// (an account the database does not list), and then only the folders
// hookOutageInstallHeld reads from the environment stand in for it. A
// variable for tests.
var outageAccountHome = func() string {
	account, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil || account == nil || !filepath.IsAbs(account.HomeDir) {
		return ""
	}
	return filepath.Clean(account.HomeDir)
}

// outageInstalledDataRoot is the data root of the installed runtime's
// protected install state. Linux and macOS per-user installs keep none, so
// install.sh holds a data_dir set apart from DEFENSECLAW_HOME itself
// (hold_hook_data_dir). A variable for tests.
var outageInstalledDataRoot = func() (string, bool) { return "", false }

// outageHomeEnvNames are the home variables whose ~/.defenseclaw
// hookOutageInstallHeld also looks in.
var outageHomeEnvNames = []string{"HOME"}
