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
	"os"
	"os/user"
	"strconv"
)

// setEnterpriseHookAuthorizationOwnership keeps the root-written guardian
// authorization record readable by the unprivileged defenseclaw gateway while
// excluding unrelated local users. Non-root development/test invocations keep
// their existing ownership and are still protected by the 0750/0640 modes.
//
// On installs where the daemon runs as root (managed_enterprise on macOS
// since the CMID switch — the shipped plist omits UserName/GroupName so
// launchd defaults to uid 0), there is no defenseclaw service user. The
// authorization file is already root-owned 0640, which root can read; the
// service-user chgrp is a leftover from the pre-root era and must not fail
// the whole reconcile when the user is absent.
func setEnterpriseHookAuthorizationOwnership(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	serviceUser, err := user.Lookup("defenseclaw")
	if err != nil {
		// No service user on this host — the daemon runs as root and
		// reads the 0640 file via its owner bit. Nothing to align.
		if _, ok := err.(user.UnknownUserError); ok {
			return nil
		}
		return err
	}
	gid, err := strconv.Atoi(serviceUser.Gid)
	if err != nil {
		return err
	}
	return os.Chown(path, 0, gid)
}
