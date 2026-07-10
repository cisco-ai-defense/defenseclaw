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
func setEnterpriseHookAuthorizationOwnership(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	serviceUser, err := user.Lookup("defenseclaw")
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(serviceUser.Gid)
	if err != nil {
		return err
	}
	return os.Chown(path, 0, gid)
}
