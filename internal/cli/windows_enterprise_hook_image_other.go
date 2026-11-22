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
	"errors"
	"io/fs"
)

// windowsHookImageAccessDenied reports an open or read the caller's token
// was refused (fs.ErrPermission here; on Windows also STATUS_ACCESS_DENIED).
func windowsHookImageAccessDenied(err error) bool { return errors.Is(err, fs.ErrPermission) }

// windowsHookImageSharingViolation is Windows' ERROR_SHARING_VIOLATION;
// other systems have no such refusal (the decisions run in their tests with
// fs.ErrPermission).
func windowsHookImageSharingViolation(error) bool { return false }
