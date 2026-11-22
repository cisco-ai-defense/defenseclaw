// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookcli

import (
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const (
	// WindowsEnterpriseMarkerKey is read by the per-user installers
	// (scripts/install.ps1, `defenseclaw upgrade`) to refuse a per-user
	// install on a managed host.
	WindowsEnterpriseMarkerKey = managed.WindowsEnterpriseMarkerKey
)
