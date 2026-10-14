//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import "github.com/defenseclaw/defenseclaw/internal/managed"

// Layout is the standalone layout of goos. On Windows the layout of this
// computer is resolved from the protected HKLM Program Files and ProgramData
// registration, never from the caller environment.
func Layout(goos string) (managed.StandaloneLayout, error) {
	if goos == "windows" {
		return managed.StandaloneWindowsLayout()
	}
	return managed.StandaloneLayoutFor(goos)
}
