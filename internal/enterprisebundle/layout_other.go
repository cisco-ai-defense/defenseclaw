//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import "github.com/defenseclaw/defenseclaw/internal/managed"

// Layout is the standalone layout of goos. The Windows layout is resolved
// only on Windows, from that computer's protected registration.
func Layout(goos string) (managed.StandaloneLayout, error) {
	return managed.StandaloneLayoutFor(goos)
}
