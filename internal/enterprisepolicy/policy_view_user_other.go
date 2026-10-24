// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package enterprisepolicy

import "github.com/defenseclaw/defenseclaw/internal/managed"

func PolicyViewUserPins(Options, string) (map[string]managed.PolicyViewFilePin, error) {
	return nil, nil
}
