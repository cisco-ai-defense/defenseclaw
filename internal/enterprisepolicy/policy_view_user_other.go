// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package enterprisepolicy

func PolicyViewUserPins(Options, string) (map[string]string, []string, error) {
	return nil, nil, nil
}
