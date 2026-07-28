// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookruntime

import "errors"

func CurrentUserPaths() (Paths, error) {
	return Paths{}, errors.New("stable native hook runtime is Windows-only")
}
