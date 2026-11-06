// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package cli

import "os"

func enterpriseHookOwnedFileChangeTime(os.FileInfo) [2]int64 {
	return [2]int64{}
}
