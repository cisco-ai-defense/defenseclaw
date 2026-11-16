// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package enterprisepolicy

import "os"

// fileChangeStamp has no change time to add here: the policy-view proof
// runs on Linux and macOS only.
func fileChangeStamp(os.FileInfo) string { return "" }
