// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import "os"

func openEnterpriseHookBoundedFile(path string) (*os.File, error) { return os.Open(path) }
