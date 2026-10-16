// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !darwin

package enterpriseunix

import "errors"

func readProcessArgv(int) ([]string, error) {
	return nil, errors.New("kern.procargs2 is available only on macOS")
}
