// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !darwin

package enterpriseunix

import "errors"

func readProcessArgv(int) ([]string, error) {
	return nil, errors.New("kern.procargs2 is available only on macOS")
}

func readProcessEnv(int) (map[string]string, error) {
	return nil, errors.New("kern.procargs2 is available only on macOS")
}

func readProcessParent(int) (int, error) {
	return 0, errors.New("kern.proc.pid is read only on macOS; Linux reads /proc/<pid>/stat")
}
