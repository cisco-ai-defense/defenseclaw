// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !darwin

package enterpriseunix

import "errors"

// processExecPath is used only on macOS; Linux reads /proc/<pid>/exe.
func processExecPath(int) (string, error) {
	return "", errors.New("process executable path is read from /proc on this OS")
}
