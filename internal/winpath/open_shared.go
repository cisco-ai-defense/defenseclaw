// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package winpath

import "io"

// ReadFileShared is os.ReadFile through OpenReadShared.
func ReadFileShared(path string) ([]byte, error) {
	file, err := OpenReadShared(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}
