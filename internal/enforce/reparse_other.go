// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enforce

import (
	"io/fs"
	"os"
)

func fileInfoIsLinkOrReparse(info fs.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}
