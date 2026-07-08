//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package safefile

import "os"

// Agent Control service packaging is Linux/macOS-only in v1. Windows keeps
// the non-symlink, regular-file, bounded-read, and identity-swap checks.
func validateReadOwnerAndLinks(_ os.FileInfo) error { return nil }
