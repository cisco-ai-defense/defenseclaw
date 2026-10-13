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

package kernelpolicy

// tryLock has nothing to guard on Windows: Tetragon is Linux only, and the
// package exists on Windows only so the rest of the tree builds.
func tryLock(Dirs) (func(), error) { return func() {}, nil }
