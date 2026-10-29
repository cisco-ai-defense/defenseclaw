// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package managed

import "path/filepath"

// EnsureCanonical has no Windows descriptors to stamp on this platform.
func EnsureCanonical(path string, kind ObjectKind, _ CanonicalOptions) (CanonicalResult, error) {
	return CanonicalResult{Path: filepath.Clean(path), Kind: kind, Outcome: CanonicalUnsupported}, nil
}

// AssessCanonical has no Windows descriptors to read on this platform.
func AssessCanonical(path string, kind ObjectKind, _ CanonicalOptions) (CanonicalResult, error) {
	return CanonicalResult{Path: filepath.Clean(path), Kind: kind, Outcome: CanonicalUnsupported}, nil
}
