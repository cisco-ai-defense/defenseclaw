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

// DiscoverCMIDLibrary has nothing to find off Windows: the version-nested
// layout it walks is Secure Client for Windows, and other platforms'
// providers resolve their own library.
func DiscoverCMIDLibrary() string { return "" }
