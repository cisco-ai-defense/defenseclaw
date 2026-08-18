// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

// DiscoverCMIDLibrary walks the Cisco Secure Client install to find the
// newest Cloud Management identity library present on the machine. The full
// version-nested walk lands with the Windows enterprise Setup work; until
// then this returns "", so the managed cloud auth provider falls back to its
// built-in default and callers skip the trust check.
func DiscoverCMIDLibrary() string { return "" }
