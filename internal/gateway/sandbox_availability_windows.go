// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import "io/fs"

// sandboxPathAccess is never consulted on Windows, where sandboxes don't
// run (sandboxAvailabilityProbe.check answers first); it grants nothing.
func sandboxPathAccess(string, int) sandboxDeviceAccess {
	return sandboxDeviceAccess{State: sandboxDeviceDenied}
}

// sandboxRecordTrusted is never consulted on Windows either; it trusts
// nothing.
var sandboxRecordTrusted = func(fs.FileInfo) bool { return false }
