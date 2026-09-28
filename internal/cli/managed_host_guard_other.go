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

package cli

// managedHostWindowsStandalone is Windows-only; unix hosts use the runtime
// descriptor.
var managedHostWindowsStandalone = func() (string, bool) { return "", false }

// managedHostRecordTrusted accepts every record outside Windows: the unix
// descriptor lives in a root-owned directory no standard user can write.
var managedHostRecordTrusted = func(string) error { return nil }
