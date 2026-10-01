//go:build !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

// Only macOS has a local requirements layer above the system file (MDM
// managed preferences); cloud-managed requirements are not visible locally.
func platformCodexHigherSources(Options) (map[string][]byte, error) { return nil, nil }
