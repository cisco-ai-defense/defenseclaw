// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package cli

// enterpriseExplainCallerFacts resolves nothing here: the macOS and Windows
// gateways resolve the account through Open Directory and the LSA themselves.
var enterpriseExplainCallerFacts = func(string) string { return "" }
