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

package cli

import "context"

// rulePackServiceReadProblem: the Windows gateway runs as LocalSystem, which
// reads any pack an administrator can.
func rulePackServiceReadProblem(context.Context, string) string { return "" }
