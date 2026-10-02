// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package cli

// copilotCLIMachinePolicyInForce: Windows keeps the gateway's Copilot
// dedupe for the CLI's second delivery.
func copilotCLIMachinePolicyInForce() bool { return false }
