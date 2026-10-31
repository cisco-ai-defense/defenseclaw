// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "github.com/spf13/cobra"

// newEnterpriseSecretCheckCommand is not registered on Windows: there, read
// inspection.ai_defense from `enterprise windows status`.
func newEnterpriseSecretCheckCommand() *cobra.Command { return nil }
