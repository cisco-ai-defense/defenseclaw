// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "github.com/defenseclaw/defenseclaw/internal/config"

// configValidateRequiredSandboxPacks: Windows runs no sandboxes. It is kept
// out of the *_windows.go files, which another owner keeps (GAP-1811).
func configValidateRequiredSandboxPacks(*config.Config) error { return nil }
