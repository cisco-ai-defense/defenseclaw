//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

// enterpriseHookPlatformWatchFiles adds nothing off Windows: the Copilot
// VS Code Local hook file is a Windows standalone file.
func enterpriseHookPlatformWatchFiles(string, string) (dirs, files []string) { return nil, nil }
