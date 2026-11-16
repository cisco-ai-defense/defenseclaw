// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

func enterpriseHookAccountOwnedDataDirLinkPlatform(string, string) bool { return false }

func enterpriseHookForeignDataDirLinkPlatform(string, string) bool { return false }
