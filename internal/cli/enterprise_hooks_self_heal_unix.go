// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

// repairEnterpriseHookManagedInstallPlatform is Windows-only: there is no
// installer ACL template or SCM descriptor to restore on this platform.
func repairEnterpriseHookManagedInstallPlatform() {}
