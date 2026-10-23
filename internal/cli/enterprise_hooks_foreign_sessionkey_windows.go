//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

// enterpriseForeignHookRunsAsAdministrator reports a guardian running as
// SYSTEM or an elevated administrator, the only accounts whose protected
// session record key the gateway and the hook accept.
func enterpriseForeignHookRunsAsAdministrator() bool { return windowsEnterpriseIsElevated() }
