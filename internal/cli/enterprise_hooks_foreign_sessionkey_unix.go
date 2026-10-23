//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import "os"

// enterpriseForeignHookRunsAsAdministrator reports a guardian running as
// root, the only account whose protected session record key the gateway
// and the hook accept.
func enterpriseForeignHookRunsAsAdministrator() bool { return os.Geteuid() == 0 }
