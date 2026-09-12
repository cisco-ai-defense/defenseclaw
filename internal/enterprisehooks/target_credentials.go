// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

// TargetCredentials identifies one exact interactive user for a bounded
// privileged mutation. ACP enrollment reuses the hook guardian's hardened
// setuid/impersonation boundary rather than granting the gateway user-home
// access.
type TargetCredentials struct {
	UserHome string
	UID      int
	GID      int
	SID      string
}

// RunAsTarget validates target identity and executes fn with the target user's
// effective filesystem identity. Platform implementations fail closed when a
// privileged process cannot prove the requested identity.
func RunAsTarget(target TargetCredentials, fn func() error) error {
	return runAsTarget(target, fn)
}
