//go:build !windows && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// repairEnterpriseHookManagedRuntimePlatform is a no-op on this platform.
// Managed runtime drift here is an ownership/mode question the POSIX
// validators already answer, and there is no ACL template to reapply.
func repairEnterpriseHookManagedRuntimePlatform(string, string) error { return nil }

// repairEnterpriseHookGatewayDataPathsPlatform is a no-op on this platform.
func repairEnterpriseHookGatewayDataPathsPlatform() {}

// repairEnterpriseHookGuardianLedgerObjectPlatform is not supported here.
// POSIX ledgers are protected by root ownership and modes the writer
// re-applies.
func repairEnterpriseHookGuardianLedgerObjectPlatform(string, bool) error {
	return errors.New("hook guardian ledger repair is not supported on this platform")
}

// repairEnterpriseHookManifestACL is a no-op; targets.yaml has no descriptor
// to re-stamp on this platform.
func repairEnterpriseHookManifestACL(string) error {
	return nil
}

// The service tokens are re-stamped by their align step on this platform.
func repairEnterpriseHookScopedTokenPlatform(string, string) {}

func repairEnterpriseOTLPTokenPlatform(string, connector.OTLPPathTokenScope) {}

// enterpriseHookTokenOwnerPlatform is the owner a service token is aligned
// to: the managed data_dir owner, which is the packaged service account.
func enterpriseHookTokenOwnerPlatform(st *syscall.Stat_t) (int, int) {
	return int(st.Uid), int(st.Gid)
}
