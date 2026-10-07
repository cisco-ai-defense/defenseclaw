//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// Seams for tests.
var (
	enterpriseACPEUID         = os.Geteuid
	enterpriseACPRunAsAccount = enterprisehooks.RunAsAccount
)

// withEnterpriseACPServiceOwner runs a change to the service-side ACP
// credentials as the account that owns the managed data_dir, the account
// whose gateway reads them. On a standalone host that is the gateway service
// account. Root used to write the records and then hand them to that
// account; safefile then refused roots next write into the accounts
// directory, so a standalone host could enroll only one user (GAP-0251).
// A root-owned data_dir (Secure Client) and a caller that is not root run fn
// unchanged.
func withEnterpriseACPServiceOwner(dataDir string, fn func() error) error {
	if enterpriseACPEUID() != 0 {
		return fn()
	}
	info, err := os.Stat(dataDir)
	if err != nil {
		return fmt.Errorf("enterprise ACP: inspect managed data_dir owner: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("enterprise ACP: cannot inspect managed data_dir owner")
	}
	if stat.Uid == 0 {
		return fn()
	}
	return enterpriseACPRunAsAccount(int(stat.Uid), int(stat.Gid), fn)
}

// alignEnterpriseACPCredentialOwner has nothing to do on Unix: the data_dir
// owner writes the records itself (withEnterpriseACPServiceOwner), with the
// 0600 and 0700 modes safefile gives them.
func alignEnterpriseACPCredentialOwner(_, _, _, _, _, _ string) error { return nil }

// configureEnterpriseACPTargetLookup turns on the standalone Unix account
// rules the enterprise hooks commands use, including the directory lookup
// for accounts the static gateway cannot find in /etc/passwd (GAP-0269).
func configureEnterpriseACPTargetLookup(ctx context.Context) {
	configureEnterpriseHooksStandaloneUnix(ctx)
}

// enterpriseACPTargetError returns err: the Unix refusals already name the
// account and what is wrong with it.
func enterpriseACPTargetError(err error) error { return err }
