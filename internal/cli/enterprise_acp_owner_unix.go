//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
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
	if err := repairEnterpriseACPLegacyLock(dataDir, int(stat.Uid), int(stat.Gid)); err != nil {
		return err
	}
	return enterpriseACPRunAsAccount(int(stat.Uid), int(stat.Gid), fn)
}

// Earlier builds left this persistent lock owned by root even after handing
// the ACP directory to the service account. Change only that exact legacy
// file, by descriptor, before dropping root privileges.
func repairEnterpriseACPLegacyLock(dataDir string, uid, gid int) error {
	lockDir := filepath.Join(dataDir, "acp")
	dir, err := os.Lstat(lockDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("enterprise ACP: inspect credential directory: %w", err)
	}
	dirOwner, ok := dir.Sys().(*syscall.Stat_t)
	if !dir.IsDir() || !ok || int(dirOwner.Uid) != uid {
		return fmt.Errorf("enterprise ACP: credential directory has an unexpected owner")
	}
	path := filepath.Join(lockDir, ".enterprise-credentials.lock")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("enterprise ACP: inspect credential lock: %w", err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || owner.Nlink != 1 || info.Size() != 0 || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("enterprise ACP: credential lock is not a private empty regular file")
	}
	if int(owner.Uid) == uid {
		return nil
	}
	if owner.Uid != 0 {
		return fmt.Errorf("enterprise ACP: credential lock has an unexpected owner")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("enterprise ACP: open legacy credential lock: %w", err)
	}
	defer syscall.Close(fd)
	var opened syscall.Stat_t
	if err := syscall.Fstat(fd, &opened); err != nil {
		return err
	}
	named, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, named) || opened.Ino != owner.Ino || opened.Dev != owner.Dev {
		return fmt.Errorf("enterprise ACP: credential lock changed during owner repair")
	}
	if err := syscall.Fchown(fd, uid, gid); err != nil {
		return fmt.Errorf("enterprise ACP: repair credential lock owner: %w", err)
	}
	return nil
}

// alignEnterpriseACPCredentialOwner has nothing to do on Unix: the data_dir
// owner writes the records itself (withEnterpriseACPServiceOwner), with the
// 0600 and 0700 modes safefile gives them.
func alignEnterpriseACPCredentialOwner(_, _, _, _, _, _ string) error { return nil }

// enterpriseACPUnknownAccount reports an account name no account database
// knows.
func enterpriseACPUnknownAccount(err error) bool {
	var unknown user.UnknownUserError
	return errors.As(err, &unknown) || unixidentity.IsNotFound(err)
}

// enterpriseACPNoAccountText is the refusal for an unknown account name.
func enterpriseACPNoAccountText(name string) string {
	return "enterprise acp: no account named " + name + " on this computer"
}

// enterpriseACPNoHomeText is the refusal for an account whose home does not
// exist; it was a raw lstat error (GAP-0687).
func enterpriseACPNoHomeText(who, home, _ string) string {
	return fmt.Sprintf("enterprise acp: %s has no home directory (%s does not exist), so there is nowhere to publish "+
		"the ACP token; create the home or enroll another account", who, home)
}

// configureEnterpriseACPTargetLookup turns on the standalone Unix account
// rules the enterprise hooks commands use, including the directory lookup
// for accounts the static gateway cannot find in /etc/passwd (GAP-0269).
func configureEnterpriseACPTargetLookup() {
	configureEnterpriseHooksStandaloneUnix()
}

// enterpriseACPTargetError returns err: the Unix refusals already name the
// account and what is wrong with it.
func enterpriseACPTargetError(err error) error { return err }
