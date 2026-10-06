// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// repairEnterpriseHookManagedRuntimePlatform is a no-op off Windows. Managed
// runtime drift there is an ownership/mode question the POSIX validators already
// answer, and there is no ACL template for the guardian to reapply.
func repairEnterpriseHookManagedRuntimePlatform(string, string) error { return nil }

func validateEnterpriseHookScopedTokenLocation(dataDir, connectorName string) error {
	tokenPath, err := connector.HookAPITokenFilePath(dataDir, connectorName)
	if err != nil {
		return err
	}
	return validateEnterpriseHookTokenPathLocation(dataDir, tokenPath, "hook token")
}

func alignEnterpriseHookScopedTokenOwner(dataDir, connectorName string) error {
	tokenPath, err := connector.HookAPITokenFilePath(dataDir, connectorName)
	if err != nil {
		return err
	}
	return alignEnterpriseHookTokenPathOwner(dataDir, tokenPath, "hook token")
}

func validateEnterpriseHookUserTokenKeyLocation(dataDir string) error {
	keyPath, err := connector.UserScopedTokenKeyPath(dataDir)
	if err != nil {
		return err
	}
	return validateEnterpriseHookTokenPathLocation(dataDir, keyPath, "per-user credential key")
}

// loadEnterpriseHookPendingUserTokenKey reads the key a credential rotation
// staged (connector.PendingUserScopedTokenKeyPath), with the committed key's
// location and trust checks; "" when no rotation is preparing it. The
// guardian renders from a staged key only while the rotation's root-only
// transaction record is in its prepare phase and names that key as next and
// the committed key as previous (enterprisehooks.CredentialTransaction): the
// key files live in the service account's data directory, so a staged key
// alone authorizes nothing, and a rolling-back rotation moves every target
// back to the committed key.
func loadEnterpriseHookPendingUserTokenKey(dataDir string) (string, error) {
	path, err := connector.PendingUserScopedTokenKeyPath(dataDir)
	if err != nil {
		return "", err
	}
	if err := validateEnterpriseHookTokenPathLocation(dataDir, path, "staged per-user credential key"); err != nil {
		return "", err
	}
	key, err := connector.LoadPendingUserScopedTokenKey(dataDir)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: %w", err)
	}
	if key == "" {
		return "", nil
	}
	transaction, err := loadEnterpriseHookCredentialTransaction(dataDir)
	if err != nil || transaction == nil {
		return "", nil
	}
	committed, err := connector.LoadUserScopedTokenKey(dataDir)
	if err != nil || committed == "" ||
		!transaction.RendersNext(connector.UserScopedTokenKeyFingerprint(committed), connector.UserScopedTokenKeyFingerprint(key)) {
		return "", nil
	}
	return key, nil
}

// loadEnterpriseHookCredentialTransaction reads the root-only record of the
// credential rotation in progress; nil when there is none. A record that
// fails its custody (a regular 0600 file of the guardian's own account in
// the trusted authorization directory) or schema check is an error.
func loadEnterpriseHookCredentialTransaction(dataDir string) (*enterprisehooks.CredentialTransaction, error) {
	dir := managed.HookGuardianAuthorizationDir(dataDir)
	path := filepath.Join(dir, managed.HookGuardianCredentialTransactionFile)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: inspect the credential transaction: %w", err)
	}
	if err := enterpriseHookAuthorizationDirTrustCheck(dir); err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("enterprise hooks: the credential transaction record is not a 0600 file of the guardian's account")
	}
	data, err := readEnterpriseHookBoundedFile(path, info, enterprisehooks.CredentialTransactionMaxBytes, "credential transaction")
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: %w", err)
	}
	transaction, err := enterprisehooks.ParseCredentialTransaction(data)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: %w", err)
	}
	return &transaction, nil
}

// currentEnterpriseHookUserTokenKeyID is the fingerprint of the key targets
// are rendered from right now: a rotation's staged key while the guardian's
// prepare record names it, else the committed one; "" when neither exists
// yet.
func currentEnterpriseHookUserTokenKeyID(dataDir string) (string, error) {
	key, err := loadEnterpriseHookPendingUserTokenKey(dataDir)
	if err == nil && key == "" {
		if err = validateEnterpriseHookUserTokenKeyLocation(dataDir); err == nil {
			key, err = connector.LoadUserScopedTokenKey(dataDir)
		}
	}
	if err != nil || key == "" {
		return "", err
	}
	return connector.UserScopedTokenKeyFingerprint(key), nil
}

func alignEnterpriseHookUserTokenKeyOwner(dataDir string) error {
	keyPath, err := connector.UserScopedTokenKeyPath(dataDir)
	if err != nil {
		return err
	}
	return alignEnterpriseHookTokenPathOwner(dataDir, keyPath, "per-user credential key")
}

func validateEnterpriseHookTokenPathLocation(dataDir, tokenPath, label string) error {
	if _, err := validateEnterpriseHookManagedDir(dataDir, "managed data_dir", true); err != nil {
		return err
	}
	tokenDir := filepath.Dir(tokenPath)
	if _, err := validateEnterpriseHookManagedDir(tokenDir, "hook token dir", false); err != nil {
		return err
	}
	if info, err := os.Lstat(tokenPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("enterprise hooks: refusing symlink %s: %s", label, tokenPath)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("enterprise hooks: %s is not a regular file: %s", label, tokenPath)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("enterprise hooks: inspect %s %s: %w", label, tokenPath, err)
	}
	return nil
}

func alignEnterpriseHookTokenPathOwner(dataDir, tokenPath, label string) error {
	info, err := validateEnterpriseHookManagedDir(dataDir, "managed data_dir", true)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("enterprise hooks: cannot inspect managed data_dir owner")
	}
	uid, gid := int(st.Uid), int(st.Gid)
	tokenDir := filepath.Dir(tokenPath)
	if _, err := validateEnterpriseHookManagedDir(tokenDir, "hook token dir", true); err != nil {
		return err
	}
	tokenInfo, err := os.Lstat(tokenPath)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect %s %s: %w", label, tokenPath, err)
	}
	if tokenInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("enterprise hooks: refusing symlink %s: %s", label, tokenPath)
	}
	if !tokenInfo.Mode().IsRegular() {
		return fmt.Errorf("enterprise hooks: %s is not a regular file: %s", label, tokenPath)
	}
	// Fix the mode while root still owns the file and only when it is
	// wrong: the standalone guardian runs without CAP_FOWNER, so it cannot
	// chmod a token after handing it to the service account.
	if tokenInfo.Mode().Perm() != 0o600 {
		if err := enterpriseHookTokenChmod(tokenPath, 0o600); err != nil {
			return fmt.Errorf("enterprise hooks: chmod %s: %w", label, err)
		}
	}
	if os.Geteuid() == 0 {
		if err := os.Lchown(tokenDir, uid, gid); err != nil {
			return fmt.Errorf("enterprise hooks: lchown hook token dir: %w", err)
		}
		if err := os.Lchown(tokenPath, uid, gid); err != nil {
			return fmt.Errorf("enterprise hooks: lchown %s: %w", label, err)
		}
	}
	return nil
}

// enterpriseHookTokenChmod is replaced in tests.
var enterpriseHookTokenChmod = os.Chmod

func validateEnterpriseOTLPTokenLocation(dataDir string, scope connector.OTLPPathTokenScope) error {
	if _, err := validateEnterpriseHookManagedDir(dataDir, "managed data_dir", true); err != nil {
		return err
	}
	tokenPath, err := connector.OTLPPathTokenFilePath(dataDir, scope)
	if err != nil {
		return err
	}
	tokenDir := filepath.Dir(tokenPath)
	if _, err := validateEnterpriseHookManagedDir(tokenDir, "OTLP token dir", false); err != nil {
		return err
	}
	if info, err := os.Lstat(tokenPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("enterprise hooks: refusing symlink OTLP token: %s", tokenPath)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("enterprise hooks: OTLP token is not a regular file: %s", tokenPath)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("enterprise hooks: inspect OTLP token %s: %w", tokenPath, err)
	}
	return nil
}

func alignEnterpriseOTLPTokenOwner(dataDir string, scope connector.OTLPPathTokenScope) error {
	info, err := validateEnterpriseHookManagedDir(dataDir, "managed data_dir", true)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("enterprise hooks: cannot inspect managed data_dir owner")
	}
	uid, gid := int(st.Uid), int(st.Gid)
	tokenPath, err := connector.OTLPPathTokenFilePath(dataDir, scope)
	if err != nil {
		return err
	}
	tokenDir := filepath.Dir(tokenPath)
	if _, err := validateEnterpriseHookManagedDir(tokenDir, "OTLP token dir", true); err != nil {
		return err
	}
	tokenInfo, err := os.Lstat(tokenPath)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect OTLP token %s: %w", tokenPath, err)
	}
	if tokenInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("enterprise hooks: refusing symlink OTLP token: %s", tokenPath)
	}
	if !tokenInfo.Mode().IsRegular() {
		return fmt.Errorf("enterprise hooks: OTLP token is not a regular file: %s", tokenPath)
	}
	// As for the hook token: chmod only a wrong mode, before the hand-off.
	if tokenInfo.Mode().Perm() != 0o600 {
		if err := enterpriseHookTokenChmod(tokenPath, 0o600); err != nil {
			return fmt.Errorf("enterprise hooks: chmod OTLP token: %w", err)
		}
	}
	if os.Geteuid() == 0 {
		if err := os.Lchown(tokenDir, uid, gid); err != nil {
			return fmt.Errorf("enterprise hooks: lchown OTLP token dir: %w", err)
		}
		if err := os.Lchown(tokenPath, uid, gid); err != nil {
			return fmt.Errorf("enterprise hooks: lchown OTLP token: %w", err)
		}
	}
	return nil
}

func validateEnterpriseHookManagedDir(path, label string, requireExisting bool) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) && !requireExisting {
			return nil, nil
		}
		return nil, fmt.Errorf("enterprise hooks: inspect %s %s: %w", label, path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("enterprise hooks: refusing symlink %s: %s", label, path)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("enterprise hooks: %s is not a directory: %s", label, path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("enterprise hooks: %s %s is group/other writable", label, path)
	}
	return info, nil
}
