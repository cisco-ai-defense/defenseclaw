// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

const (
	hookAPITokenMaxReadBytes        = 4096
	hookAPITokenPublishLockBaseName = ".hook-api-token-publish"
)

var (
	hookAPITokenMu      sync.Mutex
	hookAPITokenScopeRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
)

// HookAPITokenFilePath returns the managed-data-dir token path for a
// connector-scoped hook API credential. This credential is intentionally
// narrower than gateway.token: tokenAuth accepts it only for that connector's
// hook submission routes.
func HookAPITokenFilePath(dataDir, connectorName string) (string, error) {
	if dataDir == "" {
		return "", fmt.Errorf("HookAPITokenFilePath: empty dataDir")
	}
	return HookTokenFilePath(filepath.Join(dataDir, "hooks"), connectorName)
}

// HookTokenFilePath returns the connector-scoped token sidecar path within a
// hook directory. Managed per-user installs use the same basename as the
// service-side token so multiple connectors can share one hook directory
// without overwriting each other's credentials.
func HookTokenFilePath(hookDir, connectorName string) (string, error) {
	scope, err := normalizeHookAPITokenScope(connectorName)
	if err != nil {
		return "", err
	}
	if hookDir == "" {
		return "", fmt.Errorf("HookTokenFilePath: empty hookDir")
	}
	return filepath.Join(hookDir, ".hook-"+scope+".token"), nil
}

func hookAPITokenPublishLockPath(dataDir string) string {
	return filepath.Join(dataDir, hookAPITokenPublishLockBaseName+".lock")
}

// EnsureHookAPIToken returns a stable 64-character hex token for connectorName.
// Existing valid tokens are reused so guardian repair runs do not invalidate
// already-installed hooks.
func EnsureHookAPIToken(dataDir, connectorName string) (string, error) {
	if dataDir == "" {
		return "", fmt.Errorf("EnsureHookAPIToken: empty dataDir; refusing to mint transient token")
	}
	hookAPITokenMu.Lock()
	defer hookAPITokenMu.Unlock()

	tokenPath, err := HookAPITokenFilePath(dataDir, connectorName)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(tokenPath); err == nil {
		existing, readErr := readSecureHookAPITokenFile(dataDir, tokenPath)
		if readErr != nil {
			return "", fmt.Errorf("read hook API token %s: %w", tokenPath, readErr)
		}
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect hook API token %s: %w", tokenPath, err)
	}

	hooksDir := filepath.Dir(tokenPath)
	hooksDirCreated := false
	if _, err := os.Lstat(hooksDir); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect hook API token dir: %w", err)
		}
		if err := hookAPIValidateDirectory(dataDir); err != nil {
			return "", fmt.Errorf("hook API token data dir %s is not trusted: %w", dataDir, err)
		}
		if err := os.Mkdir(hooksDir, 0o700); err == nil {
			hooksDirCreated = true
		} else if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("create hook API token dir: %w", err)
		}
	}
	if hooksDirCreated {
		if err := validateOTLPPathTokenLocation(dataDir, tokenPath); err != nil {
			return "", err
		}
		if err := hookAPIValidateDirectoryElement(hooksDir); err != nil {
			return "", fmt.Errorf("hook API token directory %s is not trusted: %w", hooksDir, err)
		}
	} else {
		if err := validateHookAPITokenLocation(dataDir, tokenPath); err != nil {
			return "", err
		}
	}

	buf := make([]byte, otlpTokenLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("EnsureHookAPIToken: csprng read: %w", err)
	}
	tok := hex.EncodeToString(buf)

	tmp := tokenPath + ".tmp"
	_ = os.Remove(tmp)
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if nofollow := otlpOpenNoFollow(); nofollow != 0 {
		flags |= nofollow
	}
	f, err := os.OpenFile(tmp, flags, 0o600)
	if err != nil {
		return "", fmt.Errorf("write hook API token: %w", err)
	}
	_, err = f.WriteString(tok + "\n")
	if syncErr := f.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("write hook API token: %w", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("chmod hook API token: %w", err)
	}
	if err := os.Rename(tmp, tokenPath); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("rename hook API token: %w", err)
	}
	return tok, nil
}

// LoadHookAPIToken reads the connector-scoped hook API token if present.
func LoadHookAPIToken(dataDir, connectorName string) (string, error) {
	tokenPath, err := HookAPITokenFilePath(dataDir, connectorName)
	if err != nil {
		return "", err
	}
	tok, err := readSecureHookAPITokenFile(dataDir, tokenPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return tok, nil
}

// PublishHookAPIToken atomically publishes an authoritative connector-scoped
// credential into dataDir. Managed-enterprise installers use it to copy the
// gateway's service-owned credential into a target user's private hook
// directory without embedding the value in a longer-lived plugin artifact.
//
// The supplied value must already be a 32-byte lowercase-hex token. Callers
// MUST NOT include it in logs or errors.
func PublishHookAPIToken(dataDir, connectorName, token string) error {
	if dataDir == "" {
		return fmt.Errorf("PublishHookAPIToken: empty dataDir")
	}
	token = strings.TrimSpace(token)
	if !otlpTokenHexRE.MatchString(token) {
		return fmt.Errorf("PublishHookAPIToken: invalid connector-scoped token")
	}

	tokenPath, err := HookAPITokenFilePath(dataDir, connectorName)
	if err != nil {
		return err
	}
	if err := hookAPIValidateDirectory(dataDir); err != nil {
		return fmt.Errorf("hook API token data dir %s is not trusted: %w", dataDir, err)
	}
	// The lock lives in the already-existing data directory rather than the
	// optionally-created hooks directory. This serializes the complete
	// snapshot/publish/rollback transaction across guardian processes while
	// still allowing a failed first publication to restore hooks-directory
	// absence exactly.
	lockPath := hookAPITokenPublishLockPath(dataDir)
	return withOwnedFileLock(lockPath, func() error {
		hookAPITokenMu.Lock()
		defer hookAPITokenMu.Unlock()
		return publishHookAPITokenLocked(dataDir, tokenPath, token)
	})
}

func publishHookAPITokenLocked(dataDir, tokenPath, token string) (returnErr error) {
	hooksDir := filepath.Dir(tokenPath)
	hooksDirCreated := false
	if _, err := os.Lstat(hooksDir); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect hook API token dir: %w", err)
		}
		if err := hookAPIValidateDirectory(dataDir); err != nil {
			return fmt.Errorf("hook API token data dir %s is not trusted: %w", dataDir, err)
		}
		if err := os.Mkdir(hooksDir, 0o700); err == nil {
			hooksDirCreated = true
		} else if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create hook API token dir: %w", err)
		}
	}
	defer func() {
		if returnErr == nil || !hooksDirCreated {
			return
		}
		if err := os.Remove(hooksDir); err != nil && !errors.Is(err, os.ErrNotExist) {
			returnErr = errors.Join(returnErr, fmt.Errorf("remove newly-created hook API token directory: %w", err))
		}
	}()
	if err := validateHookAPITokenLocation(dataDir, tokenPath); err != nil {
		return err
	}

	snapshot, err := captureHookAPITokenPublishSnapshot(dataDir, tokenPath)
	if err != nil {
		return fmt.Errorf("snapshot existing hook API token: %w", err)
	}
	desired := []byte(token + "\n")
	if snapshot.existed && bytes.Equal(snapshot.data, desired) && hookAPITokenSnapshotIsPrivate(tokenPath, snapshot) {
		return nil
	}

	stagedProtection := hookAPITokenPublishProtection{}
	if snapshot.existed && snapshot.private {
		stagedProtection = snapshot.protection
	}
	publishedProtection, err := publishHookAPITokenBytes(
		dataDir, tokenPath, desired, stagedProtection, snapshot, publishHookAPITokenFile,
	)
	if err != nil {
		publishErr := fmt.Errorf("publish hook API token: %w", err)
		if restoreErr := restoreHookAPITokenPublishSnapshot(
			dataDir, tokenPath, snapshot, desired, publishedProtection,
		); restoreErr != nil {
			return errors.Join(publishErr, fmt.Errorf("restore hook API token after failed publication: %w", restoreErr))
		}
		return publishErr
	}
	return nil
}

// publishHookAPITokenFile is a package-private failure seam. Production uses
// the handle-bound platform publication primitive with the connector-token
// custody validator; tests replace it to prove recovery from an error reported
// after rename.
var publishHookAPITokenFile atomicFilePublisher = atomicFilePublishHookAPIToken

type hookAPITokenPublishSnapshot struct {
	existed    bool
	data       []byte
	info       os.FileInfo
	private    bool
	protection hookAPITokenPublishProtection
}

func captureHookAPITokenPublishSnapshot(dataDir, tokenPath string) (hookAPITokenPublishSnapshot, error) {
	snapshot := hookAPITokenPublishSnapshot{}
	if err := validateHookAPITokenLocation(dataDir, tokenPath); err != nil {
		return snapshot, err
	}
	pathInfo, err := os.Lstat(tokenPath)
	if errors.Is(err, os.ErrNotExist) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return snapshot, fmt.Errorf("existing hook API token is not a regular file")
	}
	if err := hookAPIValidateOwner(tokenPath, pathInfo); err != nil {
		return snapshot, fmt.Errorf("existing hook API token is not trusted: %w", err)
	}
	file, err := os.OpenFile(tokenPath, os.O_RDONLY|otlpOpenNoFollow(), 0)
	if err != nil {
		return snapshot, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return snapshot, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return snapshot, fmt.Errorf("existing hook API token changed while opening")
	}
	protectionBefore, privateBefore, err := captureHookAPITokenPublishProtectionPlatform(file, openedInfo)
	if err != nil {
		return snapshot, fmt.Errorf("inspect existing hook API token protection: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, hookAPITokenMaxReadBytes+1))
	if err != nil {
		return snapshot, err
	}
	if len(data) > hookAPITokenMaxReadBytes {
		return snapshot, fmt.Errorf("existing hook API token exceeds %d bytes", hookAPITokenMaxReadBytes)
	}
	readInfo, err := file.Stat()
	if err != nil {
		return snapshot, err
	}
	protectionAfter, privateAfter, err := captureHookAPITokenPublishProtectionPlatform(file, readInfo)
	if err != nil {
		return snapshot, fmt.Errorf("reinspect existing hook API token protection: %w", err)
	}
	if !os.SameFile(openedInfo, readInfo) || openedInfo.Mode() != readInfo.Mode() ||
		openedInfo.Size() != readInfo.Size() || !openedInfo.ModTime().Equal(readInfo.ModTime()) ||
		!hookAPITokenPublishProtectionsEqual(protectionBefore, protectionAfter) || privateBefore != privateAfter {
		return snapshot, fmt.Errorf("existing hook API token changed while reading")
	}
	currentInfo, err := os.Lstat(tokenPath)
	if err != nil || !os.SameFile(readInfo, currentInfo) {
		return snapshot, fmt.Errorf("existing hook API token changed while reading")
	}
	return hookAPITokenPublishSnapshot{
		existed:    true,
		data:       data,
		info:       readInfo,
		private:    privateAfter,
		protection: protectionAfter,
	}, nil
}

func hookAPITokenSnapshotIsPrivate(_ string, snapshot hookAPITokenPublishSnapshot) bool {
	return snapshot.info != nil && snapshot.private
}

func publishHookAPITokenBytes(
	dataDir, tokenPath string,
	data []byte,
	protection hookAPITokenPublishProtection,
	expected hookAPITokenPublishSnapshot,
	publish atomicFilePublisher,
) (hookAPITokenPublishProtection, error) {
	tmp, tmpPath, err := createSecureOTLPPathTokenTempFile(tokenPath)
	if err != nil {
		return hookAPITokenPublishProtection{}, fmt.Errorf("create private temp file: %w", err)
	}
	defer os.Remove(tmpPath)
	stagedInfo, err := tmp.Stat()
	if err != nil {
		_ = tmp.Close()
		return hookAPITokenPublishProtection{}, fmt.Errorf("stat private temp file: %w", err)
	}
	stagedProtection, stagedPrivate, err := captureHookAPITokenPublishProtectionPlatform(tmp, stagedInfo)
	if err != nil {
		_ = tmp.Close()
		return hookAPITokenPublishProtection{}, fmt.Errorf("inspect private temp file: %w", err)
	}
	if !hookAPITokenPublishProtectionIsZero(protection) &&
		!hookAPITokenPublishProtectionsEqual(stagedProtection, protection) {
		if err := applyHookAPITokenPublishProtectionPlatform(tmp, protection); err != nil {
			_ = tmp.Close()
			return hookAPITokenPublishProtection{}, fmt.Errorf("apply private temp file protection: %w", err)
		}
		stagedInfo, err = tmp.Stat()
		if err != nil {
			_ = tmp.Close()
			return hookAPITokenPublishProtection{}, fmt.Errorf("stat protected private temp file: %w", err)
		}
		stagedProtection, stagedPrivate, err = captureHookAPITokenPublishProtectionPlatform(tmp, stagedInfo)
		if err != nil {
			_ = tmp.Close()
			return hookAPITokenPublishProtection{}, fmt.Errorf("inspect protected private temp file: %w", err)
		}
	}
	if !stagedPrivate {
		_ = tmp.Close()
		return hookAPITokenPublishProtection{}, fmt.Errorf("protected private temp file does not satisfy hook-token custody")
	}
	if !hookAPITokenPublishProtectionIsZero(protection) &&
		!hookAPITokenPublishProtectionsEqual(stagedProtection, protection) {
		_ = tmp.Close()
		return hookAPITokenPublishProtection{}, fmt.Errorf("protected private temp file does not match authenticated source protection")
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return stagedProtection, fmt.Errorf("write private temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return stagedProtection, fmt.Errorf("sync private temp file: %w", err)
	}
	stagedInfo, err = tmp.Stat()
	if err != nil {
		_ = tmp.Close()
		return stagedProtection, fmt.Errorf("stat private temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return stagedProtection, fmt.Errorf("close private temp file: %w", err)
	}
	current, err := captureHookAPITokenPublishSnapshot(dataDir, tokenPath)
	if err != nil {
		return stagedProtection, fmt.Errorf("revalidate hook API token before publication: %w", err)
	}
	if !hookAPITokenPublishSnapshotsEqual(expected, current) {
		return stagedProtection, fmt.Errorf("hook API token changed before publication")
	}
	if err := publish(tmpPath, tokenPath, stagedInfo, 0o600); err != nil {
		return stagedProtection, err
	}
	return stagedProtection, syncHookAPITokenParent(tokenPath)
}

func restoreHookAPITokenPublishSnapshot(
	dataDir, tokenPath string,
	snapshot hookAPITokenPublishSnapshot,
	published []byte,
	publishedProtection hookAPITokenPublishProtection,
) error {
	current, err := captureHookAPITokenPublishSnapshot(dataDir, tokenPath)
	if err == nil && hookAPITokenPublishSnapshotsEqual(snapshot, current) {
		return nil
	}
	if !snapshot.existed {
		if err != nil {
			return err
		}
		if !current.existed {
			return nil
		}
		if !hookAPITokenPublishedStateMatches(current, published, publishedProtection) {
			return fmt.Errorf("published hook API token changed before rollback")
		}
		if err := os.Remove(tokenPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncHookAPITokenParent(tokenPath)
	}
	if err != nil {
		return err
	}
	if !hookAPITokenPublishedStateMatches(current, published, publishedProtection) {
		return fmt.Errorf("published hook API token changed before rollback")
	}
	restoreProtection := hookAPITokenPublishProtection{}
	if snapshot.private {
		restoreProtection = snapshot.protection
	}
	restoredProtection, err := publishHookAPITokenBytes(
		dataDir, tokenPath, snapshot.data, restoreProtection, current, atomicFilePublishHookAPIToken,
	)
	if err != nil {
		return err
	}
	restored, err := captureHookAPITokenPublishSnapshot(dataDir, tokenPath)
	if err != nil {
		return err
	}
	if !hookAPITokenPublishedStateMatches(restored, snapshot.data, restoredProtection) {
		return fmt.Errorf("restored hook API token does not match its snapshot")
	}
	if snapshot.private && !hookAPITokenPublishProtectionsEqual(restored.protection, snapshot.protection) {
		return fmt.Errorf("restored hook API token protection does not match its snapshot")
	}
	return nil
}

func hookAPITokenPublishedStateMatches(
	current hookAPITokenPublishSnapshot,
	published []byte,
	protection hookAPITokenPublishProtection,
) bool {
	return current.existed && current.private && bytes.Equal(current.data, published) &&
		hookAPITokenPublishProtectionsEqual(current.protection, protection)
}

func hookAPITokenPublishSnapshotsEqual(left, right hookAPITokenPublishSnapshot) bool {
	if left.existed != right.existed {
		return false
	}
	if !left.existed {
		return true
	}
	return left.info != nil && right.info != nil && os.SameFile(left.info, right.info) &&
		left.info.Mode() == right.info.Mode() && left.private == right.private && bytes.Equal(left.data, right.data) &&
		hookAPITokenPublishProtectionsEqual(left.protection, right.protection)
}

func syncHookAPITokenParent(tokenPath string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(filepath.Dir(tokenPath))
	if err != nil {
		return fmt.Errorf("open private token directory for sync: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return fmt.Errorf("sync private token directory: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close private token directory after sync: %w", closeErr)
	}
	return nil
}

// LoadHookAPITokens loads connector-scoped hook API tokens for known connector
// names. Missing tokens are omitted.
func LoadHookAPITokens(dataDir string, connectorNames []string) (map[string]string, error) {
	out := map[string]string{}
	for _, name := range connectorNames {
		scope, err := normalizeHookAPITokenScope(name)
		if err != nil {
			continue
		}
		tokenPath, err := HookAPITokenFilePath(dataDir, scope)
		if err != nil {
			return nil, err
		}
		if _, err := os.Lstat(tokenPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("inspect hook API token %s: %w", tokenPath, err)
		}
		tok, err := readSecureHookAPITokenFile(dataDir, tokenPath)
		if err != nil {
			return nil, err
		}
		out[scope] = tok
	}
	return out, nil
}

func normalizeHookAPITokenScope(connectorName string) (string, error) {
	scope := strings.ToLower(strings.TrimSpace(connectorName))
	if !hookAPITokenScopeRE.MatchString(scope) {
		return "", fmt.Errorf("invalid hook API token connector scope %q", connectorName)
	}
	return scope, nil
}

func readSecureHookAPITokenFile(dataDir, path string) (string, error) {
	if err := validateHookAPITokenLocation(dataDir, path); err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("hook API token %s is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("hook API token %s is not a regular file", path)
	}
	if err := otlpValidatePerm(path, info); err != nil {
		return "", err
	}
	if err := hookAPIValidateOwner(path, info); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|otlpOpenNoFollow(), 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	limited := io.LimitReader(f, hookAPITokenMaxReadBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", err
	}
	if len(data) > hookAPITokenMaxReadBytes {
		return "", fmt.Errorf("hook API token %s exceeds %d bytes", path, hookAPITokenMaxReadBytes)
	}
	tok := strings.TrimSpace(string(data))
	if !otlpTokenHexRE.MatchString(tok) {
		return "", fmt.Errorf("hook API token %s is not a 64-character lowercase hex token", path)
	}
	return tok, nil
}

func validateHookAPITokenLocation(dataDir, tokenPath string) error {
	if err := validateOTLPPathTokenLocation(dataDir, tokenPath); err != nil {
		return err
	}
	if err := hookAPIValidateDirectory(dataDir); err != nil {
		return fmt.Errorf("hook API token data dir %s is not trusted: %w", dataDir, err)
	}
	hooksDir := filepath.Dir(tokenPath)
	if err := hookAPIValidateDirectory(hooksDir); err != nil {
		return fmt.Errorf("hook API token directory %s is not trusted: %w", hooksDir, err)
	}
	return nil
}
