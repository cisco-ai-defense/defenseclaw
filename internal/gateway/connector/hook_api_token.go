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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

const hookAPITokenMaxReadBytes = 4096

var (
	hookAPITokenMu      sync.Mutex
	hookAPITokenScopeRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
)

// HookAPITokenFilePath returns the managed-data-dir token path for a
// connector-scoped hook API credential. This credential is intentionally
// narrower than gateway.token: tokenAuth accepts it only for that connector's
// hook submission routes.
func HookAPITokenFilePath(dataDir, connectorName string) (string, error) {
	scope, err := normalizeHookAPITokenScope(connectorName)
	if err != nil {
		return "", err
	}
	if dataDir == "" {
		return "", fmt.Errorf("HookAPITokenFilePath: empty dataDir")
	}
	return filepath.Join(dataDir, "hooks", ".hook-"+scope+".token"), nil
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
	if err := validateHookAPITokenLocation(dataDir, tokenPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if existing, err := readSecureHookAPITokenFile(dataDir, tokenPath); err == nil && existing != "" {
		return existing, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read hook API token %s: %w", tokenPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		return "", fmt.Errorf("create hook API token dir: %w", err)
	}
	if err := validateHookAPITokenLocation(dataDir, tokenPath); err != nil {
		return "", err
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

// LoadHookAPITokens loads connector-scoped hook API tokens for known connector
// names. Missing tokens are omitted.
func LoadHookAPITokens(dataDir string, connectorNames []string) (map[string]string, error) {
	out := map[string]string{}
	for _, name := range connectorNames {
		scope, err := normalizeHookAPITokenScope(name)
		if err != nil {
			continue
		}
		tok, err := LoadHookAPIToken(dataDir, scope)
		if err != nil {
			return nil, err
		}
		if tok != "" {
			out[scope] = tok
		}
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
