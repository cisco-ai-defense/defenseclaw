// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Standalone managed deployments start the helper without an environment
// file: the service account is resolved by name and the watched homes come
// from the protected guardian manifest.

const manifestLimit = 4 << 20

// validateManifestTrust is replaced by tests, which cannot create
// root-owned fixtures.
var validateManifestTrust = func(path string) error {
	return managed.ValidateTrustedFilePath(path, "guardian manifest")
}

// resolveServiceAccount returns the uid and primary gid of a local account.
func resolveServiceAccount(name string) (int, int, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("--service-account %s: %w", name, err)
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil || uid <= 0 || gid <= 0 {
		return 0, 0, fmt.Errorf("--service-account %s: unusable uid/gid %q:%q", name, account.Uid, account.Gid)
	}
	return uid, gid, nil
}

type helperManifest struct {
	Targets []struct {
		User      string `yaml:"user"`
		UserHome  string `yaml:"user_home"`
		UID       *int   `yaml:"uid"`
		Connector string `yaml:"connector"`
		Enabled   *bool  `yaml:"enabled"`
	} `yaml:"targets"`
}

// helperTarget is one enabled row of the guardian manifest: who is enrolled
// with which connector. The kernel-policy reconciler anchors enforcement
// only on these (and resolves their installs itself).
type helperTarget struct {
	User      string
	Home      string
	UID       *int
	Connector string
}

// manifestHomes returns the homes of the enabled rows of the guardian
// manifest and a digest of its bytes. A missing manifest means "no homes
// yet"; an untrusted one is an error.
func manifestHomes(path string) ([]string, string, error) {
	targets, digest, err := manifestTargets(path)
	if err != nil {
		return nil, "", err
	}
	set := map[string]bool{}
	for _, target := range targets {
		if target.Home != "" {
			set[target.Home] = true
		}
	}
	if len(set) == 0 {
		return nil, digest, nil
	}
	homes := make([]string, 0, len(set))
	for home := range set {
		homes = append(homes, home)
	}
	sort.Strings(homes)
	return homes, digest, nil
}

// manifestTargets returns the enabled rows of the guardian manifest, with
// each row's home resolved and checked (absolute, not /), and a digest of
// the manifest's bytes. A missing manifest is no rows; an untrusted one is
// an error.
func manifestTargets(path string) ([]helperTarget, string, error) {
	if path == "" {
		return nil, "", nil
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	}
	if err := validateManifestTrust(path); err != nil {
		return nil, "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, manifestLimit+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > manifestLimit {
		return nil, "", fmt.Errorf("guardian manifest exceeds %d bytes", manifestLimit)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	var manifest helperManifest
	if len(bytes.TrimSpace(data)) > 0 {
		if err := yaml.Unmarshal(data, &manifest); err != nil {
			return nil, "", fmt.Errorf("parse guardian manifest: %w", err)
		}
	}
	var targets []helperTarget
	for _, row := range manifest.Targets {
		if row.Enabled != nil && !*row.Enabled {
			continue
		}
		home := strings.TrimSpace(row.UserHome)
		if home == "" && row.User != "" {
			if account, err := user.Lookup(row.User); err == nil {
				home = account.HomeDir
			}
		}
		if home == "" || !filepath.IsAbs(home) || filepath.Clean(home) == "/" {
			continue
		}
		target := helperTarget{
			User: strings.TrimSpace(row.User), Home: filepath.Clean(home),
			Connector: strings.ToLower(strings.TrimSpace(row.Connector)),
		}
		if row.UID != nil && *row.UID >= 0 {
			uid := *row.UID
			target.UID = &uid
		}
		targets = append(targets, target)
	}
	return targets, digest, nil
}

// watchManifest cancels the returned context when the manifest bytes
// change, so the helper exits cleanly and its service manager restarts it
// with the new home set.
func watchManifest(parent context.Context, path, digest string, interval time.Duration, logger *slog.Logger) context.Context {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		defer cancel()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, current, err := manifestHomes(path)
				if err != nil {
					logger.Warn("guardian manifest unreadable; keeping the current home set", "error", err)
					continue
				}
				if current != digest {
					logger.Info("guardian manifest changed; restarting to watch the new home set")
					return
				}
			}
		}
	}()
	return ctx
}
