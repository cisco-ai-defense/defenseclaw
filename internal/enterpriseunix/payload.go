// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// payload is a validated set of binaries to install.
type payload struct {
	Dir     string            // rooted directory holding the binaries
	Digests map[string]string // binary name -> sha256
	Version string
}

var versionPattern = regexp.MustCompile(`^(dev|[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.+-]+)?)$`)

// emptySHA256 is the SHA-256 of zero bytes.
const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// loadPayload validates dir (an absolute, administrator-staged directory)
// and reads the gateway's version from it. Every binary must be a regular,
// non-empty, executable, non-symlink file that is not writable by group or
// other and is owned by root or the account running the lifecycle.
func (e *Env) loadPayload(ctx context.Context, dir string) (*payload, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("payload directory %q must be absolute", dir)
	}
	clean := filepath.Clean(dir)
	if err := checkPayloadPath(clean, true); err != nil {
		return nil, err
	}
	p := &payload{Dir: clean, Digests: map[string]string{}}
	for _, name := range append(append([]string{}, requiredBinaries...), optionalBinaries...) {
		path := filepath.Join(clean, name)
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			if contains(optionalBinaries, name) {
				continue
			}
			return nil, fmt.Errorf("payload is missing %s", name)
		}
		if err := checkPayloadPath(path, false); err != nil {
			return nil, err
		}
		digest, err := sha256File(path)
		if err != nil {
			return nil, err
		}
		if digest == emptySHA256 {
			// A crash during the package unpack can leave a binary empty,
			// and agents run an empty hook as a script that allows every
			// tool call (GAP-0680).
			return nil, fmt.Errorf("payload %s is empty (0 bytes)", path)
		}
		p.Digests[name] = digest
	}
	version, err := e.binaryVersion(ctx, filepath.Join(clean, binGateway))
	if err != nil {
		return nil, err
	}
	p.Version = version
	return p, nil
}

// payloadPathError is a payload file or directory the lifecycle refuses.
// fix, when set, is the command that restores an installed binary.
type payloadPathError struct {
	path   string
	reason string
	fix    string
}

func (e *payloadPathError) Error() string { return "payload " + e.path + " " + e.reason }

func checkPayloadPath(path string, dir bool) error {
	uid, _, mode, err := statOwnerMode(path)
	if err != nil {
		return fmt.Errorf("inspect payload %s: %w", path, err)
	}
	if mode&os.ModeSymlink != 0 {
		return &payloadPathError{path: path, reason: "is a symlink, so its target could be swapped after the check; replace it with the real file"}
	}
	if dir && !mode.IsDir() {
		return &payloadPathError{path: path, reason: "is not a directory"}
	}
	if !dir {
		if !mode.IsRegular() {
			return &payloadPathError{path: path, reason: "is not a regular file"}
		}
		if mode.Perm()&0o111 == 0 {
			return &payloadPathError{path: path, reason: "is not executable", fix: "chmod 0755 " + path}
		}
	}
	if mode.Perm()&0o022 != 0 {
		return &payloadPathError{path: path, reason: fmt.Sprintf("is writable by group or other (%04o)", mode.Perm()), fix: "chmod 0755 " + path}
	}
	if uid != 0 && uid != os.Geteuid() {
		return &payloadPathError{path: path, reason: fmt.Sprintf("is owned by uid %d; stage it as root", uid), fix: "chown 0 " + path}
	}
	return nil
}

// installedPayloadError adds the remedy to a refusal of the binaries
// already installed in the layout's bin directory (package channel, or a
// repair without --payload): restore the file, or put the product's
// binaries back.
func (e *Env) installedPayloadError(err error, channel string) error {
	var pathErr *payloadPathError
	fix := ""
	if errors.As(err, &pathErr) && pathErr.fix != "" {
		fix = "restore it with `" + e.canonicalPayloadFix(pathErr.fix) + "`, or "
	}
	if channel == ChannelPackage {
		return fmt.Errorf("%w; %sreinstall the DefenseClaw enterprise package, then rerun", err, fix)
	}
	return fmt.Errorf("%w; %srerun with --payload <staged payload directory>", err, fix)
}

// canonicalPayloadFix maps the rooted path in a fix command back to the
// host path the administrator types.
func (e *Env) canonicalPayloadFix(fix string) string {
	if e.Root == "" {
		return fix
	}
	return strings.ReplaceAll(fix, e.Root, "")
}

// binaryVersion runs `<gateway> --version-json` and returns its version.
func (e *Env) binaryVersion(ctx context.Context, gateway string) (string, error) {
	result, err := e.Runner.Run(ctx, gateway, "--version-json")
	if err != nil {
		return "", fmt.Errorf("read payload version: %w", err)
	}
	var report struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(result.Stdout, &report); err != nil {
		return "", fmt.Errorf("parse payload version: %w", err)
	}
	version := strings.TrimPrefix(strings.TrimSpace(report.Version), "v")
	if report.Name != binGateway || !versionPattern.MatchString(version) {
		return "", fmt.Errorf("payload gateway reports an unexpected identity %q %q", report.Name, report.Version)
	}
	return version, nil
}

// packageOwned reports whether the dpkg or rpm database claims path.
func (e *Env) packageOwned(ctx context.Context, path string) bool {
	if _, err := e.Runner.Run(ctx, "dpkg", "-S", path); err == nil {
		return true
	}
	if _, err := e.Runner.Run(ctx, "rpm", "-qf", "--quiet", path); err == nil {
		return true
	}
	return false
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
