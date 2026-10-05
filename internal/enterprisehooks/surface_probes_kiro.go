//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Kiro IDE discovery for the standalone Unix enumerator.
//
// The Kiro IDE and kiro-cli share one connector: both read the global
// ~/.kiro/hooks/defenseclaw.json the guardian writes (the IDE from 1.0.182,
// kiro.dev/changelog/ide/1-0-182 "adds user-level global hooks"). Discovery
// only looked for kiro-cli, so a user with only the IDE was never enrolled,
// and an IDE too old to read the global file was never reported.
//
// The IDE is never run. Its version is read from the resources/app/
// product.json every Kiro IDE package ships (Kiro 1.2.4: macOS pkg and dmg
// Kiro.app/Contents/Resources/app, the Linux deb /usr/share/kiro, the Linux
// tar.gz a Kiro/ folder), whose "version" matches the macOS bundle's
// CFBundleShortVersionString. The worker reads it as the target user; a
// candidate outside the home is used only when no other account can change
// it (unixDiscoveryCandidateTrusted).

// kiroIDEProductMaxBytes bounds the product.json read (Kiro 1.2.4: 12 KB).
const kiroIDEProductMaxBytes = 256 << 10

// kiroIDEProductCandidates lists where the Kiro IDE packages keep
// product.json for home, the user's own install first.
func kiroIDEProductCandidates(home string) []string {
	if unixAgentAppBundleGOOS == "darwin" {
		relative := filepath.Join("Kiro.app", "Contents", "Resources", "app", "product.json")
		return []string{filepath.Join(home, "Applications", relative), filepath.Join("/Applications", relative)}
	}
	relative := filepath.Join("resources", "app", "product.json")
	return []string{
		filepath.Join(home, "Kiro", relative), // tar.gz extracted in the home
		filepath.Join("/usr/share/kiro", relative),
		filepath.Join("/opt/Kiro", relative), // tar.gz extracted by an administrator
	}
}

// DiscoverUnixKiroIDEVersion returns the version of the Kiro IDE installed
// for home and where it was read, or "" when none is found.
func DiscoverUnixKiroIDEVersion(home string) (string, string) {
	home = filepath.Clean(home)
	for _, candidate := range kiroIDEProductCandidates(home) {
		if !unixDiscoveryCandidateTrusted(home, candidate) {
			continue
		}
		if version := readKiroIDEProductVersion(candidate); version != "" {
			return version, candidate
		}
	}
	return "", ""
}

// readKiroIDEProductVersion reads a bounded product.json and returns its
// version when the file names the Kiro IDE.
func readKiroIDEProductVersion(path string) string {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, kiroIDEProductMaxBytes+1))
	if err != nil || len(data) > kiroIDEProductMaxBytes {
		return ""
	}
	var product struct {
		NameShort       string `json:"nameShort"`
		ApplicationName string `json:"applicationName"`
		Version         string `json:"version"`
	}
	if json.Unmarshal(data, &product) != nil || product.NameShort != "Kiro" || product.ApplicationName != "kiro" {
		return ""
	}
	version := strings.TrimSpace(product.Version)
	if !validUnixAgentVersion(version) {
		return ""
	}
	return version
}

// applyKiroIDESurface folds the Kiro IDE version discovery returned under
// KiroIDEDiscoveryKey into the kiro result for user. An IDE at or above
// KiroIDEGlobalHooksFloor enrolls a user without a readable kiro-cli
// version: the row's version is the IDE's, marked with KiroIDEVersionSuffix
// so the standalone floor applies the IDE's floor. An older IDE reads only
// workspace hooks, so it is reported and the kiro-cli row, if any, stays.
func applyKiroIDESurface(user string, uid int, versions, reasons map[string]string) []UnprotectedAgent {
	ide := strings.TrimSpace(versions[KiroIDEDiscoveryKey])
	if ide == "" {
		return nil
	}
	delete(versions, KiroIDEDiscoveryKey)
	if compareStandaloneFloorVersion(connector.NormalizeAgentVersion("kiro", ide), KiroIDEGlobalHooksFloor) < 0 {
		consequence := "its agent sessions run without DefenseClaw hooks"
		if cli := versions["kiro"]; cli != "" {
			consequence += "; kiro-cli " + cli + " stays enrolled"
		}
		return []UnprotectedAgent{{
			User:      user,
			UID:       intPointer(uid),
			Connector: "kiro",
			Version:   ide,
			Code:      UnprotectedCodeKiroIDEBelowGlobalHooksFloor,
			Reason: fmt.Sprintf("Kiro IDE %s is below %s, the first build that reads the global ~/.kiro/hooks file, so %s; update Kiro IDE",
				ide, KiroIDEGlobalHooksFloor, consequence),
		}}
	}
	if versions["kiro"] == "" {
		versions["kiro"] = ide + KiroIDEVersionSuffix
		delete(reasons, "kiro")
	}
	return nil
}
