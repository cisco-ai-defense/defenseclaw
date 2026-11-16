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
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// DiscoverUnixKiroIDEForms returns every Kiro IDE install found for home, the
// user's own installs first: its version, or why the version could not be
// read. A product.json that exists but cannot be read or does not name a
// version, or one outside the home that other accounts can change, is an
// install whose version is unknown (JudgeKiroForm: not protected).
func DiscoverUnixKiroIDEForms(home string) []KiroForm {
	home = filepath.Clean(home)
	var forms []KiroForm
	for _, candidate := range kiroIDEProductCandidates(home) {
		if _, err := os.Lstat(candidate); err != nil {
			continue
		}
		form := KiroForm{Kind: KiroFormMachineIDE}
		if pathInside(home, candidate) {
			form.Kind = KiroFormUserIDE
		}
		switch {
		case !unixDiscoveryCandidateTrusted(home, candidate):
			form.Unread = "Kiro IDE " + UnixAgentUnversionedReasonPrefix + candidate + unixUntrustedCandidateNote
		default:
			if form.Version = readKiroIDEProductVersion(candidate); form.Version == "" {
				form.Unread = "Kiro IDE " + UnixAgentUnversionedReasonPrefix + candidate
			}
		}
		forms = append(forms, form)
	}
	return forms
}

// kiroIDEKinds are the two Kiro IDE kinds, the user's own install first.
var kiroIDEKinds = []KiroFormKind{KiroFormUserIDE, KiroFormMachineIDE}

// kiroIDEFormsPerKind bounds the installs of one kind a discovery result
// carries: kiroIDEProductCandidates lists at most this many per kind.
const kiroIDEFormsPerKind = 3

// kiroIDEDiscoveryKey is the discovery key of the index-th install of kind:
// KiroIDEDiscoveryKey or KiroIDEMachineDiscoveryKey for the first, with
// ".2", ".3" after it for the next ones; "" past kiroIDEFormsPerKind.
func kiroIDEDiscoveryKey(kind KiroFormKind, index int) string {
	base := ""
	switch kind {
	case KiroFormUserIDE:
		base = KiroIDEDiscoveryKey
	case KiroFormMachineIDE:
		base = KiroIDEMachineDiscoveryKey
	}
	if base == "" || index < 0 || index >= kiroIDEFormsPerKind {
		return ""
	}
	if index == 0 {
		return base
	}
	return base + "." + strconv.Itoa(index+1)
}

// KiroIDEDiscoveryKeys lists every discovery key a Kiro IDE install can
// travel under, so the parent keeps them all next to the kiro-cli one.
func KiroIDEDiscoveryKeys() []string {
	var keys []string
	for _, kind := range kiroIDEKinds {
		for index := 0; index < kiroIDEFormsPerKind; index++ {
			keys = append(keys, kiroIDEDiscoveryKey(kind, index))
		}
	}
	return keys
}

// PutUnixKiroIDEForms records every Kiro IDE install in a discovery result,
// in discovery order, each kind under its own keys (kiroIDEDiscoveryKey). A
// version goes under versions; an unknown one's reason under reasons.
// AssessKiro then judges each install on its own: a supported install
// enrolls the user even when an older or unreadable one of the same kind is
// installed too, and that one is still reported.
func PutUnixKiroIDEForms(forms []KiroForm, versions, reasons map[string]string) {
	next := map[KiroFormKind]int{}
	for _, form := range forms {
		key := kiroIDEDiscoveryKey(form.Kind, next[form.Kind])
		if key == "" {
			continue
		}
		next[form.Kind]++
		if form.Version != "" {
			versions[key] = form.Version
		} else if reasons != nil {
			reasons[key] = form.Unread
		}
	}
}

// takeUnixKiroIDEForms removes the Kiro IDE entries from a discovery result
// and returns them as forms, the user's installs first.
func takeUnixKiroIDEForms(versions, reasons map[string]string) []KiroForm {
	var forms []KiroForm
	for _, kind := range kiroIDEKinds {
		for index := 0; index < kiroIDEFormsPerKind; index++ {
			key := kiroIDEDiscoveryKey(kind, index)
			version, unread := strings.TrimSpace(versions[key]), strings.TrimSpace(reasons[key])
			delete(versions, key)
			delete(reasons, key)
			switch {
			case version != "":
				forms = append(forms, KiroForm{Kind: kind, Version: version})
			case strings.Contains(unread, UnixAgentUnversionedReasonPrefix):
				forms = append(forms, KiroForm{Kind: kind, Unread: unread})
			}
		}
	}
	return forms
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

// applyKiroIDESurface folds the Kiro IDE installs discovery returned
// (kiroIDEDiscoveryKey, every install of each kind) into the kiro result for
// user, through AssessKiro. When a protected kiro-cli is installed it keeps
// the row. Otherwise a protected IDE enrolls the user: the row's version is
// the IDE's, marked with KiroIDEVersionSuffix so the IDE's floor applies, and
// the kiro-cli that is not protected (below connector.KiroCLIHookFloor, or
// installed without a readable version) is reported, as it is without the
// IDE. Every IDE install that is not protected (below
// KiroIDEGlobalHooksFloor, or with no readable version) is reported whatever
// the kiro-cli is. Without a protected form the kiro-cli is left to the
// per-connector new-row and kept-row checks.
func applyKiroIDESurface(user string, uid int, versions, reasons map[string]string) []UnprotectedAgent {
	ides := takeUnixKiroIDEForms(versions, reasons)
	if len(ides) == 0 {
		return nil
	}
	var forms []KiroForm
	if cli := strings.TrimSpace(versions["kiro"]); cli != "" {
		forms = append(forms, KiroForm{Kind: KiroFormCLI, Version: cli})
	} else if UnixAgentInstalledWithoutVersion(reasons["kiro"]) {
		forms = append(forms, KiroForm{Kind: KiroFormCLI, Unread: reasons["kiro"]})
	}
	assessment := AssessKiro(append(forms, ides...))
	enrolledIDE := assessment.Enrolled != nil && assessment.Enrolled.Form.IDE()
	if enrolledIDE {
		versions["kiro"] = assessment.Enroll
		delete(reasons, "kiro")
	}
	var out []UnprotectedAgent
	for _, verdict := range assessment.Unprotected() {
		if !verdict.Form.IDE() && !enrolledIDE {
			continue
		}
		out = append(out, UnprotectedAgent{
			User:      user,
			UID:       intPointer(uid),
			Connector: "kiro",
			Version:   verdict.Version,
			Code:      verdict.Code,
			Reason:    verdict.Reason,
		})
	}
	return out
}
