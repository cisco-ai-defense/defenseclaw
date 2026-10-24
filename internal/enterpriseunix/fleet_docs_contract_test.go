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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func edgeConfigurationPage(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs-site", "content", "docs", "reference", "edge-connector", "configuration.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(strings.Fields(string(raw)), " ")
}

// GAP-0572: a Fleet-on package install has two refusal messages, one when
// share/fleet is absent and one when it exists without the compiler. The
// page quotes both as the lifecycle prints them.
func TestFleetOnPackageRefusalsAreTheDocumentedMessages(t *testing.T) {
	page := edgeConfigurationPage(t)
	for _, withDir := range []bool{false, true} {
		h := packageHost(t, "1.0.0")
		allowTestFleetPython(h)
		if err := os.Chmod(h.env.P("/opt"), 0o755); err != nil {
			t.Fatal(err)
		}
		if withDir {
			canonical := packageCompilerSourcePath(h.env.Layout)
			packagedCompiler(t, h, "print('package')\n")
			if err := os.Remove(h.env.P(canonical)); err != nil {
				t.Fatal(err)
			}
		}
		result := h.run(Options{Action: ActionInstall, FromPackage: true, Reason: "package", ConfigFile: stagedFleetConfig(t, h)})
		requireError(t, result, codePayload)
		got := strings.TrimSpace(strings.ReplaceAll(messagesOf(result.Errors, codePayload), h.env.Root, ""))
		if !strings.Contains(page, "`"+got+"`") {
			t.Errorf("share/fleet present=%t: the page does not quote %q", withDir, got)
		}
	}
}

// GAP-0573: the page's --payload route stages the enterprise archive plus
// the per-user archive's compiler. The per-user archive alone has no hook.
func TestFleetOnPayloadRouteIsTheDocumentedOne(t *testing.T) {
	page := edgeConfigurationPage(t)
	h := newTestHost(t, "linux")
	allowTestFleetPython(h)

	perUser := h.payload("1.0.0")
	if err := os.Remove(filepath.Join(perUser, binHook)); err != nil {
		t.Fatal(err)
	}
	stagedCompiler(t, perUser, "print('compiler')\n")
	refused := h.run(Options{Action: ActionInstall, PayloadDir: perUser, ConfigFile: stagedFleetConfig(t, h)})
	requireError(t, refused, codePayload)
	missing := strings.TrimSpace(messagesOf(refused.Errors, codePayload))
	if !strings.Contains(page, "`"+missing+"`") {
		t.Errorf("the page does not quote the per-user archive refusal %q", missing)
	}

	staged := h.payload("1.0.0")
	stagedCompiler(t, staged, "print('compiler')\n")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: staged, ConfigFile: stagedFleetConfig(t, h)}))
	documented := "`<dir>/" + filepath.ToSlash(filepath.Join(compilerArchiveDir, "tools", compilerFileName)) + "`"
	for _, want := range []string{documented, "defenseclaw-enterprise-<version>-<os>-<arch>.tar.gz", "`package_owned_binaries`"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not name %s", want)
		}
	}

	// The staged payload reaches the package-owned refusal on an RPM host.
	rpm := packageHost(t, "1.0.0")
	allowTestFleetPython(rpm)
	rpm.env.Runner = packageOwnedRunner{Runner: rpm.runner}
	requireOK(t, rpm.run(Options{Action: ActionInstall, FromPackage: true}))
	payload := rpm.payload("1.0.0")
	stagedCompiler(t, payload, "print('compiler')\n")
	requireError(t, rpm.run(Options{Action: ActionEnsure, PayloadDir: payload, ConfigFile: stagedFleetConfig(t, rpm)}), codePackageOwned)
	requireError(t, rpm.run(Options{Action: ActionInstall, PayloadDir: payload, ConfigFile: stagedFleetConfig(t, rpm)}), codeAlreadyInstalled)
	if !strings.Contains(page, "`already_installed`") {
		t.Error("the page does not name the already_installed refusal")
	}
	if strings.Contains(page, "is the root-owned, extracted per-user release archive") {
		t.Error("the page still says the per-user archive alone is the payload")
	}
}
