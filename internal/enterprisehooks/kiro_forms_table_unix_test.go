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

package enterprisehooks

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The Unix enumerator holds every row of the Kiro forms table: discovery's
// result goes through applyKiroIDESurface and then the per-connector new-row
// checks, as in EnumerateUnix. The row enrolls the table's form, and each
// form that is not protected is reported once, with its code.
func TestKiroFormsTableUnixEnumerator(t *testing.T) {
	keys := map[string]string{"cli": "kiro", "ide_user": "kiro-ide", "ide_machine": "kiro-ide-machine"}
	for _, row := range loadKiroFormsTable(t) {
		t.Run(row.Name, func(t *testing.T) {
			versions, reasons := map[string]string{}, map[string]string{}
			for form, value := range row.Forms {
				key := keys[form]
				if value != kiroFormsTableUnreadable {
					versions[key] = value
				} else {
					reasons[key] = UnixAgentUnversionedReasonPrefix + "/opt/" + key
				}
			}
			reports := applyKiroIDESurface("alice", 501, versions, reasons)
			enrolled := ""
			switch version := versions["kiro"]; {
			case version != "" && unixNewRowVersionRefused("kiro", version) == "":
				enrolled = version
			case version != "":
				reports = append(reports, UnprotectedAgent{Code: UnprotectedCodeForReason(unixNewRowVersionRefused("kiro", version))})
			case UnixAgentInstalledWithoutVersion(reasons["kiro"]):
				reports = append(reports, UnprotectedAgent{Code: UnprotectedCodeHookContractUnverified})
			}
			if enrolled != kiroTableEnrollVersion(row) {
				t.Fatalf("enrolled %q, want %q (versions %v, reports %+v)", enrolled, kiroTableEnrollVersion(row), versions, reports)
			}
			var codes []string
			for _, report := range reports {
				codes = append(codes, report.Code)
			}
			sort.Strings(codes)
			if want := kiroTableUnprotectedCodes(row); !slices.Equal(codes, want) {
				t.Fatalf("reported %v, want %v: %+v", codes, want, reports)
			}
			// The status record keeps each finding.
			data, err := MarshalUnprotectedAgents(withAccount(reports))
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseUnprotectedAgents(data)
			if err != nil || len(parsed) != len(reports) {
				t.Fatalf("status record kept %d of %d findings (%v)", len(parsed), len(reports), err)
			}
		})
	}
}

// withAccount gives synthesized per-connector reports the account and
// connector the enumerator fills in.
func withAccount(reports []UnprotectedAgent) []UnprotectedAgent {
	out := make([]UnprotectedAgent, 0, len(reports))
	for i, report := range reports {
		report.User, report.UID, report.Connector = "alice", intPointer(501), "kiro"
		if report.Reason == "" {
			report.Reason = "per-connector finding " + string(rune('a'+i))
		}
		out = append(out, report)
	}
	return out
}

// DiscoverUnixKiroIDEForms reports an installed IDE whose product.json cannot
// be read as an unknown form (it was skipped, so a supported kiro-cli or
// another IDE hid it), and PutUnixKiroIDEForms keeps the least protected
// install of each kind.
func TestDiscoverUnixKiroIDEFormsReportsAnUnreadableInstall(t *testing.T) {
	origGOOS := unixAgentAppBundleGOOS
	unixAgentAppBundleGOOS = "linux"
	t.Cleanup(func() { unixAgentAppBundleGOOS = origGOOS })
	home := t.TempDir()
	product := filepath.Join(home, "Kiro", "resources", "app", "product.json")
	if err := os.MkdirAll(filepath.Dir(product), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(product, []byte(`{"nameShort":"Kiro","applicationName":"kiro","version":"not a version"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	forms := DiscoverUnixKiroIDEForms(home)
	var user []KiroForm
	for _, form := range forms {
		if form.Kind == KiroFormUserIDE {
			user = append(user, form)
		}
	}
	if len(user) != 1 || user[0].Version != "" || !strings.Contains(user[0].Unread, product) {
		t.Fatalf("user IDE forms = %+v, want one unknown install at %s", user, product)
	}
	versions, reasons := map[string]string{"kiro": "2.27.1"}, map[string]string{}
	PutUnixKiroIDEForms([]KiroForm{
		{Kind: KiroFormMachineIDE, Version: "1.2.4"},
		{Kind: KiroFormMachineIDE, Version: "1.0.150"},
		user[0],
	}, versions, reasons)
	if versions[KiroIDEMachineDiscoveryKey] != "1.0.150" || !UnixAgentInstalledWithoutVersion(strings.TrimPrefix(reasons[KiroIDEDiscoveryKey], "Kiro IDE ")) {
		t.Fatalf("discovery result versions=%v reasons=%v, want the old machine IDE and the unknown user IDE", versions, reasons)
	}
	report := applyKiroIDESurface("alice", 501, versions, reasons)
	if len(report) != 2 || versions["kiro"] != "2.27.1" {
		t.Fatalf("supported kiro-cli beside an unknown and an old IDE: report=%+v versions=%v", report, versions)
	}
}

// rel-1-0-4 GAP-0895 on the managed side: Kiro's Unix hooks are not version
// gated, so an action-mode install or verify with a kiro-cli version that
// could not be read resolved as not gated and passed as if the CLI were at its
// floor. Unknown is not protected: action mode refuses it, observe installs.
func TestKiroActionInstallRefusesAnUnreadVersion(t *testing.T) {
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
	kiro := connector.NewKiroConnector()
	err := validateHookContract("action", kiro, connector.SetupOpts{DataDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Fatalf("action install of an unread kiro-cli version: err = %v, want a refusal", err)
	}
	if err := validateHookContract("observe", kiro, connector.SetupOpts{DataDir: t.TempDir()}); err != nil {
		t.Fatalf("observe install of an unread kiro-cli version: %v", err)
	}
	if err := validateHookContract("action", kiro, connector.SetupOpts{DataDir: t.TempDir(), AgentVersion: "2.27.1"}); err != nil {
		t.Fatalf("action install of kiro-cli 2.27.1: %v", err)
	}
}
