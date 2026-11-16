// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
)

// The Windows standalone enumerator holds every row of the Kiro forms table
// that a profile can hold (the machine IDE lives in the real %ProgramFiles%):
// a new row enrolls the table's form, and each form that is not protected is
// reported once, with its code.
func TestKiroFormsTableWindowsEnumerator(t *testing.T) {
	setStandaloneProfileForTest(t, true)
	for _, row := range loadKiroFormsTable(t) {
		if _, machine := row.Forms["ide_machine"]; machine {
			continue
		}
		t.Run(row.Name, func(t *testing.T) {
			home := t.TempDir()
			for form, value := range row.Forms {
				switch form {
				case "cli":
					root := filepath.Join(home, "AppData", "Local", "Kiro-Cli")
					writeKiroTableFile(t, filepath.Join(root, "kiro-cli.exe"), "MZ-current")
					if value != kiroFormsTableUnreadable {
						writeKiroTableFile(t, filepath.Join(root, "run", "chat-cli-"+value+".exe"), "MZ-current")
					}
				case "ide_user":
					product := filepath.Join(home, "AppData", "Local", "Programs", "Kiro", "resources", "app", "product.json")
					content := "{not json"
					if value != kiroFormsTableUnreadable {
						content = `{"nameShort":"Kiro","applicationName":"kiro","version":"` + value + `"}`
					}
					writeKiroTableFile(t, product, content)
				}
			}
			var reports []UnprotectedAgent
			ctx := windowsStandaloneRowContext{sessionActive: true, user: "alice", report: func(a UnprotectedAgent) { reports = append(reports, a) }}
			target := ManifestTarget{SID: testLocalUserSID, Connector: "kiro", UserHome: home}
			enrolled := ""
			if applyStandaloneRowStateFor(&target, map[string]ManifestTarget{}, nil, ctx) {
				enrolled = target.AgentVersion
			}
			if enrolled != kiroTableEnrollVersion(row) {
				t.Fatalf("enrolled %q, want %q (reports %+v)", enrolled, kiroTableEnrollVersion(row), reports)
			}
			var codes []string
			for _, report := range reports {
				codes = append(codes, report.Code)
			}
			sort.Strings(codes)
			if want := kiroTableUnprotectedCodes(row); !slices.Equal(codes, want) {
				t.Fatalf("reported %v, want %v: %+v", codes, want, reports)
			}
		})
	}
}

func writeKiroTableFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
