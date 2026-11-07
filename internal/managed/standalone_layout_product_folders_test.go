// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/productlayout"
)

// Every DefenseClaw-named folder the standalone Windows layout builds is a
// registered product folder, so audit redaction never mistakes it for a secret.
func TestStandaloneWindowsLayoutUsesRegisteredProductFolders(t *testing.T) {
	layout, err := StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{
		layout.InstallRoot, layout.ConfigDir, layout.LogDir, layout.HookRuntimeDir,
		StandaloneWindowsScannerRuntimeDirForRoot(`C:\ProgramData`),
	}
	for _, path := range paths {
		for _, segment := range strings.Split(path, `\`) {
			if strings.HasPrefix(strings.ToLower(segment), "defenseclaw") && !productlayout.IsFolderName(segment) {
				t.Errorf("%q in %q is not a registered product folder", segment, path)
			}
		}
	}
	if !strings.HasSuffix(layout.HookRuntimeDir, `\`+productlayout.WindowsHookRuntimeFolder) {
		t.Errorf("hook runtime folder %s", layout.HookRuntimeDir)
	}
}
