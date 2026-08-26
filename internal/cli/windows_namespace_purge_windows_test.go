//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"testing"
)

func TestWindowsNamespacePurgeCommandIsHiddenAndFileBound(t *testing.T) {
	command := newWindowsNamespacePurgeCommand()
	if command == nil || command.Use != "namespace-root-cleanup" || !command.Hidden {
		t.Fatalf("namespace cleanup command = %#v", command)
	}
	for _, name := range []string{"request", "output"} {
		flag := command.Flags().Lookup(name)
		if flag == nil {
			t.Fatalf("namespace cleanup command is missing --%s", name)
		}
	}
	if command.Flags().Lookup("root") != nil || command.Flags().Lookup("identity") != nil {
		t.Fatal("namespace cleanup exposes path or identity as an unprotected CLI flag")
	}
}

func TestWindowsNamespacePurgeExchangePathsAreDistinctAndOutsideRoot(t *testing.T) {
	originalResolver := windowsNamespacePurgeFinalPathResolver
	windowsNamespacePurgeFinalPathResolver = func(path string, _ bool) (string, bool, error) {
		return filepath.Clean(path), true, nil
	}
	t.Cleanup(func() { windowsNamespacePurgeFinalPathResolver = originalResolver })

	root := `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw`
	request := `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Lifecycle\request.json`
	output := `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Lifecycle\report.json`
	if err := validateWindowsNamespacePurgeExchangePaths(request, output, root); err != nil {
		t.Fatalf("valid exchange paths: %v", err)
	}
	if err := validateWindowsNamespacePurgeExchangePaths(
		`D:\DefenseClaw-Lifecycle\request.json`,
		`D:\DefenseClaw-Lifecycle\report.json`,
		root,
	); err != nil {
		t.Fatalf("valid exchange paths on another volume: %v", err)
	}
	for name, paths := range map[string][2]string{
		"same file":       {request, request},
		"request in root": {root + `\request.json`, output},
		"output in root":  {request, root + `\report.json`},
		"root itself":     {request, root},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateWindowsNamespacePurgeExchangePaths(paths[0], paths[1], root); err == nil {
				t.Fatal("unsafe namespace cleanup exchange paths were accepted")
			}
		})
	}

	windowsNamespacePurgeFinalPathResolver = func(path string, directory bool) (string, bool, error) {
		if directory {
			return root, true, nil
		}
		if sameWindowsEnterprisePathCLI(path, request) {
			return root + `\aliased-request.json`, true, nil
		}
		return output, true, nil
	}
	if err := validateWindowsNamespacePurgeExchangePaths(request, output, root); err == nil {
		t.Fatal("final-path alias placed the request inside the cleanup root")
	}
}
