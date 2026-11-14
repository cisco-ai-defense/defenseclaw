// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookcli

import (
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// isolateHookTestHost points the machine readers of the hook at a run folder
// with no deployment, so a managed lane host gives the answers of a computer
// without one (GAP-2572, GAP-0093): the HKLM standalone marker, the Secure
// Client classification, the runtime descriptor and the standalone roots.
// Tests that need a managed computer set their own. TMP and TEMP name a
// folder of this run.
func isolateHookTestHost() func() {
	_, _ = testenv.OwnNewObjectsAsTokenUser()
	previousTemp := map[string]*string{}
	dir, err := os.MkdirTemp("", "defenseclaw-hookcli-test-")
	if err != nil {
		dir = filepath.Join(os.TempDir(), "defenseclaw-hookcli-test-unavailable")
	}
	for _, name := range []string{"TMP", "TEMP"} {
		if value, ok := os.LookupEnv(name); ok {
			previousTemp[name] = &value
		} else {
			previousTemp[name] = nil
		}
		if err == nil {
			_ = os.Setenv(name, dir)
		}
	}
	standalone, marker, secureClient, descriptor := ManagedHostWindowsStandalone, ManagedHostWindowsMarkerUncertain, SecureClientHost, ManagedHostDescriptorPath
	layout := WindowsManagedLayout
	ManagedHostWindowsStandalone = func() (string, bool) { return "", false }
	ManagedHostWindowsMarkerUncertain = func() bool { return false }
	SecureClientHost = func() bool { return false }
	missingDescriptor := filepath.Join(dir, "no-runtime-descriptor")
	ManagedHostDescriptorPath = func() string { return missingDescriptor }
	programFiles, programData := filepath.Join(dir, "no-program-files"), filepath.Join(dir, "no-program-data")
	missing, layoutErr := managed.StandaloneWindowsLayoutForRoots(programFiles, programData)
	if layoutErr != nil {
		missing = managed.StandaloneLayout{ConfigPath: filepath.Join(dir, "no-config.yaml"),
			ManifestPath: filepath.Join(dir, "no-manifest.json"), DataDir: filepath.Join(dir, "no-data")}
	}
	missingRoots, missingRootsErr := winpath.EnterpriseRootsFor(managed.ProfileStandalone, programFiles, programData)
	WindowsManagedLayout.Standalone = func() (managed.StandaloneLayout, error) { return missing, nil }
	WindowsManagedLayout.Roots = func(profile string) (winpath.EnterpriseRoots, error) {
		if profile != managed.ProfileStandalone {
			return winpath.TrustedEnterpriseRoots(profile)
		}
		return missingRoots, missingRootsErr
	}
	WindowsManagedLayout.ProgramRoots = func() (string, string) { return programFiles, programData }
	return func() {
		ManagedHostWindowsStandalone, ManagedHostWindowsMarkerUncertain, SecureClientHost, ManagedHostDescriptorPath = standalone, marker, secureClient, descriptor
		WindowsManagedLayout = layout
		for name, value := range previousTemp {
			if value == nil {
				_ = os.Unsetenv(name)
			} else {
				_ = os.Setenv(name, *value)
			}
		}
		if err == nil {
			_ = os.RemoveAll(dir)
		}
	}
}
