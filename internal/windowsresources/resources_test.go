// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package windowsresources

import (
	"bytes"
	"encoding/xml"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repositoryIcon(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", IconSource)
}

func TestCompleteWindowsExecutableInventory(t *testing.T) {
	want := []Component{"gateway", "hook", "launcher", "startup", "setup"}
	if len(AllComponents) != len(want) {
		t.Fatalf("component inventory = %v, want %v", AllComponents, want)
	}
	for index := range want {
		if AllComponents[index] != want[index] {
			t.Fatalf("component inventory = %v, want %v", AllComponents, want)
		}
		if _, ok := componentMetadataByName[want[index]]; !ok {
			t.Fatalf("component %q has no metadata", want[index])
		}
	}
	if !strings.Contains(componentMetadataByName[ComponentLauncher].Description, "scanner") {
		t.Fatal("launcher identity does not cover installed scanner aliases")
	}
}

func TestManifestContractForEveryComponent(t *testing.T) {
	for _, component := range AllComponents {
		component := component
		t.Run(string(component), func(t *testing.T) {
			manifest, err := Manifest(component, "12.34.56-rc.7")
			if err != nil {
				t.Fatal(err)
			}
			if err := xml.Unmarshal(manifest, new(any)); err != nil {
				t.Fatalf("manifest is not XML: %v", err)
			}
			text := string(manifest)
			for _, required := range []string{
				`processorArchitecture="amd64"`,
				`version="12.34.56.0"`,
				`level="asInvoker" uiAccess="false"`,
				`{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}`,
				`PerMonitorV2,PerMonitor`,
				`<longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>`,
			} {
				if !strings.Contains(text, required) {
					t.Errorf("manifest missing %q", required)
				}
			}
			for _, forbidden := range []string{"requireAdministrator", "highestAvailable", "autoElevate"} {
				if strings.Contains(text, forbidden) {
					t.Errorf("manifest contains forbidden elevation marker %q", forbidden)
				}
			}
			hasCommonControls := strings.Contains(text, "Microsoft.Windows.Common-Controls")
			if hasCommonControls != (component == ComponentSetup) {
				t.Errorf("common-controls v6 present = %v, want %v", hasCommonControls, component == ComponentSetup)
			}
		})
	}
}

func TestParseTargetAllowsOnlyCanonicalWindowsArchitectures(t *testing.T) {
	for _, test := range []struct {
		value string
		want  Target
	}{
		{value: "windows_amd64", want: TargetWindowsAMD64},
		{value: " WINDOWS_ARM64 ", want: TargetWindowsARM64},
	} {
		target, err := ParseTarget(test.value)
		if err != nil {
			t.Errorf("ParseTarget(%q): %v", test.value, err)
			continue
		}
		if target != test.want {
			t.Errorf("ParseTarget(%q) = %q, want %q", test.value, target, test.want)
		}
	}

	for _, value := range []string{
		"",
		"linux_amd64",
		"windows",
		"windows_386",
		"windows_arm",
		"windows_x64",
		"windows_amd64_v1",
		"windows_arm64_v8.0",
	} {
		if _, err := ParseTarget(value); err == nil {
			t.Errorf("ParseTarget(%q) unexpectedly succeeded", value)
		}
	}
}

func TestManifestArchitectureMatchesTarget(t *testing.T) {
	for _, test := range []struct {
		target    Target
		want      string
		forbidden string
	}{
		{target: TargetWindowsAMD64, want: "amd64", forbidden: "arm64"},
		{target: TargetWindowsARM64, want: "arm64", forbidden: "amd64"},
	} {
		t.Run(string(test.target), func(t *testing.T) {
			manifest, err := ManifestForTarget(test.target, ComponentGateway, "1.2.3")
			if err != nil {
				t.Fatal(err)
			}
			if err := xml.Unmarshal(manifest, new(any)); err != nil {
				t.Fatalf("manifest is not XML: %v", err)
			}
			text := string(manifest)
			if !strings.Contains(text, `processorArchitecture="`+test.want+`"`) {
				t.Errorf("manifest does not select %s:\n%s", test.want, text)
			}
			if strings.Contains(text, `processorArchitecture="`+test.forbidden+`"`) {
				t.Errorf("manifest incorrectly selects %s:\n%s", test.forbidden, text)
			}
		})
	}
}

func TestSetupResourcesRemainAMD64Only(t *testing.T) {
	manifest, err := Manifest(ComponentSetup, "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), `processorArchitecture="amd64"`) {
		t.Fatalf("default Setup manifest is not AMD64:\n%s", manifest)
	}
	if _, err := ManifestForTarget(TargetWindowsARM64, ComponentSetup, "1.2.3"); err == nil {
		t.Fatal("ARM64 Setup resources unexpectedly succeeded")
	}
	if _, err := ManifestForTarget(Target("windows_amd64_v1"), ComponentGateway, "1.2.3"); err == nil {
		t.Fatal("uncanonical target bypassed ParseTarget validation")
	}
}

func TestResourceSetIsDeterministicAndComplete(t *testing.T) {
	icon := repositoryIcon(t)
	first, err := expectedResourceSet(TargetWindowsAMD64, ComponentSetup, "1.2.3", icon)
	if err != nil {
		t.Fatal(err)
	}
	second, err := expectedResourceSet(TargetWindowsAMD64, ComponentSetup, "1.2.3", icon)
	if err != nil {
		t.Fatal(err)
	}
	firstResources := resourceMap(first)
	secondResources := resourceMap(second)
	if len(firstResources) != 8 { // manifest + version + group icon + five icon images
		t.Fatalf("resource count = %d, want 8", len(firstResources))
	}
	if len(secondResources) != len(firstResources) {
		t.Fatalf("second resource count = %d, want %d", len(secondResources), len(firstResources))
	}
	for key, expected := range firstResources {
		if !bytes.Equal(expected, secondResources[key]) {
			t.Fatalf("resource %v is not deterministic", key)
		}
	}
}

func TestVersionParsingIsStrictAndWindowsBounded(t *testing.T) {
	for _, valid := range []string{"0.8.0", "v1.2.3", "1.2.3-rc.1", "1.2.3+build.7"} {
		if _, err := parseVersion(valid); err != nil {
			t.Errorf("parseVersion(%q): %v", valid, err)
		}
	}
	for _, invalid := range []string{"", "1.2", "1.2.3.4", "1.2.3-", "65536.1.1", "1.2.3/evil"} {
		if _, err := parseVersion(invalid); err == nil {
			t.Errorf("parseVersion(%q) unexpectedly succeeded", invalid)
		}
	}
}
