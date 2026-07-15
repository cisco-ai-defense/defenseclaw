// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package windowsresources defines the deterministic Windows PE resources used
// by every project-built executable shipped in the native Windows package.
//
// The package is build tooling, not runtime code. Release pipelines apply these
// resources before Authenticode signing and then read the PE back to verify the
// exact manifest, icon, and VERSIONINFO bytes.
package windowsresources

import (
	"bytes"
	"debug/pe"
	"errors"
	"fmt"
	"image"
	_ "image/png"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"
)

const (
	companyName = "Cisco Systems, Inc."
	productName = "Cisco DefenseClaw"
	copyright   = "Copyright © 2026 Cisco Systems, Inc. and its affiliates"

	// IconSource is the project-owned DefenseClaw shield also used by the macOS
	// application. Windows builds deliberately reuse it instead of inventing a
	// platform-specific mark or copying a mutable generated icon into the tree.
	IconSource = "macos/DefenseClawMac/DefenseClawMac/Assets.xcassets/AppIcon.appiconset/icon_256.png"
)

var semanticVersionPattern = regexp.MustCompile(`^(?:v)?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z][0-9A-Za-z.-]*))?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$`)

// Component identifies a project-built executable resource contract.
type Component string

const (
	ComponentGateway  Component = "gateway"
	ComponentHook     Component = "hook"
	ComponentLauncher Component = "launcher"
	ComponentStartup  Component = "startup"
	ComponentSetup    Component = "setup"
)

// AllComponents is the complete resource inventory for project-built Windows
// executables. The installed scanner and observability entry points are exact
// copies of ComponentLauncher and therefore inherit its generic command-launcher
// identity and resources. CPython and cosign retain their upstream resources.
var AllComponents = []Component{
	ComponentGateway,
	ComponentHook,
	ComponentLauncher,
	ComponentStartup,
	ComponentSetup,
}

type componentMetadata struct {
	AssemblyName     string
	Description      string
	FileDescription  string
	InternalName     string
	OriginalFilename string
	CommonControlsV6 bool
}

var componentMetadataByName = map[Component]componentMetadata{
	ComponentGateway: {
		AssemblyName:     "Cisco.DefenseClaw.Gateway",
		Description:      "DefenseClaw native gateway and command service",
		FileDescription:  "DefenseClaw Gateway",
		InternalName:     "defenseclaw-gateway",
		OriginalFilename: "defenseclaw.exe",
	},
	ComponentHook: {
		AssemblyName:     "Cisco.DefenseClaw.Hook",
		Description:      "DefenseClaw no-console agent hook",
		FileDescription:  "DefenseClaw Agent Hook",
		InternalName:     "defenseclaw-hook",
		OriginalFilename: "defenseclaw-hook.exe",
	},
	ComponentLauncher: {
		AssemblyName:     "Cisco.DefenseClaw.CommandLauncher",
		Description:      "DefenseClaw command, scanner, and observability launcher",
		FileDescription:  "DefenseClaw Command Launcher",
		InternalName:     "defenseclaw-launcher",
		OriginalFilename: "defenseclaw-launcher.exe",
	},
	ComponentStartup: {
		AssemblyName:     "Cisco.DefenseClaw.Startup",
		Description:      "DefenseClaw no-console logon startup launcher",
		FileDescription:  "DefenseClaw Startup Launcher",
		InternalName:     "defenseclaw-startup",
		OriginalFilename: "defenseclaw-startup.exe",
	},
	ComponentSetup: {
		AssemblyName:     "Cisco.DefenseClaw.Setup",
		Description:      "DefenseClaw native Windows setup",
		FileDescription:  "DefenseClaw Setup",
		InternalName:     "DefenseClawSetup",
		OriginalFilename: "DefenseClawSetup-x64.exe",
		CommonControlsV6: true,
	},
}

// ParseComponent validates a command-line component value.
func ParseComponent(value string) (Component, error) {
	component := Component(strings.ToLower(strings.TrimSpace(value)))
	if _, ok := componentMetadataByName[component]; !ok {
		return "", fmt.Errorf("unsupported Windows resource component %q", value)
	}
	return component, nil
}

type parsedVersion struct {
	Display string
	Fixed   [4]uint16
	Pre     bool
}

func parseVersion(value string) (parsedVersion, error) {
	match := semanticVersionPattern.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return parsedVersion{}, fmt.Errorf("version %q is not a supported semantic version", value)
	}
	var fixed [4]uint16
	for index := 0; index < 3; index++ {
		part, err := strconv.ParseUint(match[index+1], 10, 16)
		if err != nil {
			return parsedVersion{}, fmt.Errorf("version component %q exceeds the Windows 16-bit limit", match[index+1])
		}
		fixed[index] = uint16(part)
	}
	display := strings.TrimPrefix(strings.TrimSpace(value), "v")
	return parsedVersion{Display: display, Fixed: fixed, Pre: match[4] != ""}, nil
}

// Manifest returns the canonical UTF-8 RT_MANIFEST/1 bytes for a component.
// The manifest opts every binary into long paths, current Windows compatibility,
// per-monitor-v2 DPI behavior, and a non-elevating execution context. Setup is
// the sole executable that creates common controls, so it alone activates v6.
func Manifest(component Component, versionValue string) ([]byte, error) {
	metadata, ok := componentMetadataByName[component]
	if !ok {
		return nil, fmt.Errorf("unsupported Windows resource component %q", component)
	}
	parsed, err := parseVersion(versionValue)
	if err != nil {
		return nil, err
	}
	commonControls := ""
	if metadata.CommonControlsV6 {
		commonControls = `
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*" />
    </dependentAssembly>
  </dependency>`
	}
	manifest := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity name="%s" processorArchitecture="amd64" type="win32" version="%d.%d.%d.%d" />
  <description>%s</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" />
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2,PerMonitor</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>%s
</assembly>
`, metadata.AssemblyName, parsed.Fixed[0], parsed.Fixed[1], parsed.Fixed[2], parsed.Fixed[3], metadata.Description, commonControls)
	return []byte(manifest), nil
}

func expectedVersionInfo(component Component, versionValue string) (*version.Info, error) {
	metadata, ok := componentMetadataByName[component]
	if !ok {
		return nil, fmt.Errorf("unsupported Windows resource component %q", component)
	}
	parsed, err := parseVersion(versionValue)
	if err != nil {
		return nil, err
	}
	info := &version.Info{
		FileVersion:    parsed.Fixed,
		ProductVersion: parsed.Fixed,
		Type:           version.App,
	}
	info.Flags.Prerelease = parsed.Pre
	fields := []struct {
		key   string
		value string
	}{
		{key: version.Comments, value: "Built from the Cisco DefenseClaw open-source project."},
		{key: version.CompanyName, value: companyName},
		{key: version.FileDescription, value: metadata.FileDescription},
		{key: version.FileVersion, value: parsed.Display},
		{key: version.InternalName, value: metadata.InternalName},
		{key: version.LegalCopyright, value: copyright},
		{key: version.OriginalFilename, value: metadata.OriginalFilename},
		{key: version.ProductName, value: productName},
		{key: version.ProductVersion, value: parsed.Display},
	}
	for _, field := range fields {
		if err := info.Set(version.LangDefault, field.key, field.value); err != nil {
			return nil, fmt.Errorf("set VERSIONINFO %s: %w", field.key, err)
		}
	}
	return info, nil
}

func readIcon(path string) (image.Image, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open DefenseClaw icon: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect DefenseClaw icon: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4<<20 {
		return nil, errors.New("DefenseClaw icon must be a non-empty regular file no larger than 4 MiB")
	}
	decoded, format, err := image.Decode(io.LimitReader(file, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("decode DefenseClaw icon: %w", err)
	}
	if format != "png" {
		return nil, fmt.Errorf("DefenseClaw icon format is %q, want png", format)
	}
	if decoded.Bounds().Dx() != decoded.Bounds().Dy() || decoded.Bounds().Dx() < 256 {
		return nil, fmt.Errorf("DefenseClaw icon dimensions are %v, want a square image at least 256px", decoded.Bounds())
	}
	return decoded, nil
}

func expectedResourceSet(component Component, versionValue, iconPath string) (*winres.ResourceSet, error) {
	manifest, err := Manifest(component, versionValue)
	if err != nil {
		return nil, err
	}
	decoded, err := readIcon(iconPath)
	if err != nil {
		return nil, err
	}
	icon, err := winres.NewIconFromResizedImage(decoded, []int{256, 64, 48, 32, 16})
	if err != nil {
		return nil, fmt.Errorf("build DefenseClaw icon group: %w", err)
	}
	versionInfo, err := expectedVersionInfo(component, versionValue)
	if err != nil {
		return nil, err
	}
	resources := &winres.ResourceSet{}
	if err := resources.Set(winres.RT_MANIFEST, winres.ID(1), winres.LCIDNeutral, manifest); err != nil {
		return nil, fmt.Errorf("set application manifest: %w", err)
	}
	if err := resources.SetIcon(winres.ID(1), icon); err != nil {
		return nil, fmt.Errorf("set application icon: %w", err)
	}
	resources.SetVersionInfo(*versionInfo)
	return resources, nil
}

// Apply replaces the PE resource directory with the exact DefenseClaw resource
// set. Signed binaries are rejected so resources can never be changed after
// Authenticode signing. The caller must sign only after Apply returns.
func Apply(executable string, component Component, versionValue, iconPath string) error {
	expected, err := expectedResourceSet(component, versionValue, iconPath)
	if err != nil {
		return err
	}
	path, err := filepath.Abs(executable)
	if err != nil {
		return fmt.Errorf("resolve Windows executable: %w", err)
	}
	source, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open Windows executable: %w", err)
	}
	info, err := source.Stat()
	if err != nil {
		source.Close()
		return fmt.Errorf("inspect Windows executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		source.Close()
		return errors.New("Windows executable is not a regular file")
	}
	signed, err := winres.IsSignedEXE(source)
	if err != nil {
		source.Close()
		return fmt.Errorf("inspect PE signature directory: %w", err)
	}
	if signed {
		source.Close()
		return errors.New("refusing to modify resources after Authenticode signing")
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		source.Close()
		return fmt.Errorf("rewind Windows executable: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".resources-*")
	if err != nil {
		source.Close()
		return fmt.Errorf("create resource output: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(info.Mode()); err != nil {
		temporary.Close()
		source.Close()
		return fmt.Errorf("preserve executable mode: %w", err)
	}
	writeErr := expected.WriteToEXE(temporary, source, winres.ForceCheckSum())
	closeSourceErr := source.Close()
	if writeErr == nil {
		writeErr = temporary.Sync()
	}
	closeTemporaryErr := temporary.Close()
	if writeErr != nil {
		return fmt.Errorf("write Windows resources: %w", writeErr)
	}
	if closeSourceErr != nil {
		return fmt.Errorf("close source executable: %w", closeSourceErr)
	}
	if closeTemporaryErr != nil {
		return fmt.Errorf("close resource output: %w", closeTemporaryErr)
	}
	if err := Verify(temporaryPath, component, versionValue, iconPath); err != nil {
		return fmt.Errorf("verify resource output before publish: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish resource-complete executable: %w", err)
	}
	committed = true
	return Verify(path, component, versionValue, iconPath)
}

type resourceKey struct {
	Type     string
	Resource string
	Language uint16
}

func resourceMap(resources *winres.ResourceSet) map[resourceKey][]byte {
	result := make(map[resourceKey][]byte, resources.Count())
	resources.Walk(func(typeID, resourceID winres.Identifier, language uint16, data []byte) bool {
		key := resourceKey{
			Type:     fmt.Sprintf("%T:%v", typeID, typeID),
			Resource: fmt.Sprintf("%T:%v", resourceID, resourceID),
			Language: language,
		}
		result[key] = append([]byte(nil), data...)
		return true
	})
	return result
}

// Verify independently parses the PE and requires its complete resource set to
// byte-match the canonical manifest, five-size icon, and VERSIONINFO contract.
func Verify(executable string, component Component, versionValue, iconPath string) error {
	expected, err := expectedResourceSet(component, versionValue, iconPath)
	if err != nil {
		return err
	}
	path, err := filepath.Abs(executable)
	if err != nil {
		return fmt.Errorf("resolve Windows executable: %w", err)
	}
	peFile, err := pe.Open(path)
	if err != nil {
		return fmt.Errorf("parse PE headers: %w", err)
	}
	if peFile.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		machine := peFile.Machine
		peFile.Close()
		return fmt.Errorf("PE machine is %#x, want amd64 (%#x)", machine, pe.IMAGE_FILE_MACHINE_AMD64)
	}
	if err := peFile.Close(); err != nil {
		return fmt.Errorf("close PE headers: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open resource-complete executable: %w", err)
	}
	actual, loadErr := winres.LoadFromEXE(file)
	closeErr := file.Close()
	if loadErr != nil {
		return fmt.Errorf("load PE resources: %w", loadErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close resource-complete executable: %w", closeErr)
	}
	expectedResources := resourceMap(expected)
	actualResources := resourceMap(actual)
	if len(actualResources) != len(expectedResources) {
		return fmt.Errorf("PE resource count is %d, want exact count %d", len(actualResources), len(expectedResources))
	}
	for key, expectedData := range expectedResources {
		actualData, ok := actualResources[key]
		if !ok {
			return fmt.Errorf("PE resource is missing: type=%s name=%s language=%#04x", key.Type, key.Resource, key.Language)
		}
		if !bytes.Equal(actualData, expectedData) {
			return fmt.Errorf("PE resource bytes differ: type=%s name=%s language=%#04x", key.Type, key.Resource, key.Language)
		}
	}
	return nil
}
