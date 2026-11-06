//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const (
	WindowsOpenCodeServicePortsFileName = "opencode-service-ports.json"
	windowsOpenCodeServicePortsMaxBytes = 1 << 20
	windowsOpenCodeServicePortsSDDL     = "O:SYG:SYD:P(A;;FA;;;SY)"
)

type windowsOpenCodeServicePortsFile struct {
	Version int                          `json:"version"`
	Ports   []windowsOpenCodeServicePort `json:"ports"`
}

type windowsOpenCodeServicePort struct {
	SID  string `json:"sid"`
	Port int    `json:"port"`
}

func WindowsOpenCodeServicePortsPath(manifestPath string) string {
	return filepath.Join(filepath.Dir(manifestPath), WindowsOpenCodeServicePortsFileName)
}

// LoadWindowsOpenCodeServicePorts reads the guardian's SYSTEM-only record.
// A missing record is empty; an untrusted or malformed record is an error.
func LoadWindowsOpenCodeServicePorts(path string) (map[string]int, error) {
	ports := map[string]int{}
	if err := windowsOpenCodeServicePortsParent(path); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return ports, nil
	} else if err != nil {
		return nil, err
	}
	if err := validateWindowsOpenCodeServicePortsFile(path); err != nil {
		return nil, err
	}
	data, err := readWindowsBoundedPlainFile(path, windowsOpenCodeServicePortsMaxBytes)
	if err != nil {
		return nil, err
	}
	var record windowsOpenCodeServicePortsFile
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("enterprise hooks: parse OpenCode service ports: %w", err)
	}
	if record.Version != 1 {
		return nil, fmt.Errorf("enterprise hooks: OpenCode service ports version %d is not supported", record.Version)
	}
	for _, entry := range record.Ports {
		sid, err := windows.StringToSid(entry.SID)
		if err != nil || !WindowsInteractiveUserSID(entry.SID) || sid.String() != entry.SID || entry.Port <= 0 || entry.Port > 65535 {
			return nil, fmt.Errorf("enterprise hooks: OpenCode service ports record has an invalid account or port")
		}
		if _, exists := ports[entry.SID]; exists {
			return nil, fmt.Errorf("enterprise hooks: OpenCode service ports record repeats an account")
		}
		ports[entry.SID] = entry.Port
	}
	return ports, nil
}

// WriteWindowsOpenCodeServicePorts publishes only complete, validated
// assignments. The staging file gets the SYSTEM-only ACL before replacement.
func WriteWindowsOpenCodeServicePorts(path string, ports map[string]int) error {
	if err := windowsOpenCodeServicePortsParent(path); err != nil {
		return err
	}
	record := windowsOpenCodeServicePortsFile{Version: 1, Ports: make([]windowsOpenCodeServicePort, 0, len(ports))}
	for sid, port := range ports {
		parsed, err := windows.StringToSid(sid)
		if err != nil || !WindowsInteractiveUserSID(sid) || parsed.String() != sid || port <= 0 || port > 65535 {
			return fmt.Errorf("enterprise hooks: OpenCode service ports assignment has an invalid account or port")
		}
		record.Ports = append(record.Ports, windowsOpenCodeServicePort{SID: sid, Port: port})
	}
	sort.Slice(record.Ports, func(i, j int) bool { return record.Ports[i].SID < record.Ports[j].SID })
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > windowsOpenCodeServicePortsMaxBytes {
		return fmt.Errorf("enterprise hooks: OpenCode service ports record is too large")
	}
	if _, err := os.Lstat(path); err == nil {
		if err := validateWindowsOpenCodeServicePortsFile(path); err != nil {
			return err
		}
		current, err := readWindowsBoundedPlainFile(path, windowsOpenCodeServicePortsMaxBytes)
		if err != nil {
			return err
		}
		if string(current) == string(data) {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	staged, err := os.CreateTemp(filepath.Dir(path), ".defenseclaw-opencode-ports-*.new")
	if err != nil {
		return err
	}
	stagedPath := staged.Name()
	defer func() { _ = os.Remove(stagedPath) }()
	if err := staged.Close(); err != nil {
		return err
	}
	if err := protectWindowsOpenCodeServicePortsFile(stagedPath); err != nil {
		return err
	}
	staged, err = os.OpenFile(stagedPath, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if _, err := staged.Write(data); err != nil {
		_ = staged.Close()
		return err
	}
	if err := staged.Sync(); err != nil {
		_ = staged.Close()
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	if err := validateWindowsOpenCodeServicePortsFile(stagedPath); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := validateWindowsOpenCodeServicePortsFile(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := safefile.ReplaceFile(stagedPath, path); err != nil {
		return err
	}
	return validateWindowsOpenCodeServicePortsFile(path)
}

func windowsOpenCodeServicePortsParent(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("enterprise hooks: OpenCode service ports path must be absolute and clean")
	}
	dir := filepath.Dir(path)
	if err := windowsTargetsManifestAncestorTrust(dir); err != nil {
		return err
	}
	return validateWindowsTargetsManifestObject(dir, true)
}

func protectWindowsOpenCodeServicePortsFile(path string) error {
	if err := validateWindowsTargetsManifestObjectShape(path, false); err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString(windowsOpenCodeServicePortsSDDL)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	group, _, err := descriptor.Group()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, group, dacl, nil); err != nil {
		return err
	}
	return validateWindowsOpenCodeServicePortsFile(path)
}

func validateWindowsOpenCodeServicePortsFile(path string) error {
	handle, err := openWindowsTargetsManifestObject(path, false, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	actual, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	expected, err := windows.SecurityDescriptorFromString(windowsOpenCodeServicePortsSDDL)
	if err != nil {
		return err
	}
	actualOwner, _, ownerErr := actual.Owner()
	expectedOwner, _, expectedOwnerErr := expected.Owner()
	actualGroup, _, groupErr := actual.Group()
	expectedGroup, _, expectedGroupErr := expected.Group()
	control, _, controlErr := actual.Control()
	actualDACL, _, aclErr := actual.DACL()
	expectedDACL, _, expectedACLErr := expected.DACL()
	if ownerErr != nil || expectedOwnerErr != nil || groupErr != nil || expectedGroupErr != nil ||
		controlErr != nil || aclErr != nil || expectedACLErr != nil || actualOwner == nil || expectedOwner == nil ||
		actualGroup == nil || expectedGroup == nil || actualDACL == nil || expectedDACL == nil ||
		!actualOwner.Equals(expectedOwner) || !actualGroup.Equals(expectedGroup) || control&windows.SE_DACL_PROTECTED == 0 ||
		actualDACL.AceCount != 1 || expectedDACL.AceCount != 1 {
		return fmt.Errorf("enterprise hooks: OpenCode service ports record is not SYSTEM-only: %s", path)
	}
	var actualACE, expectedACE *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(actualDACL, 0, &actualACE); err != nil {
		return err
	}
	if err := windows.GetAce(expectedDACL, 0, &expectedACE); err != nil {
		return err
	}
	if actualACE == nil || expectedACE == nil || actualACE.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		actualACE.Header.AceFlags != expectedACE.Header.AceFlags || actualACE.Header.AceSize != expectedACE.Header.AceSize ||
		actualACE.Mask != expectedACE.Mask ||
		!(*windows.SID)(unsafe.Pointer(&actualACE.SidStart)).Equals((*windows.SID)(unsafe.Pointer(&expectedACE.SidStart))) {
		return fmt.Errorf("enterprise hooks: OpenCode service ports record is not SYSTEM-only: %s", path)
	}
	return nil
}
