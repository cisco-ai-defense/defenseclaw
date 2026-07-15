//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var enterpriseHookSIDProfilePath = windowsEnterpriseHookSIDProfilePath

var enterpriseHookWindowsSystemDirectory = windows.GetSystemDirectory

func enterpriseHooksNativePlatformPreflight() error {
	if enterpriseHooksRuntimeGOOS() != "windows" {
		return nil
	}
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return nil
	}
	user, err := token.GetTokenUser()
	if err == nil && user != nil && user.User.Sid != nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	return fmt.Errorf("enterprise hooks require an elevated administrator or LocalSystem token on native Windows")
}

func windowsEnterpriseHookSIDProfilePath(rawSID string) (string, error) {
	sid, err := windows.StringToSid(strings.TrimSpace(rawSID))
	if err != nil {
		return "", fmt.Errorf("parse SID: %w", err)
	}
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+sid.String(),
		registry.QUERY_VALUE,
	)
	if err != nil {
		return "", err
	}
	defer key.Close()
	profile, valueType, err := key.GetStringValue("ProfileImagePath")
	if err != nil {
		return "", err
	}
	if valueType == registry.EXPAND_SZ {
		profile, err = expandEnterpriseHookProfileImagePath(profile)
		if err != nil {
			return "", err
		}
	}
	profile = strings.TrimSpace(profile)
	if profile == "" || !filepath.IsAbs(profile) {
		return "", fmt.Errorf("profile path is empty or not absolute")
	}
	return filepath.Clean(profile), nil
}

func expandEnterpriseHookProfileImagePath(profile string) (string, error) {
	const systemDrive = `%SystemDrive%`
	profile = strings.TrimSpace(profile)
	if len(profile) < len(systemDrive) || !strings.EqualFold(profile[:len(systemDrive)], systemDrive) {
		if strings.Contains(profile, "%") {
			return "", fmt.Errorf("ProfileImagePath contains an unsupported environment expansion")
		}
		return profile, nil
	}
	systemDirectory, err := enterpriseHookWindowsSystemDirectory()
	if err != nil {
		return "", fmt.Errorf("resolve trusted Windows system drive: %w", err)
	}
	drive := filepath.VolumeName(filepath.Clean(systemDirectory))
	if drive == "" {
		return "", fmt.Errorf("resolve trusted Windows system drive from %q", systemDirectory)
	}
	expanded := drive + profile[len(systemDrive):]
	if strings.Contains(expanded, "%") {
		return "", fmt.Errorf("ProfileImagePath contains an unsupported environment expansion")
	}
	return expanded, nil
}
