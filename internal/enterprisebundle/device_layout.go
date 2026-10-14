// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"fmt"
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// DeviceLayout contains the installed paths that affect config defaults.
// Bundle assets remain rooted at the staging or version directory.
type DeviceLayout struct {
	ConfigPath string
	DataDir    string
	PolicyDir  string
}

func DeviceLayoutFromManaged(layout managed.StandaloneLayout) DeviceLayout {
	return DeviceLayout{ConfigPath: layout.ConfigPath, DataDir: layout.DataDir, PolicyDir: layout.PolicyDir}
}

// StandardDeviceLayout is the target platform's standard managed layout.
// It never consults the signing host's registration or environment.
func StandardDeviceLayout(platform string) (DeviceLayout, error) {
	var layout managed.StandaloneLayout
	var err error
	switch platform {
	case PlatformLinux, PlatformDarwin:
		layout, err = managed.StandaloneLayoutFor(platform)
	case PlatformWindows:
		layout, err = managed.StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	default:
		return DeviceLayout{}, fmt.Errorf("unknown platform %q", platform)
	}
	if err != nil {
		return DeviceLayout{}, err
	}
	return DeviceLayoutFromManaged(layout), nil
}

// IsStandard reports whether a registered device uses the paths the signer
// can model. Windows paths compare without regard to case or slash spelling.
func (l DeviceLayout) IsStandard(platform string) bool {
	standard, err := StandardDeviceLayout(platform)
	if err != nil {
		return false
	}
	paths := [][2]string{{l.ConfigPath, standard.ConfigPath}, {l.DataDir, standard.DataDir}, {l.PolicyDir, standard.PolicyDir}}
	for _, pair := range paths {
		actual, want := pair[0], pair[1]
		if platform == PlatformWindows {
			actual = strings.ToLower(path.Clean(strings.ReplaceAll(actual, `\`, `/`)))
			want = strings.ToLower(path.Clean(strings.ReplaceAll(want, `\`, `/`)))
		} else {
			actual, want = path.Clean(actual), path.Clean(want)
		}
		if actual != want {
			return false
		}
	}
	return true
}

func windowsStandardDataDir(value string) bool {
	standard, err := StandardDeviceLayout(PlatformWindows)
	if err != nil {
		return false
	}
	actual := strings.ToLower(path.Clean(strings.ReplaceAll(value, `\`, `/`)))
	want := strings.ToLower(path.Clean(strings.ReplaceAll(standard.DataDir, `\`, `/`)))
	return actual == want
}
