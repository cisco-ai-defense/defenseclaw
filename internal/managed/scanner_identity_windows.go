// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const windowsGatewayProfileRefusal = "the managed gateway runs as LocalSystem and does not read inside user profiles; scan the folder as the signed-in user (defenseclaw ... from the user session) or move it outside the profile"

var (
	windowsGatewayPathIsService = WindowsCurrentProcessIsGatewayService
	windowsGatewayPathTokenUser = func() (*windows.Tokenuser, error) {
		return windows.GetCurrentProcessToken().GetTokenUser()
	}
	windowsGatewayProfileRoots = readWindowsGatewayProfileRoots
	windowsGatewayResolvePath  = resolveWindowsGatewayPath
)

// RequireWindowsGatewayPathOutsideUserProfiles checks a path before the
// LocalSystem gateway reads it or passes it to a scanner child. All other
// processes retain their ordinary filesystem access. Existing junctions and
// short names are resolved before the profile boundary is compared.
func RequireWindowsGatewayPathOutsideUserProfiles(path string) error {
	if !windowsGatewayPathIsService() {
		return nil
	}
	user, err := windowsGatewayPathTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("managed gateway cannot verify its process token")
	}
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	roots, err := windowsGatewayProfileRoots()
	if err != nil {
		return fmt.Errorf("managed gateway cannot read Windows profile roots: %w", err)
	}
	resolved, err := windowsGatewayResolvePath(path)
	if err != nil {
		return fmt.Errorf("managed gateway cannot resolve target path: %w", err)
	}
	if windowsPathWithinProfileRoots(resolved, roots) || windowsPathWithinProfileRoots(path, roots) {
		return errors.New(windowsGatewayProfileRefusal)
	}
	return nil
}

func readWindowsGatewayProfileRoots() ([]string, error) {
	const profileList = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, profileList, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return nil, err
	}
	defer key.Close()
	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	windowsDir, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return nil, err
	}
	systemDrive := filepath.VolumeName(windowsDir)
	if systemDrive == "" {
		return nil, fmt.Errorf("Windows system drive is unavailable")
	}
	roots := []string{filepath.Join(systemDrive+`\`, "Users")}
	if configured, _, readErr := key.GetStringValue("ProfilesDirectory"); readErr == nil {
		root, expandErr := expandWindowsGatewayProfilePath(configured, systemDrive, windowsDir)
		if expandErr != nil {
			return nil, expandErr
		}
		roots = append(roots, root)
	} else if !errors.Is(readErr, registry.ErrNotExist) {
		return nil, readErr
	}
	for _, name := range names {
		entry, openErr := registry.OpenKey(key, name, registry.READ)
		if openErr != nil {
			return nil, openErr
		}
		raw, _, readErr := entry.GetStringValue("ProfileImagePath")
		entry.Close()
		if errors.Is(readErr, registry.ErrNotExist) {
			continue
		}
		if readErr != nil {
			return nil, readErr
		}
		root, expandErr := expandWindowsGatewayProfilePath(raw, systemDrive, windowsDir)
		if expandErr != nil {
			return nil, expandErr
		}
		roots = append(roots, root)
	}
	// Compare both configured names and destinations of redirected roots.
	return windowsGatewayProfileRootResolution.resolve(roots, time.Now(), resolveWindowsGatewayPath)
}

// windowsGatewayProfileRootResolution keeps the gateway process's last
// resolution of its profile roots (profileRootResolution).
var windowsGatewayProfileRootResolution profileRootResolution

func expandWindowsGatewayProfilePath(raw, systemDrive, windowsDir string) (string, error) {
	path := strings.TrimSpace(strings.ReplaceAll(raw, "/", `\`))
	for {
		start := strings.IndexByte(path, '%')
		if start < 0 {
			break
		}
		end := strings.IndexByte(path[start+1:], '%')
		if end < 0 {
			return "", fmt.Errorf("Windows profile root has an invalid expansion")
		}
		name := path[start+1 : start+1+end]
		var value string
		switch {
		case strings.EqualFold(name, "SystemDrive"):
			value = systemDrive
		case strings.EqualFold(name, "SystemRoot"):
			value = windowsDir
		default:
			return "", fmt.Errorf("Windows profile root has an unsupported expansion")
		}
		path = path[:start] + value + path[start+end+2:]
	}
	if path == "" || strings.Contains(path, "%") || !filepath.IsAbs(path) {
		return "", fmt.Errorf("Windows profile root is unavailable or invalid")
	}
	return filepath.Clean(path), nil
}

// resolveWindowsGatewayPath follows every existing reparse component. For a
// path not yet present, its deepest existing parent is resolved and the
// missing suffix is appended without opening it.
func resolveWindowsGatewayPath(path string) (string, error) {
	path = strings.ReplaceAll(path, "/", `\`)
	hadExtendedPrefix := strings.HasPrefix(strings.ToLower(path), `\\?\`)
	switch {
	case strings.HasPrefix(strings.ToLower(path), `\\?\unc\`):
		path = `\\` + path[len(`\\?\UNC\`):]
	case strings.HasPrefix(path, `\\?\`):
		path = path[len(`\\?\`):]
	}
	if hadExtendedPrefix {
		for _, part := range strings.Split(path, `\`) {
			if part == ".." {
				return "", fmt.Errorf("extended path contains a parent component")
			}
		}
	}
	if strings.HasPrefix(path, `\\.\`) || (hadExtendedPrefix && !filepath.IsAbs(path)) {
		return "", fmt.Errorf("path must be a filesystem path")
	}
	if !filepath.IsAbs(path) {
		var err error
		path, err = filepath.Abs(path)
		if err != nil {
			return "", err
		}
	}
	current := filepath.Clean(path)
	var missing []string
	for {
		pointer, err := winpath.UTF16Ptr(current)
		if err != nil {
			return "", err
		}
		handle, err := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err == nil {
			resolved, finalErr := windowsGatewayFinalPath(handle)
			windows.CloseHandle(handle)
			if finalErr != nil {
				return "", finalErr
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return "", err
		}
		// A dangling reparse point is not a safe missing path.
		if link, linkErr := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0); linkErr == nil {
			windows.CloseHandle(link)
			return "", fmt.Errorf("target contains an unresolved reparse point")
		} else if !errors.Is(linkErr, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(linkErr, windows.ERROR_PATH_NOT_FOUND) {
			return "", linkErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func windowsGatewayFinalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 512)
	for {
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err == nil && length < uint32(len(buffer)) {
			path := windows.UTF16ToString(buffer[:length])
			switch {
			case strings.HasPrefix(strings.ToLower(path), `\\?\unc\`):
				path = `\\` + path[len(`\\?\UNC\`):]
			case strings.HasPrefix(path, `\\?\`):
				path = path[len(`\\?\`):]
			}
			return filepath.Clean(path), nil
		}
		if length >= uint32(len(buffer)) || errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			buffer = make([]uint16, max(int(length)+1, len(buffer)*2))
			continue
		}
		return "", err
	}
}
