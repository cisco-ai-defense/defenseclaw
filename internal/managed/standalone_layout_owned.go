// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"reflect"
	"slices"
	"strings"
)

// OwnedPaths returns every file system path the layout names: the install
// root and binaries, the configuration, policy and secret folders, the
// guardian and lifecycle state, the data and log folders, the hook runtime
// and the socket folders. A path-valued field is recognized by its shape, so
// a field added to the layout is covered without a second list; the service
// account, the platform name and the API address are not paths.
func (l StandaloneLayout) OwnedPaths() []string {
	var owned []string
	fields := reflect.ValueOf(l)
	for i := range fields.NumField() {
		field := fields.Field(i)
		if field.Kind() != reflect.String {
			continue
		}
		value := field.String()
		if strings.HasPrefix(value, "/") || windowsDriveAbsolute(value) {
			owned = append(owned, value)
		}
	}
	return owned
}

// StandaloneWindowsOwnFolders returns the folders that hold a standalone
// Windows deployment under the given Program Files and ProgramData roots:
// the install root below Program Files and the state root, the hook runtime
// and the scanner runtime below ProgramData, each as a full path. They come
// from the layout itself, so a folder that the lifecycle adds is covered as
// well. The roots are the trusted registration (TrustedStandaloneWindowsRoots)
// or any other canonical absolute drive roots StandaloneWindowsLayoutForRoots
// accepts; nil when they are not.
func StandaloneWindowsOwnFolders(programFiles, programData string) []string {
	layout, err := StandaloneWindowsLayoutForRoots(programFiles, programData)
	if err != nil {
		return nil
	}
	programFiles = strings.TrimRight(strings.TrimSpace(programFiles), `\`)
	programData = strings.TrimRight(strings.TrimSpace(programData), `\`)
	owned := append(layout.OwnedPaths(), StandaloneWindowsScannerRuntimeDirForRoot(programData))
	var folders []string
	for _, value := range owned {
		for _, root := range []string{programFiles, programData} {
			rest, ok := strings.CutPrefix(value, root+`\`)
			if !ok {
				continue
			}
			parts := strings.SplitN(rest, `\`, 3)
			if len(parts) < 2 {
				continue
			}
			if folder := root + `\` + parts[0] + `\` + parts[1]; !slices.Contains(folders, folder) {
				folders = append(folders, folder)
			}
		}
	}
	return folders
}
