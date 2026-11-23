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
// the install root below Program Files and the state root, the hook runtime,
// the scanner runtime and the shipped rule packs below ProgramData, each as
// a full path. They come
// from the layout itself, so a folder that the lifecycle adds is covered as
// well. The roots are the trusted registration (TrustedStandaloneWindowsRoots)
// or any other canonical absolute drive roots StandaloneWindowsLayoutForRoots
// accepts; nil when they are not.
//
// Which root a layout path belongs to is read from a layout built on two
// roots that do not contain one another, never from a prefix of the real
// roots: one root may sit below the other (D:\Applications and
// D:\Applications\Data), and the folders between them are not owned.
func StandaloneWindowsOwnFolders(programFiles, programData string) []string {
	if _, err := StandaloneWindowsLayoutForRoots(programFiles, programData); err != nil {
		return nil
	}
	const probeFiles, probeData = `Z:\files`, `Z:\data`
	probe, err := StandaloneWindowsLayoutForRoots(probeFiles, probeData)
	if err != nil {
		return nil
	}
	programFiles = strings.TrimRight(strings.TrimSpace(programFiles), `\`)
	programData = strings.TrimRight(strings.TrimSpace(programData), `\`)
	owned := append(probe.OwnedPaths(), StandaloneWindowsScannerRuntimeDirForRoot(probeData),
		StandaloneWindowsShippedRulePacksDirForRoot(probeData))
	var folders []string
	for _, value := range owned {
		for _, root := range [][2]string{{probeFiles, programFiles}, {probeData, programData}} {
			rest, ok := strings.CutPrefix(value, root[0]+`\`)
			if !ok {
				continue
			}
			parts := strings.SplitN(rest, `\`, 3)
			if len(parts) < 2 {
				continue
			}
			if folder := root[1] + `\` + parts[0] + `\` + parts[1]; !slices.Contains(folders, folder) {
				folders = append(folders, folder)
			}
		}
	}
	return folders
}
