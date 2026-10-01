// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package systemdunits embeds the standalone managed-enterprise systemd
// units so the lifecycle installs exactly the reviewed files that ship in
// the repository and the Linux packages.
package systemdunits

import (
	"embed"
	"io/fs"
	"sort"
)

//go:embed *.service *.socket *.path *.timer defenseclaw.conf defenseclaw.sysusers
var files embed.FS

// Units lists the unit file names in a stable order.
func Units() []string {
	entries, _ := fs.ReadDir(files, ".")
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		switch name {
		case TmpfilesName, SysusersName:
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ReadFile returns one embedded file.
func ReadFile(name string) ([]byte, error) {
	return files.ReadFile(name)
}

// Embedded names of the tmpfiles.d and sysusers.d documents.
const (
	TmpfilesName = "defenseclaw.conf"
	SysusersName = "defenseclaw.sysusers"
)
