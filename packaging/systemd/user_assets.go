// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package systemdunits

import (
	"embed"
	"io/fs"
	"sort"
)

// The sandbox user units live in user/, outside the globs of assets.go: they
// are user-manager units (/usr/lib/systemd/user, /etc/systemd/user), not the
// system units Units lists and the lifecycle installs and enables for the
// deployment itself.
//
//go:embed user/*
var userFiles embed.FS

// UserUnits lists the sandbox user unit file names in a stable order.
func UserUnits() []string {
	entries, _ := fs.ReadDir(userFiles, "user")
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

// ReadUserUnit returns one embedded sandbox user unit.
func ReadUserUnit(name string) ([]byte, error) {
	return userFiles.ReadFile("user/" + name)
}
