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

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

// A per-user connector setup or teardown relaxes the account's
// <data dir> and <data dir>\hooks to the owner-private setup DACL
// (relaxWindowsStandalonePerUserDirectory) and hardens them again after.
// Whether such a relax is still in progress was decided from the folder's
// NTFS change time, which also moves when any entry inside the folder is
// created, renamed or deleted, and which a standard account compared only
// against a ten-minute bound (GAP-1985). The process that relaxes writes this
// record first, in the connector's machine-protected folder (administrators
// and LocalSystem write, users read), and removes it once the folders are
// hardened or restored. A relax is in progress only while a trusted record
// for the account exists, is younger than windowsGuardianSetupRelaxBound and
// names a process that still runs.
const (
	windowsSetupRelaxMarkerSchema   = 1
	windowsSetupRelaxMarkerPrefix   = ".defenseclaw-setup-relax-"
	windowsSetupRelaxMarkerMaxBytes = 4 << 10
)

type windowsSetupRelaxMarker struct {
	SchemaVersion int    `json:"schema_version"`
	SID           string `json:"sid"`
	ProcessID     uint32 `json:"process_id"`
	ProcessStart  int64  `json:"process_start_unix_nano"`
	Since         int64  `json:"since_unix_nano"`
}

// windowsGuardianSetupRelaxBound bounds one connector setup that holds a
// relax (a Hermes repair, GAP-1528).
const windowsGuardianSetupRelaxBound = 10 * time.Minute

func windowsSetupRelaxMarkerPath(connectorName string, target *windows.SID) (string, error) {
	if target == nil {
		return "", errors.New("enterprise hooks: setup relax record needs a target SID")
	}
	directory, err := windowsPerUserManagedRuntimeDir(connectorName)
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, windowsSetupRelaxMarkerPrefix+target.String()+".json"), nil
}

// writeWindowsSetupRelaxMarker records, before the relax, that this
// LocalSystem process is about to relax target's folders for a connector
// setup or teardown. It runs with the process token. A record that cannot be
// written leaves the relax unrecorded, so hooks and lifecycles treat it as
// one no running setup made, as they did with any relax before the record
// existed; the setup itself goes on.
func writeWindowsSetupRelaxMarker(connectorName string, target *windows.SID) {
	path, err := windowsSetupRelaxMarkerPath(connectorName, target)
	if err != nil {
		return
	}
	if _, err := os.Lstat(filepath.Dir(path)); err != nil {
		return
	}
	start, ok := windowsProcessStart(windows.CurrentProcess())
	if !ok {
		return
	}
	data, err := json.Marshal(windowsSetupRelaxMarker{
		SchemaVersion: windowsSetupRelaxMarkerSchema,
		SID:           target.String(),
		ProcessID:     windows.GetCurrentProcessId(),
		ProcessStart:  start,
		Since:         time.Now().UnixNano(),
	})
	if err != nil {
		return
	}
	if err := writeWindowsManagedFile(path, append(data, '\n'), true); err != nil {
		return
	}
	if err := setWindowsManagedPolicyProtection(path, false, true); err != nil {
		_ = os.Remove(path)
	}
}

// clearWindowsSetupRelaxMarker removes the record once the folders were
// hardened or restored. It runs with the process token.
func clearWindowsSetupRelaxMarker(connectorName string, target *windows.SID) {
	path, err := windowsSetupRelaxMarkerPath(connectorName, target)
	if err != nil {
		return
	}
	_ = os.Remove(path)
}

// clearWindowsSetupRelaxMarkerAsService removes the record from inside the
// target-user impersonation: a new goroutine runs on another OS thread, which
// carries only the LocalSystem process token.
func clearWindowsSetupRelaxMarkerAsService(connectorName string, target *windows.SID) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		clearWindowsSetupRelaxMarker(connectorName, target)
	}()
	<-done
}

// windowsSetupRelaxInProgress reports, only on positive proof, that a
// connector setup or teardown for target holds its relax now: a trusted
// record for target in one of the per-user connectors' machine folders,
// younger than windowsGuardianSetupRelaxBound, whose process still runs.
func windowsSetupRelaxInProgress(target *windows.SID) bool {
	if target == nil {
		return false
	}
	for _, name := range WindowsStandalonePerUserConnectorNames() {
		path, err := windowsSetupRelaxMarkerPath(name, target)
		if err != nil {
			continue
		}
		if windowsSetupRelaxMarkerLive(path, target) {
			return true
		}
	}
	return false
}

func windowsSetupRelaxMarkerLive(path string, target *windows.SID) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > windowsSetupRelaxMarkerMaxBytes {
		return false
	}
	if validateWindowsManagedRuntimeMachineFileProtection(path, true) != nil {
		return false
	}
	data, err := connector.ReadManagedHookRuntimeFile(path, "machine-protected setup relax record", windowsSetupRelaxMarkerMaxBytes)
	if err != nil {
		return false
	}
	var marker windowsSetupRelaxMarker
	if err := decodeWindowsManagedRuntimeExactJSON(data, &marker); err != nil {
		return false
	}
	if marker.SchemaVersion != windowsSetupRelaxMarkerSchema || marker.SID != target.String() || marker.ProcessID == 0 {
		return false
	}
	age := time.Since(time.Unix(0, marker.Since))
	if age < -time.Minute || age >= windowsGuardianSetupRelaxBound {
		return false
	}
	return windowsProcessStillRuns(marker.ProcessID, marker.ProcessStart)
}

// windowsProcessStillRuns reports whether process pid, started at start,
// still runs. A standard account may not open a LocalSystem process: access
// denied means the process exists, and the record's age bound covers a
// reused identifier.
func windowsProcessStillRuns(pid uint32, start int64) bool {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return errors.Is(err, windows.ERROR_ACCESS_DENIED)
	}
	defer func() { _ = windows.CloseHandle(process) }()
	var code uint32
	if err := windows.GetExitCodeProcess(process, &code); err != nil || code != windowsStillActive {
		return false
	}
	created, ok := windowsProcessStart(process)
	return ok && created == start
}

const windowsStillActive = 259

func windowsProcessStart(process windows.Handle) (int64, bool) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(process, &created, &exited, &kernel, &user); err != nil {
		return 0, false
	}
	return created.Nanoseconds(), true
}
