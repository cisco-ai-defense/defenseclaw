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

package cli

import (
	"fmt"
	"io"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// windowsChangeSpool is the change spool <ConfigDir>\bundles\change-events
// of layout (the layout the command changes) with the bundle version
// descriptors: SYSTEM and Administrators full control, the gateway service
// read, no standard user; its reservations (reserved\) have the same
// access. Its lock lives in the Administrators-only lifecycle directory.
// An event the gateway marked reported under <DataDir> may be removed. A
// test replaces it.
var windowsChangeSpool = func(layout managed.StandaloneLayout) (enterprisestatus.ChangeSpool, error) {
	service, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return enterprisestatus.ChangeSpool{}, err
	}
	return enterprisestatus.ChangeSpool{
		Dir:      enterprisestatus.ChangeEventsDir(layout.ConfigDir),
		StateDir: layout.LifecycleDir,
		Reported: func(id string) bool { return enterprisestatus.ChangeReported(layout.DataDir, id) },
		Prepare: func(dir string) error {
			err := prepareChangeSpoolDirectory(dir,
				func(parent string) error {
					return createWindowsBundleDirectory(parent, windowsBundleDirectorySDDL(service.String()))
				},
				func(path string) error {
					return createWindowsBundleDirectory(path, windowsBundleVersionSDDL(service.String(), true))
				})
			if err != nil {
				return fmt.Errorf("prepare protected change spool: %w; run `enterprise windows repair --profile standalone --json` from an elevated administrator or SYSTEM session, then retry the credential command", err)
			}
			return nil
		},
		Publish: func(path string) error {
			return applyWindowsBundleSDDL(path, windowsBundleVersionSDDL(service.String(), false))
		},
	}, nil
}

// reserveWindowsChange reserves room in the change spool for the event of
// a change about to be made (enterprisestatus.ChangeSpool.Reserve). A
// caller that is not elevated records nothing and gets no reservation.
func reserveWindowsChange(layout managed.StandaloneLayout, kind, action, name string) (*enterprisestatus.ChangeReservation, error) {
	if !windowsSecretIsElevated() {
		return nil, nil
	}
	spool, err := windowsChangeSpool(layout)
	if err != nil {
		return nil, err
	}
	return spool.Reserve(kind, action, name)
}

// recordWindowsChange writes one change event: through reservation when
// the command reserved room for its change, else (a refusal) straight
// into the spool. Only an elevated caller records; any other records
// nothing and reports no error. A failure is reported as change_unrecorded.
func recordWindowsChange(layout managed.StandaloneLayout, reservation *enterprisestatus.ChangeReservation, ev enterprisestatus.ChangeEvent) error {
	if !windowsSecretIsElevated() {
		return nil
	}
	if reservation != nil {
		return reservation.Write(ev)
	}
	spool, err := windowsChangeSpool(layout)
	if err != nil {
		return err
	}
	return spool.Write(ev)
}

// recordWindowsAnchorsChange records an anchor file a run installed.
func recordWindowsAnchorsChange(layout managed.StandaloneLayout, reservation *enterprisestatus.ChangeReservation, change *anchorOnlyChange) error {
	if change == nil {
		return nil
	}
	previous := change.previous
	if !change.existed {
		previous = nil
	}
	if ev, ok := anchorsChangeEvent(previous, change.installed); ok {
		return recordWindowsChange(layout, reservation, ev)
	}
	return nil
}

// recordWindowsAnchorsFailure records a refused or failed anchor install;
// installed is the file still installed (nil: none).
func recordWindowsAnchorsFailure(layout managed.StandaloneLayout, reservation *enterprisestatus.ChangeReservation, code string, failed bool, installed []byte) error {
	if ev, ok := anchorsFailureEvent(code, failed, installed); ok {
		return recordWindowsChange(layout, reservation, ev)
	}
	return nil
}

// warnChangeUnrecorded prints change_unrecorded on w for a run whose result
// document has no warnings to carry it.
func warnChangeUnrecorded(w io.Writer, err error) {
	if err == nil || w == nil {
		return
	}
	warning := changeUnrecordedWarning(err)
	fmt.Fprintf(w, "warning: %s: %s\n", warning.Code, warning.Message)
}
