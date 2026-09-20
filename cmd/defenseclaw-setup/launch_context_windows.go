// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	userObjectFlags      = 1
	windowStationVisible = 0x0001
)

var (
	launchContextUser32                  = windows.NewLazySystemDLL("user32.dll")
	procGetProcessWindowStation          = launchContextUser32.NewProc("GetProcessWindowStation")
	procGetUserObjectInformationForSetup = launchContextUser32.NewProc("GetUserObjectInformationW")
)

type setupUserObjectFlags struct {
	Inherit  int32
	Reserved int32
	Flags    uint32
}

func probeSetupLaunchContext() (setupLaunchFacts, error) {
	token := windows.GetCurrentProcessToken()
	var facts setupLaunchFacts
	var probeErrors []error

	elevated, err := tokenUint32(token, windows.TokenElevation)
	if err != nil {
		probeErrors = append(probeErrors, fmt.Errorf("query token elevation: %w", err))
	} else {
		facts.Elevated = elevated != 0
	}
	sessionID, err := tokenUint32(token, windows.TokenSessionId)
	sessionKnown := err == nil
	if err != nil {
		probeErrors = append(probeErrors, fmt.Errorf("query token session: %w", err))
	} else {
		facts.SessionID = sessionID
	}
	user, err := token.GetTokenUser()
	userKnown := err == nil
	if err != nil {
		probeErrors = append(probeErrors, fmt.Errorf("query token user: %w", err))
	}
	groups, err := token.GetTokenGroups()
	groupsKnown := err == nil
	if err != nil {
		probeErrors = append(probeErrors, fmt.Errorf("query token groups: %w", err))
	}

	if userKnown {
		facts.ServiceIdentity = user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) ||
			user.User.Sid.IsWellKnown(windows.WinLocalServiceSid) ||
			user.User.Sid.IsWellKnown(windows.WinNetworkServiceSid)
	}
	if groupsKnown {
		facts.ServiceIdentity = facts.ServiceIdentity || tokenContainsWellKnownGroup(groups, windows.WinServiceSid)
		facts.InteractiveToken = tokenContainsWellKnownGroup(groups, windows.WinInteractiveSid)
	}
	visibleStation, err := processWindowStationIsVisible()
	stationKnown := err == nil
	if err != nil {
		probeErrors = append(probeErrors, fmt.Errorf("query process window station: %w", err))
	} else {
		facts.InteractiveWindowStation = visibleStation
	}
	facts.DialogSafe = userKnown && groupsKnown && sessionKnown && stationKnown &&
		!facts.ServiceIdentity && facts.SessionID != 0 && facts.InteractiveToken &&
		facts.InteractiveWindowStation
	return facts, errors.Join(probeErrors...)
}

func tokenUint32(token windows.Token, informationClass uint32) (uint32, error) {
	var value uint32
	var returned uint32
	err := windows.GetTokenInformation(
		token,
		informationClass,
		(*byte)(unsafe.Pointer(&value)),
		uint32(unsafe.Sizeof(value)),
		&returned,
	)
	if err != nil {
		return 0, err
	}
	if returned != uint32(unsafe.Sizeof(value)) {
		return 0, fmt.Errorf("unexpected token information size %d", returned)
	}
	return value, nil
}

func tokenContainsWellKnownGroup(groups *windows.Tokengroups, sidType windows.WELL_KNOWN_SID_TYPE) bool {
	for _, group := range groups.AllGroups() {
		if group.Sid != nil && group.Sid.IsWellKnown(sidType) {
			return true
		}
	}
	return false
}

func processWindowStationIsVisible() (bool, error) {
	station, _, callErr := procGetProcessWindowStation.Call()
	if station == 0 {
		return false, win32LaunchContextError("GetProcessWindowStation", callErr)
	}
	var flags setupUserObjectFlags
	var returned uint32
	ok, _, callErr := procGetUserObjectInformationForSetup.Call(
		station,
		userObjectFlags,
		uintptr(unsafe.Pointer(&flags)),
		unsafe.Sizeof(flags),
		uintptr(unsafe.Pointer(&returned)),
	)
	if ok == 0 {
		return false, win32LaunchContextError("GetUserObjectInformationW", callErr)
	}
	if returned != uint32(unsafe.Sizeof(flags)) {
		return false, fmt.Errorf("GetUserObjectInformationW returned %d bytes, want %d", returned, unsafe.Sizeof(flags))
	}
	return flags.Flags&windowStationVisible != 0, nil
}

func win32LaunchContextError(operation string, err error) error {
	if err == nil || errors.Is(err, windows.ERROR_SUCCESS) {
		return fmt.Errorf("%s failed without a Win32 error", operation)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func showSetupLaunchContextFailure(err error, quiet bool) {
	if quiet {
		return
	}
	var launchErr *setupLaunchContextError
	if !errors.As(err, &launchErr) || !launchErr.Decision.AllowDialog {
		return
	}
	messageBox(0, launchErr.Error(), "DefenseClaw Setup", 0x00000010|0x00010000) // MB_ICONERROR | MB_SETFOREGROUND
}
