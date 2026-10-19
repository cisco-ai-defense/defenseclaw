// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

// Fixed read-only contributor diagnostic. No default invocation queries a profile.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const syntheticSID = "S-1-15-2-1-2-3-4-5-6-7"

type queryReport struct {
	Scope              string       `json:"scope"`
	Stage              string       `json:"stage"`
	Completed          bool         `json:"query_completed"`
	SyntheticSID       bool         `json:"fixed_synthetic_sid"`
	EnvironmentMatched bool         `json:"fixed_eight_environment_matched"`
	ThreadIdentity     string       `json:"thread_identity"`
	KnownHRESULT       *string      `json:"known_folder_hresult"`
	NativeHRESULT      *string      `json:"synthetic_native_folder_hresult"`
	Classes            *pathClasses `json:"classes"`
	ProfileCreated     bool         `json:"profile_creation_calls"`
	FilesystemWrites   bool         `json:"explicit_filesystem_write_calls"`
	Production         bool         `json:"production_qualification"`
}

func expectedPrivateBase() (string, bool) {
	image, err := os.Executable()
	if err != nil || filepath.Base(image) != "profile-query-control.exe" {
		return "", false
	}
	root := filepath.Dir(image)
	if !filepath.IsAbs(root) || !strings.HasPrefix(filepath.Base(root), "profile-query-control-") ||
		filepath.Base(filepath.Dir(root)) != "environment-control-private-02" {
		return "", false
	}
	cwd, err := os.Getwd()
	if err != nil || cwd != filepath.Join(root, "workspace") {
		return "", false
	}
	system, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return "", false
	}
	expected := map[string]string{
		"SYSTEMROOT": system, "WINDIR": system,
		"HOME": filepath.Join(root, "home"), "USERPROFILE": filepath.Join(root, "home"),
		"APPDATA":      filepath.Join(root, "home", "AppData", "Roaming"),
		"LOCALAPPDATA": filepath.Join(root, "home", "AppData", "Local"),
		"TEMP":         filepath.Join(root, "tmp"), "TMP": filepath.Join(root, "tmp"),
	}
	if len(os.Environ()) != len(expected) {
		return "", false
	}
	for name, value := range expected {
		if actual, present := os.LookupEnv(name); !present || actual != value {
			return "", false
		}
	}
	return expected["LOCALAPPDATA"], true
}

func threadIdentity() string {
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if err == nil {
		if token.Close() != nil {
			return "unexpected_thread_token_close_failed"
		}
		return "unexpected_thread_token"
	}
	if err == windows.ERROR_NO_TOKEN {
		return "absent"
	}
	return "thread_token_query_refused"
}

// The documented APIs return an OS-allocated NUL-terminated string. Copy at
// most 2048 UTF16 units before freeing with the matching CoTaskMemFree API.
func boundedWide(pointer *uint16) ([]uint16, bool) {
	if pointer == nil {
		return nil, false
	}
	var result []uint16
	for index := 0; index <= 2048; index++ {
		unit := *(*uint16)(unsafe.Add(unsafe.Pointer(pointer), index*2))
		if unit == 0 {
			return result, len(result) != 0
		}
		result = append(result, unit)
	}
	return nil, false
}

func queryFixed() queryReport {
	r := queryReport{Scope: "fixed_windows_read_only_synthetic_profile_query", SyntheticSID: true,
		Stage: "environment_refused", ThreadIdentity: "not_queried"}
	private, matched := expectedPrivateBase()
	if !matched {
		return r
	}
	r.EnvironmentMatched = true
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	r.ThreadIdentity = threadIdentity()
	if r.ThreadIdentity != "absent" {
		r.Stage = "thread_identity_refused"
		return r
	}
	known := windows.NewLazySystemDLL("shell32.dll").NewProc("SHGetKnownFolderPath")
	native := windows.NewLazySystemDLL("userenv.dll").NewProc("GetAppContainerFolderPath")
	free := windows.NewLazySystemDLL("ole32.dll").NewProc("CoTaskMemFree")
	if known.Find() != nil || native.Find() != nil || free.Find() != nil {
		r.Stage = "read_only_api_unavailable"
		return r
	}
	var knownPointer *uint16
	// Exact documented flags: DONT_VERIFY | NO_PACKAGE_REDIRECTION. No CREATE.
	status, _, _ := known.Call(uintptr(unsafe.Pointer(windows.FOLDERID_LocalAppData)), 0x4000|0x10000, 0,
		uintptr(unsafe.Pointer(&knownPointer)))
	knownHR := fmt.Sprintf("0x%08x", uint32(status))
	r.KnownHRESULT = &knownHR
	var knownUnits []uint16
	var knownOK bool
	if int32(status) >= 0 {
		knownUnits, knownOK = boundedWide(knownPointer)
	}
	if knownPointer != nil {
		free.Call(uintptr(unsafe.Pointer(knownPointer)))
	}
	if int32(status) < 0 || !knownOK {
		r.Stage = "known_folder_query_refused"
		return r
	}
	sid, _ := windows.UTF16PtrFromString(syntheticSID)
	var nativePointer *uint16
	status, _, _ = native.Call(uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&nativePointer)))
	runtime.KeepAlive(sid)
	nativeHR := fmt.Sprintf("0x%08x", uint32(status))
	r.NativeHRESULT = &nativeHR
	var nativeUnits []uint16
	var nativeOK bool
	if int32(status) >= 0 {
		nativeUnits, nativeOK = boundedWide(nativePointer)
	}
	if nativePointer != nil {
		free.Call(uintptr(unsafe.Pointer(nativePointer)))
	}
	if int32(status) < 0 || !nativeOK {
		r.Stage = "synthetic_native_folder_query_refused"
		return r // No registration, alternate SID, profile creation or retry.
	}
	r.ThreadIdentity = threadIdentity()
	if r.ThreadIdentity != "absent" {
		r.Stage = "thread_identity_changed"
		return r
	}
	privateUnits, _ := windows.UTF16FromString(private)
	classes := classify(privateUnits[:len(privateUnits)-1], knownUnits, nativeUnits)
	r.Classes = &classes
	r.Completed = classes.WellFormed
	r.Stage = "query_completed"
	if !classes.WellFormed {
		r.Stage = "native_path_shape_refused"
	}
	return r
}

func main() {
	if !fixedSelector(os.Args[1:]) {
		fmt.Fprintln(os.Stderr, "only the reviewed fixed read-only query selector is supported")
		os.Exit(2)
	}
	report := queryFixed()
	if json.NewEncoder(os.Stdout).Encode(report) != nil || !report.Completed {
		os.Exit(1)
	}
}
