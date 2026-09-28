// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/eventlog"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Standalone deployment registration and observability. MDM detection rules
// read the marker key or the Add/Remove Programs entry; administrators read
// the Application event log and the lifecycle log. Only the standalone
// profile writes any of these.
const (
	// WindowsEnterpriseMarkerKey is read by the per-user installers
	// (scripts/install.ps1, `defenseclaw upgrade`) to refuse a per-user
	// install on a managed host.
	WindowsEnterpriseMarkerKey = `SOFTWARE\Cisco\DefenseClaw\Enterprise`
	windowsEnterpriseARPKey    = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CiscoDefenseClawEnterprise`
	// windowsEnterprisePolicyKey holds the DisableSelfUpdate policy every
	// shipped per-user installer and update notice already honors. The
	// standalone lifecycle sets it only when absent and records that it
	// owns the value, so it never clobbers or removes an administrator's
	// Group Policy.
	windowsEnterprisePolicyKey = `SOFTWARE\Policies\Cisco\DefenseClaw`
	windowsEnterpriseEventSrc  = "DefenseClaw Enterprise"

	windowsEnterpriseLogName      = "enterprise-lifecycle.log"
	windowsEnterpriseLastResult   = "last-result.json"
	windowsEnterpriseLogMaxBytes  = 5 << 20
	windowsEnterpriseLogGenerates = 5
	// SYSTEM and Administrators write; users read, so a support engineer
	// can collect the log without elevation.
	windowsEnterpriseLogSDDL = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
)

// Event IDs of the "DefenseClaw Enterprise" Application-log source.
const (
	windowsEnterpriseEventInstalled   uint32 = 100
	windowsEnterpriseEventUpgraded    uint32 = 101
	windowsEnterpriseEventRepaired    uint32 = 102
	windowsEnterpriseEventUninstalled uint32 = 110
	windowsEnterpriseEventEnsureNoop  uint32 = 111
	windowsEnterpriseEventEnsureRan   uint32 = 112
	windowsEnterpriseEventUnhealthy   uint32 = 120
	windowsEnterpriseEventFailed      uint32 = 130
	windowsEnterpriseEventBusy        uint32 = 140
	windowsEnterpriseEventRefused     uint32 = 150
)

var (
	windowsEnterpriseIsElevated = func() bool { return windows.GetCurrentProcessToken().IsElevated() }
	windowsEnterpriseNow        = time.Now
	windowsEnterpriseLogLimit   = int64(windowsEnterpriseLogMaxBytes)
)

// observeWindowsEnterpriseStandaloneResult records a finished standalone
// result and returns the lifecycle log path ("" when this token cannot
// write machine logs). Recording never changes the result: a failure to
// log must not turn a successful deployment into a failed one.
func observeWindowsEnterpriseStandaloneResult(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions) string {
	if result == nil || !windowsEnterpriseIsElevated() {
		return ""
	}
	if err := updateWindowsEnterpriseRegistration(result, opts); err != nil {
		result.AddWarning("registration_failed", err.Error())
		// AddWarning does not change OK; restore the computed exit code.
	}
	writeWindowsEnterpriseEvent(result)
	path, err := appendWindowsEnterpriseLifecycleLog(result)
	if err != nil {
		result.AddWarning("lifecycle_log_failed", err.Error())
		return ""
	}
	return path
}

func windowsEnterpriseMutationAction(action string) bool {
	switch action {
	case "install", "upgrade", "repair", "ensure":
		return true
	}
	return false
}

// updateWindowsEnterpriseRegistration publishes the marker and ARP entry
// after a successful mutation and removes them after a successful
// uninstall. Failed runs leave the previous registration unchanged.
func updateWindowsEnterpriseRegistration(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions) error {
	if !result.OK {
		return nil
	}
	switch {
	case result.Action == "uninstall" && !result.Installed:
		return removeWindowsEnterpriseRegistration()
	case windowsEnterpriseMutationAction(result.Action) && result.Installed:
		return writeWindowsEnterpriseRegistration(result, opts)
	}
	return nil
}

// windowsEnterpriseRecordedTrustMode normalizes the installer report's
// trust_mode, which the module reads back from deployment.json. Anything
// but the two known modes is unknown ("").
func windowsEnterpriseRecordedTrustMode(value string) string {
	switch mode := strings.ToLower(strings.TrimSpace(value)); mode {
	case windowsEnterpriseTrustAuthenticode, windowsEnterpriseTrustHashPinned:
		return mode
	}
	return ""
}

// windowsEnterpriseMarkerTrustMode is the TrustMode the marker publishes.
// The MDM detection, remediation and uninstall scripts demand a valid
// Authenticode signature on the installed CLI when it reads authenticode,
// so it must describe the deployment, not this run's request: the
// installed CLI runs ensure and repair without --trust-mode, which
// defaults to authenticode, and a hash-pinned deployment it manages stays
// hash-pinned. The requested mode applies only when the report recorded
// none.
func windowsEnterpriseMarkerTrustMode(opts *windowsEnterpriseLifecycleOptions) string {
	if opts == nil {
		return windowsEnterpriseTrustAuthenticode
	}
	if recorded := windowsEnterpriseRecordedTrustMode(opts.deploymentTrustMode); recorded != "" {
		return recorded
	}
	if strings.ToLower(strings.TrimSpace(opts.trustMode)) == windowsEnterpriseTrustHashPinned {
		return windowsEnterpriseTrustHashPinned
	}
	return windowsEnterpriseTrustAuthenticode
}

func writeWindowsEnterpriseRegistration(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions) error {
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return err
	}
	version := strings.TrimSpace(result.InstalledVersion)
	if version == "" {
		version = strings.TrimSpace(result.ProductVersion)
	}
	trustMode := windowsEnterpriseMarkerTrustMode(opts)
	disableSelfUpdate := uint32(1)
	if !readWindowsEnterpriseSelfUpdateDisabled() {
		disableSelfUpdate = 0
	}
	now := windowsEnterpriseNow().UTC()

	marker, _, err := registry.CreateKey(registry.LOCAL_MACHINE, WindowsEnterpriseMarkerKey, registry.SET_VALUE|registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("create the enterprise marker key: %w", err)
	}
	defer marker.Close()
	for name, value := range map[string]string{
		"Profile":        managed.ProfileStandalone,
		"ProductVersion": version,
		"InstallRoot":    roots.InstallRoot,
		"StateRoot":      roots.StateRoot,
		"TrustMode":      trustMode,
		"UpdatedAt":      now.Format(time.RFC3339),
	} {
		if err := marker.SetStringValue(name, value); err != nil {
			return fmt.Errorf("write enterprise marker %s: %w", name, err)
		}
	}
	if err := marker.SetDWordValue("DisableSelfUpdate", disableSelfUpdate); err != nil {
		return fmt.Errorf("write enterprise marker DisableSelfUpdate: %w", err)
	}
	if err := reconcileWindowsEnterpriseSelfUpdatePolicy(marker, disableSelfUpdate == 1); err != nil {
		return err
	}

	arp, _, err := registry.CreateKey(registry.LOCAL_MACHINE, windowsEnterpriseARPKey, registry.SET_VALUE|registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("create the Add/Remove Programs entry: %w", err)
	}
	defer arp.Close()
	cli := filepath.Join(roots.InstallRoot, "bin", "defenseclaw.exe")
	uninstall := `"` + cli + `" enterprise windows uninstall --profile standalone`
	installDate, _, dateErr := arp.GetStringValue("InstallDate")
	if dateErr != nil || len(installDate) != 8 {
		installDate = now.Format("20060102")
	}
	for name, value := range map[string]string{
		"DisplayName":          "Cisco DefenseClaw Enterprise",
		"DisplayVersion":       version,
		"Publisher":            "Cisco Systems, Inc.",
		"InstallLocation":      roots.InstallRoot,
		"DisplayIcon":          cli,
		"UninstallString":      uninstall,
		"QuietUninstallString": uninstall + " --json",
		"InstallDate":          installDate,
		"Comments":             "Managed enterprise deployment (standalone profile)",
	} {
		if err := arp.SetStringValue(name, value); err != nil {
			return fmt.Errorf("write Add/Remove Programs %s: %w", name, err)
		}
	}
	for name, value := range map[string]uint32{
		"NoModify":      1,
		"NoRepair":      1,
		"EstimatedSize": windowsEnterpriseDirectorySizeKB(filepath.Join(roots.InstallRoot, "bin")),
	} {
		if err := arp.SetDWordValue(name, value); err != nil {
			return fmt.Errorf("write Add/Remove Programs %s: %w", name, err)
		}
	}
	return nil
}

// reconcileWindowsEnterpriseSelfUpdatePolicy sets DisableSelfUpdate=1 when
// the policy is absent and self-update should be off, and removes it when
// self-update is re-enabled or the deployment is removed, but only while
// the marker records ownership.
func reconcileWindowsEnterpriseSelfUpdatePolicy(marker registry.Key, disable bool) error {
	owned, _, err := marker.GetIntegerValue("OwnsSelfUpdatePolicy")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("read enterprise marker OwnsSelfUpdatePolicy: %w", err)
	}
	policy, _, err := registry.CreateKey(registry.LOCAL_MACHINE, windowsEnterprisePolicyKey, registry.SET_VALUE|registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("open the DefenseClaw policy key: %w", err)
	}
	defer policy.Close()
	current, _, currentErr := policy.GetIntegerValue("DisableSelfUpdate")
	switch {
	case disable && errors.Is(currentErr, registry.ErrNotExist):
		if err := policy.SetDWordValue("DisableSelfUpdate", 1); err != nil {
			return fmt.Errorf("write the DisableSelfUpdate policy: %w", err)
		}
		return marker.SetDWordValue("OwnsSelfUpdatePolicy", 1)
	case !disable && owned == 1 && currentErr == nil && current == 1:
		if err := policy.DeleteValue("DisableSelfUpdate"); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return fmt.Errorf("remove the owned DisableSelfUpdate policy: %w", err)
		}
		return marker.SetDWordValue("OwnsSelfUpdatePolicy", 0)
	}
	return nil
}

func releaseWindowsEnterpriseSelfUpdatePolicy() error {
	marker, err := registry.OpenKey(registry.LOCAL_MACHINE, WindowsEnterpriseMarkerKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil
	}
	owned, _, ownedErr := marker.GetIntegerValue("OwnsSelfUpdatePolicy")
	marker.Close()
	if ownedErr != nil || owned != 1 {
		return nil
	}
	policy, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsEnterprisePolicyKey, registry.SET_VALUE|registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil
	}
	defer policy.Close()
	if current, _, err := policy.GetIntegerValue("DisableSelfUpdate"); err == nil && current == 1 {
		if err := policy.DeleteValue("DisableSelfUpdate"); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return fmt.Errorf("remove the owned DisableSelfUpdate policy: %w", err)
		}
	}
	return nil
}

func removeWindowsEnterpriseRegistration() error {
	var failures []error
	if err := releaseWindowsEnterpriseSelfUpdatePolicy(); err != nil {
		failures = append(failures, err)
	}
	for _, key := range []string{WindowsEnterpriseMarkerKey, windowsEnterpriseARPKey} {
		err := registry.DeleteKey(registry.LOCAL_MACHINE, key)
		if err != nil && !errors.Is(err, registry.ErrNotExist) && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			failures = append(failures, fmt.Errorf("remove %s: %w", key, err))
		}
	}
	return errors.Join(failures...)
}

// readWindowsEnterpriseSelfUpdateDisabled reads
// enterprise.coexistence.disable_self_update from the installed config;
// managed hosts disable self-update unless the administrator opts out.
func readWindowsEnterpriseSelfUpdateDisabled() bool {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return true
	}
	body, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseConfigProfileLimit)
	if err != nil {
		return true
	}
	var document struct {
		Enterprise struct {
			Coexistence struct {
				DisableSelfUpdate *bool `yaml:"disable_self_update"`
			} `yaml:"coexistence"`
		} `yaml:"enterprise"`
	}
	if yaml.Unmarshal(body, &document) != nil {
		return true
	}
	value := document.Enterprise.Coexistence.DisableSelfUpdate
	return value == nil || *value
}

func windowsEnterpriseDirectorySizeKB(directory string) uint32 {
	var total int64
	_ = filepath.WalkDir(directory, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		if info, infoErr := entry.Info(); infoErr == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	kilobytes := total / 1024
	if kilobytes > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(kilobytes)
}

// windowsEnterpriseEventFor maps a result to its event ID and severity.
// Healthy status and verify runs are not logged: MDM detection polls them.
func windowsEnterpriseEventFor(result *enterprisestatus.Result) (uint32, string, bool) {
	for _, message := range result.Errors {
		switch message.Code {
		case "lifecycle_busy":
			return windowsEnterpriseEventBusy, "warning", true
		case "invalid_arguments", "powershell7_required", "powershell7_untrusted", "profile_conflict",
			"powershell_32bit_host", "unsupported_architecture", "powershell_constrained_language":
			return windowsEnterpriseEventRefused, "error", true
		}
	}
	switch result.Action {
	case "status", "verify":
		if result.OK {
			return 0, "", false
		}
		return windowsEnterpriseEventUnhealthy, "warning", true
	}
	if !result.OK {
		return windowsEnterpriseEventFailed, "error", true
	}
	switch result.Action {
	case "install":
		return windowsEnterpriseEventInstalled, "info", true
	case "upgrade":
		return windowsEnterpriseEventUpgraded, "info", true
	case "repair", "reconcile":
		return windowsEnterpriseEventRepaired, "info", true
	case "uninstall":
		return windowsEnterpriseEventUninstalled, "info", true
	case "ensure":
		if result.Noop {
			return windowsEnterpriseEventEnsureNoop, "info", true
		}
		return windowsEnterpriseEventEnsureRan, "info", true
	}
	return 0, "", false
}

func writeWindowsEnterpriseEvent(result *enterprisestatus.Result) {
	id, severity, ok := windowsEnterpriseEventFor(result)
	if !ok {
		return
	}
	// An existing source is the normal case; any other install error just
	// means the event is written without a registered message file.
	_ = eventlog.InstallAsEventCreate(windowsEnterpriseEventSrc, eventlog.Error|eventlog.Warning|eventlog.Info)
	log, err := eventlog.Open(windowsEnterpriseEventSrc)
	if err != nil {
		return
	}
	defer log.Close()
	message := windowsEnterpriseEventMessage(result)
	switch severity {
	case "error":
		_ = log.Error(id, message)
	case "warning":
		_ = log.Warning(id, message)
	default:
		_ = log.Info(id, message)
	}
}

func windowsEnterpriseEventMessage(result *enterprisestatus.Result) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "DefenseClaw enterprise %s (standalone) ok=%t exit=%d version=%s",
		result.Action, result.OK, result.ExitCode, result.ProductVersion)
	if result.InstalledVersion != "" {
		fmt.Fprintf(&builder, " installed=%s", result.InstalledVersion)
	}
	if result.Noop {
		fmt.Fprintf(&builder, " noop=%s", result.NoopReason)
	}
	for _, message := range result.Errors {
		fmt.Fprintf(&builder, "\r\nerror %s: %s", message.Code, message.Message)
	}
	for _, message := range result.Warnings {
		fmt.Fprintf(&builder, "\r\nwarning %s: %s", message.Code, message.Message)
	}
	text := builder.String()
	if len(text) > 31000 {
		text = text[:31000] + "..."
	}
	return text
}

// windowsEnterpriseLogDirectory is %WINDIR%\Logs\DefenseClaw from the
// trusted system directory, never the caller's WINDIR.
func windowsEnterpriseLogDirectory() (string, error) {
	windowsDirectory, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(windowsDirectory, "Logs", "DefenseClaw"), nil
}

func ensureWindowsEnterpriseLogDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		// Assign, never redeclare, err here: the check below must see the
		// Lstat of the created folder, not the first lookup that missed it.
		var descriptor *windows.SECURITY_DESCRIPTOR
		if descriptor, err = windows.SecurityDescriptorFromString(windowsEnterpriseLogSDDL); err != nil {
			return err
		}
		attributes := &windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: descriptor,
		}
		var pointer *uint16
		if pointer, err = winpath.UTF16Ptr(directory); err != nil {
			return err
		}
		if err = windows.CreateDirectory(pointer, attributes); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return fmt.Errorf("create %s: %w", directory, err)
		}
		info, err = os.Lstat(directory)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a regular directory", directory)
	}
	if err := winpath.RejectReparseChain(directory); err != nil {
		return err
	}
	return managed.ValidateTrustedRuntimeDir(directory, "enterprise lifecycle log directory")
}

// appendWindowsEnterpriseLifecycleLog appends one JSON line per run, keeps
// five 5 MiB generations, and replaces last-result.json with the full
// result.
func appendWindowsEnterpriseLifecycleLog(result *enterprisestatus.Result) (string, error) {
	directory, err := windowsEnterpriseLogDirectory()
	if err != nil {
		return "", err
	}
	if err := ensureWindowsEnterpriseLogDirectory(directory); err != nil {
		return "", err
	}
	return writeWindowsEnterpriseLifecycleLog(directory, result)
}

func writeWindowsEnterpriseLifecycleLog(directory string, result *enterprisestatus.Result) (string, error) {
	path := filepath.Join(directory, windowsEnterpriseLogName)
	result.LogPath = path
	document, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	line, err := json.Marshal(struct {
		Time   string                   `json:"time"`
		Result *enterprisestatus.Result `json:"result"`
	}{Time: windowsEnterpriseNow().UTC().Format(time.RFC3339Nano), Result: result})
	if err != nil {
		return "", err
	}
	if info, err := os.Lstat(path); err == nil && info.Size()+int64(len(line))+1 > windowsEnterpriseLogLimit {
		rotateWindowsEnterpriseLog(path)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return "", err
	}
	_, writeErr := file.Write(append(line, '\n'))
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return "", err
	}
	lastPath := filepath.Join(directory, windowsEnterpriseLastResult)
	temporary := lastPath + ".tmp-" + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(temporary, append(document, '\n'), 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, lastPath); err != nil {
		_ = os.Remove(temporary)
		return "", err
	}
	return path, nil
}

func rotateWindowsEnterpriseLog(path string) {
	_ = os.Remove(fmt.Sprintf("%s.%d", path, windowsEnterpriseLogGenerates-1))
	for generation := windowsEnterpriseLogGenerates - 2; generation >= 1; generation-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", path, generation), fmt.Sprintf("%s.%d", path, generation+1))
	}
	_ = os.Rename(path, path+".1")
}
