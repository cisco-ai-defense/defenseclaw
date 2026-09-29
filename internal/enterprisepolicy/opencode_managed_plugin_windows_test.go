// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisepolicy

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The Windows guardian installs the managed OpenCode plugin the payload
// carries under Program Files before it publishes OpenCode's managed
// config, so OpenCode takes the machine-policy route; teardown removes the
// entry and then the plugin.
func TestPublishWindowsGoOwnedInstallsTheOpenCodePlugin(t *testing.T) {
	opts := windowsOpenCodeTestOptions(t)
	if route := opts.Route(ConnectorOpenCode); route != RoutePerUser {
		t.Fatalf("before the guardian installs the plugin OpenCode is per-user, got %s", route)
	}

	result, err := PublishWindowsGoOwned(opts, []string{ConnectorOpenCode})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(opts.OpenCodePluginPath)
	if err != nil || string(data) != string(OpenCodeManagedPlugin()) {
		t.Fatalf("the guardian must install the shipped plugin: %v", err)
	}
	if err := validateTrustedFile(opts.OpenCodePluginPath); err != nil {
		t.Fatalf("the installed plugin must pass the machine trust rules: %v", err)
	}
	for _, dir := range []string{filepath.Dir(opts.OpenCodePluginPath), filepath.Dir(filepath.Dir(opts.OpenCodePluginPath))} {
		requireProtected(t, dir)
	}
	if len(result.MachinePolicyConnectors) != 1 || result.MachinePolicyConnectors[0] != ConnectorOpenCode {
		t.Fatalf("OpenCode must be published through machine policy: %+v", result)
	}
	config, _ := OpenCodeManagedConfigPath(opts)
	if body, err := os.ReadFile(config); err != nil || !strings.Contains(string(body), strings.ReplaceAll(opts.OpenCodePluginPath, `\`, `\\`)) {
		t.Fatalf("OpenCode's managed config must name the plugin: %v\n%s", err, body)
	}
	again, err := PublishWindowsGoOwned(opts, []string{ConnectorOpenCode})
	if err != nil || again.Changed {
		t.Fatalf("a second publish must be a no-op: changed=%v err=%v", again.Changed, err)
	}
	// OpenCode's runtime opens a module with FILE_WRITE_ATTRIBUTES, so a
	// standard account loads the plugin only when Users hold that right.
	// A copy with read and execute only, as 1.0.52 wrote it, is
	// rewritten by the next publish.
	if loadable, err := openCodePluginLoadable(opts, opts.OpenCodePluginPath); err != nil || !loadable {
		t.Fatalf("the installed plugin must be loadable by Users: %v %v", loadable, err)
	}
	if err := applySDDL(opts.OpenCodePluginPath, publicFileSDDL); err != nil {
		t.Fatal(err)
	}
	if loadable, err := openCodePluginLoadable(opts, opts.OpenCodePluginPath); err != nil || loadable {
		t.Fatalf("a read-only plugin descriptor must be trusted but not loadable: %v %v", loadable, err)
	}
	if upgraded, err := PublishWindowsGoOwned(opts, []string{ConnectorOpenCode}); err != nil || !upgraded.Changed {
		t.Fatalf("publish must rewrite a plugin standard accounts cannot load: changed=%v err=%v", upgraded.Changed, err)
	}
	if loadable, err := openCodePluginLoadable(opts, opts.OpenCodePluginPath); err != nil || !loadable {
		t.Fatalf("the rewritten plugin must be loadable by Users: %v %v", loadable, err)
	}
	if err := os.WriteFile(opts.OpenCodePluginPath, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if repaired, err := PublishWindowsGoOwned(opts, []string{ConnectorOpenCode}); err != nil || !repaired.Changed {
		t.Fatalf("publish must repair a stale plugin: changed=%v err=%v", repaired.Changed, err)
	}
	// With that right a standard account can also set a reparse point on the
	// plugin (no reader can open it) and mark it read-only (no rename
	// replaces it); the next publish must still replace it.
	markWindowsFileWithWriteAttributesOnly(t, opts.OpenCodePluginPath)
	if healed, err := PublishWindowsGoOwned(opts, []string{ConnectorOpenCode}); err != nil || !healed.Changed {
		t.Fatalf("publish must replace a read-only reparse-point plugin: changed=%v err=%v", healed.Changed, err)
	}
	if data, err := os.ReadFile(opts.OpenCodePluginPath); err != nil || string(data) != string(OpenCodeManagedPlugin()) {
		t.Fatalf("the replaced plugin must be the shipped one: %v", err)
	}

	markWindowsFileWithWriteAttributesOnly(t, opts.OpenCodePluginPath)
	if _, err := RemoveWindowsGoOwned(opts); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{opts.OpenCodePluginPath, filepath.Dir(opts.OpenCodePluginPath), filepath.Dir(filepath.Dir(opts.OpenCodePluginPath))} {
		if _, err := os.Lstat(gone); !os.IsNotExist(err) {
			t.Fatalf("%s must be removed: %v", gone, err)
		}
	}
	if body, err := os.ReadFile(config); err == nil && strings.Contains(string(body), "defenseclaw.js") {
		t.Fatalf("teardown must remove DefenseClaw's OpenCode entry:\n%s", body)
	}
}

// A standard account's FILE_WRITE_ATTRIBUTES change (a reparse point and
// the read-only attribute) leaves the plugin readable by no one. The
// guardian's watch restores it within seconds, without waiting for a pass.
func TestWatchOpenCodeManagedPluginRestoresAChangedPlugin(t *testing.T) {
	opts := windowsOpenCodeTestOptions(t)
	if _, err := PublishWindowsGoOwned(opts, []string{ConnectorOpenCode}); err != nil {
		t.Fatal(err)
	}
	previousDebounce, previousArmed := openCodeWatchDebounce, openCodeWatchArmed
	t.Cleanup(func() { openCodeWatchDebounce, openCodeWatchArmed = previousDebounce, previousArmed })
	openCodeWatchDebounce = 50 * time.Millisecond
	armed := make(chan struct{}, 8)
	openCodeWatchArmed = func() {
		select {
		case armed <- struct{}{}:
		default:
		}
	}
	logs := make(chan string, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var lock sync.Mutex
	go WatchOpenCodeManagedPlugin(ctx, opts, &lock, func(format string, args ...any) {
		logs <- fmt.Sprintf(format, args...)
	})
	select {
	case <-armed:
	case <-time.After(10 * time.Second):
		t.Fatal("the plugin watch did not arm")
	}
	markWindowsFileWithWriteAttributesOnly(t, opts.OpenCodePluginPath)
	select {
	case message := <-logs:
		if !strings.Contains(message, "restored it") {
			t.Fatalf("watch log %q, want the restored tamper", message)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the changed plugin was not restored without a pass")
	}
	if data, err := os.ReadFile(opts.OpenCodePluginPath); err != nil || string(data) != string(OpenCodeManagedPlugin()) {
		t.Fatalf("the restored plugin must be the shipped one: %v", err)
	}
	if loadable, err := openCodePluginLoadable(opts, opts.OpenCodePluginPath); err != nil || !loadable {
		t.Fatalf("the restored plugin must be loadable by Users: %v %v", loadable, err)
	}
}

// markWindowsFileWithWriteAttributesOnly sets a non-Microsoft reparse point
// and the read-only attribute on path through a handle that holds only
// FILE_WRITE_ATTRIBUTES, the right Users hold on the managed plugin.
func markWindowsFileWithWriteAttributesOnly(t *testing.T, path string) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.FILE_WRITE_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	// REPARSE_GUID_DATA_BUFFER: tag, data length, reserved, GUID, data.
	reparse := make([]byte, 28)
	binary.LittleEndian.PutUint32(reparse[0:], 0x1234)
	binary.LittleEndian.PutUint16(reparse[4:], 4)
	reparse[8] = 1
	var returned uint32
	if err := windows.DeviceIoControl(handle, windows.FSCTL_SET_REPARSE_POINT, &reparse[0], uint32(len(reparse)), nil, 0, &returned, nil); err != nil {
		t.Fatal(err)
	}
	// FILE_BASIC_INFO: four unchanged (zero) times, then the attributes.
	basic := make([]byte, 40)
	binary.LittleEndian.PutUint32(basic[32:], windows.FILE_ATTRIBUTE_READONLY)
	if err := windows.SetFileInformationByHandle(handle, windows.FileBasicInfo, &basic[0], uint32(len(basic))); err != nil {
		t.Fatal(err)
	}
}

// windowsOpenCodeTestOptions are Windows test options with a protected
// Program Files install root that carries the managed OpenCode plugin path.
func windowsOpenCodeTestOptions(t *testing.T) Options {
	t.Helper()
	opts := windowsTestOptions(t)
	root := filepath.Dir(opts.WindowsProgramData)
	programFiles := filepath.Join(root, "Program Files")
	if err := createProtectedDir(programFiles); err != nil {
		t.Fatal(err)
	}
	testWindowsTrust(t, root)
	install := filepath.Join(programFiles, "Cisco", "DefenseClaw")
	opts.WindowsProgramFiles = programFiles
	opts.HookBinary = filepath.Join(install, "bin", "defenseclaw-hook.exe")
	opts.OpenCodePluginPath = filepath.Join(install, "share", "opencode", "defenseclaw.js")
	return opts
}

// The guardian installs the managed plugin on every pass, before it
// reconciles OpenCode's managed config. With ownership: off that config never
// names the plugin, so the summary the per-user plugin's guard reads must
// keep OpenCode per-user (a machine-policy summary would deny every OpenCode
// tool call on DefenseClaw's own per-user plugin). Once the config names the
// plugin the summary moves OpenCode onto machine policy.
func TestPublishWindowsGoOwnedKeepsTheOpenCodeSummaryPerUserWithOwnershipOff(t *testing.T) {
	merge := windowsOpenCodeTestOptions(t)
	merge.PublicPolicyPath = filepath.Join(merge.WindowsProgramData, "machine-policy.json")
	off := withPolicy(merge, ConnectorOpenCode, func(p *config.EnterpriseConnectorPolicy) {
		p.Ownership = config.MachinePolicyOwnershipOff
	})
	summaryRoute := func() string {
		t.Helper()
		data, err := os.ReadFile(merge.PublicPolicyPath)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParsePublicPolicy(data)
		if err != nil {
			t.Fatal(err)
		}
		return parsed.Connectors[ConnectorOpenCode].Route
	}

	result, err := PublishWindowsGoOwned(off, []string{ConnectorOpenCode})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(off.OpenCodePluginPath); err != nil {
		t.Fatalf("the guardian still installs the shipped plugin: %v", err)
	}
	if len(result.MachinePolicyConnectors) != 0 {
		t.Fatalf("ownership off must not publish OpenCode: %+v", result)
	}
	if route := summaryRoute(); route != RoutePerUser {
		t.Fatalf("with ownership off the summary must keep OpenCode per-user, got %s", route)
	}

	if _, err := PublishWindowsGoOwned(merge, []string{ConnectorOpenCode}); err != nil {
		t.Fatal(err)
	}
	if route := summaryRoute(); route != RouteMachinePolicy {
		t.Fatalf("once the managed config names the plugin the summary must report machine policy, got %s", route)
	}
}
