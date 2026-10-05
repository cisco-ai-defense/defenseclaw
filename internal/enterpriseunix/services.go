// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// Unit is one managed systemd unit or launchd job.
type Unit struct {
	Name string
	// Kind is the enterprisestatus service kind.
	Kind string
	// Required units must be active on a started deployment.
	Required bool
	// Activate units are enabled and started by activation, in order.
	Activate bool
	// Stage is the activation order; quiesce runs in reverse.
	Stage int
}

// ServiceManager drives the host service manager.
type ServiceManager interface {
	// Check reports whether the service manager can run the deployment.
	Check(ctx context.Context) error
	// Version is the systemd version (0 for launchd).
	Version(ctx context.Context) int
	Units() []Unit
	// DefinitionPath is the canonical path of a unit's definition file.
	DefinitionPath(unit Unit, channel string) string
	Reload(ctx context.Context) error
	Start(ctx context.Context, unit Unit) error
	Stop(ctx context.Context, unit Unit) error
	Enable(ctx context.Context, unit Unit) error
	Disable(ctx context.Context, unit Unit) error
	Status(ctx context.Context, unit Unit) (enterprisestatus.Service, error)
	// Active reports whether a unit is running (or listening/waiting).
	Active(ctx context.Context, unit Unit) bool
}

// repairsRegistrations reports whether a unit writes or re-triggers
// DefenseClaw's per-user and machine-policy registrations: the guardian and
// its reconcile oneshot, the enumerator that feeds them, and the apply and
// verify triggers that start lifecycle runs.
func repairsRegistrations(unit Unit) bool {
	switch unit.Kind {
	case "guardian", "enumerator", "path", "timer", "oneshot":
		return true
	}
	return false
}

// isManagedUnit reports whether name is one of units.
func isManagedUnit(units []Unit, name string) bool {
	for _, unit := range units {
		if unit.Name == name {
			return true
		}
	}
	return false
}

// enabledReporter is implemented by service managers that can tell whether
// a unit starts at boot.
type enabledReporter interface {
	Enabled(ctx context.Context, unit Unit) bool
}

func unitEnabled(ctx context.Context, services ServiceManager, unit Unit) bool {
	reporter, ok := services.(enabledReporter)
	return ok && reporter.Enabled(ctx, unit)
}

// disabledReporter is implemented by service managers that can tell whether
// an administrator disabled a unit, so that it does not start at boot
// (launchd's disabled override).
type disabledReporter interface {
	Disabled(ctx context.Context, unit Unit) bool
}

func unitDisabled(ctx context.Context, services ServiceManager, unit Unit) bool {
	reporter, ok := services.(disabledReporter)
	return ok && reporter.Disabled(ctx, unit)
}

// restarter is implemented by service managers that restart a unit in one
// job.
type restarter interface {
	Restart(ctx context.Context, unit Unit) error
}

func restartUnit(ctx context.Context, services ServiceManager, unit Unit) error {
	if r, ok := services.(restarter); ok {
		return r.Restart(ctx, unit)
	}
	if err := services.Stop(ctx, unit); err != nil {
		return err
	}
	return services.Start(ctx, unit)
}

// fragmentReporter is implemented by service managers that report the file
// a unit's definition was loaded from.
type fragmentReporter interface {
	FragmentPath(ctx context.Context, unit Unit) string
}

// plannedRestartReporter is implemented by service managers that report a
// unit waiting for its automatic restart after a run that ended cleanly. The
// sensor helper and the guardian exit that way to reload; a unit that
// crashed is not in a planned restart.
type plannedRestartReporter interface {
	PlannedRestart(ctx context.Context, unit Unit) bool
}

func newServiceManager(env *Env) ServiceManager {
	if env.GOOS == "darwin" {
		return &launchdManager{env: env}
	}
	return &systemdManager{env: env}
}

// Linux unit names.
const (
	unitGateway           = "defenseclaw-gateway.service"
	unitAPISocket         = "defenseclaw-gateway-api.socket"
	unitHookSocket        = "defenseclaw-gateway-hook.socket"
	unitGuardian          = "defenseclaw-hook-guardian.service"
	unitGuardianOneshot   = "defenseclaw-hook-guardian-reconcile.service"
	unitEnumerator        = "defenseclaw-hook-enumerator.service"
	unitSensorHelper      = "defenseclaw-sensor-helper.service"
	unitApplyPath         = "defenseclaw-enterprise-apply.path"
	unitApplyService      = "defenseclaw-enterprise-apply.service"
	unitVerifyTimer       = "defenseclaw-enterprise-verify.timer"
	unitVerifyService     = "defenseclaw-enterprise-verify.service"
	minimumSystemd        = 239
	loadCredentialSystemd = 247
)

// linuxUnits is the standalone unit set in activation order.
var linuxUnits = []Unit{
	{Name: unitSensorHelper, Kind: "sensor_helper", Required: true, Activate: true, Stage: 1},
	{Name: unitAPISocket, Kind: "socket", Required: true, Activate: true, Stage: 2},
	{Name: unitHookSocket, Kind: "socket", Required: true, Activate: true, Stage: 2},
	{Name: unitGateway, Kind: "gateway", Required: true, Activate: true, Stage: 3},
	{Name: unitGuardian, Kind: "guardian", Required: true, Activate: true, Stage: 4},
	{Name: unitEnumerator, Kind: "enumerator", Required: true, Activate: true, Stage: 5},
	{Name: unitApplyPath, Kind: "path", Required: true, Activate: true, Stage: 6},
	{Name: unitVerifyTimer, Kind: "timer", Required: true, Activate: true, Stage: 6},
	{Name: unitGuardianOneshot, Kind: "oneshot", Stage: 7},
	{Name: unitApplyService, Kind: "oneshot", Stage: 7},
	{Name: unitVerifyService, Kind: "oneshot", Stage: 7},
}

type systemdManager struct {
	env     *Env
	version int
}

func (m *systemdManager) Units() []Unit { return append([]Unit{}, linuxUnits...) }

func (m *systemdManager) DefinitionPath(unit Unit, channel string) string {
	if channel == ChannelPackage {
		return filepath.Join("/usr/lib/systemd/system", unit.Name)
	}
	return filepath.Join("/etc/systemd/system", unit.Name)
}

// systemdTimerStampPath is where systemd keeps a Persistent= timer's last
// trigger time; it stays after the timer unit is removed.
func systemdTimerStampPath(timer string) string {
	return filepath.Join("/var/lib/systemd/timers", "stamp-"+timer)
}

var systemdVersionPattern = regexp.MustCompile(`(?m)^systemd\s+(\d+)`)

func (m *systemdManager) Version(ctx context.Context) int {
	if m.version > 0 {
		return m.version
	}
	result, err := m.env.Runner.Run(ctx, "systemctl", "--version")
	if err != nil {
		return 0
	}
	match := systemdVersionPattern.FindSubmatch(result.Stdout)
	if match == nil {
		return 0
	}
	m.version, _ = strconv.Atoi(string(match[1]))
	return m.version
}

func (m *systemdManager) Check(ctx context.Context) error {
	if !exists(m.env.P("/run/systemd/system")) {
		return errors.New("systemd is not the running init system (no /run/systemd/system); containers and WSL without systemd are not supported")
	}
	version := m.Version(ctx)
	if version == 0 {
		return errors.New("could not determine the systemd version")
	}
	if version < minimumSystemd {
		return fmt.Errorf("systemd %d is older than the supported minimum %d", version, minimumSystemd)
	}
	return nil
}

func (m *systemdManager) run(ctx context.Context, args ...string) error {
	_, err := m.env.Runner.Run(ctx, "systemctl", args...)
	return err
}

func (m *systemdManager) Reload(ctx context.Context) error { return m.run(ctx, "daemon-reload") }

func (m *systemdManager) Start(ctx context.Context, unit Unit) error {
	return m.run(ctx, "start", unit.Name)
}

// Restart replaces a unit in one systemd job; for a socket unit the
// listener is closed and reopened within that job.
func (m *systemdManager) Restart(ctx context.Context, unit Unit) error {
	return m.run(ctx, "restart", unit.Name)
}

func (m *systemdManager) Stop(ctx context.Context, unit Unit) error {
	return m.run(ctx, "stop", unit.Name)
}

func (m *systemdManager) Enable(ctx context.Context, unit Unit) error {
	return m.run(ctx, "enable", unit.Name)
}

func (m *systemdManager) Disable(ctx context.Context, unit Unit) error {
	return m.run(ctx, "disable", unit.Name)
}

func (m *systemdManager) properties(ctx context.Context, unit string, names ...string) map[string]string {
	args := []string{"show", unit}
	for _, name := range names {
		args = append(args, "-p", name)
	}
	result, err := m.env.Runner.Run(ctx, "systemctl", args...)
	props := map[string]string{}
	if err != nil {
		return props
	}
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[key] = value
		}
	}
	return props
}

func (m *systemdManager) Status(ctx context.Context, unit Unit) (enterprisestatus.Service, error) {
	props := m.properties(ctx, unit.Name, "ActiveState", "SubState", "UnitFileState", "MainPID", "NRestarts")
	service := enterprisestatus.Service{Name: unit.Name, Kind: unit.Kind, Required: unit.Required}
	if len(props) == 0 {
		service.State = "unknown"
		return service, nil
	}
	service.State = props["ActiveState"]
	if sub := props["SubState"]; sub != "" {
		service.State += "/" + sub
	}
	service.StartMode = props["UnitFileState"]
	service.PID, _ = strconv.Atoi(props["MainPID"])
	service.Restarts, _ = strconv.Atoi(props["NRestarts"])
	return service, nil
}

func (m *systemdManager) Active(ctx context.Context, unit Unit) bool {
	return m.properties(ctx, unit.Name, "ActiveState")["ActiveState"] == "active"
}

// PlannedRestart is systemd's restart delay (auto-restart, and
// auto-restart-queued on systemd 254 and later) after a run whose Result is
// success.
func (m *systemdManager) PlannedRestart(ctx context.Context, unit Unit) bool {
	props := m.properties(ctx, unit.Name, "ActiveState", "SubState", "Result")
	return props["ActiveState"] == "activating" && strings.HasPrefix(props["SubState"], "auto-restart") && props["Result"] == "success"
}

// Enabled reports whether the unit is enabled to start at boot.
func (m *systemdManager) Enabled(ctx context.Context, unit Unit) bool {
	return m.properties(ctx, unit.Name, "UnitFileState")["UnitFileState"] == "enabled"
}

// FragmentPath is the unit file systemd loaded the unit from.
func (m *systemdManager) FragmentPath(ctx context.Context, unit Unit) string {
	return m.properties(ctx, unit.Name, "FragmentPath")["FragmentPath"]
}

// Sandbox returns the systemd properties verify asserts for a unit.
func (m *systemdManager) Sandbox(ctx context.Context, unit string) map[string]string {
	return m.properties(ctx, unit, "User", "NoNewPrivileges", "CapabilityBoundingSet", "ProtectSystem", "ProtectHome", "PrivateUsers")
}

// macOS job labels.
const (
	labelGateway      = "com.cisco.defenseclaw.gateway"
	labelGuardian     = "com.cisco.defenseclaw.hook-guardian"
	labelEnumerator   = "com.cisco.defenseclaw.hook-enumerator"
	labelSensorHelper = "com.cisco.defenseclaw.sensor-helper"
	labelApply        = "com.cisco.defenseclaw.apply"
	labelVerify       = "com.cisco.defenseclaw.verify"
)

var darwinUnits = []Unit{
	{Name: labelSensorHelper, Kind: "sensor_helper", Required: true, Activate: true, Stage: 1},
	{Name: labelGateway, Kind: "gateway", Required: true, Activate: true, Stage: 3},
	{Name: labelGuardian, Kind: "guardian", Required: true, Activate: true, Stage: 4},
	{Name: labelEnumerator, Kind: "enumerator", Required: true, Activate: true, Stage: 5},
	{Name: labelApply, Kind: "path", Activate: true, Stage: 6},
	{Name: labelVerify, Kind: "timer", Activate: true, Stage: 6},
}

type launchdManager struct {
	env *Env

	mu sync.Mutex
	// bootedOut are the jobs this manager booted out; only their EALREADY
	// is a teardown still in progress.
	bootedOut map[string]bool
}

func (m *launchdManager) Units() []Unit { return append([]Unit{}, darwinUnits...) }

func (m *launchdManager) DefinitionPath(unit Unit, _ string) string {
	return filepath.Join("/Library/LaunchDaemons", unit.Name+".plist")
}

func (m *launchdManager) Version(context.Context) int { return 0 }

func (m *launchdManager) Check(context.Context) error { return nil }

func (m *launchdManager) Reload(context.Context) error { return nil }

func (m *launchdManager) Start(ctx context.Context, unit Unit) error {
	bootstrap := func() error {
		_, err := m.env.Runner.Run(ctx, "launchctl", "bootstrap", "system", m.env.P(m.DefinitionPath(unit, "")))
		return err
	}
	err := bootstrap()
	if err != nil && launchdBusy(err) && m.wasBootedOut(unit) && m.waitUnloaded(ctx, unit) {
		// This manager's bootout of the job was still finishing.
		err = bootstrap()
	}
	if err != nil && launchdAlreadyLoaded(err) {
		_, err = m.env.Runner.Run(ctx, "launchctl", "kickstart", "-k", "system/"+unit.Name)
	}
	return err
}

// Stop boots the job out and waits until launchd has removed it. bootout
// can return while launchd is still terminating the job; a bootstrap or
// kickstart in that window fails with EALREADY (exit 37), which left a
// config change on macOS with the gateway unloaded.
func (m *launchdManager) Stop(ctx context.Context, unit Unit) error {
	_, err := m.env.Runner.Run(ctx, "launchctl", "bootout", "system/"+unit.Name)
	if err != nil && launchdNotLoaded(err) {
		return nil
	}
	if err == nil || launchdBusy(err) {
		m.mu.Lock()
		if m.bootedOut == nil {
			m.bootedOut = map[string]bool{}
		}
		m.bootedOut[unit.Name] = true
		m.mu.Unlock()
		if m.waitUnloaded(ctx, unit) {
			return nil
		}
	}
	return err
}

func (m *launchdManager) wasBootedOut(unit Unit) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bootedOut[unit.Name]
}

// launchdTeardownWait bounds the wait for launchd to remove a job it is
// booting out. launchd kills a job that ignores SIGTERM after its exit
// timeout (20 seconds by default).
var launchdTeardownWait = 30 * time.Second

// waitUnloaded reports whether launchd stopped knowing the job within
// launchdTeardownWait.
func (m *launchdManager) waitUnloaded(ctx context.Context, unit Unit) bool {
	now, poll := m.env.Now, m.env.PollInterval
	if now == nil {
		now = time.Now
	}
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	deadline := now().Add(launchdTeardownWait)
	for {
		if _, err := m.env.Runner.Run(ctx, "launchctl", "print", "system/"+unit.Name); err != nil {
			return true
		}
		if !now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(poll):
		}
	}
}

// Enable clears a disabled override only. launchctl enable writes a
// "=> enabled" override for a label launchd already starts by default, and
// no command deletes an override, so every install left six DefenseClaw
// entries in launchd's disabled-services database after uninstall
// (GAP-1443). If the overrides cannot be read, it enables as before.
func (m *launchdManager) Enable(ctx context.Context, unit Unit) error {
	if disabled, known := m.disabledOverride(ctx, unit); known && !disabled {
		return nil
	}
	_, err := m.env.Runner.Run(ctx, "launchctl", "enable", "system/"+unit.Name)
	return err
}

// Disabled reports a disabled override for the label: launchd does not
// start the job at the next boot (GAP-1802).
func (m *launchdManager) Disabled(ctx context.Context, unit Unit) bool {
	disabled, _ := m.disabledOverride(ctx, unit)
	return disabled
}

// disabledOverride reads launchd's override for the label; known is false
// when the overrides cannot be read.
func (m *launchdManager) disabledOverride(ctx context.Context, unit Unit) (disabled, known bool) {
	result, err := m.env.Runner.Run(ctx, "launchctl", "print-disabled", "system")
	if err != nil {
		return false, false
	}
	return launchdDisabledPattern(unit.Name).Match(result.Stdout), true
}

// launchdDisabledPattern matches label's disabled override in
// `launchctl print-disabled` output: "label" => disabled (macOS 11 and
// later) or "label" => true (older releases).
func launchdDisabledPattern(label string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^\s*"` + regexp.QuoteMeta(label) + `"\s*=>\s*(disabled|true)\s*$`)
}

func (m *launchdManager) Disable(ctx context.Context, unit Unit) error {
	_, err := m.env.Runner.Run(ctx, "launchctl", "disable", "system/"+unit.Name)
	return err
}

var (
	// launchctl prints multi-word states ("not running", "spawn scheduled").
	launchdStatePattern = regexp.MustCompile(`(?m)^\s*state = ([^\n]*?)\s*$`)
	launchdPIDPattern   = regexp.MustCompile(`(?m)^\s*pid = (\d+)`)
	launchdRunsPattern  = regexp.MustCompile(`(?m)^\s*runs = (\d+)`)
	launchdExitPattern  = regexp.MustCompile(`(?m)^\s*last exit code = (\S+)`)
)

func (m *launchdManager) Status(ctx context.Context, unit Unit) (enterprisestatus.Service, error) {
	service := enterprisestatus.Service{Name: unit.Name, Kind: unit.Kind, Required: unit.Required}
	result, err := m.env.Runner.Run(ctx, "launchctl", "print", "system/"+unit.Name)
	if err != nil {
		service.State = "not_loaded"
		return service, nil
	}
	service.State = "loaded"
	if match := launchdStatePattern.FindSubmatch(result.Stdout); match != nil {
		service.State = string(match[1])
	}
	if match := launchdPIDPattern.FindSubmatch(result.Stdout); match != nil {
		service.PID, _ = strconv.Atoi(string(match[1]))
	}
	if match := launchdRunsPattern.FindSubmatch(result.Stdout); match != nil {
		runs, _ := strconv.Atoi(string(match[1]))
		if runs > 0 {
			service.Restarts = runs - 1
		}
	}
	service.StartMode = "loaded"
	service.State = launchdDisplayState(unit.Kind, service.State)
	return service, nil
}

// launchdDisplayState renders an on-demand job (the apply job, started by
// its watched paths, and the daily verify job) that is loaded but not
// running as idle instead of launchd's bare "not running".
func launchdDisplayState(kind, state string) string {
	if state == "running" || state == "" {
		return state
	}
	switch kind {
	case "path":
		return "on demand, idle"
	case "timer":
		return "scheduled, idle"
	}
	return state
}

// Active is true for a running daemon, and for a loaded on-demand job
// (apply, verify) that is waiting for its trigger.
func (m *launchdManager) Active(ctx context.Context, unit Unit) bool {
	status, _ := m.Status(ctx, unit)
	switch unit.Kind {
	case "path", "timer":
		return status.State != "not_loaded"
	}
	return status.State == "running"
}

// PlannedRestart is a KeepAlive daemon whose respawn launchd scheduled
// (ThrottleInterval) after a run that exited 0.
func (m *launchdManager) PlannedRestart(ctx context.Context, unit Unit) bool {
	result, err := m.env.Runner.Run(ctx, "launchctl", "print", "system/"+unit.Name)
	if err != nil {
		return false
	}
	state := launchdStatePattern.FindSubmatch(result.Stdout)
	exit := launchdExitPattern.FindSubmatch(result.Stdout)
	return state != nil && string(state[1]) == "spawn scheduled" && exit != nil && string(exit[1]) == "0"
}

func launchdAlreadyLoaded(err error) bool {
	text := err.Error()
	return strings.Contains(text, "already loaded") || strings.Contains(text, "service already bootstrapped") ||
		strings.Contains(text, "exit 17") || strings.Contains(text, "exit 37") || strings.Contains(text, "Bootstrap failed: 5")
}

// launchdBusy is EALREADY: launchd is still booting the job out.
func launchdBusy(err error) bool {
	return strings.Contains(err.Error(), "exit 37")
}

func launchdNotLoaded(err error) bool {
	text := err.Error()
	return strings.Contains(text, "Could not find service") || strings.Contains(text, "No such process") ||
		strings.Contains(text, "exit 3:") || strings.Contains(text, "exit 113")
}
