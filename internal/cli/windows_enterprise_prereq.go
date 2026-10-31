// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The Windows enterprise lifecycle preflight. It runs in the Go CLI before
// PowerShell starts, so a host that cannot run the installer fails with one
// precise prerequisite instead of a PowerShell error halfway through a
// transaction. The decision logic lives here, platform-neutral, so it is unit
// tested everywhere; windows_enterprise_prereq_windows.go collects the facts.
//
// Every failure is a MarkerPrereq resilience-event line. For Install, Upgrade
// and Repair a failed check is fatal and its line becomes the JSON error;
// every other action logs it and continues. Missing token privileges are
// always advisory.

const (
	prereqCheckElevation       = "elevated_token"
	prereqCheckNTFS            = "ntfs_volume"
	prereqCheckExecutionPolicy = "powershell_execution_policy"
	prereqCheckLanguageMode    = "powershell_language_mode"
	prereqCheckPrivileges      = "token_privileges"
	prereqCheckLoopbackPort    = "gateway_loopback_port"
	prereqCheckScriptBlocked   = "powershell_script_blocked"

	// windowsEnterprisePSLockdownEnforce is the __PSLockdownPolicy bit that
	// forces ConstrainedLanguage; the audit bit only reports.
	windowsEnterprisePSLockdownEnforce = 0x4
	windowsEnterprisePSLockdownAudit   = 0x8
)

// windowsEnterpriseRepairPrivileges are the privileges the installer enables
// to re-stamp drifted owners and ACLs. A token without them still installs;
// repairs then fall back to what the owner's implicit rights allow.
var windowsEnterpriseRepairPrivileges = []string{
	"SeBackupPrivilege",
	"SeRestorePrivilege",
	"SeTakeOwnershipPrivilege",
	"SeSecurityPrivilege",
}

// windowsEnterprisePrereqInput is what the preflight needs from the lifecycle
// options.
type windowsEnterprisePrereqInput struct {
	Action          string
	ConfigPath      string
	InstallRoot     string
	StateRoot       string
	UnsignedPayload bool
}

// windowsEnterpriseExecutionPolicyScope is one Group Policy execution-policy
// scope as read from the registry. EnableScripts is the "Turn on Script
// Execution" switch; Policy is its ExecutionPolicy value.
type windowsEnterpriseExecutionPolicyScope struct {
	Scope            string
	Key              string
	EnableScriptsSet bool
	EnableScripts    uint64
	Policy           string
}

// windowsEnterpriseVolumeFinding is one machine root whose volume failed the
// fixed-local-NTFS check.
type windowsEnterpriseVolumeFinding struct {
	Root string
	Err  error
}

// windowsEnterpriseLoopbackOps probes the gateway's loopback port.
type windowsEnterpriseLoopbackOps struct {
	// listenerPID returns the PID listening on host:port, daemon.ErrNoListener
	// when nothing listens, or another error when the table is unreadable.
	listenerPID func(host string, port int) (int, error)
	// processImage returns the full image path of pid.
	processImage func(pid int) (string, error)
	// bindAndConnect binds addr and connects to it. excluded reports a bind
	// refused with WSAEACCES (an excluded port range); inUse a bind that lost
	// a race with another listener.
	bindAndConnect func(addr string) (excluded, inUse bool, bindErr, connectErr error)
}

// windowsEnterprisePrereqOps collects host facts; every field is injectable.
type windowsEnterprisePrereqOps struct {
	elevated          func() bool
	volumeFindings    func() []windowsEnterpriseVolumeFinding
	executionPolicies func() []windowsEnterpriseExecutionPolicyScope
	lockdownPolicy    func() (string, bool)
	missingPrivileges func() ([]string, error)
	gatewayPort       func(input windowsEnterprisePrereqInput) int
	gatewayImage      func(input windowsEnterprisePrereqInput) (string, error)
	loopback          windowsEnterpriseLoopbackOps
	emit              func(marker string, fields map[string]string)
}

func windowsEnterpriseMutationAction(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "install", "upgrade", "repair":
		return true
	}
	return false
}

// newWindowsEnterprisePrereq renders one prerequisite failure. The error text
// is exactly the resilience-event line.
func newWindowsEnterprisePrereq(check string, fields map[string]string) error {
	all := make(map[string]string, len(fields)+1)
	for key, value := range fields {
		all[key] = value
	}
	all["check"] = check
	return errors.New(managed.FormatResilienceEvent(managed.MarkerPrereq, all))
}

// evaluateWindowsEnterprisePrerequisites runs every check. Fatal findings
// are returned joined for Install, Upgrade and Repair; for any other action
// they are only logged. Every finding is logged either way.
func evaluateWindowsEnterprisePrerequisites(input windowsEnterprisePrereqInput, ops windowsEnterprisePrereqOps) error {
	emit := ops.emit
	if emit == nil {
		emit = managed.EmitResilienceEvent
	}
	report := func(err error) {
		if err == nil {
			return
		}
		emit(managed.MarkerPrereq, parseWindowsEnterprisePrereqFields(err.Error()))
	}
	var fatal []error
	add := func(err error) {
		if err == nil {
			return
		}
		report(err)
		fatal = append(fatal, err)
	}
	mutation := windowsEnterpriseMutationAction(input.Action)

	if ops.elevated != nil && !ops.elevated() {
		add(newWindowsEnterprisePrereq(prereqCheckElevation, map[string]string{
			"reason": "the lifecycle is not running with an elevated administrator token",
			"remedy": "run Setup from an elevated administrator or LocalSystem context (the deployment system's machine context)",
		}))
	}
	if ops.volumeFindings != nil {
		for _, finding := range ops.volumeFindings() {
			add(newWindowsEnterprisePrereq(prereqCheckNTFS, map[string]string{
				"path":   finding.Root,
				"reason": "volume is not a fixed local NTFS volume: " + errorText(finding.Err),
				"remedy": "install on a fixed local NTFS system volume; ReFS, FAT, removable and network volumes are not supported",
			}))
		}
	}
	if ops.executionPolicies != nil {
		add(evaluateWindowsEnterpriseExecutionPolicy(ops.executionPolicies(), input.UnsignedPayload))
	}
	if ops.lockdownPolicy != nil {
		value, present := ops.lockdownPolicy()
		lockdown, advisory := evaluateWindowsEnterpriseLockdownPolicy(value, present)
		add(lockdown)
		report(advisory)
	}
	if ops.missingPrivileges != nil {
		missing, err := ops.missingPrivileges()
		if err != nil {
			report(newWindowsEnterprisePrereq(prereqCheckPrivileges, map[string]string{
				"reason": "token privileges could not be read: " + err.Error(),
				"remedy": "none required; drift repair uses only the owner's implicit rights",
			}))
		} else if len(missing) != 0 {
			report(newWindowsEnterprisePrereq(prereqCheckPrivileges, map[string]string{
				"missing": strings.Join(missing, ","),
				"reason":  "the token lacks privileges used to repair drifted owners and ACLs; continuing without them",
				"remedy":  "grant the deployment account Back up files and directories, Restore files and directories, Take ownership and Manage auditing and security log (User Rights Assignment) to let repair re-stamp foreign-owned objects",
			}))
		}
	}
	if ops.gatewayPort != nil && ops.loopback.listenerPID != nil {
		port := ops.gatewayPort(input)
		gateway := ""
		if ops.gatewayImage != nil {
			gateway, _ = ops.gatewayImage(input)
		}
		add(checkWindowsEnterpriseLoopbackPort(port, gateway, ops.loopback))
	}
	if len(fatal) == 0 || !mutation {
		return nil
	}
	return errors.Join(fatal...)
}

func errorText(err error) string {
	if err == nil {
		return "unknown"
	}
	return err.Error()
}

// effectiveWindowsEnterpriseExecutionPolicy applies Group Policy precedence:
// the first scope (machine before user) that sets a policy wins. A disabled
// "Turn on Script Execution" is Restricted.
func effectiveWindowsEnterpriseExecutionPolicy(
	scopes []windowsEnterpriseExecutionPolicyScope,
) (windowsEnterpriseExecutionPolicyScope, string, bool) {
	for _, scope := range scopes {
		if scope.EnableScriptsSet && scope.EnableScripts == 0 {
			return scope, "Restricted", true
		}
		if policy := strings.TrimSpace(scope.Policy); policy != "" {
			return scope, policy, true
		}
	}
	return windowsEnterpriseExecutionPolicyScope{}, "", false
}

// evaluateWindowsEnterpriseExecutionPolicy fails when Group Policy, which
// overrides -ExecutionPolicy Bypass, makes PowerShell refuse the installer:
// Restricted always, AllSigned only for an unsigned payload.
func evaluateWindowsEnterpriseExecutionPolicy(
	scopes []windowsEnterpriseExecutionPolicyScope,
	unsignedPayload bool,
) error {
	scope, policy, set := effectiveWindowsEnterpriseExecutionPolicy(scopes)
	if !set {
		return nil
	}
	const remedy = "set Computer Configuration (and User Configuration) > Administrative Templates > " +
		"Windows Components > Windows PowerShell > Turn on Script Execution to Not Configured, " +
		"or to allow at least local scripts and remote signed scripts, then run gpupdate /force"
	switch strings.ToLower(policy) {
	case "restricted":
		return newWindowsEnterprisePrereq(prereqCheckExecutionPolicy, map[string]string{
			"scope":  scope.Scope,
			"key":    scope.Key,
			"policy": "Restricted",
			"reason": "Group Policy disables PowerShell script execution, which overrides -ExecutionPolicy Bypass",
			"remedy": remedy,
		})
	case "allsigned":
		if !unsignedPayload {
			return nil
		}
		return newWindowsEnterprisePrereq(prereqCheckExecutionPolicy, map[string]string{
			"scope":  scope.Scope,
			"key":    scope.Key,
			"policy": "AllSigned",
			"reason": "Group Policy allows only signed PowerShell scripts and this payload is unsigned",
			"remedy": "use the signed release payload, or relax Turn on Script Execution to allow local scripts on this certification host",
		})
	}
	return nil
}

// evaluateWindowsEnterpriseLockdownPolicy reads the machine
// __PSLockdownPolicy value. An enforcing value forces ConstrainedLanguage,
// under which the installer cannot load its native helpers: fatal. An audit
// or unparseable value is only reported.
func evaluateWindowsEnterpriseLockdownPolicy(value string, present bool) (fatal, advisory error) {
	if !present {
		return nil, nil
	}
	const remedy = "remove the machine environment variable __PSLockdownPolicy " +
		`(HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment) and enforce ` +
		"ConstrainedLanguage through WDAC or AppLocker, which allows the signed installer, then restart"
	trimmed := strings.TrimSpace(value)
	parsed, err := strconv.ParseUint(trimmed, 0, 32)
	if err != nil {
		return nil, newWindowsEnterprisePrereq(prereqCheckLanguageMode, map[string]string{
			"value":  trimmed,
			"reason": "__PSLockdownPolicy is set to a value PowerShell may not honour; continuing",
			"remedy": remedy,
		})
	}
	if parsed&windowsEnterprisePSLockdownEnforce == 0 || parsed&windowsEnterprisePSLockdownAudit != 0 {
		if parsed == 0 {
			return nil, nil
		}
		return nil, newWindowsEnterprisePrereq(prereqCheckLanguageMode, map[string]string{
			"value":  trimmed,
			"reason": "__PSLockdownPolicy is set in audit mode; continuing",
			"remedy": remedy,
		})
	}
	return newWindowsEnterprisePrereq(prereqCheckLanguageMode, map[string]string{
		"value":  trimmed,
		"reason": "__PSLockdownPolicy forces PowerShell ConstrainedLanguage mode, which blocks the installer's native helpers",
		"remedy": remedy,
	}), nil
}

// windowsEnterpriseMissingPrivileges returns the repair privileges that are
// not in held (compared case-insensitively), in a stable order.
func windowsEnterpriseMissingPrivileges(held []string) []string {
	have := make(map[string]bool, len(held))
	for _, name := range held {
		have[strings.ToLower(name)] = true
	}
	var missing []string
	for _, name := range windowsEnterpriseRepairPrivileges {
		if !have[strings.ToLower(name)] {
			missing = append(missing, name)
		}
	}
	return missing
}

// checkWindowsEnterpriseLoopbackPort fails when the gateway cannot own its
// loopback port: another process listens on it, the port is in an excluded
// range, or loopback connections are blocked. A listener that is the
// installed gateway itself is expected during Upgrade and Repair.
func checkWindowsEnterpriseLoopbackPort(port int, gatewayImage string, ops windowsEnterpriseLoopbackOps) error {
	if port < 1 || port > 65535 {
		port = config.DefaultGatewayAPIPort
	}
	const host = "127.0.0.1"
	addr := fmt.Sprintf("%s:%d", host, port)
	remedyBusy := "stop or reconfigure the process that holds the port, or set gateway.api_port in config.yaml to a free port"
	pid, err := ops.listenerPID(host, port)
	switch {
	case err == nil:
		image := ""
		if ops.processImage != nil {
			image, _ = ops.processImage(pid)
		}
		if image != "" && gatewayImage != "" &&
			strings.EqualFold(filepath.Clean(image), filepath.Clean(gatewayImage)) {
			return nil
		}
		owner := image
		if owner == "" {
			owner = "unknown image"
		}
		return newWindowsEnterprisePrereq(prereqCheckLoopbackPort, map[string]string{
			"addr":   addr,
			"pid":    strconv.Itoa(pid),
			"owner":  owner,
			"reason": "port is already in use by another process",
			"remedy": remedyBusy,
		})
	case errors.Is(err, daemon.ErrNoListener):
	default:
		if !errors.Is(err, daemon.ErrListenerInspectionUnavailable) {
			// Several owners, or an unreadable table: still a busy port.
			return newWindowsEnterprisePrereq(prereqCheckLoopbackPort, map[string]string{
				"addr":   addr,
				"reason": "port is in use and its owner could not be identified: " + err.Error(),
				"remedy": remedyBusy,
			})
		}
	}
	if ops.bindAndConnect == nil {
		return nil
	}
	excluded, inUse, bindErr, connectErr := ops.bindAndConnect(addr)
	switch {
	case excluded:
		return newWindowsEnterprisePrereq(prereqCheckLoopbackPort, map[string]string{
			"addr":   addr,
			"reason": "excluded port range",
			"remedy": "remove the port from the excluded range (netsh int ipv4 show excludedportrange protocol=tcp; " +
				"Hyper-V, WSL or WinNAT reserve ranges at boot), or set gateway.api_port in config.yaml to a port outside every excluded range",
		})
	case inUse:
		return newWindowsEnterprisePrereq(prereqCheckLoopbackPort, map[string]string{
			"addr":   addr,
			"reason": "port is already in use by another process",
			"remedy": remedyBusy,
		})
	case bindErr != nil:
		return newWindowsEnterprisePrereq(prereqCheckLoopbackPort, map[string]string{
			"addr":   addr,
			"reason": "cannot bind the loopback port: " + bindErr.Error(),
			"remedy": "allow DefenseClaw to bind 127.0.0.1 in the endpoint firewall or protection product, or set gateway.api_port in config.yaml to a port it may bind",
		})
	case connectErr != nil:
		return newWindowsEnterprisePrereq(prereqCheckLoopbackPort, map[string]string{
			"addr":   addr,
			"reason": "loopback connections are blocked: " + connectErr.Error(),
			"remedy": "allow loopback (127.0.0.1) TCP connections in the host firewall or endpoint protection product",
		})
	}
	return nil
}

// windowsEnterpriseGatewayPortFromConfig reads gateway.api_port from a
// config.yaml body, or returns the default.
func windowsEnterpriseGatewayPortFromConfig(body []byte) int {
	var document struct {
		Gateway struct {
			APIPort int `yaml:"api_port"`
		} `yaml:"gateway"`
	}
	if len(body) == 0 || yaml.Unmarshal(body, &document) != nil ||
		document.Gateway.APIPort < 1 || document.Gateway.APIPort > 65535 {
		return config.DefaultGatewayAPIPort
	}
	return document.Gateway.APIPort
}

// windowsEnterprisePrereqFieldPattern parses a resilience-event line back to
// its fields for the structured log sink.
var windowsEnterprisePrereqFieldPattern = regexp.MustCompile(`([a-z_]+)=("(?:[^"\\]|\\.)*")`)

func parseWindowsEnterprisePrereqFields(line string) map[string]string {
	fields := map[string]string{}
	for _, match := range windowsEnterprisePrereqFieldPattern.FindAllStringSubmatch(line, -1) {
		value, err := strconv.Unquote(match[2])
		if err != nil {
			continue
		}
		fields[match[1]] = value
	}
	return fields
}

// windowsEnterpriseScriptBlock classifies a PowerShell refusal to start the
// installer script from the child's stderr. It matches PowerShell's error
// IDs, which are not localized, never the message text.
type windowsEnterpriseScriptBlock struct {
	ErrorID string
	Reason  string
	Remedy  string
}

var (
	windowsEnterpriseAMSIBlockPattern = regexp.MustCompile(`\bScriptContainedMaliciousContent\b`)
	windowsEnterprisePolicyIDPattern  = regexp.MustCompile(`\bUnauthorizedAccess\b`)
	windowsEnterprisePolicyCategory   = regexp.MustCompile(`\bPSSecurityException\b`)
)

func classifyWindowsEnterpriseScriptBlock(stderr []byte) (windowsEnterpriseScriptBlock, bool) {
	switch {
	case windowsEnterpriseAMSIBlockPattern.Match(stderr):
		return windowsEnterpriseScriptBlock{
			ErrorID: "ScriptContainedMaliciousContent",
			Reason:  "the antimalware scan interface blocked the installer script before it started",
			Remedy: "allow the DefenseClaw installer script and module in the antimalware or endpoint protection product " +
				"(exclusion by signer or path), then run Setup again",
		}, true
	case windowsEnterprisePolicyIDPattern.Match(stderr) && windowsEnterprisePolicyCategory.Match(stderr):
		return windowsEnterpriseScriptBlock{
			ErrorID: "UnauthorizedAccess",
			Reason:  "PowerShell refused to run the installer script under the effective execution policy",
			Remedy: "set Turn on Script Execution (Group Policy, machine and user) to Not Configured or to allow the " +
				"installer, or use the signed payload where AllSigned is enforced, then run Setup again",
		}, true
	}
	return windowsEnterpriseScriptBlock{}, false
}

// windowsEnterpriseScriptBlockError renders a classified script block.
func windowsEnterpriseScriptBlockError(block windowsEnterpriseScriptBlock, script string, exitCode int) error {
	check := prereqCheckScriptBlocked
	if block.ErrorID == "UnauthorizedAccess" {
		check = prereqCheckExecutionPolicy
	}
	return newWindowsEnterprisePrereq(check, map[string]string{
		"path":      script,
		"error_id":  block.ErrorID,
		"exit_code": strconv.Itoa(exitCode),
		"reason":    block.Reason,
		"remedy":    block.Remedy,
	})
}

// lastWindowsEnterpriseJSONObject returns the last complete top-level JSON
// object in body, or nil. PowerShell and the lifecycle may print diagnostics
// before the result; a top-level object starts at the beginning of a line
// (after an optional byte-order mark), so nested objects of a pretty-printed
// document are never mistaken for it.
func lastWindowsEnterpriseJSONObject(body []byte) []byte {
	var starts []int
	for index := 0; index < len(body); {
		lineStart := index
		if bytes.HasPrefix(body[index:], []byte{0xef, 0xbb, 0xbf}) {
			index += 3
		}
		if index < len(body) && body[index] == '{' {
			starts = append(starts, index)
		}
		next := bytes.IndexByte(body[lineStart:], '\n')
		if next < 0 {
			break
		}
		index = lineStart + next + 1
	}
	for candidate := len(starts) - 1; candidate >= 0; candidate-- {
		decoder := json.NewDecoder(bytes.NewReader(body[starts[candidate]:]))
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			continue
		}
		if len(raw) == 0 || raw[0] != '{' {
			continue
		}
		return raw
	}
	return nil
}

// windowsEnterpriseInstallerInSetupStage reports whether installer sits
// directly in an outer Setup staging directory
// (DefenseClaw-Enterprise-Setup-<32 hex>) that also holds the running
// executable: the staged CLI running its own staged installer.
func windowsEnterpriseInstallerInSetupStage(installer, executable string) bool {
	if strings.TrimSpace(installer) == "" || strings.TrimSpace(executable) == "" {
		return false
	}
	installerDir := filepath.Dir(filepath.Clean(installer))
	if !managed.IsSetupLeftoverName(filepath.Base(installerDir), []string{managed.SetupStagePrefix}) {
		return false
	}
	return strings.EqualFold(filepath.Dir(filepath.Clean(executable)), installerDir)
}
