// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func cleanWindowsEnterprisePrereqOps(emitted *[]string) windowsEnterprisePrereqOps {
	return windowsEnterprisePrereqOps{
		elevated:          func() bool { return true },
		volumeFindings:    func() []windowsEnterpriseVolumeFinding { return nil },
		executionPolicies: func() []windowsEnterpriseExecutionPolicyScope { return nil },
		lockdownPolicy:    func() (string, bool) { return "", false },
		missingPrivileges: func() ([]string, error) { return nil, nil },
		gatewayPort:       func(windowsEnterprisePrereqInput) int { return 18970 },
		gatewayImage: func(windowsEnterprisePrereqInput) (string, error) {
			return `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\bin\defenseclaw-gateway.exe`, nil
		},
		loopback: windowsEnterpriseLoopbackOps{
			listenerPID: func(string, int) (int, error) { return 0, daemon.ErrNoListener },
			bindAndConnect: func(string) (bool, bool, error, error) {
				return false, false, nil, nil
			},
		},
		emit: func(marker string, fields map[string]string) {
			*emitted = append(*emitted, managed.FormatResilienceEvent(marker, fields))
		},
	}
}

func TestWindowsEnterprisePrerequisitesCleanHostPasses(t *testing.T) {
	var emitted []string
	if err := evaluateWindowsEnterprisePrerequisites(
		windowsEnterprisePrereqInput{Action: "install"},
		cleanWindowsEnterprisePrereqOps(&emitted),
	); err != nil {
		t.Fatalf("clean host: %v", err)
	}
	if len(emitted) != 0 {
		t.Fatalf("clean host logged %v", emitted)
	}
}

func TestWindowsEnterprisePrerequisitesFatalOnlyForMutations(t *testing.T) {
	for _, action := range []string{"install", "upgrade", "repair", "status", "verify", "reconcile", "uninstall"} {
		var emitted []string
		ops := cleanWindowsEnterprisePrereqOps(&emitted)
		ops.elevated = func() bool { return false }
		err := evaluateWindowsEnterprisePrerequisites(windowsEnterprisePrereqInput{Action: action}, ops)
		mutation := action == "install" || action == "upgrade" || action == "repair"
		if mutation != (err != nil) {
			t.Fatalf("%s: err=%v, want fatal=%t", action, err, mutation)
		}
		if len(emitted) != 1 || !strings.HasPrefix(emitted[0], `defenseclaw_prereq check="elevated_token"`) {
			t.Fatalf("%s: logged %v", action, emitted)
		}
	}
}

func TestWindowsEnterprisePrerequisitesJoinEveryFatalFinding(t *testing.T) {
	var emitted []string
	ops := cleanWindowsEnterprisePrereqOps(&emitted)
	ops.volumeFindings = func() []windowsEnterpriseVolumeFinding {
		return []windowsEnterpriseVolumeFinding{{Root: `D:\`, Err: errors.New(`drive D:\ filesystem "ReFS" is not NTFS`)}}
	}
	ops.lockdownPolicy = func() (string, bool) { return "4", true }
	err := evaluateWindowsEnterprisePrerequisites(windowsEnterprisePrereqInput{Action: "repair"}, ops)
	if err == nil {
		t.Fatal("expected fatal findings")
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok || len(joined.Unwrap()) != 2 {
		t.Fatalf("findings = %v", err)
	}
	if !strings.Contains(err.Error(), `check="ntfs_volume"`) ||
		!strings.Contains(err.Error(), `check="powershell_language_mode"`) {
		t.Fatalf("findings = %v", err)
	}
}

func TestWindowsEnterprisePrivilegesAreAdvisory(t *testing.T) {
	var emitted []string
	ops := cleanWindowsEnterprisePrereqOps(&emitted)
	ops.missingPrivileges = func() ([]string, error) {
		return windowsEnterpriseMissingPrivileges([]string{"sebackupprivilege", "SeRestorePrivilege"}), nil
	}
	if err := evaluateWindowsEnterprisePrerequisites(windowsEnterprisePrereqInput{Action: "install"}, ops); err != nil {
		t.Fatalf("missing privileges must not fail install: %v", err)
	}
	if len(emitted) != 1 ||
		!strings.Contains(emitted[0], `check="token_privileges"`) ||
		!strings.Contains(emitted[0], `missing="SeTakeOwnershipPrivilege,SeSecurityPrivilege"`) {
		t.Fatalf("logged %v", emitted)
	}
}

func TestWindowsEnterpriseExecutionPolicyPrecedence(t *testing.T) {
	machineRestricted := windowsEnterpriseExecutionPolicyScope{Scope: "MachinePolicy", EnableScriptsSet: true, EnableScripts: 0}
	machineAllSigned := windowsEnterpriseExecutionPolicyScope{Scope: "MachinePolicy", EnableScriptsSet: true, EnableScripts: 1, Policy: "AllSigned"}
	userRestricted := windowsEnterpriseExecutionPolicyScope{Scope: "UserPolicy", EnableScriptsSet: true, EnableScripts: 0}
	userRemote := windowsEnterpriseExecutionPolicyScope{Scope: "UserPolicy", EnableScriptsSet: true, EnableScripts: 1, Policy: "RemoteSigned"}
	for name, test := range map[string]struct {
		scopes   []windowsEnterpriseExecutionPolicyScope
		unsigned bool
		want     string
	}{
		"not configured":                {},
		"machine restricted":            {scopes: []windowsEnterpriseExecutionPolicyScope{machineRestricted, userRemote}, want: `policy="Restricted"`},
		"user restricted":               {scopes: []windowsEnterpriseExecutionPolicyScope{{Scope: "MachinePolicy"}, userRestricted}, want: `scope="UserPolicy"`},
		"machine wins over user":        {scopes: []windowsEnterpriseExecutionPolicyScope{{Scope: "MachinePolicy", Policy: "Unrestricted"}, userRestricted}},
		"allsigned with signed payload": {scopes: []windowsEnterpriseExecutionPolicyScope{machineAllSigned}},
		"allsigned with unsigned":       {scopes: []windowsEnterpriseExecutionPolicyScope{machineAllSigned}, unsigned: true, want: `policy="AllSigned"`},
		"remote signed":                 {scopes: []windowsEnterpriseExecutionPolicyScope{userRemote}, unsigned: true},
	} {
		err := evaluateWindowsEnterpriseExecutionPolicy(test.scopes, test.unsigned)
		if test.want == "" {
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), test.want) ||
			!strings.HasPrefix(err.Error(), "defenseclaw_prereq ") ||
			!strings.Contains(err.Error(), `check="powershell_execution_policy"`) {
			t.Fatalf("%s: err=%v want %s", name, err, test.want)
		}
	}
}

func TestWindowsEnterpriseLockdownPolicy(t *testing.T) {
	for value, want := range map[string]string{"4": "fatal", "0x4": "fatal", "12": "advisory", "8": "advisory", "x": "advisory", "0": "none"} {
		fatal, advisory := evaluateWindowsEnterpriseLockdownPolicy(value, true)
		got := "none"
		if fatal != nil {
			got = "fatal"
		} else if advisory != nil {
			got = "advisory"
		}
		if got != want {
			t.Fatalf("__PSLockdownPolicy=%q: %s, want %s (fatal=%v advisory=%v)", value, got, want, fatal, advisory)
		}
	}
	if fatal, advisory := evaluateWindowsEnterpriseLockdownPolicy("", false); fatal != nil || advisory != nil {
		t.Fatalf("absent value: %v %v", fatal, advisory)
	}
}

func TestWindowsEnterpriseLoopbackPort(t *testing.T) {
	gateway := `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\bin\defenseclaw-gateway.exe`
	free := func(string, int) (int, error) { return 0, daemon.ErrNoListener }
	for name, test := range map[string]struct {
		ops  windowsEnterpriseLoopbackOps
		want string
	}{
		"free and reachable": {ops: windowsEnterpriseLoopbackOps{
			listenerPID:    free,
			bindAndConnect: func(string) (bool, bool, error, error) { return false, false, nil, nil },
		}},
		"held by installed gateway": {ops: windowsEnterpriseLoopbackOps{
			listenerPID:  func(string, int) (int, error) { return 77, nil },
			processImage: func(int) (string, error) { return strings.ToUpper(gateway), nil },
		}},
		"held by another process": {ops: windowsEnterpriseLoopbackOps{
			listenerPID:  func(string, int) (int, error) { return 77, nil },
			processImage: func(int) (string, error) { return `C:\Tools\other.exe`, nil },
		}, want: `defenseclaw_prereq addr="127.0.0.1:18970" check="gateway_loopback_port" owner="C:\\Tools\\other.exe" pid="77" reason="port is already in use by another process"`},
		"owner unknown": {ops: windowsEnterpriseLoopbackOps{
			listenerPID:  func(string, int) (int, error) { return 77, nil },
			processImage: func(int) (string, error) { return "", errors.New("denied") },
		}, want: `owner="unknown image"`},
		"ambiguous owners": {ops: windowsEnterpriseLoopbackOps{
			listenerPID: func(string, int) (int, error) { return 0, errors.New("listener ownership is ambiguous") },
		}, want: `reason="port is in use and its owner could not be identified`},
		"excluded range": {ops: windowsEnterpriseLoopbackOps{
			listenerPID:    free,
			bindAndConnect: func(string) (bool, bool, error, error) { return true, false, errors.New("WSAEACCES"), nil },
		}, want: `defenseclaw_prereq addr="127.0.0.1:18970" check="gateway_loopback_port" reason="excluded port range" remedy="`},
		"bind race": {ops: windowsEnterpriseLoopbackOps{
			listenerPID:    free,
			bindAndConnect: func(string) (bool, bool, error, error) { return false, true, errors.New("in use"), nil },
		}, want: `reason="port is already in use by another process"`},
		"loopback blocked": {ops: windowsEnterpriseLoopbackOps{
			listenerPID:    free,
			bindAndConnect: func(string) (bool, bool, error, error) { return false, false, nil, errors.New("timeout") },
		}, want: `reason="loopback connections are blocked: timeout"`},
		"table unavailable": {ops: windowsEnterpriseLoopbackOps{
			listenerPID:    func(string, int) (int, error) { return 0, daemon.ErrListenerInspectionUnavailable },
			bindAndConnect: func(string) (bool, bool, error, error) { return false, false, nil, nil },
		}},
	} {
		err := checkWindowsEnterpriseLoopbackPort(18970, gateway, test.ops)
		if test.want == "" {
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("%s: err=%v\nwant %s", name, err, test.want)
		}
	}
	if err := checkWindowsEnterpriseLoopbackPort(0, gateway, windowsEnterpriseLoopbackOps{
		listenerPID: func(_ string, port int) (int, error) {
			if port != 18970 {
				t.Fatalf("invalid port not defaulted: %d", port)
			}
			return 0, daemon.ErrNoListener
		},
	}); err != nil {
		t.Fatalf("default port: %v", err)
	}
}

func TestWindowsEnterpriseGatewayPortFromConfig(t *testing.T) {
	for body, want := range map[string]int{
		"":                                    18970,
		"gateway:\n  api_port: 19001\n":       19001,
		"gateway:\n  api_port: 70000\n":       18970,
		"gateway: [\n":                        18970,
		"deployment_mode: managed_enterprise": 18970,
	} {
		if got := windowsEnterpriseGatewayPortFromConfig([]byte(body)); got != want {
			t.Fatalf("config %q: port %d, want %d", body, got, want)
		}
	}
}

func TestParseWindowsEnterprisePrereqFieldsRoundTrips(t *testing.T) {
	fields := map[string]string{"check": "x", "path": `C:\ProgramData`, "reason": `quote " inside`}
	line := managed.FormatResilienceEvent(managed.MarkerPrereq, fields)
	parsed := parseWindowsEnterprisePrereqFields(line)
	if len(parsed) != len(fields) {
		t.Fatalf("parsed %v from %s", parsed, line)
	}
	for key, value := range fields {
		if parsed[key] != value {
			t.Fatalf("%s = %q, want %q", key, parsed[key], value)
		}
	}
}

func TestClassifyWindowsEnterpriseScriptBlockUsesErrorIDs(t *testing.T) {
	amsi := []byte("Au caractère 1 : Ce script contient du contenu malveillant.\r\n" +
		"    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException\r\n" +
		"    + FullyQualifiedErrorId : ScriptContainedMaliciousContent\r\n")
	policy := []byte("Impossible de charger le fichier install-enterprise.ps1.\r\n" +
		"    + CategoryInfo          : Erreur de sécurité : (:) [], PSSecurityException\r\n" +
		"    + FullyQualifiedErrorId : UnauthorizedAccess\r\n")
	runtimeError := []byte("Exception: System.UnauthorizedAccessException: Access to the path is denied.\r\n")
	if block, ok := classifyWindowsEnterpriseScriptBlock(amsi); !ok || block.ErrorID != "ScriptContainedMaliciousContent" {
		t.Fatalf("AMSI block = %#v %t", block, ok)
	}
	block, ok := classifyWindowsEnterpriseScriptBlock(policy)
	if !ok || block.ErrorID != "UnauthorizedAccess" {
		t.Fatalf("policy block = %#v %t", block, ok)
	}
	if _, ok := classifyWindowsEnterpriseScriptBlock(runtimeError); ok {
		t.Fatal("a runtime UnauthorizedAccessException was classified as a script block")
	}
	err := windowsEnterpriseScriptBlockError(block, `C:\stage\install-enterprise.ps1`, 1)
	if !strings.HasPrefix(err.Error(), `defenseclaw_prereq check="powershell_execution_policy" error_id="UnauthorizedAccess" exit_code="1"`) {
		t.Fatalf("policy block error = %s", err)
	}
	amsiBlock, _ := classifyWindowsEnterpriseScriptBlock(amsi)
	if err := windowsEnterpriseScriptBlockError(amsiBlock, "s", 1); !strings.HasPrefix(err.Error(),
		`defenseclaw_prereq check="powershell_script_blocked" error_id="ScriptContainedMaliciousContent"`) {
		t.Fatalf("AMSI block error = %s", err)
	}
}

func TestLastWindowsEnterpriseJSONObject(t *testing.T) {
	pretty := "{\n    \"schema_version\":  1,\n    \"nested\":  {\n        \"a\":  1\n    }\n}\n"
	for name, test := range map[string]struct {
		body string
		want string
	}{
		"only object":        {body: `{"a":1}`, want: `{"a":1}`},
		"warnings first":     {body: "WARNING: x\n{\"a\":1}\n", want: `{"a":1}`},
		"two objects":        {body: "{\"a\":1}\n{\"b\":2}\n", want: `{"b":2}`},
		"bom":                {body: "\xef\xbb\xbf{\"a\":1}", want: `{"a":1}`},
		"pretty nested":      {body: "noise\n" + pretty, want: strings.TrimSpace(pretty)},
		"incomplete last":    {body: "{\"a\":1}\n{\"b\":", want: `{"a":1}`},
		"no object":          {body: "text only\n"},
		"array is no object": {body: "[1,2]\n"},
	} {
		got := string(lastWindowsEnterpriseJSONObject([]byte(test.body)))
		if got != test.want {
			t.Fatalf("%s: got %q want %q", name, got, test.want)
		}
	}
}

func TestWindowsEnterpriseInstallerInSetupStage(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows path semantics")
	}
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	for name, test := range map[string]struct {
		installer, executable string
		want                  bool
	}{
		"staged pair":          {stage + `\install-enterprise.ps1`, stage + `\defenseclaw.exe`, true},
		"case insensitive":     {stage + `\install-enterprise.ps1`, strings.ToUpper(stage[:3]) + stage[3:] + `\DEFENSECLAW.EXE`, true},
		"executable elsewhere": {stage + `\install-enterprise.ps1`, `C:\Program Files\x\defenseclaw.exe`, false},
		"short capability":     {`C:\ProgramData\DefenseClaw-Enterprise-Setup-0123\install-enterprise.ps1`, `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123\defenseclaw.exe`, false},
		"uppercase hex":        {`C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789ABCDEF0123456789ABCDEF\i.ps1`, `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789ABCDEF0123456789ABCDEF\d.exe`, false},
		"other prefix":         {`C:\ProgramData\DefenseClaw-Installer-0123456789abcdef0123456789abcdef\i.ps1`, `C:\ProgramData\DefenseClaw-Installer-0123456789abcdef0123456789abcdef\d.exe`, false},
		"empty":                {"", "", false},
	} {
		if got := windowsEnterpriseInstallerInSetupStage(test.installer, test.executable); got != test.want {
			t.Fatalf("%s: got %t want %t", name, got, test.want)
		}
	}
}

func TestWindowsEnterprisePrerequisiteCheckerAcceptsReadOnlyStatus(t *testing.T) {
	if err := windowsEnterprisePrerequisiteChecker(windowsEnterprisePrereqInput{Action: "status"}); err != nil {
		t.Fatalf("status preflight: %v", err)
	}
}
