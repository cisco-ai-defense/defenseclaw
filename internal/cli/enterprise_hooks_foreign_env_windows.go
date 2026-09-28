//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// The Windows guardian runs as LocalSystem, so its environment is not the
// user's. An agent the user starts inherits the user's persistent
// environment: the machine variables, the user's own variables in
// HKU\<SID>\Environment (which override the machine ones) and the profile
// variables Windows sets at sign-in in HKU\<SID>\Volatile Environment. The
// cleanup reads that environment from the user's loaded registry hive, lets
// the connector's source rules (the ones the hook applies to the agent's
// environment) pick the variables that move its user config, and cleans
// those folders with the recorded redirects. The guardian never loads a
// hive: while a user's hive is not loaded the folders are skipped and the
// skip is reported.

// windowsRegistryPath names a registry key.
type windowsRegistryPath struct {
	root registry.Key
	path string
}

// Where the environment is read from. Replaceable in tests (a test cannot
// load a hive under HKEY_USERS).
var (
	// enterpriseForeignHookUserHives holds the loaded user hives, one
	// subkey per SID.
	enterpriseForeignHookUserHives          = windowsRegistryPath{root: registry.USERS}
	enterpriseForeignHookMachineEnvironment = windowsRegistryPath{
		root: registry.LOCAL_MACHINE,
		path: `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`,
	}
)

const (
	// windowsEnvValueLimit is the longest environment value Windows keeps,
	// in characters.
	windowsEnvValueLimit = 32767
	// windowsEnvKeyValueLimit bounds the values read from one key.
	windowsEnvKeyValueLimit = 1024
)

// windowsMachineWideEnv are machine-wide variables Windows puts in every
// user's environment besides the machine key; the guardian's own values are
// the machine's.
var windowsMachineWideEnv = []string{
	"SystemRoot", "SystemDrive", "windir", "ProgramData", "ALLUSERSPROFILE", "PUBLIC",
	"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
	"CommonProgramFiles", "CommonProgramFiles(x86)", "CommonProgramW6432", "COMPUTERNAME",
}

var errWindowsUserHiveNotLoaded = errors.New("its registry hive is not loaded")

// enterpriseForeignHookUserEnvRedirects returns the redirect the user's
// persistent environment applies to request's connector: every absolute
// location value its user sources read, when one of them lies outside the
// default locations. It runs as the user.
func enterpriseForeignHookUserEnvRedirects(target enterprisehooks.TargetCredentials, request enterprisepolicy.GuardRequest) ([]enterprisepolicy.EnvRedirect, error) {
	env, err := windowsUserPersistentEnvironment(target.SID, target.UserHome)
	if errors.Is(err, errWindowsUserHiveNotLoaded) {
		return nil, fmt.Errorf("environment of %s: %w; skipped the folders its variables name", target.SID, err)
	}
	if err != nil {
		err = fmt.Errorf("environment of %s: %w", target.SID, err)
	}
	if env == nil {
		return nil, err
	}
	request.Getenv = func(key string) string { return env[strings.ToUpper(key)] }
	request.WorkingDir, request.WorkingDirs = "", nil
	redirect, ok := enterprisepolicy.ObservedEnvRedirect(request)
	if !ok {
		return nil, err
	}
	return []enterprisepolicy.EnvRedirect{redirect}, err
}

// windowsEnvValue is one environment value of a registry key.
type windowsEnvValue struct {
	name   string
	value  string
	expand bool
}

// windowsUserPersistentEnvironment returns the environment an agent the
// user starts inherits, keyed by upper-case name, built the way Windows
// builds it at sign-in: the machine-wide variables and the machine key,
// the profile variables, the user's own variables, and the profile
// variables of the sign-in again, which a user variable does not override.
// REG_EXPAND_SZ values are expanded against the variables before them. A
// key that cannot be read is reported and the rest is still returned. It
// fails with errWindowsUserHiveNotLoaded when the user's hive is not
// loaded.
func windowsUserPersistentEnvironment(sid, home string) (map[string]string, error) {
	parsed, err := windows.StringToSid(strings.TrimSpace(sid))
	if err != nil {
		return nil, fmt.Errorf("invalid SID %q: %w", sid, err)
	}
	if strings.TrimSpace(home) == "" || !filepath.IsAbs(home) {
		return nil, errors.New("the profile directory is not absolute")
	}
	hivePath := parsed.String()
	if prefix := enterpriseForeignHookUserHives.path; prefix != "" {
		hivePath = prefix + `\` + hivePath
	}
	hive, err := registry.OpenKey(enterpriseForeignHookUserHives.root, hivePath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, errWindowsUserHiveNotLoaded
	}
	if err != nil {
		return nil, fmt.Errorf("open its registry hive: %w", err)
	}
	defer hive.Close()

	var errs []error
	read := func(root registry.Key, path string) []windowsEnvValue {
		values, err := readWindowsEnvironmentKey(root, path)
		if err != nil {
			errs = append(errs, err)
		}
		return values
	}
	machine := read(enterpriseForeignHookMachineEnvironment.root, enterpriseForeignHookMachineEnvironment.path)
	volatile := read(hive, "Volatile Environment")
	user := read(hive, "Environment")

	env := map[string]string{}
	for _, name := range windowsMachineWideEnv {
		if value := os.Getenv(name); value != "" {
			env[strings.ToUpper(name)] = value
		}
	}
	for _, layer := range [][]windowsEnvValue{machine, windowsProfileEnvironment(filepath.Clean(home)), volatile, user, volatile} {
		applyWindowsEnvironment(env, layer)
	}
	return env, errors.Join(errs...)
}

// windowsProfileEnvironment is the profile variables of a profile at home,
// for a user whose hive has no Volatile Environment.
func windowsProfileEnvironment(home string) []windowsEnvValue {
	volume := filepath.VolumeName(home)
	return []windowsEnvValue{
		{name: "USERPROFILE", value: home},
		{name: "HOMEDRIVE", value: volume},
		{name: "HOMEPATH", value: strings.TrimPrefix(home, volume)},
		{name: "APPDATA", value: filepath.Join(home, "AppData", "Roaming")},
		{name: "LOCALAPPDATA", value: filepath.Join(home, "AppData", "Local")},
	}
}

// applyWindowsEnvironment sets values in env as Windows does for one key:
// the REG_SZ values first, then the REG_EXPAND_SZ values, expanded.
func applyWindowsEnvironment(env map[string]string, values []windowsEnvValue) {
	for _, expand := range []bool{false, true} {
		for _, value := range values {
			if value.expand != expand {
				continue
			}
			resolved := value.value
			if expand {
				resolved = expandWindowsEnvironment(resolved, env)
			}
			if utf8.RuneCountInString(resolved) > windowsEnvValueLimit {
				continue
			}
			env[strings.ToUpper(value.name)] = resolved
		}
	}
}

// expandWindowsEnvironment expands the %NAME% references in value the way
// ExpandEnvironmentStrings does against env: names are case-insensitive and
// a reference to an undefined name is kept as written.
func expandWindowsEnvironment(value string, env map[string]string) string {
	var out strings.Builder
	for {
		start := strings.IndexByte(value, '%')
		if start < 0 {
			break
		}
		end := strings.IndexByte(value[start+1:], '%')
		if end < 0 {
			break
		}
		end += start + 1
		if resolved, ok := env[strings.ToUpper(value[start+1:end])]; ok {
			out.WriteString(value[:start])
			out.WriteString(resolved)
			value = value[end+1:]
			continue
		}
		// Keep "%NAME" and scan again from the closing '%'.
		out.WriteString(value[:end])
		value = value[end:]
	}
	out.WriteString(value)
	return out.String()
}

// readWindowsEnvironmentKey returns the string values of the key at path
// under root in enumeration order (none when the key does not exist),
// bounded like an environment block.
func readWindowsEnvironmentKey(root registry.Key, path string) ([]windowsEnvValue, error) {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer key.Close()
	names, err := key.ReadValueNames(windowsEnvKeyValueLimit)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var out []windowsEnvValue
	for _, name := range names {
		if name == "" || strings.ContainsAny(name, "=\x00") {
			continue
		}
		size, valtype, err := key.GetValue(name, nil)
		if err != nil || (valtype != registry.SZ && valtype != registry.EXPAND_SZ) || size > 2*(windowsEnvValueLimit+1) {
			continue
		}
		value, valtype, err := key.GetStringValue(name)
		if err != nil || utf8.RuneCountInString(value) > windowsEnvValueLimit {
			continue
		}
		out = append(out, windowsEnvValue{name: name, value: value, expand: valtype == registry.EXPAND_SZ})
	}
	return out, nil
}
