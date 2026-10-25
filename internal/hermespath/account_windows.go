// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hermespath

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
)

// accountRegistryPath names a registry key.
type accountRegistryPath struct {
	root registry.Key
	path string
}

// Where the account environment is read from. Replaceable in tests (a test
// cannot load a hive under HKEY_USERS or add a ProfileList entry).
var (
	accountProfileList = accountRegistryPath{
		root: registry.LOCAL_MACHINE,
		path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`,
	}
	accountUserHives          = accountRegistryPath{root: registry.USERS}
	accountMachineEnvironment = accountRegistryPath{
		root: registry.LOCAL_MACHINE,
		path: `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`,
	}
)

const (
	// accountEnvValueLimit is the longest environment value Windows keeps,
	// in characters.
	accountEnvValueLimit = 32767
	// accountEnvKeyValueLimit bounds the values read from one key.
	accountEnvKeyValueLimit = 1024
	// accountProfileLimit bounds the ProfileList entries read.
	accountProfileLimit = 4096
)

// accountMachineWideEnv are machine-wide variables Windows puts in every
// user's environment besides the machine key; the service's own values are
// the machine's.
var accountMachineWideEnv = []string{
	"SystemRoot", "SystemDrive", "windir", "ProgramData", "ALLUSERSPROFILE", "PUBLIC",
	"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
	"CommonProgramFiles", "CommonProgramFiles(x86)", "CommonProgramW6432", "COMPUTERNAME",
}

// accountSignedOutError is the error of an account whose registry hive is
// not loaded. It is both ErrAccountEnvironmentUnavailable and
// ErrAccountSignedOut.
type accountSignedOutError struct{ sid string }

func (e accountSignedOutError) Error() string {
	return ErrAccountEnvironmentUnavailable.Error() + ": the registry hive of " + e.sid +
		" is not loaded while it is signed out"
}

func (e accountSignedOutError) Is(target error) bool {
	return target == ErrAccountEnvironmentUnavailable || target == ErrAccountSignedOut
}

// accountHomeDir reads the persistent environment of the account whose
// profile is userHome from its loaded hive and resolves its Hermes home.
func accountHomeDir(userHome string) (string, error) {
	userHome = filepath.Clean(userHome)
	if !filepath.IsAbs(userHome) {
		return "", fmt.Errorf("the profile directory %q is not absolute", userHome)
	}
	sid, err := accountSIDForProfile(userHome)
	if err != nil {
		return "", err
	}
	hivePath := sid
	if accountUserHives.path != "" {
		hivePath = accountUserHives.path + `\` + sid
	}
	hive, err := registry.OpenKey(accountUserHives.root, hivePath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return "", accountSignedOutError{sid: sid}
	}
	if err != nil {
		return "", fmt.Errorf("%w: open the registry hive of %s: %v", ErrAccountEnvironmentUnavailable, sid, err)
	}
	_ = hive.Close()

	env := windowsAccountEnvironment{machineWide: map[string]string{}}
	for _, name := range accountMachineWideEnv {
		if value := os.Getenv(name); value != "" {
			env.machineWide[name] = value
		}
	}
	// Every key must read: a key that cannot be read could hold the
	// HERMES_HOME that moves the home.
	if env.machine, err = readAccountEnvironmentKey(accountMachineEnvironment.root, accountMachineEnvironment.path); err != nil {
		return "", err
	}
	if env.volatile, err = readAccountEnvironmentKey(accountUserHives.root, hivePath+`\Volatile Environment`); err != nil {
		return "", err
	}
	if env.user, err = readAccountEnvironmentKey(accountUserHives.root, hivePath+`\Environment`); err != nil {
		return "", err
	}
	return windowsAccountHermesHome(userHome, env)
}

// accountSIDForProfile returns the SID of the one ProfileList entry whose
// ProfileImagePath is profile. None, or more than one, fails: the hive to
// read cannot be chosen.
func accountSIDForProfile(profile string) (string, error) {
	list, err := registry.OpenKey(accountProfileList.root, accountProfileList.path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return "", fmt.Errorf("%w: open ProfileList: %v", ErrAccountEnvironmentUnavailable, err)
	}
	names, err := list.ReadSubKeyNames(accountProfileLimit)
	_ = list.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("%w: enumerate ProfileList: %v", ErrAccountEnvironmentUnavailable, err)
	}
	found := ""
	for _, name := range names {
		sid, sidErr := windows.StringToSid(name)
		if sidErr != nil || sid.String() != name {
			continue
		}
		key, openErr := registry.OpenKey(accountProfileList.root, accountProfileList.path+`\`+name, registry.QUERY_VALUE)
		if openErr != nil {
			continue
		}
		raw, kind, valueErr := key.GetStringValue("ProfileImagePath")
		_ = key.Close()
		if valueErr != nil {
			continue
		}
		if kind == registry.EXPAND_SZ {
			if raw, valueErr = registry.ExpandString(raw); valueErr != nil {
				continue
			}
		}
		if !filepath.IsAbs(raw) || !strings.EqualFold(filepath.Clean(raw), profile) {
			continue
		}
		if found != "" {
			return "", fmt.Errorf("%w: profiles %s and %s both name %s", ErrAccountEnvironmentUnavailable, found, name, profile)
		}
		found = name
	}
	if found == "" {
		return "", fmt.Errorf("%w: no profile names %s", ErrAccountEnvironmentUnavailable, profile)
	}
	return found, nil
}

// readAccountEnvironmentKey returns the string values of the key at path
// under root in enumeration order (none when the key does not exist),
// bounded like an environment block.
func readAccountEnvironmentKey(root registry.Key, path string) ([]accountEnvValue, error) {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %v", ErrAccountEnvironmentUnavailable, path, err)
	}
	defer key.Close()
	names, err := key.ReadValueNames(accountEnvKeyValueLimit)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: read %s: %v", ErrAccountEnvironmentUnavailable, path, err)
	}
	var out []accountEnvValue
	for _, name := range names {
		if name == "" || strings.ContainsAny(name, "=\x00") {
			continue
		}
		// A variable that moves the Hermes home and cannot be read fails
		// the read; Windows drops only non-string and oversized values.
		moves := strings.EqualFold(name, "HERMES_HOME") || strings.EqualFold(name, "LOCALAPPDATA")
		size, kind, err := key.GetValue(name, nil)
		if err != nil && moves {
			return nil, fmt.Errorf("%w: read %s of %s: %v", ErrAccountEnvironmentUnavailable, name, path, err)
		}
		if err != nil || (kind != registry.SZ && kind != registry.EXPAND_SZ) || size > 2*(accountEnvValueLimit+1) {
			continue
		}
		value, kind, err := key.GetStringValue(name)
		if err != nil && moves {
			return nil, fmt.Errorf("%w: read %s of %s: %v", ErrAccountEnvironmentUnavailable, name, path, err)
		}
		if err != nil || utf8.RuneCountInString(value) > accountEnvValueLimit {
			continue
		}
		out = append(out, accountEnvValue{name: name, value: value, expand: kind == registry.EXPAND_SZ})
	}
	return out, nil
}

// accountEnvironmentEvidence names no other home on Windows: the account's
// persistent environment is what accountHomeDir resolved the home from.
func accountEnvironmentEvidence(string) ([]homeEvidence, error) {
	return nil, nil
}

// OverrideAccountEnvironmentForTest is a no-op on Windows, where no
// host-wide environment evidence is read.
func OverrideAccountEnvironmentForTest(string) (restore func()) {
	return func() {}
}
