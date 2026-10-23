// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hermespath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrAccountEnvironmentUnavailable reports that the persistent environment
// of a Windows account cannot be read: its registry hive is not loaded while
// it is signed out, or no profile names its home.
var ErrAccountEnvironmentUnavailable = errors.New("the account's persistent environment cannot be read")

// ConfigPathForAccount resolves the config.yaml of the Hermes home the
// account at userHome configured, for a privileged service acting for that
// account (managed setup and verification). On Windows that is the
// HERMES_HOME of the account's persistent environment (its own variable
// over the machine's), else the Local AppData of its sign-in, read from its
// loaded registry hive. It fails when that home cannot be resolved, and
// never substitutes the profile default for a home it could not read: a
// check of the default proves nothing about the home the account's Hermes
// reads (GAP-0499). On Linux and macOS the result is the account's
// ~/.hermes, which ConfigPathForUserHome also returns; a check of it proves
// the account's home only together with VerifyAccountHome.
func ConfigPathForAccount(userHome string) (string, error) {
	userHome = strings.TrimSpace(userHome)
	if userHome == "" {
		return "", errors.New("the account home is empty")
	}
	home, err := accountHomeResolver(userHome)
	if err != nil {
		return "", fmt.Errorf("resolve the Hermes home of %s: %w", userHome, err)
	}
	if strings.TrimSpace(home) == "" {
		return "", fmt.Errorf("resolve the Hermes home of %s: no home", userHome)
	}
	return filepath.Join(home, "config.yaml"), nil
}

// accountHomeResolver resolves an account's Hermes home; tests in other
// packages replace it (OverrideAccountHomeForTest).
var accountHomeResolver = accountHomeDir

// OverrideAccountHomeForTest makes ConfigPathForAccount resolve every
// account with resolve, or with its profile default when resolve is nil,
// for tests whose synthetic profiles no Windows ProfileList entry names. It
// returns the function that restores the account lookup.
func OverrideAccountHomeForTest(resolve func(userHome string) (string, error)) (restore func()) {
	previous := accountHomeResolver
	if resolve == nil {
		resolve = func(userHome string) (string, error) {
			return filepath.Dir(ConfigPathForUserHome(userHome)), nil
		}
	}
	accountHomeResolver = resolve
	return func() { accountHomeResolver = previous }
}

// accountEnvValue is one variable of a Windows environment key as stored.
type accountEnvValue struct {
	name   string
	value  string
	expand bool
}

// windowsAccountEnvironment is what a Windows account's processes inherit
// that can move its Hermes home, in sign-in order: the machine-wide
// variables, the machine key, the sign-in's profile variables (Volatile
// Environment), then the account's own variables.
type windowsAccountEnvironment struct {
	machineWide map[string]string
	machine     []accountEnvValue
	volatile    []accountEnvValue
	user        []accountEnvValue
}

// windowsAccountHermesHome resolves the Hermes home a process the account
// starts reads: an explicit HERMES_HOME (the account's own over the
// machine's), else <LOCALAPPDATA>\hermes with the sign-in's LOCALAPPDATA or
// the profile default. A REG_EXPAND_SZ value expands against the variables
// Windows sets before it; a reference that does not resolve to a plain
// value, or a result that is not an absolute normalized path, fails rather
// than falling back.
func windowsAccountHermesHome(userHome string, env windowsAccountEnvironment) (string, error) {
	userHome = strings.TrimRight(strings.TrimSpace(userHome), `\/`)
	if !isAbsoluteWindowsPath(userHome + `\`) {
		return "", fmt.Errorf("the profile directory %q is not absolute", userHome)
	}
	volume := userHome[:2]
	if strings.HasPrefix(userHome, `\\`) || strings.HasPrefix(userHome, "//") {
		volume = ""
	}
	vars := map[string]string{}
	for name, value := range env.machineWide {
		vars[strings.ToUpper(name)] = value
	}
	set := func(values []accountEnvValue) {
		for _, value := range values {
			if !value.expand {
				vars[strings.ToUpper(value.name)] = value.value
			}
		}
		for _, value := range values {
			if value.expand {
				// An unresolved reference stays in the value; using it fails below.
				vars[strings.ToUpper(value.name)] = expandAccountValue(value.value, vars)
			}
		}
	}
	set(env.machine)
	set([]accountEnvValue{
		{name: "USERPROFILE", value: userHome},
		{name: "HOMEDRIVE", value: volume},
		{name: "HOMEPATH", value: strings.TrimPrefix(userHome, volume)},
		{name: "APPDATA", value: userHome + `\AppData\Roaming`},
		{name: "LOCALAPPDATA", value: userHome + `\AppData\Local`},
	})
	set(env.volatile)
	set(env.user)
	set(env.volatile)

	if configured, ok := vars["HERMES_HOME"]; ok && strings.TrimSpace(configured) != "" {
		if strings.Contains(configured, "%") {
			return "", fmt.Errorf("HERMES_HOME %q of the account's environment does not expand to a path", configured)
		}
		home := ResolveHomeDir("windows", configured, "", "")
		if home == "" {
			return "", fmt.Errorf("HERMES_HOME %q of the account's environment is not an absolute normalized path", configured)
		}
		return home, nil
	}
	localAppData := vars["LOCALAPPDATA"]
	if strings.Contains(localAppData, "%") {
		return "", fmt.Errorf("LOCALAPPDATA %q of the account's environment does not expand to a path", localAppData)
	}
	home := ResolveHomeDir("windows", "", localAppData, "")
	if home == "" {
		return "", fmt.Errorf("LOCALAPPDATA %q of the account's environment is not an absolute normalized path", localAppData)
	}
	return home, nil
}

// expandAccountValue expands the %NAME% references in value the way
// ExpandEnvironmentStrings does against vars: names are case-insensitive
// and a reference to an undefined name is kept as written.
func expandAccountValue(value string, vars map[string]string) string {
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
		if replacement, ok := vars[strings.ToUpper(value[start+1:end])]; ok && end > start+1 {
			out.WriteString(value[:start])
			out.WriteString(replacement)
			value = value[end+1:]
			continue
		}
		out.WriteString(value[:end])
		value = value[end:]
	}
	out.WriteString(value)
	return out.String()
}

// IsolateHostForTests keeps a test binary off the host's Hermes setup: it
// unsets every HERMES_* variable of the process and reads the account
// environment under an empty directory (OverrideAccountEnvironmentForTest).
// A package whose tests reach Hermes calls it from TestMain; without it a
// developer's exported HERMES_HOME, the host's /etc/profile.d, the
// environment of the test's own processes or the launchd environment failed
// them. It returns the function that removes the directory.
func IsolateHostForTests() (cleanup func(), err error) {
	for _, variable := range os.Environ() {
		if name, _, _ := strings.Cut(variable, "="); strings.HasPrefix(name, "HERMES_") {
			if err := os.Unsetenv(name); err != nil {
				return nil, err
			}
		}
	}
	root, err := os.MkdirTemp("", "hermes-host-")
	if err != nil {
		return nil, err
	}
	restore := OverrideAccountEnvironmentForTest(root)
	return func() { restore(); _ = os.RemoveAll(root) }, nil
}
