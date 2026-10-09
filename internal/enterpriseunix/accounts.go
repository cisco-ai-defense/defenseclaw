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
	"strconv"
	"strings"

	systemdunits "github.com/defenseclaw/defenseclaw/packaging/systemd"
)

// Account is the gateway service identity.
type Account struct {
	Name    string
	UID     int
	GID     int
	Created bool
	// LoginShell is the shell of an account someone can sign in to (a shell
	// other than nologin or false); "" for a service account.
	LoginShell string
	// Home is the account's home directory, named in the refusal.
	Home string
}

// noLoginShells are the shells that refuse an interactive sign-in.
var noLoginShells = map[string]bool{
	"/usr/sbin/nologin": true, "/sbin/nologin": true, "/usr/bin/nologin": true,
	"/bin/false": true, "/usr/bin/false": true, "/sbin/false": true,
}

// loginAccountError refuses an existing account someone can sign in to as
// the gateway service account: whoever signs in as it could stop the
// gateway, move its hook socket and read the managed config (GAP-0433).
func loginAccountError(account Account, ensure, goos string) error {
	if goos == "darwin" {
		return fmt.Errorf("the existing account %s (uid %d, home %s) has the login shell %s, so it cannot run the DefenseClaw gateway: "+
			"give it a no-login shell with `dscl . -create /Users/%s UserShell /usr/bin/false`, then run `%s`",
			account.Name, account.UID, account.Home, account.LoginShell, account.Name, ensure)
	}
	return fmt.Errorf("the existing account %s (uid %d, home %s) has the login shell %s, so it cannot run the DefenseClaw gateway: "+
		"anyone who signs in as it could stop the gateway or move its hook socket. Remove it with `userdel %s` "+
		"(DefenseClaw then creates a system account that cannot sign in), or give it a no-login shell with "+
		"`usermod -s /usr/sbin/nologin %s`, then run `%s`",
		account.Name, account.UID, account.Home, account.LoginShell, account.Name, account.Name, ensure)
}

// AccountManager resolves, creates and removes the service account.
type AccountManager interface {
	Lookup(ctx context.Context, name string) (Account, bool, error)
	Ensure(ctx context.Context, name string) (Account, error)
	Remove(ctx context.Context, name string) error
}

func newAccountManager(env *Env) AccountManager {
	if env.GOOS == "darwin" {
		return &dsclAccounts{env: env}
	}
	return &linuxAccounts{env: env}
}

// linuxAccounts uses NSS through getent for lookups and systemd-sysusers
// (falling back to useradd) for creation, so an existing account keeps its
// uid.
type linuxAccounts struct {
	env *Env
}

func (a *linuxAccounts) Lookup(ctx context.Context, name string) (Account, bool, error) {
	result, err := a.env.Runner.Run(ctx, "getent", "passwd", name)
	if err != nil {
		if result.ExitCode == 2 {
			return Account{}, false, nil
		}
		return Account{}, false, fmt.Errorf("look up %s: %w", name, err)
	}
	fields := strings.Split(strings.TrimSpace(string(result.Stdout)), ":")
	if len(fields) < 7 || fields[0] != name {
		return Account{}, false, fmt.Errorf("look up %s: malformed passwd entry", name)
	}
	uid, uidErr := strconv.Atoi(fields[2])
	gid, gidErr := strconv.Atoi(fields[3])
	if uidErr != nil || gidErr != nil || uid <= 0 || gid <= 0 {
		return Account{}, false, fmt.Errorf("look up %s: invalid uid/gid %q:%q", name, fields[2], fields[3])
	}
	group, err := a.env.Runner.Run(ctx, "getent", "group", strconv.Itoa(gid))
	if err != nil {
		return Account{}, false, fmt.Errorf("look up primary group of %s: %w", name, err)
	}
	if groupName := strings.SplitN(strings.TrimSpace(string(group.Stdout)), ":", 2)[0]; groupName != name {
		return Account{}, false, fmt.Errorf("service account %s must have primary group %s, found %q", name, name, groupName)
	}
	account := Account{Name: name, UID: uid, GID: gid, Home: fields[5]}
	// An empty shell field is /bin/sh.
	if shell := strings.TrimSpace(fields[6]); shell == "" || !noLoginShells[filepath.Clean(shell)] {
		account.LoginShell = shell
		if shell == "" {
			account.LoginShell = "/bin/sh"
		}
	}
	return account, true, nil
}

func (a *linuxAccounts) Ensure(ctx context.Context, name string) (Account, error) {
	if account, ok, err := a.Lookup(ctx, name); err != nil || ok {
		if err == nil && account.LoginShell != "" {
			return Account{}, loginAccountError(account, a.env.lifecycleCommand("ensure"), a.env.GOOS)
		}
		return account, err
	}
	// The account must exist before the transaction renders any file, so
	// the sysusers.d entry is passed inline rather than read from a
	// sysusers.d file the lifecycle has not written yet.
	lines, err := sysusersLines()
	if err != nil {
		return Account{}, err
	}
	sysusers, err := a.env.Runner.Run(ctx, "systemd-sysusers", append([]string{"--inline"}, lines...)...)
	if err != nil && !errors.Is(err, ErrCommandNotFound) {
		return Account{}, fmt.Errorf("create service account with systemd-sysusers: %w", err)
	}
	sysusersSkipped := ""
	if err == nil {
		account, ok, err := a.Lookup(ctx, name)
		if err != nil {
			return Account{}, err
		}
		if ok {
			account.Created = true
			return account, nil
		}
		// systemd-sysusers exits 0 without creating anything when it cannot
		// ask NSS whether the account exists, for example when nsswitch.conf
		// lists sss while sssd is stopped or masked ("Failed to check if
		// group defenseclaw already exists: Connection refused"). groupadd
		// and useradd read /etc/group and /etc/passwd themselves, so they
		// create it instead (GAP-1214).
		sysusersSkipped = truncateUTF8(firstLine(string(sysusers.Stderr)), 300)
		if sysusersSkipped == "" {
			sysusersSkipped = "it reported nothing"
		}
	}
	if err := a.createWithShadowTools(ctx, name); err != nil {
		if sysusersSkipped != "" {
			return Account{}, fmt.Errorf("systemd-sysusers exited without creating the service account %s (%s; this happens when /etc/nsswitch.conf lists sss while sssd is not running), and %w", name, sysusersSkipped, err)
		}
		return Account{}, err
	}
	account, ok, err := a.Lookup(ctx, name)
	if err != nil {
		return Account{}, err
	}
	if !ok {
		return Account{}, fmt.Errorf("service account %s was not created", name)
	}
	account.Created = true
	return account, nil
}

// createWithShadowTools creates the service group (unless it exists) and
// the service account with groupadd and useradd.
func (a *linuxAccounts) createWithShadowTools(ctx context.Context, name string) error {
	if _, err := a.env.Runner.Run(ctx, "getent", "group", name); err != nil {
		if _, err := a.env.Runner.Run(ctx, "groupadd", "--system", name); err != nil {
			return fmt.Errorf("create service group: %w", err)
		}
	}
	if _, err := a.env.Runner.Run(ctx, "useradd", "--system", "--gid", name,
		"--home-dir", a.env.Layout.DataDir, "--no-create-home",
		"--shell", "/usr/sbin/nologin", "--comment", "DefenseClaw gateway", name); err != nil {
		return fmt.Errorf("create service account: %w", err)
	}
	return nil
}

// firstLine is the first non-empty line of a command's output.
func firstLine(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}

// sysusersLines returns the entries of the embedded sysusers.d document
// without comments or blank lines.
func sysusersLines() ([]string, error) {
	data, err := systemdunits.ReadFile(systemdunits.SysusersName)
	if err != nil {
		return nil, fmt.Errorf("read the sysusers.d entry: %w", err)
	}
	lines := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return nil, errors.New("the sysusers.d entry is empty")
	}
	return lines, nil
}

func (a *linuxAccounts) Remove(ctx context.Context, name string) error {
	if _, ok, err := a.Lookup(ctx, name); err != nil || !ok {
		return err
	}
	if _, err := a.env.Runner.Run(ctx, "userdel", name); err != nil {
		return fmt.Errorf("remove service account: %w", err)
	}
	// userdel removes a user-private group; a leftover group is removed too.
	if result, err := a.env.Runner.Run(ctx, "getent", "group", name); err == nil && len(result.Stdout) > 0 {
		if _, err := a.env.Runner.Run(ctx, "groupdel", name); err != nil {
			return fmt.Errorf("remove service group: %w", err)
		}
	}
	return nil
}

// dsclAccounts manages a hidden macOS service account with dscl.
type dsclAccounts struct {
	env *Env
}

func (a *dsclAccounts) readID(ctx context.Context, record, key string) (int, bool, error) {
	result, err := a.env.Runner.Run(ctx, "dscl", ".", "-read", record, key)
	if err != nil {
		if strings.Contains(err.Error(), "eDSRecordNotFound") || strings.Contains(err.Error(), "No such key") || result.ExitCode == 56 {
			return 0, false, nil
		}
		return 0, false, err
	}
	fields := strings.Fields(string(result.Stdout))
	if len(fields) != 2 || strings.TrimSuffix(fields[0], ":") != key {
		return 0, false, fmt.Errorf("dscl %s %s: unexpected output %q", record, key, strings.TrimSpace(string(result.Stdout)))
	}
	id, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func (a *dsclAccounts) readAttribute(ctx context.Context, record, key string) (string, error) {
	result, err := a.env.Runner.Run(ctx, "dscl", ".", "-read", record, key)
	if err != nil {
		return "", fmt.Errorf("read %s %s: %w", record, key, err)
	}
	value, ok := strings.CutPrefix(strings.TrimSpace(string(result.Stdout)), key+":")
	if !ok {
		return "", fmt.Errorf("dscl %s %s: unexpected output %q", record, key, strings.TrimSpace(string(result.Stdout)))
	}
	return strings.TrimSpace(value), nil
}

func (a *dsclAccounts) Lookup(ctx context.Context, name string) (Account, bool, error) {
	uid, ok, err := a.readID(ctx, "/Users/"+name, "UniqueID")
	if err != nil || !ok {
		return Account{}, false, err
	}
	gid, ok, err := a.readID(ctx, "/Users/"+name, "PrimaryGroupID")
	if err != nil {
		return Account{}, false, err
	}
	if !ok {
		return Account{}, false, fmt.Errorf("service account %s has no primary group", name)
	}
	groupGID, ok, err := a.readID(ctx, "/Groups/"+name, "PrimaryGroupID")
	if err != nil {
		return Account{}, false, err
	}
	if !ok || groupGID != gid {
		return Account{}, false, fmt.Errorf("service account %s must have primary group %s", name, name)
	}
	shell, err := a.readAttribute(ctx, "/Users/"+name, "UserShell")
	if err != nil {
		return Account{}, false, err
	}
	home, err := a.readAttribute(ctx, "/Users/"+name, "NFSHomeDirectory")
	if err != nil {
		return Account{}, false, err
	}
	account := Account{Name: name, UID: uid, GID: gid, Home: home}
	if shell == "" {
		shell = "/bin/sh"
	}
	if !noLoginShells[filepath.Clean(shell)] {
		account.LoginShell = shell
	}
	return account, true, nil
}

func (a *dsclAccounts) usedIDs(ctx context.Context, path, key string) (map[int]bool, error) {
	result, err := a.env.Runner.Run(ctx, "dscl", ".", "-list", path, key)
	if err != nil {
		return nil, err
	}
	used := map[int]bool{}
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if id, err := strconv.Atoi(fields[len(fields)-1]); err == nil {
				used[id] = true
			}
		}
	}
	return used, nil
}

// freeServiceID returns the highest id in [300, 499] unused as both a uid
// and a gid, the range macOS reserves for daemon accounts.
func freeServiceID(users, groups map[int]bool) (int, error) {
	for id := 499; id >= 300; id-- {
		if !users[id] && !groups[id] {
			return id, nil
		}
	}
	return 0, errors.New("no free macOS daemon uid/gid in 300-499")
}

func (a *dsclAccounts) Ensure(ctx context.Context, name string) (Account, error) {
	if account, ok, err := a.Lookup(ctx, name); err != nil || ok {
		if err == nil && account.LoginShell != "" {
			return Account{}, loginAccountError(account, a.env.lifecycleCommand("ensure"), a.env.GOOS)
		}
		return account, err
	}
	users, err := a.usedIDs(ctx, "/Users", "UniqueID")
	if err != nil {
		return Account{}, fmt.Errorf("list macOS uids: %w", err)
	}
	groups, err := a.usedIDs(ctx, "/Groups", "PrimaryGroupID")
	if err != nil {
		return Account{}, fmt.Errorf("list macOS gids: %w", err)
	}
	id, err := freeServiceID(users, groups)
	if err != nil {
		return Account{}, err
	}
	idText := strconv.Itoa(id)
	steps := [][]string{
		{".", "-create", "/Groups/" + name},
		{".", "-create", "/Groups/" + name, "PrimaryGroupID", idText},
		{".", "-create", "/Groups/" + name, "RealName", "DefenseClaw gateway"},
		{".", "-create", "/Groups/" + name, "Password", "*"},
		{".", "-create", "/Users/" + name},
		{".", "-create", "/Users/" + name, "UniqueID", idText},
		{".", "-create", "/Users/" + name, "PrimaryGroupID", idText},
		{".", "-create", "/Users/" + name, "UserShell", "/usr/bin/false"},
		{".", "-create", "/Users/" + name, "NFSHomeDirectory", "/var/empty"},
		{".", "-create", "/Users/" + name, "RealName", "DefenseClaw gateway"},
		{".", "-create", "/Users/" + name, "Password", "*"},
		{".", "-create", "/Users/" + name, "IsHidden", "1"},
	}
	for _, step := range steps {
		if _, err := a.env.Runner.Run(ctx, "dscl", step...); err != nil {
			return Account{}, fmt.Errorf("create macOS service account: %w", err)
		}
	}
	account, ok, err := a.Lookup(ctx, name)
	if err != nil {
		return Account{}, err
	}
	if !ok {
		return Account{}, fmt.Errorf("service account %s was not created", name)
	}
	account.Created = true
	return account, nil
}

func (a *dsclAccounts) Remove(ctx context.Context, name string) error {
	if _, ok, err := a.Lookup(ctx, name); err != nil || !ok {
		return err
	}
	for _, record := range []string{"/Users/" + name, "/Groups/" + name} {
		if _, err := a.env.Runner.Run(ctx, "dscl", ".", "-delete", record); err != nil {
			return fmt.Errorf("remove %s: %w", record, err)
		}
	}
	return nil
}
