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

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The standalone Windows credential store: one file per credential under
// <ProgramData>\Cisco\DefenseClaw\secrets, owned by Administrators, with a
// protected DACL that grants full control only to LocalSystem and
// Administrators and read-only access to the gateway service SID — exactly
// what managed.ResolveServiceCredential accepts. The directory grants the
// gateway SID only what its trust walk needs (see
// windowsSecretDirectorySDDL). Values arrive on stdin or from an
// administrator-only file and are never printed.

const (
	windowsSecretExitInvalid = 1639
	windowsSecretExitFailure = 1603
)

var (
	// windowsSecretLayout resolves the standalone layout (tests use a
	// temporary tree).
	windowsSecretLayout = managed.StandaloneWindowsLayout
	// windowsSecretGatewayAccount is the service whose SID may read the
	// credentials.
	windowsSecretGatewayAccount = `NT SERVICE\` + managed.StandaloneWindowsGatewaySvc
	// windowsSecretDeploymentInstalled reports whether an administrator
	// recorded a standalone deployment on this host; a record a standard
	// user planted does not count.
	windowsSecretDeploymentInstalled = func() (bool, error) {
		deployment, err := inspectTrustedWindowsEnterpriseDeployment(managed.ProfileStandalone)
		if err != nil {
			return false, err
		}
		return deployment.State == winpath.EnterpriseDeploymentInstalled, nil
	}
	windowsSecretIsElevated     = func() bool { return windows.GetCurrentProcessToken().IsElevated() }
	windowsSecretRestartGateway = restartWindowsStandaloneGateway
	// windowsSecretLockBundleStore, windowsSecretLifecycleLockPath and
	// windowsSecretLifecycleLock are the two locks set and remove take.
	windowsSecretLockBundleStore   = lockWindowsBundleStoreWithin
	windowsSecretLifecycleLockPath = func() (string, error) {
		roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
		if err != nil {
			return "", err
		}
		return filepath.Join(roots.LifecycleDir, "lifecycle.lock"), nil
	}
	windowsSecretLifecycleLock = acquireWindowsEnterpriseLifecycleLock
	// windowsSecretInstallerLockWait is the fixed wait for the installer's
	// lifecycle.lock: the 30 s default of Enter-DefenseClawLifecycleLock
	// (packaging/windows/DefenseClawEnterprise.psm1).
	windowsSecretInstallerLockWait = 30 * time.Second
)

func init() {
	// Every verb prints its --json failure document for a flag error,
	// status too (mgmt-agent-api GAP-0029).
	enterpriseSecretArgumentRefusal = func(cmd *cobra.Command, action string, opts *enterpriseSecretOptions, err error) error {
		return reportWindowsSecretFailure(cmd, action, opts, err, opts.json || secretArgsRequestJSON(secretRawArgs()))
	}
}

// windowsSecretStandardUserAnswer is a standard account's refusal of
// `enterprise secret`: the elevated command to ask for, and that nothing
// changed.
func windowsSecretStandardUserAnswer(action string, opts *enterpriseSecretOptions) string {
	if action == "status" {
		return windowsManagedStandardUserViewAnswer("The protected credentials", "enterprise secret status")
	}
	command := "enterprise secret " + action
	if opts != nil && managed.ValidCredentialName(opts.name) {
		command += " --name " + opts.name
	}
	return "a standard account cannot " + action + " a protected credential of the managed deployment. Ask your administrator, who runs it from an elevated PowerShell prompt with `& '" +
		managedWindowsAdminCLI() + "' " + command + "`. Nothing was changed."
}

type windowsSecretState struct {
	Name         string `json:"name"`
	Present      bool   `json:"present"`
	SHA256Prefix string `json:"sha256_prefix,omitempty"`
	ModifiedAt   string `json:"modified_at,omitempty"`
}

// reportWindowsSecretFailure prints the failure document of err when asJSON
// and returns err, labelled 1603 when nothing chose an exit code.
func reportWindowsSecretFailure(cmd *cobra.Command, action string, opts *enterpriseSecretOptions, err error, asJSON bool) error {
	err = reportSecretFailure(cmd, action, opts, err, asJSON, windowsSecretExitFailure, windowsSecretExitInvalid)
	silenceJSONReportedError(cmd, asJSON, err)
	return err
}

// runEnterpriseSecret implements `enterprise secret` on Windows.
func runEnterpriseSecret(cmd *cobra.Command, action string, opts *enterpriseSecretOptions) error {
	if action == "status" {
		// A status failure prints the failure document too: a standard
		// account's elevation_required printed only its sentence on stderr
		// (mgmt-agent-api GAP-0029).
		if err := runWindowsSecretStatus(cmd, opts); err != nil {
			return reportWindowsSecretFailure(cmd, action, opts, err, opts.json)
		}
		return nil
	}
	restarted, err := changeWindowsSecret(cmd, action, opts)
	if err != nil {
		return reportWindowsSecretFailure(cmd, action, opts, err, opts.json)
	}
	if opts.json {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
			"schema_version": 1, "ok": true, "action": action, "name": opts.name, "gateway_restarted": restarted,
		})
	}
	fmt.Fprintf(cmd.OutOrStdout(), "credential %s %s; gateway restarted: %v\n", opts.name, windowsSecretChanged(action), restarted)
	return nil
}

func windowsSecretChanged(action string) string {
	return map[string]string{"set": "stored", "remove": "removed"}[action]
}

// windowsSecretElevation refuses a caller that is not elevated.
func windowsSecretElevation(action string, opts *enterpriseSecretOptions) error {
	if windowsSecretIsElevated() {
		return nil
	}
	if _, standalone := managedHostWindowsStandalone(); standalone {
		// Every other standard-account refusal of an enterprise command
		// on a managed computer exits 5 elevation_required with one
		// sentence; this one exited 1603 (GAP-0931).
		return withExitCode(&managedViewRefusal{code: "elevation_required", message: windowsSecretStandardUserAnswer(action, opts)},
			enterprisestatus.WindowsExitAccessDenied)
	}
	return secretFailed("elevation_required", windowsSecretExitFailure, errors.New("run this command from an elevated Administrator prompt or the MDM agent"))
}

func runWindowsSecretStatus(cmd *cobra.Command, opts *enterpriseSecretOptions) error {
	if err := windowsSecretElevation("status", opts); err != nil {
		return err
	}
	layout, err := windowsSecretLayout()
	if err != nil {
		return secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure, err)
	}
	states, err := windowsSecretStatus(layout.SecretsDir)
	if err != nil {
		return secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure, err)
	}
	if opts.json {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"schema_version": 1, "secrets": states})
	}
	if len(states) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "no protected credentials")
	}
	for _, state := range states {
		fmt.Fprintf(cmd.OutOrStdout(), "%-32s sha256:%s… modified %s\n", state.Name, state.SHA256Prefix, state.ModifiedAt)
	}
	return nil
}

// changeWindowsSecret stores or removes the credential and restarts the
// gateway so it reads the change. Arguments and the value are checked
// before any lock is taken; the change and the restart run under both
// locks (lockWindowsSecretChange). It reports whether the gateway was
// restarted.
func changeWindowsSecret(cmd *cobra.Command, action string, opts *enterpriseSecretOptions) (bool, error) {
	if err := windowsSecretElevation(action, opts); err != nil {
		return false, err
	}
	if err := checkWindowsLockWait(cmd, opts.lockWait); err != nil {
		return false, err
	}
	layout, err := windowsSecretLayout()
	if err != nil {
		return false, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure, err)
	}
	if !managed.ValidCredentialName(opts.name) {
		return false, secretFailed("invalid_arguments", windowsSecretExitInvalid, fmt.Errorf("--name %q must be lowercase letters, digits and dashes", opts.name))
	}
	if err := requireWindowsSecretDeployment(); err != nil {
		return false, err
	}
	var value []byte
	switch action {
	case "set":
		if opts.fromStdin == (opts.fromFile != "") {
			return false, secretFailed("invalid_arguments", windowsSecretExitInvalid, errors.New("pass exactly one of --from-stdin or --from-file"))
		}
		var source io.Reader = cmd.InOrStdin()
		if opts.fromFile != "" {
			if err := managed.ValidateTrustedFilePath(opts.fromFile, "credential source"); err != nil {
				return false, secretFailed("invalid_arguments", windowsSecretExitInvalid, err)
			}
			file, err := os.Open(opts.fromFile)
			if err != nil {
				return false, secretFailed("change_failed", windowsSecretExitFailure, err)
			}
			defer file.Close()
			source = file
		}
		if value, err = readWindowsSecretValue(source); err != nil {
			return false, secretFailed("invalid_arguments", windowsSecretExitInvalid, err)
		}
	case "remove":
	default:
		return false, secretFailed("invalid_arguments", windowsSecretExitInvalid, fmt.Errorf("unknown action %q", action))
	}
	release, err := lockWindowsSecretChange(cmd.Context(), layout, opts.lockWait)
	if err != nil {
		return false, err
	}
	defer release()
	// An uninstall holds lifecycle.lock, so one can finish while this run
	// waits for it; check again under both locks before anything is written.
	if err := requireWindowsSecretDeployment(); err != nil {
		return false, err
	}
	// Pin the store before anything in it is read, written or deleted: a
	// junction, mount point, symlink or file where the folder belongs is
	// state_invalid. Remove deleted the credential a junction target held
	// and reported success (GAP-1315); set reported change_failed (GAP-1314).
	store, err := openWindowsSecretStore(layout.SecretsDir, action == "set")
	if err != nil {
		return false, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure, err)
	}
	defer store.close()
	if action == "set" {
		if err := writeWindowsSecret(store, opts.name, value); err != nil {
			return false, secretFailed("change_failed", windowsSecretExitFailure, err)
		}
	} else if err := removeWindowsSecret(layout, store, opts.name); err != nil {
		return false, err
	}
	store.close()
	// The gateway reads credentials when it starts; apply the change now.
	restarted, err := windowsSecretRestartGateway()
	if err != nil {
		return false, secretFailed("restart_failed", windowsSecretExitFailure,
			fmt.Errorf("credential %s %s, but restarting the gateway failed: %w", opts.name, windowsSecretChanged(action), err))
	}
	return restarted, nil
}

// requireWindowsSecretDeployment refuses not_installed (1603) unless a
// standalone managed deployment is installed.
func requireWindowsSecretDeployment() error {
	installed, err := windowsSecretDeploymentInstalled()
	if err != nil {
		return secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure, err)
	}
	if !installed {
		return secretFailed("not_installed", windowsSecretExitFailure, errors.New("no standalone managed deployment is installed; run `enterprise windows ensure --profile standalone` first"))
	}
	return nil
}

// removeWindowsSecret deletes the credential unless the installed config
// still references it. The restart that follows would start the gateway on a
// config it cannot compile without this credential, or run the judge without
// its key (GAP-0674). A config that exists but cannot be read may still
// reference it, so nothing is removed (GAP-1507).
func removeWindowsSecret(layout managed.StandaloneLayout, store *windowsSecretStore, name string) error {
	if strings.TrimSpace(layout.ConfigPath) != "" {
		raw, err := os.ReadFile(layout.ConfigPath)
		switch {
		case err == nil:
			if at := config.InstalledCredentialReference(layout.ConfigPath, raw, layout.DataDir, name); at != "" {
				return secretFailed("credential_in_use", windowsSecretExitFailure,
					fmt.Errorf("the installed config still references credential %s at %s; remove that reference and apply the config first", name, at))
			}
		case !errors.Is(err, os.ErrNotExist):
			return secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure,
				fmt.Errorf("cannot read the installed config %s to check that it no longer references credential %s (%v); nothing was removed: restore read access to the config and run it again", layout.ConfigPath, name, err))
		}
	}
	if err := store.remove(name); err != nil {
		return secretFailed("change_failed", windowsSecretExitFailure, err)
	}
	return nil
}

// lockWindowsSecretChange takes the locks a policy bundle apply takes, in
// the apply's order: bundle.lock, waiting up to wait (--lock-wait), then the
// installer's lifecycle.lock, waiting up to 30 s as
// Enter-DefenseClawLifecycleLock does. Go opens lifecycle.lock the way the
// installer does (exclusive, no sharing), so the credential write and the
// gateway restart cannot land inside an apply or its confirm step, a repair,
// an ensure without a bundle or a guardian repair. Either lock busy is
// lifecycle_busy (1618) with nothing written. The release frees both.
func lockWindowsSecretChange(ctx context.Context, layout managed.StandaloneLayout, wait time.Duration) (func(), error) {
	unlockBundle, err := windowsSecretLockBundleStore(ctx, layout.LifecycleDir, wait)
	if err != nil {
		if errors.Is(err, errWindowsBundleStoreBusy) {
			return nil, secretFailed("lifecycle_busy", enterprisestatus.WindowsExitBusy,
				fmt.Errorf("the credential was not changed and the run can be retried: %w", err))
		}
		return nil, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure,
			fmt.Errorf("cannot lock the policy bundle store; the credential was not changed: %w", err))
	}
	path, err := windowsSecretLifecycleLockPath()
	if err != nil {
		unlockBundle()
		return nil, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure,
			fmt.Errorf("cannot resolve the trusted enterprise roots; the credential was not changed: %w", err))
	}
	unlockLifecycle, err := acquireWindowsLockWithin(ctx, windowsSecretInstallerLockWait,
		func() (func(), error) { return windowsSecretLifecycleLock(path) }, windowsLifecycleLockBusy)
	if err != nil {
		unlockBundle()
		if windowsLifecycleLockBusy(err) {
			return nil, secretFailed("lifecycle_busy", enterprisestatus.WindowsExitBusy,
				fmt.Errorf("another DefenseClaw lifecycle run holds lifecycle.lock for more than %s; the credential was not changed and the run can be retried", formatWindowsLockWait(windowsSecretInstallerLockWait)))
		}
		return nil, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure,
			fmt.Errorf("cannot open lifecycle.lock; the credential was not changed: %w", err))
	}
	return func() {
		unlockLifecycle()
		unlockBundle()
	}, nil
}

// windowsLifecycleLockBusy reports that another process has lifecycle.lock
// open (the installer opens it with no sharing).
func windowsLifecycleLockBusy(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

func readWindowsSecretValue(source io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(source, managed.ServiceCredentialLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read credential: %w", err)
	}
	if len(data) > managed.ServiceCredentialLimit {
		return nil, fmt.Errorf("credential exceeds %d bytes", managed.ServiceCredentialLimit)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("credential is empty")
	}
	if bytes.ContainsAny(data, "\x00\r\n") {
		return nil, errors.New("credential must be a single line")
	}
	return data, nil
}

// windowsSecretDirectoryReaderAccess is the directory right set of the
// gateway service SID: READ_CONTROL | SYNCHRONIZE | FILE_READ_ATTRIBUTES |
// FILE_TRAVERSE. The gateway's credential reader walks every ancestor of the
// credential and reads its owner and DACL (GetNamedSecurityInfo needs
// READ_CONTROL); without this ACE the virtual account is denied on this
// directory and AI Defense inspection never starts. It grants no list,
// create, delete or write right.
const windowsSecretDirectoryReaderAccess = "0x1200a0"

// windowsSecretDirectorySDDL: Administrators own the directory; LocalSystem
// and Administrators hold full control, inherited by new files. The reader
// (the gateway service SID) gets a non-inheritable ACE with only
// windowsSecretDirectoryReaderAccess on the directory itself. The Windows
// installer re-applies this descriptor and windowsSecretFileSDDL on install,
// upgrade and reconcile (Set-DefenseClawStandaloneSecretsAcls in
// DefenseClawEnterprise.psm1), because a non-purge uninstall resets the
// retained store to administrator-only ACLs; a contract test keeps the two
// copies identical.
func windowsSecretDirectorySDDL(reader *windows.SID) string {
	return "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;" + windowsSecretDirectoryReaderAccess + ";;;" + reader.String() + ")"
}

// windowsSecretFileSDDL: a credential file is readable by the reader (the
// gateway service SID) and writable only by LocalSystem and Administrators.
func windowsSecretFileSDDL(reader *windows.SID) string {
	return "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;" + reader.String() + ")"
}

// errWindowsSecretsDirNotReal refuses a junction, mount point, symlink or
// file where the secrets folder belongs.
var errWindowsSecretsDirNotReal = errors.New("is not a real directory")

// windowsSecretStore is the secrets folder pinned by openWindowsSecretStore.
// The handle is the folder itself, never what a reparse point names, and it
// denies FILE_SHARE_DELETE, so nobody can rename or remove the folder or swap
// a junction in while a verb works inside it. A zero handle is a folder that
// does not exist.
type windowsSecretStore struct {
	dir    string
	handle windows.Handle
}

// openWindowsSecretStore is the one guard every path into the store takes
// before it reads, writes or deletes anything there: set, remove, status and
// the credential_missing warning. A junction, mount point, symlink or file
// where the folder belongs is errWindowsSecretsDirNotReal (the verbs report
// state_invalid, exit 1603), and nothing in it or in a link target is
// touched (GAP-1314, GAP-1315). It reads the attributes of the opened object
// itself: since Go 1.23 os.Lstat reports a junction as ModeDir|ModeIrregular
// without ModeSymlink, and a check by path leaves a window for a swap. create
// makes a missing folder (set).
func openWindowsSecretStore(dir string, create bool) (*windowsSecretStore, error) {
	handle, err := pinWindowsSecretsDir(dir)
	if create && errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
		handle, err = pinWindowsSecretsDir(dir)
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		return &windowsSecretStore{dir: dir}, nil
	case err != nil:
		return nil, err
	}
	return &windowsSecretStore{dir: dir, handle: handle}, nil
}

func pinWindowsSecretsDir(dir string) (windows.Handle, error) {
	name, err := winpath.UTF16Ptr(dir)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.FILE_TRAVERSE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return 0, fmt.Errorf("%s: %w", dir, os.ErrNotExist)
	}
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", dir, err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return 0, fmt.Errorf("inspect %s: %w", dir, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		_ = windows.CloseHandle(handle)
		return 0, fmt.Errorf("%s %w", dir, errWindowsSecretsDirNotReal)
	}
	return handle, nil
}

func (s *windowsSecretStore) exists() bool { return s.handle != 0 }

func (s *windowsSecretStore) close() {
	if s.handle != 0 {
		_ = windows.CloseHandle(s.handle)
		s.handle = 0
	}
}

// remove deletes credential name from the pinned folder. It opens the entry
// relative to the folder handle and follows no reparse point
// (OBJ_DONT_REPARSE, FILE_OPEN_REPARSE_POINT), so a link named like the
// credential is removed itself, never its target; a folder of that name is
// refused. A missing credential is not an error.
func (s *windowsSecretStore) remove(name string) error {
	if !s.exists() {
		return nil
	}
	if !managed.ValidCredentialName(name) {
		return fmt.Errorf("credential name %q is not valid", name)
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: s.handle,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	var entry windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&entry, windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, &attributes, &status, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open credential %s in %s: %w", name, s.dir, err)
	}
	defer func() { _ = windows.CloseHandle(entry) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(entry, &info); err != nil {
		return fmt.Errorf("inspect credential %s in %s: %w", name, s.dir, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return fmt.Errorf("%s in %s is a folder, not a credential; nothing was removed", name, s.dir)
	}
	deleteFile := byte(1)
	if err := windows.SetFileInformationByHandle(entry, windows.FileDispositionInfo, &deleteFile, 1); err != nil {
		return fmt.Errorf("remove credential %s from %s: %w", name, s.dir, err)
	}
	return nil
}

// windowsSecretStored reports whether credential name is in the store at
// dir. A store that is not a real directory holds none: the gateway reader
// refuses it too. A store this account cannot open counts as stored
// (unchecked), so a standard account is not warned about it.
func windowsSecretStored(dir, name string) bool {
	store, err := openWindowsSecretStore(dir, false)
	if err != nil {
		return !errors.Is(err, errWindowsSecretsDirNotReal)
	}
	defer store.close()
	if !store.exists() {
		return false
	}
	_, err = os.Lstat(filepath.Join(dir, name))
	return !errors.Is(err, os.ErrNotExist)
}

func ensureWindowsSecretsDir(store *windowsSecretStore, reader *windows.SID) error {
	if reader == nil {
		return errors.New("the secrets directory needs the gateway service SID")
	}
	if !store.exists() {
		return fmt.Errorf("%s does not exist", store.dir)
	}
	// The credential write below proves the whole chain through the
	// gateway reader check.
	return applyWindowsSDDL(store.dir, windowsSecretDirectorySDDL(reader))
}

func writeWindowsSecret(store *windowsSecretStore, name string, value []byte) error {
	gateway, err := managed.WindowsServiceAccountSID(windowsSecretGatewayAccount)
	if err != nil || gateway == nil {
		return fmt.Errorf("resolve the gateway service SID (%s): %v", windowsSecretGatewayAccount, err)
	}
	final, err := storeWindowsSecret(store, name, value, gateway)
	if err != nil {
		return err
	}
	// Prove the gateway's reader accepts the stored credential. This runs
	// with the administrator's token, so it checks the path, owner and ACL
	// shape; the gateway's own rights come from the reader ACEs above
	// (pinned by TestWindowsSecretStoreUsesTheGatewayReaderDACL).
	previous, had := os.LookupEnv(managed.WindowsServiceAccountEnv)
	_ = os.Setenv(managed.WindowsServiceAccountEnv, windowsSecretGatewayAccount)
	_, _, verifyErr := managed.ResolveServiceCredential(name, store.dir)
	if had {
		_ = os.Setenv(managed.WindowsServiceAccountEnv, previous)
	} else {
		_ = os.Unsetenv(managed.WindowsServiceAccountEnv)
	}
	if verifyErr != nil {
		_ = os.Remove(final)
		return fmt.Errorf("the stored credential failed the gateway's trust check and was removed: %w", verifyErr)
	}
	return nil
}

// storeWindowsSecret writes value to name in the pinned store atomically,
// with the protected credential DACL for reader, after (re)applying the
// secrets directory DACL, and returns the final path.
func storeWindowsSecret(store *windowsSecretStore, name string, value []byte, reader *windows.SID) (string, error) {
	if err := ensureWindowsSecretsDir(store, reader); err != nil {
		return "", err
	}
	dir := store.dir
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	tmp := filepath.Join(dir, "."+name+".tmp-"+hex.EncodeToString(suffix))
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	cleanup := func() { _ = os.Remove(tmp) }
	if err := applyWindowsSDDL(tmp, windowsSecretFileSDDL(reader)); err != nil {
		_ = file.Close()
		cleanup()
		return "", err
	}
	if _, err := file.Write(value); err != nil {
		_ = file.Close()
		cleanup()
		return "", err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return "", err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", err
	}
	final := filepath.Join(dir, name)
	if err := os.Rename(tmp, final); err != nil {
		cleanup()
		return "", err
	}
	return final, nil
}

func applyWindowsSDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build security descriptor: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
}

func windowsSecretStatus(dir string) ([]windowsSecretState, error) {
	// The guard set and remove take. On Windows os.ReadDir of a regular file
	// can return no entries and no error, so a file or a link where the
	// folder belongs would list as an empty store (or as the files of the
	// link target) instead of a state the administrator must repair.
	store, err := openWindowsSecretStore(dir, false)
	if err != nil {
		return nil, err
	}
	defer store.close()
	if !store.exists() {
		return []windowsSecretState{}, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	states := []windowsSecretState{}
	for _, entry := range entries {
		name := entry.Name()
		if !managed.ValidCredentialName(name) || !entry.Type().IsRegular() {
			continue
		}
		state := windowsSecretState{Name: name, Present: true}
		if info, err := entry.Info(); err == nil {
			state.ModifiedAt = info.ModTime().UTC().Format(time.RFC3339)
		}
		if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			sum := sha256.Sum256(bytes.TrimSpace(data))
			state.SHA256Prefix = hex.EncodeToString(sum[:])[:12]
		}
		states = append(states, state)
	}
	sort.Slice(states, func(i, j int) bool { return states[i].Name < states[j].Name })
	return states, nil
}

// restartWindowsStandaloneGateway restarts the gateway service when it is
// running so it reads the changed credential; a stopped gateway reads it on
// its next start.
func restartWindowsStandaloneGateway() (bool, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return false, nil
		}
		return false, err
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return false, err
	}
	if status.State != svc.Running {
		return false, nil
	}
	if _, err := service.Control(svc.Stop); err != nil {
		return false, fmt.Errorf("stop %s: %w", managed.StandaloneWindowsGatewaySvc, err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		status, err = service.Query()
		if err != nil {
			return false, err
		}
		if status.State == svc.Stopped {
			break
		}
		if time.Now().After(deadline) {
			return false, fmt.Errorf("%s did not stop within 60s", managed.StandaloneWindowsGatewaySvc)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err := service.Start(); err != nil {
		return false, fmt.Errorf("start %s: %w", managed.StandaloneWindowsGatewaySvc, err)
	}
	return true, nil
}

// windowsStandaloneGatewayPID observes the SCM process identity around an
// installer transaction. A bundle receipt records a restart only when the
// gateway process actually changed.
func windowsStandaloneGatewayPID() uint32 {
	manager, err := mgr.Connect()
	if err != nil {
		return 0
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return 0
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil || status.State != svc.Running {
		return 0
	}
	return status.ProcessId
}

// startWindowsStandaloneGatewayIfStopped is the rollback recovery for a
// bundle restart whose stop succeeded but start failed. It never stops a
// running gateway.
func startWindowsStandaloneGatewayIfStopped() (bool, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return false, err
	}
	defer service.Close()
	deadline := time.Now().Add(60 * time.Second)
	for {
		status, err := service.Query()
		if err != nil {
			return false, err
		}
		switch status.State {
		case svc.Running, svc.StartPending:
			return false, nil
		case svc.Stopped:
			if err := service.Start(); err != nil {
				return false, err
			}
			return true, nil
		}
		if time.Now().After(deadline) {
			return false, fmt.Errorf("%s did not become restartable within 60s", managed.StandaloneWindowsGatewaySvc)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
