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
	"os/exec"
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
	"github.com/defenseclaw/defenseclaw/internal/processutil"
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
	windowsSecretIsElevated      = func() bool { return windows.GetCurrentProcessToken().IsElevated() }
	windowsSecretRestartGateway  = restartWindowsStandaloneGatewayBeforeStop
	windowsSecretSpawnRecovery   = spawnWindowsSecretGatewayRecovery
	windowsSecretStartRecovery   = processutil.StartIndependent
	windowsSecretGatewayLive     = windowsStandaloneGatewayLive
	windowsSecretRecoveryCommand = func(executable string) *exec.Cmd {
		return exec.Command(executable, "enterprise", "secret", "recover-gateway")
	}
	windowsSecretConfigTrusted             = managed.ValidateTrustedConfigPath
	windowsSecretAbsentConfigParentTrusted = func(path string) error {
		return managed.ValidateTrustedDirectoryAncestor(path, "installed config directory")
	}
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
	enterpriseSecretCmd.AddCommand(&cobra.Command{
		Use: "recover-gateway", Hidden: true, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return recoverWindowsSecretGateway(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout())
		},
	})
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
	change, err := changeWindowsSecret(cmd, action, opts)
	defer func() { _ = change.reservation.Release() }()
	if ev, ok := secretChangeEvent(action, opts.name, change.changed, secretFailureCode(err, windowsSecretExitInvalid), err, false); ok {
		// The success document (secret-result.schema.json) has no warnings.
		layout, layoutErr := windowsSecretLayout()
		if layoutErr == nil {
			warnChangeUnrecorded(cmd.ErrOrStderr(), recordWindowsChange(layout, change.reservation, ev))
		} else if change.changed || !change.layoutPreflightFailed {
			// A post-change or different layout failure still names the
			// missing audit event.
			warnChangeUnrecorded(cmd.ErrOrStderr(), layoutErr)
		}
		// The same unreadable layout before any change is already in the
		// JSON refusal; retrying it cannot record another refusal event.
	}
	// A run that recorded nothing (the stored value, an absent credential)
	// gives its reservation back here, durably.
	warnChangeReleaseUnflushed(cmd.ErrOrStderr(), change.reservation.Release())
	if err != nil {
		return reportWindowsSecretFailure(cmd, action, opts, err, opts.json)
	}
	if opts.json {
		// Contract v1 success shape (secret-result.schema.json, which allows
		// no other member): a no-op shows as gateway_restarted false.
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
			"schema_version": 1, "ok": true, "action": action, "name": opts.name, "gateway_restarted": change.restarted,
		})
	}
	if change.noop {
		if action == "remove" {
			fmt.Fprintf(cmd.OutOrStdout(), "credential %s was not stored; nothing to remove\n", opts.name)
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "credential %s already holds this value; gateway restart not needed\n", opts.name)
		return nil
	}
	if action == "remove" && !change.changed {
		fmt.Fprintf(cmd.OutOrStdout(), "credential %s was not stored; nothing to remove; gateway restarted: %v\n", opts.name, change.restarted)
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "credential %s %s; gateway restarted: %v\n", opts.name, windowsSecretChanged(action), change.restarted)
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

// windowsSecretChange is the outcome of a set or remove: whether the gateway
// was restarted, and whether set found the exact value already stored with
// no running gateway to restart (noop).
type windowsSecretChange struct {
	restarted bool
	noop      bool
	// changed is set when the run wrote or removed the credential.
	changed bool
	// layoutPreflightFailed means no change could begin because the first
	// layout lookup failed. Its JSON refusal already names that failure.
	layoutPreflightFailed bool
	// reservation holds room for the change event from before the change
	// until the caller writes the event (or releases it).
	reservation *enterprisestatus.ChangeReservation
}

// changeWindowsSecret stores or removes the credential and restarts the
// gateway so it reads the change. Arguments and the value are checked
// before any lock is taken; the change and the restart run under both
// locks (lockWindowsSecretChange). A set of the exact stored bytes is not
// rewritten, but a running gateway still restarts: nothing proves which
// value the running process loaded (it may have started while the file was
// unreadable, and an ACL repair or a preserved timestamp leaves no trace).
func changeWindowsSecret(cmd *cobra.Command, action string, opts *enterpriseSecretOptions) (windowsSecretChange, error) {
	if err := windowsSecretElevation(action, opts); err != nil {
		return windowsSecretChange{}, err
	}
	if err := checkWindowsLockWait(cmd, opts.lockWait); err != nil {
		return windowsSecretChange{}, err
	}
	layout, err := windowsSecretLayout()
	if err != nil {
		return windowsSecretChange{layoutPreflightFailed: true}, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure, err)
	}
	if !managed.ValidCredentialName(opts.name) {
		return windowsSecretChange{}, secretFailed("invalid_arguments", windowsSecretExitInvalid, fmt.Errorf("--name %q must be lowercase letters, digits and dashes", opts.name))
	}
	if err := secretTransactionArguments(opts); err != nil {
		return windowsSecretChange{}, secretFailed("invalid_arguments", windowsSecretExitInvalid, err)
	}
	if err := requireWindowsSecretDeployment(); err != nil {
		return windowsSecretChange{}, err
	}
	var value []byte
	switch action {
	case "set":
		if opts.fromStdin == (opts.fromFile != "") {
			return windowsSecretChange{}, secretFailed("invalid_arguments", windowsSecretExitInvalid, errors.New("pass exactly one of --from-stdin or --from-file"))
		}
		var source io.Reader = cmd.InOrStdin()
		if opts.fromFile != "" {
			if err := managed.ValidateTrustedFilePath(opts.fromFile, "credential source"); err != nil {
				return windowsSecretChange{}, secretFailed("invalid_arguments", windowsSecretExitInvalid, err)
			}
			file, err := os.Open(opts.fromFile)
			if err != nil {
				return windowsSecretChange{}, secretFailed("change_failed", windowsSecretExitFailure, err)
			}
			defer file.Close()
			source = file
		}
		if value, err = readWindowsSecretValue(source); err != nil {
			return windowsSecretChange{}, secretFailed("invalid_arguments", windowsSecretExitInvalid, err)
		}
	case "remove":
	default:
		return windowsSecretChange{}, secretFailed("invalid_arguments", windowsSecretExitInvalid, fmt.Errorf("unknown action %q", action))
	}
	release, err := lockWindowsSecretChange(cmd.Context(), layout, opts.lockWait)
	if err != nil {
		return windowsSecretChange{}, err
	}
	defer release()
	// An uninstall holds lifecycle.lock, so one can finish while this run
	// waits for it; check again under both locks before anything is written.
	if err := requireWindowsSecretDeployment(); err != nil {
		return windowsSecretChange{}, err
	}
	if opts.undoRotation != "" {
		// The wrapper writes its journal before secret set. If that set
		// never wrote its value, the old value (or absence) is already
		// restored. Check through the pinned store under both locks; no
		// credential write is needed. A live gateway may still hold the
		// rotated value, so reload it before retiring the journal.
		prior, err := openWindowsSecretStore(layout.SecretsDir, false)
		if err != nil {
			return windowsSecretChange{}, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure, err)
		}
		entry, stored, readErr := prior.openCredential(opts.name)
		if readErr == nil {
			_ = windows.CloseHandle(entry)
		}
		prior.close()
		if (action == "set" && readErr == nil && bytes.Equal(bytes.TrimSpace(stored), value)) ||
			(action == "remove" && windowsSecretAbsentRead(readErr)) {
			return reloadAlreadyRestoredWindowsSecret(opts.name)
		}
	}
	var installedConfig []byte
	var inUse error
	if action == "remove" {
		installedConfig, err = readWindowsSecretInstalledConfig(layout, opts.undoRotation != "" && opts.undoConfig == "none")
		if err != nil {
			return windowsSecretChange{}, err
		}
		// A put-back (--undo-rotation) removes what a failed rotation added
		// to the config installed before it, which may reference the
		// credential with no value stored: only while that same config is
		// installed (--undo-config, read under the lifecycle lock), and
		// checkSecretTransaction decides the rest. A config installed since
		// may use the stored value, so it keeps it.
		if at := config.InstalledCredentialReference(layout.ConfigPath, installedConfig, layout.DataDir, opts.name); at != "" && !undoRotationOnConfig(opts, installedConfig) {
			err := fmt.Errorf("the installed config still references credential %s at %s; remove that reference and apply the config first", opts.name, at)
			if opts.undoRotation != "" {
				err = fmt.Errorf("the installed config references credential %s at %s and is not the config installed before the rotation (--undo-config), so it may use the value stored now; credential %s was not removed", opts.name, at, opts.name)
			}
			inUse = secretFailed("credential_in_use", windowsSecretExitFailure, err)
			// A put-back first learns whether its rotation committed
			// (rotation_confirmed, below), the only refusal that retires
			// the wrapper's entry; neither refusal changes anything.
			if opts.undoRotation == "" {
				return windowsSecretChange{}, inUse
			}
		}
	}
	// Start an independent child before changing credentials, but only arm it
	// at a live gateway's restart decision. Closing its pipe on a refusal or
	// no-op cannot start a gateway that the administrator left stopped. A
	// gateway that is stopped or not installed needs no restart, so no child.
	recovery, err := prepareWindowsSecretRecovery()
	if err != nil {
		return windowsSecretChange{}, secretFailed("change_failed", windowsSecretExitFailure,
			fmt.Errorf("cannot arm gateway restart recovery; nothing was changed: %w", err))
	}
	recoverOnExit := false
	defer func() { _ = recovery.finish(recoverOnExit) }()
	// Pin the store before anything in it is read, written or deleted: a
	// junction, mount point, symlink or file where the folder belongs is
	// state_invalid. Remove deleted the credential a junction target held
	// and reported success (GAP-1315); set reported change_failed (GAP-1314).
	store, err := openWindowsSecretStore(layout.SecretsDir, action == "set")
	if err != nil {
		return windowsSecretChange{}, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure, err)
	}
	defer store.close()
	if opts.ifConfirmed != "" || opts.undoRotation != "" || opts.ifStored != "" {
		var stored []byte
		entry, raw, readErr := store.openCredential(opts.name)
		if readErr == nil {
			_ = windows.CloseHandle(entry)
			stored = raw
		}
		if opts.ifStored == "none" && readErr != nil && !windowsSecretAbsentRead(readErr) {
			return windowsSecretChange{}, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure, readErr)
		}
		if err := checkSecretTransaction(opts.name, opts, stored, readErr == nil); err != nil {
			return windowsSecretChange{}, secretFailed(secretBindingCode(err), windowsSecretExitFailure, err)
		}
	}
	if inUse != nil {
		return windowsSecretChange{}, inUse
	}
	// A change this computer could not audit is not made: the spool must
	// hold room for its change event before the credential is written or
	// removed, until the event is written. A concurrent command cannot take
	// that room in between.
	reservation, err := reserveWindowsChange(layout, enterprisestatus.ChangeKindSecret, action, opts.name)
	if err != nil {
		return windowsSecretChange{}, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure,
			fmt.Errorf("cannot record the credential change: %w", err))
	}
	change := windowsSecretChange{reservation: reservation}
	unchanged := false
	if action == "set" {
		unchanged = keepIdenticalWindowsSecret(store, opts.name, value)
		if !unchanged {
			// A value the signed bundle does not bind is not stored.
			if err := checkSecretBinding(cmd.Context(), opts.name, value, opts.bundle, windowsSecretStored(layout.SecretsDir, opts.name)); err != nil {
				return change, secretFailed(secretBindingCode(err), windowsSecretExitFailure, err)
			}
			if err := writeWindowsSecret(store, opts.name, value); err != nil {
				return change, secretFailed("change_failed", windowsSecretExitFailure, err)
			}
		}
	} else {
		unchanged = !windowsSecretStored(layout.SecretsDir, opts.name)
		if err := removeWindowsSecret(store, opts.name); err != nil {
			return change, err
		}
	}
	store.close()
	// The gateway reads credentials when it starts; apply the change now. An
	// identical value or an absent credential needs no restart once the
	// running gateway started after that credential last changed: it loaded
	// exactly what is stored (GAP-0712, GAP-1690).
	restarted := false
	if !unchanged || !windowsSecretGatewayStartedAfter(windowsSecretLastChange(layout, opts.name, action)) {
		restarted, err = windowsSecretRestartGateway(recovery.arm)
	}
	if err != nil {
		// A refused SCM stop did not stop this service. A concurrent
		// administrator stop is not this command's restart to recover.
		recoverOnExit = !errors.Is(err, errWindowsGatewayStopRefused)
		done := windowsSecretChanged(action)
		if unchanged {
			done = "was already stored"
		}
		return change, secretFailed("restart_failed", windowsSecretExitFailure,
			fmt.Errorf("credential %s %s, but restarting the gateway failed: %w", opts.name, done, err))
	}
	if err := recovery.finish(false); err != nil {
		return change, secretFailed("restart_failed", windowsSecretExitFailure,
			fmt.Errorf("credential %s changed, but cancelling gateway restart recovery failed: %w", opts.name, err))
	}
	change.restarted, change.noop, change.changed = restarted, unchanged && !restarted, !unchanged
	return change, nil
}

// windowsSecretLastChange is when credential name last changed in the
// store: its file's last write for a stored value, the store folder's for an
// absent one (a removal writes the folder), and the folder that holds the
// store when no store folder exists (nothing was ever stored, or removing
// the store folder wrote its parent): every remove of an absent credential
// on a computer with no credentials restarted the gateway (GAP-1690). The
// zero time when unknown.
func windowsSecretLastChange(layout managed.StandaloneLayout, name, action string) time.Time {
	path := layout.SecretsDir
	if action == "set" {
		path = filepath.Join(layout.SecretsDir, name)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && action != "set" {
		info, err = os.Lstat(filepath.Dir(filepath.Clean(layout.SecretsDir)))
	}
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// windowsSecretGatewayStartedAfter reports whether the running gateway
// process was created after changedAt; false when that cannot be shown. A
// seam for tests.
var windowsSecretGatewayStartedAfter = func(changedAt time.Time) bool {
	if changedAt.IsZero() {
		return false
	}
	pid := windowsStandaloneGatewayPID()
	if pid == 0 {
		return false
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(process) }()
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(process, &created, &exited, &kernel, &user); err != nil {
		return false
	}
	return time.Unix(0, created.Nanoseconds()).After(changedAt)
}

func windowsSecretAbsentRead(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND)
}

// An interrupted rotation can find its before-value already on disk while a
// live gateway still uses the delivered value. Settle the journal only after
// the gateway has loaded that before-state. A refused restart leaves it for
// the next ensure, and the recovery child covers a stop that already began.
func reloadAlreadyRestoredWindowsSecret(name string) (windowsSecretChange, error) {
	recovery, err := prepareWindowsSecretRecovery()
	if err != nil {
		return windowsSecretChange{}, secretFailed("restart_failed", windowsSecretExitFailure,
			fmt.Errorf("cannot prepare gateway reload for already-restored credential %s: %w", name, err))
	}
	recoverOnExit := false
	defer func() { _ = recovery.finish(recoverOnExit) }()
	restarted, err := windowsSecretRestartGateway(recovery.arm)
	if err != nil {
		recoverOnExit = !errors.Is(err, errWindowsGatewayStopRefused)
		return windowsSecretChange{}, secretFailed("restart_failed", windowsSecretExitFailure,
			fmt.Errorf("credential %s is restored on disk, but restarting the gateway failed: %w", name, err))
	}
	if err := recovery.finish(false); err != nil {
		return windowsSecretChange{}, secretFailed("restart_failed", windowsSecretExitFailure,
			fmt.Errorf("credential %s is restored on disk, but cancelling gateway restart recovery failed: %w", name, err))
	}
	return windowsSecretChange{restarted: restarted, noop: !restarted}, nil
}

// keepIdenticalWindowsSecret reports whether credential name already holds
// exactly value and still grants the gateway its read, so set need not
// rewrite it. The gateway reader normalizes whitespace, so the value it
// accepts and the exact stored bytes must both match. The raw bytes are read
// only after that trusted, size-limited read succeeded, from the pinned
// store through a handle that follows no reparse point (openCredential). An
// ACL edit leaves the bytes alone but can drop the gateway's read ACEs, which
// the administrator's own read does not notice, so the directory and file
// descriptors are applied again, the file's through the open handle. Any
// failure rewrites the credential instead.
func keepIdenticalWindowsSecret(store *windowsSecretStore, name string, value []byte) bool {
	stored, _, err := managed.ResolveServiceCredentialAs(name, store.dir, windowsSecretGatewayAccount)
	if err != nil || !bytes.Equal(stored, value) {
		return false
	}
	gateway, err := managed.WindowsServiceAccountSID(windowsSecretGatewayAccount)
	if err != nil || gateway == nil {
		return false
	}
	entry, raw, err := store.openCredential(name)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(entry) }()
	if !bytes.Equal(raw, value) || ensureWindowsSecretsDir(store, gateway) != nil {
		return false
	}
	return applyWindowsSDDLToHandle(entry, windowsSecretFileSDDL(gateway)) == nil
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

// readWindowsSecretInstalledConfig proves the active config can be inspected
// before remove changes the credential. A missing, unreadable, or malformed
// config cannot prove that the key is unused (GAP-0674, GAP-1507).
func readWindowsSecretInstalledConfig(layout managed.StandaloneLayout, allowAbsent bool) ([]byte, error) {
	if strings.TrimSpace(layout.ConfigPath) == "" {
		return nil, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure,
			errors.New("cannot locate the installed config; nothing was removed"))
	}
	if allowAbsent {
		// Only an absent-credential undo that journaled no config may treat
		// ENOENT as an empty reference roster. The stored-value comparison
		// still runs under the same locks before removal. Ordinary remove and
		// a journal from a prior config keep the state_invalid refusal.
		if _, err := os.Lstat(layout.ConfigPath); errors.Is(err, os.ErrNotExist) {
			if err := windowsSecretAbsentConfigParentTrusted(filepath.Dir(layout.ConfigPath)); err != nil {
				return nil, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure,
					fmt.Errorf("cannot trust the directory of the absent installed config %s (%v); nothing was removed", layout.ConfigPath, err))
			}
			return nil, nil
		} else if err != nil {
			return nil, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure,
				fmt.Errorf("cannot inspect the installed config %s (%v); nothing was removed", layout.ConfigPath, err))
		}
	}
	if err := windowsSecretConfigTrusted(layout.ConfigPath); err != nil {
		return nil, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure,
			fmt.Errorf("cannot trust the installed config %s (%v); nothing was removed", layout.ConfigPath, err))
	}
	raw, err := readWindowsSecretConfigAsCaller(layout.ConfigPath)
	if err != nil {
		return nil, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure,
			fmt.Errorf("cannot read the installed config %s (%v); nothing was removed: restore read access to the config and run it again", layout.ConfigPath, err))
	}
	// The gateway reads the config as its service account when it starts
	// again after the change: a config that account cannot read would leave
	// it stopped with the credential gone (GAP-0750).
	if err := managed.ValidateServiceCanReadTree(layout.ConfigPath, "installed config", layout.ServiceUser); err != nil && !managed.IsServiceAccountUnresolved(err) {
		return nil, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure,
			fmt.Errorf("the gateway could not start on the installed config after this change (%v); nothing was removed", err))
	}
	if _, err := config.LoadRuntimeV8InspectionCandidateFromBytes(layout.ConfigPath, raw); err != nil {
		return nil, secretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure,
			fmt.Errorf("cannot load the installed config %s (%v); nothing was removed", layout.ConfigPath, err))
	}
	return raw, nil
}

// readWindowsSecretConfigAsCaller reads the installed config with the
// caller's own access check. os.ReadFile opens with backup semantics, so an
// elevated caller whose token had SeBackupPrivilege enabled read a config
// whose DACL denies Administrators, removed the credential, and the gateway
// then failed to start (GAP-0750, TST-30694).
func readWindowsSecretConfigAsCaller(path string) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, windowsEnterpriseHotConfigMaxBytes+1))
}

func removeWindowsSecret(store *windowsSecretStore, name string) error {
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
	entry, err := s.openEntry(name, windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
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

// openEntry opens entry name of the pinned folder relative to the folder
// handle, following no reparse point (OBJ_DONT_REPARSE,
// FILE_OPEN_REPARSE_POINT): a link named like the credential is opened
// itself, never its target.
func (s *windowsSecretStore) openEntry(name string, access, share uint32) (windows.Handle, error) {
	if !managed.ValidCredentialName(name) {
		return 0, fmt.Errorf("credential name %q is not valid", name)
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: s.handle,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	var entry windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&entry, access, &attributes, &status, nil, 0, share, windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	return entry, err
}

// openCredential opens credential name in the pinned folder (openEntry) to
// read it and to repair its descriptor, and reads at most
// managed.ServiceCredentialLimit bytes. A link, a folder or a larger file is
// refused before anything is read. Writers are shut out while the handle is
// open; the caller closes it.
func (s *windowsSecretStore) openCredential(name string) (windows.Handle, []byte, error) {
	if !s.exists() {
		return 0, nil, fmt.Errorf("%s: %w", s.dir, os.ErrNotExist)
	}
	entry, err := s.openEntry(name, windows.FILE_READ_DATA|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|
		windows.WRITE_DAC|windows.WRITE_OWNER|windows.SYNCHRONIZE, windows.FILE_SHARE_READ)
	if err != nil {
		return 0, nil, fmt.Errorf("open credential %s in %s: %w", name, s.dir, err)
	}
	data, err := readWindowsSecretEntry(entry)
	if err != nil {
		_ = windows.CloseHandle(entry)
		return 0, nil, fmt.Errorf("credential %s in %s: %w", name, s.dir, err)
	}
	return entry, data, nil
}

func readWindowsSecretEntry(entry windows.Handle) ([]byte, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(entry, &info); err != nil {
		return nil, fmt.Errorf("inspect: %w", err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return nil, errors.New("is a link or a folder, not a credential file")
	}
	if info.FileSizeHigh != 0 || info.FileSizeLow > managed.ServiceCredentialLimit {
		return nil, fmt.Errorf("exceeds %d bytes", managed.ServiceCredentialLimit)
	}
	data := make([]byte, managed.ServiceCredentialLimit+1)
	total := 0
	for total < len(data) {
		var n uint32
		err := windows.ReadFile(entry, data[total:], &n, nil)
		if err != nil && !errors.Is(err, windows.ERROR_HANDLE_EOF) {
			return nil, fmt.Errorf("read: %w", err)
		}
		if n == 0 {
			break
		}
		total += int(n)
	}
	if total > managed.ServiceCredentialLimit {
		return nil, fmt.Errorf("exceeds %d bytes", managed.ServiceCredentialLimit)
	}
	return data[:total], nil
}

// windowsSecretStored reports whether credential name is in the store at
// // dir. A store that is not a real directory holds none: the gateway reader
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
	// GAP-2430: keep the stored credential under a second name until the
	// new value passes the gateway trust check below. A failed check put the
	// new file away and the previous credential went with it, while the
	// result said change_failed. The extra name is a hard link: the same
	// file, bytes and protected DACL, so putting it back changes nothing.
	kept, keepErr := keepWindowsSecret(store, name)
	dropKept := kept != ""
	defer func() {
		if dropKept {
			_ = os.Remove(kept)
		}
	}()
	final, err := storeWindowsSecret(store, name, value, gateway)
	if err != nil {
		return err
	}
	verifyErr := windowsSecretTrustCheck(name, store.dir)
	if verifyErr == nil {
		return nil
	}
	if kept != "" {
		if err := restoreWindowsSecret(kept, final); err != nil {
			// Never drop the only copy of the previous value: leave it
			// under its kept name and say how to put it back.
			dropKept = false
			return fmt.Errorf("the new credential failed the gateway trust check, and the previous credential could not be put back (%v); it is kept as %s: rename it to %s, or run secret set again: %w", err, kept, name, verifyErr)
		}
		return fmt.Errorf("the new credential failed the gateway trust check; the previous credential is kept unchanged: %w", verifyErr)
	}
	_ = os.Remove(final)
	if keepErr != nil {
		return fmt.Errorf("the new credential failed the gateway trust check and was removed; the previous credential could not be kept (%v): %w", keepErr, verifyErr)
	}
	return fmt.Errorf("the new credential failed the gateway trust check and was removed: %w", verifyErr)
}

// keepWindowsSecret gives the stored credential name a second, hidden name
// in the pinned store (a hard link), so writeWindowsSecret can put it back.
// "" and no error when nothing is stored.
func keepWindowsSecret(store *windowsSecretStore, name string) (string, error) {
	final := filepath.Join(store.dir, name)
	info, err := os.Lstat(final)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", final)
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	kept := filepath.Join(store.dir, "."+name+".kept-"+hex.EncodeToString(suffix))
	if err := os.Link(final, kept); err != nil {
		return "", err
	}
	return kept, nil
}

// restoreWindowsSecret puts the kept previous credential back over final.
// Another process that holds final open (an EDR or backup agent reading it,
// a concurrent re-ACL) makes the replace fail with access denied for a
// moment, so it retries for about two seconds before it gives up.
func restoreWindowsSecret(kept, final string) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if err = os.Rename(kept, final); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

// windowsSecretTrustCheck proves the gateway reader accepts the stored
// credential. It runs with the administrator token, so it checks the path,
// owner and ACL shape; the gateway rights come from the reader ACEs
// (pinned by TestWindowsSecretStoreUsesTheGatewayReaderDACL). A seam for
// tests.
var windowsSecretTrustCheck = func(name, dir string) error {
	previous, had := os.LookupEnv(managed.WindowsServiceAccountEnv)
	_ = os.Setenv(managed.WindowsServiceAccountEnv, windowsSecretGatewayAccount)
	_, _, err := managed.ResolveServiceCredential(name, dir)
	if had {
		_ = os.Setenv(managed.WindowsServiceAccountEnv, previous)
	} else {
		_ = os.Unsetenv(managed.WindowsServiceAccountEnv)
	}
	return err
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

// windowsSDDLOwnerAndDACL is the owner and the protected DACL that
// applyWindowsSDDL and applyWindowsSDDLToHandle set.
func windowsSDDLOwnerAndDACL(sddl string) (*windows.SID, *windows.ACL, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, nil, fmt.Errorf("build security descriptor: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, nil, err
	}
	return owner, dacl, nil
}

const windowsSDDLApplied = windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION

func applyWindowsSDDL(path, sddl string) error {
	owner, dacl, err := windowsSDDLOwnerAndDACL(sddl)
	if err != nil {
		return err
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windowsSDDLApplied, owner, nil, dacl, nil)
}

// applyWindowsSDDLToHandle is applyWindowsSDDL for an open handle (opened
// with WRITE_DAC and WRITE_OWNER), so no path is resolved again.
func applyWindowsSDDLToHandle(handle windows.Handle, sddl string) error {
	owner, dacl, err := windowsSDDLOwnerAndDACL(sddl)
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windowsSDDLApplied, owner, nil, dacl, nil)
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

// restartWindowsStandaloneGateway restarts the gateway service so a new
// process reads the changed credential or config; a stopped gateway reads it
// on its next start (restartWindowsGatewayService). A gateway in StartPending
// is a process that may already hold the old value: it is restarted once it
// runs, not taken for stopped.
func restartWindowsStandaloneGateway() (bool, error) {
	return restartWindowsStandaloneGatewayBeforeStop(nil)
}

func restartWindowsStandaloneGatewayBeforeStop(beforeStop func() error) (bool, error) {
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
	return restartWindowsGatewayServiceBeforeStop(scmGatewayService{service}, managed.StandaloneWindowsGatewaySvc, 60*time.Second, 250*time.Millisecond, beforeStop)
}

type windowsSecretRecoveryControl interface {
	arm() error
	finish(recoverGateway bool) error
}

type windowsSecretRecoveryChild struct {
	child  *exec.Cmd
	input  io.WriteCloser
	armed  bool
	closed bool
}

// deferredWindowsSecretRecovery is the recovery a credential change holds.
// changeWindowsSecret starts its child before the change when the gateway
// runs (prepareWindowsSecretRecovery). With the gateway stopped or not
// installed no restart is due and no child runs; one that started after that
// check gets its child at the restart decision, before its stop, and a child
// that cannot start there leaves the gateway running and the restart failed.
type deferredWindowsSecretRecovery struct {
	spawn func() (windowsSecretRecoveryControl, error)
	child windowsSecretRecoveryControl
}

func (r *deferredWindowsSecretRecovery) arm() error {
	if r.child == nil {
		child, err := r.spawn()
		if err != nil {
			return err
		}
		r.child = child
	}
	return r.child.arm()
}

func (r *deferredWindowsSecretRecovery) finish(recoverGateway bool) error {
	if r.child == nil {
		return nil
	}
	return r.child.finish(recoverGateway)
}

// prepareWindowsSecretRecovery starts the recovery child up front unless the
// service manager reports the gateway stopped or not installed. A state it
// cannot read counts as running.
func prepareWindowsSecretRecovery() (windowsSecretRecoveryControl, error) {
	recovery := &deferredWindowsSecretRecovery{spawn: windowsSecretSpawnRecovery}
	if live, err := windowsSecretGatewayLive(); err == nil && !live {
		return recovery, nil
	}
	child, err := recovery.spawn()
	if err != nil {
		return nil, err
	}
	recovery.child = child
	return recovery, nil
}

// windowsStandaloneGatewayLive reports whether the gateway service runs or
// is changing state: false only for a stopped or absent service.
func windowsStandaloneGatewayLive() (bool, error) {
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
	return windowsServiceState(status.State) != windowsServiceStopped, nil
}

func (r *windowsSecretRecoveryChild) arm() error {
	if r.closed || r.armed {
		return errors.New("gateway restart recovery is not ready to arm")
	}
	if _, err := io.WriteString(r.input, "ARM\n"); err != nil {
		return err
	}
	r.armed = true
	return nil
}

func (r *windowsSecretRecoveryChild) finish(recoverGateway bool) error {
	if r.closed {
		return nil
	}
	r.closed = true
	if r.armed && !recoverGateway {
		// The child waits for the locks before reading this cancellation, so
		// it cannot start a gateway after the completed command releases them.
		if _, err := io.WriteString(r.input, "CANCEL\n"); err != nil {
			_ = r.child.Process.Kill()
			_ = r.input.Close()
			_ = r.child.Wait()
			return fmt.Errorf("cancel gateway recovery child: %w", err)
		}
	}
	closeErr := r.input.Close()
	releaseErr := r.child.Process.Release()
	return errors.Join(closeErr, releaseErr)
}

// spawnWindowsSecretGatewayRecovery starts a detached child before the
// credential write. The child has no credential value or writable state and
// cannot start a service until the parent explicitly arms its restart. It
// must outlive this command's process job (processutil.StartIndependent),
// including the unreadable job of a LocalSystem scheduled task.
func spawnWindowsSecretGatewayRecovery() (windowsSecretRecoveryControl, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	child := windowsSecretRecoveryCommand(executable)
	child.Dir = filepath.Dir(executable)
	child.Stderr = io.Discard
	input, err := child.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("create gateway recovery control pipe: %w", err)
	}
	ready, err := child.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, fmt.Errorf("create gateway recovery readiness pipe: %w", err)
	}
	if err := windowsSecretStartRecovery(child); err != nil {
		_ = input.Close()
		_ = ready.Close()
		return nil, fmt.Errorf("start gateway recovery: %w", err)
	}
	result := make(chan error, 1)
	go func() {
		marker := make([]byte, len("READY\n"))
		_, readErr := io.ReadFull(ready, marker)
		if readErr == nil && string(marker) != "READY\n" {
			readErr = errors.New("gateway recovery sent an invalid readiness marker")
		}
		result <- readErr
	}()
	select {
	case err = <-result:
	case <-time.After(30 * time.Second):
		err = errors.New("gateway recovery did not become ready within 30 seconds")
	}
	if err != nil {
		_ = child.Process.Kill()
		_ = input.Close()
		_ = ready.Close()
		_ = child.Wait()
		return nil, fmt.Errorf("gateway recovery was not ready: %w", err)
	}
	_ = ready.Close()
	return &windowsSecretRecoveryChild{child: child, input: input}, nil
}

func recoverWindowsSecretGateway(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	if err := windowsSecretElevation("recover-gateway", nil); err != nil {
		return err
	}
	return runWindowsSecretRecoveryProtocol(stdin, stdout, func() (func(), error) {
		layout, err := windowsSecretLayout()
		if err != nil {
			return nil, err
		}
		return lockWindowsSecretChange(ctx, layout, 10*time.Minute)
	}, func() error {
		if err := requireWindowsSecretDeployment(); err != nil {
			return err
		}
		manager, err := mgr.Connect()
		if err != nil {
			return err
		}
		defer manager.Disconnect()
		service, err := manager.OpenService(managed.StandaloneWindowsGatewaySvc)
		if err != nil {
			return err
		}
		defer service.Close()
		_, err = startWindowsGatewayServiceIfStopped(scmGatewayService{service}, managed.StandaloneWindowsGatewaySvc, 60*time.Second, 250*time.Millisecond)
		return err
	})
}

// scmGatewayService drives the installed gateway service through the SCM.
type scmGatewayService struct{ service *mgr.Service }

func (s scmGatewayService) state() (windowsServiceState, error) {
	status, err := s.service.Query()
	return windowsServiceState(status.State), err
}

func (s scmGatewayService) stop() error {
	_, err := s.service.Control(svc.Stop)
	return err
}

func (s scmGatewayService) start() error { return s.service.Start() }

// stopWindowsStandaloneGatewayFailClosed stops the gateway service after a
// hot config undo that could not be proven, and returns nil only once the
// service manager reports it stopped (or there is no gateway service). The
// hooks then treat it as an outage. Nothing starts it again but a lifecycle
// run: the hook guardian never starts the gateway, and the service manager
// restarts it only after a crash.
func stopWindowsStandaloneGatewayFailClosed() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return err
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped && status.State != svc.StopPending {
		if _, err := service.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return fmt.Errorf("stop %s: %w", managed.StandaloneWindowsGatewaySvc, err)
		}
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		status, err = service.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%s did not stop within 60s", managed.StandaloneWindowsGatewaySvc)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// windowsStandaloneGatewayPID observes the SCM process identity around an
// installer transaction. A bundle receipt records a restart only when the
// gateway process actually changed. A starting gateway has a process
// (windowsServiceProcessLive), so it counts as running.
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
	if err != nil || !windowsServiceProcessLive(windowsServiceState(status.State)) {
		return 0
	}
	return status.ProcessId
}

// startWindowsStandaloneGatewayIfStopped is the rollback recovery for a
// bundle restart whose stop succeeded but start failed. It never stops a
// running gateway, and reports a start only once the gateway runs
// (startWindowsGatewayServiceIfStopped).
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
	return startWindowsGatewayServiceIfStopped(scmGatewayService{service}, managed.StandaloneWindowsGatewaySvc, 60*time.Second, 250*time.Millisecond)
}
