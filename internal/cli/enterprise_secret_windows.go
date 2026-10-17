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
	"strconv"
	"strings"
	"time"

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
	// windowsSecretRawArgs is the command line a flag error is read from:
	// cobra stops parsing at the bad flag, so a later --json is not in opts.
	windowsSecretRawArgs = func() []string { return os.Args[1:] }
)

func init() {
	enterpriseSecretArgumentRefusal = func(cmd *cobra.Command, action string, opts *enterpriseSecretOptions, err error) error {
		if action == "status" {
			return err
		}
		return reportWindowsSecretFailure(cmd, action, opts, err, opts.json || windowsArgsRequestJSON(windowsSecretRawArgs()))
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

// windowsSecretFailureResult is what `secret set|remove --json` prints when
// it fails: the Windows failure branch of secret-result.schema.json. The
// value never appears in it.
type windowsSecretFailureResult struct {
	SchemaVersion    int                        `json:"schema_version"`
	OK               bool                       `json:"ok"`
	Action           string                     `json:"action"`
	Name             string                     `json:"name,omitempty"`
	GatewayRestarted bool                       `json:"gateway_restarted"`
	Errors           []enterprisestatus.Message `json:"errors"`
	ExitCode         int                        `json:"exit_code"`
}

// windowsSecretRefusal names the errors[].code of a set or remove failure.
type windowsSecretRefusal struct {
	code string
	err  error
}

func (r *windowsSecretRefusal) Error() string { return r.err.Error() }
func (r *windowsSecretRefusal) Unwrap() error { return r.err }

func windowsSecretFailed(code string, exit int, err error) error {
	return withExitCode(&windowsSecretRefusal{code: code, err: err}, exit)
}

// reportWindowsSecretFailure prints the failure document of err when asJSON
// and returns err, labelled 1603 when nothing chose an exit code.
func reportWindowsSecretFailure(cmd *cobra.Command, action string, opts *enterpriseSecretOptions, err error, asJSON bool) error {
	err = withExitCode(err, windowsSecretExitFailure)
	if !asJSON {
		return err
	}
	exit := commandExitCode(err)
	code := ""
	var refusal *windowsSecretRefusal
	var view *managedViewRefusal
	switch {
	case errors.As(err, &refusal):
		code = refusal.code
	case errors.As(err, &view):
		code = view.code
	case exit == windowsSecretExitInvalid:
		code = "invalid_arguments"
	default:
		code = string(enterprisebundle.CodeStateInvalid)
	}
	result := windowsSecretFailureResult{SchemaVersion: 1, Action: action, Name: opts.name,
		Errors: []enterprisestatus.Message{{Code: code, Message: err.Error()}}, ExitCode: exit}
	if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(result); encodeErr != nil {
		return encodeErr
	}
	silenceJSONReportedError(cmd, true, err)
	return err
}

// windowsArgsRequestJSON reports whether a command line passes --json
// before any "--".
func windowsArgsRequestJSON(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "--json" {
			return true
		}
		if value, ok := strings.CutPrefix(arg, "--json="); ok {
			on, err := strconv.ParseBool(value)
			return err == nil && on
		}
	}
	return false
}

// runEnterpriseSecret implements `enterprise secret` on Windows.
func runEnterpriseSecret(cmd *cobra.Command, action string, opts *enterpriseSecretOptions) error {
	if action == "status" {
		return runWindowsSecretStatus(cmd, opts)
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
	return windowsSecretFailed("elevation_required", windowsSecretExitFailure, errors.New("run this command from an elevated Administrator prompt or the MDM agent"))
}

func runWindowsSecretStatus(cmd *cobra.Command, opts *enterpriseSecretOptions) error {
	if err := windowsSecretElevation("status", opts); err != nil {
		return err
	}
	layout, err := windowsSecretLayout()
	if err != nil {
		return withExitCode(err, windowsSecretExitFailure)
	}
	states, err := windowsSecretStatus(layout.SecretsDir)
	if err != nil {
		return withExitCode(err, windowsSecretExitFailure)
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
		return false, windowsSecretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure, err)
	}
	if !managed.ValidCredentialName(opts.name) {
		return false, windowsSecretFailed("invalid_arguments", windowsSecretExitInvalid, fmt.Errorf("--name %q must be lowercase letters, digits and dashes", opts.name))
	}
	if err := requireWindowsSecretDeployment(); err != nil {
		return false, err
	}
	var value []byte
	switch action {
	case "set":
		if opts.fromStdin == (opts.fromFile != "") {
			return false, windowsSecretFailed("invalid_arguments", windowsSecretExitInvalid, errors.New("pass exactly one of --from-stdin or --from-file"))
		}
		var source io.Reader = cmd.InOrStdin()
		if opts.fromFile != "" {
			if err := managed.ValidateTrustedFilePath(opts.fromFile, "credential source"); err != nil {
				return false, windowsSecretFailed("invalid_arguments", windowsSecretExitInvalid, err)
			}
			file, err := os.Open(opts.fromFile)
			if err != nil {
				return false, windowsSecretFailed("change_failed", windowsSecretExitFailure, err)
			}
			defer file.Close()
			source = file
		}
		if value, err = readWindowsSecretValue(source); err != nil {
			return false, windowsSecretFailed("invalid_arguments", windowsSecretExitInvalid, err)
		}
	case "remove":
	default:
		return false, windowsSecretFailed("invalid_arguments", windowsSecretExitInvalid, fmt.Errorf("unknown action %q", action))
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
	if action == "set" {
		if err := writeWindowsSecret(layout.SecretsDir, opts.name, value); err != nil {
			return false, windowsSecretFailed("change_failed", windowsSecretExitFailure, err)
		}
	} else if err := removeWindowsSecret(layout, opts.name); err != nil {
		return false, err
	}
	// The gateway reads credentials when it starts; apply the change now.
	restarted, err := windowsSecretRestartGateway()
	if err != nil {
		return false, windowsSecretFailed("restart_failed", windowsSecretExitFailure,
			fmt.Errorf("credential %s %s, but restarting the gateway failed: %w", opts.name, windowsSecretChanged(action), err))
	}
	return restarted, nil
}

// requireWindowsSecretDeployment refuses not_installed (1603) unless a
// standalone managed deployment is installed.
func requireWindowsSecretDeployment() error {
	installed, err := windowsSecretDeploymentInstalled()
	if err != nil {
		return windowsSecretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure, err)
	}
	if !installed {
		return windowsSecretFailed("not_installed", windowsSecretExitFailure, errors.New("no standalone managed deployment is installed; run `enterprise windows ensure --profile standalone` first"))
	}
	return nil
}

// removeWindowsSecret deletes the credential unless the installed config
// still references it. The restart that follows would start the gateway on a
// config it cannot compile without this credential, or run the judge without
// its key (GAP-0674). A config that exists but cannot be read may still
// reference it, so nothing is removed (GAP-1507).
func removeWindowsSecret(layout managed.StandaloneLayout, name string) error {
	if strings.TrimSpace(layout.ConfigPath) != "" {
		raw, err := os.ReadFile(layout.ConfigPath)
		switch {
		case err == nil:
			if at := config.InstalledCredentialReference(layout.ConfigPath, raw, layout.DataDir, name); at != "" {
				return windowsSecretFailed("credential_in_use", windowsSecretExitFailure,
					fmt.Errorf("the installed config still references credential %s at %s; remove that reference and apply the config first", name, at))
			}
		case !errors.Is(err, os.ErrNotExist):
			return windowsSecretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure,
				fmt.Errorf("cannot read the installed config %s to check that it no longer references credential %s (%v); nothing was removed: restore read access to the config and run it again", layout.ConfigPath, name, err))
		}
	}
	if err := os.Remove(filepath.Join(layout.SecretsDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return windowsSecretFailed("change_failed", windowsSecretExitFailure, err)
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
			return nil, windowsSecretFailed("lifecycle_busy", enterprisestatus.WindowsExitBusy,
				fmt.Errorf("the credential was not changed and the run can be retried: %w", err))
		}
		return nil, windowsSecretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure,
			fmt.Errorf("cannot lock the policy bundle store; the credential was not changed: %w", err))
	}
	path, err := windowsSecretLifecycleLockPath()
	if err != nil {
		unlockBundle()
		return nil, windowsSecretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure,
			fmt.Errorf("cannot resolve the trusted enterprise roots; the credential was not changed: %w", err))
	}
	unlockLifecycle, err := acquireWindowsLockWithin(ctx, windowsSecretInstallerLockWait,
		func() (func(), error) { return windowsSecretLifecycleLock(path) }, windowsLifecycleLockBusy)
	if err != nil {
		unlockBundle()
		if windowsLifecycleLockBusy(err) {
			return nil, windowsSecretFailed("lifecycle_busy", enterprisestatus.WindowsExitBusy,
				fmt.Errorf("another DefenseClaw lifecycle run holds lifecycle.lock for more than %s; the credential was not changed and the run can be retried", formatWindowsLockWait(windowsSecretInstallerLockWait)))
		}
		return nil, windowsSecretFailed(string(enterprisebundle.CodeStateInvalid), windowsSecretExitFailure,
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

func ensureWindowsSecretsDir(dir string, reader *windows.SID) error {
	if reader == nil {
		return errors.New("the secrets directory needs the gateway service SID")
	}
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	case err != nil:
		return err
	case !info.IsDir() || info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("%s is not a real directory", dir)
	}
	// The credential write below proves the whole chain through the
	// gateway's own reader check.
	return applyWindowsSDDL(dir, windowsSecretDirectorySDDL(reader))
}

func writeWindowsSecret(dir, name string, value []byte) error {
	gateway, err := managed.WindowsServiceAccountSID(windowsSecretGatewayAccount)
	if err != nil || gateway == nil {
		return fmt.Errorf("resolve the gateway service SID (%s): %v", windowsSecretGatewayAccount, err)
	}
	final, err := storeWindowsSecret(dir, name, value, gateway)
	if err != nil {
		return err
	}
	// Prove the gateway's reader accepts the stored credential. This runs
	// with the administrator's token, so it checks the path, owner and ACL
	// shape; the gateway's own rights come from the reader ACEs above
	// (pinned by TestWindowsSecretStoreUsesTheGatewayReaderDACL).
	previous, had := os.LookupEnv(managed.WindowsServiceAccountEnv)
	_ = os.Setenv(managed.WindowsServiceAccountEnv, windowsSecretGatewayAccount)
	_, _, verifyErr := managed.ResolveServiceCredential(name, dir)
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

// storeWindowsSecret writes value to dir\name atomically with the protected
// credential DACL for reader, after (re)applying the secrets directory DACL,
// and returns the final path.
func storeWindowsSecret(dir, name string, value []byte, reader *windows.SID) (string, error) {
	if err := ensureWindowsSecretsDir(dir, reader); err != nil {
		return "", err
	}
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
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return []windowsSecretState{}, nil
	}
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
