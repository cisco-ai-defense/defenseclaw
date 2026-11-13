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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsHookImagesDACL protects bin\hooks and each launch folder as Setup
// protects bin: SYSTEM and Administrators full control, Users read and
// execute (agents start the images as their users), inherited by the
// images. Setup's access-list pass then stamps the canonical forms
// (Set-DefenseClawManagedAcls), and the guardian keeps them
// (managed.ManagedInstallLayout).
const windowsHookImagesDACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

const windowsHookImagesSDDL = "O:BAG:SY" + windowsHookImagesDACL

// windowsHookImageExecutable is the running gateway; a seam for tests.
var windowsHookImageExecutable = os.Executable

func newWindowsHookImageCommand() *cobra.Command {
	command := &cobra.Command{
		Use:    "hook-image",
		Short:  "Stage or prune the versioned managed hook images (Setup only)",
		Hidden: true,
		Args:   cobra.NoArgs,
	}
	command.AddCommand(newWindowsHookImageStageCommand(), newWindowsHookImagePruneCommand(), newWindowsHookImageRetireCommand())
	return command
}

func newWindowsHookImageStageCommand() *cobra.Command {
	var hookSHA, guardSHA string
	var jsonOutput bool
	command := &cobra.Command{
		Use:          "stage",
		Short:        "Put this release's hook and guard in their launch folder and start them once",
		Hidden:       true,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			report := runWindowsHookImageStage(hookSHA, guardSHA)
			summary := "hook image staged in " + report.Folder
			return writeWindowsHookImageReport(cmd.OutOrStdout(), jsonOutput, report, summary, report.OK, report.Reason, report.Error)
		},
	}
	command.Flags().StringVar(&hookSHA, "sha256", "", "SHA-256 of the hook Setup installed at bin\\defenseclaw-hook.exe")
	command.Flags().StringVar(&guardSHA, "guard-sha256", "", "SHA-256 of the hook guard Setup installed at bin\\defenseclaw-hook-guard.exe")
	// Setup always passes --json and reads one JSON line; without it a person
	// gets a one-line summary.
	command.Flags().BoolVar(&jsonOutput, "json", false, "print the JSON report (Setup's form)")
	return command
}

func newWindowsHookImagePruneCommand() *cobra.Command {
	var keep []string
	var jsonOutput bool
	command := &cobra.Command{
		Use:          "prune",
		Short:        "Remove the launch folders no agent config names any more",
		Hidden:       true,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			report := runWindowsHookImagePrune(keep)
			summary := fmt.Sprintf("hook images pruned: %d removed, %d kept, %d in use", len(report.Removed), len(report.Kept), len(report.InUse))
			return writeWindowsHookImageReport(cmd.OutOrStdout(), jsonOutput, report, summary, report.OK, "", report.Error)
		},
	}
	command.Flags().StringArrayVar(&keep, "keep", nil, "launch folder (16 hex digits) to keep; repeat for each")
	command.Flags().BoolVar(&jsonOutput, "json", false, "print the JSON report (Setup's form)")
	return command
}

func writeWindowsHookImageReport(out io.Writer, jsonOutput bool, report any, summary string, ok bool, reason, message string) error {
	if jsonOutput {
		encoded, err := json.Marshal(report)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, string(encoded))
	} else if ok {
		fmt.Fprintln(out, summary)
	}
	if ok {
		return nil
	}
	if reason != "" {
		return fmt.Errorf("%s: %s", reason, message)
	}
	return errors.New(message)
}

// windowsHookImageBin is the bin of the running gateway, which must be the
// installed gateway of a standalone install root (production or a
// certification run's).
func windowsHookImageBin() (string, error) {
	executable, err := windowsHookImageExecutable()
	if err != nil {
		return "", fmt.Errorf("resolve the running gateway: %w", err)
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return "", err
	}
	bin := filepath.Dir(filepath.Clean(executable))
	if !strings.EqualFold(filepath.Base(executable), "defenseclaw-gateway.exe") || !strings.EqualFold(filepath.Base(bin), "bin") {
		return "", fmt.Errorf("hook-image must run from the installed gateway <InstallRoot>\\bin\\defenseclaw-gateway.exe, not %s", executable)
	}
	roots, err := windowsManagedLayout.roots(winpath.EnterpriseProfileStandalone)
	if err != nil {
		return "", fmt.Errorf("resolve the standalone install roots: %w", err)
	}
	if err := winpath.ValidateEnterpriseInstallRoot(roots, filepath.Dir(bin)); err != nil {
		return "", fmt.Errorf("hook-image runs only for a standalone install root: %w", err)
	}
	return bin, nil
}

func runWindowsHookImageStage(hookSHA, guardSHA string) windowsHookImageStageReport {
	failed := func(err error) windowsHookImageStageReport {
		return windowsHookImageStageReport{
			SchemaVersion: windowsHookImageReportSchema,
			Reason:        windowsHookImageStageFailed,
			Error:         err.Error(),
		}
	}
	if !windowsEnterpriseIsElevated() {
		return failed(errors.New("staging the hook image needs LocalSystem or an elevated administrator"))
	}
	bin, err := windowsHookImageBin()
	if err != nil {
		return failed(err)
	}
	// Every folder and file written is owned by Administrators, also when
	// the built-in Administrator runs this (GAP-1718).
	restoreOwner, err := adoptWindowsAdministratorsDefaultOwner()
	if err != nil {
		return failed(err)
	}
	defer restoreOwner()
	return stageWindowsHookImage(osWindowsHookImageFS{}, osWindowsHookImageStarter{}, windowsHookImageStageRequest{
		Bin:         bin,
		HookSHA256:  hookSHA,
		GuardSHA256: guardSHA,
		Build:       windowsHookImageBuild{Version: appVersion, Commit: appCommit},
	})
}

func runWindowsHookImagePrune(keep []string) windowsHookImagePruneReport {
	failed := func(err error) windowsHookImagePruneReport {
		return windowsHookImagePruneReport{
			SchemaVersion: windowsHookImageReportSchema,
			Removed:       []string{},
			Kept:          []string{},
			InUse:         []windowsHookImageInUse{},
			Error:         err.Error(),
		}
	}
	if !windowsEnterpriseIsElevated() {
		return failed(errors.New("pruning the hook images needs LocalSystem or an elevated administrator"))
	}
	bin, err := windowsHookImageBin()
	if err != nil {
		return failed(err)
	}
	roots, err := windowsManagedLayout.roots(winpath.EnterpriseProfileStandalone)
	if err != nil {
		return failed(fmt.Errorf("resolve the standalone roots: %w", err))
	}
	// A folder a DefenseClaw-written config still names, or that was
	// superseded recently, stays (review 1 P1-2).
	return pruneWindowsHookImages(osWindowsHookImageFS{}, bin, keep, windowsHookImagePrunePolicy{
		Scan: scanWindowsHookImageConfigs(roots, bin),
		Now:  time.Now(),
	})
}

type osWindowsHookImageFS struct{}

func (osWindowsHookImageFS) Lstat(path string) (fs.FileInfo, error)     { return os.Lstat(path) }
func (osWindowsHookImageFS) ReadDir(path string) ([]fs.DirEntry, error) { return os.ReadDir(path) }
func (osWindowsHookImageFS) SHA256(path string) (string, error)         { return windowsFileSHA256Hex(path) }
func (osWindowsHookImageFS) RemoveAll(path string) error                { return os.RemoveAll(path) }

func (osWindowsHookImageFS) MkdirProtected(path string) error {
	if err := winpath.RejectReparseChain(filepath.Dir(path)); err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString(windowsHookImagesDACL)
	if err != nil {
		return err
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(pointer, attributes); err != nil {
		return err
	}
	if err := applyWindowsSDDL(path, windowsHookImagesSDDL); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("protect %s: %w", path, err)
	}
	return nil
}

// PlaceImage is the guardian's copy without replacement: a secured
// temporary beside destination, renamed to a name that must not exist.
func (osWindowsHookImageFS) PlaceImage(source, destination string) error {
	return copyWindowsManagedFile(source, destination, windowsInstallFileSDDL, false, true)
}

// ReplaceImage is the guardian's restore of a changed hook: the one-step
// swap that keeps the old image under a backup name while it runs.
func (osWindowsHookImageFS) ReplaceImage(source, destination string) error {
	return copyWindowsManagedFile(source, destination, windowsInstallFileSDDL, true, true)
}

// Rename moves a folder to a name that does not exist. A folder that holds a
// file a program runs, or has open for writing, is refused first (GAP-0751,
// Windows Server 2025 native proof): older Windows refused the rename itself
// while an image ran, but Server 2025 (build 26100) renames the folder under a
// running image, so the refusal the publish retry and prune rely on is made
// here, by opening each file of the folder for writing without sharing, which
// no running image or other open handle allows.
func (osWindowsHookImageFS) Rename(from, to string) error {
	if err := windowsHookImageFolderBusy(from); err != nil {
		return err
	}
	source, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(source, target, windows.MOVEFILE_WRITE_THROUGH)
}

// windowsHookImageFolderBusy returns the sharing violation or access denial
// of the first file under folder that cannot be opened for writing with no
// sharing (a running image, or a scanner's handle), and nil when every file
// opens or the folder does not exist (the rename then reports that itself).
func windowsHookImageFolderBusy(folder string) error {
	var busy error
	_ = filepath.WalkDir(folder, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || entry.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			return nil
		}
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil
		}
		handle, err := windows.CreateFile(name, windows.FILE_WRITE_DATA, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				busy = err
				return filepath.SkipAll
			}
			return nil
		}
		_ = windows.CloseHandle(handle)
		return nil
	})
	return busy
}

func (osWindowsHookImageFS) RandomHex(n int) (string, error) {
	buffer := make([]byte, n)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

// osWindowsHookImageStarter starts the checks under a filtered copy of the
// installer token (windowsHookImageFilteredToken): no privileges,
// Administrators deny-only. That proves the staged bytes start and answer;
// it is not the agent's user, so an application control rule aimed at one
// user or group is not seen by it (review 3: starting the check as a
// signed-in enrolled account is a follow-up for a native-proof round).
type osWindowsHookImageStarter struct{}

// Start runs one start check: no window, only the standard handles, inside a
// kill-on-close job, under the filtered token (windowsHookImageFilteredToken)
// when it can be made, and returns what the image printed and its status.
func (osWindowsHookImageStarter) Start(req windowsHookImageStart) (windowsHookImageStartResult, error) {
	var result windowsHookImageStartResult
	ctx, cancel := context.WithTimeout(context.Background(), req.Timeout)
	defer cancel()
	cmd := processutil.CommandContext(ctx, req.Path, req.Args...)
	cmd.Dir = filepath.Dir(req.Path)
	// CREATE_NO_WINDOW makes the child allocate a hidden console, which fails
	// with STATUS_DLL_INIT_FAILED (0xC0000142) under a token whose
	// Administrators group is deny-only (GAP-0751 native proof). The check
	// needs no console: its streams are pipes, so it starts detached.
	cmd.SysProcAttr.CreationFlags = cmd.SysProcAttr.CreationFlags&^windows.CREATE_NO_WINDOW | windows.DETACHED_PROCESS
	if req.Stdin != nil {
		cmd.Stdin = bytes.NewReader(req.Stdin)
	}
	token, err := windowsHookImageFilteredToken()
	if err != nil {
		result.TokenProblem = err.Error()
		result.Token = "the installer token"
	} else {
		defer token.Close()
		cmd.SysProcAttr.Token = syscall.Token(token)
		result.Restricted = true
		result.Token = windowsHookImageFilteredTokenName
	}
	stdout, stderr, err := processutil.OutputTree(cmd, false)
	result.Stdout, result.Stderr = stdout, stderr
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return result, fmt.Errorf("no answer within %s", req.Timeout)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	if err != nil {
		return result, fmt.Errorf("%w: %s", err, boundedWindowsHookImageText(stderr))
	}
	return result, nil
}

// windowsHookImageFilteredTokenName is how the report names the start
// check's token.
const windowsHookImageFilteredTokenName = "a filtered copy of the installer token (no privileges, Administrators deny-only)"

var procCreateRestrictedToken = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")

// CreateRestrictedToken flags (winnt.h).
const (
	windowsDisableMaxPrivilege = 0x1
	windowsLUAToken            = 0x4
)

// windowsHookImageFilteredToken is the token of the start checks: this
// process's token with every privilege but SeChangeNotify removed and the
// Administrators group deny-only, as a filtered (UAC) administrator or a
// standard user runs. Application control and antivirus rules that apply to
// users, not to elevated administrators, then decide the start as they will
// for the agent's user. It is a restricted copy of this process's own
// primary token, which CreateProcessAsUser takes without further privilege.
// LUA_TOKEN is asked for and dropped when Windows refuses it.
func windowsHookImageFilteredToken() (windows.Token, error) {
	var process windows.Token
	access := uint32(windows.TOKEN_DUPLICATE | windows.TOKEN_QUERY | windows.TOKEN_ASSIGN_PRIMARY |
		windows.TOKEN_ADJUST_DEFAULT | windows.TOKEN_ADJUST_SESSIONID)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &process); err != nil {
		return 0, fmt.Errorf("open this process's token: %w", err)
	}
	defer process.Close()
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return 0, fmt.Errorf("name the Administrators group: %w", err)
	}
	disable := []windows.SIDAndAttributes{{Sid: administrators}}
	var lastErr error
	for _, flags := range []uintptr{windowsDisableMaxPrivilege | windowsLUAToken, windowsDisableMaxPrivilege} {
		var restricted windows.Token
		ok, _, callErr := procCreateRestrictedToken.Call(
			uintptr(process), flags,
			uintptr(len(disable)), uintptr(unsafe.Pointer(&disable[0])),
			0, 0, 0, 0,
			uintptr(unsafe.Pointer(&restricted)))
		if ok != 0 {
			return restricted, nil
		}
		lastErr = callErr
	}
	return 0, fmt.Errorf("create the filtered token: %w", lastErr)
}

// windowsHookImageSharingViolation is a rename refused with
// ERROR_SHARING_VIOLATION (a handle open in the folder without delete
// sharing).
func windowsHookImageSharingViolation(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}

// windowsHookImageStandaloneBin is the bin whose launch set status, verify
// and ensure judge: the running binary's, when it is the bin of a
// standalone install root.
func windowsHookImageStandaloneBin() (string, bool) {
	executable, err := windowsHookImageExecutable()
	if err != nil {
		return "", false
	}
	bin := filepath.Dir(filepath.Clean(executable))
	if !strings.EqualFold(filepath.Base(bin), "bin") {
		return "", false
	}
	roots, err := windowsManagedLayout.roots(winpath.EnterpriseProfileStandalone)
	if err != nil || winpath.ValidateEnterpriseInstallRoot(roots, filepath.Dir(bin)) != nil {
		return "", false
	}
	if _, err := os.Lstat(filepath.Join(bin, winpath.EnterpriseHookImageName)); err != nil {
		return "", false
	}
	return bin, true
}

// windowsHookImageResolve is the launch set resolution; a seam for tests.
var windowsHookImageResolve = winpath.ResolveEnterpriseHookImage

// applyWindowsEnterpriseHookImage fails status and verify while the launch
// set agent configs should name is not staged and exact (GAP-0751).
func applyWindowsEnterpriseHookImage(result *enterprisestatus.Result) {
	if result == nil {
		return
	}
	bin, ok := windowsHookImageStandaloneBin()
	if !ok {
		return
	}
	image := windowsHookImageResolve(bin)
	if image.State == winpath.EnterpriseHookImageRetired {
		// An administrator retired the launch folders before a rollback to
		// an older release: expected, and not a drift to repair.
		result.AddWarning("hook_image_retired", image.Problem)
		return
	}
	if problem := windowsHookImageVerifyProblem(image); problem != "" {
		result.AddError("hook_image_not_staged", problem)
	}
}

// windowsEnterpriseHookImageEnsureDrift is the repair a compliant ensure
// still owes a launch set that is not staged: Setup stages it. A var for
// tests.
var windowsEnterpriseHookImageEnsureDrift = func() (reason, detail string) {
	bin, ok := windowsHookImageStandaloneBin()
	if !ok {
		return "", ""
	}
	image := windowsHookImageResolve(bin)
	if image.State == winpath.EnterpriseHookImageRetired {
		// A compliant ensure must not undo a retire that waits for the older
		// Setup; this release's own Setup run un-retires on its stage.
		return "", ""
	}
	if problem := windowsHookImageVerifyProblem(image); problem != "" {
		return "drift:hook_image", problem
	}
	return "", ""
}
