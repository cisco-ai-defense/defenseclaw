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
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
	command.AddCommand(newWindowsHookImageStageCommand(), newWindowsHookImagePruneCommand())
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
			return writeWindowsHookImageReport(cmd.OutOrStdout(), report, report.OK, report.Reason, report.Error)
		},
	}
	command.Flags().StringVar(&hookSHA, "sha256", "", "SHA-256 of the hook Setup installed at bin\\defenseclaw-hook.exe")
	command.Flags().StringVar(&guardSHA, "guard-sha256", "", "SHA-256 of the hook guard Setup installed at bin\\defenseclaw-hook-guard.exe")
	// The report is always JSON; the flag keeps the lifecycle helpers' calling shape.
	command.Flags().BoolVar(&jsonOutput, "json", true, "print the JSON report")
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
			return writeWindowsHookImageReport(cmd.OutOrStdout(), report, report.OK, "", report.Error)
		},
	}
	command.Flags().StringArrayVar(&keep, "keep", nil, "launch folder (16 hex digits) to keep; repeat for each")
	command.Flags().BoolVar(&jsonOutput, "json", true, "print the JSON report")
	return command
}

func writeWindowsHookImageReport(out io.Writer, report any, ok bool, reason, message string) error {
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, string(encoded))
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
	return pruneWindowsHookImages(osWindowsHookImageFS{}, bin, keep)
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

func (osWindowsHookImageFS) Rename(from, to string) error {
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

func (osWindowsHookImageFS) RandomHex(n int) (string, error) {
	buffer := make([]byte, n)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

type osWindowsHookImageStarter struct{}

// Run starts path with no window and only the standard handles, inside a
// kill-on-close job, and returns its standard output.
func (osWindowsHookImageStarter) Run(path string, args []string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := processutil.CommandContext(ctx, path, args...)
	cmd.Dir = filepath.Dir(path)
	stdout, stderr, err := processutil.OutputTree(cmd, false)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("no answer within %s", timeout)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, boundedWindowsHookImageText(stderr))
	}
	return stdout, nil
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
	if problem := windowsHookImageVerifyProblem(windowsHookImageResolve(bin)); problem != "" {
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
	if problem := windowsHookImageVerifyProblem(windowsHookImageResolve(bin)); problem != "" {
		return "drift:hook_image", problem
	}
	return "", ""
}
