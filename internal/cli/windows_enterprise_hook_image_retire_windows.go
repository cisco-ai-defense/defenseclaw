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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func newWindowsHookImageRetireCommand() *cobra.Command {
	var jsonOutput bool
	command := &cobra.Command{
		Use:          "retire",
		Short:        "Point every agent hook back at bin\\defenseclaw-hook.exe before an older release's Setup runs",
		Hidden:       true,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			report := runWindowsHookImageRetire()
			summary := "every agent hook names the transition image again; the launch folders stay"
			return writeWindowsHookImageReport(cmd.OutOrStdout(), jsonOutput, report, summary, report.OK, report.Reason, report.Error)
		},
	}
	command.Flags().BoolVar(&jsonOutput, "json", false, "print the JSON report (otherwise one summary line)")
	return command
}

func runWindowsHookImageRetire() windowsHookImageRetireReport {
	refused := func(err error) windowsHookImageRetireReport {
		return windowsHookImageRetireReport{
			SchemaVersion: windowsHookImageReportSchema,
			Reason:        windowsHookImageRetireRefused,
			Error:         err.Error(),
			Rewritten:     []string{},
			StillNamed:    []windowsHookImageNamedFile{},
		}
	}
	if !windowsEnterpriseIsElevated() {
		return refused(errors.New("retiring the hook images needs LocalSystem or an elevated administrator"))
	}
	bin, err := windowsHookImageBin()
	if err != nil {
		return refused(err)
	}
	roots, err := windowsManagedLayout.roots(winpath.EnterpriseProfileStandalone)
	if err != nil {
		return refused(fmt.Errorf("resolve the standalone roots: %w", err))
	}
	// Setup and the other lifecycle commands hold this lock while they
	// write configs; retire never runs beside them.
	release, err := windowsEnterpriseHotConfigLock(filepath.Join(roots.LifecycleDir, "lifecycle.lock"))
	if err != nil {
		return refused(fmt.Errorf("lifecycle_busy: another DefenseClaw lifecycle run holds lifecycle.lock; run retire again after it finishes: %w", err))
	}
	defer release()
	restoreOwner, err := adoptWindowsAdministratorsDefaultOwner()
	if err != nil {
		return refused(err)
	}
	defer restoreOwner()
	guardian, err := windowsHookImageGuardianService(roots, filepath.Dir(bin))
	if err != nil {
		return refused(err)
	}
	return retireWindowsHookImages(windowsHookImageRetireSteps{
		FS:  osWindowsHookImageFS{},
		Bin: bin,
		RecordedSHA256: func(artifact string) (string, error) {
			return windowsRecordedArtifactHash(roots.MetadataPath, artifact)
		},
		WriteMarker: func(path string, body []byte) error {
			if err := os.WriteFile(path, body, 0o600); err != nil {
				return err
			}
			return applyWindowsSDDL(path, windowsInstallFileSDDL)
		},
		ReconcileCodex:  reconcileWindowsCodexRequirementsForHookImage,
		RestartGuardian: func() error { return restartWindowsHookImageGuardian(guardian) },
		Scan:            func() windowsHookImageConfigScan { return scanWindowsHookImageConfigs(roots, bin) },
		Now:             time.Now,
		Sleep:           time.Sleep,
		Wait:            windowsHookImageRetireWait,
		Poll:            windowsHookImageRetirePoll,
	})
}

// windowsHookImageGuardianService is the guardian service of the install
// root: DefenseClawHookGuardian, or a certification run's guardian.
func windowsHookImageGuardianService(roots winpath.EnterpriseRoots, installRoot string) (string, error) {
	gateway, err := winpath.EnterpriseGatewayServiceForRoot(roots, installRoot)
	if err != nil {
		return "", err
	}
	if id, ok := strings.CutPrefix(gateway, "DefenseClawCertGateway_"); ok {
		return "DefenseClawCertGuardian_" + id, nil
	}
	return "DefenseClawHookGuardian", nil
}

// restartWindowsHookImageGuardian restarts the guardian so its first
// reconcile rewrites every per-user config and machine policy with the
// launch set the resolver now returns. A stopped guardian is started.
func restartWindowsHookImageGuardian(name string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(name)
	if err != nil {
		return err
	}
	defer service.Close()
	restarted, err := restartWindowsGatewayServiceBeforeStop(scmGatewayService{service}, name, 60*time.Second, 250*time.Millisecond, nil)
	if err != nil {
		return err
	}
	if !restarted {
		return service.Start()
	}
	return nil
}

// reconcileWindowsCodexRequirementsForHookImage rewrites the Codex machine
// requirements with the resolver's launch set, as Setup's
// `codex-requirements reconcile` does. An install without Codex machine
// requirements has nothing to rewrite.
func reconcileWindowsCodexRequirementsForHookImage() error {
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return err
	}
	restore := setTemporaryEnvironment(windowsEnterpriseServicePins(layout))
	defer restore()
	if err := enterpriseHooksPlatformPreflight(); err != nil {
		return err
	}
	opts, err := windowsCodexRequirementsLayoutResolver("reconcile")
	if err != nil {
		return err
	}
	if _, err := os.Lstat(opts.RequirementsPath); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	_, err = windowsCodexRequirementsReconciler(opts)
	return err
}

// scanWindowsHookImageConfigs reads every file DefenseClaw writes that can
// name a hook image of bin (windowsHookImageConfigFiles): machine files make
// the scan incomplete when they cannot be read, account files are skipped
// (windowsHookImageConfigScan).
func scanWindowsHookImageConfigs(roots winpath.EnterpriseRoots, bin string) windowsHookImageConfigScan {
	entries, problems := windowsHookImageConfigFiles(roots)
	files, incomplete, skipped := expandWindowsHookImageConfigFiles(entries, os.Lstat, os.ReadDir)
	scan := scanWindowsHookImageConfigFiles(files, bin, readWindowsHookImageConfigFile)
	scan.Incomplete = append(append(problems, incomplete...), scan.Incomplete...)
	scan.Skipped = append(skipped, scan.Skipped...)
	return scan
}

// windowsHookImageScanMaxBytes bounds one scanned file. Every file
// DefenseClaw writes that names a hook is far smaller; a larger one is not
// read (a machine file makes the scan incomplete, an account file is skipped).
const windowsHookImageScanMaxBytes = 16 << 20

// windowsHookImageScanFileTimeout bounds one file's open and read, so a
// file an account holds with an oplock, or a path that does not answer,
// cannot keep retire or prune (which hold the lifecycle lock) waiting. A
// read still blocked at the timeout is given up on; its goroutine ends with
// the process.
const windowsHookImageScanFileTimeout = 5 * time.Second

var errWindowsHookImageScanTimeout = fmt.Errorf("did not answer within %s; not read", windowsHookImageScanFileTimeout)

func readWindowsHookImageConfigFile(path string) ([]byte, error) {
	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		body, err := readWindowsHookImageConfigFileNow(path)
		done <- result{body, err}
	}()
	timer := time.NewTimer(windowsHookImageScanFileTimeout)
	defer timer.Stop()
	select {
	case got := <-done:
		return got.body, got.err
	case <-timer.C:
		return nil, errWindowsHookImageScanTimeout
	}
}

// readWindowsHookImageConfigFileNow opens path without following a final
// link (FILE_FLAG_OPEN_REPARSE_POINT) and reads it only when the opened
// object is a regular file: a link, a junction or a folder is never read.
func readWindowsHookImageConfigFileNow(path string) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, fs.ErrNotExist
		}
		if info, statErr := os.Lstat(path); statErr == nil && !info.Mode().IsRegular() {
			return nil, errWindowsHookImageScanUnsafe
		}
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		return nil, errWindowsHookImageScanUnsafe
	}
	if size := int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow); size > windowsHookImageScanMaxBytes {
		return nil, fmt.Errorf("larger than %d bytes; not read", windowsHookImageScanMaxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(file, windowsHookImageScanMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > windowsHookImageScanMaxBytes {
		return nil, fmt.Errorf("larger than %d bytes; not read", windowsHookImageScanMaxBytes)
	}
	return body, nil
}

// windowsHookImageConfigFiles lists the files DefenseClaw writes that can
// name a hook image: the machine policies (the Claude Code managed settings
// and its drop-in folder, the Codex requirements and its managed hooks state
// and selector, the Cursor machine hooks), the hook runtime folder (machine
// policy summary, each connector's enrollment and selector state), the
// lifecycle folder (managed hooks lifecycle and teardown journals, the
// machine policy state), the Codex requirements ownership record in the
// state root and, for every enrolled account of targets.yaml, the agent
// config paths its connector's hooks live in (account files; a watched
// folder is expanded by expandWindowsHookImageConfigFiles). Problems are the
// folders or targets that could not be listed; they make the scan
// incomplete.
func windowsHookImageConfigFiles(roots winpath.EnterpriseRoots) ([]windowsHookImageConfigFile, []string) {
	var files []windowsHookImageConfigFile
	var problems []string
	programFiles, err := winpath.TrustedProgramFiles()
	if err != nil {
		return nil, []string{"Program Files: " + err.Error()}
	}
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return nil, []string{"ProgramData: " + err.Error()}
	}
	machine := func(path string) {
		files = append(files, windowsHookImageConfigFile{Path: path})
	}
	list := func(dir string, depth int, skip ...string) {
		more, problem := listWindowsHookImageConfigDir(dir, depth, skip)
		for _, path := range more {
			machine(path)
		}
		if problem != "" {
			problems = append(problems, problem)
		}
	}
	machine(filepath.Join(programFiles, "ClaudeCode", "managed-settings.json"))
	list(filepath.Join(programFiles, "ClaudeCode", "managed-settings.d"), 0)
	list(filepath.Join(programData, "OpenAI", "Codex"), 0)
	list(filepath.Join(programData, "Cursor"), 1)
	list(filepath.Join(programData, "Cisco", managed.StandaloneWindowsHookRuntimeDirName), 1)
	// The transaction snapshots keep preimages of earlier configs; they are
	// not configs and are deleted when the transaction retires.
	list(roots.LifecycleDir, 1, "transactions")
	// The Codex requirements ownership record names the hook a 1.0.9 Setup
	// compares (RETIRE-1.0.9.md).
	machine(filepath.Join(roots.StateRoot, "install", "codex-requirements-ownership.json"))
	accountFiles, accountProblems := enterprisehooks.WindowsManagedHookConfigFiles(
		filepath.Join(roots.StateRoot, "hook-guardian", "targets.yaml"))
	for _, file := range accountFiles {
		files = append(files, windowsHookImageConfigFile{Path: file.Path, User: file.User})
	}
	problems = append(problems, accountProblems...)
	return files, problems
}

// listWindowsHookImageConfigDir lists the regular files of dir and, to depth,
// of its plain subfolders. Lock files and temporaries are left out: Setup
// and the writers hold them open without sharing and they never name a hook.
func listWindowsHookImageConfigDir(dir string, depth int, skip []string) ([]string, string) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ""
	}
	if err != nil {
		return nil, fmt.Sprintf("%s: %v", dir, err)
	}
	var files []string
	for _, entry := range entries {
		name := entry.Name()
		lower := strings.ToLower(name)
		path := filepath.Join(dir, name)
		switch {
		case entry.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0:
			continue
		case entry.IsDir():
			if depth <= 0 || containsFoldString(skip, name) {
				continue
			}
			more, problem := listWindowsHookImageConfigDir(path, depth-1, nil)
			files = append(files, more...)
			if problem != "" {
				return files, problem
			}
		case strings.HasSuffix(lower, ".lock") || strings.Contains(lower, ".tmp"):
			continue
		default:
			files = append(files, path)
		}
	}
	return files, ""
}

func containsFoldString(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}
