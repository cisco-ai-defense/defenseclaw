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
		Scan:            func() windowsHookImageConfigScan { return scanWindowsHookImageConfigs(roots) },
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
// name a hook image (windowsHookImageConfigFiles).
func scanWindowsHookImageConfigs(roots winpath.EnterpriseRoots) windowsHookImageConfigScan {
	files, problems := windowsHookImageConfigFiles(roots)
	scan := scanWindowsHookImageConfigFiles(files, readWindowsHookImageConfigFile)
	scan.Incomplete = append(problems, scan.Incomplete...)
	return scan
}

// windowsHookImageScanMaxBytes bounds one scanned file. Every file
// DefenseClaw writes that names a hook is far smaller; a larger one is
// reported as not scanned, which keeps every folder.
const windowsHookImageScanMaxBytes = 16 << 20

func readWindowsHookImageConfigFile(path string) ([]byte, error) {
	file, err := winpath.OpenReadShared(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, windowsHookImageScanMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > windowsHookImageScanMaxBytes {
		return nil, fmt.Errorf("larger than %d bytes", windowsHookImageScanMaxBytes)
	}
	return body, nil
}

// windowsHookImageConfigFiles lists the files DefenseClaw writes that can
// name a hook image: the machine policies (the Claude Code managed settings
// drop-in, the Codex requirements and its managed hooks state and selector,
// the Cursor machine hooks), the hook runtime folder (machine policy summary,
// each connector's enrollment and selector state), the lifecycle folder
// (managed hooks lifecycle and teardown journals, the machine policy state)
// and, for every enrolled account of targets.yaml, the agent config files
// its connector's hooks live in. Problems are the folders or targets that
// could not be listed; they make the scan incomplete.
func windowsHookImageConfigFiles(roots winpath.EnterpriseRoots) ([]string, []string) {
	var files, problems []string
	programFiles, err := winpath.TrustedProgramFiles()
	if err != nil {
		return nil, []string{"Program Files: " + err.Error()}
	}
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return nil, []string{"ProgramData: " + err.Error()}
	}
	list := func(dir string, depth int, skip ...string) {
		more, problem := listWindowsHookImageConfigDir(dir, depth, skip)
		files = append(files, more...)
		if problem != "" {
			problems = append(problems, problem)
		}
	}
	files = append(files, filepath.Join(programFiles, "ClaudeCode", "managed-settings.json"))
	list(filepath.Join(programFiles, "ClaudeCode", "managed-settings.d"), 0)
	list(filepath.Join(programData, "OpenAI", "Codex"), 0)
	list(filepath.Join(programData, "Cursor"), 1)
	list(filepath.Join(programData, "Cisco", managed.StandaloneWindowsHookRuntimeDirName), 1)
	// The transaction snapshots keep preimages of earlier configs; they are
	// not configs and are deleted when the transaction retires.
	list(roots.LifecycleDir, 1, "transactions")
	userFiles, userProblems := enterprisehooks.WindowsManagedHookConfigFiles(
		filepath.Join(roots.StateRoot, "hook-guardian", "targets.yaml"))
	files = append(files, userFiles...)
	problems = append(problems, userProblems...)
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
