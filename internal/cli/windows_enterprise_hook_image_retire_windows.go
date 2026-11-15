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
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/hookcli"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func newWindowsHookImageRetireCommand() *cobra.Command {
	var jsonOutput bool
	var skipProfiles []string
	command := &cobra.Command{
		Use:          "retire",
		Short:        "Point every agent hook back at bin\\defenseclaw-hook.exe before an older release's Setup runs",
		Hidden:       true,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			report := runWindowsHookImageRetire(skipProfiles)
			summary := "every agent hook names the transition image again; the launch folders stay"
			return writeWindowsHookImageReport(cmd.OutOrStdout(), jsonOutput, report, summary, report.OK, report.Reason, report.Error)
		},
	}
	command.Flags().BoolVar(&jsonOutput, "json", false, "print the JSON report (otherwise one summary line)")
	command.Flags().StringArrayVar(&skipProfiles, "skip-profile", nil,
		"SID of an enrolled profile whose own agent configs still name a launch folder to leave unconverted (repeatable; audited, and listed by status and verify until converted)")
	return command
}

func runWindowsHookImageRetire(skipProfiles []string) windowsHookImageRetireReport {
	refused := func(err error) windowsHookImageRetireReport {
		return windowsHookImageRetireReport{
			SchemaVersion:     windowsHookImageReportSchema,
			Reason:            windowsHookImageRetireRefused,
			Error:             err.Error(),
			Rewritten:         []string{},
			StillNamed:        []windowsHookImageNamedFile{},
			SkippedProfiles:   []windowsHookImageSkippedProfile{},
			SignedOutProfiles: []windowsHookImageSignedOutProfile{},
		}
	}
	if !windowsEnterpriseIsElevated() {
		return refused(errors.New("retiring the hook images needs LocalSystem or an elevated administrator"))
	}
	bin, err := windowsHookImageBin()
	if err != nil {
		return refused(err)
	}
	roots, err := hookcli.WindowsManagedLayout.Roots(winpath.EnterpriseProfileStandalone)
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
	gateway, err := winpath.EnterpriseGatewayServiceForRoot(roots, filepath.Dir(bin))
	if err != nil {
		return refused(err)
	}
	guardian := windowsHookImageGuardianService(gateway)
	return retireWindowsHookImages(windowsHookImageRetireSteps{
		FS:  osWindowsHookImageFS{},
		Bin: bin,
		RecordedSHA256: func(artifact string) (string, error) {
			return windowsRecordedArtifactHash(roots.MetadataPath, artifact)
		},
		WriteMarker: func(path string, body []byte) error {
			return writeWindowsHookImageRetiredMarker(path, body, applyWindowsSDDL)
		},
		ReconcileCodex: func() error { return reconcileWindowsCodexRequirementsForHookImage(gateway) },
		DeselectSignedOut: func() windowsHookImageDeselection {
			return deselectWindowsHookImageSignedOutSelections(roots, bin, gateway)
		},
		RestartGuardian:  func() error { return restartWindowsHookImageGuardian(guardian) },
		GuardianFailures: windowsHookImageGuardianFailures,
		Scan:             func() windowsHookImageConfigScan { return scanWindowsHookImageConfigs(roots, bin) },
		RouteOnlyRouted: func() ([]string, error) {
			cfg, err := loadWindowsEnterpriseStandaloneConfig("")
			if errors.Is(err, fs.ErrNotExist) {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			return managedRouteOnlyConnectors(cfg), nil
		},
		SkipProfiles: skipProfiles,
		Profiles: func() (map[string]windowsHookImageProfile, error) {
			return windowsHookImageEnrolledProfiles(roots)
		},
		Actor:      windowsHookImageRetireActor,
		Audit:      postWindowsHookImageRetireSkip,
		ReadMarker: os.ReadFile,
		Now:        time.Now,
		Sleep:      time.Sleep,
		Wait:       windowsHookImageRetireWait,
		Poll:       windowsHookImageRetirePoll,
	})
}

// windowsHookImageEnrolledProfiles is every enabled account of the
// guardian's manifest by SID.
func windowsHookImageEnrolledProfiles(roots winpath.EnterpriseRoots) (map[string]windowsHookImageProfile, error) {
	manifest, err := enterprisehooks.LoadManifest(filepath.Join(roots.StateRoot, "hook-guardian", "targets.yaml"))
	if err != nil {
		return nil, err
	}
	profiles := map[string]windowsHookImageProfile{}
	for _, target := range manifest.Targets {
		sid := strings.TrimSpace(target.SID)
		if sid == "" || (target.Enabled != nil && !*target.Enabled) {
			continue
		}
		profiles[sid] = windowsHookImageProfile{Account: strings.TrimSpace(target.User), Home: strings.TrimSpace(target.UserHome)}
	}
	return profiles, nil
}

// windowsHookImageRetireActor names the account that runs retire:
// "DOMAIN\user (SID)", or the SID alone when it has no name.
func windowsHookImageRetireActor() string {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return "unknown account"
	}
	sid := user.User.Sid.String()
	if account, domain, _, err := user.User.Sid.LookupAccount(""); err == nil && account != "" {
		if domain != "" {
			account = domain + `\` + account
		}
		return account + " (" + sid + ")"
	}
	return sid
}

// postWindowsHookImageRetireSkip writes the HIGH audit row of one skipped
// profile through the managed gateway: who skipped it and when, the SID and
// the files that still name a launch folder (GAP-0794 review F4). It is an
// operator mutation of the managed hook state, so the config-update action.
func postWindowsHookImageRetireSkip(profile windowsHookImageSkippedProfile) error {
	return writeWindowsEnterpriseAuditRow(func() error {
		return postWindowsManagedObservability(map[string]any{"kind": "activity", "activity": map[string]any{
			"actor":       profile.SkippedBy,
			"action":      string(audit.ActionConfigUpdate),
			"target_type": "hook-image-retire-skip",
			"target_id":   profile.SID,
			"severity":    "HIGH",
			"before":      map[string]any{"account": profile.Account, "still_named": profile.Files},
			"after":       map[string]any{"skipped_at": profile.SkippedAt, "retired": false},
		}})
	})
}

// windowsHookImageGuardianService is the guardian service beside the
// install root's gateway service: DefenseClawHookGuardian, or a
// certification run's guardian.
func windowsHookImageGuardianService(gateway string) string {
	if id, ok := strings.CutPrefix(gateway, "DefenseClawCertGateway_"); ok {
		return "DefenseClawCertGuardian_" + id
	}
	return "DefenseClawHookGuardian"
}

// deselectWindowsHookImageSignedOutSelections is retire's runtime selector
// step (rel-1-0-10 GAP-0856): for each enrolled account of the guardian's
// manifest the guardian cannot repair now (no Windows session it repairs
// in, the guardian's own check), it drops the selections that name a launch
// image of bin, under the guardian's service pins. An account with a session
// keeps its selections: the guardian rewrites them after its restart.
func deselectWindowsHookImageSignedOutSelections(roots winpath.EnterpriseRoots, bin, gateway string) windowsHookImageDeselection {
	result := windowsHookImageDeselection{Errors: map[string]string{}}
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		result.Error = "resolve the standalone layout: " + err.Error()
		return result
	}
	manifest, err := windowsHookImageManifestLoader(filepath.Join(roots.StateRoot, "hook-guardian", "targets.yaml"))
	if err != nil {
		result.Error = "read the guardian's manifest: " + err.Error()
		return result
	}
	targets := map[string]enterprisehooks.ManifestTarget{}
	for _, target := range manifest.Targets {
		sid := strings.ToUpper(strings.TrimSpace(target.SID))
		if sid == "" || !target.IsEnabled() {
			continue
		}
		if _, seen := targets[sid]; !seen {
			targets[sid] = target
		}
	}
	restore := setTemporaryEnvironment(windowsEnterpriseGuardianRecordPins(layout, gateway))
	defer restore()
	dropped, failures := windowsHookImageDeselector(bin, func(sid string) (bool, error) {
		target, enrolled := targets[strings.ToUpper(strings.TrimSpace(sid))]
		if !enrolled {
			// Not this guardian's account: the guardian's own pass retires
			// a selection its machine policy no longer registers (GAP-0262).
			return false, nil
		}
		available, err := enterpriseHookTargetSessionAvailable(target)
		return err == nil && !available, err
	})
	for path, failure := range failures {
		if path == "" || !filepath.IsAbs(path) {
			result.Error = strings.TrimSpace(strings.Join([]string{result.Error, path + ": " + failure.Error()}, " "))
			continue
		}
		result.Errors[strings.ToLower(path)] = failure.Error()
	}
	byAccount := map[string]*windowsHookImageSignedOutProfile{}
	var order []string
	for _, selection := range dropped {
		key := strings.ToUpper(selection.SID)
		profile, seen := byAccount[key]
		if !seen {
			profile = &windowsHookImageSignedOutProfile{SID: selection.SID, Account: strings.TrimSpace(targets[key].User), Connectors: []string{}}
			byAccount[key] = profile
			order = append(order, key)
		}
		profile.Connectors = append(profile.Connectors, selection.Connector)
	}
	sort.Strings(order)
	for _, key := range order {
		sort.Strings(byAccount[key].Connectors)
		result.Profiles = append(result.Profiles, *byAccount[key])
	}
	return result
}

// windowsHookImageDeselector is the enterprisehooks runtime selector step and
// windowsHookImageManifestLoader the guardian manifest reader; seams for
// tests.
var (
	windowsHookImageDeselector     = enterprisehooks.DeselectWindowsStandaloneSignedOutLaunchSelections
	windowsHookImageManifestLoader = enterprisehooks.LoadManifest
)

// windowsHookImageGuardianFailures are the failed rows of the guardian's
// last reconcile, worded as enterprise windows status words them, for the
// cause of a machine file retire stays pending on.
func windowsHookImageGuardianFailures() []string {
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return nil
	}
	state, exists, err := loadEnterpriseHookGuardianState(layout.DataDir)
	if err != nil {
		return []string{"the guardian's state could not be read: " + err.Error()}
	}
	if !exists {
		return nil
	}
	var failures []string
	for _, row := range state.Results {
		if !row.OK && !row.Pending {
			failures = append(failures, enterpriseHookGuardianFailureIssue(row))
		}
	}
	return failures
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
//
// It runs under the guardian's record pins (windowsEnterpriseGuardianRecordPins):
// the layout resolver requires the guardian's authorization directory and the
// gateway service name, which an administrator's or SYSTEM's shell does not
// carry, so with the service pins alone every retire's reconcile refused with
// "DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR must be an exact absolute protected
// path", the requirements kept naming the launch folder, and the guardian's
// next pass refused them too (rel-1-0-10 GAP-0856).
func reconcileWindowsCodexRequirementsForHookImage(gateway string) error {
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return err
	}
	restore := setTemporaryEnvironment(windowsEnterpriseGuardianRecordPins(layout, gateway))
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
// (windowsHookImageConfigScan). An account path is looked at, listed and read
// only from its home's handle with no link followed from the home down
// (link_in_account_path otherwise).
func scanWindowsHookImageConfigs(roots winpath.EnterpriseRoots, bin string) windowsHookImageConfigScan {
	entries, problems := windowsHookImageConfigFiles(roots)
	files, incomplete, unverified := expandWindowsHookImageConfigFiles(entries, os.Lstat, os.ReadDir,
		windowsHookImageAccountView(viewWindowsHookImageAccountPath))
	scan := scanWindowsHookImageConfigFiles(files, bin, readWindowsHookImageConfigFile)
	scan.Incomplete = append(append(problems, incomplete...), scan.Incomplete...)
	scan.Unverified = append(unverified, scan.Unverified...)
	return scan
}

// viewWindowsHookImageAccountPath opens an account path from its home's
// handle (winpath.OpenBelow: every element relative to its parent, no link
// followed, so a junction swapped in anywhere below the home fails inside
// the open and SYSTEM never reaches what it points to). The walk before it
// (winpath.RejectReparseBelow) names the link in the error; the check on the
// opened handle (winpath.VerifyOpenedBelow) is defence in depth. A folder is
// listed through the opened handle.
func viewWindowsHookImageAccountPath(home, path string) (fs.FileInfo, []fs.DirEntry, error) {
	if err := winpath.RejectReparseBelow(home, path); err != nil {
		return nil, nil, err
	}
	opened, err := winpath.OpenBelow(home, path, winpath.BelowAny)
	if err != nil {
		return nil, nil, err
	}
	defer opened.Close()
	if err := winpath.VerifyOpenedBelow(windows.Handle(opened.Fd()), home, path); err != nil {
		return nil, nil, err
	}
	info, err := opened.Stat()
	if err != nil || !info.IsDir() {
		return info, nil, err
	}
	children, err := opened.ReadDir(-1)
	if err != nil {
		return nil, nil, err
	}
	return info, children, nil
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

func readWindowsHookImageConfigFile(file windowsHookImageConfigFile) ([]byte, error) {
	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		body, err := readWindowsHookImageConfigFileNow(file)
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

// readWindowsHookImageConfigFileNow reads a regular file: a link, a
// junction, a folder or a device is never read. An account file is opened
// only from its home's handle with no link followed from the home down
// (winpath.OpenBelow), after the walk that names a link
// (winpath.RejectReparseBelow), and read only when the opened handle's final
// path is still the home's plus the file's own elements
// (winpath.VerifyOpenedBelow). Any refusal is link_in_account_path. A
// machine file is opened by name without following a final link
// (FILE_FLAG_OPEN_REPARSE_POINT; its folders are SYSTEM's or the
// administrators'); one held open without read sharing, or with a byte-range lock
// over it, is retried, then reported as machine_file_busy.
func readWindowsHookImageConfigFileNow(file windowsHookImageConfigFile) ([]byte, error) {
	if !file.User {
		return readWindowsHookImageRetryingBusy(func() ([]byte, error) { return readWindowsHookImageMachineFile(file.Path) },
			func(err error) bool {
				return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)
			}, time.Sleep)
	}
	if strings.TrimSpace(file.Home) == "" {
		return nil, errWindowsHookImageNoAccountHome
	}
	if err := winpath.RejectReparseBelow(file.Home, file.Path); err != nil {
		return nil, windowsHookImageAccountPathError(err)
	}
	opened, err := winpath.OpenBelow(file.Home, file.Path, winpath.BelowFile)
	if err != nil {
		return nil, windowsHookImageAccountPathError(err)
	}
	defer opened.Close()
	handle := windows.Handle(opened.Fd())
	if err := windowsHookImageAccountPathError(winpath.VerifyOpenedBelow(handle, file.Home, file.Path)); err != nil {
		return nil, err
	}
	return readWindowsHookImageOpened(opened, handle)
}

func readWindowsHookImageMachineFile(path string) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, fs.ErrNotExist
		}
		if info, statErr := os.Lstat(path); statErr == nil && !info.Mode().IsRegular() {
			return nil, errWindowsHookImageScanUnsafe
		}
		return nil, err
	}
	opened := os.NewFile(uintptr(handle), path)
	defer opened.Close()
	return readWindowsHookImageOpened(opened, handle)
}

// readWindowsHookImageOpened reads an opened regular file up to
// windowsHookImageScanMaxBytes.
func readWindowsHookImageOpened(opened *os.File, handle windows.Handle) ([]byte, error) {
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
	body, err := io.ReadAll(io.LimitReader(opened, windowsHookImageScanMaxBytes+1))
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
// folder is expanded by expandWindowsHookImageConfigFiles). The files of the
// ProgramData vendor folders a standard user can create (OpenAI\Codex,
// Cursor) are listed from ProgramData's handle and are account files unless
// they and their folders are owned by SYSTEM or Administrators
// (windowsHookImageVendorFiles). Problems are the machine folders or targets
// that could not be listed; they make the scan incomplete.
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
		more, failures := listWindowsHookImageConfigDir(dir, depth, skip)
		for _, path := range more {
			machine(path)
		}
		for _, failure := range failures {
			problems = append(problems, failure.String())
		}
	}
	vendor := func(dir string, depth int) {
		more, failures := windowsHookImageVendorFiles(programData, dir, depth, windowsHookImageVendorFS{
			Inspect: winpath.InspectBelow,
			List:    listWindowsHookImageBelow,
		})
		files = append(files, more...)
		problems = append(problems, failures...)
	}
	machine(filepath.Join(programFiles, "ClaudeCode", "managed-settings.json"))
	list(filepath.Join(programFiles, "ClaudeCode", "managed-settings.d"), 0)
	vendor(filepath.Join(programData, "OpenAI", "Codex"), 0)
	vendor(filepath.Join(programData, "Cursor"), 1)
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
		files = append(files, windowsHookImageConfigFile{Path: file.Path, User: file.User, Home: file.Home, SID: file.SID})
	}
	problems = append(problems, accountProblems...)
	return files, problems
}

// windowsHookImageListFailure is a folder listWindowsHookImageConfigDir could
// not list.
type windowsHookImageListFailure struct {
	Dir string
	Err error
}

func (f windowsHookImageListFailure) String() string { return fmt.Sprintf("%s: %v", f.Dir, f.Err) }

// listWindowsHookImageConfigDir lists the regular files of dir and, to depth,
// of its plain subfolders. Lock files and temporaries are left out: Setup
// and the writers hold them open without sharing and they never name a hook.
// A subfolder that cannot be listed is returned as a failure and the listing
// goes on with its siblings, so one folder an account made unreadable cannot
// hide the other files.
func listWindowsHookImageConfigDir(dir string, depth int, skip []string) ([]string, []windowsHookImageListFailure) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, []windowsHookImageListFailure{{Dir: dir, Err: err}}
	}
	var files []string
	var failures []windowsHookImageListFailure
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
			more, failed := listWindowsHookImageConfigDir(path, depth-1, nil)
			files = append(files, more...)
			failures = append(failures, failed...)
		case strings.HasSuffix(lower, ".lock") || strings.Contains(lower, ".tmp"):
			continue
		default:
			files = append(files, path)
		}
	}
	return files, failures
}

// listWindowsHookImageBelow lists the folder path from root's handle
// (winpath.OpenBelow): no folder from root down is resolved by name.
func listWindowsHookImageBelow(root, path string) ([]fs.DirEntry, error) {
	opened, err := winpath.OpenBelow(root, path, winpath.BelowDirectory)
	if err != nil {
		return nil, err
	}
	defer opened.Close()
	return opened.ReadDir(-1)
}

func containsFoldString(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

// writeWindowsHookImageRetiredMarker writes the retire marker and protects it
// like an install file. It fails closed: when the protection cannot be set,
// the marker is removed again, so no unprotected marker tells the writers the
// install is retired (rel-1-0-10:GAP-0840: a failed protection left the
// marker behind, and every later retire reported pending over it).
func writeWindowsHookImageRetiredMarker(path string, body []byte, protect func(path, sddl string) error) error {
	if err := os.WriteFile(path, body, 0o600); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := protect(path, windowsInstallFileSDDL); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			return fmt.Errorf("protect the retire marker: %w; remove it again: %v", err, removeErr)
		}
		return fmt.Errorf("protect the retire marker: %w", err)
	}
	return nil
}
