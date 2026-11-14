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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookguard"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The versioned managed hook image (GAP-0751). A standalone managed Windows
// install starts its hook from a launch folder <bin>\hooks\<d16> that holds
// the hook and its guard (d16: the first 16 hex digits of the hook's
// SHA-256), so an upgrade never replaces the image an agent starts: Setup
// stages the new release's folder, starts the hook once, and only then do the
// agent configs switch to it; the replaced release's folder stays for the
// sessions that still run it until the next upgrade. The lifecycle runs the
// installed gateway's hidden `enterprise windows hook-image stage` right after
// it installs the transition image (bin\defenseclaw-hook.exe) and
// `hook-image prune` after it committed (Install-DefenseClawStandaloneHookImage
// and Invoke-DefenseClawStandaloneHookImagePrune in the installer module).
// The decisions here are OS-independent and run in every platform's tests;
// windows_enterprise_hook_image_windows.go supplies the file system and the
// process start.

// windowsHookImageReportSchema is the schema of both reports, which the
// installer module checks.
const windowsHookImageReportSchema = 1

// Reason codes of a failed stage. hook_image_start_failed is the managed
// fail-closed exit: Setup rolls the transaction back, every agent config
// keeps the image it names, and that image is kept.
//
// hook_image_publish_busy: the complete staging folder could not be renamed
// to its launch folder name because another program (an antivirus scanning
// the new images) kept a handle in it through every retry; nothing switched,
// and the same Setup command can be run again.
const (
	windowsHookImageStartFailed    = "hook_image_start_failed"
	windowsHookImageDigestMismatch = "hook_image_digest_mismatch"
	windowsHookImageStageFailed    = "hook_image_stage_failed"
	windowsHookImagePublishBusy    = "hook_image_publish_busy"
)

// windowsHookImageStartTimeout bounds each start check.
const windowsHookImageStartTimeout = 60 * time.Second

// The publish rename (staging folder to launch folder) is retried while
// Windows refuses it because a handle is open in the folder: an antivirus or
// EDR scan of the two new images, which right after they are written is the
// rule, not the exception. Up to windowsHookImagePublishTries attempts,
// waiting windowsHookImagePublishFirstWait and doubling up to
// windowsHookImagePublishMaxWait between them: about 11 s in all.
const (
	windowsHookImagePublishTries     = 10
	windowsHookImagePublishFirstWait = 100 * time.Millisecond
	windowsHookImagePublishMaxWait   = 2 * time.Second
)

// windowsHookImageStagingMinAge is how old a staging folder must be before a
// stage removes it as an interrupted run's leftover. Setup's lifecycle lock
// keeps two of its own stages apart, but an administrator can run the hidden
// command beside Setup; a fresh staging folder is another run's work in
// progress.
const windowsHookImageStagingMinAge = time.Hour

// Seams for tests.
var (
	windowsHookImageSleep = time.Sleep
	windowsHookImageNow   = time.Now
)

// windowsHookImageOutputLimit bounds what a start check reads back.
const windowsHookImageOutputLimit = 64 << 10

type windowsHookImageStageReport struct {
	SchemaVersion int      `json:"schema_version"`
	OK            bool     `json:"ok"`
	Folder        string   `json:"folder"`
	Hook          string   `json:"hook"`
	Guard         string   `json:"guard"`
	CreatedFolder bool     `json:"created_folder"`
	Changed       bool     `json:"changed"`
	Reason        string   `json:"reason"`
	Error         string   `json:"error"`
	Notes         []string `json:"notes,omitempty"`
}

type windowsHookImageInUse struct {
	Folder string `json:"folder"`
	Error  string `json:"error"`
}

type windowsHookImagePruneReport struct {
	SchemaVersion int                        `json:"schema_version"`
	OK            bool                       `json:"ok"`
	Removed       []string                   `json:"removed"`
	Kept          []string                   `json:"kept"`
	Retained      []windowsHookImageRetained `json:"retained"`
	InUse         []windowsHookImageInUse    `json:"in_use"`
	Error         string                     `json:"error"`
	Notes         []string                   `json:"notes,omitempty"`
}

// windowsHookImageRetained is a launch folder prune left although it is
// neither current nor kept: Why is named_by:<file>,
// superseded_recently:<RFC3339 time it was superseded> or scan_incomplete.
type windowsHookImageRetained struct {
	Folder string `json:"folder"`
	Why    string `json:"why"`
}

// hookImageRetainAfterSupersede is how long prune keeps a launch folder
// after a newer one was staged, even when no config names it any more. An
// agent session reads its hook command once, at its start, and keeps it for
// its life: a Claude Code or Codex session that started on release N keeps
// starting N's folder after N+1 and N+2 switched every config. Removing that
// folder makes the session's hook command fail to start, which the agent
// takes as a non-blocking error and runs the tool call without a DefenseClaw
// decision (review 1 P1-2). Sessions that outlive this window are expected to
// be restarted; the windows enterprise guide says so.
const hookImageRetainAfterSupersede = 14 * 24 * time.Hour

// windowsHookImagePrunePolicy is what prune needs besides the folders: the
// config scan (which launch folders a DefenseClaw-written config still names)
// and the clock.
type windowsHookImagePrunePolicy struct {
	Scan windowsHookImageConfigScan
	Now  time.Time
}

// windowsHookImageFS is the file access of stage and prune. Paths are
// absolute Windows paths.
type windowsHookImageFS interface {
	Lstat(path string) (fs.FileInfo, error)
	ReadDir(path string) ([]fs.DirEntry, error)
	// SHA256 is the lowercase digest of a regular file, read with every
	// sharing mode so a running hook is no obstacle.
	SHA256(path string) (string, error)
	// MkdirProtected creates a new folder (failing when it exists) with the
	// launch folder's protected access list, owned by Administrators.
	MkdirProtected(path string) error
	// PlaceImage writes source's bytes as the new file destination, with the
	// install-file access list; it never replaces an existing file.
	PlaceImage(source, destination string) error
	// ReplaceImage puts source's bytes at the existing destination in one
	// rename and keeps the old file under <destination>.backup.<32 hex> while
	// a program runs it: the guardian's swap (swapWindowsProgramImage).
	ReplaceImage(source, destination string) error
	// Rename moves a folder to a name that does not exist.
	Rename(from, to string) error
	RemoveAll(path string) error
	// RandomHex returns n random bytes in lowercase hex.
	RandomHex(n int) (string, error)
}

// windowsHookImageStart is one start of a staged image.
type windowsHookImageStart struct {
	Path  string
	Args  []string
	Stdin []byte
	// Env, when set, is added to this process's environment for the image
	// (tests). Left empty, the image gets the default environment of its
	// token, as Windows gives any process started under another token.
	Env     []string
	Timeout time.Duration
}

// windowsHookImageStartResult is what one start printed and how it ended.
type windowsHookImageStartResult struct {
	Stdout, Stderr []byte
	ExitCode       int
	// Restricted reports that the image ran under the filtered token (no
	// Administrators group, no privileges), the token whose starts an agent
	// user's application control rules decide. TokenProblem says why not.
	Restricted   bool
	TokenProblem string
	// Token names the token the start ran with (the filtered installer
	// token, or the installer token when it could not be made).
	Token string
}

// windowsHookImageStarter starts an image once. The Windows implementation
// hides the window, inherits only the standard handles, runs the image under
// a filtered token without Administrators and ends the process tree at the
// timeout. An error means the image did not start or did not end in time;
// any exit code is a result.
type windowsHookImageStarter interface {
	Start(windowsHookImageStart) (windowsHookImageStartResult, error)
}

// windowsHookImageBuild is the build every image of the launch set must
// report: the gateway's own version and commit.
type windowsHookImageBuild struct {
	Version string
	Commit  string
}

type windowsHookImageStageRequest struct {
	Bin         string
	HookSHA256  string
	GuardSHA256 string
	Build       windowsHookImageBuild
}

func windowsHookImageJoin(dir string, names ...string) string {
	out := strings.TrimRight(dir, `\`)
	for _, name := range names {
		out += `\` + name
	}
	return out
}

func validWindowsHookImageSHA256(value string) bool {
	_, err := winpath.EnterpriseHookImageDigest(value)
	return err == nil
}

// stageWindowsHookImage puts the launch set of the transition image of
// req.Bin in its launch folder and starts it once. It returns a report with
// OK false and a reason code on any failure.
func stageWindowsHookImage(fsys windowsHookImageFS, starter windowsHookImageStarter, req windowsHookImageStageRequest) windowsHookImageStageReport {
	report := windowsHookImageStageReport{SchemaVersion: windowsHookImageReportSchema}
	fail := func(reason string, format string, args ...any) windowsHookImageStageReport {
		report.OK = false
		report.Reason = reason
		report.Error = fmt.Sprintf(format, args...)
		return report
	}
	bin := strings.TrimRight(strings.TrimSpace(req.Bin), `\`)
	hookSHA := strings.ToLower(strings.TrimSpace(req.HookSHA256))
	guardSHA := strings.ToLower(strings.TrimSpace(req.GuardSHA256))
	if !validWindowsHookImageSHA256(hookSHA) {
		return fail(windowsHookImageStageFailed, "--sha256 is not a SHA-256: %q", req.HookSHA256)
	}
	if guardSHA != "" && !validWindowsHookImageSHA256(guardSHA) {
		return fail(windowsHookImageStageFailed, "--guard-sha256 is not a SHA-256: %q", req.GuardSHA256)
	}
	if strings.TrimSpace(req.Build.Version) == "" || strings.TrimSpace(req.Build.Commit) == "" {
		return fail(windowsHookImageStageFailed, "this gateway reports no build version and commit to check the hook image against")
	}
	transitionHook := windowsHookImageJoin(bin, winpath.EnterpriseHookImageName)
	transitionGuard := windowsHookImageJoin(bin, winpath.EnterpriseHookGuardImageName)
	have, err := fsys.SHA256(transitionHook)
	if err != nil {
		return fail(windowsHookImageDigestMismatch, "read the installed hook %s: %v", transitionHook, err)
	}
	if have != hookSHA {
		return fail(windowsHookImageDigestMismatch, "the installed hook %s has sha256 %s, not the %s Setup installed", transitionHook, have, hookSHA)
	}
	// The launch set holds the guard whenever the layout has one: the
	// managed Claude Code command starts the guard beside the hook, and the
	// guard starts the hook beside itself.
	withGuard := false
	if info, err := fsys.Lstat(transitionGuard); err == nil && info.Mode().IsRegular() {
		withGuard = true
		have, err := fsys.SHA256(transitionGuard)
		if err != nil {
			return fail(windowsHookImageDigestMismatch, "read the installed hook guard %s: %v", transitionGuard, err)
		}
		if guardSHA == "" {
			guardSHA = have
		} else if have != guardSHA {
			return fail(windowsHookImageDigestMismatch, "the installed hook guard %s has sha256 %s, not the %s Setup installed", transitionGuard, have, guardSHA)
		}
	} else if guardSHA != "" {
		return fail(windowsHookImageDigestMismatch, "Setup installed the hook guard %s, but it is missing", transitionGuard)
	}
	root := winpath.EnterpriseHookImagesRoot(bin)
	folder, err := winpath.EnterpriseHookImageDir(bin, hookSHA)
	if err != nil {
		return fail(windowsHookImageStageFailed, "%v", err)
	}
	report.Folder = folder
	report.Hook = windowsHookImageJoin(folder, winpath.EnterpriseHookImageName)
	if withGuard {
		report.Guard = windowsHookImageJoin(folder, winpath.EnterpriseHookGuardImageName)
	}
	type image struct {
		source, name, sha string
	}
	images := []image{{transitionHook, winpath.EnterpriseHookImageName, hookSHA}}
	if withGuard {
		images = append(images, image{transitionGuard, winpath.EnterpriseHookGuardImageName, guardSHA})
	}

	info, err := fsys.Lstat(root)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := fsys.MkdirProtected(root); err != nil {
			return fail(windowsHookImageStageFailed, "create %s: %v", root, err)
		}
		report.Changed = true
	case err != nil:
		return fail(windowsHookImageStageFailed, "inspect %s: %v", root, err)
	case !windowsHookImagePlainDir(info):
		return fail(windowsHookImageStageFailed, "%s is not a plain folder; remove it, then run the same command again", root)
	default:
		report.Notes = append(report.Notes, removeWindowsHookImageStaging(fsys, root)...)
	}

	info, err = fsys.Lstat(folder)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		suffix, err := fsys.RandomHex(16)
		if err != nil {
			return fail(windowsHookImageStageFailed, "name a staging folder: %v", err)
		}
		staging := windowsHookImageJoin(root, winpath.EnterpriseHookStagingDirName(suffix))
		if err := fsys.MkdirProtected(staging); err != nil {
			return fail(windowsHookImageStageFailed, "create %s: %v", staging, err)
		}
		for _, item := range images {
			target := windowsHookImageJoin(staging, item.name)
			if problem := placeWindowsHookImage(fsys, item.source, target, item.sha); problem != "" {
				_ = fsys.RemoveAll(staging)
				return fail(windowsHookImageStageFailed, "%s", problem)
			}
		}
		// The folder appears under its name only complete: no agent config
		// names it before the lifecycle's configs switch, and a crash leaves
		// only a staging folder the next stage or prune removes.
		if err, busy := renameWindowsHookImageFolder(fsys, staging, folder); err != nil {
			_ = fsys.RemoveAll(staging)
			if busy {
				return fail(windowsHookImagePublishBusy, "publish %s: %v; another program (an antivirus scan of the new images) keeps a handle in the folder", folder, err)
			}
			return fail(windowsHookImageStageFailed, "publish %s: %v", folder, err)
		}
		report.CreatedFolder = true
		report.Changed = true
	case err != nil:
		return fail(windowsHookImageStageFailed, "inspect %s: %v", folder, err)
	case !windowsHookImagePlainDir(info):
		return fail(windowsHookImageStageFailed, "%s is not a plain folder; remove it, then run the same command again", folder)
	default:
		// A repair or an ensure of the installed release: an exact image is
		// kept, so a repeated ensure changes nothing; a changed or missing
		// one is put back the way the guardian restores the transition
		// image.
		for _, item := range images {
			target := windowsHookImageJoin(folder, item.name)
			changed, problem := keepWindowsHookImage(fsys, item.source, target, item.sha)
			if problem != "" {
				return fail(windowsHookImageStageFailed, "%s", problem)
			}
			if changed {
				report.Changed = true
				report.Notes = append(report.Notes, "replaced "+target+", which was not this release's image")
			}
		}
	}

	notes, problem := checkWindowsHookImageStarts(starter, report.Hook, report.Guard, req.Build)
	report.Notes = append(report.Notes, notes...)
	if problem != "" {
		return fail(windowsHookImageStartFailed, "%s", problem)
	}
	report.Notes = append(report.Notes, clearWindowsHookImagesRetired(fsys, root)...)
	report.OK = true
	return report
}

// renameWindowsHookImageFolder renames from to to, retrying while Windows
// refuses it for an open handle (windowsHookImageRenameBusy). busy reports
// that the last refusal was of that kind.
func renameWindowsHookImageFolder(fsys windowsHookImageFS, from, to string) (error, bool) {
	wait := windowsHookImagePublishFirstWait
	for attempt := 1; ; attempt++ {
		err := fsys.Rename(from, to)
		if err == nil {
			return nil, false
		}
		if !windowsHookImageRenameBusy(err) {
			return err, false
		}
		if attempt == windowsHookImagePublishTries {
			return fmt.Errorf("%w (still refused after %d tries)", err, attempt), true
		}
		windowsHookImageSleep(wait)
		wait *= 2
		if wait > windowsHookImagePublishMaxWait {
			wait = windowsHookImagePublishMaxWait
		}
	}
}

// windowsHookImageRenameBusy reports a rename Windows refused because a
// handle is open in the folder: access denied (a running image, or a scanner
// handle without delete sharing) or a sharing violation.
func windowsHookImageRenameBusy(err error) bool {
	return errors.Is(err, fs.ErrPermission) || windowsHookImageSharingViolation(err)
}

func windowsHookImagePlainDir(info fs.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) == 0
}

// placeWindowsHookImage writes a new image and checks its bytes.
func placeWindowsHookImage(fsys windowsHookImageFS, source, target, sha string) string {
	if err := fsys.PlaceImage(source, target); err != nil {
		return fmt.Sprintf("write %s: %v", target, err)
	}
	if have, err := fsys.SHA256(target); err != nil || have != sha {
		return fmt.Sprintf("the copy %s does not have sha256 %s (%s, %v)", target, sha, have, err)
	}
	return ""
}

// keepWindowsHookImage keeps an exact image and puts back a missing or
// changed one. A folder or link at the image's name is refused.
func keepWindowsHookImage(fsys windowsHookImageFS, source, target, sha string) (bool, string) {
	info, err := fsys.Lstat(target)
	if errors.Is(err, fs.ErrNotExist) {
		if problem := placeWindowsHookImage(fsys, source, target, sha); problem != "" {
			return false, problem
		}
		return true, ""
	}
	if err != nil {
		return false, fmt.Sprintf("inspect %s: %v", target, err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Sprintf("%s is not a regular file; remove it, then run the same command again", target)
	}
	if have, err := fsys.SHA256(target); err == nil && have == sha && info.Size() > 0 {
		return false, ""
	}
	if err := fsys.ReplaceImage(source, target); err != nil {
		return false, fmt.Sprintf("replace %s: %v", target, err)
	}
	if have, err := fsys.SHA256(target); err != nil || have != sha {
		return false, fmt.Sprintf("the replaced %s does not have sha256 %s (%s, %v)", target, sha, have, err)
	}
	return true, ""
}

// windowsHookImageIdentity is the hook's --version-json document.
type windowsHookImageIdentity struct {
	SchemaVersion int    `json:"schema_version"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	Built         string `json:"built,omitempty"`
}

// checkWindowsHookImageStarts starts the staged launch set the way an agent
// will once its config switches: the hook and the guard must start and report
// this gateway's build, and the managed Claude Code command (cmd.exe, the
// guard and the hook from the new folder) must answer a harmless PreToolUse
// call. Every start runs under the filtered token, so an application control
// or antivirus rule that blocks the new folder for users fails here, before
// any config names it. It returns notes and a problem ("" when it passes).
func checkWindowsHookImageStarts(starter windowsHookImageStarter, hook, guard string, build windowsHookImageBuild) ([]string, string) {
	var notes []string
	tokenNoted := false
	start := func(req windowsHookImageStart) (windowsHookImageStartResult, error) {
		req.Timeout = windowsHookImageStartTimeout
		result, err := starter.Start(req)
		if !tokenNoted {
			tokenNoted = true
			switch {
			case !result.Restricted && result.TokenProblem != "":
				notes = append(notes, "start check ran with the installer token: "+result.TokenProblem)
			case result.Token != "":
				notes = append(notes, "start check ran as "+result.Token)
			}
		}
		return result, err
	}
	ranAs := func(result windowsHookImageStartResult) string {
		token := result.Token
		if token == "" {
			token = "the installer token"
		}
		return fmt.Sprintf(" [exit %d, ran as %s, stderr: %q]", result.ExitCode, token, boundedWindowsHookImageText(result.Stderr))
	}
	result, err := start(windowsHookImageStart{Path: hook, Args: []string{"--version-json"}})
	if err != nil {
		return notes, fmt.Sprintf("the staged hook %s did not start: %v", hook, err) + ranAs(result)
	}
	if result.ExitCode != 0 {
		return notes, fmt.Sprintf("the staged hook %s ended with status %d", hook, result.ExitCode) + ranAs(result)
	}
	output := result.Stdout
	if len(output) > windowsHookImageOutputLimit {
		return notes, fmt.Sprintf("the staged hook %s printed more than %d bytes", hook, windowsHookImageOutputLimit)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	var identity windowsHookImageIdentity
	if err := decoder.Decode(&identity); err != nil {
		return notes, fmt.Sprintf("the staged hook %s printed no version document: %q", hook, boundedWindowsHookImageText(output))
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return notes, fmt.Sprintf("the staged hook %s printed more than one version document", hook)
	}
	if identity.SchemaVersion != 1 || identity.Name != "defenseclaw-hook" ||
		identity.Version != build.Version || identity.Commit != build.Commit {
		return notes, fmt.Sprintf("the staged hook %s reports %s %s (commit %s), not defenseclaw-hook %s (commit %s)",
			hook, identity.Name, identity.Version, identity.Commit, build.Version, build.Commit)
	}
	if guard != "" {
		result, err = start(windowsHookImageStart{Path: guard, Args: []string{"--version"}})
		if err != nil {
			return notes, fmt.Sprintf("the staged hook guard %s did not start: %v", guard, err) + ranAs(result)
		}
		want := fmt.Sprintf("defenseclaw-hook-guard version %s (commit=%s,", build.Version, build.Commit)
		if result.ExitCode != 0 || len(result.Stdout) > windowsHookImageOutputLimit ||
			!strings.HasPrefix(strings.TrimSpace(string(result.Stdout)), want) {
			return notes, fmt.Sprintf("the staged hook guard %s reports %q (status %d), not %q",
				guard, boundedWindowsHookImageText(result.Stdout), result.ExitCode, want) + ranAs(result)
		}
	}
	command, args := windowsHookImageSelfTestCommand(hook, guard)
	result, err = start(windowsHookImageStart{Path: command, Args: args, Stdin: windowsHookImageSelfTestInput})
	if err != nil {
		return notes, fmt.Sprintf("the managed Claude Code hook command of %s did not start: %v", hook, err) + ranAs(result)
	}
	if problem := windowsHookImageSelfTestProblem(result); problem != "" {
		return notes, fmt.Sprintf("the managed Claude Code hook command of %s %s", hook, problem) + ranAs(result)
	}
	return notes, ""
}

// windowsHookImageSelfTestArgs are the managed Claude Code hook arguments the
// writer registers for the launch hook.
var windowsHookImageSelfTestArgs = []string{"hook", "--connector", "claudecode", "--enterprise-managed"}

// windowsHookImageSelfTestInput is the canned PreToolUse call of the self
// test: a Read of a file that does not exist. During Setup the lifecycle
// holds the gateway, so the managed hook answers it closed (a deny), which is
// a pass: the chain started from the new folder and answered. The pass rule
// (windowsHookImageSelfTestProblem): exit 0 (allow, with no output or one
// JSON answer) or exit 2 with a reason (one JSON answer on stdout or text on
// stderr); a guard or cmd.exe message that the hook or guard could not
// start, any other status, more than one answer or a bare exit 2 fail. The
// managed hook may write one audit line for this call (a row in the audit
// store and the SIEM export, tool Read of
// defenseclaw-hook-image-self-test.txt), attributed to SYSTEM (or the
// administrator who ran Setup), the account behind the filtered token.
var windowsHookImageSelfTestInput = []byte(`{"session_id":"defenseclaw-hook-image-self-test",` +
	`"transcript_path":"","cwd":"C:\\Windows\\Temp","hook_event_name":"PreToolUse","tool_name":"Read",` +
	`"tool_input":{"file_path":"C:\\Windows\\Temp\\defenseclaw-hook-image-self-test.txt"}}` + "\n")

// windowsHookImageSelfTestCommand is the command a managed Claude Code
// session runs for the launch hook: the writer's cmd.exe guard wrapper when
// the launch set has a guard (connector.ClaudeCodeManagedGuardInvocation),
// else the hook itself.
func windowsHookImageSelfTestCommand(hook, guard string) (string, []string) {
	if guard != "" {
		if command, args, ok := connector.ClaudeCodeManagedGuardInvocation("PreToolUse", hook, windowsHookImageSelfTestArgs); ok {
			return command, args
		}
	}
	return hook, append([]string(nil), windowsHookImageSelfTestArgs...)
}

// windowsHookImageSelfTestNotStarted are the texts the guard and its cmd.exe
// wrapper print when the hook or the guard could not start: an answer, but
// not one from the staged hook.
var windowsHookImageSelfTestNotStarted = []string{
	hookguard.MissingMessage,
	hookguard.CannotStartMessage,
	hookguard.NonBlockingExitMessage,
	hookguard.OpenExitMessage,
	"could not start its Claude Code hook guard",
}

// windowsHookImageSelfTestProblem judges the self test's answer: status 0 or
// 2 (an allow or a block, the only statuses the managed Claude command
// returns for an answer), at most one JSON answer on standard output, and no
// text that says the guard or the hook did not start. "" is a pass.
func windowsHookImageSelfTestProblem(result windowsHookImageStartResult) string {
	stderr := string(result.Stderr)
	for _, marker := range windowsHookImageSelfTestNotStarted {
		if strings.Contains(stderr, marker) {
			return "could not start the staged images: " + boundedWindowsHookImageText(result.Stderr)
		}
	}
	if result.ExitCode != 0 && result.ExitCode != 2 {
		return fmt.Sprintf("ended with status %d (%s)", result.ExitCode, boundedWindowsHookImageText(result.Stderr))
	}
	if len(result.Stdout) > windowsHookImageOutputLimit {
		return fmt.Sprintf("printed more than %d bytes", windowsHookImageOutputLimit)
	}
	output := bytes.TrimSpace(result.Stdout)
	if len(output) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(output))
		var answer map[string]any
		if err := decoder.Decode(&answer); err != nil {
			return fmt.Sprintf("printed no hook answer: %q", boundedWindowsHookImageText(output))
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return "printed more than one hook answer"
		}
	}
	if result.ExitCode == 2 && len(output) == 0 && strings.TrimSpace(stderr) == "" {
		return "blocked with no reason (status 2, no output)"
	}
	return ""
}

func boundedWindowsHookImageText(output []byte) string {
	text := strings.TrimSpace(string(output))
	if len(text) > 200 {
		text = text[:200] + "..."
	}
	return text
}

// removeWindowsHookImageStaging removes the staging folders an interrupted
// stage left (nothing starts from them) once they are older than
// windowsHookImageStagingMinAge: a younger one may be another stage's or
// prune's folder in flight.
func removeWindowsHookImageStaging(fsys windowsHookImageFS, root string) []string {
	entries, err := fsys.ReadDir(root)
	if err != nil {
		return []string{fmt.Sprintf("list %s: %v", root, err)}
	}
	var notes []string
	for _, entry := range entries {
		if !winpath.IsEnterpriseHookStagingDirName(entry.Name()) || !entry.IsDir() || entry.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			continue
		}
		path := windowsHookImageJoin(root, entry.Name())
		if info, err := entry.Info(); err != nil || windowsHookImageNow().Sub(info.ModTime()) < windowsHookImageStagingMinAge {
			continue
		}
		if err := fsys.RemoveAll(path); err != nil {
			notes = append(notes, fmt.Sprintf("the staging folder %s stays: %v", path, err))
		}
	}
	return notes
}

// pruneWindowsHookImages removes the launch folders of bin no agent can
// still start, and the staging folders an interrupted stage left. A launch
// folder goes only when it is neither current nor kept, no DefenseClaw-written
// config names it (policy.Scan, which must be complete), and it was
// superseded at least hookImageRetainAfterSupersede ago. A folder an image of
// which is still running stays and is reported; so is anything that is not a
// launch or staging folder, which prune never touches.
func pruneWindowsHookImages(fsys windowsHookImageFS, bin string, keep []string, policy windowsHookImagePrunePolicy) windowsHookImagePruneReport {
	report := windowsHookImagePruneReport{
		SchemaVersion: windowsHookImageReportSchema,
		Removed:       []string{},
		Kept:          []string{},
		Retained:      []windowsHookImageRetained{},
		InUse:         []windowsHookImageInUse{},
	}
	bin = strings.TrimRight(strings.TrimSpace(bin), `\`)
	keepSet := map[string]bool{}
	for _, name := range keep {
		name = strings.ToLower(strings.TrimSpace(name))
		if !winpath.IsEnterpriseHookImageDirName(name) {
			report.Error = fmt.Sprintf("--keep %q is not a launch folder name (16 hex digits)", name)
			return report
		}
		keepSet[name] = true
	}
	root := winpath.EnterpriseHookImagesRoot(bin)
	info, err := fsys.Lstat(root)
	if errors.Is(err, fs.ErrNotExist) {
		report.OK = true
		return report
	}
	if err != nil {
		report.Error = fmt.Sprintf("inspect %s: %v", root, err)
		return report
	}
	if !windowsHookImagePlainDir(info) {
		report.Error = fmt.Sprintf("%s is not a plain folder", root)
		return report
	}
	// The current folder is never removed, whatever the caller kept: it is
	// the one every agent config names.
	current, err := fsys.SHA256(windowsHookImageJoin(bin, winpath.EnterpriseHookImageName))
	if err != nil {
		report.Error = fmt.Sprintf("read the installed hook to find the current launch folder: %v", err)
		return report
	}
	currentName, err := winpath.EnterpriseHookImageDigest(current)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	keepSet[currentName] = true
	entries, err := fsys.ReadDir(root)
	if err != nil {
		report.Error = fmt.Sprintf("list %s: %v", root, err)
		return report
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	staged := windowsHookImageStageTimes(fsys, root, entries)
	for _, note := range policy.Scan.Incomplete {
		report.Notes = append(report.Notes, "scan_incomplete: "+note)
	}
	for _, note := range policy.Scan.Skipped {
		report.Notes = append(report.Notes, "skipped_unsafe: "+note)
	}
	for _, entry := range entries {
		name := entry.Name()
		path := windowsHookImageJoin(root, name)
		launch := winpath.IsEnterpriseHookImageDirName(name)
		staging := winpath.IsEnterpriseHookStagingDirName(name)
		if !launch && !staging {
			report.Notes = append(report.Notes, "left "+path+": not a launch or staging folder")
			continue
		}
		if !entry.IsDir() || entry.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			report.Notes = append(report.Notes, "left "+path+": not a plain folder")
			continue
		}
		if launch && keepSet[strings.ToLower(name)] {
			report.Kept = append(report.Kept, path)
			continue
		}
		if launch {
			if why := windowsHookImageRetainReason(strings.ToLower(name), staged, policy); why != "" {
				report.Retained = append(report.Retained, windowsHookImageRetained{Folder: path, Why: why})
				continue
			}
		}
		target := path
		if launch {
			// A launch folder goes only whole: it is first renamed to a
			// staging name, which Windows refuses while a program runs (or
			// holds) a file in it, so a session that still runs the old
			// image keeps its whole launch set, and no session meets half
			// of one. Nothing names a staging folder.
			suffix, err := fsys.RandomHex(16)
			if err != nil {
				report.InUse = append(report.InUse, windowsHookImageInUse{Folder: path, Error: err.Error()})
				continue
			}
			aside := windowsHookImageJoin(root, winpath.EnterpriseHookStagingDirName(suffix))
			if err := fsys.Rename(path, aside); err != nil {
				report.InUse = append(report.InUse, windowsHookImageInUse{Folder: path, Error: err.Error()})
				continue
			}
			target = aside
		}
		if err := fsys.RemoveAll(target); err != nil {
			if launch {
				// Out of service already; the next stage or prune removes it.
				report.Removed = append(report.Removed, path)
				report.Notes = append(report.Notes, fmt.Sprintf("the retired folder %s stays until the next stage or prune: %v", target, err))
				continue
			}
			report.InUse = append(report.InUse, windowsHookImageInUse{Folder: path, Error: err.Error()})
			continue
		}
		report.Removed = append(report.Removed, path)
	}
	report.OK = true
	return report
}

// sameWindowsManagedHookImage reports two hook paths of one install: the
// same path, or the same image kind of the same bin (the transition image or
// any launch image, GAP-0751). A lifecycle or teardown journal written
// before an upgrade names the image that was current then.
func sameWindowsManagedHookImage(a, b string) bool {
	return a == b || winpath.SameEnterpriseHookImageFamily(a, b)
}

// windowsHookImageVerifyProblem is the status and verify finding for a
// standalone install's launch set: "" when the launch set is staged and
// exact, else what is wrong. A standalone install of this release always has
// one after Setup; without it agent configs name the transition image, which
// the next upgrade replaces in place.
func windowsHookImageVerifyProblem(image winpath.EnterpriseHookImage) string {
	switch image.State {
	case winpath.EnterpriseHookImageStaged:
		return ""
	case winpath.EnterpriseHookImageLegacyLayout:
		return fmt.Sprintf("%s has no launch folder (bin\\hooks); agent hooks start the transition image %s, which an upgrade replaces in place", image.Bin, image.Hook)
	default:
		return fmt.Sprintf("the launch set of %s is not staged: %s; agent hooks start the transition image %s", image.Bin, image.Problem, image.Hook)
	}
}
