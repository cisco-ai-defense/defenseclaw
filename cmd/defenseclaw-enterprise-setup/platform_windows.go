// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const (
	enterpriseSetupStagePrefix = managed.SetupStagePrefix
	enterpriseSetupStageSDDL   = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	// enterpriseSetupScratchDirName is a dedicated subdirectory under
	// stageRoot pointed at by TEMP/TMP/LOCALAPPDATA/APPDATA/USERPROFILE/HOME
	// so PowerShell and the lifecycle can create scratch files beside, not
	// among, the staged payload files. Cleanup removes the whole stage.
	enterpriseSetupScratchDirName = "scratch"
)

// enterpriseSetupStage is one run's protected staging directory. The
// directory is held open without delete sharing, and each staged file is held
// open for reading only from its digest check until the lifecycle child
// exits, so nothing can rename, replace or rewrite what was verified.
type enterpriseSetupStage struct {
	root     string
	parent   string
	rootPin  *managed.SetupPin
	filePins []*managed.SetupPin
	cleaned  bool
	// refused marks a stage path that cleanup will not touch at all: it is
	// outside the staging roots or no longer names the directory this run
	// created, so nothing is scheduled for removal either.
	refused bool
}

func executeEnterpriseSetup(
	parent context.Context,
	opts enterpriseSetupOptions,
	stdout, stderr io.Writer,
) (exitCode int, returnErr error) {
	if runtime.GOARCH != "amd64" {
		return 0, errors.New("DefenseClaw enterprise Setup requires native Windows x64")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return 0, errors.New("DefenseClaw enterprise Setup requires an elevated administrator token")
	}
	payload, err := loadEmbeddedEnterprisePayload()
	if err != nil {
		return 0, err
	}
	if payload.Manifest.Unsigned && !opts.AllowUnsigned {
		return 0, errors.New("this enterprise Setup is unsigned and can run only with --allow-unsigned in exact disposable certification scope")
	}
	if !payload.Manifest.Unsigned && opts.AllowUnsigned {
		return 0, errors.New("--allow-unsigned is forbidden for a signed enterprise Setup payload")
	}
	for _, input := range []struct {
		label string
		value *string
	}{
		{label: "config", value: &opts.Config},
		{label: "manifest", value: &opts.Manifest},
	} {
		if strings.TrimSpace(*input.value) == "" {
			continue
		}
		canonical, err := validateEnterpriseSetupInput(*input.value, input.label)
		if err != nil {
			return 0, err
		}
		*input.value = canonical
	}

	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return 0, fmt.Errorf("resolve trusted ProgramData for enterprise Setup staging: %w", err)
	}
	// No machine-wide lock is taken, so only leftovers older than any run
	// can last are swept; a concurrent run's stage is always younger.
	managed.SweepSetupLeftovers(
		managed.SetupStagingRoots(programData),
		managed.SetupLeftoverPrefixes(),
		time.Now(),
	)
	stage, err := stageEnterprisePayload(payload, programData)
	if err != nil {
		return 0, err
	}
	// Cleanup never changes the exit code: the lifecycle's own result is
	// what the deployment system acts on, and a stage that cannot be removed
	// now is scheduled for removal at the next restart.
	defer stage.cleanupAndAccept()

	arguments := enterpriseLifecycleArguments(stage.root, opts)
	childEnvironment, err := trustedEnterpriseSetupEnvironment(stage.root)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(parent, opts.LifecycleTimeout)
	defer cancel()
	cliPath := filepath.Join(stage.root, "defenseclaw.exe")
	child := processutil.CommandContext(ctx, cliPath, arguments...)
	child.Dir = stage.root
	child.Env = childEnvironment
	// Standard output carries the lifecycle's machine-readable result and is
	// republished on Setup's stdout; standard error carries diagnostics and
	// resilience markers and goes to Setup's stderr, so stdout stays JSON-only
	// under --json.
	childStdout, childStderr, runErr := processutil.OutputTree(child, false)
	stage.releaseFiles()
	childStdout = boundLifecycleStream(childStdout, "stdout")
	childStderr = boundLifecycleStream(childStderr, "stderr")
	if len(childStdout) != 0 {
		destination := stdout
		if runErr != nil && !opts.JSON {
			destination = stderr
		}
		if _, err := destination.Write(childStdout); err != nil {
			return 0, fmt.Errorf("publish enterprise lifecycle output: %w", err)
		}
	}
	if len(childStderr) != 0 {
		_, _ = stderr.Write(childStderr)
	}
	stage.cleanupAndAccept()
	if ctx.Err() != nil {
		return 0, fmt.Errorf("enterprise %s exceeded the bounded %s timeout: %w", opts.Action, opts.LifecycleTimeout, ctx.Err())
	}
	if runErr == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) {
		return 0, fmt.Errorf("launch enterprise lifecycle: %w", runErr)
	}
	// The public enterprise lifecycle promises only 0 and 1603. Collapse any
	// unexpected child status to the same fatal-install code so AVC never
	// mistakes a partial transaction for reboot-required success.
	return enterpriseFailureExitCode, nil
}

// boundLifecycleStream keeps the tail of an oversized lifecycle stream and
// logs that the head was dropped.
func boundLifecycleStream(output []byte, stream string) []byte {
	bounded, truncated := boundedLifecycleTail(output, maximumLifecycleOutput)
	if truncated {
		managed.EmitResilienceEvent(managed.MarkerAccept, map[string]string{
			"object": "enterprise lifecycle " + stream,
			"reason": fmt.Sprintf(
				"lifecycle %s was %d bytes; republishing only its last %d bytes, which hold the result",
				stream, len(output), len(bounded),
			),
		})
	}
	return bounded
}

func validateEnterpriseSetupInput(value, label string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.Contains(value, "%") ||
		strings.ContainsAny(value, "\x00\r\n") || !filepath.IsAbs(value) {
		return "", fmt.Errorf("%s path is empty, relative, padded, or environment-expanded", label)
	}
	full, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("resolve %s path: %w", label, err)
	}
	volume := filepath.VolumeName(full)
	if len(volume) != 2 || volume[1] != ':' || strings.HasPrefix(full, `\\`) ||
		strings.HasPrefix(full, `//`) || strings.HasPrefix(full, `\\?\`) ||
		strings.HasPrefix(full, `\\.\`) {
		return "", fmt.Errorf("%s must use an absolute local Win32 drive path", label)
	}
	info, err := os.Lstat(full)
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", label, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is not a regular non-link file: %s", label, full)
	}
	// The administrator who ran Setup legitimately owns the files they were
	// handed (a download, a share copy), so that account is trusted as the
	// owner and writer of --config and --manifest; the installer re-stamps
	// the canonical descriptor on the copies it installs.
	invoker, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || invoker == nil || invoker.User.Sid == nil {
		return "", fmt.Errorf("resolve the elevated administrator account for %s: %w", label, err)
	}
	if err := managed.ValidateSetupPathWithWriter(full, label, managed.SetupPathFile, invoker.User.Sid); err != nil {
		return "", fmt.Errorf("refusing untrusted %s: %w", label, err)
	}
	return filepath.Clean(full), nil
}

// stageEnterprisePayload stages the payload under ProgramData. When
// Controlled Folder Access or an endpoint product refuses that with access
// denied, it stages once more under an existing ProgramData\Cisco (never
// created here) and, if that is refused too, fails with a prerequisite that
// names the block and its remedy.
func stageEnterprisePayload(payload enterprisePayload, programData string) (*enterpriseSetupStage, error) {
	stage, err := stageEnterprisePayloadUnder(payload, programData)
	if err == nil || !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return stage, err
	}
	parents := []string{filepath.Clean(programData)}
	firstErr := err
	if fallback, ok := managed.SetupStagingFallbackRoot(programData); ok {
		parents = append(parents, fallback)
		stage, fallbackErr := stageEnterprisePayloadUnder(payload, fallback)
		if fallbackErr == nil {
			managed.EmitResilienceEvent(managed.MarkerAccept, map[string]string{
				"path":   stage.root,
				"object": "enterprise Setup staging directory",
				"reason": "ProgramData refused the staging directory (" + firstErr.Error() + "); staged under " + fallback,
			})
			return stage, nil
		}
		if !errors.Is(fallbackErr, windows.ERROR_ACCESS_DENIED) {
			return nil, fallbackErr
		}
		firstErr = errors.Join(firstErr, fallbackErr)
	}
	setupPath, _ := os.Executable()
	prereq := stagingBlockedPrereq(setupPath, parents, firstErr)
	log.Print(prereq)
	return nil, errors.New(prereq)
}

func stageEnterprisePayloadUnder(payload enterprisePayload, parent string) (*enterpriseSetupStage, error) {
	stage, err := createEnterpriseSetupStage(parent)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*enterpriseSetupStage, error) {
		if cleanupErr := stage.cleanup(); cleanupErr != nil {
			stage.scheduleAtRestart(cleanupErr)
		}
		return nil, cause
	}
	scratchDir := filepath.Join(stage.root, enterpriseSetupScratchDirName)
	if err := managed.CreateSetupDirectory(scratchDir); err != nil {
		return fail(fmt.Errorf("create enterprise Setup scratch directory: %w", err))
	}
	for _, name := range requiredPayloadFiles {
		expected, ok := payload.Files[name]
		if !ok {
			return fail(fmt.Errorf("validated enterprise payload is missing manifest entry %s", name))
		}
		pin, err := stageEnterprisePayloadFile(payload, stage.root, name, expected)
		if err != nil {
			return fail(err)
		}
		stage.filePins = append(stage.filePins, pin)
	}
	return stage, nil
}

// stageEnterprisePayloadFile writes one payload file Administrators-owned,
// reopens it read-share-only, proves the reopened handle is the file just
// written, applies the Setup trust rule and verifies the digest through the
// pinned handle. The pin stays open until the lifecycle child exits.
func stageEnterprisePayloadFile(
	payload enterprisePayload,
	stageRoot, name string,
	expected enterprisePayloadManifestFile,
) (*managed.SetupPin, error) {
	path := filepath.Join(stageRoot, name)
	file, err := managed.CreateSetupFile(path)
	if err != nil {
		return nil, fmt.Errorf("create staged enterprise payload %s: %w", name, err)
	}
	source, sourceErr := payload.PayloadFS.Open("payload/" + name)
	if sourceErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("open embedded enterprise payload %s: %w", name, sourceErr)
	}
	written, writeErr := io.Copy(file, io.LimitReader(source, maximumPayloadFileBytes+1))
	sourceCloseErr := source.Close()
	syncErr := file.Sync()
	writtenID, idErr := managed.SetupFileIDOfFile(file)
	closeErr := file.Close()
	if err := errors.Join(writeErr, sourceCloseErr, syncErr, idErr, closeErr); err != nil {
		return nil, fmt.Errorf("write staged enterprise payload %s: %w", name, err)
	}
	if written <= 0 || written > maximumPayloadFileBytes {
		return nil, fmt.Errorf("staged enterprise payload has invalid size: %s", name)
	}
	pin, err := managed.PinSetupPath(path, managed.SetupPathFile)
	if err != nil {
		return nil, fmt.Errorf("open staged enterprise payload for verification %s: %w", name, err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = pin.Close()
		}
	}()
	if pin.ID() != writtenID {
		return nil, fmt.Errorf("staged enterprise payload %s changed between write and verification", name)
	}
	if err := managed.ValidateSetupPath(path, "staged enterprise payload "+name, managed.SetupPathFile); err != nil {
		return nil, err
	}
	if err := pin.Rewind(); err != nil {
		return nil, fmt.Errorf("verify staged enterprise payload %s: %w", name, err)
	}
	hasher := sha256.New()
	verifiedBytes, verifyErr := io.Copy(hasher, io.LimitReader(pin, maximumPayloadFileBytes+1))
	if verifyErr != nil {
		return nil, fmt.Errorf("verify staged enterprise payload %s: %w", name, verifyErr)
	}
	if verifiedBytes != written || verifiedBytes != expected.Size ||
		!strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), expected.SHA256) {
		return nil, fmt.Errorf("staged enterprise payload digest mismatch: %s", name)
	}
	keep = true
	return pin, nil
}

func createEnterpriseSetupStage(parent string) (*enterpriseSetupStage, error) {
	descriptor, err := windows.SecurityDescriptorFromString(enterpriseSetupStageSDDL)
	if err != nil {
		return nil, fmt.Errorf("build enterprise Setup staging DACL: %w", err)
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	for attempt := 0; attempt < 4; attempt++ {
		capability := make([]byte, 16)
		if _, err := rand.Read(capability); err != nil {
			return nil, fmt.Errorf("generate enterprise Setup staging capability: %w", err)
		}
		path := filepath.Join(parent, enterpriseSetupStagePrefix+hex.EncodeToString(capability))
		pathPointer, err := winpath.UTF16Ptr(path)
		if err != nil {
			return nil, fmt.Errorf("encode enterprise Setup staging path: %w", err)
		}
		if err := windows.CreateDirectory(pathPointer, attributes); err != nil {
			if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
				continue
			}
			return nil, fmt.Errorf("create protected enterprise Setup staging directory: %w", err)
		}
		pin, err := managed.PinSetupPath(path, managed.SetupPathDirectory)
		if err != nil {
			_ = os.Remove(path)
			return nil, fmt.Errorf("hold enterprise Setup staging directory: %w", err)
		}
		stage := &enterpriseSetupStage{root: filepath.Clean(path), parent: filepath.Clean(parent), rootPin: pin}
		if err := managed.ValidateSetupPath(path, "enterprise Setup staging directory", managed.SetupPathDirectory); err != nil {
			if cleanupErr := stage.cleanup(); cleanupErr != nil {
				stage.scheduleAtRestart(cleanupErr)
			}
			return nil, err
		}
		return stage, nil
	}
	return nil, errors.New("create enterprise Setup staging directory: random path collisions exhausted")
}

// releaseFiles closes the staged-file pins once the lifecycle child exited.
func (stage *enterpriseSetupStage) releaseFiles() {
	for _, pin := range stage.filePins {
		_ = pin.Close()
	}
	stage.filePins = nil
}

// cleanup removes the stage through a no-follow walk after proving the path
// still names the directory this run created and holds. Entries the
// lifecycle left beside the payload are accepted, logged and removed.
func (stage *enterpriseSetupStage) cleanup() error {
	if stage == nil || stage.cleaned {
		return nil
	}
	stage.releaseFiles()
	defer func() { _ = stage.rootPin.Close() }()
	if !isEnterpriseSetupStagingChild(stage.root, stage.parent) {
		stage.refused = true
		return fmt.Errorf("refusing unsafe enterprise Setup staging cleanup: %s", stage.root)
	}
	if stage.rootPin == nil {
		return fmt.Errorf("enterprise Setup staging directory is not held: %s", stage.root)
	}
	same, err := stage.rootPin.Matches(stage.root)
	if err != nil {
		return fmt.Errorf("inspect enterprise Setup staging directory before cleanup: %w", err)
	}
	if !same {
		stage.refused = true
		return fmt.Errorf("refusing enterprise Setup cleanup: %s no longer names the staged directory", stage.root)
	}
	stage.acceptUnexpectedEntries()
	id := stage.rootPin.ID()
	// The removal walk needs delete access to the stage itself, which the
	// pin's sharing denies; the file-ID check above and the one inside the
	// walk bracket the release.
	_ = stage.rootPin.Close()
	if err := managed.RemoveSetupTreeIfSame(stage.root, id); err != nil {
		return err
	}
	stage.cleaned = true
	return nil
}

func (stage *enterpriseSetupStage) acceptUnexpectedEntries() {
	entries, err := os.ReadDir(stage.root)
	if err != nil {
		return
	}
	expected := map[string]bool{enterpriseSetupScratchDirName: true}
	for _, name := range requiredPayloadFiles {
		expected[strings.ToLower(name)] = true
	}
	var unexpected []string
	for _, entry := range entries {
		if !expected[strings.ToLower(entry.Name())] {
			unexpected = append(unexpected, entry.Name())
		}
	}
	if len(unexpected) == 0 {
		return
	}
	sort.Strings(unexpected)
	managed.EmitResilienceEvent(managed.MarkerAccept, map[string]string{
		"path":    stage.root,
		"object":  "enterprise Setup staging directory",
		"entries": strings.Join(unexpected, ";"),
		"reason":  "the lifecycle left entries beside the staged payload; removing them with the stage",
	})
}

// cleanupAndAccept runs cleanup once and, when it fails, schedules what is
// left for removal at the next restart and logs the acceptance. It never
// fails the run.
func (stage *enterpriseSetupStage) cleanupAndAccept() {
	if stage == nil || stage.cleaned {
		return
	}
	if err := stage.cleanup(); err != nil {
		stage.scheduleAtRestart(err)
	}
}

func (stage *enterpriseSetupStage) scheduleAtRestart(cause error) {
	stage.cleaned = true
	fields := map[string]string{
		"path":   stage.root,
		"object": "enterprise Setup staging directory",
		"reason": "staging cleanup failed; the lifecycle result stands: " + cause.Error(),
	}
	if !stage.refused && isEnterpriseSetupStagingChild(stage.root, stage.parent) {
		if err := managed.ScheduleSetupTreeRemovalAtReboot(stage.root); err != nil {
			fields["restart_removal"] = "not scheduled: " + err.Error()
		} else {
			fields["restart_removal"] = "scheduled"
		}
	}
	managed.EmitResilienceEvent(managed.MarkerAccept, fields)
}

// isEnterpriseSetupStagingChild reports whether stageRoot is a capability
// directory directly under parent, and parent is ProgramData or
// ProgramData\Cisco.
func isEnterpriseSetupStagingChild(stageRoot, parent string) bool {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return false
	}
	roots := []string{filepath.Clean(programData), filepath.Join(filepath.Clean(programData), "Cisco")}
	allowedParent := false
	for _, root := range roots {
		if strings.EqualFold(filepath.Clean(parent), root) {
			allowedParent = true
		}
	}
	return allowedParent &&
		managed.IsSetupStagingChild(stageRoot, []string{parent}, []string{enterpriseSetupStagePrefix})
}

func enterpriseLifecycleArguments(stageRoot string, opts enterpriseSetupOptions) []string {
	arguments := []string{"enterprise", "windows", opts.Action, "--installer", filepath.Join(stageRoot, "install-enterprise.ps1")}
	mutation := opts.Action == "install" || opts.Action == "upgrade" || opts.Action == "repair"
	appendValue := func(flag, value string) {
		if strings.TrimSpace(value) != "" {
			arguments = append(arguments, flag, value)
		}
	}
	if mutation {
		appendValue("--broker-binary", filepath.Join(stageRoot, "defenseclaw-cmid-broker.exe"))
		appendValue("--gateway-binary", filepath.Join(stageRoot, "defenseclaw-gateway.exe"))
		appendValue("--hook-binary", filepath.Join(stageRoot, "defenseclaw-hook.exe"))
		appendValue("--cli-binary", filepath.Join(stageRoot, "defenseclaw.exe"))
		appendValue("--config", opts.Config)
		appendValue("--manifest", opts.Manifest)
		// QA shorthand pair. Forwarded only when both are non-empty
		// so the CLI's own opts.Mode / opts.Connector validation
		// (parseEnterpriseSetupOptions in main.go) has already
		// rejected the half-supplied grammar.
		appendValue("--mode", opts.Mode)
		appendValue("--connector", opts.Connector)
	}
	appendValue("--install-root", opts.InstallRoot)
	appendValue("--state-root", opts.StateRoot)
	appendValue("--gateway-service-name", opts.GatewayServiceName)
	appendValue("--guardian-service-name", opts.GuardianServiceName)
	appendValue("--certification-codex-home", opts.CertificationCodexHome)
	// Forward the outer Setup's protected scratch directory under
	// %ProgramData%\DefenseClaw-Enterprise-Setup-<hex>\scratch as the
	// installer's one-shot bootstrap parent. install-enterprise.ps1 uses
	// this instead of C:\Windows\Temp so its rendered YAML content passes
	// the module's later trusted-ancestor walk on Azure-AD-joined hosts,
	// where C:\Windows\Temp carries an inherited Allow ACE for the
	// interactive AAD principal with Delete rights.
	arguments = append(arguments, "--bootstrap-parent",
		filepath.Join(stageRoot, enterpriseSetupScratchDirName))
	if opts.NoStart {
		arguments = append(arguments, "--no-start")
	}
	if opts.Purge {
		arguments = append(arguments, "--purge")
	}
	if opts.JSON {
		arguments = append(arguments, "--json")
	}
	if opts.AllowUnsigned {
		arguments = append(arguments, "--allow-unsigned")
	}
	if opts.CoreHardeningCertification {
		arguments = append(arguments, "--core-hardening-certification")
	}
	if opts.AttestAgentApplicationControl {
		arguments = append(arguments, "--attest-agent-application-control")
	}
	if opts.AttestClaudeEffectivePolicy {
		arguments = append(arguments, "--attest-claude-effective-policy")
	}
	// Spec 003 --deferred-config forwards only for the initial
	// install action. Upgrade/repair use the config/manifest already
	// on disk and cannot legitimately defer them. See CR
	// spec-003:PRRT_kwDORuAK-s6alkr4.
	if opts.DeferredConfig && opts.Action == "install" {
		arguments = append(arguments, "--deferred-config")
	}
	return arguments
}

func trustedEnterpriseSetupEnvironment(stageRoot string) ([]string, error) {
	windowsDirectory, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return nil, fmt.Errorf("resolve trusted Windows directory: %w", err)
	}
	roots, err := winpath.ResolveTrustedMachineRoots()
	if err != nil {
		return nil, fmt.Errorf("resolve trusted Windows machine roots: %w", err)
	}
	system32 := filepath.Join(windowsDirectory, "System32")
	// Point the child's scratch env vars at a dedicated subdirectory so
	// PowerShell/CLR scratch writes stay out of the staged payload files.
	scratchDir := filepath.Join(stageRoot, enterpriseSetupScratchDirName)
	allowed := map[string]string{
		"SystemRoot": windowsDirectory, "windir": windowsDirectory,
		"SystemDrive": filepath.VolumeName(windowsDirectory), "ComSpec": filepath.Join(system32, "cmd.exe"),
		"ProgramFiles": roots.ProgramFiles, "ProgramW6432": roots.ProgramFiles,
		"ProgramFiles(x86)": roots.ProgramFilesX86, "ProgramData": roots.ProgramData,
		"ALLUSERSPROFILE": roots.ProgramData, "TEMP": scratchDir, "TMP": scratchDir,
		"LOCALAPPDATA": scratchDir, "APPDATA": scratchDir, "USERPROFILE": scratchDir,
		"HOME": scratchDir, "HOMEDRIVE": filepath.VolumeName(scratchDir),
		"HOMEPATH": strings.TrimPrefix(scratchDir, filepath.VolumeName(scratchDir)),
		"PATH": strings.Join([]string{
			system32, windowsDirectory, filepath.Join(system32, "Wbem"),
			filepath.Join(system32, "WindowsPowerShell", "v1.0"),
		}, string(os.PathListSeparator)),
	}
	keys := make([]string, 0, len(allowed))
	for key := range allowed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		environment = append(environment, key+"="+allowed[key])
	}
	return environment, nil
}
