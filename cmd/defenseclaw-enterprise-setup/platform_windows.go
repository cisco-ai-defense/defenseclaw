// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

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
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/setuppayload"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// The hash-pinned trust anchor staged next to an unsigned standalone payload.
const standalonePayloadTrustName = "payload-trust.json"

// Keep the Setup image file open without write/delete sharing while the
// trailer is decoded and its Authenticode signature is verified, and stage
// only the payload whose digests match the payload binding linked into the
// running image (loadBoundEnterprisePayload): the file at the launch path is
// not necessarily the image that is running.
func loadTrustedEnterprisePayload() (enterprisePayload, error) {
	path, err := os.Executable()
	if err != nil {
		return enterprisePayload{}, fmt.Errorf("resolve enterprise Setup image: %w", err)
	}
	encoded, err := winpath.UTF16Ptr(path)
	if err != nil {
		return enterprisePayload{}, err
	}
	handle, err := windows.CreateFile(encoded, windows.GENERIC_READ, windows.FILE_SHARE_READ,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return enterprisePayload{}, fmt.Errorf("lock enterprise Setup image: %w", err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return enterprisePayload{}, errors.New("wrap enterprise Setup image handle")
	}
	defer file.Close()
	var identity windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &identity); err != nil {
		return enterprisePayload{}, err
	}
	if identity.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return enterprisePayload{}, errors.New("enterprise Setup image is not a regular non-reparse file")
	}
	info, err := file.Stat()
	if err != nil {
		return enterprisePayload{}, err
	}
	result, err := setuppayload.Read(file, info.Size())
	if err != nil {
		return enterprisePayload{}, fmt.Errorf("read enterprise Setup image trailer: %w", err)
	}
	payload, err := loadBoundEnterprisePayload(result, standalonePayloadBinding)
	if err != nil {
		return enterprisePayload{}, err
	}
	if payload.Standalone() && !payload.Manifest.Unsigned {
		if err := verifySignedEnterpriseSetup(file, path); err != nil {
			return enterprisePayload{}, err
		}
	}
	return payload, nil
}

func verifySignedEnterpriseSetup(file *os.File, path string) error {
	encoded, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	fileInfo := &windows.WinTrustFileInfo{
		Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: encoded,
		File: windows.Handle(file.Fd()),
	}
	data := &windows.WinTrustData{
		Size: uint32(unsafe.Sizeof(windows.WinTrustData{})), UIChoice: windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_NONE, UnionChoice: windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fileInfo),
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL | windows.WTD_REVOCATION_CHECK_NONE | windows.WTD_DISABLE_MD2_MD4,
		UIContext:                       windows.WTD_UICONTEXT_INSTALL,
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	closeErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verifyErr != nil {
		return fmt.Errorf("WinVerifyTrust rejected outer Setup signature: %w", verifyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close WinVerifyTrust state: %w", closeErr)
	}
	return nil
}

const (
	enterpriseSetupStagePrefix = managed.SetupStagePrefix
	enterpriseSetupStageSDDL   = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	// enterpriseSetupScratchDirName is a dedicated subdirectory under
	// stageRoot pointed at by TEMP/TMP/LOCALAPPDATA/APPDATA/USERPROFILE/HOME
	// so PowerShell and the lifecycle can create scratch files beside, not
	// among, the staged payload files. Cleanup removes the whole stage.
	enterpriseSetupScratchDirName = "scratch"
	// enterpriseSetupStageStaleAge is the age after which a staging folder
	// belongs to no Setup still staging: unpacking the payload takes
	// seconds to minutes. A Setup whose lifecycle still runs holds its
	// folder as the working directory, which the rename below needs free;
	// a Setup of this release holds it from its creation (the stage pin,
	// enterpriseSetupStage). After an interrupted transaction the age is
	// not waited for (enterpriseSetupStageSweepAge).
	enterpriseSetupStageStaleAge = 30 * time.Minute
)

// enterpriseSetupStage is one run's protected staging directory. The
// directory is held open without delete sharing from its creation, so no
// other Setup's removeStaleEnterpriseSetupStages can rename it (GAP-0165),
// and each staged file is held open for reading only from its digest check
// until the last lifecycle child exits, so nothing can rename, replace or
// rewrite what was verified.
type enterpriseSetupStage struct {
	root     string
	parent   string
	rootPin  *managed.SetupPin
	filePins []*managed.SetupPin
	// staged names the files this run puts at the top of root.
	staged []string
	// standalone selects the standalone profile's trust check (validate).
	standalone bool
	cleaned    bool
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
	payload, err := enterpriseSetupPayloadLoader()
	if err != nil {
		return 0, err
	}
	standalone := payload.Standalone()
	if standalone && opts.Action == "ensure" {
		// Status and Verify can report a no-op before another Setup's
		// lifecycle commits. Hold one host-wide intent from before staging
		// through the final result (GAP-1027). The child still takes its
		// ordinary journaled lifecycle lock for every change.
		release, err := acquireStandaloneSetupEnsure()
		if err != nil {
			return 0, err
		}
		defer release()
	}
	if payload.Manifest.Unsigned && !opts.AllowUnsigned && !standalone {
		return 0, errors.New("this enterprise Setup is unsigned and can run only with --allow-unsigned in exact disposable certification scope")
	}
	if !payload.Manifest.Unsigned && opts.AllowUnsigned {
		err := errors.New("--allow-unsigned is forbidden for a signed enterprise Setup payload")
		if standalone {
			return 0, enterpriseSetupInvalidArguments{err}
		}
		return 0, err
	}
	if !standalone && (opts.Action == "ensure" || strings.TrimSpace(opts.AllowedSigners) != "") {
		return 0, errors.New("ensure and --allowed-signers are available only in the standalone enterprise Setup")
	}
	opts.Standalone = standalone
	opts.StandaloneUnsigned = standalone && payload.Manifest.Unsigned
	opts.ProductVersion = payload.Manifest.Version
	// A policy-less /install is only the first half of a fresh deployment.
	// Refuse an existing or unproven deployment before staging a child: the
	// lifecycle used to publish a fresh-install rollback receipt first, then
	// reject DeferredConfig and strand all later repair/ensure runs.
	if standalone && opts.Action == "install" && opts.DeferredConfig {
		if err := requireStandaloneDeferredInstallAbsent(); err != nil {
			return 0, err
		}
	}
	for _, input := range []struct {
		label string
		value *string
	}{
		{label: "config", value: &opts.Config},
		{label: "manifest", value: &opts.Manifest},
		{label: "Cowork package", value: &opts.CoworkPackage},
		{label: "Cowork signature", value: &opts.CoworkSignature},
		{label: "trust anchors", value: &opts.TrustAnchors},
	} {
		if strings.TrimSpace(*input.value) == "" {
			continue
		}
		canonical, err := validateEnterpriseSetupInput(*input.value, input.label, standalone)
		if err != nil {
			return 0, standaloneEnterpriseSetupInputError(standalone, err)
		}
		*input.value = canonical
	}

	if strings.TrimSpace(opts.Bundle) != "" {
		// A signed bundle may come from any folder: the lifecycle copies it
		// into its store and verifies that copy, never this path again.
		bundle, err := validateEnterpriseSetupBundle(opts.Bundle)
		if err != nil {
			return 0, standaloneEnterpriseSetupInputError(standalone, err)
		}
		opts.Bundle = bundle
	}
	if standalone {
		// Refuse a too-full volume before anything is staged. The Secure
		// Client Setup keeps its historical behavior.
		if programData, err := winpath.TrustedProgramData(); err == nil {
			// A removed folder is progress, not a failure: an MDM reads any
			// stderr output as a failed script (GAP-1353, GAP-1069), and in
			// a JSON run stdout is the result alone.
			progress := stdout
			if opts.JSON {
				progress = io.Discard
			}
			sweepAge := enterpriseSetupStageSweepAge()
			for _, root := range managed.SetupStagingRoots(programData) {
				removeStaleEnterpriseSetupStages(root, time.Now(), sweepAge, progress, stderr)
			}
			// The manifest staging folder of an ensure a killed Setup
			// left (rel-1-0-6:GAP-0342). Only an ensure creates it, and
			// every ensure holds the host-wide ensure mutex from before
			// staging to its result: holding that mutex proves no ensure
			// runs, so any such folder is stale whatever its age.
			switch opts.Action {
			case "ensure":
				removeStaleEnterpriseEnsureStages(programData, progress, stderr)
			case "uninstall":
				if release, err := acquireStandaloneSetupEnsure(); err == nil {
					removeStaleEnterpriseEnsureStages(programData, progress, stderr)
					release()
				}
			}
			if err := requireEnterpriseSetupFreeSpace(programData, payload, opts.Action); err != nil {
				return 0, err
			}
		}
		// Refuse an upgrade on saturated processors before staging: it
		// could not finish within TIMEOUTSECONDS (GAP-2265).
		if deployment, err := standaloneSetupDeployment(); err == nil {
			if err := requireEnterpriseSetupHostCapacity(opts.Action, deployment, payload.Manifest.Version); err != nil {
				return 0, err
			}
		}
	}
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return 0, fmt.Errorf("resolve trusted ProgramData for enterprise Setup staging: %w", err)
	}
	if !standalone {
		// The standalone Setup took the stages interrupted runs left above.
		// No machine-wide lock is taken, so only leftovers older than any
		// run can last are swept; a concurrent run's stage is always younger.
		managed.SweepSetupLeftovers(
			managed.SetupStagingRoots(programData),
			managed.SetupLeftoverPrefixes(),
			time.Now(),
		)
	}
	stage, err := stageEnterprisePayload(payload, programData)
	if err != nil {
		return 0, err
	}
	// Cleanup never changes the exit code: the lifecycle's own result is
	// what the deployment system acts on, and a stage that cannot be removed
	// now is scheduled for removal at the next restart.
	defer stage.cleanupAndAccept()

	childEnvironment, err := trustedEnterpriseSetupEnvironment(stage.root)
	if err != nil {
		return 0, err
	}
	// A standalone /ensure with CONFIG= and BUNDLE= is the single-app form:
	// on a new computer it stages the install with every service stopped and
	// then applies the signed bundle, so the first policy any service runs is
	// the signed one (first_bundle.go).
	plan := standaloneEnsurePlan{steps: []standaloneEnsureStep{{opts: opts}}}
	if opts.Standalone && standaloneFirstBundleRequested(opts) {
		deployment, err := standaloneSetupDeployment()
		if err != nil {
			return 0, fmt.Errorf("cannot establish whether a standalone deployment is already installed: %w", err)
		}
		plan = planStandaloneEnsure(opts, deployment.State != winpath.EnterpriseDeploymentAbsent &&
			deployment.State != winpath.EnterpriseDeploymentTombstone)
	}
	cliPath := filepath.Join(stage.root, "defenseclaw.exe")
	// The Secure Client lifecycle's standard error, published after its
	// result.
	var secureClientDiagnostics []byte
	runChild := func(runOpts enterpriseSetupOptions) (enterpriseLifecycleChildRun, error) {
		arguments := enterpriseLifecycleArguments(stage.root, runOpts)
		if runOpts.Standalone && runOpts.Action == "uninstall" {
			// The worker can be killed after it removes managed hook wiring and
			// before it commits. Arm an independent journal replay first.
			if err := enterpriseSetupArmUninstallRecovery(); err != nil {
				return enterpriseLifecycleChildRun{}, fmt.Errorf("cannot arm uninstall recovery before changing the installation: %w", err)
			}
		}
		return runEnterpriseLifecycleChild(parent, runOpts, func(ctx context.Context) ([]byte, error) {
			child := processutil.CommandContext(ctx, cliPath, arguments...)
			child.Dir = stage.root
			child.Env = childEnvironment
			if !runOpts.Standalone {
				// Standard output carries the lifecycle's machine-readable
				// result and is republished on Setup's stdout; standard error
				// carries diagnostics and resilience markers and goes to
				// Setup's stderr, so stdout stays JSON-only under --json. A
				// stream over the cap keeps its tail, which holds the result.
				childStdout, childStderr, err := processutil.OutputTree(child, false)
				secureClientDiagnostics = boundLifecycleStream(childStderr, "stderr")
				return boundLifecycleStream(childStdout, "stdout"), err
			}
			// Pass the lifecycle stderr (diagnostics of a failing run) on at
			// once. Its scanner runtime progress goes to stdout for a person and
			// to the lifecycle log in a JSON run, never to stderr, which an MDM
			// reads as a failed script (GAP-0642, GAP-1069). stdout is the result.
			var captured bytes.Buffer
			child.Stdout = &captured
			child.Stderr = lifecycleProgress{stderr}
			err := processutil.RunTree(child)
			return captured.Bytes(), err
		}, func(ctx context.Context) ([]byte, error) {
			// The trusted staged CLI and module stay pinned until this recovery
			// ends: releaseFiles and cleanup run below. It replays pending
			// rollback or committed uninstall hook teardown using the protected
			// lifecycle evidence.
			return enterpriseSetupRecoveryRunner(ctx, cliPath,
				enterpriseLifecycleArguments(stage.root, standaloneRecoveryOptions(runOpts)), stage.root, childEnvironment)
		}), nil
	}
	lifecycle, last, err := runStandaloneEnsurePlan(plan, runChild)
	// Every lifecycle child, recovery and rollback included, has exited.
	stage.releaseFiles()
	if err != nil {
		return 0, err
	}
	opts = last
	output, runErr, timedOut := lifecycle.output, lifecycle.runErr, lifecycle.timedOut
	if len(output) > maximumLifecycleOutput {
		// Only a standalone run gets here; a Secure Client stream kept its
		// tail (boundLifecycleStream).
		if !timedOut {
			return 0, fmt.Errorf("enterprise lifecycle output exceeded %d bytes", maximumLifecycleOutput)
		}
		// The timeout result is authoritative; a killed child did not finish
		// a result and its oversized partial diagnostics are discarded.
		output = nil
	}
	if len(output) != 0 {
		destination := stdout
		if runErr != nil && !opts.JSON {
			destination = stderr
		}
		if opts.Standalone && opts.JSON && timedOut {
			// A stopped run printed no result: what it wrote is diagnostics,
			// and stdout carries the timeout result alone (GAP-0509).
			destination = stderr
		} else if opts.Standalone && opts.JSON {
			// The lifecycle child's stderr is merged into this capture. An MDM
			// parses stdout, so only the lifecycle's JSON result goes there.
			document, diagnostics := splitStandaloneLifecycleJSON(output)
			if len(diagnostics) != 0 {
				if _, err := stderr.Write(diagnostics); err != nil {
					return 0, fmt.Errorf("publish enterprise lifecycle diagnostics: %w", err)
				}
			}
			output = document
		}
		if _, err := destination.Write(output); err != nil {
			return 0, fmt.Errorf("publish enterprise lifecycle output: %w", err)
		}
	}
	if len(secureClientDiagnostics) != 0 {
		_, _ = stderr.Write(secureClientDiagnostics)
	}
	// The result is out before the stage is removed, and the removal cannot
	// change it.
	stage.cleanupAndAccept()
	if timedOut {
		return 0, timedOutEnterpriseLifecycleError(opts, lifecycle)
	}
	if runErr == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) {
		return 0, fmt.Errorf("launch enterprise lifecycle: %w", runErr)
	}
	if opts.Standalone {
		// The standalone lifecycle reports MSI-compatible codes so an MDM
		// retries a busy host (1618) and does not retry bad arguments
		// (1639). Anything else is the fatal-install code.
		switch code := exitErr.ExitCode(); code {
		case enterpriseBusyExitCode, enterpriseInvalidArgsExitCode:
			return code, nil
		}
	}
	// The public enterprise lifecycle promises only 0 and 1603. Collapse any
	// unexpected child status to the same fatal-install code so AVC never
	// mistakes a partial transaction for reboot-required success.
	return enterpriseFailureExitCode, nil
}

// acquireStandaloneSetupEnsure admits one standalone Setup /ensure at a
// time, including the read-only no-op path. A named kernel mutex has no
// stale file after a killed Setup. The owning thread stays fixed until the
// returned release runs; another active Setup gets MSI's retryable 1618.
func acquireStandaloneSetupEnsure() (release func(), err error) {
	runtime.LockOSThread()
	defer func() {
		if release == nil {
			runtime.UnlockOSThread()
		}
	}()
	descriptor, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return nil, fmt.Errorf("build standalone ensure mutex ACL: %w", err)
	}
	attrs := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	name, err := windows.UTF16PtrFromString(`Global\Cisco-DefenseClaw-Standalone-Setup-Ensure`)
	if err != nil {
		return nil, err
	}
	handle, createErr := windows.CreateMutex(attrs, true, name)
	if handle == 0 {
		return nil, fmt.Errorf("create standalone ensure mutex: %w", createErr)
	}
	closeWith := func(err error) (func(), error) {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	if createErr != nil {
		if !errors.Is(createErr, windows.ERROR_ALREADY_EXISTS) {
			return closeWith(fmt.Errorf("open standalone ensure mutex: %w", createErr))
		}
		state, waitErr := windows.WaitForSingleObject(handle, 0)
		if waitErr != nil {
			return closeWith(fmt.Errorf("wait for standalone ensure mutex: %w", waitErr))
		}
		switch state {
		case uint32(windows.WAIT_OBJECT_0), uint32(windows.WAIT_ABANDONED):
		case uint32(windows.WAIT_TIMEOUT):
			return closeWith(errEnterpriseSetupEnsureBusy)
		default:
			return closeWith(fmt.Errorf("standalone ensure mutex returned unexpected wait state %d", state))
		}
	}
	return func() {
		_ = windows.ReleaseMutex(handle)
		_ = windows.CloseHandle(handle)
		runtime.UnlockOSThread()
	}, nil
}

// enterpriseSetupServiceState is a service state as the lifecycle names it;
// tests replace it.
var enterpriseSetupServiceState = winpath.EnterpriseServiceState

// enterpriseSetupRecordedDeployment gives a refusal of Setup itself the
// standalone deployment this computer records (installed, its version) and
// the states of its services, as the CLI does for its own refusals
// (applyWindowsEnterpriseRecordedDeployment). It reports whether a
// deployment is installed; a missing, retired or unreadable record changes
// nothing (rel-1-0-6:GAP-0321).
var enterpriseSetupRecordedDeployment = func(result *enterprisestatus.Result) bool {
	deployment, err := standaloneSetupDeployment()
	if err != nil || deployment.State != winpath.EnterpriseDeploymentInstalled {
		return false
	}
	result.Installed, result.InstalledVersion = true, deployment.ProductVersion
	for _, service := range winpath.EnterpriseStandaloneServices {
		state := enterpriseSetupServiceState(service.Name)
		if state == "absent" {
			continue
		}
		result.Services = append(result.Services, enterprisestatus.Service{
			Name: service.Name, Kind: service.Kind, State: state, Required: true,
		})
		switch service.Kind {
		case "enumerator":
			result.Readiness.Enumerator = state == "running"
		case "sensor_helper":
			result.Readiness.SensorHelper = state == "running"
		}
	}
	return true
}

var standaloneSetupDeployment = func() (winpath.EnterpriseDeployment, error) {
	deployment, err := winpath.InspectEnterpriseDeployment(managed.ProfileStandalone)
	if err != nil || deployment.State == winpath.EnterpriseDeploymentAbsent {
		return deployment, err
	}
	if err := managed.ValidateTrustedFilePathStandalone(deployment.MetadataPath, "standalone deployment record"); err != nil {
		return deployment, err
	}
	return deployment, nil
}

func requireStandaloneDeferredInstallAbsent() error {
	deployment, err := standaloneSetupDeployment()
	if err != nil {
		return fmt.Errorf("cannot establish whether a standalone deployment is already installed: %w", err)
	}
	if deployment.State != winpath.EnterpriseDeploymentAbsent &&
		deployment.State != winpath.EnterpriseDeploymentTombstone {
		return enterpriseSetupInvalidArguments{errors.New("/install without CONFIG and MANIFEST requires an empty standalone deployment; use /repair to complete a deferred install or /ensure to update an active install (nothing was changed)")}
	}
	return nil
}

// Recovery uses this seam so the timeout contract can be exercised without
// installing services in the Setup unit test.
var enterpriseSetupRecoveryRunner = func(ctx context.Context, path string, args []string, dir string, env []string) ([]byte, error) {
	child := processutil.CommandContext(ctx, path, args...)
	child.Dir, child.Env = dir, env
	return processutil.CombinedOutputTree(child, false)
}

// enterpriseSetupPathError is a CONFIG=/MANIFEST= value that is not an
// existing absolute local path: a command-line error, not a security
// refusal. Its text is unchanged.
type enterpriseSetupPathError struct{ error }

func (err enterpriseSetupPathError) Unwrap() error { return err.error }

// enterpriseSetupUntrustedInput is an existing CONFIG=/MANIFEST= file Setup
// will not take: a link or other non-regular file, or one a principal other
// than Administrators, SYSTEM or TrustedInstaller owns or can change. Its
// text is unchanged.
type enterpriseSetupUntrustedInput struct {
	label string
	path  string
	error
}

func (err enterpriseSetupUntrustedInput) Unwrap() error { return err.error }

// standaloneEnterpriseSetupInputError reports, for the standalone Setup
// only, a malformed or missing input path and an input it will not take as
// invalid arguments (1639), as the lifecycle reports every config it
// refuses; an ownership or write-access refusal names the account and the
// icacls fix (GAP-0528, GAP-0562). The Secure Client Setup keeps 1603.
func standaloneEnterpriseSetupInputError(standalone bool, err error) error {
	if !standalone {
		return err
	}
	var path enterpriseSetupPathError
	if errors.As(err, &path) {
		return enterpriseSetupInvalidArguments{err}
	}
	var untrusted enterpriseSetupUntrustedInput
	if errors.As(err, &untrusted) {
		if text, ok := managed.DescribeUntrustedSource(untrusted.label, untrusted.path, untrusted.error); ok {
			return enterpriseSetupInvalidArguments{errors.New(text)}
		}
		return enterpriseSetupInvalidArguments{err}
	}
	return err
}

// validateEnterpriseSetupBundle accepts an existing absolute local
// regular file that is not a link. Unlike CONFIG=, the folder need not be
// administrator-only: the bundle signature and file hashes are checked on
// the copy the lifecycle makes in its store.
func validateEnterpriseSetupBundle(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.Contains(value, "%") ||
		strings.ContainsAny(value, "\x00\r\n") || !filepath.IsAbs(value) {
		return "", enterpriseSetupPathError{errors.New("bundle path is empty, relative, padded, or environment-expanded")}
	}
	full := filepath.Clean(value)
	volume := filepath.VolumeName(full)
	if len(volume) != 2 || volume[1] != ':' {
		return "", enterpriseSetupPathError{errors.New("bundle must use an absolute local Win32 drive path")}
	}
	info, err := os.Lstat(full)
	if err != nil {
		return "", enterpriseSetupPathError{fmt.Errorf("inspect bundle: %w", err)}
	}
	if !info.Mode().IsRegular() {
		return "", enterpriseSetupPathError{fmt.Errorf("bundle is not a regular non-link file: %s", full)}
	}
	return full, nil
}

// validateEnterpriseSetupInput accepts an existing absolute local regular
// file that is not a link and that Setup can trust. The Secure Client Setup
// applies the Setup trust rule (managed.ValidateSetupPathWithWriter) and
// trusts the administrator who ran it as the owner and writer of the file:
// that account legitimately owns the files it was handed (a download, a share
// copy), and the installer re-stamps the canonical descriptor on the copies
// it installs. The standalone Setup keeps the full trusted-path walk.
func validateEnterpriseSetupInput(value, label string, standalone bool) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.Contains(value, "%") ||
		strings.ContainsAny(value, "\x00\r\n") || !filepath.IsAbs(value) {
		return "", enterpriseSetupPathError{fmt.Errorf("%s path is empty, relative, padded, or environment-expanded", label)}
	}
	full, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("resolve %s path: %w", label, err)
	}
	volume := filepath.VolumeName(full)
	if len(volume) != 2 || volume[1] != ':' || strings.HasPrefix(full, `\\`) ||
		strings.HasPrefix(full, `//`) || strings.HasPrefix(full, `\\?\`) ||
		strings.HasPrefix(full, `\\.\`) {
		return "", enterpriseSetupPathError{fmt.Errorf("%s must use an absolute local Win32 drive path", label)}
	}
	info, err := os.Lstat(full)
	if errors.Is(err, os.ErrNotExist) {
		return "", enterpriseSetupPathError{fmt.Errorf("inspect %s: %w", label, err)}
	}
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", label, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", enterpriseSetupUntrustedInput{label, full, fmt.Errorf("%s is not a regular non-link file: %s", label, full)}
	}
	if standalone {
		if err := managed.ValidateTrustedFilePathStandalone(full, label); err != nil {
			return "", enterpriseSetupUntrustedInput{label, full, fmt.Errorf("refusing untrusted %s: %w", label, err)}
		}
		return filepath.Clean(full), nil
	}
	invoker, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || invoker == nil || invoker.User.Sid == nil {
		return "", fmt.Errorf("resolve the elevated administrator account for %s: %w", label, err)
	}
	if err := managed.ValidateSetupPathWithWriter(full, label, managed.SetupPathFile, invoker.User.Sid); err != nil {
		return "", enterpriseSetupUntrustedInput{label, full, fmt.Errorf("refusing untrusted %s: %w", label, err)}
	}
	return filepath.Clean(full), nil
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
	stage, err := createEnterpriseSetupStage(parent, payload.Standalone())
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*enterpriseSetupStage, error) {
		if cleanupErr := stage.cleanup(); cleanupErr != nil {
			stage.scheduleAtRestart(cleanupErr)
		}
		return nil, cause
	}
	required := payload.Required
	if len(required) == 0 {
		required = requiredPayloadFiles
	}
	trustManifest := payload.Standalone() && payload.Manifest.Unsigned
	stage.staged = append(stage.staged, required...)
	if trustManifest {
		stage.staged = append(stage.staged, standalonePayloadTrustName)
	}
	// Create a dedicated scratch subdirectory that TEMP/TMP/LOCALAPPDATA/
	// APPDATA/USERPROFILE/HOME all point at, so PowerShell and the
	// lifecycle write their scratch files beside, not among, the staged
	// payload files.
	scratchDir := filepath.Join(stage.root, enterpriseSetupScratchDirName)
	if err := managed.CreateSetupDirectory(scratchDir); err != nil {
		return fail(fmt.Errorf("create enterprise Setup scratch directory: %w", err))
	}
	for _, name := range required {
		expected, ok := payload.Files[name]
		if !ok {
			return fail(fmt.Errorf("validated enterprise payload is missing manifest entry %s", name))
		}
		pin, err := stageEnterprisePayloadFile(payload, stage, name, expected)
		if err != nil {
			return fail(err)
		}
		stage.filePins = append(stage.filePins, pin)
	}
	if trustManifest {
		if err := writeStandalonePayloadTrust(stage, payload, required); err != nil {
			return fail(err)
		}
	}
	return stage, nil
}

// stageEnterprisePayloadFile writes one payload file Administrators-owned,
// reopens it read-share-only, proves the reopened handle is the file just
// written, applies the profile's trust check and verifies the digest through
// the pinned handle. The pin stays open until the lifecycle children exit.
func stageEnterprisePayloadFile(
	payload enterprisePayload,
	stage *enterpriseSetupStage,
	name string,
	expected enterprisePayloadManifestFile,
) (*managed.SetupPin, error) {
	path := filepath.Join(stage.root, name)
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
	if err := stage.validate(path, "staged enterprise payload "+name, managed.SetupPathFile); err != nil {
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

// writeStandalonePayloadTrust stages the hash_pinned trust anchor for an
// unsigned standalone payload: the digests this Setup verified against its
// own embedded manifest, in the lifecycle's
// {"schema_version":1,"files":{...}} form. It is staged and pinned like a
// payload file.
func writeStandalonePayloadTrust(stage *enterpriseSetupStage, payload enterprisePayload, required []string) error {
	files := make(map[string]string, len(required))
	for _, name := range required {
		files[name] = strings.ToLower(payload.Files[name].SHA256)
	}
	body, err := json.Marshal(map[string]any{"schema_version": 1, "files": files})
	if err != nil {
		return err
	}
	body = append(body, '\n')
	path := filepath.Join(stage.root, standalonePayloadTrustName)
	file, err := managed.CreateSetupFile(path)
	if err != nil {
		return fmt.Errorf("create the standalone payload trust manifest: %w", err)
	}
	_, writeErr := file.Write(body)
	syncErr := file.Sync()
	writtenID, idErr := managed.SetupFileIDOfFile(file)
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, idErr, closeErr); err != nil {
		return fmt.Errorf("write the standalone payload trust manifest: %w", err)
	}
	pin, err := managed.PinSetupPath(path, managed.SetupPathFile)
	if err != nil {
		return fmt.Errorf("open the standalone payload trust manifest for verification: %w", err)
	}
	if pin.ID() != writtenID {
		_ = pin.Close()
		return errors.New("the standalone payload trust manifest changed between write and verification")
	}
	if err := stage.validate(path, "standalone payload trust manifest", managed.SetupPathFile); err != nil {
		_ = pin.Close()
		return err
	}
	readErr := pin.Rewind()
	var verified []byte
	if readErr == nil {
		verified, readErr = io.ReadAll(io.LimitReader(pin, int64(len(body))+1))
	}
	if readErr != nil || !bytes.Equal(verified, body) {
		_ = pin.Close()
		return errors.Join(errors.New("the standalone payload trust manifest does not read back as written"), readErr)
	}
	stage.filePins = append(stage.filePins, pin)
	return nil
}

func createEnterpriseSetupStage(parent string, standalone bool) (*enterpriseSetupStage, error) {
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
		stage := &enterpriseSetupStage{
			root: filepath.Clean(path), parent: filepath.Clean(parent), rootPin: pin, standalone: standalone,
		}
		if err := stage.validate(path, "enterprise Setup staging directory", managed.SetupPathDirectory); err != nil {
			if cleanupErr := stage.cleanup(); cleanupErr != nil {
				stage.scheduleAtRestart(cleanupErr)
			}
			return nil, err
		}
		return stage, nil
	}
	return nil, errors.New("create enterprise Setup staging directory: random path collisions exhausted")
}

// validate applies the profile's trust check to an object this run staged.
// The Secure Client Setup applies the Setup trust rule: the object itself is
// strict, structure is fatal and the ancestors are advisory, which the pins
// make safe. The standalone Setup keeps the full trusted-path walk, its
// ancestors included; the pins still refuse a reparse point, the wrong type
// and a second hard link.
func (stage *enterpriseSetupStage) validate(path, label string, kind managed.SetupPathKind) error {
	if !stage.standalone {
		return managed.ValidateSetupPath(path, label, kind)
	}
	if kind == managed.SetupPathDirectory {
		return managed.ValidateTrustedRuntimeDirStandalone(path, label)
	}
	return managed.ValidateTrustedFilePathStandalone(path, label)
}

// releaseFiles closes the staged-file pins once the lifecycle children
// exited.
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
	if err := retryEnterpriseSetupStageRemoval(func() error {
		return managed.RemoveSetupTreeIfSame(stage.root, id)
	}); err != nil {
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
	for _, name := range stage.staged {
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

// standaloneSetupTransactionPending reports a protected pending.json in the
// standalone lifecycle folder: a lifecycle transaction that has not finished.
// A variable for tests.
var standaloneSetupTransactionPending = func() bool {
	layout, err := setupRecoveryLayout()
	if err != nil {
		return false
	}
	path := filepath.Join(layout.LifecycleDir, "pending.json")
	if _, err := os.Lstat(path); err != nil {
		return false
	}
	return managed.ValidateTrustedFilePathStandalone(path, "standalone pending transaction") == nil
}

// enterpriseSetupStageSweepAge is how old a staging folder must be before
// this Setup takes it. A pending transaction means a Setup run was stopped
// before it finished: this run recovers it, and the staging folder the
// stopped run left (the whole payload, about 700 MB) is taken now instead
// of by a run 30 minutes later (GAP-0165). A folder a running Setup or
// lifecycle still holds is kept either way: the rename fails for it.
func enterpriseSetupStageSweepAge() time.Duration {
	if standaloneSetupTransactionPending() {
		return 0
	}
	return enterpriseSetupStageStaleAge
}

// cleanupEnterpriseSetupStage removes a stage that an interrupted standalone
// Setup run left directly under root (ProgramData or its Cisco fallback) and
// that removeStaleEnterpriseSetupStages renamed: only after its trust walk
// passes, and only when it holds nothing but the payload files and the
// scratch folder. A stage this run created is removed by its own cleanup
// (enterpriseSetupStage).
func cleanupEnterpriseSetupStage(stageRoot, root string) error {
	cleanStage := filepath.Clean(stageRoot)
	cleanRoot := filepath.Clean(root)
	relative, err := filepath.Rel(cleanRoot, cleanStage)
	if err != nil || filepath.Dir(relative) != "." ||
		!strings.HasPrefix(filepath.Base(relative), enterpriseSetupStagePrefix) {
		return fmt.Errorf("refusing unsafe enterprise Setup staging cleanup: %s", cleanStage)
	}
	if _, err := os.Lstat(cleanStage); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := managed.ValidateTrustedRuntimeDirStandalone(cleanStage, "enterprise Setup staging cleanup"); err != nil {
		return fmt.Errorf("refusing enterprise Setup cleanup after trust drift: %w", err)
	}
	// Delete the scratch subdirectory (recursively) first. PowerShell and
	// the child lifecycle may have created arbitrary temp files under it
	// via TEMP/TMP/LOCALAPPDATA/etc.; the strict allowlist below refuses
	// anything except payload files at the top of stageRoot.
	scratchDir := filepath.Join(cleanStage, enterpriseSetupScratchDirName)
	if err := os.RemoveAll(scratchDir); err != nil {
		return fmt.Errorf("remove enterprise Setup scratch directory: %w", err)
	}
	entries, err := os.ReadDir(cleanStage)
	if err != nil {
		return err
	}
	stagedNames := append(append(append([]string{}, requiredPayloadFiles...), standalonePayloadFiles...), standalonePayloadTrustName)
	allowed := make(map[string]bool, len(stagedNames))
	for _, name := range stagedNames {
		allowed[name] = true
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing enterprise Setup cleanup with unexpected staged object: %s", entry.Name())
		}
	}
	for name := range allowed {
		path := filepath.Join(cleanStage, name)
		if err := removeEnterpriseSetupStageEntry(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return removeEnterpriseSetupStageEntry(cleanStage)
}

// enterpriseSetupStageRemoveWait bounds how long cleanup waits for a staged
// file another process still holds. Tests lower it.
var enterpriseSetupStageRemoveWait = 10 * time.Second

// removeEnterpriseSetupStageFile is the removal cleanup makes. Tests
// replace it.
var removeEnterpriseSetupStageFile = os.Remove

// removeEnterpriseSetupStageEntry removes one staged file or the empty
// stage folder of a stale stage (retryEnterpriseSetupStageRemoval).
func removeEnterpriseSetupStageEntry(path string) error {
	return retryEnterpriseSetupStageRemoval(func() error { return removeEnterpriseSetupStageFile(path) })
}

// retryEnterpriseSetupStageRemoval runs one stage removal. Right after the
// lifecycle child exits, Windows can still hold its image (defenseclaw.exe)
// for a moment, and an antivirus scan of a new file opens it without delete
// sharing: the removal then fails with a sharing violation or access denied
// although nothing is wrong. A refused /ensure (exit 1639) became exit 1603
// that way on a hosted runner. The removal is retried until
// enterpriseSetupStageRemoveWait; what is still held then is scheduled for
// removal at the next restart (this run's stage) or left for a later run (a
// stale stage), and the run's result stands either way.
func retryEnterpriseSetupStageRemoval(remove func() error) error {
	deadline := time.Now().Add(enterpriseSetupStageRemoveWait)
	delay := 25 * time.Millisecond
	for {
		err := remove()
		retryable := errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
		if err == nil || !retryable || !time.Now().Add(delay).Before(deadline) {
			return err
		}
		time.Sleep(delay)
		delay = min(2*delay, 500*time.Millisecond)
	}
}

// cleanupStaleEnterpriseSetupStage removes a renamed stale staging folder.
// A seam for tests: a test folder is not owned by the administrators group,
// so the real cleanup keeps it.
var cleanupStaleEnterpriseSetupStage = cleanupEnterpriseSetupStage

// removeStaleEnterpriseSetupStages removes the staging folders that
// interrupted standalone Setup runs left in root, ProgramData or its Cisco
// staging fallback (a stopped Setup cannot clean up; each holds the whole
// payload, GAP-0525). Only a folder at least minimumAge old
// (enterpriseSetupStageSweepAge) that can be renamed is taken: a Setup of
// this release holds its folder from its creation, and a Setup whose
// lifecycle still runs holds it as the working directory, so the rename
// fails for it. The renamed folder keeps the stage prefix, so one this run
// cannot clean (unexpected content) is swept by a later run or by uninstall.
// A removed folder is reported to progress, one it had to keep to
// diagnostics.
func removeStaleEnterpriseSetupStages(root string, now time.Time, minimumAge time.Duration, progress, diagnostics io.Writer) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		capability, found := strings.CutPrefix(name, enterpriseSetupStagePrefix)
		if !found || !entry.IsDir() || len(capability) != 32 || strings.Trim(capability, "0123456789abcdef") != "" {
			continue
		}
		path := filepath.Join(root, name)
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			continue
		}
		attributes, ok := info.Sys().(*syscall.Win32FileAttributeData)
		if !ok || now.Sub(time.Unix(0, attributes.CreationTime.Nanoseconds())) < minimumAge {
			continue
		}
		retired := ""
		for attempt := 0; attempt < 4 && retired == ""; attempt++ {
			next := make([]byte, 16)
			if _, err := rand.Read(next); err != nil {
				return
			}
			candidate := filepath.Join(root, enterpriseSetupStagePrefix+hex.EncodeToString(next))
			if err := os.Rename(path, candidate); err == nil {
				retired = candidate
			} else if !errors.Is(err, os.ErrExist) {
				break
			}
		}
		if retired == "" {
			continue
		}
		if err := cleanupStaleEnterpriseSetupStage(retired, root); err != nil {
			fmt.Fprintf(diagnostics, "%s: kept the staging folder an interrupted Setup run left, %s: %v\n", standaloneSetupArtifactName, retired, err)
			continue
		}
		fmt.Fprintf(progress, "%s: removed the staging folder an interrupted Setup run left, %s\n", standaloneSetupArtifactName, path)
	}
}

// enterpriseSetupEnsureStagePrefix names the protected folder in which the
// lifecycle of a standalone ensure stages its first guardian manifest
// (internal/cli stageWindowsEnterpriseEnsureManifest): the prefix and 32
// lowercase hex characters, holding at most targets.yaml.
const enterpriseSetupEnsureStagePrefix = "DefenseClaw-Ensure-"

// enterpriseSetupEnsureStageMaxBytes bounds the manifest a stale folder may
// hold for it to be taken as DefenseClaw's.
const enterpriseSetupEnsureStageMaxBytes = 16 << 20

// validateEnterpriseEnsureStage is the trust check of a stale ensure
// staging folder (owned by an administrator principal, no write for anyone
// else); a seam for tests, whose temporary folders are not owned that way.
var validateEnterpriseEnsureStage = func(path string) error {
	return managed.ValidateTrustedRuntimeDir(path, "ensure manifest staging folder")
}

// removeStaleEnterpriseEnsureStages removes the manifest staging folders
// that ensures a killed Setup stopped left in ProgramData
// (rel-1-0-6:GAP-0342). The caller holds the ensure mutex. A folder is
// taken only when its name, its owner and access list, and its content
// prove it is one: DefenseClaw-Ensure-<32 lowercase hex>, a real folder
// (no link), trusted, empty or holding only a regular targets.yaml of a
// bounded size. Anything else is kept and reported to diagnostics.
func removeStaleEnterpriseEnsureStages(programData string, progress, diagnostics io.Writer) {
	entries, err := os.ReadDir(programData)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		capability, found := strings.CutPrefix(name, enterpriseSetupEnsureStagePrefix)
		if !found || len(capability) != 32 || strings.Trim(capability, "0123456789abcdef") != "" {
			continue
		}
		path := filepath.Join(programData, name)
		if err := removeStaleEnterpriseEnsureStage(path); err != nil {
			fmt.Fprintf(diagnostics, "%s: kept the ensure staging folder %s: %v\n", standaloneSetupArtifactName, path, err)
			continue
		}
		fmt.Fprintf(progress, "%s: removed the ensure staging folder an interrupted Setup run left, %s\n", standaloneSetupArtifactName, path)
	}
}

func removeStaleEnterpriseEnsureStage(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	attributes, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok ||
		attributes.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("not a plain folder")
	}
	if err := validateEnterpriseEnsureStage(path); err != nil {
		return err
	}
	children, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(children) > 1 || (len(children) == 1 && children[0].Name() != "targets.yaml") {
		return errors.New("it holds something other than targets.yaml")
	}
	if len(children) == 1 {
		manifest := filepath.Join(path, "targets.yaml")
		fileInfo, err := os.Lstat(manifest)
		if err != nil {
			return err
		}
		fileAttributes, ok := fileInfo.Sys().(*syscall.Win32FileAttributeData)
		if !fileInfo.Mode().IsRegular() || !ok ||
			fileAttributes.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
			fileInfo.Size() > enterpriseSetupEnsureStageMaxBytes {
			return errors.New("its targets.yaml is not a plain bounded file")
		}
		if err := os.Remove(manifest); err != nil {
			return err
		}
	}
	return os.Remove(path)
}

func enterpriseLifecycleArguments(stageRoot string, opts enterpriseSetupOptions) []string {
	arguments := []string{"enterprise", "windows", opts.Action, "--installer", filepath.Join(stageRoot, "install-enterprise.ps1")}
	mutation := opts.Action == "install" || opts.Action == "upgrade" || opts.Action == "repair" || opts.Action == "ensure"
	appendValue := func(flag, value string) {
		if strings.TrimSpace(value) != "" {
			arguments = append(arguments, flag, value)
		}
	}
	if mutation {
		if !opts.Standalone {
			appendValue("--broker-binary", filepath.Join(stageRoot, "defenseclaw-cmid-broker.exe"))
		}
		appendValue("--gateway-binary", filepath.Join(stageRoot, "defenseclaw-gateway.exe"))
		appendValue("--acp-binary", filepath.Join(stageRoot, "defenseclaw-acp.exe"))
		appendValue("--hook-binary", filepath.Join(stageRoot, "defenseclaw-hook.exe"))
		appendValue("--sensor-helper-binary", filepath.Join(stageRoot, "defenseclaw-sensor-helper.exe"))
		appendValue("--cli-binary", filepath.Join(stageRoot, "defenseclaw.exe"))
		appendValue("--config", opts.Config)
		appendValue("--manifest", opts.Manifest)
		if opts.Standalone {
			appendValue("--cowork-package", opts.CoworkPackage)
			appendValue("--cowork-signature", opts.CoworkSignature)
		}
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
	if opts.Force {
		arguments = append(arguments, "--force")
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
	// --deferred-config forwards only for the initial install
	// action. Upgrade/repair use the config/manifest already on disk
	// and cannot legitimately defer them.
	if opts.DeferredConfig && opts.Action == "install" {
		arguments = append(arguments, "--deferred-config")
	}
	if opts.Standalone {
		arguments = append(arguments, "--profile", "standalone")
		appendValue("--product-version", opts.ProductVersion)
		if opts.StandaloneUnsigned {
			arguments = append(arguments,
				"--trust-mode", "hash_pinned",
				"--payload-manifest", filepath.Join(stageRoot, standalonePayloadTrustName))
		}
		for _, signer := range strings.Split(opts.AllowedSigners, ",") {
			appendValue("--allowed-signer", strings.ToLower(strings.TrimSpace(signer)))
		}
		if mutation {
			// The lifecycle refuses BUNDLE= and TRUSTANCHORS= on another
			// action itself, and records a refused anchor install (GAP-0608).
			appendValue("--bundle", opts.Bundle)
			appendValue("--trust-anchors", opts.TrustAnchors)
			appendValue("--device-group", opts.DeviceGroup)
			if opts.RefuseCapabilityLoss {
				arguments = append(arguments, "--refuse-capability-loss")
			}
		}
		if opts.Action == "ensure" {
			// What is left of TIMEOUTSECONDS after the payload checks and
			// unpacking (GAP-2509).
			remaining := time.Until(enterpriseSetupLifecycleDeadline(opts, time.Now()))
			if seconds := enterpriseEnsureChildTimeoutSeconds(remaining); seconds > 0 {
				arguments = append(arguments, "--timeout-seconds", strconv.Itoa(seconds))
			}
		}
	}
	return arguments
}

// enterpriseSetupProcessStarted is this process's creation time, so the time
// Windows took to load and start the Setup image counts toward
// TIMEOUTSECONDS too (GAP-2509).
func enterpriseSetupProcessStarted() time.Time {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err == nil {
		if started := enterpriseSetupStartFromCreation(time.Now(), time.Unix(0, creation.Nanoseconds())); !started.IsZero() {
			return started
		}
	}
	return enterpriseSetupInitTime
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

// lifecycleProgress passes the lifecycle stderr on. It is not an *os.File,
// so the child always gets a pipe: a scheduled task can start Setup with no
// usable stderr, and a failed write must not end the copy or the lifecycle.
type lifecycleProgress struct{ w io.Writer }

func (p lifecycleProgress) Write(b []byte) (int, error) {
	_, _ = p.w.Write(b)
	return len(b), nil
}
