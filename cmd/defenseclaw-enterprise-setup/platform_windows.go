// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
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
	"runtime"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const (
	enterpriseSetupStagePrefix = "DefenseClaw-Enterprise-Setup-"
	enterpriseSetupStageSDDL   = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	// enterpriseSetupScratchDirName is a dedicated subdirectory under
	// stageRoot pointed at by TEMP/TMP/LOCALAPPDATA/APPDATA/USERPROFILE/HOME
	// so PowerShell and the lifecycle can create scratch files WITHOUT
	// polluting the strict payload-file allowlist cleanupEnterpriseSetupStage
	// enforces on stageRoot itself. Removed recursively before the outer
	// stage cleanup runs.
	enterpriseSetupScratchDirName = "scratch"
	maximumLifecycleOutput        = 2 << 20
	enterpriseBusyExitCode        = 1618 // ERROR_INSTALL_ALREADY_RUNNING
)

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
			return 0, standaloneEnterpriseSetupInputError(standalone, err)
		}
		*input.value = canonical
	}

	if standalone {
		// Refuse a too-full volume before anything is staged. The Secure
		// Client Setup keeps its historical behavior.
		if programData, err := winpath.TrustedProgramData(); err == nil {
			if err := requireEnterpriseSetupFreeSpace(programData, payload, opts.Action); err != nil {
				return 0, err
			}
		}
	}
	stageRoot, cleanup, err := stageEnterprisePayload(payload)
	if err != nil {
		return 0, err
	}
	cleaned := false
	defer func() {
		if cleaned {
			return
		}
		if cleanupErr := cleanup(); cleanupErr != nil {
			exitCode = enterpriseFailureExitCode
			returnErr = errors.Join(returnErr, cleanupErr)
		}
	}()

	arguments := enterpriseLifecycleArguments(stageRoot, opts)
	childEnvironment, err := trustedEnterpriseSetupEnvironment(stageRoot)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(parent, opts.LifecycleTimeout)
	defer cancel()
	cliPath := filepath.Join(stageRoot, "defenseclaw.exe")
	child := processutil.CommandContext(ctx, cliPath, arguments...)
	child.Dir = stageRoot
	child.Env = childEnvironment
	output, runErr := processutil.CombinedOutputTree(child, false)
	if len(output) > maximumLifecycleOutput {
		return 0, fmt.Errorf("enterprise lifecycle output exceeded %d bytes", maximumLifecycleOutput)
	}
	cleanupErr := cleanup()
	cleaned = true
	if cleanupErr != nil {
		if runErr != nil && len(output) != 0 {
			return 0, fmt.Errorf(
				"enterprise lifecycle failed and protected staging cleanup also failed; lifecycle output=%s: %w",
				strings.TrimSpace(string(output)),
				cleanupErr,
			)
		}
		return 0, cleanupErr
	}
	timedOut := ctx.Err() != nil
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
	if timedOut {
		if opts.Standalone {
			return 0, standaloneEnterpriseSetupTimeout(opts, ctx.Err())
		}
		return 0, fmt.Errorf("enterprise %s exceeded the bounded %s timeout: %w", opts.Action, opts.LifecycleTimeout, ctx.Err())
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

func validateEnterpriseSetupInput(value, label string) (string, error) {
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
	if err := managed.ValidateTrustedFilePath(full, label); err != nil {
		return "", enterpriseSetupUntrustedInput{label, full, fmt.Errorf("refusing untrusted %s: %w", label, err)}
	}
	return filepath.Clean(full), nil
}

func stageEnterprisePayload(payload enterprisePayload) (string, func() error, error) {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return "", nil, fmt.Errorf("resolve trusted ProgramData for enterprise Setup staging: %w", err)
	}
	stageRoot, err := createEnterpriseSetupStage(programData)
	if err != nil {
		return "", nil, err
	}
	// Create a dedicated scratch subdirectory that TEMP/TMP/LOCALAPPDATA/
	// APPDATA/USERPROFILE/HOME all point at, so PowerShell and the
	// lifecycle can write scratch files without breaking the strict
	// payload-file allowlist that cleanupEnterpriseSetupStage enforces
	// on stageRoot itself.
	scratchDir := filepath.Join(stageRoot, enterpriseSetupScratchDirName)
	if err := os.Mkdir(scratchDir, 0o700); err != nil {
		return "", nil, errors.Join(fmt.Errorf("create enterprise Setup scratch directory: %w", err), cleanupEnterpriseSetupStage(stageRoot, programData))
	}
	cleanup := func() error { return cleanupEnterpriseSetupStage(stageRoot, programData) }
	required := payload.Required
	if len(required) == 0 {
		required = requiredPayloadFiles
	}
	for _, name := range required {
		expected, ok := payload.Files[name]
		if !ok {
			return "", nil, errors.Join(fmt.Errorf("validated enterprise payload is missing manifest entry %s", name), cleanup())
		}
		path := filepath.Join(stageRoot, name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return "", nil, errors.Join(fmt.Errorf("create staged enterprise payload %s: %w", name, err), cleanup())
		}
		source, sourceErr := embeddedPayload.Open("payload/" + name)
		if sourceErr != nil {
			_ = file.Close()
			return "", nil, errors.Join(fmt.Errorf("open embedded enterprise payload %s: %w", name, sourceErr), cleanup())
		}
		written, writeErr := io.Copy(file, io.LimitReader(source, maximumPayloadFileBytes+1))
		sourceCloseErr := source.Close()
		syncErr := file.Sync()
		closeErr := file.Close()
		if err := errors.Join(writeErr, sourceCloseErr, syncErr, closeErr); err != nil {
			return "", nil, errors.Join(fmt.Errorf("write staged enterprise payload %s: %w", name, err), cleanup())
		}
		if written <= 0 || written > maximumPayloadFileBytes {
			return "", nil, errors.Join(fmt.Errorf("staged enterprise payload has invalid size: %s", name), cleanup())
		}
		if err := managed.ValidateTrustedFilePath(path, "staged enterprise payload "+name); err != nil {
			return "", nil, errors.Join(err, cleanup())
		}
		readback, err := os.Open(path)
		if err != nil {
			return "", nil, errors.Join(fmt.Errorf("open staged enterprise payload for verification %s: %w", name, err), cleanup())
		}
		hasher := sha256.New()
		verifiedBytes, verifyErr := io.Copy(hasher, io.LimitReader(readback, maximumPayloadFileBytes+1))
		readCloseErr := readback.Close()
		if err := errors.Join(verifyErr, readCloseErr); err != nil {
			return "", nil, errors.Join(fmt.Errorf("verify staged enterprise payload %s: %w", name, err), cleanup())
		}
		if verifiedBytes != written || verifiedBytes != expected.Size ||
			!strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), expected.SHA256) {
			return "", nil, errors.Join(fmt.Errorf("staged enterprise payload digest mismatch: %s", name), cleanup())
		}
	}
	if payload.Standalone() && payload.Manifest.Unsigned {
		if err := writeStandalonePayloadTrust(stageRoot, payload, required); err != nil {
			return "", nil, errors.Join(err, cleanup())
		}
	}
	return stageRoot, cleanup, nil
}

// writeStandalonePayloadTrust stages the hash_pinned trust anchor for an
// unsigned standalone payload: the digests this Setup verified against its
// own embedded manifest, in the lifecycle's
// {"schema_version":1,"files":{...}} form.
func writeStandalonePayloadTrust(stageRoot string, payload enterprisePayload, required []string) error {
	files := make(map[string]string, len(required))
	for _, name := range required {
		files[name] = strings.ToLower(payload.Files[name].SHA256)
	}
	body, err := json.Marshal(map[string]any{"schema_version": 1, "files": files})
	if err != nil {
		return err
	}
	path := filepath.Join(stageRoot, standalonePayloadTrustName)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create the standalone payload trust manifest: %w", err)
	}
	_, writeErr := file.Write(append(body, '\n'))
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("write the standalone payload trust manifest: %w", err)
	}
	return managed.ValidateTrustedFilePath(path, "standalone payload trust manifest")
}

func createEnterpriseSetupStage(programData string) (string, error) {
	descriptor, err := windows.SecurityDescriptorFromString(enterpriseSetupStageSDDL)
	if err != nil {
		return "", fmt.Errorf("build enterprise Setup staging DACL: %w", err)
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	for attempt := 0; attempt < 4; attempt++ {
		capability := make([]byte, 16)
		if _, err := rand.Read(capability); err != nil {
			return "", fmt.Errorf("generate enterprise Setup staging capability: %w", err)
		}
		path := filepath.Join(programData, enterpriseSetupStagePrefix+hex.EncodeToString(capability))
		pathPointer, err := winpath.UTF16Ptr(path)
		if err != nil {
			return "", fmt.Errorf("encode enterprise Setup staging path: %w", err)
		}
		if err := windows.CreateDirectory(pathPointer, attributes); err != nil {
			if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
				continue
			}
			return "", fmt.Errorf("create protected enterprise Setup staging directory: %w", err)
		}
		if err := managed.ValidateTrustedRuntimeDir(path, "enterprise Setup staging directory"); err != nil {
			_ = os.Remove(path)
			return "", err
		}
		return filepath.Clean(path), nil
	}
	return "", errors.New("create enterprise Setup staging directory: random path collisions exhausted")
}

func cleanupEnterpriseSetupStage(stageRoot, programData string) error {
	cleanStage := filepath.Clean(stageRoot)
	cleanProgramData := filepath.Clean(programData)
	relative, err := filepath.Rel(cleanProgramData, cleanStage)
	if err != nil || filepath.Dir(relative) != "." ||
		!strings.HasPrefix(filepath.Base(relative), enterpriseSetupStagePrefix) {
		return fmt.Errorf("refusing unsafe enterprise Setup staging cleanup: %s", cleanStage)
	}
	if _, err := os.Lstat(cleanStage); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := managed.ValidateTrustedRuntimeDir(cleanStage, "enterprise Setup staging cleanup"); err != nil {
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
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Remove(cleanStage)
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
	// PowerShell/CLR scratch writes don't collide with the strict payload
	// allowlist enforced on stageRoot itself.
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
