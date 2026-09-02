// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// DefenseClawSetup-Enterprise-x64.exe is the machine-wide bootstrap for the
// Windows managed-enterprise lifecycle. It is intentionally separate from the
// ordinary per-user Setup executable: their elevation, path, service, and
// rollback contracts are different security boundaries.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/setuppayload"
)

// The signed inner payload used to be embedded at compile time via
// //go:embed payload/*. The Windows AVC handoff moved to a runtime
// trailer append so AVC's Windows CI no longer needs Go: DefenseClaw
// prebuilds the outer EXE (this binary) with NO payload, then a
// native Windows DefenseClawAssembler.exe appends the AVC-signed
// payload to the tail as a deterministic trailer.
// loadEmbeddedEnterprisePayload below reads the trailer off the
// running EXE at startup and hands the same fs.FS shape
// ("payload/manifest.json" + "payload/<name>") the existing
// loadEnterprisePayload validator consumes — so nothing downstream
// of the loader had to change.

const (
	enterpriseSetupArtifactName     = "DefenseClawSetup-Enterprise-x64.exe"
	enterpriseFailureExitCode       = 1603
	enterpriseInvalidArgsExitCode   = 1639 // ERROR_INVALID_COMMAND_LINE
	defaultLifecycleTimeout         = 30 * time.Minute
	maximumLifecycleTimeout         = 2 * time.Hour
	maximumPayloadFileBytes         = int64(512 << 20)
	maximumPayloadTotalBytes        = int64(1 << 30)
	managedEnterpriseFlavor         = "managed-enterprise"
	managedEnterpriseUnsignedFlavor = "managed-enterprise-unsigned"
	// The standalone flavors carry the MDM-deployable profile: no CMID
	// credential broker, PowerShell 7, vendor-neutral roots. An unsigned
	// standalone payload is admitted by SHA-256 pins the Setup writes from
	// its own embedded manifest (hash_pinned trust).
	standaloneFlavor         = "standalone"
	standaloneUnsignedFlavor = "standalone-unsigned"
	// standalonePayloadTrustName is the hash-pinned trust anchor staged
	// next to an unsigned standalone payload.
	standalonePayloadTrustName = "payload-trust.json"
)

// enterpriseSetupPayloadLoader reads the embedded payload; tests replace it.
var enterpriseSetupPayloadLoader = loadEmbeddedEnterprisePayload

// enterpriseSetupInvalidArguments marks a command-line error without changing
// its text. The standalone Setup reports it as 1639 so an MDM does not retry
// a command line that can never succeed; the Secure Client Setup never
// produces it and keeps its 0-or-1603 contract.
type enterpriseSetupInvalidArguments struct{ error }

func (err enterpriseSetupInvalidArguments) Unwrap() error { return err.error }

var sourceCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

var requiredPayloadFiles = []string{
	"DefenseClawEnterprise.psm1",
	"defenseclaw-acp.exe",
	"defenseclaw-cmid-broker.exe",
	"defenseclaw-gateway.exe",
	"defenseclaw-hook.exe",
	"defenseclaw-sensor-helper.exe",
	"defenseclaw.exe",
	"install-enterprise.ps1",
}

// standalonePayloadFiles is the standalone flavor's inventory: the Secure
// Client set without the CMID credential broker.
var standalonePayloadFiles = []string{
	"DefenseClawEnterprise.psm1",
	"defenseclaw-acp.exe",
	"defenseclaw-gateway.exe",
	"defenseclaw-hook.exe",
	"defenseclaw-sensor-helper.exe",
	"defenseclaw.exe",
	"install-enterprise.ps1",
}

func isStandaloneFlavor(flavor string) bool {
	return flavor == standaloneFlavor || flavor == standaloneUnsignedFlavor
}

func payloadFilesForFlavor(flavor string) []string {
	if isStandaloneFlavor(flavor) {
		return standalonePayloadFiles
	}
	return requiredPayloadFiles
}

type enterpriseSetupOptions struct {
	Action                 string
	Config                 string
	Manifest               string
	InstallRoot            string
	StateRoot              string
	GatewayServiceName     string
	GuardianServiceName    string
	CertificationCodexHome string
	NoStart                bool
	// Purge widens uninstall past service teardown to state removal. A
	// committed StateRoot or authenticated external receipt authorizes the
	// ordinary scoped purge. If neither survives, recovery may remove only the
	// exact requested service identities and an exact canonical install-root
	// inode through the native no-follow helper; user runtimes, shared connector
	// configuration, other certification scopes, and similarly named services
	// are never inferred from names alone.
	Purge                         bool
	JSON                          bool
	AllowUnsigned                 bool
	CoreHardeningCertification    bool
	AttestAgentApplicationControl bool
	AttestClaudeEffectivePolicy   bool
	// DeferredConfig turns on the UCB-friendly late-config install
	// path from spec 003 (docs/specs/003-windows-deferred-config/):
	// --config and --manifest become optional at install time; the
	// installer provisions the canonical drop-point directories with
	// ACLs but writes no file bodies; the daemon + guardian fsnotify-
	// wait for UCB to atomically drop them later.
	DeferredConfig bool
	// Mode / Connector are the macOS-parity QA shorthand: when both are
	// supplied (and --config / --manifest are empty) the installed
	// install-enterprise.ps1 renders a minimal managed_enterprise
	// config.yaml + per-user targets.yaml into the bootstrap staging
	// directory before invoking the lifecycle. See install-enterprise.ps1
	// (Get-DefenseClawRenderedEnterpriseConfig +
	// Get-DefenseClawRenderedEnterpriseTargets) for the renderer.
	Mode             string
	Connector        string
	LifecycleTimeout time.Duration
	// AllowedSigners is a comma-separated list of SHA-256 Authenticode
	// signer thumbprints the standalone lifecycle accepts (customer
	// re-signing). Standalone Setup only.
	AllowedSigners string

	// Set from the embedded payload, never from the command line.
	Standalone         bool
	StandaloneUnsigned bool
	ProductVersion     string
}

type enterprisePayloadManifest struct {
	SchemaVersion      int                             `json:"schema_version"`
	Version            string                          `json:"version"`
	SourceCommit       string                          `json:"source_commit"`
	DistributionFlavor string                          `json:"distribution_flavor"`
	Unsigned           bool                            `json:"unsigned"`
	Files              []enterprisePayloadManifestFile `json:"files"`
}

type enterprisePayloadManifestFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type enterprisePayload struct {
	Manifest enterprisePayloadManifest
	Files    map[string]enterprisePayloadManifestFile
	// Required is the flavor's exact file inventory.
	Required []string
	// PayloadFS is the fs.FS the platform-specific stage step opens
	// per-file readers against. Before spec 003 this was a package-
	// level embed.FS held in `embeddedPayload`; the trailer refactor
	// carries the FS alongside the validated manifest so the loader
	// stays the single boundary that decides what's trusted.
	PayloadFS fs.FS
}

// Standalone reports whether the payload is the standalone flavor.
func (payload enterprisePayload) Standalone() bool {
	return isStandaloneFlavor(payload.Manifest.DistributionFlavor)
}

type enterpriseSetupFailure struct {
	SchemaVersion int      `json:"schema_version"`
	Action        string   `json:"action"`
	OK            bool     `json:"ok"`
	Error         string   `json:"error"`
	Errors        []string `json:"errors"`
}

func main() {
	os.Exit(runEnterpriseSetup(os.Args[1:], os.Stdout, os.Stderr))
}

// enterpriseSetupStandaloneFlavor reports whether this Setup embeds the
// standalone payload. Replaceable in tests.
var enterpriseSetupStandaloneFlavor = embeddedEnterpriseSetupStandalone

// embeddedEnterpriseSetupStandalone reads only the trailer manifest's
// distribution flavor, before any argument is parsed, so the Secure Client
// Setup keeps its own action set, usage text and error messages. Anything
// other than a readable standalone manifest is the Secure Client Setup;
// executeEnterpriseSetup validates the whole payload before anything runs.
//
// Spec 003: the payload is no longer carried via //go:embed; it is
// appended at assemble time as a deterministic trailer and read off
// the running EXE here.
func embeddedEnterpriseSetupStandalone() bool {
	exePath, err := os.Executable()
	if err != nil {
		return false
	}
	result, err := setuppayload.ReadFile(exePath)
	if err != nil {
		return false
	}
	var manifest struct {
		DistributionFlavor string `json:"distribution_flavor"`
	}
	if json.Unmarshal(result.Manifest, &manifest) != nil {
		return false
	}
	return isStandaloneFlavor(manifest.DistributionFlavor)
}

func runEnterpriseSetup(arguments []string, stdout, stderr io.Writer) int {
	standalone := enterpriseSetupStandaloneFlavor()
	opts, help, err := parseEnterpriseSetupOptionsForFlavor(arguments, standalone)
	if help {
		writeEnterpriseSetupUsageForFlavor(stdout, standalone)
		return 0
	}
	if err != nil {
		writeEnterpriseSetupFailure(stdout, stderr, opts, err)
		return enterpriseSetupArgumentFailureCode()
	}
	exitCode, err := executeEnterpriseSetup(context.Background(), opts, stdout, stderr)
	if err != nil {
		writeEnterpriseSetupFailure(stdout, stderr, opts, err)
		var invalid enterpriseSetupInvalidArguments
		if errors.As(err, &invalid) {
			return enterpriseInvalidArgsExitCode
		}
		return enterpriseFailureExitCode
	}
	if exitCode != 0 {
		return exitCode
	}
	return 0
}

// enterpriseSetupArgumentFailureCode is the exit code for a command line that
// does not parse: 1639 when this Setup embeds the standalone payload, the
// historical 1603 for the Secure Client Setup (and when no payload loads).
func enterpriseSetupArgumentFailureCode() int {
	payload, err := enterpriseSetupPayloadLoader()
	if err == nil && payload.Standalone() {
		return enterpriseInvalidArgsExitCode
	}
	return enterpriseFailureExitCode
}

// parseEnterpriseSetupOptions parses the Secure Client Setup command line.
func parseEnterpriseSetupOptions(arguments []string) (enterpriseSetupOptions, bool, error) {
	return parseEnterpriseSetupOptionsForFlavor(arguments, false)
}

// parseStandaloneEnterpriseSetupOptions parses the standalone Setup command
// line, which adds the ensure action and --allowed-signers.
func parseStandaloneEnterpriseSetupOptions(arguments []string) (enterpriseSetupOptions, bool, error) {
	return parseEnterpriseSetupOptionsForFlavor(arguments, true)
}

// enterpriseSetupActions is the flavor's action set.
func enterpriseSetupActions(standalone bool) []string {
	actions := []string{"install", "upgrade", "repair", "reconcile", "status", "verify", "uninstall"}
	if standalone {
		actions = append(actions, "ensure")
	}
	return actions
}

// enterpriseSetupMutation reports whether action installs or changes the
// deployment for this flavor.
func enterpriseSetupMutation(action string, standalone bool) bool {
	return action == "install" || action == "upgrade" || action == "repair" || (standalone && action == "ensure")
}

// enterpriseSetupMutationList names the flavor's mutation actions in the
// Secure Client Setup's error wording.
func enterpriseSetupMutationList(standalone bool) string {
	if standalone {
		return "install, upgrade, repair, or ensure"
	}
	return "install, upgrade, or repair"
}

func parseEnterpriseSetupOptionsForFlavor(arguments []string, standalone bool) (enterpriseSetupOptions, bool, error) {
	opts := enterpriseSetupOptions{LifecycleTimeout: defaultLifecycleTimeout}
	normalized, help, err := normalizeEnterpriseSetupArgumentsForFlavor(arguments, standalone)
	if err != nil || help {
		return opts, help, err
	}
	flags := flag.NewFlagSet(enterpriseSetupArtifactName, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.Action, "action", "", "enterprise lifecycle action")
	flags.StringVar(&opts.Config, "config", "", "administrator-approved config.yaml")
	flags.StringVar(&opts.Manifest, "manifest", "", "administrator-approved targets.yaml")
	flags.StringVar(&opts.Mode, "mode", "", "QA shorthand: observe|action (paired with --connector; renders config.yaml + targets.yaml in-installer)")
	flags.StringVar(&opts.Connector, "connector", "", "QA shorthand: comma-separated connector list (paired with --mode)")
	flags.StringVar(&opts.InstallRoot, "install-root", "", "certification-only install root")
	flags.StringVar(&opts.StateRoot, "state-root", "", "certification-only state root")
	flags.StringVar(&opts.GatewayServiceName, "gateway-service-name", "", "certification-only gateway service name")
	flags.StringVar(&opts.GuardianServiceName, "guardian-service-name", "", "certification-only guardian service name")
	flags.StringVar(&opts.CertificationCodexHome, "certification-codex-home", "", "certification-only CODEX_HOME")
	flags.BoolVar(&opts.NoStart, "no-start", false, "install services disabled and stopped")
	flags.BoolVar(&opts.Purge, "purge", false, "remove managed state during uninstall (authenticated purge or fail-closed exact-scope recovery)")
	flags.BoolVar(&opts.JSON, "json", false, "emit machine-readable lifecycle output")
	flags.BoolVar(&opts.AllowUnsigned, "allow-unsigned", false, "allow only exact disposable certification scope")
	flags.BoolVar(&opts.CoreHardeningCertification, "core-hardening-certification", false, "run the unsigned core-only certification profile")
	flags.BoolVar(&opts.AttestAgentApplicationControl, "attest-agent-application-control", false, "attest live WDAC or AppLocker enforcement")
	flags.BoolVar(&opts.AttestClaudeEffectivePolicy, "attest-claude-effective-policy", false, "attest Claude managed-policy precedence")
	flags.BoolVar(&opts.DeferredConfig, "deferred-config", false, "spec 003 UCB-friendly install: --config and --manifest optional; services registered stopped")
	if standalone {
		flags.StringVar(&opts.AllowedSigners, "allowed-signers", "", "standalone: comma-separated SHA-256 thumbprints of accepted Authenticode signer certificates")
	}
	timeoutSeconds := int(defaultLifecycleTimeout / time.Second)
	flags.IntVar(&timeoutSeconds, "timeout-seconds", timeoutSeconds, "bounded lifecycle timeout")
	if err := flags.Parse(normalized); err != nil {
		return opts, false, err
	}
	if flags.NArg() != 0 {
		return opts, false, fmt.Errorf("unexpected positional argument %q", flags.Arg(0))
	}
	opts.Action = strings.ToLower(strings.TrimSpace(opts.Action))
	validActions := map[string]bool{}
	for _, action := range enterpriseSetupActions(standalone) {
		validActions[action] = true
	}
	if !validActions[opts.Action] {
		if standalone {
			return opts, false, errors.New("--action must be install, upgrade, repair, reconcile, status, verify, uninstall, or ensure")
		}
		return opts, false, errors.New("--action must be install, upgrade, repair, reconcile, status, verify, or uninstall")
	}
	for _, signer := range strings.Split(opts.AllowedSigners, ",") {
		signer = strings.ToLower(strings.TrimSpace(signer))
		if signer != "" && !sha256Pattern.MatchString(signer) {
			return opts, false, fmt.Errorf("--allowed-signers entry %q is not a SHA-256 certificate thumbprint", signer)
		}
	}
	modeSupplied := strings.TrimSpace(opts.Mode) != ""
	connectorSupplied := strings.TrimSpace(opts.Connector) != ""
	if modeSupplied != connectorSupplied {
		return opts, false, errors.New("--mode and --connector must be supplied together (they are the QA shorthand pair)")
	}
	if modeSupplied && (strings.TrimSpace(opts.Config) != "" ||
		strings.TrimSpace(opts.Manifest) != "") {
		return opts, false, errors.New("--mode / --connector are mutually exclusive with --config / --manifest")
	}
	if modeSupplied && opts.DeferredConfig {
		return opts, false, errors.New("--mode / --connector cannot be combined with --deferred-config")
	}
	if modeSupplied {
		mode := strings.ToLower(strings.TrimSpace(opts.Mode))
		if mode != "observe" && mode != "action" {
			return opts, false, errors.New("--mode must be observe or action")
		}
		opts.Mode = mode
		if !enterpriseSetupMutation(opts.Action, standalone) {
			return opts, false, errors.New("--mode / --connector are valid only with " + enterpriseSetupMutationList(standalone))
		}
		// Keep this closed set aligned with the native Windows lifecycle. Each
		// entry must have reconcile, trusted-runtime, rollback, and teardown
		// coverage before it is accepted at this boundary.
		supportedOnWindows := map[string]bool{"codex": true, "claudecode": true, "cursor": true}
		for _, entry := range strings.Split(opts.Connector, ",") {
			trimmed := strings.ToLower(strings.TrimSpace(entry))
			if trimmed == "" {
				continue
			}
			if !supportedOnWindows[trimmed] {
				return opts, false, fmt.Errorf(
					"--connector entry %q is not supported on Windows managed_enterprise; "+
						"supported: codex, claudecode, cursor.",
					trimmed,
				)
			}
		}
	}
	if opts.Action == "install" && !opts.DeferredConfig && !modeSupplied &&
		(strings.TrimSpace(opts.Config) == "" || strings.TrimSpace(opts.Manifest) == "") {
		// --deferred-config bypasses the config/manifest requirement:
		// the installer will provision the drop-point directories
		// with ACLs but write no file bodies; UCB atomically writes
		// the bodies later, and the daemon + guardian fsnotify-wait
		// pick them up. Spec 003 REQ-02 / REQ-03.
		// --mode + --connector also bypass it: install-enterprise.ps1
		// renders config.yaml + targets.yaml into the bootstrap
		// staging directory before invoking the lifecycle.
		return opts, false, errors.New("install requires both --config and --manifest (or --mode/--connector, or --deferred-config)")
	}
	if opts.DeferredConfig && opts.Action != "install" {
		// Spec 003 --deferred-config is meaningful only at initial
		// install. Upgrade/repair use the config/manifest already on
		// disk; deferring them would leave the deployment offline.
		// CR spec-003:PRRT_kwDORuAK-s6alkr4.
		return opts, false, errors.New("--deferred-config is valid only with install")
	}
	if opts.NoStart && !enterpriseSetupMutation(opts.Action, standalone) {
		return opts, false, errors.New("--no-start is valid only with " + enterpriseSetupMutationList(standalone))
	}
	if opts.Purge && opts.Action != "uninstall" {
		return opts, false, errors.New("--purge is valid only with uninstall")
	}
	if opts.AllowUnsigned && strings.TrimSpace(opts.CertificationCodexHome) == "" {
		return opts, false, errors.New("--allow-unsigned requires --certification-codex-home")
	}
	if opts.CoreHardeningCertification && !opts.AllowUnsigned {
		return opts, false, errors.New("--core-hardening-certification requires --allow-unsigned")
	}
	// Bound the raw integer BEFORE multiplying by time.Second. A very large
	// timeoutSeconds value would otherwise overflow int64 during the
	// multiplication, wrap to a small or negative time.Duration, and slip
	// past the upper-bound check — leaving LifecycleTimeout at a non-positive
	// value that expires context.WithTimeout at once.
	maxTimeoutSeconds := int64(maximumLifecycleTimeout / time.Second)
	if timeoutSeconds < 60 || int64(timeoutSeconds) > maxTimeoutSeconds {
		return opts, false, fmt.Errorf("--timeout-seconds must be between 60 and %d", maxTimeoutSeconds)
	}
	opts.LifecycleTimeout = time.Duration(timeoutSeconds) * time.Second
	return opts, false, nil
}

func normalizeEnterpriseSetupArgumentsForFlavor(arguments []string, standalone bool) ([]string, bool, error) {
	normalized := make([]string, 0, len(arguments))
	valueNames := map[string]string{
		"action": "action", "config": "config", "manifest": "manifest",
		"mode": "mode", "connector": "connector",
		"installroot": "install-root", "stateroot": "state-root",
		"gatewayservicename": "gateway-service-name", "guardianservicename": "guardian-service-name",
		"certificationcodexhome": "certification-codex-home",
		"timeoutseconds":         "timeout-seconds",
	}
	boolNames := map[string]string{
		"nostart": "no-start", "purge": "purge", "json": "json",
		"allowunsigned": "allow-unsigned", "corehardeningcertification": "core-hardening-certification",
		"attestagentapplicationcontrol": "attest-agent-application-control",
		"attestclaudeeffectivepolicy":   "attest-claude-effective-policy",
	}
	actions := map[string]string{
		"/install": "install", "/upgrade": "upgrade", "/repair": "repair",
		"/reconcile": "reconcile", "/status": "status", "/verify": "verify",
		"/uninstall": "uninstall",
	}
	if standalone {
		// Only the standalone Setup has the ensure action and signer pins.
		for name, canonical := range map[string]string{"allowedsigners": "allowed-signers"} {
			valueNames[name] = canonical
		}
		for switchName, action := range map[string]string{"/ensure": "ensure"} {
			actions[switchName] = action
		}
	}
	for _, argument := range arguments {
		trimmed := strings.TrimSpace(argument)
		lower := strings.ToLower(trimmed)
		if lower == "/?" || lower == "/help" || lower == "--help" || lower == "-h" {
			return nil, true, nil
		}
		if action, ok := actions[lower]; ok {
			normalized = append(normalized, "--action="+action)
			continue
		}
		if lower == "/quiet" || lower == "/norestart" {
			// The enterprise bootstrap is always noninteractive and never reports
			// reboot-required success, so these deployment-system switches are
			// accepted as explicit no-ops.
			continue
		}
		if separator := strings.IndexByte(trimmed, '='); separator > 0 && !strings.HasPrefix(trimmed, "--") {
			name := strings.ToLower(strings.ReplaceAll(trimmed[:separator], "-", ""))
			value := trimmed[separator+1:]
			if canonical, ok := valueNames[name]; ok {
				normalized = append(normalized, "--"+canonical+"="+value)
				continue
			}
			if canonical, ok := boolNames[name]; ok {
				enabled, err := strconv.ParseBool(value)
				if err != nil {
					if value == "1" {
						enabled = true
						err = nil
					}
					if value == "0" {
						enabled = false
						err = nil
					}
				}
				if err != nil {
					return nil, false, fmt.Errorf("%s must be true, false, 1, or 0", trimmed[:separator])
				}
				normalized = append(normalized, fmt.Sprintf("--%s=%t", canonical, enabled))
				continue
			}
		}
		normalized = append(normalized, argument)
	}
	return normalized, false, nil
}

// loadEmbeddedEnterprisePayload reads the setuppayload trailer off the
// tail of the running EXE, hands an in-memory fs.FS (the same shape
// the old //go:embed produced — "payload/manifest.json" +
// "payload/<name>") to loadEnterprisePayload, and returns the
// validated result.
//
// Failure modes are surfaced as they were before the refactor:
//   - No trailer at all → "enterprise payload missing; assemble with
//     DefenseClawAssembler.exe" so the operator sees an actionable
//     diagnostic instead of a low-level IO error.
//   - Trailer present but corrupt (CRC / hash mismatch) → the
//     setuppayload package's ErrTrailerCorrupt is passed through.
//   - Manifest content wrong shape → the existing loadEnterprisePayload
//     validator surfaces the same errors it always did (unknown file,
//     size mismatch, invalid SHA-256, wrong flavor).
func loadEmbeddedEnterprisePayload() (enterprisePayload, error) {
	// os.Executable resolves the running binary's path even when
	// invoked via a relative name, a symlink, or from a directory that
	// is not $PWD. On a runtime install (`DefenseClawSetup-Enterprise-x64.exe /install`)
	// this resolves to the signed outer EXE the trailer was appended
	// to. Under `go test` it resolves to the test binary, which has
	// no trailer — the trailer-missing test in main_test.go pins
	// that failure mode.
	exePath, err := os.Executable()
	if err != nil {
		return enterprisePayload{}, fmt.Errorf("resolve running EXE for trailer read: %w", err)
	}
	result, err := setuppayload.ReadFile(exePath)
	if err != nil {
		if errors.Is(err, setuppayload.ErrTrailerMissing) {
			return enterprisePayload{}, errors.New(
				"enterprise payload missing; assemble with DefenseClawAssembler.exe",
			)
		}
		return enterprisePayload{}, fmt.Errorf("read enterprise payload trailer: %w", err)
	}
	return loadEnterprisePayload(result.AsPayloadFS())
}

func loadEnterprisePayload(payloadFS fs.FS) (enterprisePayload, error) {
	manifestBytes, err := fs.ReadFile(payloadFS, "payload/manifest.json")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return enterprisePayload{}, errors.New("enterprise payload missing; build with `make packaging-windows-enterprise-installer VERSION=<version>` for a local unsigned artifact or `make packaging-windows-avc-buildkit VERSION=<version>` for the signed AVC handoff")
		}
		return enterprisePayload{}, fmt.Errorf("read embedded enterprise manifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	var manifest enterprisePayloadManifest
	if err := decoder.Decode(&manifest); err != nil {
		return enterprisePayload{}, fmt.Errorf("parse embedded enterprise manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return enterprisePayload{}, errors.New("parse embedded enterprise manifest: trailing JSON data")
	}
	expectedFlavor := managedEnterpriseFlavor
	if manifest.Unsigned {
		expectedFlavor = managedEnterpriseUnsignedFlavor
	}
	if isStandaloneFlavor(manifest.DistributionFlavor) {
		expectedFlavor = standaloneFlavor
		if manifest.Unsigned {
			expectedFlavor = standaloneUnsignedFlavor
		}
	}
	requiredFiles := payloadFilesForFlavor(expectedFlavor)
	if manifest.SchemaVersion != 1 || strings.TrimSpace(manifest.Version) == "" ||
		!sourceCommitPattern.MatchString(manifest.SourceCommit) ||
		manifest.DistributionFlavor != expectedFlavor {
		return enterprisePayload{}, errors.New("embedded enterprise manifest identity is invalid")
	}
	if len(manifest.Files) != len(requiredFiles) {
		return enterprisePayload{}, errors.New("embedded enterprise manifest has an unexpected file inventory")
	}
	required := make(map[string]struct{}, len(requiredFiles))
	for _, name := range requiredFiles {
		required[name] = struct{}{}
	}
	files := make(map[string]enterprisePayloadManifestFile, len(manifest.Files))
	var totalSize int64
	for _, entry := range manifest.Files {
		if _, ok := required[entry.Name]; !ok {
			return enterprisePayload{}, fmt.Errorf("embedded enterprise manifest contains unexpected file %q", entry.Name)
		}
		if _, duplicate := files[entry.Name]; duplicate {
			return enterprisePayload{}, fmt.Errorf("embedded enterprise manifest contains duplicate file %q", entry.Name)
		}
		if !sha256Pattern.MatchString(entry.SHA256) {
			return enterprisePayload{}, fmt.Errorf("embedded enterprise manifest has an invalid SHA-256 for %s", entry.Name)
		}
		if entry.Size <= 0 || entry.Size > maximumPayloadFileBytes {
			return enterprisePayload{}, fmt.Errorf("embedded enterprise manifest has an invalid size for %s", entry.Name)
		}
		info, err := fs.Stat(payloadFS, "payload/"+entry.Name)
		if err != nil {
			return enterprisePayload{}, fmt.Errorf("inspect embedded enterprise payload %s: %w", entry.Name, err)
		}
		if !info.Mode().IsRegular() || info.Size() != entry.Size {
			return enterprisePayload{}, fmt.Errorf("embedded enterprise payload type or size does not match manifest: %s", entry.Name)
		}
		if entry.Size > maximumPayloadTotalBytes-totalSize {
			return enterprisePayload{}, fmt.Errorf("embedded enterprise payload exceeds %d bytes", maximumPayloadTotalBytes)
		}
		totalSize += entry.Size
		files[entry.Name] = entry
	}
	for _, name := range requiredFiles {
		if _, ok := files[name]; !ok {
			return enterprisePayload{}, fmt.Errorf("embedded enterprise manifest is missing required file %s", name)
		}
	}
	return enterprisePayload{Manifest: manifest, Files: files, Required: requiredFiles, PayloadFS: payloadFS}, nil
}

// splitStandaloneLifecycleJSON separates the lifecycle's JSON result from
// diagnostics that share the combined child output (for example a library
// warning printed at process start). The result is the last line that is a
// complete JSON object; everything else is returned as diagnostics. Output
// without such a line is returned unchanged as the document.
func splitStandaloneLifecycleJSON(output []byte) (document, diagnostics []byte) {
	lines := bytes.Split(output, []byte("\n"))
	for index := len(lines) - 1; index >= 0; index-- {
		line := bytes.TrimSpace(lines[index])
		if len(line) == 0 || line[0] != '{' || !json.Valid(line) {
			continue
		}
		var rest bytes.Buffer
		for other, text := range lines {
			if other == index || len(bytes.TrimSpace(text)) == 0 {
				continue
			}
			rest.Write(bytes.TrimRight(text, "\r"))
			rest.WriteByte('\n')
		}
		return append(append([]byte{}, line...), '\n'), rest.Bytes()
	}
	return output, nil
}

func writeEnterpriseSetupFailure(stdout, stderr io.Writer, opts enterpriseSetupOptions, err error) {
	if err == nil {
		return
	}
	if opts.JSON {
		report := enterpriseSetupFailure{
			SchemaVersion: 1,
			Action:        strings.ToLower(strings.TrimSpace(opts.Action)),
			OK:            false,
			Error:         err.Error(),
			Errors:        []string{err.Error()},
		}
		_ = json.NewEncoder(stdout).Encode(report)
		return
	}
	fmt.Fprintf(stderr, "%s: %v\n", enterpriseSetupArtifactName, err)
}

// writeEnterpriseSetupUsage prints the Secure Client Setup usage.
func writeEnterpriseSetupUsage(output io.Writer) {
	writeEnterpriseSetupUsageForFlavor(output, false)
}

func writeEnterpriseSetupUsageForFlavor(output io.Writer, standalone bool) {
	actions := enterpriseSetupActions(standalone)
	sort.Strings(actions)
	fmt.Fprintf(output, "%s --action <%s> [options]\n", enterpriseSetupArtifactName, strings.Join(actions, "|"))
	fmt.Fprintln(output, "Install requires --config <config.yaml> and --manifest <targets.yaml>.")
	if standalone {
		fmt.Fprintln(output, "Ensure (standalone Setup) converges the host: install, upgrade, repair, or no-op.")
	}
	fmt.Fprintln(output, "Production paths and service names are fixed by the enterprise lifecycle.")
}
