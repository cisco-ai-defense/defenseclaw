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
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
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
	enterpriseBusyExitCode          = 1618 // ERROR_INSTALL_ALREADY_RUNNING
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
)

// standaloneSetupArtifactName is the file name the standalone Setup ships
// under; its usage and errors name it, not the Secure Client Setup
// (GAP-0353).
const standaloneSetupArtifactName = "DefenseClawSetup-Enterprise-Standalone-x64.exe"

// enterpriseSetupPayloadLoader reads the embedded payload; tests replace it.
var enterpriseSetupPayloadLoader = loadTrustedEnterprisePayload

var errEnterpriseSetupEnsureBusy = errors.New("lifecycle_busy: another standalone Setup /ensure is active; retry after it finishes")

// standalonePayloadBinding is the setuppayload.PayloadBinding of the payload
// and manifest identity (flavor, version, source commit)
// this Setup image was built with. packaging/windows/standalone/build-setup.sh
// links it in (-X main.standalonePayloadBinding=<hex>), so it lives in the
// running image, which no other process can change. The Setup stages a
// trailer payload only when it produces this value, whatever file the
// trailer was read from (#1281). Empty in an image no standalone build
// stamped: the Secure Client Setup and test binaries.
var standalonePayloadBinding string

// enterpriseSetupInvalidArguments marks a command-line error without changing
// its text. The standalone Setup reports it as 1639 so an MDM does not retry
// a command line that can never succeed; the Secure Client Setup never
// produces it and keeps its 0-or-1603 contract.
type enterpriseSetupInvalidArguments struct{ error }

func (err enterpriseSetupInvalidArguments) Unwrap() error { return err.error }

var sourceCommitPattern = lazyregexp.New(`^[0-9a-f]{40}$`)
var sha256Pattern = lazyregexp.New(`^[0-9a-f]{64}$`)

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
// Client set without the CMID credential broker, plus the scanner runtime
// (skill, MCP and plugin scanners).
var standalonePayloadFiles = []string{
	"DefenseClawEnterprise.psm1",
	"defenseclaw-acp.exe",
	"defenseclaw-gateway.exe",
	"defenseclaw-hook.exe",
	"defenseclaw-scanners.exe",
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
	// DeferredConfig stages a protected installed deployment with all
	// managed services disabled. A later Repair supplying both authenticated
	// config and manifest files performs target preparation and activation;
	// directly dropping files or starting services is not supported.
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
	// Started is when this standalone Setup process started. Its
	// TIMEOUTSECONDS limit counts from then, the payload checks and the
	// unpacking before the lifecycle child included, so Setup ends within
	// TIMEOUTSECONDS plus its bounded recovery on a loaded host too
	// (GAP-2509). Zero counts from the lifecycle child's start (the Secure
	// Client Setup and the recovery watchdog).
	Started time.Time
	// AllowedSigners is a comma-separated list of SHA-256 Authenticode
	// signer thumbprints the standalone lifecycle accepts (customer
	// re-signing). Standalone Setup only.
	AllowedSigners string
	// Force, with /uninstall, removes the deployment without recovering a
	// pending transaction: the last resort when no ensure, repair or
	// uninstall can recover it (GAP-0920, GAP-1041). Standalone Setup only.
	Force bool
	// Bundle is the signed policy bundle /ensure applies (BUNDLE=) and
	// TrustAnchors the bundle trust anchor file it installs first
	// (TRUSTANCHORS=). The bundle carries the config, so BUNDLE= is not
	// combined with CONFIG=. Standalone Setup only.
	Bundle               string
	TrustAnchors         string
	RefuseCapabilityLoss bool

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
	// per-file readers against. Before the payload trailer this was a package-
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
// The payload is no longer carried via //go:embed; it is
// appended at assemble time as a deterministic trailer and read off
// the running EXE here.
func embeddedEnterpriseSetupStandalone() bool {
	if standalonePayloadBinding != "" {
		// Only the standalone build stamps a payload binding into the image.
		return true
	}
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
	if len(arguments) == 2 && arguments[0] == "--internal-recover-after-parent" {
		return runStandaloneSetupRecoveryWatchdog(arguments[1], stdout, stderr)
	}
	standalone := enterpriseSetupStandaloneFlavor()
	opts, help, err := parseEnterpriseSetupOptionsForFlavor(arguments, standalone)
	if help {
		writeEnterpriseSetupUsageForFlavor(stdout, standalone)
		return 0
	}
	name := enterpriseSetupArtifactName
	if standalone {
		name = standaloneSetupArtifactName
	}
	if err != nil {
		code := enterpriseSetupArgumentFailureCode()
		if standalone {
			err = enterpriseSetupInvalidArguments{err}
		}
		writeEnterpriseSetupFailureFor(stdout, stderr, standalone, name, opts, err, code)
		return code
	}
	if standalone {
		opts.Started = enterpriseSetupProcessStarted()
	}
	exitCode, err := executeEnterpriseSetup(context.Background(), opts, stdout, stderr)
	if err != nil {
		code := enterpriseFailureExitCode
		var invalid enterpriseSetupInvalidArguments
		if errors.Is(err, errEnterpriseSetupEnsureBusy) {
			code = enterpriseBusyExitCode
		} else if errors.As(err, &invalid) {
			code = enterpriseInvalidArgsExitCode
		}
		writeEnterpriseSetupFailureFor(stdout, stderr, standalone, name, opts, err, code)
		return code
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
		if standalone && err != nil {
			captureStandaloneSetupErrorIntent(arguments, &opts)
		}
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
	flags.BoolVar(&opts.DeferredConfig, "deferred-config", false, "UCB-friendly install: --config and --manifest optional; services registered stopped")
	if standalone {
		flags.StringVar(&opts.AllowedSigners, "allowed-signers", "", "standalone: comma-separated SHA-256 thumbprints of accepted Authenticode signer certificates")
		flags.BoolVar(&opts.Force, "force", false, "standalone /uninstall: remove the deployment without recovering a pending transaction (last resort)")
		flags.StringVar(&opts.Bundle, "bundle", "", "standalone /ensure: signed policy bundle (.dcbundle) to apply")
		flags.StringVar(&opts.TrustAnchors, "trust-anchors", "", "standalone /ensure: bundle trust anchor file to install first")
		flags.BoolVar(&opts.RefuseCapabilityLoss, "refuse-capability-loss", false, "standalone /ensure: refuse a bundle that disables an enforced capability")
	}
	timeoutSeconds := int(defaultLifecycleTimeout / time.Second)
	flags.IntVar(&timeoutSeconds, "timeout-seconds", timeoutSeconds, "bounded lifecycle timeout")
	if err := flags.Parse(normalized); err != nil {
		return opts, false, err
	}
	if flags.NArg() != 0 {
		if standalone {
			return opts, false, fmt.Errorf("unexpected argument %q; run %s /? for the actions and the NAME=value properties", flags.Arg(0), standaloneSetupArtifactName)
		}
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
		// coverage before it is accepted at this boundary. Secure Client also
		// manages GitHub Copilot (the CLI and the GitHub Copilot app).
		supportedOnWindows := map[string]bool{"codex": true, "claudecode": true, "cursor": true}
		supported := "codex, claudecode, cursor"
		if !standalone {
			supportedOnWindows["copilot"] = true
			supported += ", copilot (GitHub Copilot)"
		}
		for _, entry := range strings.Split(opts.Connector, ",") {
			trimmed := strings.ToLower(strings.TrimSpace(entry))
			if trimmed == "" {
				continue
			}
			if !supportedOnWindows[trimmed] {
				return opts, false, fmt.Errorf(
					"--connector entry %q is not supported on Windows managed_enterprise; "+
						"supported: %s.",
					trimmed,
					supported,
				)
			}
		}
	}
	configSupplied := strings.TrimSpace(opts.Config) != ""
	manifestSupplied := strings.TrimSpace(opts.Manifest) != ""
	if opts.Action == "install" && !modeSupplied {
		if configSupplied != manifestSupplied {
			return opts, false, errors.New("install requires config and manifest together")
		}
		if opts.DeferredConfig && (configSupplied || manifestSupplied) {
			return opts, false, errors.New("--deferred-config cannot be combined with --config or --manifest")
		}
		if !configSupplied && !manifestSupplied {
			// A standalone /install with no policy inputs is the supported
			// first half of the late-configuration lifecycle. It stages a
			// protected, disabled deployment; a later /repair with BOTH
			// authenticated files performs target preparation and activation.
			opts.DeferredConfig = true
		}
	}
	if opts.DeferredConfig && opts.Action != "install" {
		// The flag marks only the initial staged install. Its protected
		// metadata later selects the special complete-Repair activation path.
		return opts, false, errors.New("--deferred-config is valid only with install")
	}
	if opts.NoStart && !enterpriseSetupMutation(opts.Action, standalone) {
		return opts, false, errors.New("--no-start is valid only with " + enterpriseSetupMutationList(standalone))
	}
	if opts.Purge && opts.Action != "uninstall" {
		return opts, false, errors.New("--purge is valid only with uninstall")
	}
	if opts.Force && opts.Action != "uninstall" {
		return opts, false, errors.New("FORCE=1 is valid only with /uninstall")
	}
	// With TRUSTANCHORS= on a mutation the lifecycle refuses each of these
	// command lines itself, before it changes anything, and on an installed
	// computer records the refused anchor install (config.trust_anchors.changed)
	// as the defenseclaw.exe route does; Setup refusing first left no audit
	// row (GAP-0608). Without anchors there is nothing to record.
	if strings.TrimSpace(opts.TrustAnchors) == "" || !enterpriseSetupMutation(opts.Action, standalone) {
		if opts.RefuseCapabilityLoss && opts.Action != "ensure" {
			if strings.TrimSpace(opts.Bundle) == "" {
				return opts, false, errors.New("REFUSECAPABILITYLOSS=1 requires BUNDLE= and is valid only with /ensure; nothing was changed: deliver both with Setup /ensure")
			}
			return opts, false, errors.New("REFUSECAPABILITYLOSS=1 is valid only with /ensure; nothing was changed: deliver BUNDLE= and REFUSECAPABILITYLOSS=1 with Setup /ensure")
		}
		if (strings.TrimSpace(opts.Bundle) != "" || strings.TrimSpace(opts.TrustAnchors) != "") && opts.Action != "ensure" {
			return opts, false, errors.New("BUNDLE= and TRUSTANCHORS= are valid only with /ensure")
		}
		// CONFIG= with BUNDLE= is the single-app form: CONFIG= stages a
		// first install that no service runs on, and the bundle is the first
		// enforced policy (first_bundle.go). The --mode shorthand renders a
		// config to enforce, so it stays refused.
		if strings.TrimSpace(opts.Bundle) != "" && modeSupplied {
			return opts, false, errors.New("BUNDLE= cannot be combined with --mode/--connector: the signed bundle carries the config")
		}
		if opts.RefuseCapabilityLoss && strings.TrimSpace(opts.Bundle) == "" {
			return opts, false, errors.New("REFUSECAPABILITYLOSS=1 requires BUNDLE=; nothing was changed: deliver both with Setup /ensure")
		}
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

// captureStandaloneSetupErrorIntent preserves the output mode and action when
// normalization rejects an earlier property. MDM callers may put JSON=1 after
// the bad property, so the failure still needs the schema-2 result.
func captureStandaloneSetupErrorIntent(arguments []string, opts *enterpriseSetupOptions) {
	for _, argument := range arguments {
		argument = strings.TrimSpace(argument)
		lower := strings.ToLower(argument)
		if lower == "--json" {
			opts.JSON = true
			continue
		}
		if strings.HasPrefix(lower, "/") {
			for _, action := range enterpriseSetupActions(true) {
				if lower == "/"+action {
					opts.Action = action
					break
				}
			}
			continue
		}
		name, value, found := strings.Cut(argument, "=")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "json", "--json":
			if enabled, err := strconv.ParseBool(value); err == nil {
				opts.JSON = enabled
			}
		case "action", "--action":
			opts.Action = strings.ToLower(strings.TrimSpace(value))
		}
	}
}

// standalonePathNames are the standalone Setup's file properties, whose
// values the path checks see as given.
var standalonePathNames = map[string]bool{"config": true, "manifest": true, "bundle": true, "trustanchors": true}

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
		"deferredconfig": "deferred-config",
		"allowunsigned":  "allow-unsigned", "corehardeningcertification": "core-hardening-certification",
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
		for name, canonical := range map[string]string{"allowedsigners": "allowed-signers", "bundle": "bundle", "trustanchors": "trust-anchors"} {
			valueNames[name] = canonical
		}
		boolNames["force"] = "force"
		boolNames["refusecapabilityloss"] = "refuse-capability-loss"
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
			if standalone && standalonePathNames[name] {
				// A path keeps its padding, so the path check refuses it as
				// the refusal says (GAP-0632).
				value = strings.TrimLeftFunc(argument, unicode.IsSpace)[separator+1:]
			}
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
			if standalone {
				return nil, false, fmt.Errorf("unknown property %s; run %s /? for the actions and the NAME=value properties (%s)",
					trimmed[:separator], standaloneSetupArtifactName, standaloneSetupPropertyHint())
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
	return loadBoundEnterprisePayload(result, standalonePayloadBinding)
}

// loadBoundEnterprisePayload validates a trailer read off the Setup image and
// requires its payload to match binding, the payload binding linked into
// the running image.
func loadBoundEnterprisePayload(result setuppayload.ReadResult, binding string) (enterprisePayload, error) {
	payload, err := loadEnterprisePayload(result.AsPayloadFS())
	if err != nil {
		return enterprisePayload{}, err
	}
	if err := requireEnterprisePayloadBinding(payload, binding); err != nil {
		return enterprisePayload{}, err
	}
	return payload, nil
}

// requireEnterprisePayloadBinding refuses a payload this Setup image was not
// built with. A stamped image (the standalone build) takes only the payload
// whose flavor, version, source commit and file digests produce its
// binding, of any flavor: the lifecycle acts on the manifest version
// (upgrade, compliant or downgrade refusal, and the recorded version), so a
// trailer with the same bytes but another identity is refused too. An image
// with no binding takes no standalone payload, since only the standalone
// build produces one; the Secure Client flavors keep their own checks.
func requireEnterprisePayloadBinding(payload enterprisePayload, binding string) error {
	if binding == "" {
		if payload.Standalone() {
			return errors.New("this Setup image has no payload binding, so it cannot vouch for its standalone payload; " +
				"build the standalone Setup with packaging/windows/standalone/build-setup.sh")
		}
		return nil
	}
	digests := make(map[string]string, len(payload.Files))
	for name, file := range payload.Files {
		digests[name] = file.SHA256
	}
	identity := setuppayload.PayloadIdentity{
		DistributionFlavor: payload.Manifest.DistributionFlavor,
		Version:            payload.Manifest.Version,
		SourceCommit:       payload.Manifest.SourceCommit,
	}
	if !strings.EqualFold(setuppayload.PayloadBinding(identity, digests), binding) {
		return errors.New("the payload this Setup read is not the payload its image was built with, so nothing was staged; " +
			"copy the Setup file your MDM delivered to a folder only administrators can change and run it again")
	}
	return nil
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

// writeEnterpriseSetupFailureAs reports err under the Setup file name.
func writeEnterpriseSetupFailureAs(stdout, stderr io.Writer, name string, opts enterpriseSetupOptions, err error) {
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
	fmt.Fprintf(stderr, "%s: %v\n", name, err)
}

// writeEnterpriseSetupFailureFor reports a failure of Setup itself. With
// JSON=1 the standalone Setup prints the lifecycle's schema-2 result, so an
// MDM reads one shape whether Setup or the lifecycle refused (GAP-0562). It
// reports no deployment state unless Setup's bounded timeout recovery
// proved one: its replay left no lifecycle record, and its status is shown.
func writeEnterpriseSetupFailureFor(stdout, stderr io.Writer, standalone bool, name string, opts enterpriseSetupOptions, err error, exitCode int) {
	if !standalone || !opts.JSON || err == nil {
		writeEnterpriseSetupFailureAs(stdout, stderr, name, opts, err)
		return
	}
	action := strings.ToLower(strings.TrimSpace(opts.Action))
	if action == "" {
		// Early argument errors have no action yet; use the schema's
		// install-like action so the MDM can still parse the failure.
		action = "ensure"
	}
	result := enterprisestatus.New(action, "standalone", "windows", opts.ProductVersion)
	code := "setup_failed"
	var invalid enterpriseSetupInvalidArguments
	var timeout enterpriseSetupLifecycleTimeout
	switch {
	case errors.Is(err, errEnterpriseSetupEnsureBusy):
		code = "lifecycle_busy"
	case errors.As(err, &invalid):
		code = "invalid_arguments"
	case errors.As(err, &timeout):
		code = "lifecycle_timeout"
	}
	if timeout.recovery != nil {
		// Recovery is a second, successful lifecycle query of the host. Keep
		// its proven deployment and service state, while this Setup request
		// still fails because its first child hit TIMEOUTSECONDS.
		recovered := *timeout.recovery
		recovered.Action = action
		recovered.AddError(code, err.Error())
		recovered.Finish("windows", exitCode)
		_ = json.NewEncoder(stdout).Encode(&recovered)
		return
	}
	result.AddError(code, err.Error())
	result.AddWarning("health_not_checked", "Setup stopped before the lifecycle reported on this computer, so installed, services and readiness are not evaluated; "+
		name+" /status JSON=1 reports them")
	result.Finish("windows", exitCode)
	_ = json.NewEncoder(stdout).Encode(result)
}

// enterpriseSetupLifecycleTimeout is a lifecycle run Setup stopped at its
// TIMEOUTSECONDS limit.
type enterpriseSetupLifecycleTimeout struct {
	error
	recovery *enterprisestatus.Result
}

func (err enterpriseSetupLifecycleTimeout) Unwrap() error { return err.error }

// standaloneEnterpriseSetupTimeoutBeforeLifecycle is Setup's error for a
// standalone run whose payload checks and unpacking used up TIMEOUTSECONDS
// (it counts from Setup's start, GAP-2509): the lifecycle child never
// started, so nothing changed and no recovery ran.
func standaloneEnterpriseSetupTimeoutBeforeLifecycle(opts enterpriseSetupOptions, cause error) error {
	limit := int(opts.LifecycleTimeout / time.Second)
	maximum := int(maximumLifecycleTimeout / time.Second)
	longer := "with a longer limit"
	if limit >= maximum {
		longer = fmt.Sprintf("again (%d seconds is the longest limit)", maximum)
	}
	return enterpriseSetupLifecycleTimeout{error: fmt.Errorf(
		"enterprise %s did not start within TIMEOUTSECONDS=%d (%w): the limit counts from Setup's start, and Setup's payload checks "+
			"and unpacking left too little of it to start the lifecycle, so it did not run and nothing was changed. Run %s as LocalSystem %s: %s",
		opts.Action, limit, cause, standaloneSetupArtifactName, longer, standaloneSetupRetryCommand(opts, maximum),
	)}
}

// standaloneEnterpriseSetupTimeout names the manual retry when Setup's own
// bounded replay could not prove restoration. That retry gets the longest
// limit: omitting TIMEOUTSECONDS would use the default the run hit.
func standaloneEnterpriseSetupTimeout(opts enterpriseSetupOptions, cause error) error {
	return standaloneEnterpriseSetupTimeoutWithRecovery(opts, cause, nil)
}

func standaloneEnterpriseSetupTimeoutWithRecovery(opts enterpriseSetupOptions, cause error, report *enterprisestatus.Result) error {
	config := opts.Config
	if strings.TrimSpace(config) == "" {
		config = "<config.yaml>"
	}
	limit := int(opts.LifecycleTimeout / time.Second)
	maximum := int(maximumLifecycleTimeout / time.Second)
	if report != nil {
		// The deployment is back as it was; what is left is the requested
		// action as it was given, which needs a longer limit than the one it
		// hit (GAP-1709, GAP-2114).
		retry := standaloneSetupRetryCommand(opts, maximum)
		longer := "with a longer limit"
		if limit >= maximum {
			longer = fmt.Sprintf("again (%d seconds is the longest limit)", maximum)
		}
		return enterpriseSetupLifecycleTimeout{error: fmt.Errorf(
			"enterprise %s did not finish within TIMEOUTSECONDS=%d and Setup stopped it (%w). "+
				"Setup replayed its pending transaction and no lifecycle record remains; this result is the recovered deployment's status, "+
				"and the requested action did not finish. Run %s as LocalSystem %s: %s",
			opts.Action, limit, cause, standaloneSetupArtifactName, longer, retry,
		), recovery: report}
	}
	recovery := fmt.Sprintf("/ensure CONFIG=%s JSON=1 TIMEOUTSECONDS=%d to recover (without TIMEOUTSECONDS the limit is the default %d seconds)",
		config, maximum, int(defaultLifecycleTimeout/time.Second))
	if limit >= maximum {
		recovery = fmt.Sprintf("/ensure CONFIG=%s JSON=1 TIMEOUTSECONDS=%d again to recover (%d seconds is the longest limit)", config, maximum, maximum)
	}
	return enterpriseSetupLifecycleTimeout{error: fmt.Errorf(
		"enterprise %s did not finish within TIMEOUTSECONDS=%d and Setup stopped it (%w). It may have left a lifecycle transaction pending with the DefenseClaw services stopped: "+
			"run %s /status JSON=1 to check, then run Setup as LocalSystem with %s",
		opts.Action, limit, cause, standaloneSetupArtifactName, recovery,
	)}
}

// standaloneSetupRetryCommand repeats a standalone Setup request as it was
// given, with TIMEOUTSECONDS at timeoutSeconds: the action and every property
// the run had, and no property it did not have (a BUNDLE= ensure stays a
// bundle ensure, an uninstall keeps PURGE=1 and FORCE=1). GAP-2114.
func standaloneSetupRetryCommand(opts enterpriseSetupOptions, timeoutSeconds int) string {
	parts := []string{"/" + opts.Action}
	value := func(name, v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if strings.ContainsAny(v, " \t") {
			v = `"` + v + `"`
		}
		parts = append(parts, name+"="+v)
	}
	flag := func(name string, on bool) {
		if on {
			parts = append(parts, name+"=1")
		}
	}
	value("CONFIG", opts.Config)
	value("MANIFEST", opts.Manifest)
	value("BUNDLE", opts.Bundle)
	value("TRUSTANCHORS", opts.TrustAnchors)
	value("MODE", opts.Mode)
	value("CONNECTOR", opts.Connector)
	flag("REFUSECAPABILITYLOSS", opts.RefuseCapabilityLoss)
	flag("NOSTART", opts.NoStart)
	flag("PURGE", opts.Purge)
	flag("FORCE", opts.Force)
	value("ALLOWEDSIGNERS", opts.AllowedSigners)
	flag("ATTESTCLAUDEEFFECTIVEPOLICY", opts.AttestClaudeEffectivePolicy)
	flag("ATTESTAGENTAPPLICATIONCONTROL", opts.AttestAgentApplicationControl)
	value("INSTALLROOT", opts.InstallRoot)
	value("STATEROOT", opts.StateRoot)
	value("GATEWAYSERVICENAME", opts.GatewayServiceName)
	value("GUARDIANSERVICENAME", opts.GuardianServiceName)
	value("CERTIFICATIONCODEXHOME", opts.CertificationCodexHome)
	flag("ALLOWUNSIGNED", opts.AllowUnsigned)
	flag("COREHARDENINGCERTIFICATION", opts.CoreHardeningCertification)
	flag("JSON", opts.JSON)
	parts = append(parts, fmt.Sprintf("TIMEOUTSECONDS=%d", timeoutSeconds))
	return strings.Join(parts, " ")
}

// writeEnterpriseSetupUsage prints the Secure Client Setup usage.
func writeEnterpriseSetupUsage(output io.Writer) {
	writeEnterpriseSetupUsageForFlavor(output, false)
}

func writeEnterpriseSetupUsageForFlavor(output io.Writer, standalone bool) {
	if standalone {
		writeStandaloneSetupUsage(output)
		return
	}
	actions := enterpriseSetupActions(standalone)
	sort.Strings(actions)
	fmt.Fprintf(output, "%s --action <%s> [options]\n", enterpriseSetupArtifactName, strings.Join(actions, "|"))
	fmt.Fprintln(output, "Install takes --config <config.yaml> and --manifest <targets.yaml> together; with neither, it stages a disabled deployment that a later Repair with both files activates.")
	if standalone {
		fmt.Fprintln(output, "Ensure (standalone Setup) converges the host: install, upgrade, repair, or no-op.")
	}
	fmt.Fprintln(output, "Production paths and service names are fixed by the enterprise lifecycle.")
}

// standaloneSetupUsageProperty matches a property row of
// writeStandaloneSetupUsage: its name and the value it shows.
var standaloneSetupUsageProperty = lazyregexp.New(`(?m)^  ([A-Z]+)=(\S*)`)

// standaloneSetupPropertyHint lists the properties /? prints, read from
// writeStandaloneSetupUsage itself, so the unknown-property hint cannot miss
// one the usage gains. A hand-kept copy lacked REFUSECAPABILITYLOSS=1
// (GAP-2398). A placeholder value (<path>, <n>, <sha256>) is shown as NAME=,
// a literal one as NAME=1.
func standaloneSetupPropertyHint() string {
	var usage strings.Builder
	writeStandaloneSetupUsage(&usage)
	var names []string
	for _, match := range standaloneSetupUsageProperty.FindAllStringSubmatch(usage.String(), -1) {
		value := match[2]
		if strings.HasPrefix(value, "<") {
			value = ""
		}
		names = append(names, match[1]+"="+value)
	}
	return strings.Join(names, ", ")
}

// writeStandaloneSetupUsage prints the standalone Setup usage in the form
// windows.mdx documents: /action switches and NAME=value properties. It
// printed the Secure Client Setup name and --action flags (GAP-0353).
func writeStandaloneSetupUsage(output io.Writer) {
	fmt.Fprintf(output, "%s /ensure [NAME=value ...]\n", standaloneSetupArtifactName)
	fmt.Fprintln(output, "  /ensure converges the computer: install, upgrade, repair, or nothing to do.")
	fmt.Fprintln(output, "  Other actions: /install /upgrade /repair /reconcile /status /verify /uninstall")
	fmt.Fprintln(output, "Properties (case-insensitive, dashes ignored):")
	fmt.Fprintln(output, "  CONFIG=<path>                  administrator config; required for the first install")
	fmt.Fprintln(output, "  MANIFEST=<path>                target manifest you publish yourself; required for /install")
	fmt.Fprintln(output, "  BUNDLE=<path>                  with /ensure: apply this signed policy bundle; with CONFIG= on a new computer, the first install starts on the bundle")
	fmt.Fprintln(output, "  TRUSTANCHORS=<path>            with /ensure BUNDLE=: install this administrator-only bundle trust anchor file with the bundle")
	fmt.Fprintln(output, "  REFUSECAPABILITYLOSS=1         with /ensure: refuse a bundle that disables an enforced capability")
	fmt.Fprintln(output, "  JSON=1                         print the result document on standard output")
	fmt.Fprintln(output, "  NOSTART=1                      install or update with the services stopped and disabled")
	fmt.Fprintln(output, "  PURGE=1                        with /uninstall: also remove the DefenseClaw files of each enrolled account")
	fmt.Fprintln(output, "  FORCE=1                        with /uninstall, last resort: remove the deployment without recovering a pending transaction")
	fmt.Fprintln(output, "  TIMEOUTSECONDS=<n>             lifecycle timeout, 60 to 7200 seconds (default 1800)")
	fmt.Fprintln(output, "  ALLOWEDSIGNERS=<sha256>,...    accept only these Authenticode signer certificates")
	fmt.Fprintln(output, "  ATTESTCLAUDEEFFECTIVEPOLICY=1  with /repair: record that Claude Code runs the managed hooks")
	fmt.Fprintf(output, "Example: %s /ensure CONFIG=C:\\ProgramData\\DefenseClaw-Staging\\config.yaml JSON=1\n", standaloneSetupArtifactName)
	fmt.Fprintln(output, "Exit codes: 0 success, 1603 failure, 1618 busy, 1639 invalid arguments.")
}
