// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// DefenseClawSetup-Enterprise-x64.exe is the machine-wide bootstrap for the
// Windows managed-enterprise lifecycle. It is intentionally separate from the
// ordinary per-user Setup executable: their elevation, path, service, and
// rollback contracts are different security boundaries.
package main

import (
	"context"
	"embed"
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
)

//go:embed payload/*
var embeddedPayload embed.FS

const (
	enterpriseSetupArtifactName = "DefenseClawSetup-Enterprise-x64.exe"
	enterpriseFailureExitCode   = 1603
	defaultLifecycleTimeout     = 30 * time.Minute
	maximumLifecycleTimeout     = 2 * time.Hour
	maximumPayloadFileBytes     = int64(512 << 20)
	maximumPayloadTotalBytes    = int64(1 << 30)
)

var sourceCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

var requiredPayloadFiles = []string{
	"DefenseClawEnterprise.psm1",
	"defenseclaw-gateway.exe",
	"defenseclaw-hook.exe",
	"defenseclaw.exe",
	"install-enterprise.ps1",
}

type enterpriseSetupOptions struct {
	Action                         string
	Config                         string
	Manifest                       string
	InstallRoot                    string
	StateRoot                      string
	GatewayServiceName             string
	GuardianServiceName            string
	CertificationCodexHome         string
	CodexTrustedHookLauncherBinary string
	NoStart                        bool
	Purge                          bool
	JSON                           bool
	AllowUnsigned                  bool
	CoreHardeningCertification     bool
	AttestAgentApplicationControl  bool
	AttestClaudeEffectivePolicy    bool
	AttestCodexTrustedHookLauncher bool
	// DeferredConfig turns on the UCB-friendly late-config install
	// path from spec 003 (docs/specs/003-windows-deferred-config/):
	// --config and --manifest become optional at install time; the
	// installer provisions the canonical drop-point directories with
	// ACLs but writes no file bodies; the daemon + guardian fsnotify-
	// wait for UCB to atomically drop them later.
	DeferredConfig   bool
	LifecycleTimeout time.Duration
}

type enterprisePayloadManifest struct {
	SchemaVersion      int               `json:"schema_version"`
	Version            string            `json:"version"`
	SourceCommit       string            `json:"source_commit"`
	DistributionFlavor string            `json:"distribution_flavor"`
	Unsigned           bool              `json:"unsigned"`
	Files              map[string]string `json:"files"`
}

type enterprisePayload struct {
	Manifest enterprisePayloadManifest
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

func runEnterpriseSetup(arguments []string, stdout, stderr io.Writer) int {
	opts, help, err := parseEnterpriseSetupOptions(arguments)
	if help {
		writeEnterpriseSetupUsage(stdout)
		return 0
	}
	if err != nil {
		writeEnterpriseSetupFailure(stdout, stderr, opts, err)
		return enterpriseFailureExitCode
	}
	exitCode, err := executeEnterpriseSetup(context.Background(), opts, stdout, stderr)
	if err != nil {
		writeEnterpriseSetupFailure(stdout, stderr, opts, err)
		return enterpriseFailureExitCode
	}
	if exitCode != 0 {
		return exitCode
	}
	return 0
}

func parseEnterpriseSetupOptions(arguments []string) (enterpriseSetupOptions, bool, error) {
	opts := enterpriseSetupOptions{LifecycleTimeout: defaultLifecycleTimeout}
	normalized, help, err := normalizeEnterpriseSetupArguments(arguments)
	if err != nil || help {
		return opts, help, err
	}
	flags := flag.NewFlagSet(enterpriseSetupArtifactName, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.Action, "action", "", "enterprise lifecycle action")
	flags.StringVar(&opts.Config, "config", "", "administrator-approved config.yaml")
	flags.StringVar(&opts.Manifest, "manifest", "", "administrator-approved targets.yaml")
	flags.StringVar(&opts.InstallRoot, "install-root", "", "certification-only install root")
	flags.StringVar(&opts.StateRoot, "state-root", "", "certification-only state root")
	flags.StringVar(&opts.GatewayServiceName, "gateway-service-name", "", "certification-only gateway service name")
	flags.StringVar(&opts.GuardianServiceName, "guardian-service-name", "", "certification-only guardian service name")
	flags.StringVar(&opts.CertificationCodexHome, "certification-codex-home", "", "certification-only CODEX_HOME")
	flags.StringVar(&opts.CodexTrustedHookLauncherBinary, "codex-trusted-hook-launcher-binary", "", "approved fail-closed Codex launcher")
	flags.BoolVar(&opts.NoStart, "no-start", false, "install services disabled and stopped")
	flags.BoolVar(&opts.Purge, "purge", false, "remove managed state during uninstall")
	flags.BoolVar(&opts.JSON, "json", false, "emit machine-readable lifecycle output")
	flags.BoolVar(&opts.AllowUnsigned, "allow-unsigned", false, "allow only exact disposable certification scope")
	flags.BoolVar(&opts.CoreHardeningCertification, "core-hardening-certification", false, "run the unsigned core-only certification profile")
	flags.BoolVar(&opts.AttestAgentApplicationControl, "attest-agent-application-control", false, "attest live WDAC or AppLocker enforcement")
	flags.BoolVar(&opts.AttestClaudeEffectivePolicy, "attest-claude-effective-policy", false, "attest Claude managed-policy precedence")
	flags.BoolVar(&opts.AttestCodexTrustedHookLauncher, "attest-codex-trusted-hook-launcher", false, "attest the supplied fail-closed Codex launcher")
	flags.BoolVar(&opts.DeferredConfig, "deferred-config", false, "spec 003 UCB-friendly install: --config and --manifest optional; services registered stopped")
	timeoutSeconds := int(defaultLifecycleTimeout / time.Second)
	flags.IntVar(&timeoutSeconds, "timeout-seconds", timeoutSeconds, "bounded lifecycle timeout")
	if err := flags.Parse(normalized); err != nil {
		return opts, false, err
	}
	if flags.NArg() != 0 {
		return opts, false, fmt.Errorf("unexpected positional argument %q", flags.Arg(0))
	}
	opts.Action = strings.ToLower(strings.TrimSpace(opts.Action))
	validActions := map[string]bool{
		"install": true, "upgrade": true, "repair": true,
		"reconcile": true, "status": true, "verify": true, "uninstall": true,
	}
	if !validActions[opts.Action] {
		return opts, false, errors.New("--action must be install, upgrade, repair, reconcile, status, verify, or uninstall")
	}
	if opts.Action == "install" && !opts.DeferredConfig &&
		(strings.TrimSpace(opts.Config) == "" || strings.TrimSpace(opts.Manifest) == "") {
		// --deferred-config bypasses the config/manifest requirement:
		// the installer will provision the drop-point directories
		// with ACLs but write no file bodies; UCB atomically writes
		// the bodies later, and the daemon + guardian fsnotify-wait
		// pick them up. Spec 003 REQ-02 / REQ-03.
		return opts, false, errors.New("install requires both --config and --manifest (or --deferred-config for the UCB-friendly late-arrival path)")
	}
	if opts.DeferredConfig && opts.Action != "install" {
		// Spec 003 --deferred-config is meaningful only at initial
		// install. Upgrade/repair use the config/manifest already on
		// disk; deferring them would leave the deployment offline.
		// CR spec-003:PRRT_kwDORuAK-s6alkr4.
		return opts, false, errors.New("--deferred-config is valid only with install")
	}
	mutation := opts.Action == "install" || opts.Action == "upgrade" || opts.Action == "repair"
	if opts.NoStart && !mutation {
		return opts, false, errors.New("--no-start is valid only with install, upgrade, or repair")
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
	if opts.AttestCodexTrustedHookLauncher !=
		(strings.TrimSpace(opts.CodexTrustedHookLauncherBinary) != "") {
		return opts, false, errors.New("--attest-codex-trusted-hook-launcher and --codex-trusted-hook-launcher-binary must be supplied together")
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

func normalizeEnterpriseSetupArguments(arguments []string) ([]string, bool, error) {
	normalized := make([]string, 0, len(arguments))
	valueNames := map[string]string{
		"action": "action", "config": "config", "manifest": "manifest",
		"installroot": "install-root", "stateroot": "state-root",
		"gatewayservicename": "gateway-service-name", "guardianservicename": "guardian-service-name",
		"certificationcodexhome":         "certification-codex-home",
		"codextrustedhooklauncherbinary": "codex-trusted-hook-launcher-binary",
		"timeoutseconds":                 "timeout-seconds",
	}
	boolNames := map[string]string{
		"nostart": "no-start", "purge": "purge", "json": "json",
		"allowunsigned": "allow-unsigned", "corehardeningcertification": "core-hardening-certification",
		"attestagentapplicationcontrol":  "attest-agent-application-control",
		"attestclaudeeffectivepolicy":    "attest-claude-effective-policy",
		"attestcodextrustedhooklauncher": "attest-codex-trusted-hook-launcher",
	}
	actions := map[string]string{
		"/install": "install", "/upgrade": "upgrade", "/repair": "repair",
		"/reconcile": "reconcile", "/status": "status", "/verify": "verify",
		"/uninstall": "uninstall",
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

func loadEmbeddedEnterprisePayload() (enterprisePayload, error) {
	manifestBytes, err := fs.ReadFile(embeddedPayload, "payload/manifest.json")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return enterprisePayload{}, errors.New("enterprise payload missing; build with scripts/build-windows-enterprise-installer.ps1")
		}
		return enterprisePayload{}, fmt.Errorf("read embedded enterprise manifest: %w", err)
	}
	var manifest enterprisePayloadManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return enterprisePayload{}, fmt.Errorf("parse embedded enterprise manifest: %w", err)
	}
	if manifest.SchemaVersion != 1 || strings.TrimSpace(manifest.Version) == "" ||
		!sourceCommitPattern.MatchString(manifest.SourceCommit) ||
		manifest.DistributionFlavor != "managed-enterprise" {
		return enterprisePayload{}, errors.New("embedded enterprise manifest identity is invalid")
	}
	if len(manifest.Files) != len(requiredPayloadFiles) {
		return enterprisePayload{}, errors.New("embedded enterprise manifest has an unexpected file inventory")
	}
	var totalSize int64
	for _, name := range requiredPayloadFiles {
		expected, ok := manifest.Files[name]
		if !ok || !sha256Pattern.MatchString(expected) {
			return enterprisePayload{}, fmt.Errorf("embedded enterprise manifest is missing a valid SHA-256 for %s", name)
		}
		info, err := fs.Stat(embeddedPayload, "payload/"+name)
		if err != nil {
			return enterprisePayload{}, fmt.Errorf("inspect embedded enterprise payload %s: %w", name, err)
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumPayloadFileBytes {
			return enterprisePayload{}, fmt.Errorf("embedded enterprise payload has invalid type or size: %s", name)
		}
		totalSize += info.Size()
		if totalSize > maximumPayloadTotalBytes {
			return enterprisePayload{}, fmt.Errorf("embedded enterprise payload exceeds %d bytes", maximumPayloadTotalBytes)
		}
	}
	return enterprisePayload{Manifest: manifest}, nil
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

func writeEnterpriseSetupUsage(output io.Writer) {
	actions := []string{"install", "upgrade", "repair", "reconcile", "status", "verify", "uninstall"}
	sort.Strings(actions)
	fmt.Fprintf(output, "%s --action <%s> [options]\n", enterpriseSetupArtifactName, strings.Join(actions, "|"))
	fmt.Fprintln(output, "Install requires --config <config.yaml> and --manifest <targets.yaml>.")
	fmt.Fprintln(output, "Production paths and service names are fixed by the enterprise lifecycle.")
}
