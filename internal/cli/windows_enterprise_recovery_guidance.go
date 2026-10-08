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
	"fmt"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// Recovery evidence and failure guidance for the standalone Windows
// lifecycle. The Windows-only wrapper feeds these the installer's report;
// the logic itself is platform-neutral so every platform tests it.

const windowsEnterpriseStandaloneSetupName = "DefenseClawSetup-Enterprise-Standalone-x64.exe"

// windowsEnterpriseRecoveryGatewayRun is one managed-hook lifecycle step
// that a pending transaction's recovery ran with the running Setup's
// verified gateway because the transaction's staged gateway failed it.
type windowsEnterpriseRecoveryGatewayRun struct {
	Action           string `json:"action"`
	Binary           string `json:"binary"`
	Source           string `json:"source"`
	SHA256           string `json:"sha256"`
	Trust            string `json:"trust"`
	SignerThumbprint string `json:"signer_thumbprint"`
	ProductVersion   string `json:"product_version"`
	Identity         string `json:"identity"`
	ReplacedSHA256   string `json:"replaced_sha256"`
	StagedVersion    string `json:"staged_version"`
	Reason           string `json:"reason"`
	StagedError      string `json:"staged_error"`
	Outcome          string `json:"outcome"`
	Error            string `json:"error"`
}

// windowsEnterpriseRecoveryGatewayRefusal says why a recovery did not fall
// back to the running Setup's gateway after the staged gateway failed.
type windowsEnterpriseRecoveryGatewayRefusal struct {
	Action  string `json:"action"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// decodeWindowsEnterpriseRecoveryGatewayRuns reads the installer's
// recovery_gateway_runs leniently: one object is one run, and a malformed
// value is ignored so it never hides the lifecycle's own report.
func decodeWindowsEnterpriseRecoveryGatewayRuns(raw json.RawMessage) []windowsEnterpriseRecoveryGatewayRun {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	var runs []windowsEnterpriseRecoveryGatewayRun
	if err := json.Unmarshal(raw, &runs); err != nil {
		var single windowsEnterpriseRecoveryGatewayRun
		if json.Unmarshal(raw, &single) != nil {
			return nil
		}
		runs = []windowsEnterpriseRecoveryGatewayRun{single}
	}
	out := runs[:0]
	for _, run := range runs {
		if strings.TrimSpace(run.Action) != "" && strings.TrimSpace(run.Binary) != "" {
			out = append(out, run)
		}
	}
	return out
}

func decodeWindowsEnterpriseRecoveryGatewayRefusal(raw json.RawMessage) *windowsEnterpriseRecoveryGatewayRefusal {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	var refusal windowsEnterpriseRecoveryGatewayRefusal
	if json.Unmarshal(raw, &refusal) != nil || strings.TrimSpace(refusal.Code) == "" {
		return nil
	}
	return &refusal
}

// windowsEnterpriseRecoveryStepLabel names a recovery step for the
// administrator: the target-runtime rollback cleanup, or a managed-hook
// lifecycle action (restore, retire).
func windowsEnterpriseRecoveryStepLabel(action string) string {
	action = strings.TrimSpace(action)
	switch action {
	case "target-runtime-cleanup":
		return "target-runtime rollback cleanup"
	case windowsEnterpriseRecoveryReactivationAction:
		return "service reactivation of the restored release"
	}
	return "managed-hook lifecycle " + action
}

// windowsEnterpriseRecoveryReactivationAction is the recovery record of a
// pending transaction whose restored release could not be reactivated and
// was left stopped for this Setup's own release to replace.
const windowsEnterpriseRecoveryReactivationAction = "service-reactivation"

// windowsEnterpriseRecoveryDeferredActivation reports whether an installer
// report's recovery_gateway_runs say the recovery left the restored release
// stopped (outcome "deferred").
func windowsEnterpriseRecoveryDeferredActivation(runs json.RawMessage) bool {
	for _, run := range decodeWindowsEnterpriseRecoveryGatewayRuns(runs) {
		if run.Action == windowsEnterpriseRecoveryReactivationAction && run.Outcome == "deferred" {
			return true
		}
	}
	return false
}

// windowsEnterpriseRecoveryGatewayWarnings records, for the result document
// and the lifecycle log, which gateway each recovery step ran and why, and
// why a recovery kept the staged gateway.
func windowsEnterpriseRecoveryGatewayWarnings(
	runs []windowsEnterpriseRecoveryGatewayRun,
	refusal *windowsEnterpriseRecoveryGatewayRefusal,
) []enterprisestatus.Message {
	var warnings []enterprisestatus.Message
	for _, run := range runs {
		staged, _ := windowsEnterpriseStandaloneErrorText(run.StagedError)
		if strings.TrimSpace(staged) == "" {
			staged = "no detail"
		}
		if run.Action == windowsEnterpriseRecoveryReactivationAction {
			message := fmt.Sprintf(
				"recovery left the restored release %s stopped because it could not be reactivated (%s); this Setup's verified release %s (%s, sha256 %s, trust %s) replaces it, as %s",
				run.StagedVersion, staged, run.ProductVersion, run.Source, run.SHA256, run.Trust, run.Identity,
			)
			warnings = append(warnings, enterprisestatus.Message{Code: "recovery_activation_deferred", Message: message})
			continue
		}
		message := fmt.Sprintf(
			"recovery ran the %s with this Setup's verified gateway because the staged gateway failed it (%s); binary %s (copied from %s), sha256 %s, trust %s",
			windowsEnterpriseRecoveryStepLabel(run.Action), staged, run.Binary, run.Source, run.SHA256, run.Trust,
		)
		if run.SignerThumbprint != "" {
			message += ", signer " + run.SignerThumbprint
		}
		if run.ProductVersion != "" {
			message += ", version " + run.ProductVersion
		}
		message += ", as " + run.Identity
		if run.ReplacedSHA256 != "" {
			message += ", replaced staged sha256 " + run.ReplacedSHA256
		}
		if run.StagedVersion != "" {
			message += ", staged version " + run.StagedVersion
		}
		message += "; outcome " + run.Outcome
		if run.Error != "" {
			failure, _ := windowsEnterpriseStandaloneErrorText(run.Error)
			message += ": " + failure
		}
		warnings = append(warnings, enterprisestatus.Message{Code: "recovery_gateway_fallback", Message: message})
	}
	if refusal != nil {
		warnings = append(warnings, enterprisestatus.Message{
			Code: "recovery_gateway_not_used",
			Message: fmt.Sprintf(
				"recovery kept the staged gateway for the %s (%s): %s",
				windowsEnterpriseRecoveryStepLabel(refusal.Action), refusal.Code, refusal.Message,
			),
		})
	}
	return warnings
}

var (
	// Internal security-descriptor detail that a failed lifecycle must not
	// hand the administrator as its error.
	windowsEnterpriseSecurityDetailPattern = regexp.MustCompile(`(?i)\b(DACLs?|ACEs?|ACLs?|SDDL|security descriptors?)\b`)
	windowsEnterpriseSecurityRewrites      = []struct {
		pattern *regexp.Regexp
		plain   string
	}{
		{
			regexp.MustCompile(`(?i)managed Windows DACL on (.+?) has \d+ ACEs?, expected \d+`),
			"the permissions on $1 are not the ones DefenseClaw set",
		},
		{
			regexp.MustCompile(`(?i)inspect Windows security descriptor for ([A-Za-z]:\\[^:;]*?): ([^:;]+)`),
			"DefenseClaw could not read the permissions on $1 ($2)",
		},
		{
			regexp.MustCompile(`(?i)([A-Za-z]:\\[^:;]*?): inspect Windows security descriptor: ([^:;]+)`),
			"DefenseClaw could not read the permissions on $1 ($2)",
		},
		{
			regexp.MustCompile(`(?i)(?:enterprise hooks: )?read DACL of ([A-Za-z]:\\[^:;]*?): ([^:;]+)`),
			"DefenseClaw could not read the permissions on $1 ($2)",
		},
	}
	windowsEnterpriseDrivePathPattern = regexp.MustCompile(`[A-Za-z]:\\`)
)

// windowsEnterpriseStandaloneErrorText turns a lifecycle diagnostic into the
// text an administrator reads. Internal security-descriptor detail (ACE
// counts, DACL shapes, SDDL) becomes a plain statement about the path it
// concerns; internal reports whether anything was rewritten, in which case
// the caller keeps the original as a diagnostic.
func windowsEnterpriseStandaloneErrorText(message string) (text string, internal bool) {
	text = strings.TrimSpace(message)
	if !windowsEnterpriseSecurityDetailPattern.MatchString(text) {
		return text, false
	}
	for _, rewrite := range windowsEnterpriseSecurityRewrites {
		text = rewrite.pattern.ReplaceAllString(text, rewrite.plain)
	}
	if !windowsEnterpriseSecurityDetailPattern.MatchString(text) {
		return text, true
	}
	// Unknown internal detail: keep the context before the first clause that
	// carries it and state the finding plainly.
	segments := strings.Split(text, ": ")
	for index, segment := range segments {
		if !windowsEnterpriseSecurityDetailPattern.MatchString(segment) {
			continue
		}
		plain := "DefenseClaw could not verify or apply the permissions of a managed path"
		if path := windowsEnterpriseFirstWindowsPath(strings.Join(segments[index:], ": ")); path != "" {
			plain = "DefenseClaw could not verify or apply the permissions on " + path
		}
		if index == 0 {
			return plain, true
		}
		return strings.Join(segments[:index], ": ") + ": " + plain, true
	}
	return text, true
}

// windowsEnterprisePerUserDataDirNextStep names the next step when Setup
// refused a user's .defenseclaw folder it did not create: the data folder of
// a per-user install, which `defenseclaw uninstall --binaries` keeps. Setup
// never adopts it (that user controls it), so the folder has to go first.
func windowsEnterprisePerUserDataDirNextStep(original, text string) string {
	if !strings.Contains(original, "reject noncanonical managed runtime baseline") {
		return ""
	}
	folder := `that user's %USERPROFILE%\.defenseclaw`
	if path := windowsEnterpriseFirstWindowsPath(text); path != "" {
		if index := strings.Index(strings.ToLower(path), `\.defenseclaw`); index >= 0 {
			folder = path[:index+len(`\.defenseclaw`)]
		}
	}
	return ". DefenseClaw's managed install did not create " + folder +
		"; a per-user DefenseClaw install leaves it, also after `defenseclaw uninstall --binaries`." +
		" Next step: have that user run `defenseclaw uninstall --all --binaries --yes`, or move " + folder +
		" out of the profile, then run Setup again."
}

// windowsEnterpriseCommittedJournalNextStep says what an install, upgrade or
// repair that committed but could not retire its managed-hook lifecycle
// journal leaves, and how it converges. The result failed with 1603 while
// DefenseClaw was installed and running, and named no remedy (GAP-0741). A
// per-user .defenseclaw folder named in the error is the usual cause.
func windowsEnterpriseCommittedJournalNextStep(original string, installed bool) string {
	if !installed || !strings.Contains(original, "committed, but its protected managed-hook lifecycle journal could not be retired") {
		return ""
	}
	step := ". The change is committed and DefenseClaw is installed and running; only the clean-up of its lifecycle journal failed."
	if path := windowsEnterpriseFirstWindowsPath(original); path != "" {
		if index := strings.Index(strings.ToLower(path), `\.defenseclaw`); index >= 0 {
			folder := path[:index+len(`\.defenseclaw`)]
			step += " " + folder + " was left by a per-user DefenseClaw install, whose permissions the managed install does not change:" +
				" have that user run `defenseclaw uninstall --all --binaries --yes`, or move the folder out of the profile."
		}
	}
	return step + " Next step: run Setup /ensure again; it removes the stale journal and converges."
}

// windowsEnterpriseInvalidRuntimeBundleNextStep names the next step when a
// lifecycle refused to collect a managed runtime bundle it cannot confirm
// belongs to this deployment (GAP-1419): the error named no file, no reason
// and no way forward. DefenseClaw keeps such a file rather than delete what
// it cannot attribute, so support has to look at it.
func windowsEnterpriseInvalidRuntimeBundleNextStep(original string) string {
	if !strings.Contains(original, "refusing to collect") || !strings.Contains(original, "managed runtime bundle") {
		return ""
	}
	file := "the managed runtime bundle named above"
	if path := windowsEnterpriseFirstWindowsPath(original[strings.Index(original, "refusing to collect"):]); path != "" {
		file = path
	}
	return ". DefenseClaw does not delete a managed runtime bundle it cannot attribute to this deployment, so the lifecycle stopped." +
		" Next step: leave " + file + " in place and send it with the lifecycle log (" + windowsEnterpriseLifecycleLogPath +
		") to DefenseClaw support"
}

// windowsEnterpriseLifecycleLogPath is the lifecycle log Setup and the CLI
// write, as an administrator finds it.
const windowsEnterpriseLifecycleLogPath = `C:\Windows\Logs\DefenseClaw\enterprise-lifecycle.log`

// windowsEnterpriseInstallerBuildMismatchText rewrites the installer's
// refusal of a module whose SHA-256 is not the one the installed deployment
// recorded: the CLI that ran carries the installer of another DefenseClaw
// build (GAP-1658). ok is false for any other message.
func windowsEnterpriseInstallerBuildMismatchText(message, action string, purge bool) (text string, ok bool) {
	if !strings.Contains(message, "installer module SHA-256 does not match the pinned payload manifest") {
		return "", false
	}
	command := action
	if action == "uninstall" && purge {
		command += " --purge"
	}
	return "this CLI does not match the installed DefenseClaw: the enterprise installer module it carries is not the one the installed deployment recorded" +
		" (a CLI from another DefenseClaw build, or a changed module file), so the " + action + " stopped before it changed anything." +
		" Next step: run the installed CLI, " + windowsEnterpriseAdminCommand(command) +
		", or the DefenseClaw Setup of the installed release; to move to another release, run that release's Setup", true
}

// windowsEnterprisePerUserGatewayHolder reports a listener that is a
// per-user install's DefenseClaw gateway: the gateway binary running as an
// account. A managed gateway runs as a service identity (NT SERVICE or NT
// AUTHORITY), for example another deployment's while this one's service
// process is unknown.
func windowsEnterprisePerUserGatewayHolder(image, account string) bool {
	base := image[strings.LastIndexAny(image, `\/`)+1:]
	if !strings.EqualFold(base, "defenseclaw-gateway.exe") {
		return false
	}
	domain, _, found := strings.Cut(strings.TrimSpace(account), `\`)
	if !found {
		return false
	}
	return !strings.EqualFold(domain, "NT SERVICE") && !strings.EqualFold(domain, "NT AUTHORITY")
}

// windowsEnterpriseFirstWindowsPath returns the first drive-letter path in
// text, ending at the first delimiter that cannot be part of it here.
func windowsEnterpriseFirstWindowsPath(text string) string {
	location := windowsEnterpriseDrivePathPattern.FindStringIndex(text)
	if location == nil {
		return ""
	}
	rest := text[location[0]:]
	end := len(rest)
	for _, delimiter := range []string{": ", " has ", " is ", " for ", ";", ",", ")", "\"", "'"} {
		if index := strings.Index(rest[3:], delimiter); index >= 0 && index+3 < end {
			end = index + 3
		}
	}
	return strings.TrimRight(strings.TrimSpace(rest[:end]), ".")
}

// windowsEnterpriseStandaloneSetupCommand is the Setup command line that
// recovers a pending transaction for action. A purge keeps PURGE=1, so the
// re-run finishes the uninstall the administrator asked for.
func windowsEnterpriseStandaloneSetupCommand(action, configPath string, purge bool) string {
	if action == "uninstall" {
		if purge {
			return windowsEnterpriseStandaloneSetupName + " /uninstall PURGE=1 JSON=1"
		}
		return windowsEnterpriseStandaloneSetupName + " /uninstall JSON=1"
	}
	config := strings.TrimSpace(configPath)
	switch {
	case config == "":
		config = "<config.yaml>"
	case strings.ContainsAny(config, " \t"):
		config = `"` + config + `"`
	}
	return windowsEnterpriseStandaloneSetupName + " /ensure CONFIG=" + config + " JSON=1"
}

// windowsEnterprisePendingInspectionStep is what status and verify say about
// a pending transaction. Status named only not_ready and the installed
// version, and verify said "run Repair", which an administrator shell cannot
// use to recover it; a failed Setup names this same command.
func windowsEnterprisePendingInspectionStep(configPath string) string {
	return "A lifecycle transaction is pending, so the DefenseClaw services stay stopped until it finishes or is recovered. " +
		"If no DefenseClaw Setup or lifecycle command is running now, run DefenseClaw Setup (this release or a newer one) as LocalSystem: " +
		windowsEnterpriseStandaloneSetupCommand("ensure", configPath, false) + "; as LocalSystem, Setup recovers the transaction with its own verified gateway."
}

// windowsEnterpriseStandaloneNextStep names what the administrator runs
// after a failed lifecycle left its transaction pending: the exact Setup
// command, and when the recovery could not use this Setup's gateway, why.
// It is empty when nothing is pending.
func windowsEnterpriseStandaloneNextStep(
	action string,
	configPath string,
	purge bool,
	pending bool,
	runs []windowsEnterpriseRecoveryGatewayRun,
	refusal *windowsEnterpriseRecoveryGatewayRefusal,
) string {
	if !pending {
		return ""
	}
	command := windowsEnterpriseStandaloneSetupCommand(action, configPath, purge)
	const lead = "The transaction is still pending: the DefenseClaw services stay stopped until it is recovered."
	const recovers = "; as LocalSystem, Setup recovers the transaction with its own verified gateway."
	if len(runs) != 0 {
		return lead + " Recovery ran with this Setup's verified gateway and still did not finish." +
			" Next step: leave DefenseClaw files and permissions as they are, send the lifecycle log to DefenseClaw support," +
			" and run a DefenseClaw Setup that fixes this failure as LocalSystem: " + command + "."
	}
	code := ""
	detail := ""
	if refusal != nil {
		code = refusal.Code
		detail = strings.TrimSpace(refusal.Message)
	}
	switch code {
	case "not_local_system":
		return lead + " This run was not LocalSystem, so it could not recover with its own gateway." +
			" Next step: run the same Setup as LocalSystem (the MDM System context, or a one-time scheduled task that runs as SYSTEM): " +
			command + recovers
	case "same_binary":
		return lead + " This Setup's gateway is the one that failed." +
			" Next step: run a newer DefenseClaw Setup that fixes this failure as LocalSystem: " + command + recovers
	case "untrusted", "unsigned_scope":
		if detail != "" {
			detail = " (" + detail + ")"
		}
		return lead + " This Setup's gateway did not pass the payload trust check" + detail + "." +
			" Next step: run a DefenseClaw Setup whose payload passes the deployment's trust mode, as LocalSystem: " + command + recovers
	case "older_release":
		if detail != "" {
			detail = " (" + detail + ")"
		}
		return lead + " This Setup is an older release than the one that staged the transaction" + detail + "." +
			" Next step: run a DefenseClaw Setup of that release or a newer one as LocalSystem: " + command + recovers
	case "version_unknown":
		if detail != "" {
			detail = " (" + detail + ")"
		}
		return lead + " The release of this Setup's gateway or of the staged gateway could not be read" + detail + "." +
			" Next step: leave DefenseClaw files and permissions as they are, send the lifecycle log to DefenseClaw support," +
			" and run a DefenseClaw Setup whose gateway carries its release version as LocalSystem: " + command + recovers
	default:
		return lead + " Next step: run DefenseClaw Setup (this release or a newer one) as LocalSystem: " + command + recovers
	}
}

// windowsEnterpriseStoppedServiceNextStep names what starts the stopped
// DefenseClaw services again when status or verify fails on them
// (GAP-1072: verify named the stopped guardian but no next step). It is
// empty when every required service runs.
func windowsEnterpriseStoppedServiceNextStep(services []enterprisestatus.Service) string {
	stopped := windowsEnterpriseStoppedRequiredServices(services)
	if len(stopped) == 0 {
		return ""
	}
	return ". Next step: from an elevated PowerShell prompt run " + windowsEnterpriseAdminCommand("repair") + ", or " +
		windowsEnterpriseStandaloneSetupName + " /repair JSON=1, to start " + strings.Join(stopped, ", ") + " again"
}

// windowsEnterpriseAdminCommand is an `enterprise windows <action>` command
// for the standalone profile as an administrator types it. Setup puts no
// DefenseClaw command on PATH, so a bare `defenseclaw ...` hint was "not
// recognized"; the installed CLI is named by its path (GAP-1183, GAP-1338).
func windowsEnterpriseAdminCommand(action string) string {
	return "`& '" + managedWindowsAdminCLI() + "' enterprise windows " + action + " --profile standalone`"
}

// windowsEnterpriseStandaloneLifecycleAction reports whether a standalone
// result is a lifecycle mutation whose failure gets administrator guidance.
// Status and verify report deployment state and keep their full detail.
func windowsEnterpriseStandaloneLifecycleAction(action string) bool {
	switch action {
	case "install", "upgrade", "repair", "reconcile", "ensure", "uninstall":
		return true
	}
	return false
}

// windowsEnterpriseStoppedRequiredServices names the required DefenseClaw
// services that are stopped.
func windowsEnterpriseStoppedRequiredServices(services []enterprisestatus.Service) []string {
	var stopped []string
	for _, service := range services {
		if service.Required && strings.EqualFold(strings.TrimSpace(service.State), "stopped") {
			stopped = append(stopped, service.Name)
		}
	}
	return stopped
}

// windowsEnterpriseNotHealthyMessage says what is unhealthy when the
// installer reported no error of its own. It said only "not healthy
// (installer exit 1)" for a stopped gateway service (GAP-1184); the stopped
// services are named instead, and the next step follows.
func windowsEnterpriseNotHealthyMessage(services []enterprisestatus.Service, exitCode int) string {
	stopped := windowsEnterpriseStoppedRequiredServices(services)
	switch len(stopped) {
	case 0:
		return fmt.Sprintf("the standalone deployment is not healthy (its health check exited %d); "+
			"from an elevated PowerShell prompt run "+windowsEnterpriseAdminCommand("verify")+" for the failing checks", exitCode)
	case 1:
		return "the standalone deployment is not healthy: the " + stopped[0] + " service is stopped"
	default:
		return "the standalone deployment is not healthy: the " + strings.Join(stopped, ", ") + " services are stopped"
	}
}

// windowsEnterpriseEnumeratorFailurePrefix starts the module's report of a
// failed synchronous `enterprise windows enumerate` run, which carries the
// enumerator's whole output.
const windowsEnterpriseEnumeratorFailurePrefix = "synchronous target enumeration failed with exit "

// windowsEnterpriseEnumeratorFailureText returns the enumerator's own error
// from that report, without its log line and command prefixes, and a
// dedicated code for a rule pack the gateway service cannot read. The
// actionable icacls advice was buried after "[hook-enumerator] windows:
// manifest=... interval=5m0s once=true initial_delay=30s Error: ..."
// (GAP-1276). ok is false for any other message.
func windowsEnterpriseEnumeratorFailureText(message string) (text, code string, ok bool) {
	start := strings.Index(message, windowsEnterpriseEnumeratorFailurePrefix)
	if start < 0 {
		return message, "", false
	}
	index := strings.LastIndex(message, "Error: ")
	if index < start {
		return message, "", false
	}
	text = strings.TrimSpace(message[index+len("Error: "):])
	for _, prefix := range []string{"enterprise windows enumerate: ", "load config: ", "config: "} {
		text = strings.TrimPrefix(text, prefix)
	}
	if rest, found := strings.CutPrefix(text, "managed standalone "); found {
		text = "the managed config's " + rest
	}
	if text == "" {
		return message, "", false
	}
	if label, _, found := strings.Cut(strings.TrimPrefix(text, "the managed config's "), " "); found &&
		windowsEnterpriseRulePackLabel(label) && strings.Contains(text, "cannot read") {
		code = "rule_pack_unreadable"
	}
	return text, code, true
}

// windowsEnterpriseRulePackLabel reports whether label is a rule-pack
// setting config.ReferencedRulePackDirs names: a rule_pack (v9) or
// rule_pack_dir, global, per connector or per profile, or a custom_packs
// path.
func windowsEnterpriseRulePackLabel(label string) bool {
	return strings.HasSuffix(label, ".rule_pack") || strings.HasSuffix(label, ".rule_pack_dir") ||
		(strings.HasPrefix(label, "guardrail.custom_packs.") && strings.HasSuffix(label, ".path"))
}
