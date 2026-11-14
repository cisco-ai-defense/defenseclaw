// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/jsonc"
)

// OpenClaw security.installPolicy (connectors.openclaw.install_policy):
// OpenClaw runs a trusted local command before it installs or updates a
// skill or plugin and refuses the install unless the command answers allow.
// Setup registers "defenseclaw-gateway connector openclaw install-policy",
// which asks the gateway for its skill or plugin admission. It is written
// only on OpenClaw 2026.8.35 and later (older releases reject the key), only
// when the operator has no installPolicy of their own, and teardown takes it
// out only while it is still exactly what setup wrote.

// OpenClawInstallPolicySince is the first OpenClaw release whose
// security.installPolicy runs an exec command.
const OpenClawInstallPolicySince = "2026.8.35"

// OpenClawInstallPolicyArgs are the static arguments setup writes.
var OpenClawInstallPolicyArgs = []string{"connector", "openclaw", "install-policy"}

// Environment the install-policy command reads. OpenClaw starts the command
// with an empty environment plus exec.env and the passEnv names.
const (
	OpenClawInstallPolicyTimeoutEnv   = "DEFENSECLAW_INSTALL_POLICY_TIMEOUT_MS"
	OpenClawInstallPolicyTokenFileEnv = "DEFENSECLAW_INSTALL_POLICY_TOKEN_FILE"
	OpenClawInstallPolicyAPIEnv       = "DEFENSECLAW_INSTALL_POLICY_API"
	OpenClawInstallPolicyOutageEnv    = "DEFENSECLAW_INSTALL_POLICY_OUTAGE"
)

var openClawInstallPolicyPassEnv = []string{"HOME", "USERPROFILE", "SystemRoot", "TMPDIR", "TEMP", "TMP"}

// openClawInstallPolicyExecutable is the defenseclaw-gateway binary setup
// names as the command; tests replace it.
var openClawInstallPolicyExecutable = defaultOpenClawInstallPolicyExecutable

// defaultOpenClawInstallPolicyExecutable is this process binary with links
// resolved (OpenClaw refuses a symlinked command), or the defenseclaw-gateway
// next to it when this process is another DefenseClaw binary.
func defaultOpenClawInstallPolicyExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	name := "defenseclaw-gateway"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if strings.EqualFold(filepath.Base(exe), name) {
		return exe, nil
	}
	sibling := filepath.Join(filepath.Dir(exe), name)
	if info, err := os.Lstat(sibling); err == nil && info.Mode().IsRegular() {
		return sibling, nil
	}
	return "", fmt.Errorf("%s is not %s and there is none next to it", exe, name)
}

// openClawInstallPolicySupported reports an OpenClaw known to run
// security.installPolicy exec commands. An unknown version is not written:
// an older OpenClaw does not start with a key it does not know.
func openClawInstallPolicySupported(rawVersion string) bool {
	version := NormalizeAgentVersion("openclaw", rawVersion)
	return version != "" && CompareAgentVersions(version, OpenClawInstallPolicySince) >= 0
}

// openClawInstallPolicyWanted reports whether setup registers the command.
func openClawInstallPolicyWanted(opts SetupOpts) bool {
	return opts.OpenClawInstallPolicy && openClawInstallPolicySupported(openClawObservedVersion(opts))
}

// openClawInstallPolicyBlock is the security.installPolicy value setup
// writes for command, in parsed-JSON form (float64 numbers, []interface{}).
func openClawInstallPolicyBlock(opts SetupOpts, command string) map[string]interface{} {
	timeout := opts.OpenClawInstallPolicyTimeoutMs
	if timeout <= 0 {
		timeout = 30000
	}
	env := map[string]string{OpenClawInstallPolicyTimeoutEnv: strconv.Itoa(timeout)}
	if openClawSeparateUser(opts) {
		// The OpenClaw account cannot read config.yaml or the data folder.
		host, port := splitOpenClawAddr(opts.APIAddr, 18970)
		env[OpenClawInstallPolicyTokenFileEnv] = strings.TrimSpace(opts.OpenClawPluginTokenFile)
		env[OpenClawInstallPolicyAPIEnv] = net.JoinHostPort(host, strconv.Itoa(port))
		outage := "open"
		if opts.OpenClawInstallPolicyFailsClosed || opts.ManagedEnterprise {
			outage = "closed"
		}
		env[OpenClawInstallPolicyOutageEnv] = outage
	} else if opts.DataDir != "" {
		env["DEFENSECLAW_HOME"] = opts.DataDir
	}
	block := map[string]interface{}{
		"enabled": true,
		"targets": []string{"skill", "plugin"},
		"exec": map[string]interface{}{
			"source":            "exec",
			"command":           command,
			"args":              OpenClawInstallPolicyArgs,
			"timeoutMs":         timeout,
			"noOutputTimeoutMs": timeout,
			"passEnv":           openClawInstallPolicyPassEnv,
			"env":               env,
			"trustedDirs":       []string{filepath.Dir(command)},
		},
	}
	raw, _ := json.Marshal(block)
	out := map[string]interface{}{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// openClawInstallPolicyCommand is the command setup writes for opts, or an
// error naming why OpenClaw would refuse it (and so every install).
func openClawInstallPolicyCommand(opts SetupOpts) (string, error) {
	command, err := openClawInstallPolicyExecutable()
	if err != nil {
		return "", err
	}
	if err := openClawInstallPolicyTrusted(command, strings.TrimSpace(opts.OpenClawPluginAccount)); err != nil {
		return "", fmt.Errorf("OpenClaw would refuse %s as its install policy command (%v)", command, err)
	}
	return command, nil
}

// openClawInstallPolicyTrusted is openClawInstallPolicyPathTrusted; tests
// replace it.
var openClawInstallPolicyTrusted = openClawInstallPolicyPathTrusted

var openClawInstallPolicyNotices sync.Map

// noteOpenClawInstallPolicyOnce prints a setup notice once per process and
// key, since setup runs on every gateway start.
func noteOpenClawInstallPolicyOnce(key, format string, args ...interface{}) {
	if _, seen := openClawInstallPolicyNotices.LoadOrStore(key, true); seen {
		return
	}
	fmt.Fprintf(openClawTeardownNoticeOutput, "[connector] openclaw: "+format+"\n", args...)
}

// openClawInstallPolicyOf returns security.installPolicy of a parsed
// openclaw.json and whether security was there at all.
func openClawInstallPolicyOf(cfg map[string]interface{}) (policy interface{}, present, securityPresent bool) {
	security, securityPresent := cfg["security"].(map[string]interface{})
	if !securityPresent {
		_, securityPresent = cfg["security"]
		return nil, false, securityPresent
	}
	policy, present = security["installPolicy"]
	return policy, present, true
}

// looksLikeDefenseClawInstallPolicy reports an installPolicy that runs a
// defenseclaw-gateway with the install-policy arguments.
func looksLikeDefenseClawInstallPolicy(policy interface{}) bool {
	m, _ := policy.(map[string]interface{})
	exec, _ := m["exec"].(map[string]interface{})
	command, _ := exec["command"].(string)
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(command)), ".exe")
	args, _ := json.Marshal(exec["args"])
	want, _ := json.Marshal(OpenClawInstallPolicyArgs)
	return base == "defenseclaw-gateway" && string(args) == string(want)
}

// openClawInstallPolicyRecord is what setup wrote: the exact block, and
// whether openclaw.json had a security object before, so teardown takes out
// an emptied security object only when setup created it.
type openClawInstallPolicyRecord struct {
	Block          map[string]interface{} `json:"block"`
	SecurityBefore bool                   `json:"security_before"`
}

func openClawInstallPolicyRecordPath(dataDir string) string {
	return filepath.Join(dataDir, "openclaw-install-policy.json")
}

func loadOpenClawInstallPolicyRecord(dataDir string) (openClawInstallPolicyRecord, bool) {
	var rec openClawInstallPolicyRecord
	if dataDir == "" {
		return rec, false
	}
	data, err := os.ReadFile(openClawInstallPolicyRecordPath(dataDir))
	if err != nil || json.Unmarshal(data, &rec) != nil || rec.Block == nil {
		return openClawInstallPolicyRecord{}, false
	}
	return rec, true
}

func saveOpenClawInstallPolicyRecord(dataDir string, rec openClawInstallPolicyRecord) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(openClawInstallPolicyRecordPath(dataDir), append(data, byte(10)), 0o600)
}

func discardOpenClawInstallPolicyRecord(dataDir string) {
	if dataDir != "" {
		_ = os.Remove(openClawInstallPolicyRecordPath(dataDir))
	}
}

// applyOpenClawInstallPolicy writes, refreshes or removes the DefenseClaw
// security.installPolicy in openclaw.json after the plugin registration. The
// caller holds the openclaw.json lock. A block the operator wrote, or
// changed, is left as it is.
func applyOpenClawInstallPolicy(configPath string, opts SetupOpts) error {
	if opts.DataDir == "" {
		return nil
	}
	rec, hasRec := loadOpenClawInstallPolicyRecord(opts.DataDir)
	original, err := readConnectorStateFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", configPath, err)
	}
	cfg := map[string]interface{}{}
	if len(original) > 0 {
		if cfg, err = parseOpenClawConfig(configPath, original); err != nil {
			return err
		}
	}
	current, present, securityBefore := openClawInstallPolicyOf(cfg)
	ours := hasRec && present && reflect.DeepEqual(current, rec.Block)
	if !openClawInstallPolicyWanted(opts) {
		if ours {
			return removeOpenClawInstallPolicy(configPath, opts.DataDir)
		}
		if hasRec {
			discardOpenClawInstallPolicyRecord(opts.DataDir)
		}
		return nil
	}
	if present && !ours {
		if hasRec {
			discardOpenClawInstallPolicyRecord(opts.DataDir)
		}
		noteOpenClawInstallPolicyOnce("operator|"+configPath,
			"%s already has a security.installPolicy; DefenseClaw left it and does not add its install admission (remove it to let setup add DefenseClaw)", configPath)
		return nil
	}
	command, err := openClawInstallPolicyCommand(opts)
	if err != nil {
		noteOpenClawInstallPolicyOnce("command|"+configPath, "install admission is not registered: %v", err)
		if ours {
			return removeOpenClawInstallPolicy(configPath, opts.DataDir)
		}
		return nil
	}
	block := openClawInstallPolicyBlock(opts, command)
	if ours && reflect.DeepEqual(current, block) {
		return nil
	}
	if ours {
		securityBefore = rec.SecurityBefore
	}
	if err := saveOpenClawInstallPolicyRecord(opts.DataDir, openClawInstallPolicyRecord{Block: block, SecurityBefore: securityBefore}); err != nil {
		return fmt.Errorf("record the install policy: %w", err)
	}
	security, _ := cfg["security"].(map[string]interface{})
	if security == nil {
		security = map[string]interface{}{}
	}
	security["installPolicy"] = block
	cfg["security"] = security
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", configPath, err)
	}
	return atomicWriteFile(configPath, append(out, byte(10)), 0o644)
}

// removeOpenClawInstallPolicy takes the DefenseClaw security.installPolicy
// out of openclaw.json when it is still exactly what setup recorded, and
// drops the record. Only those members are cut from the text, so the rest of
// the JSON5 file keeps its bytes. The caller holds the openclaw.json lock.
func removeOpenClawInstallPolicy(configPath, dataDir string) error {
	rec, ok := loadOpenClawInstallPolicyRecord(dataDir)
	if !ok {
		return nil
	}
	data, err := readConnectorStateFile(configPath)
	if errors.Is(err, os.ErrNotExist) {
		discardOpenClawInstallPolicyRecord(dataDir)
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", configPath, err)
	}
	out, err := removeOpenClawInstallPolicyText(configPath, data, rec)
	if err != nil {
		return err
	}
	if out != nil {
		if err := atomicWriteFile(configPath, out, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", configPath, err)
		}
	}
	discardOpenClawInstallPolicyRecord(dataDir)
	return nil
}

// removeOpenClawInstallPolicyText returns data without the recorded block
// (and without a security object setup created and left empty), or nil when
// the file does not hold exactly that block.
func removeOpenClawInstallPolicyText(configPath string, data []byte, rec openClawInstallPolicyRecord) ([]byte, error) {
	want, err := parseOpenClawConfig(configPath, data)
	if err != nil {
		return nil, err
	}
	current, present, _ := openClawInstallPolicyOf(want)
	if !present || !reflect.DeepEqual(current, rec.Block) {
		return nil, nil
	}
	security := want["security"].(map[string]interface{})
	delete(security, "installPolicy")
	dropSecurity := len(security) == 0 && !rec.SecurityBefore
	if dropSecurity {
		delete(want, "security")
	}
	out := data
	for pass := 0; pass < 2; pass++ {
		doc, err := jsonc.Parse(out)
		if err != nil {
			return nil, openClawInstallPolicyEditError(configPath, err)
		}
		sec := childValue(doc, "security")
		if sec == nil || !sec.Object {
			break
		}
		if i, ok := sec.Lookup("installPolicy"); ok {
			out = jsonc.Apply(out, sec.RemoveChild(out, i))
			continue
		}
		if dropSecurity && len(sec.Children) == 0 {
			k, _ := doc.Lookup("security")
			out = jsonc.Apply(out, doc.RemoveChild(out, k))
		}
		break
	}
	got, err := parseOpenClawConfig(configPath, out)
	if err != nil || !reflect.DeepEqual(got, want) {
		return nil, openClawInstallPolicyEditError(configPath, err)
	}
	return out, nil
}

func openClawInstallPolicyEditError(configPath string, cause error) error {
	msg := fmt.Sprintf("%s: could not take the DefenseClaw security.installPolicy out without rewriting the file; remove security.installPolicy by hand", configPath)
	if cause != nil {
		return fmt.Errorf("%s: %w", msg, cause)
	}
	return errors.New(msg)
}

// openClawSeparateUserInstallPolicy is the security.installPolicy block the
// administrator adds in the separate-user layout, where DefenseClaw does not
// write openclaw.json, or nil when install admission is off or OpenClaw
// would refuse the command (the OpenClaw account runs it, so it must be
// owned by root or by that account).
func openClawSeparateUserInstallPolicy(opts SetupOpts) map[string]interface{} {
	if !openClawInstallPolicyWanted(opts) {
		return nil
	}
	command, err := openClawInstallPolicyCommand(opts)
	if err != nil {
		noteOpenClawInstallPolicyOnce("separate|"+opts.OpenClawPluginAccount,
			"install admission is left out of the openclaw.json block: %v; install defenseclaw-gateway in a root-owned folder to use it", err)
		return nil
	}
	return openClawInstallPolicyBlock(opts, command)
}

// openClawSeparateUserInstallPolicyMissing names the install policy entry
// openclaw.json lacks in the separate-user layout. A policy of the
// operator (one that does not run defenseclaw-gateway) is left alone.
func openClawSeparateUserInstallPolicyMissing(cfg map[string]interface{}, opts SetupOpts) []string {
	want := openClawSeparateUserInstallPolicy(opts)
	if want == nil {
		return nil
	}
	current, present, _ := openClawInstallPolicyOf(cfg)
	switch {
	case present && reflect.DeepEqual(current, want):
		return nil
	case present && !looksLikeDefenseClawInstallPolicy(current):
		noteOpenClawInstallPolicyOnce("operator-separate|"+opts.OpenClawPluginAccount,
			"openclaw.json already has a security.installPolicy; DefenseClaw left it and does not ask for its install admission")
		return nil
	}
	return []string{"security.installPolicy (DefenseClaw install admission)"}
}
