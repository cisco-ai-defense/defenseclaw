//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// DefenseClaw writes no machine policy on macOS. It reads the agents'
// machine and MDM policy only to report, precisely, what makes user-scope
// hooks ineffective. A policy read that fails or times out never fails a
// reconcile: it is logged once per streak and the user's hooks stay.

const (
	agentPolicyCheck = "agent_policy_blocks_user_hooks"
	// agentPolicyStreakGap: the same finding seen again within this gap
	// belongs to one streak and is logged once.
	agentPolicyStreakGap = 15 * time.Minute

	agentPolicySourceMDMDevice = "mdm-device"
	agentPolicySourceMDMUser   = "mdm-user"
	agentPolicySourceFile      = "file"
	agentPolicySourceServer    = "server"
)

// managedPreferencesRoot holds the forced (MDM-delivered) preference plists:
// <root>/<domain>.plist for the device and <root>/<user>/<domain>.plist
// for one user. Root-owned and forced by definition, so no per-key check
// is needed. Replaced in tests.
var managedPreferencesRoot = "/Library/Managed Preferences"

// managedPreferencesConverter turns a plist into JSON. Replaced in tests.
var managedPreferencesConverter = func(plist []byte) ([]byte, error) {
	return runClaudeCodeManagedPreferenceCommandWithLimits(
		"/usr/bin/plutil",
		[]string{"-convert", "json", "-o", "-", "--", "-"},
		plist,
		claudeCodeManagedPreferenceCommandTimeout,
		claudeCodeSettingsReadLimit+1,
	)
}

// managedPreferencesUser names the user whose per-user managed preferences
// apply: the effective user the guardian dropped to, or nobody as root.
// Replaced in tests.
var managedPreferencesUser = func() string {
	euid := os.Geteuid()
	if euid == 0 {
		return ""
	}
	account, err := user.LookupId(strconv.Itoa(euid))
	if err != nil {
		return ""
	}
	return account.Username
}

type managedPreferenceLayer struct {
	source string
	path   string
}

// managedPreferenceLayers lists a domain's forced plists, device first and
// the per-user layer last, so a per-user value overrides a device value
// when both set a key.
func managedPreferenceLayers(domain string) []managedPreferenceLayer {
	layers := []managedPreferenceLayer{{
		source: agentPolicySourceMDMDevice,
		path:   filepath.Join(managedPreferencesRoot, domain+".plist"),
	}}
	if name := managedPreferencesUser(); name != "" && !strings.ContainsAny(name, "/\x00") && name != "." && name != ".." {
		layers = append(layers, managedPreferenceLayer{
			source: agentPolicySourceMDMUser,
			path:   filepath.Join(managedPreferencesRoot, name, domain+".plist"),
		})
	}
	return layers
}

// readManagedPreferences reads every forced layer of domain into JSON
// objects. A missing layer is skipped; a layer that cannot be read or
// parsed is reported once per streak and skipped.
func readManagedPreferences(connectorName, domain string) []managedPreferenceValues {
	var values []managedPreferenceValues
	for _, layer := range managedPreferenceLayers(domain) {
		data, exists, err := readBoundedPolicyFile(layer.path, claudeCodeSettingsReadLimit)
		if err != nil {
			reportAgentPolicyReadFailure(connectorName, layer.source, layer.path, err)
			continue
		}
		if !exists {
			clearAgentPolicyReadFailure(connectorName, layer.source, layer.path)
			continue
		}
		converted, err := managedPreferencesConverter(data)
		if err != nil {
			reportAgentPolicyReadFailure(connectorName, layer.source, layer.path, err)
			continue
		}
		settings, err := decodeClaudeCodeSettings(converted, layer.path)
		if err != nil {
			reportAgentPolicyReadFailure(connectorName, layer.source, layer.path, err)
			continue
		}
		clearAgentPolicyReadFailure(connectorName, layer.source, layer.path)
		values = append(values, managedPreferenceValues{layer: layer, settings: settings})
	}
	return values
}

type managedPreferenceValues struct {
	layer    managedPreferenceLayer
	settings map[string]interface{}
}

// readBoundedPolicyFile reads a root-owned policy file without following a
// link, bounded to limit bytes.
func readBoundedPolicyFile(path string, limit int64) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > limit {
		return nil, false, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return nil, false, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return data, true, nil
}

// loadClaudeCodeOSManagedSettings reads the Claude Code MDM domain from the
// device and per-user forced plists. Every key there is
// administrator-forced, so the per-key osascript probe is not needed.
func loadClaudeCodeOSManagedSettings() (claudeCodeOSManagedSources, error) {
	merged := map[string]interface{}{}
	origins := map[string]string{}
	var paths []string
	for _, values := range readManagedPreferences("claudecode", claudeCodeManagedPreferencesDomain) {
		for key, value := range values.settings {
			merged[key] = value
			origins[key] = values.layer.source
		}
		paths = append(paths, values.layer.path)
	}
	if len(merged) == 0 {
		return claudeCodeOSManagedSources{}, nil
	}
	return claudeCodeOSManagedSources{admin: &claudeCodeSettingsSource{
		name:     "MDM managed preferences",
		path:     strings.Join(paths, ", "),
		settings: merged,
		kind:     agentPolicySourceMDMDevice,
		origins:  origins,
	}}, nil
}

// agentPolicyStreaks deduplicates findings: one line per streak.
var agentPolicyStreaks = struct {
	sync.Mutex
	last map[string]time.Time
}{last: map[string]time.Time{}}

func agentPolicyNewStreak(key string) bool {
	now := time.Now()
	agentPolicyStreaks.Lock()
	defer agentPolicyStreaks.Unlock()
	last := agentPolicyStreaks.last[key]
	agentPolicyStreaks.last[key] = now
	return last.IsZero() || now.Sub(last) > agentPolicyStreakGap
}

func agentPolicyEndStreak(key string) {
	agentPolicyStreaks.Lock()
	delete(agentPolicyStreaks.last, key)
	agentPolicyStreaks.Unlock()
}

// reportAgentPolicyBlocksUserHooks logs the exact policy source and key that
// makes an agent ignore DefenseClaw's user-scope hooks. The target is
// reported unprotected by its failed verification.
func reportAgentPolicyBlocksUserHooks(connectorName, source, key, path string) {
	if !agentPolicyNewStreak("block\x00" + connectorName + "\x00" + source + "\x00" + key + "\x00" + path) {
		return
	}
	managed.EmitResilienceEvent(managed.MarkerPrereq, map[string]string{
		"check":     agentPolicyCheck,
		"connector": connectorName,
		"source":    source,
		"key":       key,
		"path":      path,
		"remedy":    "remove " + key + " from the " + source + " policy, or deliver the DefenseClaw hooks through that administrator-managed source",
	})
}

func reportAgentPolicyReadFailure(connectorName, source, path string, err error) {
	if !agentPolicyNewStreak("read\x00" + connectorName + "\x00" + source + "\x00" + path) {
		return
	}
	managed.EmitResilienceEvent(managed.MarkerSkip, map[string]string{
		"unit":   "connector:" + connectorName,
		"source": source,
		"path":   path,
		"reason": "policy_read_failed: " + err.Error() + "; treated as absent, the user's hooks are kept",
	})
}

func clearAgentPolicyReadFailure(connectorName, source, path string) {
	agentPolicyEndStreak("read\x00" + connectorName + "\x00" + source + "\x00" + path)
}

// agentPolicyReadRetryable reports a transient policy read (the file was
// rewritten while it was read), which is retried before it is reported.
func agentPolicyReadRetryable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "changed during inspection")
}

// agentPolicyReadTolerated decides that a failed machine-policy read does
// not fail the reconcile: it is logged and the source is treated as absent.
// A symlinked or non-regular policy file stays an error.
func agentPolicyReadTolerated(connectorName, source, path string, err error) bool {
	if err == nil || strings.Contains(err.Error(), "not a regular file") {
		return false
	}
	reportAgentPolicyReadFailure(connectorName, source, path, err)
	return true
}

// reportUserDisabledHooksRepair logs that a user-scope "all hooks off"
// setting was turned back on, once per streak.
func reportUserDisabledHooksRepair(connectorName, path string) {
	if !agentPolicyNewStreak("disabled\x00" + connectorName + "\x00" + path) {
		return
	}
	unit := "user:" + managedPreferencesUser()
	if unit == "user:" {
		unit = "uid:" + strconv.Itoa(os.Geteuid())
	}
	managed.EmitResilienceEvent(managed.MarkerRepair, map[string]string{
		"unit":      unit,
		"connector": connectorName,
		"path":      path,
		"reason":    "user_disabled_hooks",
	})
}

// userDisabledHooksRepairEnabled: managed macOS installs turn a user's own
// "hooks off" setting back on.
func userDisabledHooksRepairEnabled(opts SetupOpts) bool {
	return opts.ManagedEnterprise
}

// --- Codex ---------------------------------------------------------------

const codexManagedPreferencesDomain = "com.openai.codex"

// codexManagedPreferencesPolicy reads requirements_toml_base64 from the
// forced com.openai.codex plists. A layer that sets
// allow_managed_hooks_only wins; per-user overrides device.
func codexManagedPreferencesPolicy() codexEffectivePolicy {
	var policy codexEffectivePolicy
	for _, values := range readManagedPreferences("codex", codexManagedPreferencesDomain) {
		raw, ok := values.settings["requirements_toml_base64"].(string)
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
		if err != nil {
			reportAgentPolicyReadFailure("codex", values.layer.source, values.layer.path, fmt.Errorf("requirements_toml_base64: %w", err))
			continue
		}
		var requirements struct {
			AllowManagedHooksOnly *bool `toml:"allow_managed_hooks_only"`
		}
		if err := toml.Unmarshal(decoded, &requirements); err != nil {
			reportAgentPolicyReadFailure("codex", values.layer.source, values.layer.path, fmt.Errorf("requirements_toml_base64: %w", err))
			continue
		}
		if requirements.AllowManagedHooksOnly != nil {
			policy = codexEffectivePolicy{
				AllowManagedHooksOnly: requirements.AllowManagedHooksOnly,
				Source:                values.layer.path,
				SourceKind:            values.layer.source,
			}
		}
	}
	return policy
}

// codexPlatformManagedPolicy adds the MDM requirements to the system file's
// policy when no Codex executable answered for the composition.
func codexPlatformManagedPolicy(policy codexEffectivePolicy, err error) (codexEffectivePolicy, error) {
	if err == nil && policy.SourceKind == "" {
		policy.SourceKind = agentPolicySourceFile
	}
	mdm := codexManagedPreferencesPolicy()
	if mdm.AllowManagedHooksOnly != nil && *mdm.AllowManagedHooksOnly {
		return mdm, nil
	}
	return policy, err
}

// codexAttributePolicy names where an app-server answer came from: the MDM
// plist or the system file when either sets allow_managed_hooks_only,
// otherwise cloud (server) requirements.
func codexAttributePolicy(policy codexEffectivePolicy) codexEffectivePolicy {
	if policy.AllowManagedHooksOnly == nil || !*policy.AllowManagedHooksOnly {
		return policy
	}
	if mdm := codexManagedPreferencesPolicy(); mdm.AllowManagedHooksOnly != nil && *mdm.AllowManagedHooksOnly {
		policy.SourceKind, policy.Source = mdm.SourceKind, mdm.Source+" (via "+policy.Source+")"
		return policy
	}
	if file, err := inspectCodexSystemRequirementsForMode(true); err == nil &&
		file.AllowManagedHooksOnly != nil && *file.AllowManagedHooksOnly {
		policy.SourceKind = agentPolicySourceFile
		policy.Source = file.Source + " (via " + policy.Source + ")"
		return policy
	}
	policy.SourceKind = agentPolicySourceServer
	return policy
}

// codexRequirementsUntrustedAccepted reads a system requirements file or
// folder that fails the strict owner/mode check anyway: DefenseClaw only
// reads this vendor file, and its content can only restrict hooks. The
// finding is logged as a boundary once per streak.
func codexRequirementsUntrustedAccepted(path string, err error) bool {
	if agentPolicyNewStreak("untrusted\x00" + path) {
		managed.EmitResilienceEvent(managed.MarkerBoundary, map[string]string{
			"connector": "codex",
			"path":      path,
			"reason":    "Codex system requirements are writable by a non-administrator or not root-owned; read anyway: " + err.Error(),
		})
	}
	return true
}

// Codex effective requirements come from `codex app-server`. Inside the
// guardian's per-user euid drop the real uid stays 0, so a child started
// there could regain root: the inspection instead runs before the drop,
// as root starting the child with the user's full credentials, and the
// result is consumed inside the drop.

const codexPreinspectionTTL = 10 * time.Minute

var codexPreinspections = struct {
	sync.Mutex
	entries map[string]codexPreinspection
}{entries: map[string]codexPreinspection{}}

type codexPreinspection struct {
	policy codexEffectivePolicy
	at     time.Time
}

func codexPreinspectionKey(executable, codexHome string) string {
	return filepath.Clean(executable) + "\x00" + filepath.Clean(codexHome)
}

// codexPolicyInspectionAsUser is replaced in tests.
var codexPolicyInspectionAsUser = func(ctx context.Context, executable, codexHome string, prepare func(*exec.Cmd)) (codexEffectivePolicy, error) {
	return inspectCodexPolicyWithAppServerPrepared(ctx, executable, codexHome, prepare)
}

// PreinspectCodexPolicy runs Codex's configRequirements/read for one user,
// as that user, and caches the answer for the guardian's work inside the
// per-user drop. It must be called as root, outside the drop; elsewhere it
// does nothing. A failure is logged once per streak and the requirements
// read falls back to the system file and MDM plists.
func PreinspectCodexPolicy(ctx context.Context, executable, home string, uid, gid int) error {
	if os.Geteuid() != 0 || uid <= 0 || gid < 0 {
		return nil
	}
	executable = filepath.Clean(strings.TrimSpace(executable))
	if !filepath.IsAbs(executable) {
		return fmt.Errorf("codex executable %q is not absolute", executable)
	}
	info, err := os.Stat(executable)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("codex executable %s is not a regular file", executable)
	}
	codexHome := filepath.Join(home, ".codex")
	if env := strings.TrimSpace(os.Getenv("CODEX_HOME")); env != "" && filepath.IsAbs(env) {
		codexHome = env
	}
	key := codexPreinspectionKey(executable, codexHome)
	codexPreinspections.Lock()
	cached, fresh := codexPreinspections.entries[key]
	codexPreinspections.Unlock()
	if fresh && time.Since(cached.at) < codexPreinspectionTTL/2 {
		return nil
	}
	username := ""
	if account, lookupErr := user.LookupId(strconv.Itoa(uid)); lookupErr == nil {
		username = account.Username
	}
	prepare := func(cmd *exec.Cmd) {
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}
		cmd.Dir = home
		env := cmd.Env
		if env == nil {
			env = os.Environ()
		}
		env = replaceProcessEnv(env, "HOME", home)
		if username != "" {
			env = replaceProcessEnv(env, "USER", username)
			env = replaceProcessEnv(env, "LOGNAME", username)
		}
		cmd.Env = env
	}
	policy, err := codexPolicyInspectionAsUser(ctx, executable, codexHome, prepare)
	if err != nil {
		reportAgentPolicyReadFailure("codex", "app-server", executable, err)
		codexPreinspections.Lock()
		delete(codexPreinspections.entries, key)
		codexPreinspections.Unlock()
		return err
	}
	clearAgentPolicyReadFailure("codex", "app-server", executable)
	codexPreinspections.Lock()
	codexPreinspections.entries[key] = codexPreinspection{policy: policy, at: time.Now()}
	codexPreinspections.Unlock()
	return nil
}

// codexPreinspectedPolicy returns a fresh answer PreinspectCodexPolicy
// cached for this executable and Codex home.
func codexPreinspectedPolicy(executable, codexHome string) (codexEffectivePolicy, bool) {
	codexPreinspections.Lock()
	defer codexPreinspections.Unlock()
	entry, ok := codexPreinspections.entries[codexPreinspectionKey(executable, codexHome)]
	if !ok || time.Since(entry.at) > codexPreinspectionTTL {
		return codexEffectivePolicy{}, false
	}
	return entry.policy, true
}

// codexPolicySpawnUnsafe reports a per-user euid drop with a real uid of 0,
// where a started child could regain root.
func codexPolicySpawnUnsafe() bool {
	return os.Getuid() == 0 && os.Geteuid() != 0
}

// --- Cursor --------------------------------------------------------------

// cursorHooksLockedWriter: the managed guardian patches ~/.cursor/hooks.json
// under the config lock with compare-and-swap.
const cursorHooksLockedWriter = true

// cursorMachineHooksPath is Cursor's machine-wide hooks.json. Replaced in
// tests.
var cursorMachineHooksPath = "/Library/Application Support/Cursor/hooks.json"

// ReportCursorMachineHooksPolicy reports a machine-wide Cursor hooks.json
// that registers hooks for the events DefenseClaw uses. Whether Cursor lets
// it suppress user hooks is not established, so the target is not failed;
// the finding is logged once per streak so an unprotected user is
// diagnosable. A file that cannot be read is logged and ignored.
func ReportCursorMachineHooksPolicy() {
	data, exists, err := readBoundedPolicyFile(cursorMachineHooksPath, claudeCodeSettingsReadLimit)
	if err != nil {
		reportAgentPolicyReadFailure("cursor", agentPolicySourceFile, cursorMachineHooksPath, err)
		return
	}
	if !exists {
		return
	}
	var document struct {
		Hooks map[string]json.RawMessage `json:"hooks"`
	}
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&document); err != nil {
		reportAgentPolicyReadFailure("cursor", agentPolicySourceFile, cursorMachineHooksPath, err)
		return
	}
	var conflicts []string
	for _, event := range cursorHookEvents {
		if raw, ok := document.Hooks[event]; ok && len(bytes.TrimSpace(raw)) > 0 && string(bytes.TrimSpace(raw)) != "[]" {
			conflicts = append(conflicts, event)
		}
	}
	if len(conflicts) == 0 {
		return
	}
	sort.Strings(conflicts)
	reportAgentPolicyBlocksUserHooks("cursor", agentPolicySourceFile, "hooks."+strings.Join(conflicts, ",hooks."), cursorMachineHooksPath)
}
