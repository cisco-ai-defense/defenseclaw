// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

// A native OTLP exporter sends to whatever process holds the port named in its
// configuration; it cannot check which account accepted the connection. A
// DefenseClaw exporter may stay in an account's agent configuration only while
// the gateway it names serves it. The Windows managed profile delivers Codex
// and Claude Code through machine policy and writes no user-level exporter, so
// an exporter an earlier per-user install left behind names a port that no
// DefenseClaw process holds and that another account can bind (GAP-0836).
//
// UserNativeOTLPResidue names the DefenseClaw exporter entries in the current
// account's Codex or Claude Code configuration (field names only, never
// values). RemoveUserNativeOTLP removes them, puts back an operator value the
// setup backup proves, and revokes the scoped OTLP credential file. Both act
// only on entries DefenseClaw's own markers prove and leave every other entry
// alone. Use them only for a profile that installs no user-level exporter;
// managed standalone hosts on Linux and macOS render theirs through Setup.
func UserNativeOTLPResidue(connectorName string, opts SetupOpts) ([]string, error) {
	return userNativeOTLP(connectorName, opts, false)
}

// RemoveUserNativeOTLP removes the entries UserNativeOTLPResidue names and
// returns them.
func RemoveUserNativeOTLP(connectorName string, opts SetupOpts) ([]string, error) {
	return userNativeOTLP(connectorName, opts, true)
}

func userNativeOTLP(connectorName string, opts SetupOpts, apply bool) ([]string, error) {
	if strings.TrimSpace(opts.DataDir) == "" {
		return nil, errors.New("native OTLP cleanup: empty data dir")
	}
	var scope OTLPPathTokenScope
	var removed []string
	var err error
	switch connectorName {
	case "codex":
		scope = OTLPScopeCodex
		removed, err = codexUserNativeOTLP(opts, apply)
	case "claudecode":
		scope = OTLPScopeClaude
		removed, err = claudeCodeUserNativeOTLP(opts, apply)
	default:
		return nil, nil
	}
	if err != nil {
		return removed, err
	}
	tokenPath, err := OTLPPathTokenFilePath(opts.DataDir, scope)
	if err != nil {
		return removed, err
	}
	if _, statErr := os.Lstat(tokenPath); statErr == nil {
		removed = append(removed, "hooks/"+otlpPathTokenFileName(scope))
		if apply {
			// Revoke only after no configuration references the credential.
			if err := RemoveOTLPPathToken(opts.DataDir, scope); err != nil {
				return removed, fmt.Errorf("revoke obsolete %s native OTLP credential: %w", connectorName, err)
			}
		}
	} else if !os.IsNotExist(statErr) {
		return removed, fmt.Errorf("inspect %s native OTLP credential: %w", connectorName, statErr)
	}
	return removed, nil
}

// withUserAgentConfigLock serializes the edit with other DefenseClaw writers of
// the account's agent configuration. A managed row has none: the guardian holds
// the row's runtime transaction lock and the host refuses per-user gateways.
// Its connector lock would also refuse the unprotected lock file an earlier
// per-user install created beside the config, so it is not taken there. The
// atomic transform never replaces bytes it did not read, which keeps an edit
// by the agent or the user intact either way.
func withUserAgentConfigLock(path string, opts SetupOpts, fn func() error) error {
	if opts.ManagedEnterprise {
		return fn()
	}
	return withFileLock(path, fn)
}

func codexUserNativeOTLP(opts SetupOpts, apply bool) ([]string, error) {
	configPath := codexConfigPath()
	backup, err := (&CodexConnector{}).loadConfigBackup(opts.DataDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("load original Codex OTel config: %w", err)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read Codex config: %w", err)
	}
	_, removed, err := codexWithoutUserNativeOTLP(raw, backup, opts)
	if err != nil || !apply || len(removed) == 0 {
		return removed, err
	}
	err = withUserAgentConfigLock(configPath, opts, func() error {
		return atomicTransformFileWithStateDir(configPath, opts.DataDir, 0o600, func(current []byte, exists bool) (atomicTransformResult, error) {
			if !exists {
				removed = nil
				return atomicTransformResult{Remove: true}, nil
			}
			out, changed, err := codexWithoutUserNativeOTLP(current, backup, opts)
			if err != nil {
				return atomicTransformResult{}, err
			}
			removed = changed
			if len(changed) == 0 {
				return atomicTransformResult{Data: current}, nil
			}
			return atomicTransformResult{Data: out}, nil
		})
	})
	if err != nil {
		return removed, fmt.Errorf("remove Codex native OTLP exporter: %w", err)
	}
	return removed, nil
}

// codexWithoutUserNativeOTLP returns raw without the DefenseClaw exporter
// entries and the [otel] fields Setup wrote beside them.
func codexWithoutUserNativeOTLP(raw []byte, backup codexConfigBackup, opts SetupOpts) ([]byte, []string, error) {
	if len(raw) == 0 {
		return nil, nil, nil
	}
	cfg := map[string]interface{}{}
	if err := parseCodexTOML(raw, &cfg); err != nil {
		// Codex refuses to start on a config it cannot parse, so it exports
		// nothing; leave the operator's file for them to fix.
		return nil, nil, nil
	}
	otel, ok := cfg["otel"].(map[string]interface{})
	if !ok {
		return nil, nil, nil
	}
	owned := false
	for _, key := range codexOtelExporterKeys {
		if codexExporterLooksManaged(otel[key], opts) || codexExporterHasManagedHeaderPair(otel[key]) {
			owned = true
			break
		}
	}
	if !owned {
		return nil, nil, nil
	}
	before := make(map[string]string, len(otel))
	for key, value := range otel {
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, nil, fmt.Errorf("inspect Codex OTel config: %w", err)
		}
		before[key] = string(encoded)
	}
	restoreCodexOtelEntries(cfg, backup, opts)
	after, _ := cfg["otel"].(map[string]interface{})
	var removed []string
	for key, previous := range before {
		value, kept := after[key]
		if kept {
			encoded, err := json.Marshal(value)
			if err != nil {
				return nil, nil, fmt.Errorf("inspect Codex OTel config: %w", err)
			}
			if string(encoded) == previous {
				continue
			}
		}
		removed = append(removed, "config.toml otel."+key)
	}
	if len(removed) == 0 {
		return nil, nil, nil
	}
	sort.Strings(removed)
	out, err := editCodexOwnedTOML(raw, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("edit Codex config: %w", err)
	}
	return out, removed, nil
}

func claudeCodeUserNativeOTLP(opts SetupOpts, apply bool) ([]string, error) {
	settingsPath := claudeCodeSettingsPath()
	backup, err := (&ClaudeCodeConnector{}).loadBackup(opts.DataDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("load Claude Code settings backup: %w", err)
	}
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read Claude Code settings: %w", err)
	}
	_, removed, err := claudeCodeWithoutUserNativeOTLP(raw, backup, opts)
	if err != nil || !apply || len(removed) == 0 {
		return removed, err
	}
	err = withUserAgentConfigLock(settingsPath, opts, func() error {
		return atomicTransformFileWithStateDir(settingsPath, opts.DataDir, 0o600, func(current []byte, exists bool) (atomicTransformResult, error) {
			if !exists {
				removed = nil
				return atomicTransformResult{Remove: true}, nil
			}
			out, changed, err := claudeCodeWithoutUserNativeOTLP(current, backup, opts)
			if err != nil {
				return atomicTransformResult{}, err
			}
			removed = changed
			if len(changed) == 0 {
				return atomicTransformResult{Data: current}, nil
			}
			return atomicTransformResult{Data: out}, nil
		})
	})
	if err != nil {
		return removed, fmt.Errorf("remove Claude Code native OTLP exporter: %w", err)
	}
	return removed, nil
}

// claudeCodeWithoutUserNativeOTLP returns the settings without the
// DefenseClaw native exporter. Ownership needs a DefenseClaw marker in the env
// block: a header carrying the product source or client marker, a scoped
// /otlp/claudecode/ endpoint, a value the setup backup recorded, or the
// earlier headers helper. Values that turn export off are left in place.
func claudeCodeWithoutUserNativeOTLP(raw []byte, backup claudeCodeBackup, opts SetupOpts) ([]byte, []string, error) {
	settings := map[string]interface{}{}
	if err := json.Unmarshal(raw, &settings); err != nil || settings == nil {
		// Claude Code ignores a settings file it cannot parse.
		return nil, nil, nil
	}
	env, _ := settings["env"].(map[string]interface{})
	recorded := func(key, value string) bool {
		written := backup.ManagedEnv[key]
		return written != "" && written == value
	}
	helperOwned := false
	if helper, present := settings[claudeCodeOTLPHeadersHelperKey]; present {
		helperOwned = claudeCodeOTLPHeadersHelperOwned(helper, backup.ManagedOTLPHeadersHelper)
	}
	proof := helperOwned
	for key, value := range env {
		got, _ := value.(string)
		if got == "" {
			continue
		}
		switch {
		case claudeCodeOTLPEndpointKey(key):
			if claudeCodeScopedLoopbackOTLPEndpoint(got) || recorded(key, got) {
				proof = true
			}
		case claudeCodeOTLPHeadersKey(key):
			if _, marked := claudeCodeWithoutDefenseClawHeaders(got); marked || recorded(key, got) {
				proof = true
			}
		}
	}
	if !proof {
		return nil, nil, nil
	}

	reference := claudeCodeNativeOtelReferenceEnv(opts)
	original := map[string]interface{}{}
	if backup.HadEnvKey && len(backup.OriginalEnv) > 0 {
		if err := json.Unmarshal(backup.OriginalEnv, &original); err != nil {
			return nil, nil, fmt.Errorf("parse original Claude env backup: %w", err)
		}
	}
	// A snapshot an upgrade took of DefenseClaw's own env block is not the
	// operator's, so nothing is restored from it.
	if claudeCodeEnvSnapshotIsDefenseClawWritten(original, reference) ||
		claudeCodeEnvSnapshotIsOrphanedDefenseClawBlock(original) {
		original = map[string]interface{}{}
	}

	var removed []string
	for _, key := range claudeCodeOtelEnvKeys {
		if key == "DEFENSECLAW_FAIL_MODE" {
			continue
		}
		got, isString := env[key].(string)
		if !isString || got == "" {
			continue
		}
		owned := false
		replacement, keepRest := "", false
		switch {
		case claudeCodeOTLPEndpointKey(key):
			owned = claudeCodeLoopbackGatewayEndpoint(got)
		case claudeCodeOTLPHeadersKey(key):
			rest, marked := claudeCodeWithoutDefenseClawHeaders(got)
			owned = marked || recorded(key, got)
			replacement, keepRest = rest, marked && rest != ""
		default:
			owned = !claudeCodeEnvValueDisablesExport(got) &&
				(got == reference[key] || claudeCodeEarlierReleaseEnv[key] == got || recorded(key, got))
		}
		if !owned {
			continue
		}
		removed = append(removed, "settings.json env."+key)
		if keepRest {
			env[key] = replacement
			continue
		}
		if prior, existed := original[key]; existed && !claudeCodeEnvValueIsDefenseClaw(key, prior, reference) {
			env[key] = prior
		} else {
			delete(env, key)
		}
	}
	if helperOwned {
		restoreClaudeCodeOTLPHeadersHelper(settings, backup)
		removed = append(removed, "settings.json "+claudeCodeOTLPHeadersHelperKey)
	}
	if len(removed) == 0 {
		return nil, nil, nil
	}
	if env != nil {
		if len(env) == 0 && !backup.HadEnvKey {
			delete(settings, "env")
		} else {
			settings["env"] = env
		}
	}
	sort.Strings(removed)
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshal Claude Code settings: %w", err)
	}
	return out, removed, nil
}

func claudeCodeOTLPEndpointKey(key string) bool {
	return strings.HasPrefix(key, "OTEL_EXPORTER_OTLP_") && strings.HasSuffix(key, "_ENDPOINT")
}

func claudeCodeOTLPHeadersKey(key string) bool {
	return strings.HasPrefix(key, "OTEL_EXPORTER_OTLP_") && strings.HasSuffix(key, "_HEADERS")
}

// claudeCodeEnvValueDisablesExport reports a value that turns an exporter, a
// capture gate or telemetry off. Leaving it keeps the account's data private.
func claudeCodeEnvValueDisablesExport(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "none", "0", "false":
		return true
	default:
		return false
	}
}

// claudeCodeEnvValueIsDefenseClaw reports a backed-up value that is itself
// DefenseClaw's, so it must not come back.
func claudeCodeEnvValueIsDefenseClaw(key string, value interface{}, reference map[string]string) bool {
	got, _ := value.(string)
	switch {
	case claudeCodeOTLPEndpointKey(key):
		return claudeCodeScopedLoopbackOTLPEndpoint(got)
	case claudeCodeOTLPHeadersKey(key):
		_, marked := claudeCodeWithoutDefenseClawHeaders(got)
		return marked
	default:
		return got != "" && !claudeCodeEnvValueDisablesExport(got) &&
			(got == reference[key] || claudeCodeEarlierReleaseEnv[key] == got)
	}
}

// claudeCodeScopedLoopbackOTLPEndpoint reports a loopback http endpoint with
// the connector-scoped /otlp/claudecode/<token> path, on any port. The API port
// is mutable configuration, so it cannot be part of ownership.
func claudeCodeScopedLoopbackOTLPEndpoint(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host := strings.TrimSuffix(parsed.Hostname(), ".")
	if ip := net.ParseIP(host); !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
		return false
	}
	if port, err := strconv.Atoi(parsed.Port()); err != nil || port <= 0 || port > 65535 {
		return false
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "otlp" || parts[1] != string(OTLPScopeClaude) || !otlpTokenHexRE.MatchString(parts[2]) {
		return false
	}
	if len(parts) == 3 {
		return true
	}
	if len(parts) != 5 || parts[3] != "v1" {
		return false
	}
	for _, signal := range AllNativeOTLPSignals() {
		if parts[4] == string(signal) {
			return true
		}
	}
	return false
}

// claudeCodeWithoutDefenseClawHeaders removes the DefenseClaw parts of an
// OTLP headers value. A value is DefenseClaw's only when it carries the
// claudecode source or client marker; then its x-defenseclaw-* parts and the
// connector bearer DefenseClaw wrote beside them go, and any operator header
// stays.
func claudeCodeWithoutDefenseClawHeaders(value string) (string, bool) {
	parts := strings.Split(value, ",")
	marked := false
	for _, part := range parts {
		name, headerValue, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		decoded, err := url.PathUnescape(strings.TrimSpace(headerValue))
		if err != nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "x-defenseclaw-source":
			marked = marked || decoded == string(OTLPScopeClaude)
		case "x-defenseclaw-client":
			marked = marked || strings.HasPrefix(decoded, "claudecode-otel/")
		}
	}
	if !marked {
		return value, false
	}
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		name, headerValue, _ := strings.Cut(strings.TrimSpace(part), "=")
		lower := strings.ToLower(strings.TrimSpace(name))
		if strings.HasPrefix(lower, "x-defenseclaw-") {
			continue
		}
		if lower == "authorization" {
			decoded, err := url.PathUnescape(strings.TrimSpace(headerValue))
			if err == nil && strings.HasPrefix(decoded, "Bearer ") &&
				otlpTokenHexRE.MatchString(strings.TrimPrefix(decoded, "Bearer ")) {
				continue
			}
		}
		if strings.TrimSpace(part) != "" {
			kept = append(kept, strings.TrimSpace(part))
		}
	}
	return strings.Join(kept, ","), true
}
