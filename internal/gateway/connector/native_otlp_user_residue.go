// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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
// setup backup proves, and revokes the scoped OTLP credential file. Both use
// product markers, recorded values, or the scoped product token to prove
// ownership and leave every other entry alone. Use them only for a profile
// that installs no user-level exporter;
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

// A managed Windows user's .defenseclaw directory has a protected DACL that
// lets the user edit runtime files but reserves WRITE_DAC for SYSTEM. The
// compare-and-swap helper's private-state setup would try to replace that
// DACL under the user's impersonated token. Keep this edit's private recovery
// state beside the user's agent config instead.
func userNativeOTLPTransactionDir(configPath string, opts SetupOpts) string {
	if opts.ManagedEnterprise && runtime.GOOS == "windows" {
		return filepath.Join(filepath.Dir(configPath), ".defenseclaw-cas-state")
	}
	return opts.DataDir
}

// userNativeOTLPReadLimit bounds every file the check reads: the agent
// configuration and the setup backup. Managed Verify runs the check inside the
// shared Windows guardian on every reconcile, against files the account
// controls, so a larger file is reported unverified and never read or parsed.
// Repair applies the same bound, so such a row stays unverified until the
// account trims the file.
const userNativeOTLPReadLimit int64 = 4 << 20

// errUserNativeOTLPFileTooLarge marks a file over userNativeOTLPReadLimit.
var errUserNativeOTLPFileTooLarge = errors.New("file exceeds the native OTLP check read limit")

func userNativeOTLPTooLarge(name string) error {
	return fmt.Errorf("%s is larger than %d bytes: %w", name, userNativeOTLPReadLimit, errUserNativeOTLPFileTooLarge)
}

// readUserNativeOTLPFile reads a regular file of at most
// userNativeOTLPReadLimit bytes. It checks the size before it allocates and
// reads through a limit, so neither a sparse file nor one that grows during
// the read costs more than the limit. A missing file keeps its os.ErrNotExist.
func readUserNativeOTLPFile(path string) ([]byte, error) {
	name := filepath.Base(path)
	before, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	// A FIFO or device would block the open or never end.
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	if before.Size() > userNativeOTLPReadLimit {
		return nil, userNativeOTLPTooLarge(name)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("%s changed during inspection", name)
	}
	if opened.Size() > userNativeOTLPReadLimit {
		return nil, userNativeOTLPTooLarge(name)
	}
	data, err := io.ReadAll(io.LimitReader(file, userNativeOTLPReadLimit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > userNativeOTLPReadLimit {
		return nil, userNativeOTLPTooLarge(name)
	}
	return data, nil
}

// readUserNativeOTLPBackup decodes the setup backup name in dataDir into
// backup. A missing backup leaves backup as it is.
func readUserNativeOTLPBackup(dataDir, name string, backup interface{}) error {
	data, err := readUserNativeOTLPFile(filepath.Join(dataDir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, backup)
}

func codexUserNativeOTLP(opts SetupOpts, apply bool) ([]string, error) {
	configPath := codexConfigPath()
	var backup codexConfigBackup
	if err := readUserNativeOTLPBackup(opts.DataDir, "codex_config_backup.json", &backup); err != nil {
		return nil, fmt.Errorf("load original Codex OTel config: %w", err)
	}
	raw, err := readUserNativeOTLPFile(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read Codex config: %w", err)
	}
	_, removed, err := codexWithoutUserNativeOTLP(raw, backup, opts)
	if err != nil || !apply || len(removed) == 0 {
		return removed, err
	}
	err = withUserAgentConfigLock(configPath, opts, func() error {
		return atomicTransformFileWithStateDir(configPath, userNativeOTLPTransactionDir(configPath, opts), 0o600, func(current []byte, exists bool) (atomicTransformResult, error) {
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
	// The repair transform rereads the file under a larger bound.
	if int64(len(raw)) > userNativeOTLPReadLimit {
		return nil, nil, userNativeOTLPTooLarge("config.toml")
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
		if codexExporterHasAmbiguousLegacyPort(otel[key], opts) {
			return nil, nil, fmt.Errorf("Codex native OTLP exporter ownership is unresolved at otel.%s.otlp-http.endpoint; remove the stale exporter from config.toml before retrying", key) //nolint:staticcheck // Preserve the product name in this operator diagnostic.
		}
		if codexExporterLooksManaged(otel[key], opts) || codexExporterHasManagedHeaderPair(otel[key]) || codexExporterUsesProductBearer(otel[key], opts) {
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
	if err := restoreCodexOtelEntries(cfg, backup, opts); err != nil {
		return nil, nil, err
	}
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
	var backup claudeCodeBackup
	if err := readUserNativeOTLPBackup(opts.DataDir, "claudecode_backup.json", &backup); err != nil {
		return nil, fmt.Errorf("load Claude Code settings backup: %w", err)
	}
	raw, err := readUserNativeOTLPFile(settingsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read Claude Code settings: %w", err)
	}
	_, removed, err := claudeCodeWithoutUserNativeOTLP(raw, backup, opts)
	if err != nil || !apply || len(removed) == 0 {
		return removed, err
	}
	err = withUserAgentConfigLock(settingsPath, opts, func() error {
		return atomicTransformFileWithStateDir(settingsPath, userNativeOTLPTransactionDir(settingsPath, opts), 0o600, func(current []byte, exists bool) (atomicTransformResult, error) {
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
// DefenseClaw native exporter. Ownership needs a product marker in the env
// block: a marked header, a scoped /otlp/claudecode/ endpoint, a value the
// setup backup recorded, a bearer matching the recorded or scoped product
// token, or the earlier headers helper. Values that turn export off stay.
func claudeCodeWithoutUserNativeOTLP(raw []byte, backup claudeCodeBackup, opts SetupOpts) ([]byte, []string, error) {
	// The repair transform rereads the file under a larger bound.
	if int64(len(raw)) > userNativeOTLPReadLimit {
		return nil, nil, userNativeOTLPTooLarge("settings.json")
	}
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
			product, _ := claudeCodeProductBearers(got, backup.ManagedEnv, opts)
			if _, marked := claudeCodeWithoutDefenseClawHeaders(got); marked || recorded(key, got) || len(product) > 0 {
				proof = true
			}
		}
	}
	if !proof {
		return nil, nil, nil
	}
	// Header cleanup can precede an endpoint in claudeCodeOtelEnvKeys. Keep
	// ownership decisions tied to the unchanged settings, including a generic
	// header inherited by a signal-specific endpoint.
	ownershipEnv := make(map[string]interface{}, len(env))
	for key, value := range env {
		ownershipEnv[key] = value
	}
	endpointOwned := func(key, endpoint string) bool {
		return recorded(key, endpoint) || claudeCodeScopedLoopbackOTLPEndpoint(endpoint) ||
			claudeCodeLoopbackRouteIsProduct(ownershipEnv, key, endpoint, backup.ManagedEnv, opts)
	}
	// Keeping an operator endpoint also requires keeping the settings that
	// activate that signal. Otherwise cleanup would leave a valid collector
	// address in the file while silently disabling its exporter.
	keepOperatorSetting := map[string]bool{}
	keepSignal := func(signal string) {
		upper := strings.ToUpper(signal)
		keepOperatorSetting["CLAUDE_CODE_ENABLE_TELEMETRY"] = true
		keepOperatorSetting["OTEL_"+upper+"_EXPORTER"] = true
		keepOperatorSetting["OTEL_EXPORTER_OTLP_"+upper+"_PROTOCOL"] = true
	}
	genericEndpoint, _ := env["OTEL_EXPORTER_OTLP_ENDPOINT"].(string)
	if genericEndpoint != "" && !claudeCodeEnvValueDisablesExport(genericEndpoint) &&
		!endpointOwned("OTEL_EXPORTER_OTLP_ENDPOINT", genericEndpoint) {
		keepOperatorSetting["OTEL_EXPORTER_OTLP_PROTOCOL"] = true
		for _, signal := range AllNativeOTLPSignals() {
			keepSignal(string(signal))
		}
	}
	for _, signal := range AllNativeOTLPSignals() {
		key := "OTEL_EXPORTER_OTLP_" + strings.ToUpper(string(signal)) + "_ENDPOINT"
		endpoint, _ := env[key].(string)
		if endpoint != "" && !claudeCodeEnvValueDisablesExport(endpoint) &&
			!endpointOwned(key, endpoint) {
			keepSignal(string(signal))
		}
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
		if keepOperatorSetting[key] {
			continue
		}
		owned := false
		replacement, keepRest := "", false
		switch {
		case claudeCodeOTLPEndpointKey(key):
			// A marker on logs does not claim another signal's collector.
			owned = endpointOwned(key, got)
		case claudeCodeOTLPHeadersKey(key):
			// Exact backup or scoped-token equality proves product ownership.
			// Verify may be unable to read a target user's sidecar as SYSTEM.
			product, _ := claudeCodeProductBearers(got, backup.ManagedEnv, opts)
			rest, productPart := claudeCodeWithoutDefenseClawHeaders(got, product...)
			owned = productPart || recorded(key, got)
			replacement, keepRest = rest, productPart && rest != ""
		default:
			earlierValue := claudeCodeEarlierReleaseEnv[key] == got &&
				(backup.ManagedEnv[key] == "" || backup.ManagedEnv[key] == got)
			owned = !claudeCodeEnvValueDisablesExport(got) &&
				(got == reference[key] || earlierValue || recorded(key, got))
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
	if !otlpLocalHost(parsed.Hostname()) {
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

// claudeCodeWithoutDefenseClawHeaders removes product markers and every
// Authorization entry whose Bearer credential is one of productTokens, under
// any spelling of the header name or scheme. An operator's changed
// Authorization stays.
func claudeCodeWithoutDefenseClawHeaders(value string, productTokens ...string) (string, bool) {
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
	if !marked && len(productTokens) == 0 {
		return value, false
	}
	kept := make([]string, 0, len(parts))
	removedBearer := false
	for _, part := range parts {
		name, headerValue, _ := strings.Cut(strings.TrimSpace(part), "=")
		lower := strings.ToLower(strings.TrimSpace(name))
		if marked && strings.HasPrefix(lower, "x-defenseclaw-") {
			continue
		}
		if lower == "authorization" && len(productTokens) > 0 {
			decoded, err := url.PathUnescape(strings.TrimSpace(headerValue))
			if credential, ok := otlpBearerCredential(decoded); err == nil && ok && slices.Contains(productTokens, credential) {
				removedBearer = true
				continue
			}
		}
		if strings.TrimSpace(part) != "" {
			kept = append(kept, strings.TrimSpace(part))
		}
	}
	if !marked && !removedBearer {
		return value, false
	}
	return strings.Join(kept, ","), true
}

// A signal-specific header overrides the generic OTLP header. Claude uses the
// generic value when no signal-specific header is set.
func claudeCodeEffectiveEndpointHeaders(env map[string]interface{}, endpointKey string) string {
	headersKey := strings.TrimSuffix(endpointKey, "_ENDPOINT") + "_HEADERS"
	if headers, _ := env[headersKey].(string); headers != "" {
		return headers
	}
	if headersKey != "OTEL_EXPORTER_OTLP_HEADERS" {
		headers, _ := env["OTEL_EXPORTER_OTLP_HEADERS"].(string)
		return headers
	}
	return ""
}

// claudeCodeProductBearers splits the Authorization entries of an OTLP
// headers value into DefenseClaw product credentials and the count of every
// other entry. A released install's backup or trusted scoped-token sidecar
// identifies a product bearer after an operator changes its header key,
// endpoint, markers, header-name spelling or Bearer-scheme spelling. Every
// entry is checked, so an operator entry cannot hide a product one.
func claudeCodeProductBearers(headers string, recordedHeaders map[string]string, opts SetupOpts) (product []string, other int) {
	var known []string
	loaded := false
	isProduct := func(token string) bool {
		if !loaded {
			loaded = true
			for key, value := range recordedHeaders {
				if !claudeCodeOTLPHeadersKey(key) {
					continue
				}
				for _, entry := range claudeCodeAuthorizationValues(value) {
					if credential, ok := otlpBearerCredential(entry); ok && otlpTokenHexRE.MatchString(credential) {
						known = append(known, credential)
					}
				}
			}
			if sidecar, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeClaude); err == nil && sidecar != "" {
				known = append(known, sidecar)
			}
		}
		return slices.Contains(known, token)
	}
	for _, entry := range claudeCodeAuthorizationValues(headers) {
		if credential, ok := otlpBearerCredential(entry); ok && otlpTokenHexRE.MatchString(credential) && isProduct(credential) {
			product = append(product, credential)
			continue
		}
		other++
	}
	return product, other
}

// claudeCodeAuthorizationValues returns the decoded value of every
// Authorization entry, matching the header name case-insensitively.
func claudeCodeAuthorizationValues(value string) []string {
	var values []string
	for _, part := range strings.Split(value, ",") {
		name, headerValue, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "authorization") {
			continue
		}
		decoded, err := url.PathUnescape(strings.TrimSpace(headerValue))
		if err != nil {
			decoded = headerValue
		}
		values = append(values, decoded)
	}
	return values
}

// claudeCodeLoopbackRouteIsProduct reports a local gateway route that is
// DefenseClaw's: the headers Claude sends with it carry a product marker, or
// every Authorization entry in them is a product bearer. Another credential
// beside a product bearer is the operator's edit, so the route stays theirs
// and cleanup strips only the product bearer.
func claudeCodeLoopbackRouteIsProduct(env map[string]interface{}, endpointKey, endpoint string, recordedHeaders map[string]string, opts SetupOpts) bool {
	if !claudeCodeLoopbackGatewayEndpoint(endpoint) {
		return false
	}
	headers := claudeCodeEffectiveEndpointHeaders(env, endpointKey)
	if _, marked := claudeCodeWithoutDefenseClawHeaders(headers); marked {
		return true
	}
	product, other := claudeCodeProductBearers(headers, recordedHeaders, opts)
	return len(product) > 0 && other == 0
}
