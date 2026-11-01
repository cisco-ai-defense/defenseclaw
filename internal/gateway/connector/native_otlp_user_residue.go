// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/sha256"
	"encoding/hex"
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
	"strings"
	"time"
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
	removed, err := userNativeOTLPConfig(connectorName, "", opts, apply)
	if err != nil {
		return removed, err
	}
	// Revoke only after no configuration references the credential.
	credential, err := userNativeOTLPCredential(connectorName, opts, apply)
	return append(removed, credential...), err
}

// RemoveUserNativeOTLPAt removes the DefenseClaw exporter entries from one
// agent configuration file, configPath, which may sit outside the default
// root (CODEX_HOME, CLAUDE_CONFIG_DIR, or the file a setup recorded). It
// leaves the scoped credential: the caller revokes it
// (RevokeUserNativeOTLPCredential) once no configuration names it.
func RemoveUserNativeOTLPAt(connectorName, configPath string, opts SetupOpts) ([]string, error) {
	if strings.TrimSpace(configPath) == "" {
		return nil, errors.New("native OTLP cleanup: empty config path")
	}
	return userNativeOTLPConfig(connectorName, configPath, opts, true)
}

// UserNativeOTLPCredentialResidue names the scoped native OTLP credential
// file a per-user setup left, if it is still there.
func UserNativeOTLPCredentialResidue(connectorName string, opts SetupOpts) ([]string, error) {
	return userNativeOTLPCredential(connectorName, opts, false)
}

// RevokeUserNativeOTLPCredential removes that credential and names it.
func RevokeUserNativeOTLPCredential(connectorName string, opts SetupOpts) ([]string, error) {
	return userNativeOTLPCredential(connectorName, opts, true)
}

// UserNativeOTLPResidueIn names the DefenseClaw exporter entries in config,
// the bytes of a Codex config.toml or Claude Code settings.json the caller
// read itself, judged against backup, the bytes of the connector's setup
// backup (UserNativeOTLPBackupName; nil when there is none). A config over
// UserNativeOTLPReadLimit is refused unread.
func UserNativeOTLPResidueIn(connectorName string, config, backup []byte, opts SetupOpts) ([]string, error) {
	_, removed, err := userNativeOTLPWithoutIn(connectorName, config, backup, opts)
	return removed, err
}

// NativeOTLPCredentialDigest names a product credential by its length and
// SHA-256, so a process that must not hold the credential itself (the
// managed Unix guardian's worker, which runs as the account) still knows an
// exporter that carries it (GAP-2376).
type NativeOTLPCredentialDigest struct {
	Length int    `json:"length"`
	SHA256 string `json:"sha256"`
}

// NativeOTLPCredentialDigestOf is the digest of credential; ok is false for
// a credential too short to prove ownership.
func NativeOTLPCredentialDigestOf(credential string) (NativeOTLPCredentialDigest, bool) {
	credential = strings.TrimSpace(credential)
	if len(credential) < otlpMinKnownTokenLen {
		return NativeOTLPCredentialDigest{}, false
	}
	sum := sha256.Sum256([]byte(credential))
	return NativeOTLPCredentialDigest{Length: len(credential), SHA256: hex.EncodeToString(sum[:])}, true
}

// UserNativeOTLPWithout returns config (the bytes of a Codex config.toml or
// Claude Code settings.json the caller read itself) without the DefenseClaw
// exporter entries UserNativeOTLPResidueIn names, and those entries; out is
// nil when there are none. A credential in config whose digest is one of
// credentials is known as the product's as well; any other entry, an
// exporter with a foreign bearer included, is kept as it is.
func UserNativeOTLPWithout(connectorName string, config, backup []byte, opts SetupOpts, credentials []NativeOTLPCredentialDigest) ([]byte, []string, error) {
	for _, digest := range credentials {
		if credential, ok := nativeOTLPCredentialIn(config, digest.Length, digest.SHA256); ok {
			opts.knownCredentials = append(slices.Clone(opts.knownCredentials), credential)
		}
	}
	return userNativeOTLPWithoutIn(connectorName, config, backup, opts)
}

func userNativeOTLPWithoutIn(connectorName string, config, backup []byte, opts SetupOpts) ([]byte, []string, error) {
	switch connectorName {
	case "codex":
		var original codexConfigBackup
		if len(backup) > 0 {
			if err := json.Unmarshal(backup, &original); err != nil {
				return nil, nil, fmt.Errorf("load original Codex OTel config: %w", err)
			}
		}
		return codexWithoutUserNativeOTLP(config, original, opts)
	case "claudecode":
		var original claudeCodeBackup
		if len(backup) > 0 {
			if err := json.Unmarshal(backup, &original); err != nil {
				return nil, nil, fmt.Errorf("load Claude Code settings backup: %w", err)
			}
		}
		return claudeCodeWithoutUserNativeOTLP(config, original, opts)
	}
	return nil, nil, nil
}

// UserNativeOTLPTakeBackResidueIn is UserNativeOTLPResidueIn for a
// take-back: an exporter whose credential an earlier take-back revoked is
// still known as DefenseClaw's by the digest its pending marker keeps
// (GAP-1839). Verify never uses it: with the credential revoked the managed
// gateway serves none, and the marker is reported instead.
func UserNativeOTLPTakeBackResidueIn(connectorName string, config, backup []byte, opts SetupOpts) ([]string, error) {
	return UserNativeOTLPResidueIn(connectorName, config, backup, withNativeOTLPTakeBackCredential(opts, connectorName, config))
}

// UserNativeOTLPBackupName is the setup backup a per-user install kept in its
// data dir for connectorName ("" for a connector without a native exporter).
func UserNativeOTLPBackupName(connectorName string) string {
	switch connectorName {
	case "codex":
		return "codex_config_backup.json"
	case "claudecode":
		return "claudecode_backup.json"
	}
	return ""
}

// UserNativeOTLPConfigPathFor is the agent configuration file under the
// account home that a per-user setup wrote its exporter into when no
// variable moved the root: ~/.codex/config.toml or ~/.claude/settings.json.
// The caller adds the roots the account's own environment names; this
// process's environment is not the account's.
func UserNativeOTLPConfigPathFor(connectorName, home string) string {
	switch connectorName {
	case "codex":
		if CodexConfigPathOverride != "" {
			return CodexConfigPathOverride
		}
		return filepath.Join(home, ".codex", "config.toml")
	case "claudecode":
		if ClaudeCodeSettingsPathOverride != "" {
			return ClaudeCodeSettingsPathOverride
		}
		return filepath.Join(home, ".claude", "settings.json")
	}
	return ""
}

// UserNativeOTLPReadLimit bounds every file the native OTLP check reads.
const UserNativeOTLPReadLimit = userNativeOTLPReadLimit

// UserNativeOTLPFileTooLarge is the error for a file over
// UserNativeOTLPReadLimit; it names the base name only.
func UserNativeOTLPFileTooLarge(name string) error {
	return userNativeOTLPTooLarge(name)
}

// UserAgentConfigRecordPath is where a per-user setup recorded the agent
// configuration file it bound its managed record to, for connectorName.
func UserAgentConfigRecordPath(dataDir, connectorName string) string {
	for _, pin := range connectorConfigRootPins {
		if pin.connector == connectorName {
			return managedFileBackupPath(dataDir, pin.connector, pin.logical)
		}
	}
	return ""
}

// UserAgentConfigRecordTarget is the configuration file record (the bytes of
// UserAgentConfigRecordPath) names, or "" when it names none of that
// connector's.
func UserAgentConfigRecordTarget(connectorName string, record []byte) string {
	for _, pin := range connectorConfigRootPins {
		if pin.connector != connectorName {
			continue
		}
		var b managedFileBackup
		if json.Unmarshal(record, &b) != nil || b.Version != managedBackupVersion ||
			b.Connector != pin.connector || b.LogicalName != pin.logical {
			return ""
		}
		target := filepath.Clean(strings.TrimSpace(b.Path))
		if !filepath.IsAbs(target) || !strings.EqualFold(filepath.Base(target), pin.file[len(pin.file)-1]) {
			return ""
		}
		return target
	}
	return ""
}

func userNativeOTLPConfig(connectorName, configPath string, opts SetupOpts, apply bool) ([]string, error) {
	if strings.TrimSpace(opts.DataDir) == "" {
		return nil, errors.New("native OTLP cleanup: empty data dir")
	}
	switch connectorName {
	case "codex":
		if configPath == "" {
			configPath = codexConfigPath()
		}
		return codexUserNativeOTLP(configPath, opts, apply)
	case "claudecode":
		if configPath == "" {
			configPath = claudeCodeSettingsPath()
		}
		return claudeCodeUserNativeOTLP(configPath, opts, apply)
	}
	return nil, nil
}

func userNativeOTLPCredential(connectorName string, opts SetupOpts, apply bool) ([]string, error) {
	if strings.TrimSpace(opts.DataDir) == "" {
		return nil, errors.New("native OTLP cleanup: empty data dir")
	}
	var scope OTLPPathTokenScope
	switch connectorName {
	case "codex":
		scope = OTLPScopeCodex
	case "claudecode":
		scope = OTLPScopeClaude
	default:
		return nil, nil
	}
	tokenPath, err := OTLPPathTokenFilePath(opts.DataDir, scope)
	if err != nil {
		return nil, err
	}
	var removed []string
	if _, statErr := os.Lstat(tokenPath); statErr == nil {
		removed = append(removed, "hooks/"+otlpPathTokenFileName(scope))
		if apply {
			if err := RemoveOTLPPathToken(opts.DataDir, scope); err != nil {
				return removed, fmt.Errorf("revoke obsolete %s native OTLP credential: %w", connectorName, err)
			}
		}
	} else if !os.IsNotExist(statErr) {
		return nil, fmt.Errorf("inspect %s native OTLP credential: %w", connectorName, statErr)
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

func codexUserNativeOTLP(configPath string, opts SetupOpts, apply bool) ([]string, error) {
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
	opts = withNativeOTLPTakeBackCredential(opts, "codex", raw)
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
	opts = withMarkedOrphanExporterCredentials(opts, "codex", raw)
	// Any [otel] value that carries a DefenseClaw credential is the
	// product's, an exporter or not.
	if !otlpCarriesProductCredential(otel, otlpKnownProductTokens(opts, OTLPScopeCodex)) {
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

func claudeCodeUserNativeOTLP(settingsPath string, opts SetupOpts, apply bool) ([]string, error) {
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
	opts = withNativeOTLPTakeBackCredential(opts, "claudecode", raw)
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
// DefenseClaw native exporter. Ownership needs proof in the env block: any
// OTLP env value carrying a DefenseClaw credential
// (otlpCarriesProductCredential), the exact endpoint or header value the setup
// backup recorded writing, or the earlier headers helper. A credential-bearing
// value is always removed; any other route is the operator's. Values that turn
// export off stay.
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
	opts = withMarkedOrphanExporterCredentials(opts, "claudecode", raw)
	known := claudeCodeKnownProductTokens(backup, opts)
	proof := helperOwned
	for key, value := range env {
		got, _ := value.(string)
		if got != "" && claudeCodeOTLPEnvKey(key) && otlpCarriesProductCredential(got, known) ||
			got != "" && (claudeCodeOTLPEndpointKey(key) || claudeCodeOTLPHeadersKey(key)) && recorded(key, got) {
			proof = true
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
	// The backup proves DefenseClaw wrote that exact endpoint, so a value it
	// recorded is the product's even after its bearer was replaced.
	endpointOwned := func(key, endpoint string) bool {
		return recorded(key, endpoint) || claudeCodeRouteIsProduct(ownershipEnv, key, endpoint, known)
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
	for _, key := range claudeCodeOTLPEnvKeys(env) {
		if key == "DEFENSECLAW_FAIL_MODE" {
			continue
		}
		got, isString := env[key].(string)
		if !isString || got == "" {
			continue
		}
		credential := claudeCodeOTLPEnvKey(key) && otlpCarriesProductCredential(got, known)
		if keepOperatorSetting[key] && !credential {
			continue
		}
		owned := false
		switch {
		case credential:
			// A DefenseClaw credential in any OTLP value (resource attributes
			// and service name included) never stays beside a kept route.
			owned = true
		case claudeCodeOTLPEndpointKey(key):
			// A credential on logs does not claim another signal's collector.
			owned = endpointOwned(key, got)
		case claudeCodeOTLPHeadersKey(key):
			owned = recorded(key, got)
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
		if prior, existed := original[key]; existed && !claudeCodeEnvValueIsDefenseClaw(key, prior, reference, known) {
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

// claudeCodeOTLPEnvKey reports an env key the OpenTelemetry SDK reads, so a
// credential in its value would reach an exporter.
func claudeCodeOTLPEnvKey(key string) bool {
	return strings.HasPrefix(key, "OTEL_")
}

// claudeCodeOTLPEnvKeys returns claudeCodeOtelEnvKeys followed, sorted, by the
// other OTLP keys env holds, so credential cleanup covers every OTLP value.
func claudeCodeOTLPEnvKeys(env map[string]interface{}) []string {
	keys := append([]string(nil), claudeCodeOtelEnvKeys...)
	var extra []string
	for key := range env {
		if claudeCodeOTLPEnvKey(key) && !slices.Contains(claudeCodeOtelEnvKeys, key) {
			extra = append(extra, key)
		}
	}
	sort.Strings(extra)
	return append(keys, extra...)
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
// DefenseClaw's, so it must not come back: one that carries a known product
// credential, or a value an earlier profile wrote.
func claudeCodeEnvValueIsDefenseClaw(key string, value interface{}, reference map[string]string, known []string) bool {
	got, _ := value.(string)
	switch {
	case claudeCodeOTLPEnvKey(key) && otlpCarriesProductCredential(got, known):
		return true
	case claudeCodeOTLPEndpointKey(key), claudeCodeOTLPHeadersKey(key):
		return false
	default:
		return got != "" && !claudeCodeEnvValueDisablesExport(got) &&
			(got == reference[key] || claudeCodeEarlierReleaseEnv[key] == got)
	}
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

// claudeCodeKnownProductTokens returns the credentials this install can name:
// otlpKnownProductTokens for the Claude Code scope, every bearer its backup
// recorded under an OTLP header key, and every credential an earlier Setup
// retired. A retired credential's sidecar is revoked and the hook-only
// ManagedEnv no longer names it, so without the retired list a restored
// pre-upgrade exporter would pass cleanup and Verify (GAP-1511).
func claudeCodeKnownProductTokens(backup claudeCodeBackup, opts SetupOpts) []string {
	known := otlpKnownProductTokens(opts, OTLPScopeClaude)
	known = append(known, backup.RetiredOTLPCredentials...)
	for key, value := range backup.ManagedEnv {
		if !claudeCodeOTLPHeadersKey(key) {
			continue
		}
		for _, entry := range claudeCodeAuthorizationValues(value) {
			if credential, ok := otlpBearerCredential(entry); ok {
				known = append(known, credential)
			}
		}
	}
	return known
}

// claudeCodeRouteIsProduct reports a Claude Code OTLP endpoint DefenseClaw
// owns: the route (the endpoint and the headers Claude Code sends with it)
// carries a DefenseClaw credential. Any other endpoint is the operator's
// collector, on any host or port.
func claudeCodeRouteIsProduct(env map[string]interface{}, endpointKey, endpoint string, known []string) bool {
	return endpoint != "" && otlpCarriesProductCredential(
		[]interface{}{endpoint, claudeCodeEffectiveEndpointHeaders(env, endpointKey)}, known)
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

// A take-back that could not clean the account's agent config (a .codex on a
// network share a signed-out account's S4U token cannot read, a path through
// a reparse point) leaves this marker in the account's managed data
// directory, beside the hook runtime it protects (GAP-1839, GAP-1840). The
// exporter may still send the agent's prompts to a port no DefenseClaw
// process holds, so the guardian reports the account and connector in status
// and verify (AgentConfigNativeOTLPTakeBackPending) until a later install or
// repair removes the exporter and the marker; it never fails the install.
// The take-back revokes the scoped credential, which was the proof that the
// exporter is DefenseClaw's, so the marker keeps its SHA-256 (never the
// value): a later take-back finds the credential in the config by that digest
// and still removes the exporter.
const nativeOTLPTakeBackPendingPrefix = "native-otlp-take-back-pending-"

// nativeOTLPTakeBackPendingMaxBytes bounds the marker read.
const nativeOTLPTakeBackPendingMaxBytes = 4 << 10

type nativeOTLPTakeBackPendingRecord struct {
	Connector        string `json:"connector"`
	At               string `json:"at"`
	CredentialSHA256 string `json:"credential_sha256,omitempty"`
	CredentialLength int    `json:"credential_length,omitempty"`
	// Backup (the removed-exporter note only) is the copy of the agent
	// config the take-back kept before it removed a managed orphan exporter.
	Backup string `json:"backup,omitempty"`
}

func nativeOTLPTakeBackPendingPath(dataDir, connectorName string) (string, OTLPPathTokenScope, bool) {
	if strings.TrimSpace(dataDir) == "" {
		return "", "", false
	}
	scope, ok := OTLPPathTokenScopeForConnector(connectorName)
	if !ok {
		return "", "", false
	}
	return filepath.Join(dataDir, nativeOTLPTakeBackPendingPrefix+strings.ToLower(strings.TrimSpace(connectorName))+".json"), scope, true
}

// nativeOTLPTakeBackPendingBeforeRead runs between the marker's checks and
// its read. Tests replace it.
var nativeOTLPTakeBackPendingBeforeRead = func(string) {}

// readNativeOTLPTakeBackPending reads the marker in the account's data
// directory, which the SYSTEM guardian does every pass (GAP-2021): only a
// regular file the account (or a trusted principal) owns counts, and it is
// read without following a link or blocking on a FIFO, at most
// nativeOTLPTakeBackPendingMaxBytes, and only while it is still the file
// that was checked. Anything else is no marker. The type, size and owner are
// read from the opened handle and the bytes from that same handle, so a file
// swapped in after the check is never trusted (GAP-2065: on Windows the
// owner was read by path and os.SameFile of two Lstat results reloads both
// file IDs by path, so the swap check always passed there).
func readNativeOTLPTakeBackPending(path string) (nativeOTLPTakeBackPendingRecord, bool) {
	var record nativeOTLPTakeBackPendingRecord
	file, err := openNativeOTLPTakeBackMarker(path)
	if err != nil {
		return record, false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > nativeOTLPTakeBackPendingMaxBytes ||
		nativeOTLPTakeBackMarkerOwnerTrusted(path, file, info) != nil {
		return record, false
	}
	nativeOTLPTakeBackPendingBeforeRead(path)
	data, err := io.ReadAll(io.LimitReader(file, nativeOTLPTakeBackPendingMaxBytes+1))
	if err != nil || int64(len(data)) > nativeOTLPTakeBackPendingMaxBytes {
		return record, false
	}
	if after, err := os.Lstat(path); err != nil || !os.SameFile(info, after) {
		return record, false
	}
	if json.Unmarshal(data, &record) != nil {
		return nativeOTLPTakeBackPendingRecord{}, true
	}
	return record, true
}

// RecordNativeOTLPTakeBackPending leaves the take-back-pending marker for
// connectorName in dataDir. Call it before the scoped credential is revoked:
// it keeps the credential's digest (or the digest an earlier marker kept).
func RecordNativeOTLPTakeBackPending(dataDir, connectorName string) error {
	path, scope, ok := nativeOTLPTakeBackPendingPath(dataDir, connectorName)
	if !ok {
		return fmt.Errorf("native OTLP take-back marker: no exporter for connector %q", connectorName)
	}
	record, _ := readNativeOTLPTakeBackPending(path)
	record.Connector = strings.ToLower(strings.TrimSpace(connectorName))
	record.At = time.Now().UTC().Format(time.RFC3339)
	if token, err := LoadOTLPPathToken(dataDir, scope); err == nil && len(token) >= otlpMinKnownTokenLen {
		sum := sha256.Sum256([]byte(token))
		record.CredentialSHA256, record.CredentialLength = hex.EncodeToString(sum[:]), len(token)
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// ClearNativeOTLPTakeBackPending removes the marker once the take-back found
// nothing left to remove; an absent marker is not an error.
func ClearNativeOTLPTakeBackPending(dataDir, connectorName string) error {
	path, _, ok := nativeOTLPTakeBackPendingPath(dataDir, connectorName)
	if !ok {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// The managed Windows take-back that removes an exporter only the managed
// orphan shape proves (GAP-0836) keeps a copy of the account's file beside
// it (NativeOTLPMarkedOrphanBackupSuffix) and leaves this note in the
// account's managed data directory; status and verify name the removal
// (AgentConfigNativeOTLPMarkedRemoved) while the note and the copy are both
// there, so the account deletes the copy once it has checked it.
const (
	nativeOTLPMarkedRemovedPrefix      = "native-otlp-removed-"
	NativeOTLPMarkedOrphanBackupSuffix = ".defenseclaw-otlp-removed.bak"
)

func nativeOTLPMarkedRemovedPath(dataDir, connectorName string) (string, bool) {
	if strings.TrimSpace(dataDir) == "" {
		return "", false
	}
	if _, ok := OTLPPathTokenScopeForConnector(connectorName); !ok {
		return "", false
	}
	return filepath.Join(dataDir, nativeOTLPMarkedRemovedPrefix+strings.ToLower(strings.TrimSpace(connectorName))+".json"), true
}

// RecordNativeOTLPMarkedOrphanRemoved leaves the removed-exporter note for
// connectorName in dataDir naming backup, the copy the take-back kept.
func RecordNativeOTLPMarkedOrphanRemoved(dataDir, connectorName, backup string) error {
	path, ok := nativeOTLPMarkedRemovedPath(dataDir, connectorName)
	if !ok {
		return fmt.Errorf("native OTLP removed-exporter note: no exporter for connector %q", connectorName)
	}
	data, err := json.Marshal(nativeOTLPTakeBackPendingRecord{
		Connector: strings.ToLower(strings.TrimSpace(connectorName)),
		At:        time.Now().UTC().Format(time.RFC3339),
		Backup:    backup,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// NativeOTLPMarkedOrphanRemoved reports the removed-exporter note for
// connectorName in dataDir while the copy it names is still there. The note
// is read like the take-back-pending marker (a regular file the account
// owns, never through a link); a copy that is not a regular file with the
// product's suffix does not count.
func NativeOTLPMarkedOrphanRemoved(dataDir, connectorName string) bool {
	path, ok := nativeOTLPMarkedRemovedPath(dataDir, connectorName)
	if !ok {
		return false
	}
	record, ok := readNativeOTLPTakeBackPending(path)
	if !ok || !strings.HasSuffix(record.Backup, NativeOTLPMarkedOrphanBackupSuffix) || !filepath.IsAbs(record.Backup) {
		return false
	}
	info, err := os.Lstat(record.Backup)
	return err == nil && info.Mode().IsRegular()
}

// NativeOTLPTakeBackPending reports a take-back-pending marker for
// connectorName in dataDir (a regular file, read without following a link).
func NativeOTLPTakeBackPending(dataDir, connectorName string) bool {
	path, _, ok := nativeOTLPTakeBackPendingPath(dataDir, connectorName)
	if !ok {
		return false
	}
	_, ok = readNativeOTLPTakeBackPending(path)
	return ok
}

// UserNativeOTLPPathUnreachable names the link on the path to an agent
// configuration file whose target cannot be reached (a symlink to a share
// whose server is off the network or whose name does not resolve, a junction
// to a removed folder), else "". Go reports such a config as os.ErrNotExist
// (Windows maps ERROR_BAD_NETPATH to it), the same as an account with no
// config, so the residue check alone would read "no exporter". A take-back
// must treat it as a config it cannot read, never as a clean one (GAP-2095).
func UserNativeOTLPPathUnreachable(path string) string {
	return unresolvedLinkOnPath(path)
}

// unresolvedLinkOnPath returns the link on path that does not resolve: the
// config file itself when it is a link (symlink or other reparse point) whose
// target cannot be reached (a config.toml linked to a share whose server is
// off the network), else the nearest existing ancestor of a missing path when
// that ancestor is such a link, else "".
func unresolvedLinkOnPath(path string) string {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
			return ""
		}
		if _, err := os.Stat(path); err != nil {
			return path
		}
		return ""
	} else if !errors.Is(err, os.ErrNotExist) {
		return ""
	}
	for dir := filepath.Dir(path); ; {
		info, err := os.Lstat(dir)
		if err == nil {
			if info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
				return ""
			}
			if _, err := os.Stat(dir); err != nil {
				return dir
			}
			return ""
		}
		if !errors.Is(err, os.ErrNotExist) {
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// withNativeOTLPTakeBackCredential gives opts the revoked credential that a
// pending marker's digest finds in raw (the account's agent config), so the
// take-back can still prove the exporter is DefenseClaw's.
func withNativeOTLPTakeBackCredential(opts SetupOpts, connectorName string, raw []byte) SetupOpts {
	if strings.TrimSpace(opts.OTLPPathToken) != "" {
		return opts
	}
	path, _, ok := nativeOTLPTakeBackPendingPath(opts.DataDir, connectorName)
	if !ok {
		return opts
	}
	record, ok := readNativeOTLPTakeBackPending(path)
	if !ok {
		return opts
	}
	if credential, found := nativeOTLPCredentialIn(raw, record.CredentialLength, record.CredentialSHA256); found {
		opts.OTLPPathToken = credential
	}
	return opts
}

// nativeOTLPCredentialIn finds the credential of length bytes whose SHA-256
// is sha256Hex in raw. A credential is a run of token characters (letters,
// digits and -._~+/=), so only windows inside such runs are hashed.
func nativeOTLPCredentialIn(raw []byte, length int, sha256Hex string) (string, bool) {
	if length < otlpMinKnownTokenLen || len(sha256Hex) != hex.EncodedLen(sha256.Size) {
		return "", false
	}
	want := strings.ToLower(sha256Hex)
	tokenByte := func(c byte) bool {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.IndexByte("-._~+/=", c) >= 0
	}
	for start := 0; start < len(raw); {
		if !tokenByte(raw[start]) {
			start++
			continue
		}
		end := start
		for end < len(raw) && tokenByte(raw[end]) {
			end++
		}
		for i := start; i+length <= end; i++ {
			sum := sha256.Sum256(raw[i : i+length])
			if hex.EncodeToString(sum[:]) == want {
				return string(raw[i : i+length]), true
			}
		}
		start = end
	}
	return "", false
}
