// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// scrubAgentConfig removes DefenseClaw-owned entries from a user's native
// agent hook config file so that after `defenseclaw uninstall --purge`
// deletes the hook scripts under ~/.defenseclaw/, the native agent stops
// referencing them and no longer fail-closes every tool call.
//
// This subcommand replaces packaging/macos/lib/scrub_agent_configs.py.
// The Python variant crashed on stock macOS hosts where /usr/bin/python3
// is a Xcode CLT stub that requires developer tools to actually run;
// keeping the scrub inside the daemon binary sidesteps that dependency
// entirely.

// Well-known markers that identify a config value as DefenseClaw-owned.
// Matches DEFAULT_MARKERS in the previous Python implementation.
var scrubDefaultMarkers = []string{
	"/.defenseclaw/hooks/",
	"/defenseclaw/hooks/",
	"defenseclaw-managed-hook",
	"notify-bridge.sh",
}

// Additional markers that identify a Codex [otel] block as DefenseClaw-managed
// when the block body itself doesn't carry a hook script path. DefenseClaw
// configures Codex to send OTLP to a loopback DefenseClaw gateway, so an
// endpoint value pointing at 127.0.0.1 (or localhost) is a strong signal.
// We deliberately do NOT match on "otlp_endpoint" alone — a user with their
// own vendor OTel setup would then get their block scrubbed too.
var scrubCodexOtelMarkers = []string{
	"127.0.0.1",
	"localhost",
	"defenseclaw",
}

// claudeManagedEnvKeys enumerates the env-var keys DefenseClaw's Claude Code
// connector writes into ~/.claude/settings.json. Kept in sync with
// claudeCodeOtelEnvKeys in internal/gateway/connector/claudecode.go.
var claudeManagedEnvKeys = map[string]struct{}{
	"CLAUDE_CODE_ENABLE_TELEMETRY": {},
	"DEFENSECLAW_FAIL_MODE":        {},
	"OTEL_METRICS_EXPORTER":        {},
	"OTEL_LOGS_EXPORTER":           {},
	"OTEL_EXPORTER_OTLP_PROTOCOL":  {},
	"OTEL_EXPORTER_OTLP_ENDPOINT":  {},
	"OTEL_EXPORTER_OTLP_HEADERS":   {},
	"OTEL_LOG_USER_PROMPTS":        {},
	"OTEL_RESOURCE_ATTRIBUTES":     {},
	"OTEL_SERVICE_NAME":            {},
}

var (
	scrubConnectorFlag   string
	scrubFileFlag        string
	scrubDataDirMarker   string
	scrubJSONOutput      bool
	scrubMissingIsSilent bool
)

var enterpriseHooksScrubCmd = &cobra.Command{
	Use:   "scrub",
	Short: "Remove DefenseClaw entries from a user's native agent hook config",
	Long: `Scrub DefenseClaw-owned hook entries out of a user's native agent
config file. Non-DefenseClaw entries are preserved verbatim.

Called by the macOS uninstaller's --purge path so the agent stops referencing
the DefenseClaw hook scripts we're about to delete under ~/.defenseclaw/. May
also be run manually to un-wire hooks for a specific user without a full
uninstall.

Exit codes:
  0   file scrubbed (or already clean)
  2   file missing (nothing to do)
  3   unsupported connector
  4   file unreadable / parse failure (left untouched)`,
	Annotations: map[string]string{
		// Uninstall runs this on hosts where config.yaml may be gone or
		// never existed; skip the daemon-state bootstrap in root.go's
		// PersistentPreRunE so a "config not found" error never masks
		// the real scrub outcome.
		"defenseclaw.skip-daemon-bootstrap": "true",
	},
	SilenceUsage: true,
	RunE:         runEnterpriseHooksScrub,
}

func init() {
	enterpriseHooksScrubCmd.Flags().StringVar(&scrubConnectorFlag, "connector", "",
		"Connector whose entries to remove: codex, claudecode, or cursor (required)")
	enterpriseHooksScrubCmd.Flags().StringVar(&scrubFileFlag, "file", "",
		"Path to the agent config file to scrub (required)")
	enterpriseHooksScrubCmd.Flags().StringVar(&scrubDataDirMarker, "datadir-marker", "",
		"Extra path substring treated as DefenseClaw-owned (defaults are hard-coded)")
	enterpriseHooksScrubCmd.Flags().BoolVar(&scrubJSONOutput, "json", false,
		"Emit machine-readable JSON summary")
	enterpriseHooksScrubCmd.Flags().BoolVar(&scrubMissingIsSilent, "quiet-missing", false,
		"Return 0 (silent) instead of 2 when the target file does not exist")
	enterpriseHooksCmd.AddCommand(enterpriseHooksScrubCmd)
}

// scrubExitError carries a specific exit code out of RunE so the harness
// preserves the numeric contract callers (uninstall.sh) rely on. cli.Execute
// looks for an `ExitCode() int` method on the error and propagates the
// returned value; anything else stays at the default rc 1.
type scrubExitError struct {
	code int
	msg  string
}

func (e *scrubExitError) Error() string { return e.msg }
func (e *scrubExitError) ExitCode() int { return e.code }

func runEnterpriseHooksScrub(cmd *cobra.Command, _ []string) error {
	connector := strings.ToLower(strings.TrimSpace(scrubConnectorFlag))
	path := strings.TrimSpace(scrubFileFlag)
	if path == "" {
		return &scrubExitError{code: 64, msg: "enterprise hooks scrub: --file is required"}
	}
	handler, ok := map[string]func(string, []string) (bool, error){
		"cursor":     scrubCursorFile,
		"claudecode": scrubClaudeCodeFile,
		"codex":      scrubCodexFile,
	}[connector]
	if !ok {
		return &scrubExitError{code: 3, msg: fmt.Sprintf("enterprise hooks scrub: unsupported connector: %q", scrubConnectorFlag)}
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			if scrubMissingIsSilent {
				return nil
			}
			return &scrubExitError{code: 2, msg: fmt.Sprintf("enterprise hooks scrub: file missing: %s", path)}
		}
		return &scrubExitError{code: 4, msg: fmt.Sprintf("enterprise hooks scrub: stat %s: %v", path, err)}
	}
	markers := append([]string{}, scrubDefaultMarkers...)
	if extra := strings.TrimSpace(scrubDataDirMarker); extra != "" {
		markers = append([]string{extra}, markers...)
	}
	changed, err := handler(path, markers)
	if err != nil {
		return &scrubExitError{code: 4, msg: fmt.Sprintf("enterprise hooks scrub: %s: %v", path, err)}
	}
	if scrubJSONOutput {
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
			"ok":        true,
			"connector": connector,
			"file":      path,
			"changed":   changed,
		})
	}
	return nil
}

// containsAnyMarker reports whether haystack contains any marker.
func containsAnyMarker(haystack string, markers []string) bool {
	for _, m := range markers {
		if m != "" && strings.Contains(haystack, m) {
			return true
		}
	}
	return false
}

// looksOwned mirrors the Python `looks_owned` recursion: any string
// anywhere inside the value that contains a marker flags the value.
func looksOwned(v any, markers []string) bool {
	switch val := v.(type) {
	case string:
		return containsAnyMarker(val, markers)
	case []any:
		for _, item := range val {
			if looksOwned(item, markers) {
				return true
			}
		}
	case map[string]any:
		for _, item := range val {
			if looksOwned(item, markers) {
				return true
			}
		}
	}
	return false
}

// ---- Cursor JSON (~/.cursor/hooks.json) --------------------------------

func scrubCursorFile(path string, markers []string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false, fmt.Errorf("parse JSON: %w", err)
	}
	hooks, _ := cfg["hooks"].(map[string]any)
	if hooks != nil {
		for event, raw := range hooks {
			entries, ok := raw.([]any)
			if !ok {
				continue
			}
			kept := make([]any, 0, len(entries))
			for _, entry := range entries {
				if !looksOwned(entry, markers) {
					kept = append(kept, entry)
				}
			}
			if len(kept) == 0 {
				delete(hooks, event)
			} else {
				hooks[event] = kept
			}
		}
	}
	return writeSortedJSON(path, cfg, data)
}

// ---- Claude Code JSON (~/.claude/settings.json) ------------------------

func scrubClaudeCodeFile(path string, markers []string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false, fmt.Errorf("parse JSON: %w", err)
	}
	hooks, _ := cfg["hooks"].(map[string]any)
	if hooks != nil {
		for event, raw := range hooks {
			groups, ok := raw.([]any)
			if !ok {
				continue
			}
			keptGroups := make([]any, 0, len(groups))
			for _, g := range groups {
				gm, isMap := g.(map[string]any)
				if !isMap {
					keptGroups = append(keptGroups, g)
					continue
				}
				inner, hasInner := gm["hooks"].([]any)
				if !hasInner {
					if !looksOwned(gm, markers) {
						keptGroups = append(keptGroups, gm)
					}
					continue
				}
				keptInner := make([]any, 0, len(inner))
				for _, h := range inner {
					if !looksOwned(h, markers) {
						keptInner = append(keptInner, h)
					}
				}
				if len(keptInner) > 0 {
					gm["hooks"] = keptInner
					keptGroups = append(keptGroups, gm)
				}
			}
			if len(keptGroups) == 0 {
				delete(hooks, event)
			} else {
				hooks[event] = keptGroups
			}
		}
	}
	if env, ok := cfg["env"].(map[string]any); ok {
		for key, val := range env {
			if _, managed := claudeManagedEnvKeys[key]; managed {
				delete(env, key)
				continue
			}
			if looksOwned(val, markers) {
				delete(env, key)
			}
		}
		if len(env) == 0 {
			delete(cfg, "env")
		}
	}
	return writeSortedJSON(path, cfg, data)
}

// writeSortedJSON re-serialises cfg with a stable key order (matching
// json.dumps(sort_keys=True) from the Python variant) and writes it to
// path, returning changed=true iff the file bytes actually moved.
func writeSortedJSON(path string, cfg any, original []byte) (bool, error) {
	buf, err := marshalSortedIndent(cfg, "  ")
	if err != nil {
		return false, err
	}
	buf = append(buf, '\n')
	if bytes.Equal(buf, original) {
		return false, nil
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// marshalSortedIndent is a Go equivalent of json.dumps(sort_keys=True,
// indent=2). encoding/json already sorts map keys but doesn't offer a
// custom recursion hook, so we drop into a small manual encoder that
// walks the decoded structure. Numbers arriving from json.Unmarshal are
// float64 or json.Number depending on the decoder; we don't use
// UseNumber() here, so plain float64/string/bool/nil are enough.
func marshalSortedIndent(v any, indent string) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeSortedJSONValue(&buf, v, "", indent); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeSortedJSONValue(buf *bytes.Buffer, v any, prefix, indent string) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		encoded, err := json.Marshal(val)
		if err != nil {
			return err
		}
		buf.Write(encoded)
	case float64:
		encoded, err := json.Marshal(val)
		if err != nil {
			return err
		}
		buf.Write(encoded)
	case json.Number:
		buf.WriteString(val.String())
	case []any:
		if len(val) == 0 {
			buf.WriteString("[]")
			return nil
		}
		inner := prefix + indent
		buf.WriteString("[\n")
		for i, item := range val {
			buf.WriteString(inner)
			if err := writeSortedJSONValue(buf, item, inner, indent); err != nil {
				return err
			}
			if i < len(val)-1 {
				buf.WriteString(",")
			}
			buf.WriteString("\n")
		}
		buf.WriteString(prefix)
		buf.WriteString("]")
	case map[string]any:
		if len(val) == 0 {
			buf.WriteString("{}")
			return nil
		}
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		inner := prefix + indent
		buf.WriteString("{\n")
		for i, k := range keys {
			buf.WriteString(inner)
			keyBytes, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(keyBytes)
			buf.WriteString(": ")
			if err := writeSortedJSONValue(buf, val[k], inner, indent); err != nil {
				return err
			}
			if i < len(keys)-1 {
				buf.WriteString(",")
			}
			buf.WriteString("\n")
		}
		buf.WriteString(prefix)
		buf.WriteString("}")
	default:
		// Fall back to encoding/json for anything unexpected — matches
		// the Python variant's "we don't touch unknown value types"
		// behaviour by round-tripping the payload unchanged.
		encoded, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(encoded)
	}
	return nil
}

// ---- Codex TOML (~/.codex/config.toml) ---------------------------------
//
// Codex's writer marshals a Go map[string]interface{} so it produces a
// canonical TOML shape. DefenseClaw owns three top-level entries
// wholesale (see internal/gateway/connector/codex.go):
//   - [hooks] table        every value references our script path
//   - [otel] table         endpoint points at the loopback gateway
//   - notify = [...] array invokes our notify-bridge.sh
//
// We scrub these wholesale rather than parsing TOML because Codex's
// writer overwrites the three top-level keys on every install, so
// deleting them entirely matches the install contract. Anything outside
// those three keys is left alone (model preferences, project trust list,
// personality, etc.).

var (
	tomlTopLevelRE   = regexp.MustCompile(`^\[([^\[\]\.\s]+)\]\s*$`)
	tomlTableHeader  = regexp.MustCompile(`^\s*\[\[?[^\[\]]+\]\]?\s*$`)
	codexNotifyStart = regexp.MustCompile(`^\s*notify\s*=`)
)

func scrubCodexFile(path string, markers []string) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	// Preserve original line separators for round-tripping. splitLines
	// treats "\r\n" as a single logical newline but re-emits with the
	// same suffix on each line so mixed-endian files survive.
	lines := splitLines(string(raw))
	out := make([]string, 0, len(lines))
	i := 0
	n := len(lines)
	changed := false

	sectionReferencesDC := func(start int, extra []string) (bool, int) {
		combined := append([]string{}, markers...)
		combined = append(combined, extra...)
		j := start
		matched := false
		for j < n {
			line := lines[j]
			trimmed := strings.TrimSpace(line)
			if tomlTableHeader.MatchString(trimmed) {
				break
			}
			if containsAnyMarker(line, combined) {
				matched = true
			}
			j++
		}
		return matched, j
	}

	for i < n {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		if m := tomlTopLevelRE.FindStringSubmatch(trimmed); m != nil && (m[1] == "hooks" || m[1] == "otel") {
			var extra []string
			if m[1] == "otel" {
				extra = scrubCodexOtelMarkers
			}
			matched, end := sectionReferencesDC(i+1, extra)
			if matched {
				changed = true
				i = end
				// Eat one trailing blank line for tidiness.
				if i < n && strings.TrimSpace(lines[i]) == "" {
					i++
				}
				continue
			}
			out = append(out, line)
			i++
			continue
		}

		if codexNotifyStart.MatchString(line) {
			if strings.Contains(line, "]") {
				if containsAnyMarker(line, markers) {
					changed = true
					i++
					continue
				}
				out = append(out, line)
				i++
				continue
			}
			// Multi-line array — collect until the closing bracket.
			buf := []string{line}
			j := i + 1
			for j < n {
				buf = append(buf, lines[j])
				if strings.Contains(lines[j], "]") {
					break
				}
				j++
			}
			joined := strings.Join(buf, "\n")
			if containsAnyMarker(joined, markers) {
				changed = true
				i = j + 1
				continue
			}
			out = append(out, buf...)
			i = j + 1
			continue
		}

		out = append(out, line)
		i++
	}

	if !changed {
		return false, nil
	}
	joined := strings.Join(out, "")
	if err := os.WriteFile(path, []byte(joined), 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// splitLines keeps the trailing newline character on each returned line
// (Python's readlines() semantics) so joining without a separator
// reproduces the original byte stream.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	i := 0
	for i < len(s) {
		j := i
		for j < len(s) && s[j] != '\n' {
			j++
		}
		if j < len(s) {
			out = append(out, s[i:j+1])
			i = j + 1
		} else {
			out = append(out, s[i:])
			i = j
		}
	}
	return out
}
