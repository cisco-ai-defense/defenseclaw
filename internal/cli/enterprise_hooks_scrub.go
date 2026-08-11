// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
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

// Additional markers that identify a Codex [otel] block as
// DefenseClaw-managed when the block body itself doesn't carry a hook
// script path.
//
// DefenseClaw configures Codex to send OTLP to a loopback DefenseClaw
// gateway with headers that name the connector explicitly
// (`x-defenseclaw-source`, `x-defenseclaw-client`,
// `x-defenseclaw-token`) — see internal/gateway/connector/codex.go
// HookProfile. Keying on those header names is unambiguous and does
// not false-positive against a developer's own local OTel collector
// running at http://localhost:4318 with no DefenseClaw involvement.
//
// The prior list included "127.0.0.1" and "localhost", which would
// wipe any local-collector [otel] block on uninstall. Endpoint-
// software users who run their own OTel stack (a common shape on
// developer laptops) would have silently lost that config with
// no error surface. Restricting the markers to DC-owned header
// substrings closes that hole.
var scrubCodexOtelMarkers = []string{
	"x-defenseclaw-source",
	"x-defenseclaw-client",
	"x-defenseclaw-token",
	"defenseclaw-managed-hook",
	"defenseclaw",
}

// claudeManagedEnvKeys enumerates the env-var keys DefenseClaw's Claude Code
// connector writes into ~/.claude/settings.json. Kept in sync with
// claudeCodeOtelEnvKeys in internal/gateway/connector/claudecode.go.
var claudeManagedEnvKeys = map[string]struct{}{
	"CLAUDE_CODE_ENABLE_TELEMETRY":        {},
	"DEFENSECLAW_FAIL_MODE":               {},
	"OTEL_METRICS_EXPORTER":               {},
	"OTEL_LOGS_EXPORTER":                  {},
	"OTEL_TRACES_EXPORTER":                {},
	"OTEL_EXPORTER_OTLP_PROTOCOL":         {},
	"OTEL_EXPORTER_OTLP_ENDPOINT":         {},
	"OTEL_EXPORTER_OTLP_HEADERS":          {},
	"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL": {},
	"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": {},
	"OTEL_EXPORTER_OTLP_METRICS_HEADERS":  {},
	"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL":    {},
	"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":    {},
	"OTEL_EXPORTER_OTLP_LOGS_HEADERS":     {},
	"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL":  {},
	"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":  {},
	"OTEL_EXPORTER_OTLP_TRACES_HEADERS":   {},
	"OTEL_LOG_USER_PROMPTS":               {},
	"OTEL_RESOURCE_ATTRIBUTES":            {},
	"OTEL_SERVICE_NAME":                   {},
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
	// Both flags are required. Marking them here lets Cobra emit its
	// standard "required flag(s) --file, --connector not set" usage
	// error BEFORE RunE runs, so shell callers see a documented
	// non-zero exit rather than the ad-hoc rc 64 the RunE fallback
	// used to return. Errors marking flags required are fatal at init
	// time, not per-call, so a panic here is a build bug — not a
	// runtime failure — and matches the pattern the rest of the CLI
	// uses for required flags.
	if err := enterpriseHooksScrubCmd.MarkFlagRequired("connector"); err != nil {
		panic("enterprise hooks scrub: MarkFlagRequired connector: " + err.Error())
	}
	if err := enterpriseHooksScrubCmd.MarkFlagRequired("file"); err != nil {
		panic("enterprise hooks scrub: MarkFlagRequired file: " + err.Error())
	}
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
	// --connector and --file are MarkFlagRequired in init(); Cobra
	// rejects the invocation with its standard usage error before
	// RunE gets called. Belt-and-suspenders: if a caller bypasses
	// Cobra (test harness, future refactor) we still guard here.
	if path == "" {
		return &scrubExitError{code: 3, msg: "enterprise hooks scrub: --file is required"}
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
	if err := writeConfigAtomic(path, buf); err != nil {
		return false, err
	}
	return true, nil
}

// writeConfigAtomic writes payload to path via a same-directory temp
// file + rename, so an interrupted scrub can never leave a truncated
// user config. Preserves the target file's existing mode (0644 vs 0600
// vary across agents) and — when running as root under `sudo` — the
// existing owner uid/gid too, matching the "scrub only edits, never
// re-perms" contract the uninstaller documents.
//
// Symlink handling: dotfiles workflows (chezmoi, GNU stow, homeshick,
// vcsh, ...) routinely publish agent configs as symlinks pointing
// into ~/.dotfiles/… . Refusing to scrub through a symlink would fail
// uninstall on those setups; renaming a fresh file over the symlink
// would replace the symlink with a regular file and break the
// dotfiles indirection. The right move is to resolve the symlink and
// write to the concrete target file, so the user's dotfiles link
// survives and the scrub still lands on the file the agent actually
// reads.
//
// A symlink-swap privesc surface exists only when the writer runs at
// a HIGHER privilege than the entity that controls the link target
// path. This scrubber runs via `sudo -u <target-user>` in
// uninstall.sh, so the effective uid at write time is the target
// user's — a symlink they control can only redirect the write to a
// path they could already write to themselves. The check that
// remains is: no writing through symlinks whose eventual target is
// outside the caller's uid boundary, which the kernel enforces via
// the standard file-permissions gate.
//
// Falls back to 0600 mode when the target did not exist (dead code
// on the scrub path — callers Stat first — but robust if this helper
// is reused).
func writeConfigAtomic(path string, payload []byte) error {
	// Resolve chained symlinks so a chezmoi-style dotfiles setup
	// (~/.cursor/hooks.json -> ~/.dotfiles/cursor/hooks.json ->
	// ~/dev/dotfiles/cursor/hooks.json) has the scrub land on the
	// concrete target file rather than clobber the link.
	//
	// Bounded loop (maxSymlinkHops = 16) guards against symlink
	// cycles — a user with a self-referential link would otherwise
	// spin forever. 16 matches the Linux kernel's default
	// MAXSYMLINKS and is generous enough for any legitimate dotfiles
	// chain. On a cycle detection or readlink/stat error we fall
	// back to the last resolvable path, and the downstream Rename
	// will report a concrete errno the operator can act on.
	//
	// Deliberately NOT using filepath.EvalSymlinks: it fails if any
	// intermediate component does not exist, so a chain whose final
	// resolved target's parent directory is temporarily missing
	// (rare, but possible during a chezmoi apply in-flight) would
	// abort the scrub. Manual per-hop resolution degrades gracefully.
	resolved := path
	const maxSymlinkHops = 16
	for hop := 0; hop < maxSymlinkHops; hop++ {
		lstat, err := os.Lstat(resolved)
		if err != nil || lstat.Mode()&os.ModeSymlink == 0 {
			break
		}
		target, err := os.Readlink(resolved)
		if err != nil {
			break
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(resolved), target)
		}
		resolved = target
	}
	var (
		mode     os.FileMode = 0o600
		uid, gid             = -1, -1
	)
	if st, err := os.Stat(resolved); err == nil {
		mode = st.Mode().Perm()
		uid, gid = fileOwner(st)
	}
	dir := filepath.Dir(resolved)
	tmp, err := os.CreateTemp(dir, ".scrub-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup: after a successful rename Remove() is a no-op;
	// on any error before the rename it wipes the temp so nothing dangles.
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if uid >= 0 && gid >= 0 {
		// Failure here is not fatal: on unprivileged scrubs Chown will
		// EPERM against a foreign uid, and we'd rather keep the caller's
		// uid on the swapped-in file than abort. On a root uninstall
		// (the primary caller) it succeeds and preserves the user's
		// ownership across the atomic swap.
		_ = os.Chown(tmpName, uid, gid)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, resolved); err != nil {
		return fmt.Errorf("rename temp -> target: %w", err)
	}
	// Best-effort parent fsync so the rename survives a crash immediately
	// after this call returns. Endpoint-shipping constraint: laptop lids
	// close, kernel panics happen, the swap must be durable.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
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

// writeSortedJSONValue emits `v` in the exact byte shape Python
// `json.dumps(sort_keys=True, indent=2)` would produce, so that a
// scrub over a file the Python variant previously wrote is idempotent
// (no `bytes.Equal(buf, original)` mismatch). Two Go-specific defaults
// we deliberately override:
//
//   - json.Marshal HTML-escapes `<`, `>`, `&` to `<` / `>` /
//     `&`. Python's json.dumps does not. A settings.json emitted
//     by the old Python scrubber that contains URL query strings, HTML
//     snippets in env values, or ampersands in labels would otherwise
//     always fail the equality check and force a rewrite (mtime bump,
//     file watchers wake, and a doc claim would silently drift).
//   - json.Marshal's default `<` / `>` / `&` treatment is meant for
//     `<script>` embedding, which does not apply here.
//
// The equivalent to Python's ensure_ascii=False (letting non-ASCII
// bytes through un-\uXXXX-encoded) is emitting the raw UTF-8. Python
// defaults to ensure_ascii=True (escapes), which matches Go's
// json.Marshal behaviour for non-ASCII bytes, so no adjustment is
// needed there.
func writeSortedJSONValue(buf *bytes.Buffer, v any, prefix, indent string) error {
	// jsonNoHTMLEscape marshals a value with SetEscapeHTML(false) so
	// `<`, `>`, `&` survive verbatim.
	jsonNoHTMLEscape := func(x any) ([]byte, error) {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(x); err != nil {
			return nil, err
		}
		out := b.Bytes()
		// enc.Encode appends a trailing newline; strip it so the
		// caller controls line separators.
		if len(out) > 0 && out[len(out)-1] == '\n' {
			out = out[:len(out)-1]
		}
		return out, nil
	}
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
		encoded, err := jsonNoHTMLEscape(val)
		if err != nil {
			return err
		}
		buf.Write(encoded)
	case float64:
		encoded, err := jsonNoHTMLEscape(val)
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
			keyBytes, err := jsonNoHTMLEscape(k)
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
		// Fall back to encoding/json (with HTML escaping disabled so
		// the round-trip stays byte-idempotent with Python's json.dumps
		// output) for anything unexpected — matches the Python variant's
		// "we do not touch unknown value types" behaviour.
		encoded, err := jsonNoHTMLEscape(v)
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
	// tomlOtelSectionRE matches every table header rooted at the `otel`
	// key: bare `[otel]`, dotted `[otel.exporter]`,
	// `[otel.exporter.otlp-http]`, `[otel.exporter.otlp-http.headers]`,
	// `[otel.trace_exporter.otlp-http.headers]`, etc. The Codex TOML
	// marshaller emits the DC config across multiple sub-tables and
	// the DC-identifying `x-defenseclaw-*` header keys land in the
	// leaf table, not in the bare `[otel]` section, so a scrubber
	// that stops at the first sub-table would miss them. This regex
	// lets the section-scan walk every `otel.*` subsection as one
	// logical block.
	tomlOtelSectionRE = regexp.MustCompile(`^\s*\[otel(?:\.[^\[\]]+)?\]\s*$`)
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
	// inTopLevel tracks whether the scanner is still before the first
	// table header. The `notify` array is a DefenseClaw-owned top-level
	// key ONLY when it appears above every `[section]` line — inside a
	// user-owned table (say [projects."/x"] with its own `notify =` for
	// per-project alerting), TOML scopes the key to that table and a
	// blanket scrub would delete user state. Flag flips false on the
	// first table header we see and stays false for the rest of the
	// file. The `[hooks]` / `[otel]` branch consumes its own section, so
	// the section-scoped headers there never reach the flip point.
	inTopLevel := true

	// sectionReferencesDC walks forward from `start` (the line right
	// after a `[section]` header) until either (a) EOF, or (b) a
	// table header that fails `stayInSection` is seen. Returns
	// (matched, end) where `end` is the line index of the first line
	// NOT consumed. Any line whose text contains a `combined`
	// marker sets matched=true. `combined = markers + extra`.
	//
	// `stayInSection` decides whether an intervening table header
	// keeps the scan going (for the `[otel]` hierarchy where the
	// DC-identifying content lives under a nested sub-table, so the
	// scan must span sub-tables to see the markers) or terminates
	// the scan (for `[hooks]` where all DC content lives inline).
	sectionReferencesDC := func(start int, extra []string, stayInSection func(hdr string) bool) (bool, int) {
		combined := append([]string{}, markers...)
		combined = append(combined, extra...)
		j := start
		matched := false
		for j < n {
			line := lines[j]
			trimmed := strings.TrimSpace(line)
			if tomlTableHeader.MatchString(trimmed) {
				if stayInSection == nil || !stayInSection(trimmed) {
					break
				}
			}
			if containsAnyMarker(line, combined) {
				matched = true
			}
			j++
		}
		return matched, j
	}

	// stayInOtelHierarchy accepts any `[otel]` or `[otel.<subpath>]`
	// header so the section-scan spans the whole DC-emitted OTel
	// TOML shape:
	//
	//   [otel]
	//   log_user_prompt = false
	//   [otel.exporter.otlp-http]
	//   endpoint = "http://127.0.0.1:18970/v1/logs"
	//   [otel.exporter.otlp-http.headers]
	//   x-defenseclaw-token = "..."   <-- DC-identifying marker lives here
	//
	// A scan that stopped at the first sub-table header would never
	// reach the identifying header substrings and mis-classify the
	// block as user-owned.
	stayInOtelHierarchy := func(hdr string) bool {
		return tomlOtelSectionRE.MatchString(hdr)
	}

	for i < n {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		if m := tomlTopLevelRE.FindStringSubmatch(trimmed); m != nil && (m[1] == "hooks" || m[1] == "otel") {
			var extra []string
			var stayIn func(string) bool
			if m[1] == "otel" {
				extra = scrubCodexOtelMarkers
				stayIn = stayInOtelHierarchy
			}
			matched, end := sectionReferencesDC(i+1, extra, stayIn)
			if matched {
				changed = true
				i = end
				// Eat one trailing blank line for tidiness.
				if i < n && strings.TrimSpace(lines[i]) == "" {
					i++
				}
				continue
			}
			// Kept user's [hooks] or [otel] block: we are now inside a
			// user table, so a later `notify = …` no longer refers to
			// the top-level DC-owned notify array. Same policy as any
			// other table header below.
			inTopLevel = false
			out = append(out, line)
			i++
			continue
		}

		// Any non-DC-owned table header ends the top-level region for
		// the rest of the file. Uses the broader tomlTableHeader regex
		// so simple `[foo]`, dotted `[projects."x"]`, and array-of-tables
		// `[[some.array]]` all count.
		if tomlTableHeader.MatchString(trimmed) {
			inTopLevel = false
		}

		if inTopLevel && codexNotifyStart.MatchString(line) {
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
	// Round-trip sanity check: the line scanner deliberately walks a
	// surface subset of TOML (top-level [hooks]/[otel] tables + the
	// pre-table `notify = [...]` array) and cannot guarantee the
	// output is well-formed for every possible input shape. Endpoint
	// software: shipping a broken config.toml would brick Codex on
	// the user's next launch, which is worse than leaving DC entries
	// behind and letting the guardian re-repair. Parse the post-scrub
	// bytes and, if TOML rejects them, refuse the write with a
	// distinct error so the uninstall path falls through to the
	// "one or more agent-config scrubs failed" die() at
	// packaging/macos/uninstall.sh — the operator sees a clear
	// diagnostic and the file stays intact for hand-editing.
	//
	// A nested TOML validation would need a full parser; go-toml is
	// already imported by other parts of the tree, so the cost of
	// this guard is one Unmarshal call per successful scrub.
	var parsed map[string]any
	if err := toml.Unmarshal([]byte(joined), &parsed); err != nil {
		return false, fmt.Errorf("post-scrub TOML would not re-parse (%s left unchanged): %w", path, err)
	}
	if err := writeConfigAtomic(path, []byte(joined)); err != nil {
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
