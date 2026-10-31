// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/jsonc"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const MaxContractLockBytes = 64 << 10

// EntryDigestPrefix marks a contract lock that pins the guarded editor
// entry rather than the whole editor settings file. An editor that rewrote
// its settings (Zed on a theme change) stopped every guarded entry until
// setup ran again (GAP-0708). enterprise acp setup writes it; an older
// guard reads such a lock as a changed settings file and asks for setup.
const EntryDigestPrefix = "entry-sha256:"

// maxClientConfigBytes bounds an editor settings file the guard reads.
const maxClientConfigBytes = 4 << 20

// ManagedEntryName is the editor entry name of an agent's guarded entry.
func ManagedEntryName(agent string) string {
	if agent == "" {
		return "DefenseClaw"
	}
	return "DefenseClaw · " + strings.ToUpper(agent[:1]) + strings.ToLower(agent[1:])
}

// editorOwnedEntryKeys are the keys an editor stores in an agent entry for
// choices made in its own UI. Zed keeps the session mode, model and config
// options picked in the agent panel there and sends them to the agent over
// ACP (session/set_mode, session/set_model, session/set_config_option), where
// the guard checks them like any other request; they cannot change what the
// editor launches. Choosing "Accept Edits" stored default_mode in the guarded
// entry, and the next start refused the entry as changed (GAP-0900). The
// command, args, env and type, and every key not named here, stay pinned.
var editorOwnedEntryKeys = map[string]map[string]bool{
	"zed": {
		"default_mode": true, "default_model": true, "favorite_models": true,
		"default_config_options": true, "favorite_config_option_values": true,
	},
}

// ClientEntrySHA256 is the digest of the guarded entries in the editor
// settings file at path: the entries that start the guard with the contract
// lock at lockPath, as the editor starts them. Setup routes an adopted entry
// (its own name) or a numbered one (the reserved name is taken) through the
// guard, and those were pinned by the whole file, so a theme edit stopped
// them (GAP-0504). With no such entry, or no lockPath, it is the entry under
// agent's reserved name, as before. Each entry is its JSON with sorted keys,
// so that the editor rewriting the file around it, or reformatting it, leaves
// it unchanged; the keys the editor owns for client are left out. Several
// entries (an adopted one next to the reserved one) are pinned together, as
// one JSON object by name.
func ClientEntrySHA256(path, clientID, agentID, lockPath string) (string, error) {
	pinned, _, err := pinnedClientEntries(path, clientID, agentID, lockPath)
	if err != nil {
		return "", err
	}
	canonical, err := json.Marshal(pinned)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

// pinnedClientEntries is the value ClientEntrySHA256 digests and the names of
// the entries in it, sorted.
func pinnedClientEntries(path, clientID, agentID, lockPath string) (any, []string, error) {
	body, err := safefile.ReadRegularFileBounded(path, maxClientConfigBytes)
	if err != nil {
		return nil, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(jsonc.Strip(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")))))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, nil, err
	}
	servers, _ := document["agent_servers"].(map[string]any)
	guarded := map[string]any{}
	names := []string{}
	for name, entry := range servers {
		if lockPath != "" && entryStartsLock(entry, lockPath) {
			guarded[name] = withoutEditorOwnedKeys(clientID, entry)
			names = append(names, name)
		}
	}
	sort.Strings(names)
	switch len(guarded) {
	case 0:
		entry, ok := servers[ManagedEntryName(agentID)]
		if !ok {
			return nil, nil, fmt.Errorf("%s has no %s entry", path, ManagedEntryName(agentID))
		}
		return withoutEditorOwnedKeys(clientID, entry), []string{ManagedEntryName(agentID)}, nil
	case 1:
		return guarded[names[0]], names, nil
	default:
		return guarded, names, nil
	}
}

// pinnedEntriesLabel names the entries the contract lock pins, for a refusal:
// an adopted or numbered entry has its own name, not the reserved one
// (GAP-0043). It falls back to the reserved name when the file cannot be read.
// The second value is the pronoun for the label: it or them.
func pinnedEntriesLabel(path, clientID, agentID, lockPath string) (string, string) {
	_, names, err := pinnedClientEntries(path, clientID, agentID, lockPath)
	if err != nil || len(names) == 0 {
		return ManagedEntryName(agentID) + " entry", "it"
	}
	if len(names) == 1 {
		return names[0] + " entry", "it"
	}
	return strings.Join(names, ", ") + " entries", "them"
}

// RecordedEntrySHA256 is the digest the per-user CLI keeps in its record of
// the editor entries DefenseClaw wrote (cmd_acp._entry_digest, the
// owned-entries.json record): the entry without the keys the editor owns, as
// Python's json.dumps(sort_keys=True, separators=(",", ":"),
// ensure_ascii=False) writes it. Enterprise setup records its entry with it,
// so the CLI's verify and status know the entry is DefenseClaw's (GAP-2111).
func RecordedEntrySHA256(clientID string, entry any) (string, error) {
	var canonical strings.Builder
	if err := writePythonJSON(&canonical, withoutEditorOwnedKeys(clientID, entry)); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(digest[:]), nil
}

// writePythonJSON writes value as Python's compact, key-sorted json.dumps
// with ensure_ascii=False. Map keys sort by code point, which for UTF-8 is
// Go's byte order. Only the value kinds an editor entry holds are accepted.
func writePythonJSON(out *strings.Builder, value any) error {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(v))
	case string:
		writePythonJSONString(out, v)
	case json.Number:
		out.WriteString(v.String())
	case []string:
		items := make([]any, len(v))
		for i, item := range v {
			items[i] = item
		}
		return writePythonJSON(out, items)
	case []any:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writePythonJSON(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			writePythonJSONString(out, key)
			out.WriteByte(':')
			if err := writePythonJSON(out, v[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("an editor entry value of type %T cannot be recorded", value)
	}
	return nil
}

// writePythonJSONString escapes as Python's json encoder with
// ensure_ascii=False: the quote, the backslash, short forms for \b \f \n \r
// \t, and \u00XX for the other control characters; everything else as is.
func writePythonJSONString(out *strings.Builder, value string) {
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

// withoutEditorOwnedKeys is entry without the keys the editor owns for client.
func withoutEditorOwnedKeys(clientID string, entry any) any {
	fields, isObject := entry.(map[string]any)
	if !isObject || len(editorOwnedEntryKeys[clientID]) == 0 {
		return entry
	}
	pinned := make(map[string]any, len(fields))
	for key, value := range fields {
		if !editorOwnedEntryKeys[clientID][key] {
			pinned[key] = value
		}
	}
	return pinned
}

// entryStartsLock reports whether an editor entry starts the guard with the
// contract lock at lockPath: its guard options (flag and value pairs before
// --, each once) carry --contract-lock with that path. cmd_acp._guard_options
// reads the options the same way.
func entryStartsLock(entry any, lockPath string) bool {
	fields, _ := entry.(map[string]any)
	args, _ := fields["args"].([]any)
	end := -1
	for i, arg := range args {
		if arg == "--" {
			end = i
			break
		}
	}
	if end < 0 || end%2 != 0 {
		return false
	}
	options := make(map[string]string, end/2)
	for i := 0; i < end; i += 2 {
		flag, isFlag := args[i].(string)
		value, isValue := args[i+1].(string)
		if _, seen := options[flag]; !isFlag || !isValue || seen {
			return false
		}
		options[flag] = value
	}
	value := options["--contract-lock"]
	if value == "" {
		return false
	}
	entryLock, err := filepath.Abs(value)
	if err != nil {
		return false
	}
	guardLock, err := filepath.Abs(lockPath)
	return err == nil && samePath(entryLock, guardLock)
}

// ErrRuntimeContractMissing means the binding's contract lock file does not
// exist: the editor entry outlived `defenseclaw acp remove` (or was copied
// from another machine) and the guard must not start.
var ErrRuntimeContractMissing = errors.New("ACP runtime contract lock is missing")

type RuntimeContractLock struct {
	Version     int    `json:"version"`
	GeneratedAt string `json:"generated_at"`
	Protocol    struct {
		SchemaVersion string `json:"schema_version"`
		SchemaSHA256  string `json:"schema_sha256"`
	} `json:"protocol"`
	Client struct {
		ID           string `json:"id"`
		ConfigPath   string `json:"config_path"`
		ConfigSHA256 string `json:"config_sha256"`
	} `json:"client"`
	Agent struct {
		ID      string `json:"id"`
		Path    string `json:"path"`
		SHA256  string `json:"sha256"`
		Version string `json:"version"`
	} `json:"agent"`
	Guard struct {
		Path           string `json:"path"`
		SHA256         string `json:"sha256"`
		ManagedCustody bool   `json:"managed_custody,omitempty"`
	} `json:"guard"`
	Profile string `json:"profile"`
	Mode    string `json:"mode"`
}

// ValidateRuntimeContract fails closed when the setup-selected guard or agent
// executable has moved or changed since the editor binding was published.
func ValidateRuntimeContract(path, clientID, agentID, profile string, mode Mode, command string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ErrRuntimeContractMissing
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxContractLockBytes {
		return errors.New("ACP runtime contract lock is unavailable or unsafe")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("ACP runtime contract lock permissions are too broad")
	}
	if err := safefile.ValidatePrivateFile(path); err != nil {
		return errors.New("ACP runtime contract lock protection is unsafe")
	}
	body, err := safefile.ReadRegularFileBounded(path, MaxContractLockBytes)
	if err != nil {
		return fmt.Errorf("read ACP runtime contract lock: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var lock RuntimeContractLock
	if err := decoder.Decode(&lock); err != nil {
		return errors.New("ACP runtime contract lock is malformed")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("ACP runtime contract lock has trailing content")
	}
	if lock.Version != 1 || lock.Protocol.SchemaVersion != SchemaVersion || lock.Protocol.SchemaSHA256 != SchemaSHA256 ||
		lock.Client.ID != clientID || lock.Agent.ID != agentID || lock.Profile != profile || lock.Mode != string(mode) {
		return errors.New("ACP runtime contract metadata does not match the guarded binding")
	}
	agentPath, err := lock.agentExecutablePath(command)
	if err != nil {
		return err
	}
	guardPath, err := os.Executable()
	if err != nil {
		return errors.New("resolve ACP guard executable")
	}
	if err := lock.guardExecutablePathMatches(guardPath); err != nil {
		return err
	}
	clientConfigPath, err := filepath.Abs(lock.Client.ConfigPath)
	if err != nil || strings.TrimSpace(lock.Client.ConfigSHA256) == "" {
		return errors.New("ACP client configuration identity is missing from the runtime contract")
	}
	if pinned, entry := strings.CutPrefix(lock.Client.ConfigSHA256, EntryDigestPrefix); entry && !secureClientHost() {
		observed, digestErr := ClientEntrySHA256(clientConfigPath, clientID, agentID, path)
		if digestErr != nil || !strings.EqualFold(observed, pinned) {
			label, pronoun := pinnedEntriesLabel(clientConfigPath, clientID, agentID, path)
			subject := "it"
			if pronoun == "them" {
				subject = "they"
			}
			return fmt.Errorf("the %s in the editor settings file %s changed after setup (the contract lock pins %s), "+
				"so %s must be set up again", label, clientConfigPath, pronoun, subject)
		}
	} else if observed, digestErr := fileSHA256(clientConfigPath); digestErr != nil || !strings.EqualFold(observed, lock.Client.ConfigSHA256) {
		if !secureClientHost() {
			// The lock pins the whole settings file, and "executable
			// digest" sent users looking for a changed binary (GAP-0391).
			return fmt.Errorf("the editor settings file %s changed after setup (the contract lock pins its digest, "+
				"so any edit needs setup again)", clientConfigPath)
		}
		return errors.New("ACP client configuration executable digest does not match the runtime contract")
	}
	return lock.executableDigestsMatch(agentPath, guardPath)
}

// LockedExecutablesMatch checks the agent command an editor entry starts and
// the guard at guardPath against the executables the contract lock pins, by
// the rule the guard applies at start (ValidateRuntimeContract): the same
// paths and digests, with the managed guard's custody exception. enterprise
// acp verify and list said setup was done while the guard refused to start
// because the agent executable it pins had changed (GAP-1156).
func LockedExecutablesMatch(lock RuntimeContractLock, command, guardPath string) error {
	agentPath, err := lock.agentExecutablePath(command)
	if err != nil {
		return err
	}
	guardPath, err = filepath.Abs(guardPath)
	if err != nil {
		return errors.New("resolve ACP guard executable")
	}
	if err := lock.guardExecutablePathMatches(guardPath); err != nil {
		return err
	}
	return lock.executableDigestsMatch(agentPath, guardPath)
}

// EntryAgentCommand is the agent command the guard starts for an editor
// entry with args: the first argument after "--", or the catalog command of
// agentID when the entry names none, as defenseclaw-acp reads its command
// line.
func EntryAgentCommand(args []any, agentID string) string {
	for i, arg := range args {
		if arg != "--" {
			continue
		}
		if i+1 < len(args) {
			command, _ := args[i+1].(string)
			return command
		}
		break
	}
	agent, err := LookupAgent(agentID)
	if err != nil {
		return ""
	}
	return agent.Command
}

// agentExecutablePath is the absolute path of command, the agent the guard
// starts, which must be the one the lock pins.
func (lock RuntimeContractLock) agentExecutablePath(command string) (string, error) {
	agentPath, err := filepath.Abs(command)
	if err != nil {
		return "", errors.New("resolve ACP agent executable")
	}
	lockedAgentPath, err := filepath.Abs(lock.Agent.Path)
	if err != nil || !samePath(agentPath, lockedAgentPath) {
		return "", errors.New("ACP agent executable path does not match the runtime contract")
	}
	return agentPath, nil
}

// guardExecutablePathMatches checks that guardPath is the guard the lock pins.
func (lock RuntimeContractLock) guardExecutablePathMatches(guardPath string) error {
	lockedGuardPath, err := filepath.Abs(lock.Guard.Path)
	if err != nil || !samePath(guardPath, lockedGuardPath) {
		return errors.New("ACP guard executable path does not match the runtime contract")
	}
	return nil
}

// executableDigestsMatch checks the agent and guard executables against the
// digests the lock pins.
func (lock RuntimeContractLock) executableDigestsMatch(agentPath, guardPath string) error {
	if observed, err := fileSHA256(agentPath); err != nil || !strings.EqualFold(observed, lock.Agent.SHA256) {
		return errors.New("ACP agent executable digest does not match the runtime contract")
	}
	observedGuardDigest, err := fileSHA256(guardPath)
	if err != nil || !strings.EqualFold(observedGuardDigest, lock.Guard.SHA256) {
		// Managed deployments bind the guard to an administrator-controlled
		// path rather than bytes that necessarily change on every signed
		// enterprise upgrade. This exception is valid only while the complete
		// path still passes the platform root/Admin ownership and no-untrusted-
		// writer contract. User-owned guards always retain exact digest pinning.
		if !lock.Guard.ManagedCustody || managed.ValidateTrustedFilePath(guardPath, "managed ACP guard") != nil {
			return errors.New("ACP guard executable digest does not match the runtime contract")
		}
	}
	return nil
}

// ClientConfigMatchesLock reports whether the editor settings file still
// matches what the contract lock at lockPath pins, by the rule the guard
// applies at start (ValidateRuntimeContract): the guarded entries for an
// entry-pinned lock, the whole file otherwise. enterprise acp list and verify
// said setup was done while the guard refused the entry because the agent it
// starts had been changed in the entry (GAP-1154).
func ClientConfigMatchesLock(lock RuntimeContractLock, lockPath, clientID, agentID string) bool {
	path, err := filepath.Abs(lock.Client.ConfigPath)
	if err != nil || strings.TrimSpace(lock.Client.ConfigSHA256) == "" {
		return false
	}
	if pinned, entry := strings.CutPrefix(lock.Client.ConfigSHA256, EntryDigestPrefix); entry && !secureClientHost() {
		observed, digestErr := ClientEntrySHA256(path, clientID, agentID, lockPath)
		return digestErr == nil && strings.EqualFold(observed, pinned)
	}
	observed, digestErr := fileSHA256(path)
	return digestErr == nil && strings.EqualFold(observed, lock.Client.ConfigSHA256)
}

// SecureClientHost reports a Secure Client install, whose guard keeps the
// behaviour of main (issue #1092).
func SecureClientHost() bool { return secureClientHost() }

func samePath(left, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

func fileSHA256(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("executable is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
