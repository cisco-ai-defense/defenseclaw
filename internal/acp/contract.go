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

// ClientEntrySHA256 is the digest of agent's guarded entry in the editor
// settings file at path: its JSON with sorted keys, so that the editor
// rewriting the file around it, or reformatting it, leaves it unchanged. The
// keys the editor owns for client are left out.
func ClientEntrySHA256(path, clientID, agentID string) (string, error) {
	body, err := safefile.ReadRegularFileBounded(path, maxClientConfigBytes)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(jsonc.Strip(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")))))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return "", err
	}
	servers, _ := document["agent_servers"].(map[string]any)
	entry, ok := servers[ManagedEntryName(agentID)]
	if !ok {
		return "", fmt.Errorf("%s has no %s entry", path, ManagedEntryName(agentID))
	}
	if fields, isObject := entry.(map[string]any); isObject && len(editorOwnedEntryKeys[clientID]) > 0 {
		pinned := make(map[string]any, len(fields))
		for key, value := range fields {
			if !editorOwnedEntryKeys[clientID][key] {
				pinned[key] = value
			}
		}
		entry = pinned
	}
	canonical, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
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
	agentPath, err := filepath.Abs(command)
	if err != nil {
		return errors.New("resolve ACP agent executable")
	}
	lockedAgentPath, err := filepath.Abs(lock.Agent.Path)
	if err != nil || !samePath(agentPath, lockedAgentPath) {
		return errors.New("ACP agent executable path does not match the runtime contract")
	}
	guardPath, err := os.Executable()
	if err != nil {
		return errors.New("resolve ACP guard executable")
	}
	lockedGuardPath, err := filepath.Abs(lock.Guard.Path)
	if err != nil || !samePath(guardPath, lockedGuardPath) {
		return errors.New("ACP guard executable path does not match the runtime contract")
	}
	clientConfigPath, err := filepath.Abs(lock.Client.ConfigPath)
	if err != nil || strings.TrimSpace(lock.Client.ConfigSHA256) == "" {
		return errors.New("ACP client configuration identity is missing from the runtime contract")
	}
	for _, item := range []struct{ path, expected, label string }{
		{clientConfigPath, lock.Client.ConfigSHA256, "client configuration"},
		{agentPath, lock.Agent.SHA256, "agent"},
	} {
		if pinned, entry := strings.CutPrefix(item.expected, EntryDigestPrefix); entry && item.label == "client configuration" && !secureClientHost() {
			observed, digestErr := ClientEntrySHA256(item.path, clientID, agentID)
			if digestErr != nil || !strings.EqualFold(observed, pinned) {
				return fmt.Errorf("the %s entry in the editor settings file %s changed after setup (the contract lock pins it), "+
					"so it must be set up again", ManagedEntryName(agentID), clientConfigPath)
			}
			continue
		}
		observed, digestErr := fileSHA256(item.path)
		if digestErr != nil || !strings.EqualFold(observed, item.expected) {
			if item.label == "client configuration" && !secureClientHost() {
				// The lock pins the whole settings file, and "executable
				// digest" sent users looking for a changed binary (GAP-0391).
				return fmt.Errorf("the editor settings file %s changed after setup (the contract lock pins its digest, "+
					"so any edit needs setup again)", clientConfigPath)
			}
			return fmt.Errorf("ACP %s executable digest does not match the runtime contract", item.label)
		}
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
