// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package idfabric

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// SpoolDirName is the leaf directory holding records that would have been sent
// to AI Defense.
const SpoolDirName = "aid-spool"

// SpoolDirEnv overrides the spool location for testing.
const SpoolDirEnv = "DEFENSECLAW_IDFABRIC_SPOOL_DIR"

// maxSpoolFiles bounds the spool so a long-running agent session cannot fill
// the disk. Once reached, writes stop rather than evicting evidence, because
// silently discarding the oldest record would misrepresent the capture.
const maxSpoolFiles = 5000

// spoolTimestampLayout is sortable and filename-safe in UTC.
const spoolTimestampLayout = "20060102T150405.000Z"

// ErrSpoolFull reports that the spool has reached maxSpoolFiles.
var ErrSpoolFull = errors.New("idfabric: spool directory is full")

// Spool writes Astrix records to disk in place of the AI Defense ingest
// endpoint, which does not exist yet.
type Spool struct {
	dir string
}

// SpoolDir resolves the directory records are written to.
//
// The spool lives in the invoking user's own state directory rather than under
// the DefenseClaw home, for two reasons.
//
// It has to. In managed enterprise mode the home is the machine state root,
// whose DACL grants SYSTEM, Administrators, and the gateway service account
// only - nothing to Users, with inheritance protected. A hook running as the
// interactive user cannot create a directory there, so resolving the spool
// from the home made capture fail in precisely the mode it is gated to.
//
// It also belongs there. These are per-user records produced by a user-context
// process, and each user's spool is independently collectable per profile.
//
// The tradeoff is that a user can delete their own pending records. That is
// acceptable for a pre-ingest staging buffer that disappears once AI Defense
// ingest exists and the hook forwards directly; tamper-evident retention is
// the audit store's responsibility, not this sink's.
func SpoolDir() (string, error) {
	if override := strings.TrimSpace(os.Getenv(SpoolDirEnv)); override != "" {
		return override, nil
	}
	root, err := userStateRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, SpoolDirName), nil
}

// userStateRoot reports the per-user DefenseClaw state directory, following
// each platform's own convention.
//
// It deliberately avoids ~/.defenseclaw. That path is the unmanaged home, and
// the Unix hook scripts read its existence as "an unmanaged install is
// present" - creating it on a managed endpoint, where it is otherwise absent,
// would change how a stray unmanaged hook behaves.
func userStateRoot() (string, error) {
	switch runtime.GOOS {
	case "windows":
		if dir := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); dir != "" {
			return filepath.Join(dir, "DefenseClaw"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "AppData", "Local", "DefenseClaw"), nil
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", "DefenseClaw"), nil
	default:
		if dir := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); dir != "" {
			return filepath.Join(dir, "DefenseClaw"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".local", "state", "DefenseClaw"), nil
	}
}

// NewSpool resolves the spool directory and creates it with owner-only access.
func NewSpool() (*Spool, error) {
	dir, err := SpoolDir()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("idfabric: spool directory is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// Owner-only on POSIX; owner + SYSTEM + Administrators DACL on Windows.
	// The directory is inside the user's own profile, so this sole-owner
	// contract is satisfiable here in a way it never was under the
	// Administrators-owned managed state root.
	if err := safefile.ProtectDirectory(dir); err != nil {
		return nil, err
	}
	return &Spool{dir: dir}, nil
}

// Dir reports the resolved spool directory.
func (s *Spool) Dir() string {
	if s == nil {
		return ""
	}
	return s.dir
}

// Source names the origin of a spooled record, which becomes part of the
// filename so a reviewer can tell what produced it without opening it.
type Source struct {
	// Model is the Astrix model carried by the record.
	Model SchemaModel
	// Connector is the agent platform, e.g. "codex".
	Connector string
	// Event is the hook event, e.g. "session_start". Inventory records use a
	// synthetic label.
	Event string
}

// Write serializes a record and writes it under a filename derived from its
// source and the given time.
//
// The record is written with mode 0600 through an atomic replace, so a
// reviewer never observes a partial JSON document.
func (s *Spool) Write(source Source, at time.Time, record any) (string, error) {
	if s == nil {
		return "", errors.New("idfabric: nil spool")
	}
	full, err := s.atCapacity()
	if err != nil {
		return "", err
	}
	if full {
		return "", ErrSpoolFull
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')

	name, err := spoolFileName(source, at)
	if err != nil {
		return "", err
	}
	path := filepath.Join(s.dir, name)
	if err := safefile.WritePrivate(path, data); err != nil {
		return "", err
	}
	return path, nil
}

// atCapacity reports whether the spool already holds maxSpoolFiles entries.
// It stops reading directory names as soon as the limit is exceeded.
func (s *Spool) atCapacity() (bool, error) {
	handle, err := os.Open(s.dir)
	if err != nil {
		return false, err
	}
	defer handle.Close()
	names, err := handle.Readdirnames(maxSpoolFiles + 1)
	if err != nil && !errors.Is(err, os.ErrClosed) && len(names) == 0 {
		// io.EOF on an empty directory is expected and not a failure.
		if !isEOF(err) {
			return false, err
		}
	}
	return len(names) > maxSpoolFiles, nil
}

func isEOF(err error) bool {
	return err != nil && err.Error() == "EOF"
}

// spoolFileName builds "<model>-<connector>-<event>-<timestamp>-<nonce>.json".
//
// Every component is sanitized: the connector and event names originate in
// agent-controlled hook JSON, so an unsanitized event could otherwise contain
// path separators or traversal sequences and place the file outside the spool.
func spoolFileName(source Source, at time.Time) (string, error) {
	model := sanitizeFileComponent(shortModel(source.Model))
	connector := sanitizeFileComponent(source.Connector)
	event := sanitizeFileComponent(source.Event)
	if model == "" {
		model = "record"
	}
	if connector == "" {
		connector = "unknown"
	}
	if event == "" {
		event = "unknown"
	}
	nonce, err := randomNonce()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"%s-%s-%s-%s-%s.json",
		model,
		connector,
		event,
		at.UTC().Format(spoolTimestampLayout),
		nonce,
	), nil
}

// shortModel abbreviates the Astrix model for use in a filename.
func shortModel(model SchemaModel) string {
	switch model {
	case SchemaModelAgent:
		return "agent"
	case SchemaModelAgentEvent:
		return "agentevent"
	default:
		return string(model)
	}
}

// sanitizeFileComponent reduces a value to a conservative filename-safe token.
// Anything outside the allow-list becomes "_", and the result is length
// bounded so a long agent-supplied event cannot exhaust path limits.
func sanitizeFileComponent(raw string) string {
	const maxComponent = 48
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(trimmed))
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
		if b.Len() >= maxComponent {
			break
		}
	}
	return strings.Trim(b.String(), "_-")
}

// randomNonce keeps concurrent hooks in the same millisecond from colliding.
func randomNonce() (string, error) {
	buf := make([]byte, 3)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
