// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/spf13/cobra"
)

const (
	deferredVerifyDocumentLimit = int64(4 << 20)
	deferredVerifySetupName     = "DefenseClawSetup-x64.exe"
	deferredVerifyGatewayName   = "defenseclaw-gateway.exe"
)

var (
	deferredVerifyExecutable  = os.Executable
	deferredVerifyParent      = deferredVerifyParentImage
	deferredVerifyPrivateFile = safefile.ValidatePrivateFile
)

type deferredVerifyProcessIdentity struct {
	ImagePath     string
	StartIdentity string
	requireLive   func() error
	close         func() error
}

func (identity deferredVerifyProcessIdentity) requireLiveParent() error {
	if identity.requireLive == nil {
		return errors.New("parent process liveness proof is unavailable")
	}
	return identity.requireLive()
}

func (identity deferredVerifyProcessIdentity) closeParent() error {
	if identity.close == nil {
		return errors.New("parent process handle is unavailable")
	}
	return identity.close()
}

type deferredVerifyCleanupRecord struct {
	SchemaVersion      int      `json:"schema_version"`
	Status             string   `json:"status"`
	TransactionID      string   `json:"transaction_id"`
	MaintenancePath    string   `json:"maintenance_path"`
	MaintenanceSHA256  string   `json:"maintenance_sha256"`
	InstallerStateRoot string   `json:"installer_state_root"`
	JournalPath        string   `json:"journal_path"`
	RecordPath         string   `json:"record_path"`
	CacheAckPath       string   `json:"cache_ack_path"`
	VerifiedConnectors []string `json:"verified_connectors"`
}

type deferredVerifyInstallState struct {
	CodexHome       string `json:"codex_home,omitempty"`
	ClaudeConfigDir string `json:"claude_config_dir,omitempty"`
}

type deferredVerifyTransaction struct {
	ID                        string                      `json:"id"`
	Action                    string                      `json:"action"`
	DataRoot                  string                      `json:"data_root"`
	MaintenancePath           string                      `json:"maintenance_path"`
	PreviousMaintenanceSHA256 string                      `json:"previous_maintenance_sha256,omitempty"`
	PreviousState             *deferredVerifyInstallState `json:"previous_state,omitempty"`
	PreviousConnectors        []string                    `json:"previous_connectors,omitempty"`
	PreviousCodexHome         string                      `json:"previous_codex_home,omitempty"`
	PreviousClaudeConfigDir   string                      `json:"previous_claude_config_dir,omitempty"`
	CodexHome                 string                      `json:"codex_home,omitempty"`
	ClaudeConfigDir           string                      `json:"claude_config_dir,omitempty"`
}

type deferredVerifyJournal struct {
	SchemaVersion int                       `json:"schema_version"`
	Phase         string                    `json:"phase"`
	Transaction   deferredVerifyTransaction `json:"transaction"`
}

func validateDeferredUninstallConnectorVerify(cmd *cobra.Command) error {
	if cmd == nil || cmd.Name() != "verify" || cmd.Parent() == nil || cmd.Parent().Name() != "connector" {
		return errors.New("private authorization is accepted only by connector verify")
	}
	if !deferredVerifyFlagChanged(cmd, "internal-setup-parent") ||
		!deferredVerifyFlagChanged(cmd, "internal-setup-start-identity") ||
		!deferredVerifyFlagChanged(cmd, "internal-deferred-cleanup-record") ||
		!deferredVerifyFlagChanged(cmd, "internal-deferred-cleanup-transaction") ||
		!deferredVerifyFlagChanged(cmd, "connector") ||
		!deferredVerifyFlagChanged(cmd, "data-dir") ||
		!deferredVerifyFlagChanged(cmd, "config-home") ||
		!deferredVerifyFlagChanged(cmd, "json") {
		return errors.New("private verification requires every explicit authenticated binding")
	}
	transactionID := connectorVerifyCleanupTransaction
	if !validDeferredVerifyTransactionID(transactionID) {
		return errors.New("cleanup transaction identity is invalid")
	}
	if !validDeferredVerifyProcessStartIdentity(connectorVerifySetupStartIdentity) {
		return errors.New("Setup process start identity is invalid")
	}
	parentPath, err := normalizedDeferredVerifyPath(connectorVerifySetupParent, deferredVerifySetupName)
	if err != nil {
		return fmt.Errorf("Setup parent path: %w", err)
	}
	recordPath, err := normalizedDeferredVerifyPath(connectorVerifyCleanupRecord, "uninstall-cleanup.json")
	if err != nil {
		return fmt.Errorf("cleanup record path: %w", err)
	}
	dataDir, err := normalizedDeferredVerifyDirectory(connectorFlagDataDir)
	if err != nil || !strings.EqualFold(filepath.Base(dataDir), ".defenseclaw") {
		return errors.New("data directory is not the exact normalized native data root")
	}
	configHome, err := normalizedDeferredVerifyDirectory(connectorFlagConfigHome)
	if err != nil {
		return fmt.Errorf("config home: %w", err)
	}
	connectorName := strings.ToLower(strings.TrimSpace(connectorFlagName))
	if connectorName == "" || connectorName != connectorFlagName || !connectorFlagJSON {
		return errors.New("connector or JSON binding is not canonical")
	}

	self, err := deferredVerifyExecutable()
	if err != nil {
		return fmt.Errorf("resolve maintenance gateway executable: %w", err)
	}
	self, err = normalizedDeferredVerifyPath(self, deferredVerifyGatewayName)
	if err != nil {
		return fmt.Errorf("maintenance gateway executable: %w", err)
	}
	for _, path := range []string{self, parentPath, recordPath} {
		if err := deferredVerifyPrivateFile(path); err != nil {
			return fmt.Errorf("private file binding %s: %w", filepath.Base(path), err)
		}
	}
	actualParent, err := deferredVerifyParent(os.Getppid())
	if err != nil {
		return fmt.Errorf("resolve live Setup parent: %w", err)
	}
	defer func() { _ = actualParent.closeParent() }()
	if err := actualParent.requireLiveParent(); err != nil {
		return fmt.Errorf("authenticate live Setup parent process: %w", err)
	}
	actualParentPath, err := normalizedDeferredVerifyPath(actualParent.ImagePath, deferredVerifySetupName)
	if err != nil || !sameDeferredVerifyPath(actualParentPath, parentPath) ||
		actualParent.StartIdentity != connectorVerifySetupStartIdentity {
		return errors.New("live parent process is not the authenticated Setup executable")
	}

	var record deferredVerifyCleanupRecord
	if err := readDeferredVerifyJSON(recordPath, &record); err != nil {
		return fmt.Errorf("read cleanup record: %w", err)
	}
	if record.SchemaVersion != 1 ||
		(record.Status != "pending-reboot" && record.Status != "runtime-retired") ||
		record.TransactionID != transactionID ||
		!sameDeferredVerifyPath(record.RecordPath, recordPath) ||
		!sameDeferredVerifyPath(record.InstallerStateRoot, filepath.Dir(recordPath)) ||
		!sameDeferredVerifyPath(record.JournalPath, filepath.Join(filepath.Dir(recordPath), "setup-transaction.json")) ||
		!sameDeferredVerifyPath(record.MaintenancePath, parentPath) ||
		!sameDeferredVerifyPath(filepath.Dir(record.MaintenancePath), filepath.Join(filepath.Dir(record.InstallerStateRoot), "InstallerCache")) ||
		!sameDeferredVerifyPath(record.CacheAckPath, filepath.Join(filepath.Dir(record.MaintenancePath), "uninstall-cleanup-ack.json")) ||
		!validDeferredVerifySHA256(record.MaintenanceSHA256) {
		return errors.New("cleanup record does not bind the exact pending transaction and canonical maintenance paths")
	}
	parentDigest, err := hashDeferredVerifyFile(parentPath)
	if err != nil || parentDigest != record.MaintenanceSHA256 {
		return errors.New("live Setup parent digest does not match the authenticated cleanup record")
	}
	if err := deferredVerifyPrivateFile(record.JournalPath); err != nil {
		return fmt.Errorf("private journal binding: %w", err)
	}
	var journal deferredVerifyJournal
	if err := readDeferredVerifyJSON(record.JournalPath, &journal); err != nil {
		return fmt.Errorf("read cleanup journal: %w", err)
	}
	transaction := journal.Transaction
	if journal.SchemaVersion != 2 || journal.Phase != "converged" ||
		transaction.Action != "uninstall" || transaction.ID != transactionID ||
		!sameDeferredVerifyPath(transaction.DataRoot, dataDir) ||
		!sameDeferredVerifyPath(transaction.MaintenancePath, parentPath) ||
		transaction.PreviousMaintenanceSHA256 != record.MaintenanceSHA256 {
		return errors.New("cleanup journal does not bind the exact uninstall transaction")
	}
	recordConnectors := append([]string(nil), record.VerifiedConnectors...)
	journalConnectors := append([]string(nil), transaction.PreviousConnectors...)
	slices.Sort(recordConnectors)
	slices.Sort(journalConnectors)
	if !slices.Equal(recordConnectors, journalConnectors) ||
		!slices.Contains(journalConnectors, connectorName) {
		return errors.New("connector is outside the authenticated uninstall roster")
	}
	if !deferredVerifyConfigHomeBound(transaction, connectorName, configHome) {
		return errors.New("config home is outside the authenticated uninstall transaction")
	}
	if err := actualParent.requireLiveParent(); err != nil {
		return fmt.Errorf("revalidate live Setup parent process: %w", err)
	}
	return nil
}

func deferredVerifyFlagChanged(cmd *cobra.Command, name string) bool {
	if flag := cmd.Flags().Lookup(name); flag != nil && flag.Changed {
		return true
	}
	return cmd.InheritedFlags().Lookup(name) != nil && cmd.InheritedFlags().Lookup(name).Changed
}

func validDeferredVerifyTransactionID(value string) bool {
	if len(value) != 32 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validDeferredVerifySHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validDeferredVerifyProcessStartIdentity(value string) bool {
	identity, err := strconv.ParseInt(value, 10, 64)
	return err == nil && identity > 0 && value == strconv.FormatInt(identity, 10)
}

func normalizedDeferredVerifyPath(value, base string) (string, error) {
	clean, err := normalizedDeferredVerifyDirectory(value)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(filepath.Base(clean), base) {
		return "", fmt.Errorf("unexpected basename")
	}
	return clean, nil
}

func normalizedDeferredVerifyDirectory(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n\"") ||
		!filepath.IsAbs(value) || filepath.Clean(value) != value {
		return "", errors.New("path is not absolute and normalized")
	}
	return value, nil
}

func sameDeferredVerifyPath(left, right string) bool {
	if left == "" || right == "" {
		return false
	}
	return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
}

func readDeferredVerifyJSON(path string, target any) error {
	data, err := readDeferredVerifyFile(path, deferredVerifyDocumentLimit)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return err
	}
	return nil
}

func readDeferredVerifyFile(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > limit {
		return nil, errors.New("authenticated file violates the regular-file size contract")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, errors.New("authenticated file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("authenticated file exceeds its read bound")
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(opened, after) {
		return nil, errors.New("authenticated file changed while reading")
	}
	return data, nil
}

func hashDeferredVerifyFile(path string) (string, error) {
	const limit = int64(512 << 20)
	before, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > limit {
		return "", errors.New("authenticated executable violates the regular-file size contract")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return "", errors.New("authenticated executable changed while opening")
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, limit+1))
	if err != nil || written != before.Size() || written > limit {
		return "", errors.New("authenticated executable changed while hashing")
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(opened, after) || after.Size() != before.Size() {
		return "", errors.New("authenticated executable changed after hashing")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func deferredVerifyConfigHomeBound(transaction deferredVerifyTransaction, connectorName, configHome string) bool {
	candidates := deferredVerifyConfigHomes(transaction, connectorName)
	for _, candidate := range candidates {
		if sameDeferredVerifyPath(candidate, configHome) {
			return true
		}
	}
	return false
}

func deferredVerifyConfigHomes(transaction deferredVerifyTransaction, connectorName string) []string {
	var candidates []string
	add := func(values ...string) {
		for _, value := range values {
			if value != "" {
				candidates = append(candidates, value)
			}
		}
	}
	previous := transaction.PreviousState
	switch connectorName {
	case "codex":
		add(transaction.PreviousCodexHome, transaction.CodexHome)
		if previous != nil {
			add(previous.CodexHome)
		}
		add(filepath.Join(filepath.Dir(transaction.DataRoot), ".codex"))
	case "claudecode":
		add(transaction.PreviousClaudeConfigDir, transaction.ClaudeConfigDir)
		if previous != nil {
			add(previous.ClaudeConfigDir)
		}
		add(filepath.Join(filepath.Dir(transaction.DataRoot), ".claude"))
	case "amp":
		// Amp has no configurable home. The authenticated native data root is
		// fixed at %USERPROFILE%\\.defenseclaw, so its sibling is the exact
		// documented %USERPROFILE%\\.config\\amp home used by Setup.
		add(filepath.Join(filepath.Dir(transaction.DataRoot), ".config", "amp"))
	}
	return candidates
}
