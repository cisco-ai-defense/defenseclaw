// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// ProtectedSetupAgentSelectionTransaction is a prepared open lock inode. The
// nonblocking Prepare phase can run under target credentials; Acquire may then
// wait only after the privileged caller has restored its original identity.
type ProtectedSetupAgentSelectionTransaction struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	acquired bool
	released bool
}

func PrepareProtectedSetupAgentSelectionTransaction(
	dataDir, connectorName string,
) (*ProtectedSetupAgentSelectionTransaction, error) {
	dataDir = strings.TrimSpace(dataDir)
	connectorName = normalizeConnectorName(connectorName)
	if dataDir == "" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return nil, errors.New("protected setup selection transaction requires a canonical absolute data directory")
	}
	if !RequiresProtectedSetupAgentSelection(connectorName) {
		return nil, fmt.Errorf("connector %q does not use protected setup selection on this host", connectorName)
	}
	// A fresh managed profile is allowed to have no DefenseClaw state
	// directory yet. Prepare runs in the brief target-credential scope, so it
	// can create the directory with the same owner-only custody contract used
	// by receipt publication without waiting on another transaction.
	if err := safefile.ProtectDirectory(dataDir); err != nil {
		return nil, fmt.Errorf("protect setup selection transaction directory: %w", err)
	}
	path := filepath.Join(dataDir, ".agent-selection-"+connectorName+".transaction.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|otlpOpenNoFollow(), 0o600)
	if err != nil {
		return nil, fmt.Errorf("open protected setup selection transaction lock: %w", err)
	}
	if err := validateOwnedLockFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &ProtectedSetupAgentSelectionTransaction{path: path, file: file}, nil
}

func (transaction *ProtectedSetupAgentSelectionTransaction) Acquire() error {
	if transaction == nil {
		return errors.New("acquire protected setup selection transaction: nil lease")
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.released || transaction.file == nil {
		return errors.New("acquire protected setup selection transaction: lease is closed")
	}
	if transaction.acquired {
		return nil
	}
	setupAgentSelectionTransactionMu.Lock()
	if err := syscall.Flock(int(transaction.file.Fd()), syscall.LOCK_EX); err != nil {
		setupAgentSelectionTransactionMu.Unlock()
		return fmt.Errorf("acquire protected setup selection transaction lock: %w", err)
	}
	transaction.acquired = true
	return nil
}

func (transaction *ProtectedSetupAgentSelectionTransaction) Release() error {
	if transaction == nil {
		return errors.New("release protected setup selection transaction: nil lease")
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.released {
		return nil
	}
	transaction.released = true
	var releaseErr error
	if transaction.acquired {
		if err := syscall.Flock(int(transaction.file.Fd()), syscall.LOCK_UN); err != nil {
			releaseErr = fmt.Errorf("release protected setup selection transaction lock: %w", err)
		}
		transaction.acquired = false
		setupAgentSelectionTransactionMu.Unlock()
	}
	if err := transaction.file.Close(); err != nil {
		releaseErr = errors.Join(releaseErr, err)
	}
	transaction.file = nil
	return releaseErr
}
