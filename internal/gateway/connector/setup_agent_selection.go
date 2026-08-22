// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// SetupAgentSelectionPublication is an opaque rollback/consume handle for an
// enterprise setup selection. The caller must call Rollback after every failed
// setup transaction or Consume after the selected identity has been sealed in
// the durable hook-contract lock.
type SetupAgentSelectionPublication struct {
	mu                 sync.Mutex
	dataDir            string
	connectorName      string
	previousBody       []byte
	previousExisted    bool
	publishedBody      []byte
	publishedSelection agentSelectionEvidence
	finalized          setupAgentSelectionFinalization
}

type setupAgentSelectionFinalization uint8

const (
	setupAgentSelectionPending setupAgentSelectionFinalization = iota
	setupAgentSelectionRolledBack
	setupAgentSelectionConsumed
)

// setupAgentSelectionMu complements the persistent cross-process lock. File
// locks acquired through separately opened descriptors do not provide the same
// in-process exclusion semantics on every supported Unix variant.
var setupAgentSelectionMu sync.Mutex

// setupAgentSelectionTransactionMu pairs the persistent transaction lock with
// same-process exclusion on platforms whose advisory locks are per-process.
var setupAgentSelectionTransactionMu sync.Mutex

var transformSetupAgentSelectionFile = atomicTransformFileWithStateDir

func withSetupAgentSelectionLock(dataDir string, fn func() error) error {
	setupAgentSelectionMu.Lock()
	defer setupAgentSelectionMu.Unlock()
	return withOwnedFileLock(filepath.Join(dataDir, agentSelectionFile+".lock"), fn)
}

// WithProtectedSetupAgentSelectionTransaction serializes the complete
// publish, Setup, durable-lock seal, and receipt finalization transaction for
// one protected connector. Holding only the receipt's short mutation lock
// would allow a second process to commit newer hooks between the first
// process's Setup and rollback.
func WithProtectedSetupAgentSelectionTransaction(
	dataDir, connectorName string,
	fn func() error,
) error {
	if fn == nil {
		return errors.New("protected setup selection transaction requires a callback")
	}
	transaction, err := PrepareProtectedSetupAgentSelectionTransaction(dataDir, connectorName)
	if err != nil {
		return err
	}
	if err := transaction.Acquire(); err != nil {
		_ = transaction.Release()
		return err
	}
	callbackErr := fn()
	return errors.Join(callbackErr, transaction.Release())
}

// RequiresProtectedSetupAgentSelection reports whether the current host binds
// this connector's setup authority to a protected executable receipt/lock.
func RequiresProtectedSetupAgentSelection(connectorName string) bool {
	return protectedSetupSelectionConnectorForOS(normalizeConnectorName(connectorName), runtime.GOOS)
}

// PublishSetupAgentSelection records an explicit, short-lived executable
// selection for a protected native connector. It is the Go-side equivalent of
// the Python setup picker's agent_selection.json publication and is used by
// the privileged enterprise guardian after it consumes an administrator-owned
// manifest. Connector Setup still revalidates the vendor signature, native
// architecture, quarantine state, path custody, version binding, and digest
// before it can mutate an agent configuration or seal a durable contract lock.
//
// The executable is never resolved through PATH here. Callers must supply the
// exact canonical regular file selected by their trusted setup boundary.
func PublishSetupAgentSelection(
	dataDir, connectorName, executable, rawVersion string,
) (*SetupAgentSelectionPublication, error) {
	dataDir = strings.TrimSpace(dataDir)
	connectorName = normalizeConnectorName(connectorName)
	rawVersion = strings.TrimSpace(rawVersion)
	if dataDir == "" || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return nil, errors.New("setup agent selection requires a canonical absolute data directory")
	}
	if !RequiresProtectedSetupAgentSelection(connectorName) {
		return nil, fmt.Errorf("connector %q does not use protected setup selection on this host", connectorName)
	}
	resolution := ResolveHookContract(connectorName, rawVersion)
	if resolution.Status != HookCompatibilityKnown || strings.TrimSpace(resolution.NormalizedVersion) == "" {
		return nil, fmt.Errorf(
			"connector %s agent version %q is not covered by a known hook contract: %s",
			connectorName,
			rawVersion,
			resolution.Reason,
		)
	}
	stablePath, digest, ok := setupSelectedAgentExecutableEvidence(executable)
	if !ok || strings.TrimSpace(executable) != stablePath {
		return nil, fmt.Errorf("connector %s setup-selected executable is not a stable canonical regular file", connectorName)
	}

	if err := safefile.ProtectDirectory(dataDir); err != nil {
		return nil, fmt.Errorf("protect setup agent selection directory: %w", err)
	}
	publication := &SetupAgentSelectionPublication{
		dataDir:       dataDir,
		connectorName: connectorName,
	}
	path := filepath.Join(dataDir, agentSelectionFile)
	err := withSetupAgentSelectionLock(dataDir, func() error {
		// Fail closed before the CAS engine accepts an existing receipt. The
		// protected directory prevents an unprivileged writer from replacing it
		// after this check; CAS still detects same-owner concurrent changes.
		if _, exists, err := readRequiredStablePrivateStateFile(
			dataDir,
			agentSelectionFile,
			agentSelectionMaxBytes,
		); err != nil {
			return fmt.Errorf("load existing setup agent selection: %w", err)
		} else if exists {
			if err := validateProtectedStateFileLeaf(path); err != nil {
				return fmt.Errorf("validate existing setup agent selection: %w", err)
			}
		}
		return transformSetupAgentSelectionFile(path, dataDir, 0o600, func(body []byte, exists bool) (atomicTransformResult, error) {
			receipt := agentSelectionReceipt{
				SchemaVersion: agentSelectionSchemaVersion,
				Selections:    map[string]agentSelectionEvidence{},
			}
			publication.previousBody = append([]byte(nil), body...)
			publication.previousExisted = exists
			now := time.Now().UTC()
			if exists {
				var current agentSelectionReceipt
				if err := json.Unmarshal(body, &current); err != nil ||
					current.SchemaVersion != agentSelectionSchemaVersion || current.Selections == nil {
					return atomicTransformResult{}, errors.New("existing setup agent selection receipt is malformed")
				}
				if _, err := time.Parse(time.RFC3339, current.UpdatedAt); err != nil {
					return atomicTransformResult{}, errors.New("existing setup agent selection receipt has invalid updated_at")
				}
				// Preserve only entries that remain valid under the exact consumer
				// contract. Expired evidence is intentionally dropped.
				seen := make(map[string]struct{}, len(current.Selections))
				for rawName, selection := range current.Selections {
					name := normalizeConnectorName(rawName)
					if rawName != strings.TrimSpace(rawName) || name == "" || name != rawName {
						return atomicTransformResult{}, fmt.Errorf("existing setup agent selection has non-canonical connector key %q", rawName)
					}
					if _, duplicate := seen[name]; duplicate {
						return atomicTransformResult{}, fmt.Errorf("existing setup agent selection has duplicate connector key %q", name)
					}
					seen[name] = struct{}{}
					if validSetupAgentSelectionEvidence(name, selection, now) {
						receipt.Selections[name] = selection
					}
				}
			}

			publication.publishedSelection = agentSelectionEvidence{
				Connector:         connectorName,
				Source:            "setup-selected",
				Executable:        stablePath,
				RawVersion:        resolution.RawVersion,
				NormalizedVersion: resolution.NormalizedVersion,
				SHA256:            digest,
				SelectedAt:        now.Format(time.RFC3339),
				ExpiresAt:         now.Add(agentSelectionMaxLifetime).Format(time.RFC3339),
			}
			receipt.UpdatedAt = now.Format(time.RFC3339)
			receipt.Selections[connectorName] = publication.publishedSelection
			published, err := marshalSetupAgentSelectionReceipt(receipt)
			if err != nil {
				return atomicTransformResult{}, err
			}
			publication.publishedBody = append([]byte(nil), published...)
			return atomicTransformResult{Data: published}, nil
		})
	})
	if err != nil {
		// The POSIX CAS engine can rename the new receipt successfully and then
		// report a parent-directory durability error. Once the transform built a
		// candidate, treat publication as potentially visible and CAS-restore the
		// exact predecessor before returning failure.
		if len(publication.publishedBody) != 0 {
			if rollbackErr := publication.Rollback(); rollbackErr != nil {
				return nil, errors.Join(err, fmt.Errorf("rollback ambiguous setup agent selection publication: %w", rollbackErr))
			}
		}
		return nil, err
	}
	return publication, nil
}

// Rollback restores the exact preceding receipt when no other writer has
// intervened. If another writer added selections, it removes only this
// publication and preserves that newer state.
func (publication *SetupAgentSelectionPublication) Rollback() error {
	if publication == nil {
		return nil
	}
	return publication.finish(false)
}

// Consume removes this short-lived selection after Setup has sealed the same
// identity into the durable hook-contract lock. Other concurrent selections
// remain untouched.
func (publication *SetupAgentSelectionPublication) Consume() error {
	if publication == nil {
		return nil
	}
	return publication.finish(true)
}

// Consumed reports whether finalization durably completed. Callers use this
// only to distinguish an injected/wrapped post-success error from a failed or
// ambiguous Consume that still requires full transaction rollback.
func (publication *SetupAgentSelectionPublication) Consumed() bool {
	if publication == nil {
		return false
	}
	publication.mu.Lock()
	defer publication.mu.Unlock()
	return publication.finalized == setupAgentSelectionConsumed
}

func (publication *SetupAgentSelectionPublication) finish(consume bool) error {
	publication.mu.Lock()
	defer publication.mu.Unlock()
	wanted := setupAgentSelectionRolledBack
	label := "rollback"
	if consume {
		wanted = setupAgentSelectionConsumed
		label = "consume"
	}
	if publication.finalized != setupAgentSelectionPending {
		if publication.finalized == wanted {
			return nil
		}
		return fmt.Errorf("setup agent selection was already finalized by %s", map[setupAgentSelectionFinalization]string{
			setupAgentSelectionRolledBack: "rollback",
			setupAgentSelectionConsumed:   "consume",
		}[publication.finalized])
	}
	if consume {
		entries, err := LoadProtectedHookContractLockEntries(publication.dataDir)
		if err != nil {
			return fmt.Errorf("validate protected hook contract lock before consuming setup agent selection: %w", err)
		}
		entry, exists := entries[publication.connectorName]
		if !exists || !validSetupSelectedAgentExecutableEvidence(entry, publication.connectorName) ||
			!protectedSelectionMatchesLock(publication.publishedSelection, entry) {
			return fmt.Errorf(
				"cannot consume %s setup agent selection before the exact executable identity is sealed in the protected hook contract lock",
				publication.connectorName,
			)
		}
	}
	path := filepath.Join(publication.dataDir, agentSelectionFile)
	err := withSetupAgentSelectionLock(publication.dataDir, func() error {
		if _, exists, err := readRequiredStablePrivateStateFile(
			publication.dataDir,
			agentSelectionFile,
			agentSelectionMaxBytes,
		); err != nil {
			return fmt.Errorf("load published setup agent selection: %w", err)
		} else if exists {
			if err := validateProtectedStateFileLeaf(path); err != nil {
				return fmt.Errorf("validate published setup agent selection: %w", err)
			}
		}
		return transformSetupAgentSelectionFile(path, publication.dataDir, 0o600, func(body []byte, exists bool) (atomicTransformResult, error) {
			if !consume {
				if publication.previousExisted && exists && bytes.Equal(body, publication.previousBody) {
					return atomicTransformResult{Data: append([]byte(nil), body...)}, nil
				}
				if !publication.previousExisted && !exists {
					return atomicTransformResult{Remove: true}, nil
				}
			}
			if !exists {
				return atomicTransformResult{}, errors.New("published setup agent selection disappeared before finalization")
			}
			if !consume && bytes.Equal(body, publication.publishedBody) {
				if publication.previousExisted {
					return atomicTransformResult{Data: append([]byte(nil), publication.previousBody...)}, nil
				}
				return atomicTransformResult{Remove: true}, nil
			}

			var current agentSelectionReceipt
			if err := json.Unmarshal(body, &current); err != nil ||
				current.SchemaVersion != agentSelectionSchemaVersion || current.Selections == nil {
				return atomicTransformResult{}, errors.New("published setup agent selection became malformed before finalization")
			}
			selected, exists := current.Selections[publication.connectorName]
			if !exists || selected != publication.publishedSelection {
				return atomicTransformResult{}, fmt.Errorf(
					"published %s setup agent selection changed before finalization",
					publication.connectorName,
				)
			}
			delete(current.Selections, publication.connectorName)
			if !consume && publication.previousExisted {
				var previous agentSelectionReceipt
				if err := json.Unmarshal(publication.previousBody, &previous); err != nil || previous.Selections == nil {
					return atomicTransformResult{}, errors.New("previous setup agent selection snapshot is malformed")
				}
				if prior, ok := previous.Selections[publication.connectorName]; ok {
					current.Selections[publication.connectorName] = prior
				}
			}
			if len(current.Selections) == 0 {
				return atomicTransformResult{Remove: true}, nil
			}
			current.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			updated, err := marshalSetupAgentSelectionReceipt(current)
			if err != nil {
				return atomicTransformResult{}, err
			}
			return atomicTransformResult{Data: updated}, nil
		})
	})
	if err != nil {
		if consume {
			if restoreErr := publication.restoreAfterAmbiguousConsume(); restoreErr != nil {
				err = errors.Join(err, fmt.Errorf("restore receipt after ambiguous consume: %w", restoreErr))
			}
		}
		return fmt.Errorf("%s setup agent selection: %w", label, err)
	}
	publication.finalized = wanted
	return nil
}

func (publication *SetupAgentSelectionPublication) restoreAfterAmbiguousConsume() error {
	path := filepath.Join(publication.dataDir, agentSelectionFile)
	return withSetupAgentSelectionLock(publication.dataDir, func() error {
		if _, exists, err := readRequiredStablePrivateStateFile(
			publication.dataDir,
			agentSelectionFile,
			agentSelectionMaxBytes,
		); err != nil {
			return err
		} else if exists {
			if err := validateProtectedStateFileLeaf(path); err != nil {
				return err
			}
		}
		return transformSetupAgentSelectionFile(path, publication.dataDir, 0o600, func(body []byte, exists bool) (atomicTransformResult, error) {
			if publication.previousExisted && exists && bytes.Equal(body, publication.previousBody) {
				return atomicTransformResult{Data: append([]byte(nil), body...)}, nil
			}
			if !publication.previousExisted && !exists {
				return atomicTransformResult{Remove: true}, nil
			}
			if !bytes.Equal(body, publication.publishedBody) &&
				!publication.receiptMatchesConsumedPublication(body, exists) {
				return atomicTransformResult{}, errors.New("setup agent selection changed during ambiguous consume")
			}
			if publication.previousExisted {
				return atomicTransformResult{Data: append([]byte(nil), publication.previousBody...)}, nil
			}
			return atomicTransformResult{Remove: true}, nil
		})
	})
}

func (publication *SetupAgentSelectionPublication) receiptMatchesConsumedPublication(body []byte, exists bool) bool {
	var published agentSelectionReceipt
	if err := json.Unmarshal(publication.publishedBody, &published); err != nil || published.Selections == nil {
		return false
	}
	delete(published.Selections, publication.connectorName)
	if len(published.Selections) == 0 {
		return !exists
	}
	if !exists {
		return false
	}
	var current agentSelectionReceipt
	if err := json.Unmarshal(body, &current); err != nil ||
		current.SchemaVersion != agentSelectionSchemaVersion ||
		len(current.Selections) != len(published.Selections) {
		return false
	}
	for name, expected := range published.Selections {
		if actual, ok := current.Selections[name]; !ok || actual != expected {
			return false
		}
	}
	return true
}

func marshalSetupAgentSelectionReceipt(receipt agentSelectionReceipt) ([]byte, error) {
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode setup agent selection: %w", err)
	}
	if len(body)+1 > agentSelectionMaxBytes {
		return nil, fmt.Errorf("setup agent selection exceeds %d bytes", agentSelectionMaxBytes)
	}
	return append(body, '\n'), nil
}
