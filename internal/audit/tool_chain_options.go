// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Tool-chain repository options for Agent Substrate actors. Hosts and
// OpenShell sandboxes set none of them: Store.ToolChainRepository and
// Store.ToolChainRootRepository behave as they always did.
//
//   - WithToolChainActorScope keeps the repository's state in the root table
//     set, keyed on the actor root scope digest (ToolChainActorScopeDigest):
//     every call of one actor lands in one window, however often its
//     sessions rotate their IDs.
//   - WithToolChainHorizon measures the window's horizon in the actor's
//     running time rather than wall time (a suspended actor's clock stops).
//   - WithToolChainForkParent starts a forked actor's window from a copy of
//     its parent's.

// ToolChainOption configures a repository ToolChainRepositoryWith returns.
type ToolChainOption func(*toolChainOptions) error

type toolChainOptions struct {
	actorDigest string
	horizon     ToolChainHorizon
	forkParent  *ToolChainPartition
}

// ToolChainPartition names one window: a connector instance and its scope
// digest (a session digest, or a root or actor scope digest).
type ToolChainPartition struct {
	ConnectorInstanceID ConnectorInstanceID
	ScopeDigest         string
}

// ToolChainHorizon says where a window of a horizon of running time starts.
type ToolChainHorizon interface {
	// Cutoff returns the earliest received time a window ending at at
	// keeps, for horizon of running time. A cutoff after
	// at.Add(-horizon) (a window shorter than the wall-clock one) or a zero
	// time is ignored: the window is then the wall-clock one.
	Cutoff(at time.Time, horizon time.Duration) time.Time
}

// ErrToolChainForkCopyUnsupported is what a repository with a fork parent
// returns when it would start the child's window and cannot copy the
// parent's: a fork is never judged as if it had no history.
var ErrToolChainForkCopyUnsupported = errors.New("audit: copying a forked actor's tool-chain window is not supported yet")

const toolChainActorScopeDomain = "defenseclaw.chain.actor.v1"

// ToolChainActorScopeDigest is the actor root partition key: SHA-256 over
// the length-prefixed namespace, atespace and actor UID. The UID is the
// verified actor token's actorUID, so another actor (a fork among them,
// which gets a new UID) never names this one's partition, and the namespace
// keeps it apart from every ToolChainRootScopeDigest.
func ToolChainActorScopeDigest(atespace, actorUID string) (string, error) {
	for _, part := range [...]struct{ field, value string }{
		{"actor atespace", atespace},
		{"actor uid", actorUID},
	} {
		if err := validateBoundedIdentifier(part.field, part.value, true, toolChainRootIDMaxBytes); err != nil {
			return "", err
		}
	}
	hash := sha256.New()
	for _, part := range []string{toolChainActorScopeDomain, atespace, actorUID} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// WithToolChainActorScope keeps the repository's state in the actor root
// scope of atespace and actorUID (ToolChainActorScopeDigest).
func WithToolChainActorScope(atespace, actorUID string) ToolChainOption {
	return func(o *toolChainOptions) error {
		digest, err := ToolChainActorScopeDigest(atespace, actorUID)
		if err != nil {
			return err
		}
		o.actorDigest = digest
		return nil
	}
}

// WithToolChainHorizon measures the window's horizon with h.
func WithToolChainHorizon(h ToolChainHorizon) ToolChainOption {
	return func(o *toolChainOptions) error {
		if h == nil {
			return errors.New("audit: tool-chain horizon is required")
		}
		o.horizon = h
		return nil
	}
}

// WithToolChainForkParent starts the window of a forked actor, the first
// time the repository opens it, from a copy of parent's. It needs
// WithToolChainActorScope.
func WithToolChainForkParent(parent ToolChainPartition) ToolChainOption {
	return func(o *toolChainOptions) error {
		if err := validateUUIDv7("fork parent connector instance id", string(parent.ConnectorInstanceID)); err != nil {
			return err
		}
		if err := validateSHA256("fork parent scope digest", parent.ScopeDigest, true); err != nil {
			return err
		}
		o.forkParent = &parent
		return nil
	}
}

// ToolChainRepositoryWith returns a repository configured by opts. Without
// options it is Store.ToolChainRepository.
func (s *Store) ToolChainRepositoryWith(ctx context.Context, opts ...ToolChainOption) (*ToolChainRepository, error) {
	if ctx == nil {
		return nil, errors.New("audit: tool-chain context is required")
	}
	var o toolChainOptions
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	if o.forkParent != nil && o.actorDigest == "" {
		return nil, errors.New("audit: a tool-chain fork parent needs the actor scope")
	}
	if o.forkParent != nil && o.forkParent.ScopeDigest == o.actorDigest {
		return nil, fmt.Errorf("audit: a forked actor's tool-chain scope cannot be its parent's")
	}
	var (
		repo *ToolChainRepository
		err  error
	)
	if o.actorDigest != "" {
		repo, err = s.ToolChainRootRepository(ctx, o.actorDigest)
	} else {
		repo, err = s.ToolChainRepository()
	}
	if err != nil {
		return nil, err
	}
	repo.horizon, repo.forkParent = o.horizon, o.forkParent
	return repo, nil
}

// horizonCutoff is the earliest received time the window ending at at
// keeps: the wall-clock horizon, or the repository horizon's cutoff when it
// is set and keeps at least as much.
func (repo *ToolChainRepository) horizonCutoff(at time.Time) time.Time {
	wall := at.Add(-repo.maxHorizon)
	if repo.horizon == nil {
		return wall
	}
	cutoff := repo.horizon.Cutoff(at, repo.maxHorizon)
	if cutoff.IsZero() || cutoff.After(wall) {
		return wall
	}
	return cutoff
}

// toolChainCopyForkWindow copies parent's window into child, the partition
// a forked actor's repository is creating, inside its transaction.
// Agent Substrate fork support provides it; until then a configured fork
// parent refuses to start the child's window.
var toolChainCopyForkWindow = func(
	ctx context.Context, tx *sql.Tx, repo *ToolChainRepository, parent, child ToolChainPartition, now time.Time,
) error {
	return ErrToolChainForkCopyUnsupported
}
