// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"errors"
	"os"
	"runtime"
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// NewHostStageAssets transfers an already prepared supported host stage into
// exclusive asset custody without reopening TreePath. CWD and the one /work
// Write entry must be nil; two independent held-root duplicates fill them.
// /work labels this host-object association, not guest permission. Windows
// requires MXC ProcessContainer; Linux requires MXC Bubblewrap. Native policy,
// copied-root mount/no-IDMAP lineage and production admission stay independent.
// The current Windows bridge and production catalog remain unavailable.
//
// On success, all inputs and the stage transfer exclusively. A nonnil result
// with an error owns only its newly allocated duplicates, lease and stage and
// must be closed; the supplied images and other files remain caller-owned.
// Such a result is cleanup-only and cannot be bound. A nil result leaves all
// ownership with the caller. The caller must not concurrently close the stage.
func NewHostStageAssets(ctx context.Context, identity sandboxruntime.SessionIdentity, inputs bridgeprocess.Inputs, read, write []string, stage *workspace.HostStage) (*Assets, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		return nil, workspace.ErrUnsupportedPlatform
	}
	driver := "process_container"
	if runtime.GOOS == "linux" {
		driver = "bubblewrap"
	}
	if stage == nil || identity.Runtime.HostOS != runtime.GOOS || identity.Runtime.ExecutionOS != runtime.GOOS || identity.Runtime.Backend != "mxc" || identity.Runtime.Driver != driver ||
		validateHostStageInputs(identity, inputs, read, write) != nil {
		return nil, ErrAssets
	}
	lease, err := stage.AcquireRoot()
	if lease == nil {
		return nil, err
	}
	return assembleHostStageAssets(ctx, identity, inputs, read, write, lease.Duplicate,
		&hostStageRelease{closeLease: lease.Close, closeStage: stage.Close}, err)
}

// These callbacks are a private test seam for the concrete workspace lease;
// they are not a provider/custody interface or a native launch permission.
type hostStageRelease struct {
	closeLease func() error
	closeStage func() error
	leaseDone  bool
	leaseErr   error
}

func (r *hostStageRelease) close() error {
	if !r.leaseDone {
		if r.leaseErr != nil {
			return r.leaseErr
		}
		if err := r.closeLease(); err != nil {
			if !errors.Is(err, workspace.ErrHostStageInUse) {
				r.leaseErr = err
			}
			return err
		}
		r.leaseDone = true
	}
	// A stage in-use refusal has performed no deletion. Keep the stage and
	// permit explicit retry after its other tracked leases have released.
	return r.closeStage()
}

func validateHostStageInputs(identity sandboxruntime.SessionIdentity, inputs bridgeprocess.Inputs, read, write []string) error {
	work := slices.Index(write, "/work")
	if identity.Validate() != nil || identity.Runtime.Runtime != sandboxruntime.Axis || inputs.CWD != nil ||
		inputs.Peer == nil || inputs.Bubblewrap == nil || inputs.Payload == nil ||
		len(inputs.Read) != len(read) || len(inputs.Write) != len(write) || len(read)+len(write) > 256 ||
		work < 0 || inputs.Write[work] != nil || guestGrants(read, write) != nil {
		return ErrAssets
	}
	return nil
}

func assembleHostStageAssets(ctx context.Context, identity sandboxruntime.SessionIdentity, inputs bridgeprocess.Inputs, read, write []string,
	duplicate func() (*os.File, error), release *hostStageRelease, admissionErr error) (*Assets, error) {
	// Until NewAssets accepts the complete candidate, this owner contains no
	// caller-supplied file/image. Partial allocation is still cleanup custody.
	partial := &Assets{identity: identity, cleanupOnly: true, releaseStage: release.close}
	if admissionErr != nil {
		return partial, admissionErr
	}
	if err := validateHostStageInputs(identity, inputs, read, write); err != nil {
		return partial, err
	}
	for i := range 2 {
		if err := ctx.Err(); err != nil {
			return partial, err
		}
		file, err := duplicate()
		if i == 0 {
			partial.inputs.CWD = file
		} else if file != nil {
			partial.inputs.Write = []*os.File{file}
		}
		if err != nil {
			return partial, err
		}
		if file == nil {
			return partial, ErrAssets
		}
	}
	if err := ctx.Err(); err != nil {
		return partial, err
	}
	inputs.CWD = partial.inputs.CWD
	inputs.Write = slices.Clone(inputs.Write)
	inputs.Write[slices.Index(write, "/work")] = partial.inputs.Write[0]
	// NewAssets only validates and assembles an in-memory candidate; it does
	// not close resources, bind, launch or escape this constructor. Until the
	// outer successful return, cancellation can discard that unpublished
	// candidate and leave supplied inputs with their original caller.
	assets, err := NewAssets(identity, inputs, read, write)
	if err != nil {
		return partial, err
	}
	if err := ctx.Err(); err != nil {
		return partial, err
	}
	assets.releaseStage = release.close
	return assets, nil
}
