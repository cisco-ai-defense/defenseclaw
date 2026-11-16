// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"sort"
)

// RecoverRetainedConfigTransforms finishes every config transform that left
// recovery receipts in dataDir, whichever agent file it was changing. A
// rollback or an upgrade refuses to go on while a receipt remains, and an
// interrupted transform leaves one; this is the command that clears them with
// the same recovery every later change to that file runs first. A receipt that
// recovery cannot prove (an ambiguous publication) is kept and reported by the
// name of its config. It returns how many transactions it finished.
func RecoverRetainedConfigTransforms(dataDir string) (int, error) {
	if _, err := os.Stat(dataDir); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	stateDir, err := prepareAtomicTransformStateDir(dataDir)
	if err != nil {
		return 0, err
	}
	stateBound, err := bindAtomicTransformDirectory(stateDir)
	if err != nil {
		return 0, err
	}
	groups, enumerateErr := enumerateAtomicTransformV2Groups(stateBound)
	configs := map[string]struct{}{}
	var loadErrs []error
	if enumerateErr == nil {
		for _, group := range groups {
			loaded, loadErr := loadAtomicTransformV2Group(group, stateBound)
			if loadErr != nil {
				loadErrs = append(loadErrs, fmt.Errorf("recovery receipt %s: %w", group.base, loadErr))
				continue
			}
			if loaded.exists {
				configs[loaded.logical] = struct{}{}
			}
		}
	}
	closeErr := stateBound.Close()
	if err := errors.Join(enumerateErr, closeErr); err != nil {
		return 0, err
	}
	paths := make([]string, 0, len(configs))
	for path := range configs {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	recovered, errs := 0, loadErrs
	for _, path := range paths {
		if err := recoverAtomicTransformV2(path, stateDir); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			continue
		}
		recovered++
	}
	return recovered, errors.Join(errs...)
}
