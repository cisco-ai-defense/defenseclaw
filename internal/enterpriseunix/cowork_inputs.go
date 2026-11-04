// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// coworkAsset is an input, never a second source of policy. Config supplies
// the release digest; the lifecycle copies explicit inputs into its cache in
// the same snapshot as their public Claude Desktop copies.
type coworkAsset struct {
	source string // canonical path; Env.P resolves fake roots
	suffix string // "" or ".sig"
	cache  bool
}

func (l *lifecycle) coworkInputs(p *plan, name string) ([]coworkAsset, error) {
	c := p.config.Loaded.Enterprise.CoworkVMSensor
	explicit := l.opts.CoworkPackage != "" || l.opts.CoworkSignature != ""
	archive := filepath.Join(c.SourceDir, name)
	if !explicit {
		if err := l.env.checkCoworkPath(c.SourceDir, true); err != nil {
			return nil, fmt.Errorf("Cowork VM source: %w", err)
		}
		return []coworkAsset{{source: archive}, {source: archive + ".sig", suffix: ".sig"}}, nil
	}
	cache := l.env.coworkCacheDir()
	if c.SourceDir != cache {
		return nil, fmt.Errorf("explicit Cowork inputs require enterprise.cowork_vm_sensor.source_dir: %s (the protected lifecycle cache)", cache)
	}
	// Only this fixed cache may be written. Check existing ancestors before
	// snapshotting; never change a shared system directory's owner or mode.
	for path := cache; path != "/"; path = filepath.Dir(path) {
		if _, err := os.Lstat(l.env.P(path)); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, err
		}
		if err := l.env.checkCoworkPath(path, true); err != nil {
			return nil, fmt.Errorf("Cowork VM cache: %w", err)
		}
	}
	p.dirs = append(p.dirs,
		desiredDir{Path: filepath.Dir(cache), Mode: 0o755, Owner: rootOwner(), External: true},
		desiredDir{Path: cache, Mode: 0o700, Owner: rootOwner()},
	)
	packageSource := archive
	if l.opts.CoworkPackage != "" {
		if filepath.Base(l.opts.CoworkPackage) != name {
			return nil, fmt.Errorf("Cowork package input must be named %s for this machine's VM architecture", name)
		}
		var err error
		packageSource, err = l.env.coworkInputCanonical(l.opts.CoworkPackage)
		if err != nil {
			return nil, err
		}
	}
	assets := []coworkAsset{{source: packageSource, cache: l.opts.CoworkPackage != ""}}
	if l.opts.CoworkSignature != "" {
		source, err := l.env.coworkInputCanonical(l.opts.CoworkSignature)
		if err != nil {
			return nil, err
		}
		assets = append(assets, coworkAsset{source: source, suffix: ".sig", cache: true})
	} else if c.SignatureSHA256 != "" || l.opts.CoworkPackage == "" {
		assets = append(assets, coworkAsset{source: archive + ".sig", suffix: ".sig"})
	}
	return assets, nil
}

func (e *Env) coworkInputCanonical(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("Cowork artifact input must be a canonical absolute path")
	}
	if e.Root != "" {
		if !strings.HasPrefix(path, filepath.Clean(e.Root)+string(filepath.Separator)) {
			return "", fmt.Errorf("Cowork input is outside the test root")
		}
		path = strings.TrimPrefix(path, filepath.Clean(e.Root))
	}
	return path, nil
}
