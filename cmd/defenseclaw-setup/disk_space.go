// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// diskSpaceMargin covers the journal, logs and other small files written
// around the extracted payload.
const diskSpaceMargin = 256 << 20

// freeDiskBytes reports the free space of the volume holding dir; ok is
// false where it is unknown. Replaceable in tests.
var freeDiskBytes = platformFreeDiskBytes

// requireFreeSpace refuses a step that needs more space than the volume
// holding dir has free, before it writes anything. Setup used to stage for a
// long time and then fail on a full disk deep in the extraction. When the
// free space is unknown, the step goes ahead.
func requireFreeSpace(dir string, need uint64, step string) error {
	probe := nearestExistingDir(dir)
	free, ok, err := freeDiskBytes(probe)
	if err != nil || !ok {
		return nil
	}
	need += diskSpaceMargin
	if free >= need {
		return nil
	}
	volume := filepath.VolumeName(probe)
	if volume == "" {
		volume = probe
	}
	return fmt.Errorf("not enough free disk space to %s: %s has %d MB free and about %d MB is needed; free some space and run Setup again",
		step, volume, free>>20, (need+(1<<20)-1)>>20)
}

func nearestExistingDir(dir string) string {
	dir = filepath.Clean(dir)
	for {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return dir
		}
		dir = parent
	}
}

func zipExpandedSize(reader *zip.Reader) uint64 {
	var total uint64
	for _, file := range reader.File {
		total += file.UncompressedSize64
	}
	return total
}

func zipFileExpandedSize(path string) (uint64, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return 0, err
	}
	defer reader.Close()
	return zipExpandedSize(&reader.Reader), nil
}

// stagingSpaceNeeded bounds what staging writes: each payload archive
// expanded (the gateway archive twice, since it is expanded beside the
// payload and then copied), plus every payload file, which covers the files
// copied as they are.
func stagingSpaceNeeded(payload loadedPayload) (uint64, error) {
	var total uint64
	archives := []string{
		payload.Manifest.PythonEmbed,
		payload.Manifest.VCRuntime,
		payload.Manifest.SitePackages,
		payload.Manifest.GatewayArchive,
		payload.Manifest.GatewayArchive,
	}
	for _, name := range archives {
		if strings.TrimSpace(name) == "" {
			continue
		}
		size, err := zipFileExpandedSize(filepath.Join(payload.Root, name))
		if err != nil {
			return 0, err
		}
		total += size
	}
	err := filepath.WalkDir(payload.Root, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			total += uint64(info.Size())
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	return total, nil
}
