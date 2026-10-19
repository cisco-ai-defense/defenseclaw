// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package workspace

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// freezeWindowsHostStageSettings reads only operator fallback facts. Captured
// local repository values are merged by the engine from that same snapshot.
// Missing files are known absent through held parents; unreadable/linked or
// unrepresentable configuration is not silently treated as absent.
func freezeWindowsHostStageSettings(ctx context.Context, opts StageOptions) (capturedGitSettings, error) {
	home, xdg := operatorConfigDirs(opts.Home)
	if home == "" || xdg == "" {
		return capturedGitSettings{}, capturedRefuse("operator_config_location_unknown")
	}
	facts := capturedGitSettings{frozen: true, lineEndings: map[string]string{}}
	for _, name := range []string{filepath.Join(home, ".gitconfig"), filepath.Join(xdg, "git", "config")} {
		data, present, err := readWindowsHostStageOptionalConfig(ctx, name)
		if err != nil {
			return capturedGitSettings{}, err
		}
		if !present {
			continue
		}
		cfg, err := parseCapturedGitConfig(data)
		if err != nil {
			return capturedGitSettings{}, capturedRefuse("operator_config_invalid_or_unbounded")
		}
		for _, section := range cfg.Sections {
			if section.IsName("include") || section.IsName("includeif") {
				return capturedGitSettings{}, capturedRefuse("operator_config_includes_not_supported")
			}
			if !section.IsName("core") {
				continue
			}
			for _, key := range lineEndingKeys {
				short := strings.TrimPrefix(key, "core.")
				if !section.HasOption(short) {
					continue
				}
				if _, set := facts.lineEndings[key]; !set {
					facts.lineEndings[key] = section.Option(short)
				}
			}
		}
	}
	return facts, nil
}

func readWindowsHostStageOptionalConfig(ctx context.Context, name string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	parent, err := openWindowsHostStageOptionalPin(filepath.Dir(name))
	if err != nil {
		return nil, false, capturedRefuse("operator_config_parent_not_held")
	}
	if parent == nil {
		return nil, false, nil
	}
	defer parent.close()
	file, err := openWindowsHostStageChild(parent.leaf(), filepath.Base(name), windows.FILE_SHARE_READ)
	if windowsHostStageMissing(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, capturedRefuse("operator_config_not_readable_or_stable")
	}
	defer file.Close()
	if _, err = windowsHostStageInfo(file, false); err != nil {
		return nil, false, capturedRefuse("operator_config_type_or_link_not_supported")
	}
	if err = windowsHostStageNoStreams(file); err != nil {
		return nil, false, capturedRefuse("operator_config_stream_not_supported")
	}
	if _, err = windowsHostStageIdentity(file); err != nil {
		return nil, false, capturedRefuse("operator_config_identity_unknown")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, false, capturedRefuse("operator_config_stat_failed")
	}
	if info.Size() < 0 || info.Size() > 1<<20 {
		return nil, false, capturedRefuse("operator_config_size_limit")
	}
	data, err := io.ReadAll(io.LimitReader(capturedContextReader{ctx, file}, info.Size()+1))
	if err != nil {
		return nil, false, capturedRefuse("operator_config_read_failed")
	}
	if int64(len(data)) != info.Size() {
		return nil, false, capturedRefuse("operator_config_size_changed")
	}
	return data, true, nil
}

func windowsHostStageMissing(err error) bool {
	return errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND)
}
