// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package workspace

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
)

func freezeLinuxHostStageSettings(ctx context.Context, access *linuxHostAccess, opts StageOptions) (capturedGitSettings, error) {
	home, xdg := operatorConfigDirs(opts.Home)
	if home == "" || xdg == "" {
		return capturedGitSettings{}, capturedRefuse("operator_config_location_unknown")
	}
	facts := capturedGitSettings{frozen: true, lineEndings: map[string]string{}}
	for _, name := range []string{filepath.Join(home, ".gitconfig"), filepath.Join(xdg, "git", "config")} {
		data, present, err := readLinuxHostStageOptionalConfig(ctx, access, name)
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
				if section.HasOption(short) {
					if _, set := facts.lineEndings[key]; !set {
						facts.lineEndings[key] = section.Option(short)
					}
				}
			}
		}
	}
	return facts, nil
}

func readLinuxHostStageOptionalConfig(ctx context.Context, access *linuxHostAccess, name string) (data []byte, present bool, retErr error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if err := linuxHostAbsolute(name); err != nil {
		return nil, false, capturedRefuse("operator_config_location_invalid")
	}
	parent, err := access.absolute(filepath.Dir(name))
	if linuxHostMissing(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, capturedRefuse("operator_config_parent_not_held")
	}
	defer func() { retErr = errors.Join(retErr, access.closeFile(parent)) }()
	pin, err := linuxHostOpen(parent, filepath.Base(name))
	if linuxHostMissing(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, capturedRefuse("operator_config_not_readable_or_stable")
	}
	defer func() { retErr = errors.Join(retErr, access.closeFile(pin)) }()
	before, err := linuxHostInfo(pin, false)
	if err != nil || before.mode&0o170000 != 0o100000 || before.size > 1<<20 {
		return nil, false, capturedRefuse("operator_config_type_link_or_size_not_supported")
	}
	file, err := access.readable(pin, false)
	if err != nil {
		return nil, false, capturedRefuse("operator_config_read_failed")
	}
	data, readErr := io.ReadAll(io.LimitReader(capturedContextReader{ctx, file}, before.size+1))
	after, infoErr := linuxHostInfo(pin, false)
	closeErr := access.closeFile(file)
	if readErr != nil || infoErr != nil || closeErr != nil || before != after || int64(len(data)) != before.size {
		return nil, false, errors.Join(capturedRefuse("operator_config_read_or_identity_changed"), readErr, infoErr, closeErr)
	}
	return data, true, nil
}
