//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

var windowsNamespacePurgeFinalPathResolver = resolveWindowsNamespacePurgeFinalPath

type windowsNamespacePurgeOptions struct {
	request string
	output  string
}

func newWindowsNamespacePurgeCommand() *cobra.Command {
	opts := &windowsNamespacePurgeOptions{}
	command := &cobra.Command{
		Use:          "namespace-root-cleanup",
		Short:        "Remove one authenticated abandoned Windows install root",
		Hidden:       true,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runWindowsNamespacePurge(opts)
		},
	}
	flags := command.Flags()
	flags.StringVar(&opts.request, "request", "", "protected exact-root cleanup request")
	flags.StringVar(&opts.output, "output", "", "pre-created protected AdminFile report path")
	return command
}

func runWindowsNamespacePurge(opts *windowsNamespacePurgeOptions) error {
	if opts == nil {
		return errors.New("namespace-root-cleanup options are required")
	}
	if err := enterpriseHooksNativePlatformPreflight(); err != nil {
		return err
	}
	requestPath, err := requireWindowsTargetRuntimeProtectedPath(
		opts.request,
		"target-runtime request",
	)
	if err != nil {
		return err
	}
	outputPath, err := requireWindowsTargetRuntimeProtectedPath(
		opts.output,
		"target-runtime output",
	)
	if err != nil {
		return err
	}

	var request enterprisehooks.WindowsNamespacePurgeRequest
	if err := readWindowsTargetRuntimeProtectedJSON(requestPath, &request); err != nil {
		return fmt.Errorf("read protected exact-root cleanup request: %w", err)
	}
	if err := validateWindowsNamespacePurgeExchangePaths(
		requestPath,
		outputPath,
		request.Root,
	); err != nil {
		return err
	}
	report, purgeErr := enterprisehooks.PurgeWindowsNamespaceRoot(request)
	if purgeErr != nil {
		report.OK = false
		report.Error = purgeErr.Error()
	}
	if err := writeWindowsTargetRuntimeProtectedJSON(outputPath, report); err != nil {
		return err
	}
	if purgeErr != nil {
		return errors.New("namespace-root-cleanup failed; inspect the protected report")
	}
	return nil
}

func validateWindowsNamespacePurgeExchangePaths(requestPath, outputPath, root string) error {
	if err := validateWindowsNamespacePurgeExchangePathStrings(
		requestPath,
		outputPath,
		root,
	); err != nil {
		return err
	}
	rootFinal, rootExists, err := windowsNamespacePurgeFinalPathResolver(root, true)
	if err != nil {
		return fmt.Errorf("resolve final namespace-root-cleanup root: %w", err)
	}
	if !rootExists {
		return nil
	}
	requestFinal, requestExists, err := windowsNamespacePurgeFinalPathResolver(requestPath, false)
	if err != nil || !requestExists {
		if err == nil {
			err = errors.New("request disappeared")
		}
		return fmt.Errorf("resolve final namespace-root-cleanup request: %w", err)
	}
	outputFinal, outputExists, err := windowsNamespacePurgeFinalPathResolver(outputPath, false)
	if err != nil || !outputExists {
		if err == nil {
			err = errors.New("output disappeared")
		}
		return fmt.Errorf("resolve final namespace-root-cleanup output: %w", err)
	}
	return validateWindowsNamespacePurgeExchangePathStrings(
		requestFinal,
		outputFinal,
		rootFinal,
	)
}

func validateWindowsNamespacePurgeExchangePathStrings(requestPath, outputPath, root string) error {
	if sameWindowsEnterprisePathCLI(requestPath, outputPath) {
		return errors.New("namespace-root-cleanup request and output must be distinct files")
	}
	cleanRoot := filepath.Clean(root)
	if cleanRoot == "." || !filepath.IsAbs(cleanRoot) {
		return errors.New("namespace-root-cleanup root must be an absolute path")
	}
	for _, entry := range []struct {
		label string
		path  string
	}{
		{label: "request", path: requestPath},
		{label: "output", path: outputPath},
	} {
		cleanEntry := filepath.Clean(entry.path)
		if !strings.EqualFold(
			filepath.VolumeName(cleanRoot),
			filepath.VolumeName(cleanEntry),
		) {
			continue
		}
		relative, err := filepath.Rel(cleanRoot, cleanEntry)
		if err != nil {
			return fmt.Errorf("resolve namespace-root-cleanup %s against root: %w", entry.label, err)
		}
		if relative == "." ||
			(relative != ".." && !strings.HasPrefix(relative, `..\`)) {
			return fmt.Errorf("namespace-root-cleanup %s must be outside the cleanup root", entry.label)
		}
	}
	return nil
}

func resolveWindowsNamespacePurgeFinalPath(path string, directory bool) (string, bool, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return "", false, err
	}
	pointer, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return "", false, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer windows.CloseHandle(handle)
	buffer := make([]uint16, 512)
	for {
		length, err := windows.GetFinalPathNameByHandle(
			handle,
			&buffer[0],
			uint32(len(buffer)),
			0,
		)
		if err != nil {
			return "", false, err
		}
		if length < uint32(len(buffer)) {
			final := windows.UTF16ToString(buffer[:length])
			if strings.HasPrefix(final, `\\?\UNC\`) {
				final = `\\` + strings.TrimPrefix(final, `\\?\UNC\`)
			} else {
				final = strings.TrimPrefix(final, `\\?\`)
			}
			return filepath.Clean(final), true, nil
		}
		buffer = make([]uint16, int(length)+1)
	}
}
