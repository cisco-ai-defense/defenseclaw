//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

const (
	windowsTargetRuntimeJSONMaxBytes     = 1 << 20
	windowsTargetRuntimeManifestMaxBytes = 4 << 20
)

type windowsTargetRuntimeOptions struct {
	manifest string
	request  string
	claims   string
	output   string
}

var (
	windowsTargetRuntimeManifestTrust = managed.ValidateTrustedFilePath
	windowsTargetRuntimeRequestTrust  = managed.ValidateTrustedFilePath
	windowsTargetRuntimeAdminValidate = enterprisehooks.ValidateWindowsManagedRuntimeAdminFile
	windowsTargetRuntimeManifestLoad  = enterprisehooks.LoadManifest
)

func newWindowsTargetRuntimeCommand() *cobra.Command {
	command := &cobra.Command{
		Use:    "target-runtime",
		Short:  "Prepare target-owned Windows managed runtime roots",
		Hidden: true,
	}
	for _, action := range []string{"plan", "stage", "finalize", "cleanup"} {
		action := action
		opts := &windowsTargetRuntimeOptions{}
		child := &cobra.Command{
			Use:          action,
			Hidden:       true,
			Args:         cobra.NoArgs,
			SilenceUsage: true,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runWindowsTargetRuntimeAction(cmd, action, opts)
			},
		}
		flags := child.Flags()
		flags.StringVar(&opts.output, "output", "", "pre-created protected AdminFile report path")
		if action == "plan" {
			flags.StringVar(&opts.manifest, "manifest", "", "protected targets.yaml")
		} else {
			flags.StringVar(&opts.request, "request", "", "protected target-runtime plan JSON")
			if action == "finalize" || action == "cleanup" {
				flags.StringVar(&opts.claims, "claims", "", "protected target-runtime stage/final report JSON")
			}
		}
		command.AddCommand(child)
	}
	return command
}

func runWindowsTargetRuntimeAction(cmd *cobra.Command, action string, opts *windowsTargetRuntimeOptions) error {
	if opts == nil {
		return errors.New("target-runtime options are required")
	}
	// Authorization precedes every protected-file read so an unelevated caller
	// cannot use this hidden command as a manifest/transaction oracle.
	if err := enterpriseHooksNativePlatformPreflight(); err != nil {
		return err
	}
	output, err := requireWindowsTargetRuntimeProtectedPath(opts.output, "target-runtime output")
	if err != nil {
		return err
	}

	if action == "plan" {
		manifestPath, err := requireWindowsTargetRuntimeAbsolutePath(opts.manifest, "manifest")
		if err != nil {
			return err
		}
		manifest, digest, err := loadWindowsTargetRuntimeManifest(manifestPath)
		if err != nil {
			return err
		}
		plan, err := enterprisehooks.PlanWindowsManagedRuntimeRoots(manifest, manifestPath, digest)
		if err != nil {
			return err
		}
		if err := writeWindowsTargetRuntimeProtectedJSON(output, plan); err != nil {
			return err
		}
		return nil
	}

	requestPath, err := requireWindowsTargetRuntimeProtectedPath(opts.request, "target-runtime request")
	if err != nil {
		return err
	}
	var plan enterprisehooks.WindowsManagedRuntimePlan
	if err := readWindowsTargetRuntimeProtectedJSON(requestPath, &plan); err != nil {
		return fmt.Errorf("read protected target-runtime plan: %w", err)
	}
	manifest, digest, err := loadWindowsTargetRuntimeManifest(plan.ManifestPath)
	if err != nil {
		return err
	}
	request := enterprisehooks.WindowsManagedRuntimeRequest{
		SchemaVersion: enterprisehooks.WindowsManagedRuntimeRequestSchemaVersion,
		Plan:          plan,
	}
	if action == "finalize" || (action == "cleanup" && strings.TrimSpace(opts.claims) != "") {
		claimsPath, err := requireWindowsTargetRuntimeProtectedPath(opts.claims, "target-runtime claims")
		if err != nil {
			return err
		}
		var prior enterprisehooks.WindowsManagedRuntimeReport
		if err := readWindowsTargetRuntimeProtectedJSON(claimsPath, &prior); err != nil {
			return fmt.Errorf("read protected target-runtime claims: %w", err)
		}
		if err := validateWindowsTargetRuntimeClaimsReport(prior); err != nil {
			return err
		}
		request.Claims = prior.Claims
	}

	report := enterprisehooks.WindowsManagedRuntimeReport{
		SchemaVersion: enterprisehooks.WindowsManagedRuntimeReportSchemaVersion,
		Action:        action,
	}
	switch action {
	case "stage":
		report.Claims, err = enterprisehooks.StageWindowsManagedRuntimeRoots(
			plan,
			manifest,
			digest,
			func(claims []enterprisehooks.WindowsManagedRuntimeClaim) error {
				// Persist each newly authenticated inode while its staging and
				// profile handles still deny delete sharing. A process death after
				// FILE_CREATE therefore leaves either this identity journal or an
				// exact secret-marker staging inode recoverable from the plan.
				return writeWindowsTargetRuntimeProtectedJSON(output, enterprisehooks.WindowsManagedRuntimeReport{
					SchemaVersion: enterprisehooks.WindowsManagedRuntimeReportSchemaVersion,
					Action:        "stage",
					OK:            false,
					Claims:        claims,
				})
			},
		)
	case "finalize":
		report.Claims, err = enterprisehooks.FinalizeWindowsManagedRuntimeRoots(request, manifest, digest)
	case "cleanup":
		report.Claims, err = enterprisehooks.CleanupWindowsManagedRuntimeRoots(request, manifest, digest)
	default:
		return fmt.Errorf("unsupported target-runtime action %q", action)
	}
	report.OK = err == nil
	if err != nil {
		report.Error = err.Error()
	}
	if writeErr := writeWindowsTargetRuntimeProtectedJSON(output, report); writeErr != nil {
		return writeErr
	}
	if err != nil {
		// Detailed paths and recovery state remain only in the protected report.
		return windowsTargetRuntimePublicMutationError(action, err)
	}
	return nil
}

func loadWindowsTargetRuntimeManifest(path string) (enterprisehooks.Manifest, string, error) {
	var manifest enterprisehooks.Manifest
	path, err := requireWindowsTargetRuntimeAbsolutePath(path, "manifest")
	if err != nil {
		return manifest, "", err
	}
	if err := windowsTargetRuntimeManifestTrust(path, "target-runtime manifest"); err != nil {
		return manifest, "", err
	}
	if err := windowsTargetRuntimeAdminValidate(path); err != nil {
		return manifest, "", err
	}
	file, err := openWindowsTargetRuntimeFile(path, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ)
	if err != nil {
		return manifest, "", fmt.Errorf("pin target-runtime manifest: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > windowsTargetRuntimeManifestMaxBytes {
		return manifest, "", errors.New("target-runtime manifest is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, windowsTargetRuntimeManifestMaxBytes+1))
	if err != nil || len(data) > windowsTargetRuntimeManifestMaxBytes {
		return manifest, "", errors.New("read bounded target-runtime manifest")
	}
	// The pinned handle denies write/delete sharing while LoadManifest performs
	// its schema/platform validation by name, so both operations observe the
	// same immutable inode and bytes.
	manifest, err = windowsTargetRuntimeManifestLoad(path)
	if err != nil {
		return manifest, "", err
	}
	digest := sha256.Sum256(data)
	return manifest, hex.EncodeToString(digest[:]), nil
}

func readWindowsTargetRuntimeProtectedJSON(path string, destination any) error {
	if destination == nil {
		return errors.New("target-runtime JSON destination is required")
	}
	if err := windowsTargetRuntimeRequestTrust(path, "target-runtime protected JSON"); err != nil {
		return err
	}
	if err := windowsTargetRuntimeAdminValidate(path); err != nil {
		return err
	}
	file, err := openWindowsTargetRuntimeFile(path, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > windowsTargetRuntimeJSONMaxBytes {
		return errors.New("target-runtime JSON is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, windowsTargetRuntimeJSONMaxBytes+1))
	if err != nil || len(data) > windowsTargetRuntimeJSONMaxBytes {
		return errors.New("read bounded target-runtime JSON")
	}
	return decodeWindowsTargetRuntimeJSON(data, destination)
}

func decodeWindowsTargetRuntimeJSON(data []byte, destination any) error {
	if destination == nil {
		return errors.New("target-runtime JSON destination is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = errors.New("multiple JSON documents are not allowed")
		}
		return err
	}
	return nil
}

func writeWindowsTargetRuntimeProtectedJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > windowsTargetRuntimeJSONMaxBytes {
		return errors.New("target-runtime JSON exceeds protected output bound")
	}
	if err := windowsTargetRuntimeRequestTrust(path, "target-runtime protected output"); err != nil {
		return err
	}
	if err := windowsTargetRuntimeAdminValidate(path); err != nil {
		return err
	}
	file, err := openWindowsTargetRuntimeFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, windows.FILE_SHARE_READ)
	if err != nil {
		return err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return errors.New("target-runtime output is not a regular file")
	}
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != int64(len(data)) {
		return errors.New("target-runtime protected output changed identity or length during write")
	}
	return nil
}

func openWindowsTargetRuntimeFile(path string, access, share uint32) (*os.File, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return nil, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		ptr,
		access,
		share,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("wrap target-runtime protected file handle")
	}
	return file, nil
}

func requireWindowsTargetRuntimeAbsolutePath(raw, label string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("--%s is required", label)
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if !filepath.IsAbs(value) || filepath.Clean(value) != value || !sameWindowsEnterprisePathCLI(value, abs) {
		return "", fmt.Errorf("--%s must be an exact absolute path", label)
	}
	return abs, nil
}

func requireWindowsTargetRuntimeProtectedPath(raw, label string) (string, error) {
	path, err := requireWindowsTargetRuntimeAbsolutePath(raw, label)
	if err != nil {
		return "", err
	}
	if err := windowsTargetRuntimeRequestTrust(path, label); err != nil {
		return "", err
	}
	if err := windowsTargetRuntimeAdminValidate(path); err != nil {
		return "", err
	}
	return path, nil
}

func validateWindowsTargetRuntimeClaimsReport(report enterprisehooks.WindowsManagedRuntimeReport) error {
	if report.SchemaVersion != enterprisehooks.WindowsManagedRuntimeReportSchemaVersion || (report.Action != "stage" && report.Action != "finalize") {
		return errors.New("protected target-runtime claims have an unsupported schema or action")
	}
	return nil
}

func windowsTargetRuntimePublicMutationError(action string, _ error) error {
	return fmt.Errorf("target-runtime %s failed; inspect the protected report", action)
}
