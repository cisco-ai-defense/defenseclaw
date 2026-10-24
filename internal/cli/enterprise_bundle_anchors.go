// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

type bundleAnchorsOptions struct {
	file     string
	lockWait time.Duration
	json     bool
}

// bundleAnchorsResult is the anchors install --json document
// (packaging/mdm/contract/anchors-install.schema.json).
type bundleAnchorsResult struct {
	SchemaVersion int    `json:"schema_version"`
	Command       string `json:"command"`
	OK            bool   `json:"ok"`
	// Result is installed, replaced, unchanged or refused.
	Result         string                     `json:"result"`
	Anchors        string                     `json:"anchors"`
	SHA256         string                     `json:"sha256,omitempty"`
	PreviousSHA256 string                     `json:"previous_sha256,omitempty"`
	TenantID       string                     `json:"tenant_id,omitempty"`
	KeyIDs         []string                   `json:"key_ids,omitempty"`
	Warnings       []enterprisebundle.Warning `json:"warnings"`
	Errors         []bundleError              `json:"errors"`
}

// platformBundleVerbs are the bundle verbs only Linux and macOS have.
func platformBundleVerbs() []*cobra.Command {
	return []*cobra.Command{newEnterpriseBundleAnchorsCommand(), newEnterpriseBundleFloorCheckCommand()}
}

func newEnterpriseBundleAnchorsCommand() *cobra.Command {
	group := &cobra.Command{
		Use:          "anchors",
		Short:        "Install the bundle trust anchors (root, Linux and macOS)",
		SilenceUsage: true,
		Annotations:  map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
	}
	group.SetFlagErrorFunc(lifecycleFlagError)
	opts := &bundleAnchorsOptions{}
	install := &cobra.Command{
		Use:   "install",
		Short: "Install a trust anchor file on this managed device (root)",
		Long: `Install the trust anchor file that bundle signatures are checked against
(<etc>/trust/bundle-anchors.json) on this Linux or macOS standalone managed
device, for a management agent that runs without the MDM kit. The file named
by --file must be a valid anchor file and, like the installed file, owned by
root with neither it nor any folder above it writable by another account or a
link; it is read once and exactly those bytes are written, under the lifecycle
lock, root-owned with mode 0644. A byte-identical file writes nothing. When the
installed file fails its check after the write, the previous file is put back.
key_unknown and key_revoked warn when the new anchors no longer trust the
signer of the confirmed bundle; that bundle keeps enforcing, and the next
bundle must be signed by an active key. Every install that changes the
file, is refused or fails is recorded as a config.trust_anchors.changed audit
event (hashes and key ids only), reported by the gateway when it runs; an
install that cannot be recorded is refused (state_invalid) before the file is
written. The result also carries sha256, previous_sha256 and key_ids. Exit codes: 0, 1
(errors[].code names the refusal), 2 usage, 75 busy. On Windows, use enterprise windows ensure --profile standalone
--trust-anchors <file>.`,
		Example:      `  defenseclaw-gateway enterprise bundle anchors install --file /var/lib/acme-agent/trust/bundle-anchors.json --lock-wait 10m --json`,
		Args:         bundleNoArgs,
		SilenceUsage: true,
		Annotations:  map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEnterpriseBundleAnchorsInstall(cmd, opts)
		},
	}
	f := install.Flags()
	f.StringVar(&opts.file, "file", "", "the bundle-anchors.json to install, in a root-only folder")
	addLockWaitFlag(f, &opts.lockWait)
	f.BoolVar(&opts.json, "json", false, "print the result as JSON")
	install.SetFlagErrorFunc(lifecycleFlagError)
	group.AddCommand(install)
	return group
}

func runEnterpriseBundleAnchorsInstall(cmd *cobra.Command, opts *bundleAnchorsOptions) error {
	res := &bundleAnchorsResult{SchemaVersion: bundleOutputSchemaVersion, Command: "anchors install", Result: "refused",
		Warnings: []enterprisebundle.Warning{}, Errors: []bundleError{}}
	err := bundleAnchorsInstall(bundleContext(cmd), cmd, opts, res)
	if err != nil {
		var usage *exitCodeError
		if errors.As(err, &usage) && usage.ExitCode() == enterprisestatus.InvalidArgsExitCode(runtime.GOOS) {
			res.Errors = []bundleError{{Code: "invalid_arguments", Message: err.Error()}}
		} else {
			code := enterprisestatus.UnixExitFailure
			if enterprisebundle.CodeOf(err) == enterprisebundle.CodeLifecycleBusy {
				code = enterprisestatus.UnixExitBusy
			}
			res.Errors, _ = bundleRefusal(err)
			err = withExitCode(err, code)
		}
	}
	res.OK = err == nil
	return printBundleResult(cmd, opts.json, res, err, func(w io.Writer) { printAnchorsText(w, res) })
}

// bundleAnchorsInstall refuses a Secure Client computer and a computer that
// is not a standalone managed device (a per-user install) before anything
// is read, then installs through the lifecycle.
func bundleAnchorsInstall(ctx context.Context, cmd *cobra.Command, opts *bundleAnchorsOptions, res *bundleAnchorsResult) error {
	if bundleSecureClient() {
		return secureClientBundleRefusal()
	}
	if path, err := bundleDefaultAnchors(); err == nil {
		res.Anchors = path
	}
	if !bundleManagedDevice() {
		return &enterprisebundle.Error{Code: enterprisebundle.CodeNotManaged,
			Detail: "this computer is not a standalone managed device; install the enterprise profile first"}
	}
	if opts.file == "" {
		return bundleUsage("--file is required")
	}
	if err := checkLockWait(cmd, opts.lockWait); err != nil {
		return err
	}
	src, err := filepath.Abs(opts.file)
	if err != nil {
		return bundleUsage("--file: %v", err)
	}
	env, err := newUnixLifecycleEnv(runtime.GOOS)
	if err != nil {
		return &enterprisebundle.Error{Code: enterprisebundle.CodeStateInvalid, Detail: err.Error()}
	}
	if opts.lockWait > 0 {
		env.LockTimeout = opts.lockWait
	}
	out, err := env.InstallBundleAnchors(ctx, src)
	if out != nil {
		res.Anchors, res.SHA256 = out.Path, out.SHA256
		if out.Unrecorded != nil {
			res.Warnings = append(res.Warnings, changeUnrecordedWarning(out.Unrecorded))
		}
		if out.ReleaseUnflushed != nil {
			res.Warnings = append(res.Warnings, changeReleaseUnflushedWarning(out.ReleaseUnflushed))
		}
	}
	if err != nil {
		return err
	}
	res.Result, res.PreviousSHA256, res.TenantID = out.Result, out.PreviousSHA256, out.Anchors.TenantID
	for _, key := range out.Anchors.Keys {
		res.KeyIDs = append(res.KeyIDs, key.KeyID)
	}
	if warning := bundleSignerWarning(out.Anchors, out.SignerKeyID); warning != nil {
		res.Warnings = append(res.Warnings, *warning)
	}
	return nil
}

func printAnchorsText(w io.Writer, res *bundleAnchorsResult) {
	for _, warning := range res.Warnings {
		fmt.Fprintf(w, "warning: %s: %s\n", warning.Code, warning.Message)
	}
	if !res.OK {
		return
	}
	keys := strings.Join(res.KeyIDs, ", ")
	switch res.Result {
	case "unchanged":
		fmt.Fprintf(w, "Trust anchors %s already hold this file (sha256 %s); nothing written.\n", res.Anchors, res.SHA256)
	case "installed":
		fmt.Fprintf(w, "Installed trust anchors %s (sha256 %s, keys %s); this device now takes signed bundles.\n", res.Anchors, res.SHA256, keys)
	default:
		fmt.Fprintf(w, "Replaced trust anchors %s (sha256 %s, was %s; keys %s).\n", res.Anchors, res.SHA256, res.PreviousSHA256, keys)
	}
}
