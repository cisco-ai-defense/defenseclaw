// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/spf13/cobra"
)

// bundleOutputSchemaVersion is the schema of the sign and verify --json
// documents.
const bundleOutputSchemaVersion = 1

// maxBundleKeyFileBytes bounds a PEM key file and a detached signature file.
const maxBundleKeyFileBytes = 64 << 10

// Seams for tests: the clock, the bundle id entropy, whether this computer
// is a standalone managed device and how a credential is looked up there.
var (
	bundleNow            = time.Now
	bundleIDEntropy      io.Reader
	bundleManagedDevice  = managed.IsStandaloneManagedHost
	bundlePrivilege      = func() error { return nil }
	bundleSecretValue    = managedBundleSecretValue
	bundleSecureClient   = func() bool { return secureClientHost() }
	bundleDefaultAnchors = func() (string, error) { return enterprisebundle.AnchorsPath(runtime.GOOS) }
	// bundleAnchorTrust is the anchor file trust check on a device.
	bundleAnchorTrust = enterprisebundle.TrustCheck(enterprisebundle.TrustAnchorFile)
	// bundleAnchorsLstat inspects the installed anchor file before verify
	// reads it.
	bundleAnchorsLstat = os.Lstat
	// bundleDeviceRecordUnreadable reports a deployment record this account
	// cannot read (a standard user on Windows), so verify cannot tell
	// whether this is a managed device.
	bundleDeviceRecordUnreadable = func() bool { return false }
)

const enterpriseBundleLong = `Sign, verify and report signed policy bundles for the standalone
enterprise profile. A bundle carries config.yaml and the policy files it
names, a manifest with their hashes and the effective policy digest per
platform, and a detached signature. Devices trust the keys in their
MDM-installed anchor file (<etc>/trust/bundle-anchors.json). sign and verify
run offline and change nothing; status reports the bundle state of a managed
device; apply installs a bundle on a managed device (as root on Linux and
macOS, as an elevated administrator or SYSTEM on Windows).
Secure Client computers do not have them.`

func init() {
	enterpriseCmd.AddCommand(newEnterpriseBundleCommand())
}

// newEnterpriseBundleCommand builds `enterprise bundle`. The verbs read no
// DefenseClaw state, so they skip the daemon bootstrap; a Secure Client
// computer keeps the command tree of main (the group is absent there) and a
// run that still reaches a verb is refused before anything is read.
func newEnterpriseBundleCommand() *cobra.Command {
	group := &cobra.Command{
		Use:          "bundle",
		Short:        "Sign, verify and report signed policy bundles (standalone enterprise)",
		Long:         enterpriseBundleLong,
		Annotations:  map[string]string{secureClientAbsentAnnotation: "true"},
		SilenceUsage: true,
		// The verbs need no config, audit store or PID registration.
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	}
	group.SetFlagErrorFunc(lifecycleFlagError)
	group.AddCommand(newEnterpriseBundleSignCommand(), newEnterpriseBundleVerifyCommand(), newEnterpriseBundleStatusCommand(), newEnterpriseBundleApplyCommand())
	group.AddCommand(platformBundleVerbs()...)
	return group
}

type bundleSignOptions struct {
	in, out, key, keyID, publicKey, attachSig, tbsOut  string
	tenant, deviceGroup, createdBy, parent, rollbackOf string
	summary, minProductVersion                         string
	platforms, secretFiles                             []string
	version                                            uint64
	emitDigest, json                                   bool
}

var bundleComposeFlags = []string{"tenant", "device-group", "version", "created-by", "parent", "rollback-of", "summary", "min-product-version", "platform", "secret-file"}

func newEnterpriseBundleSignCommand() *cobra.Command {
	opts := &bundleSignOptions{}
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Validate a bundle directory and write a signed .dcbundle",
		Long: `Validate a bundle directory offline (no root, any OS) and write a signed
.dcbundle: files[] hashes, secret references, the effective policy digest
per platform and group reachability warnings. Errors refuse; warnings are
printed and recorded in the manifest.

Every credential config.yaml references needs --secret-file NAME=PATH with
the value the devices will store. The bundle never carries the value: its
secret_refs entry signs a SHA-256 of the tenant, the name and the value
(value_sha256), and a device refuses the bundle while it stores another
value (secret_ref_mismatch). To rotate a credential, sign a bundle with the
new value, store the value with enterprise secret set --bundle, then apply
the bundle.

For managed bundles, omit data_dir so each device uses its service state
directory: /var/lib/defenseclaw on Linux, /opt/cisco/defenseclaw/runtime on
macOS, or the registered ProgramData\Cisco\DefenseClaw\runtime on Windows.
/var/lib/defenseclaw-enterprise holds lifecycle receipts, not gateway data.
An explicit Windows data_dir is signable only when it equals the standard
C:\ProgramData\Cisco\DefenseClaw\runtime path. A device under another
ProgramData root also computes the digest for the standard layout and refuses
a signed digest that differs from it (digest_mismatch); it reports
digest_layout_unverifiable only when the signed digest equals that
standard-layout digest but its own root changes its digest.

Each device recomputes the digest for its platform. When the signer ran the
device's product version, on any OS, a different digest refuses the bundle
(digest_mismatch); a signer of another product version leaves the digest
digest_unverifiable. Sign with the release the devices run.

For an HSM or KMS key, run sign with --emit-digest to write the unsigned
bundle and print the SHA-256 to sign (ecdsa-p256-sha256; an ed25519 key
signs the exact bytes --tbs-out writes), then run sign --attach-sig with the
unsigned bundle, the signature and the public key.`,
		Example: `  defenseclaw-gateway enterprise bundle sign --in ./policy --out v12.dcbundle \
    --key signing.pem --key-id acme-2026a --tenant acme --device-group eng-laptops \
    --version 12 --created-by operator:alice --summary "Block HIGH for eng"`,
		Args:         bundleNoArgs,
		SilenceUsage: true,
		Annotations:  map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEnterpriseBundleSign(cmd, opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.in, "in", "", "bundle directory to sign (with --attach-sig: the unsigned .dcbundle)")
	f.StringVar(&opts.out, "out", "", "the .dcbundle file to write")
	f.StringVar(&opts.key, "key", "", "PEM private key (PKCS#8 Ed25519 or ECDSA P-256, or SEC 1 EC)")
	f.StringVar(&opts.keyID, "key-id", "", "the trust anchor key id of the signing key")
	f.StringVar(&opts.tenant, "tenant", "", "tenant id (must equal the anchor tenant)")
	f.StringVar(&opts.deviceGroup, "device-group", "", "target device group")
	f.Uint64Var(&opts.version, "version", 0, "bundle version, above trust anchor min_version and the last confirmed bundle version")
	f.StringVar(&opts.createdBy, "created-by", "", "principal: operator:<os-admin> or control-plane:<tenant>/<admin>")
	f.StringVar(&opts.parent, "parent", "", "bundle id this version was composed on")
	f.StringVar(&opts.rollbackOf, "rollback-of", "", "bundle id whose content this version re-publishes")
	f.StringVar(&opts.summary, "summary", "", "change summary shown in audit (512 characters at most)")
	f.StringVar(&opts.minProductVersion, "min-product-version", "", "lowest product version that may apply the bundle")
	f.StringSliceVar(&opts.platforms, "platform", nil, "target platform: linux, darwin or windows (repeat; default all three)")
	f.StringArrayVar(&opts.secretFiles, "secret-file", nil, "NAME=PATH: the value of credential NAME that the bundle binds (repeat once for every credential config.yaml references)")
	f.BoolVar(&opts.emitDigest, "emit-digest", false, "write the unsigned bundle and print the digest to sign with an HSM or KMS")
	f.StringVar(&opts.tbsOut, "tbs-out", "", "with --emit-digest: also write the exact bytes to sign (ed25519 HSMs)")
	f.StringVar(&opts.attachSig, "attach-sig", "", "attach this detached signature (DER, raw r||s or base64) to the unsigned bundle --in")
	f.StringVar(&opts.publicKey, "public-key", "", "with --attach-sig: PEM public key that must verify the signature")
	f.BoolVar(&opts.json, "json", false, "print the result as JSON")
	cmd.SetFlagErrorFunc(lifecycleFlagError)
	return cmd
}

type bundleVerifyOptions struct {
	bundle, anchors, platform string
	json                      bool
	// skipSecretStore leaves the stored credentials unchecked: secret set
	// --bundle verifies the bundle that binds a value it has not stored yet.
	skipSecretStore bool
}

func newEnterpriseBundleVerifyCommand() *cobra.Command {
	opts := &bundleVerifyOptions{}
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Check a bundle against the trust anchors without applying it",
		Long: `Run every bundle check without changing anything: trust anchor, key,
signature, manifest, tenant, device group and platform, version floor,
minimum product version, files[] hashes, inline secrets, secret references,
the config validator and the effective policy digest. On a standalone managed
device it also checks that every required credential is present.

A bundle must have a version above both floors: the min_version of the trust
anchors and the last confirmed bundle version; the confirmed bundle itself
passes as already_applied. On Linux and macOS a standard account cannot read
the confirmed state, so verify warns floor_unchecked and checks only the
anchor floor; apply checks again as root. On Windows the installed anchors
are readable only by administrators and SYSTEM, so run verify elevated; a
standard account gets not_admin. A bundle signed by a revoked key is refused
(key_revoked). A retired key verifies only the confirmed bundle, which needs
the confirmed state; any other bundle it signed is refused (key_expired).`,
		Args:         bundleNoArgs,
		SilenceUsage: true,
		Annotations:  map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEnterpriseBundleVerify(cmd, opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.bundle, "bundle", "", "the .dcbundle file or bundle directory")
	f.StringVar(&opts.anchors, "anchors", "", "trust anchor file (default <etc>/trust/bundle-anchors.json)")
	f.StringVar(&opts.platform, "platform", runtime.GOOS, "platform the bundle must target")
	f.BoolVar(&opts.json, "json", false, "print the result as JSON")
	cmd.SetFlagErrorFunc(lifecycleFlagError)
	return cmd
}

// bundleError is one errors[] entry.
type bundleError struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

type bundleSummary struct {
	BundleID      string   `json:"bundle_id"`
	Version       uint64   `json:"version"`
	TenantID      string   `json:"tenant_id"`
	DeviceGroup   string   `json:"device_group"`
	Platforms     []string `json:"platforms"`
	CreatedAt     string   `json:"created_at"`
	CreatedBy     string   `json:"created_by"`
	ChangeSummary string   `json:"change_summary,omitempty"`
	Parent        string   `json:"parent,omitempty"`
	RollbackOf    string   `json:"rollback_of,omitempty"`
}

func summarize(m *enterprisebundle.Manifest) *bundleSummary {
	if m == nil {
		return nil
	}
	return &bundleSummary{
		BundleID: m.BundleID, Version: m.Version, TenantID: m.TenantID, DeviceGroup: m.Target.DeviceGroup,
		Platforms: m.Target.Platforms, CreatedAt: m.CreatedAt, CreatedBy: m.CreatedBy,
		ChangeSummary: m.ChangeSummary, Parent: m.Parent, RollbackOf: m.RollbackOf,
	}
}

type bundleSignResult struct {
	SchemaVersion    int                               `json:"schema_version"`
	Command          string                            `json:"command"`
	OK               bool                              `json:"ok"`
	Result           string                            `json:"result"`
	Out              string                            `json:"out,omitempty"`
	Bundle           *bundleSummary                    `json:"bundle,omitempty"`
	ManifestSHA256   string                            `json:"manifest_sha256,omitempty"`
	KeyID            string                            `json:"key_id,omitempty"`
	Alg              string                            `json:"alg,omitempty"`
	ToBeSignedSHA256 string                            `json:"to_be_signed_sha256,omitempty"`
	ToBeSignedBase64 string                            `json:"to_be_signed_sha256_base64,omitempty"`
	TBSOut           string                            `json:"tbs_out,omitempty"`
	EffectivePolicy  *enterprisebundle.EffectivePolicy `json:"effective_policy,omitempty"`
	SecretRefs       []enterprisebundle.SecretRef      `json:"secret_refs"`
	Warnings         []enterprisebundle.Warning        `json:"warnings"`
	Errors           []bundleError                     `json:"errors"`
}

// bundleVerifyResult is the bundle verify --json document. SecretRefsMissing
// is set when the presence of every secret_refs credential was checked;
// RestartPrediction for a verified bundle on this device.
type bundleVerifyResult struct {
	SchemaVersion         int            `json:"schema_version"`
	Command               string         `json:"command"`
	OK                    bool           `json:"ok"`
	Result                string         `json:"result"`
	Platform              string         `json:"platform"`
	Anchors               string         `json:"anchors,omitempty"`
	AnchorTrust           string         `json:"anchor_trust,omitempty"`
	Bundle                *bundleSummary `json:"bundle,omitempty"`
	SignerKeyID           string         `json:"signer_key_id,omitempty"`
	Alg                   string         `json:"alg,omitempty"`
	Floor                 uint64         `json:"floor"`
	FloorSource           string         `json:"floor_source,omitempty"`
	EffectivePolicyDigest string         `json:"effective_policy_digest,omitempty"`
	ExpectedDigest        string         `json:"expected_digest,omitempty"`
	DigestVerified        bool           `json:"digest_verified"`
	SecretRefsMissing     *[]string      `json:"secret_refs_missing,omitempty"`
	SecretRefsMismatch    *[]string      `json:"secret_refs_mismatch,omitempty"`
	// SecretRefs is every secret_refs entry with its state (names and
	// booleans only), present exactly when SecretRefsMissing is.
	SecretRefs        *[]enterprisebundle.SecretRefState `json:"secret_refs,omitempty"`
	RestartPrediction *bundleRestartPrediction           `json:"restart_prediction,omitempty"`
	ConfigDrift       *bool                              `json:"config_drift,omitempty"`
	Warnings          []enterprisebundle.Warning         `json:"warnings"`
	Errors            []bundleError                      `json:"errors"`

	// manifest is the verified manifest, for secret set --bundle.
	manifest *enterprisebundle.Manifest
}

// bundleRefusal turns err into errors[] and the failure exit code
// (1603 on Windows, 1 elsewhere).
func bundleRefusal(err error) ([]bundleError, error) {
	var be *enterprisebundle.Error
	entry := bundleError{Code: "failed", Message: err.Error()}
	if errors.As(err, &be) {
		entry = bundleError{Code: string(be.Code), Path: be.Path, Message: be.Error()}
	}
	return []bundleError{entry}, withExitCode(err, bundleFailureExitCode())
}

func bundleFailureExitCode() int {
	if runtime.GOOS == "windows" {
		return enterprisestatus.WindowsExitFailure
	}
	return enterprisestatus.UnixExitFailure
}

// bundleNoArgs refuses a stray argument with the usage line and the
// invalid-arguments exit code of the enterprise lifecycle.
func bundleNoArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	return lifecycleFlagError(cmd, fmt.Errorf("unknown argument %q for %q", args[0], cmd.CommandPath()))
}

func bundleUsage(format string, args ...any) error {
	return invalidLifecycleArguments(fmt.Errorf(format, args...))
}

func secureClientBundleRefusal() error {
	return &enterprisebundle.Error{Code: enterprisebundle.CodeNotSupportedSecureClient,
		Detail: "policy bundles are not supported on a Secure Client computer"}
}

func runEnterpriseBundleSign(cmd *cobra.Command, opts *bundleSignOptions) error {
	res := &bundleSignResult{SchemaVersion: bundleOutputSchemaVersion, Command: "sign", Result: "refused",
		SecretRefs: []enterprisebundle.SecretRef{}, Warnings: []enterprisebundle.Warning{}, Errors: []bundleError{}}
	err := bundleSign(bundleContext(cmd), cmd, opts, res)
	if err != nil {
		var usage *exitCodeError
		if errors.As(err, &usage) && usage.ExitCode() == enterprisestatus.InvalidArgsExitCode(runtime.GOOS) {
			res.Errors = []bundleError{{Code: "invalid_arguments", Message: err.Error()}}
		} else {
			res.Errors, err = bundleRefusal(err)
		}
	}
	res.OK = err == nil
	return printBundleResult(cmd, opts.json, res, err, func(w io.Writer) { printSignText(w, res) })
}

func bundleSign(ctx context.Context, cmd *cobra.Command, opts *bundleSignOptions, res *bundleSignResult) error {
	if bundleSecureClient() {
		return secureClientBundleRefusal()
	}
	flags := cmd.Flags()
	if opts.in == "" || opts.out == "" {
		return bundleUsage("--in and --out are required")
	}
	if opts.attachSig != "" {
		for _, name := range append([]string{"key", "emit-digest", "tbs-out"}, bundleComposeFlags...) {
			if flags.Changed(name) {
				return bundleUsage("--attach-sig takes --in (the unsigned bundle), --out, --key-id and --public-key; --%s does not apply", name)
			}
		}
		if opts.keyID == "" || opts.publicKey == "" {
			return bundleUsage("--attach-sig needs --key-id and --public-key")
		}
		return bundleAttach(opts, res)
	}
	if flags.Changed("public-key") {
		return bundleUsage("--public-key applies only with --attach-sig")
	}
	if opts.emitDigest == (opts.key != "") {
		return bundleUsage("give exactly one of --key (sign here) and --emit-digest (sign with an HSM or KMS)")
	}
	if opts.tbsOut != "" && !opts.emitDigest {
		return bundleUsage("--tbs-out applies only with --emit-digest")
	}
	if opts.key != "" && opts.keyID == "" {
		return bundleUsage("--key needs --key-id")
	}
	for _, name := range []string{"tenant", "device-group", "version", "created-by"} {
		if !flags.Changed(name) {
			return bundleUsage("--%s is required", name)
		}
	}
	var signer crypto.Signer
	if opts.key != "" {
		var err error
		if signer, err = readBundlePrivateKey(opts.key); err != nil {
			return err
		}
	}
	secretValues, err := readBundleSecretFiles(opts.secretFiles)
	if err != nil {
		return err
	}
	defer func() {
		for _, value := range secretValues {
			clear(value)
		}
	}()
	info, err := os.Lstat(opts.in)
	if err != nil || !info.IsDir() {
		return bundleUsage("--in must be a bundle directory")
	}
	b, err := enterprisebundle.ReadDir(opts.in)
	if err != nil {
		return err
	}
	root, cleanup, err := stageBundle(b)
	if err != nil {
		return err
	}
	defer cleanup()
	now := bundleNow().UTC()
	id, err := enterprisebundle.NewBundleID(now, bundleIDEntropy)
	if err != nil {
		return err
	}
	m, raw, err := enterprisebundle.Compose(ctx, enterprisebundle.ComposeInput{
		Bundle: b, Root: root, BundleID: id, TenantID: opts.tenant, DeviceGroup: opts.deviceGroup,
		Platforms: opts.platforms, Version: opts.version, Parent: opts.parent, RollbackOf: opts.rollbackOf,
		CreatedAt: now, CreatedBy: opts.createdBy, ChangeSummary: opts.summary, MinProductVersion: opts.minProductVersion,
		ProductVersion: appVersion, HostPlatform: runtime.GOOS, Digester: bundleDigester, SecretValues: secretValues,
	})
	if err != nil {
		return err
	}
	res.Bundle = summarize(m)
	res.EffectivePolicy = &m.EffectivePolicy
	res.SecretRefs = append(res.SecretRefs, m.SecretRefs...)
	res.Warnings = append(res.Warnings, m.Warnings...)
	manifestSum := sha256.Sum256(raw)
	res.ManifestSHA256 = hex.EncodeToString(manifestSum[:])
	out := &enterprisebundle.Bundle{Manifest: raw, Files: b.Files}
	if opts.emitDigest {
		digest := enterprisebundle.SignedDigest(raw)
		res.ToBeSignedSHA256 = hex.EncodeToString(digest[:])
		res.ToBeSignedBase64 = base64.StdEncoding.EncodeToString(digest[:])
		if opts.tbsOut != "" {
			if err := safefile.Write(opts.tbsOut, enterprisebundle.SignedMessage(raw)); err != nil {
				return fmt.Errorf("write --tbs-out: %w", err)
			}
			res.TBSOut = opts.tbsOut
		}
		if err := writeBundleArchive(opts.out, out); err != nil {
			return err
		}
		res.Out, res.Result = opts.out, "digest_emitted"
		return nil
	}
	sig, err := enterprisebundle.Sign(raw, signer, opts.keyID)
	if err != nil {
		return err
	}
	if out.Signature, err = sig.Marshal(); err != nil {
		return err
	}
	if err := writeBundleArchive(opts.out, out); err != nil {
		return err
	}
	res.Out, res.Result, res.KeyID, res.Alg = opts.out, "signed", sig.KeyID, sig.Alg
	return nil
}

func bundleAttach(opts *bundleSignOptions, res *bundleSignResult) error {
	b, err := readBundleInput(opts.in)
	if err != nil {
		return err
	}
	if len(b.Signature) != 0 {
		return &enterprisebundle.Error{Code: enterprisebundle.CodeSignatureInvalid, Path: enterprisebundle.SignatureName, Detail: "the --in bundle is already signed"}
	}
	m, err := enterprisebundle.DecodeManifest(b.Manifest)
	if err != nil {
		return err
	}
	if err := enterprisebundle.CheckFiles(m, b); err != nil {
		return err
	}
	public, err := readBundlePublicKey(opts.publicKey)
	if err != nil {
		return err
	}
	raw, err := safefile.ReadRegularFileBounded(opts.attachSig, maxBundleKeyFileBytes)
	if err != nil {
		return bundleUsage("--attach-sig: %v", errors.Unwrap(err))
	}
	sig, err := enterprisebundle.AttachSignature(b.Manifest, public, opts.keyID, decodeDetachedSignature(raw))
	if err != nil {
		return err
	}
	if b.Signature, err = sig.Marshal(); err != nil {
		return err
	}
	if err := writeBundleArchive(opts.out, b); err != nil {
		return err
	}
	sum := sha256.Sum256(b.Manifest)
	res.Bundle, res.ManifestSHA256 = summarize(m), hex.EncodeToString(sum[:])
	res.EffectivePolicy = &m.EffectivePolicy
	res.SecretRefs = append(res.SecretRefs, m.SecretRefs...)
	res.Warnings = append(res.Warnings, m.Warnings...)
	res.Out, res.Result, res.KeyID, res.Alg = opts.out, "signature_attached", sig.KeyID, sig.Alg
	return nil
}

// decodeDetachedSignature accepts a signature file as base64 text or raw
// bytes (DER or r||s).
func decodeDetachedSignature(raw []byte) []byte {
	text := strings.TrimSpace(string(raw))
	if decoded, err := base64.StdEncoding.Strict().DecodeString(text); err == nil && len(decoded) > 0 {
		return decoded
	}
	return raw
}

func runEnterpriseBundleVerify(cmd *cobra.Command, opts *bundleVerifyOptions) error {
	res := &bundleVerifyResult{SchemaVersion: bundleOutputSchemaVersion, Command: "verify", Result: "refused",
		Platform: opts.platform, Warnings: []enterprisebundle.Warning{}, Errors: []bundleError{}}
	err := bundleVerify(bundleContext(cmd), opts, res)
	if err != nil {
		var usage *exitCodeError
		if errors.As(err, &usage) && usage.ExitCode() == enterprisestatus.InvalidArgsExitCode(runtime.GOOS) {
			res.Errors = []bundleError{{Code: "invalid_arguments", Message: err.Error()}}
		} else {
			res.Errors, err = bundleRefusal(err)
		}
	}
	res.OK = err == nil
	return printBundleResult(cmd, opts.json, res, err, func(w io.Writer) { printVerifyText(w, res) })
}

// bundleAnchorsNotAdmin is the refusal of verify for an account that cannot
// read the installed trust anchors.
func bundleAnchorsNotAdmin() error {
	return &enterprisebundle.Error{Code: enterprisebundle.CodeNotAdmin, Path: enterprisebundle.AnchorsName,
		Detail: "this account cannot read the installed trust anchors; run verify as root or as an elevated administrator or SYSTEM, or pass --anchors with a copy of the anchor file that this account can read"}
}

func bundleVerify(ctx context.Context, opts *bundleVerifyOptions, res *bundleVerifyResult) error {
	if bundleSecureClient() {
		return secureClientBundleRefusal()
	}
	if opts.bundle == "" {
		return bundleUsage("--bundle is required")
	}
	device := bundleManagedDevice()
	path, trust := opts.anchors, bundleAnchorTrust
	res.AnchorTrust = "checked"
	if path == "" {
		var err error
		if path, err = bundleDefaultAnchors(); err != nil {
			return err
		}
		// On Windows the installed anchors are readable only by
		// administrators and SYSTEM (GAP-0009): say how to verify instead
		// of calling the anchor file insecure.
		if _, err := bundleAnchorsLstat(path); errors.Is(err, fs.ErrPermission) {
			res.Anchors = path
			return bundleAnchorsNotAdmin()
		}
	} else if !device {
		// An administrator checking a bundle on a workstation names an
		// anchor file of their own; only a device needs it root-owned.
		trust, res.AnchorTrust = nil, "unchecked"
		message := "not a managed device: the anchor file ownership and permissions were not checked"
		if bundleDeviceRecordUnreadable() {
			message = "this account cannot read the deployment record, so the device checks were skipped and the anchor file ownership and permissions were not checked; run verify elevated for them"
		}
		res.Warnings = append(res.Warnings, enterprisebundle.Warning{Code: "anchor_trust_unchecked", Message: message})
	}
	res.Anchors = path
	b, err := readBundleInput(opts.bundle)
	if err != nil {
		return err
	}
	anchors, err := enterprisebundle.LoadAnchors(path, trust)
	if err != nil {
		// The file can be listed but not inspected or read by this account
		// (an ACL that denies it the file only).
		if opts.anchors == "" && errors.Is(err, fs.ErrPermission) {
			return bundleAnchorsNotAdmin()
		}
		return err
	}
	in := enterprisebundle.VerifyInput{
		Bundle: b, Anchors: anchors, Platform: opts.platform, Now: bundleNow().UTC(),
		ProductVersion: appVersion, Digester: bundleDigester,
	}
	if device {
		layout, err := enterprisebundle.Layout(opts.platform)
		if err != nil {
			return err
		}
		deviceLayout := enterprisebundle.DeviceLayoutFromManaged(layout)
		in.DeviceLayout = &deviceLayout
		if !opts.skipSecretStore {
			in.SecretValue = bundleSecretValue
		}
		// The version floor is the confirmed bundle of bundle-state.json. A
		// standard account cannot read it (apply checks it again as root);
		// a state that cannot be parsed refuses, so it never lowers the floor.
		store, err := bundleStore()
		if err != nil {
			return err
		}
		switch st, err := store.LoadState(); {
		case err == nil:
			in.Confirmed = st.Confirmed()
		case errors.Is(err, fs.ErrPermission):
			res.Warnings = append(res.Warnings, enterprisebundle.Warning{Code: "floor_unchecked",
				Message: "the bundle state is readable only by root or an administrator, so only the anchor min_version floor was checked"})
		default:
			return &enterprisebundle.Error{Code: enterprisebundle.CodeStateInvalid, Detail: err.Error()}
		}
	}
	var cleanup func()
	in.Stage = func(b *enterprisebundle.Bundle) (string, error) {
		root, done, err := stageBundle(b)
		cleanup = done
		return root, err
	}
	defer func() {
		if cleanup != nil {
			cleanup()
		}
	}()
	out, err := enterprisebundle.Verify(ctx, in)
	res.Bundle = summarize(out.Manifest)
	if out.Signature != nil {
		res.SignerKeyID, res.Alg = out.Signature.KeyID, out.Signature.Alg
	}
	res.Floor = out.Floor
	res.FloorSource = out.FloorSource
	res.EffectivePolicyDigest, res.ExpectedDigest, res.DigestVerified = out.EffectivePolicyDigest, out.ExpectedDigest, out.DigestVerified
	res.Warnings = append(res.Warnings, out.Warnings...)
	if out.SecretRefsMissing != nil {
		missing, mismatch, states := out.SecretRefsMissing, out.SecretRefsMismatch, out.SecretRefs
		res.SecretRefsMissing, res.SecretRefsMismatch, res.SecretRefs = &missing, &mismatch, &states
	}
	if err != nil {
		return err
	}
	res.manifest = out.Manifest
	res.Result = "verified"
	if out.AlreadyApplied {
		res.Result = "already_applied"
	}
	// An apply on this device runs for its own platform only.
	if device && opts.platform == runtime.GOOS {
		res.RestartPrediction, res.ConfigDrift = bundleVerifyRestartPrediction(opts.platform, out)
	}
	return nil
}

func printBundleResult(cmd *cobra.Command, asJSON bool, res any, err error, text func(io.Writer)) error {
	w := cmd.OutOrStdout()
	if asJSON {
		data, mErr := json.MarshalIndent(res, "", "  ")
		if mErr != nil {
			return mErr
		}
		fmt.Fprintln(w, string(data))
		silenceJSONReportedError(cmd, true, err)
		return err
	}
	text(w)
	return err
}

func printSignText(w io.Writer, res *bundleSignResult) {
	for _, warning := range res.Warnings {
		fmt.Fprintf(w, "warning: %s: %s\n", warning.Code, warning.Message)
	}
	if !res.OK || res.Bundle == nil {
		return
	}
	switch res.Result {
	case "digest_emitted":
		fmt.Fprintf(w, "Wrote the unsigned bundle %s (%s, version %d).\n", res.Out, res.Bundle.BundleID, res.Bundle.Version)
		fmt.Fprintf(w, "To-be-signed SHA-256: %s\n", res.ToBeSignedSHA256)
		fmt.Fprintln(w, "Sign it with the HSM or KMS, then run: enterprise bundle sign --attach-sig <sig> --in <unsigned> --out <signed> --key-id <id> --public-key <pem>")
	default:
		fmt.Fprintf(w, "Signed %s: %s, version %d, key %s (%s).\n", res.Out, res.Bundle.BundleID, res.Bundle.Version, res.KeyID, res.Alg)
	}
	if res.EffectivePolicy != nil {
		for _, platform := range res.Bundle.Platforms {
			fmt.Fprintf(w, "Effective policy %s: %s\n", platform, res.EffectivePolicy.Digests[platform])
			for _, component := range res.EffectivePolicy.Components[platform] {
				fmt.Fprintf(w, "  %s: %s\n", component.Name, component.Digest)
			}
		}
	}
}

func printVerifyText(w io.Writer, res *bundleVerifyResult) {
	for _, warning := range res.Warnings {
		fmt.Fprintf(w, "warning: %s: %s\n", warning.Code, warning.Message)
	}
	if res.SecretRefsMissing != nil && len(*res.SecretRefsMissing) > 0 {
		fmt.Fprintf(w, "Credentials missing: %s (store them with enterprise secret set before the apply).\n", strings.Join(*res.SecretRefsMissing, ", "))
	}
	if res.SecretRefsMismatch != nil && len(*res.SecretRefsMismatch) > 0 {
		fmt.Fprintf(w, "Credentials not the signed value: %s (store the signed values with enterprise secret set --bundle before the apply).\n", strings.Join(*res.SecretRefsMismatch, ", "))
	}
	if !res.OK {
		return
	}
	switch res.Result {
	case "already_applied":
		fmt.Fprintf(w, "Bundle %s version %d is the bundle already applied.\n", res.Bundle.BundleID, res.Bundle.Version)
		if res.ConfigDrift != nil && *res.ConfigDrift {
			fmt.Fprintln(w, "The installed config.yaml is not this bundle's config: apply the bundle again to repair it.")
		}
	default:
		fmt.Fprintf(w, "Bundle %s version %d verified for %s (key %s, floor %d).\n", res.Bundle.BundleID, res.Bundle.Version, res.Platform, res.SignerKeyID, res.Floor)
	}
	fmt.Fprintf(w, "Effective policy digest: %s\n", res.EffectivePolicyDigest)
	if p := res.RestartPrediction; p != nil {
		line := "Gateway restart on apply: " + p.GatewayRestart
		if len(p.ReasonCodes) > 0 {
			line += " (" + strings.Join(p.ReasonCodes, ", ") + ")"
		}
		if len(p.Settings) > 0 {
			line += "; settings: " + strings.Join(p.Settings, ", ")
		}
		fmt.Fprintln(w, line)
	}
}

func bundleDigester(ctx context.Context, cfg *config.Config, raw []byte, goos, root string) (string, error) {
	policy, err := gateway.ComputeEffectivePolicyFor(ctx, cfg, gateway.EffectivePolicyOptions{GOOS: goos, BundleRoot: root, Raw: raw})
	if err == nil {
		enterprisebundle.ReportPolicyComponents(ctx, policy.Components)
	}
	return policy.Digest, err
}

// readBundleSecretFiles reads the --secret-file NAME=PATH values bundle
// sign binds, as the gateway reads a stored credential
// (managed.ReadCredentialSource).
func readBundleSecretFiles(specs []string) (map[string][]byte, error) {
	values := map[string][]byte{}
	for _, spec := range specs {
		name, path, ok := strings.Cut(spec, "=")
		if !ok || path == "" || !config.ValidEnterpriseCredentialName(name) {
			return nil, bundleUsage("--secret-file takes NAME=PATH with an enterprise credential name (lowercase letters, digits and dashes)")
		}
		if _, dup := values[name]; dup {
			return nil, bundleUsage("--secret-file names the credential %s twice", name)
		}
		value, err := managed.ReadCredentialSource(path)
		if err != nil {
			return nil, bundleUsage("--secret-file %s: %v", name, err)
		}
		values[name] = value
	}
	return values, nil
}

// readBundleInput reads a .dcbundle file or a bundle directory.
func readBundleInput(path string) (*enterprisebundle.Bundle, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, &enterprisebundle.Error{Code: enterprisebundle.CodeArchiveInvalid, Detail: "the bundle path does not exist"}
	}
	if info.IsDir() {
		return enterprisebundle.ReadDir(path)
	}
	raw, err := safefile.ReadRegularFileBounded(path, enterprisebundle.MaxCompressedBytes+1)
	if err != nil {
		return nil, &enterprisebundle.Error{Code: enterprisebundle.CodeArchiveInvalid, Detail: "not a regular bundle file of at most 4 MiB"}
	}
	return enterprisebundle.ReadArchive(bytes.NewReader(raw))
}

// stageBundle writes the bundle files to a new private directory: the
// config loader and the digest read exactly the bytes whose hashes were
// checked, never the input path again.
func stageBundle(b *enterprisebundle.Bundle) (string, func(), error) {
	root, err := os.MkdirTemp("", "dcbundle-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(root) }
	for _, name := range b.Paths() {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			cleanup()
			return "", func() {}, err
		}
		if err := os.WriteFile(full, b.Files[name], 0o600); err != nil {
			cleanup()
			return "", func() {}, err
		}
	}
	return root, cleanup, nil
}

func writeBundleArchive(path string, b *enterprisebundle.Bundle) error {
	var buf bytes.Buffer
	if err := enterprisebundle.WriteArchive(&buf, b); err != nil {
		return err
	}
	if buf.Len() > enterprisebundle.MaxCompressedBytes {
		return &enterprisebundle.Error{Code: enterprisebundle.CodeArchiveInvalid, Detail: "the signed bundle is larger than 4 MiB"}
	}
	if err := safefile.Write(path, buf.Bytes()); err != nil {
		return fmt.Errorf("write --out: %w", err)
	}
	return nil
}

func readBundlePEM(path, flag string) (*pem.Block, error) {
	raw, err := safefile.ReadRegularFileBounded(path, maxBundleKeyFileBytes)
	if err != nil {
		return nil, bundleUsage("--%s: cannot read the key file", flag)
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, bundleUsage("--%s: want one PEM block", flag)
	}
	return block, nil
}

func readBundlePrivateKey(path string) (crypto.Signer, error) {
	block, err := readBundlePEM(path, "key")
	if err != nil {
		return nil, err
	}
	var key any
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "ENCRYPTED PRIVATE KEY":
		return nil, bundleUsage("--key: the key is encrypted; decrypt it to a protected file or sign with --emit-digest and an HSM or KMS")
	default:
		return nil, bundleUsage("--key: want a PRIVATE KEY or EC PRIVATE KEY PEM block")
	}
	if err != nil {
		return nil, bundleUsage("--key: not a valid private key")
	}
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		if _, err := enterprisebundle.KeyAlg(k.Public()); err == nil {
			return k, nil
		}
	}
	return nil, bundleUsage("--key: want an Ed25519 or ECDSA P-256 key")
}

func readBundlePublicKey(path string) (crypto.PublicKey, error) {
	block, err := readBundlePEM(path, "public-key")
	if err != nil {
		return nil, err
	}
	if block.Type != "PUBLIC KEY" {
		return nil, bundleUsage("--public-key: want a PUBLIC KEY PEM block")
	}
	public, _, err := enterprisebundle.ParsePublicKey(block.Bytes)
	if err != nil {
		return nil, bundleUsage("--public-key: %v", err)
	}
	return public, nil
}

func bundleContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}
