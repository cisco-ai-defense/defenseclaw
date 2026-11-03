// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

const (
	macCoworkDir         = "/Library/Application Support/Cisco/DefenseClaw/Cowork"
	macCoworkPreferences = "/Library/Managed Preferences/com.anthropic.claudefordesktop.plist"
	codeCoworkIncomplete = "cowork_vm_sensor_incomplete"
)

func (e *Env) coworkPackageName() (string, error) {
	arch := e.GOARCH
	if arch == "" {
		arch = runtime.GOARCH
		if e.GOOS == "darwin" {
			// A translated amd64 process on Apple silicon still needs the
			// arm64 VM package. -i tolerates the absent Intel optional key.
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			out, err := e.Runner.Run(ctx, "sysctl", "-in", "hw.optional.arm64")
			if err != nil {
				return "", fmt.Errorf("inspect Cowork VM native architecture: %w", err)
			}
			switch strings.TrimSpace(string(out.Stdout)) {
			case "1":
				arch = "arm64"
			case "0":
				arch = "amd64"
			case "": // Intel macOS versions that do not expose this key.
			default:
				return "", fmt.Errorf("cannot determine Cowork VM native architecture")
			}
		}
	}
	if arch != "amd64" && arch != "arm64" {
		return "", fmt.Errorf("Cowork VM sensor does not support host architecture %s", arch)
	}
	return "defenseclaw-cowork-" + arch + ".tar.gz", nil
}

// planCoworkVM contributes to the existing lifecycle snapshot and rollback.
// MDM owns Claude Desktop's profile; this lifecycle never edits its preferences.
func (l *lifecycle) planCoworkVM(p *plan, record *Deployment) error {
	c := p.config.Loaded.Enterprise.CoworkVMSensor
	if c.Mode != "on" {
		if l.opts.CoworkPackage != "" || l.opts.CoworkSignature != "" {
			return fmt.Errorf("Cowork artifact inputs require enterprise.cowork_vm_sensor.mode: on")
		}
		return nil
	}
	if l.env.GOOS != "darwin" {
		return fmt.Errorf("enterprise.cowork_vm_sensor is supported only on macOS and Windows")
	}
	name, err := l.env.coworkPackageName()
	if err != nil {
		return err
	}
	assets, err := l.coworkInputs(p, name)
	if err != nil {
		return err
	}
	if l.opts.CoworkPackage != "" && l.opts.CoworkSignature == "" && c.SignatureSHA256 == "" {
		// An unowned signature must not be hidden by explicit unsigned
		// staging and then break the next ordinary repair from this cache.
		sigPath := filepath.Join(c.SourceDir, name+".sig")
		if _, err := os.Lstat(l.env.P(sigPath)); !errors.Is(err, os.ErrNotExist) {
			digest, digestErr := sha256File(l.env.P(sigPath))
			if err != nil || digestErr != nil || record == nil || record.Files[sigPath] == "" || record.Files[sigPath] != digest {
				return fmt.Errorf("Cowork cache signature %s is not an unchanged DefenseClaw file; remove it or configure its signature_sha256 before delivery", sigPath)
			}
		}
	}
	args, err := c.InstallArguments()
	if err != nil {
		return err
	}
	files := []desiredFile{{Path: filepath.Join(macCoworkDir, name+".args"), Data: []byte(args), SHA: sha256Bytes([]byte(args)), Mode: 0o644, Owner: rootOwner(), Kind: "cowork_vm_args"}}
	for _, asset := range assets {
		source := asset.source
		info, err := os.Lstat(l.env.P(source))
		if errors.Is(err, os.ErrNotExist) && asset.suffix == ".sig" && c.SignatureSHA256 == "" && !asset.cache {
			// The release can be staged before its production key arrives.
			// verify reports incomplete until the signature is delivered.
			continue
		}
		if err != nil {
			return err
		}
		limit := int64(512 << 20)
		if asset.suffix == ".sig" {
			limit = 1 << 20
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
			return fmt.Errorf("Cowork VM source %s must be a nonempty regular file of at most %d bytes", source, limit)
		}
		if err := l.env.checkCoworkPath(source, false); err != nil {
			return fmt.Errorf("Cowork VM source: %w", err)
		}
		digest, err := sha256File(l.env.P(source))
		if err != nil {
			return err
		}
		expected := c.PackageSHA256
		if asset.suffix == ".sig" {
			expected = c.SignatureSHA256
		}
		if expected == "" || digest != expected {
			return fmt.Errorf("Cowork VM source %s does not match its configured SHA-256 release pin", source)
		}
		files = append(files, desiredFile{Path: filepath.Join(macCoworkDir, name+asset.suffix), Src: l.env.P(source), SHA: digest, Mode: 0o644, Owner: rootOwner(), Kind: "cowork_vm_asset"})
		cachePath := filepath.Join(c.SourceDir, name+asset.suffix)
		fixedCache := filepath.Join(l.env.Layout.InstallRoot, "share", "cowork")
		if c.SourceDir == fixedCache && (asset.cache || (record != nil && record.Files[cachePath] != "")) {
			files = append(files, desiredFile{Path: cachePath, Src: l.env.P(source), SHA: digest, Mode: 0o600, Owner: rootOwner(), Kind: "cowork_vm_cache"})
		}
	}
	// Check every existing destination ancestor before the transaction reads
	// preimages. Shared directories remain under the administrator's control.
	for path := macCoworkDir; path != "/"; path = filepath.Dir(path) {
		if _, err := os.Lstat(l.env.P(path)); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := l.env.checkCoworkPath(path, true); err != nil {
			return fmt.Errorf("Cowork VM destination: %w", err)
		}
	}
	for _, file := range files {
		if _, err := os.Lstat(l.env.P(file.Path)); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if record == nil || record.Files[file.Path] == "" {
			return fmt.Errorf("Cowork VM destination %s already exists and was not written by DefenseClaw; move it aside before enabling delivery", file.Path)
		}
	}
	for _, path := range []string{"/Library/Application Support/Cisco", "/Library/Application Support/Cisco/DefenseClaw", macCoworkDir} {
		p.dirs = append(p.dirs, desiredDir{Path: path, Mode: 0o755, Owner: rootOwner(), External: path != macCoworkDir})
	}
	p.files = append(p.files, files...)
	return nil
}

// checkCoworkPath includes ACL and ancestor checks in production. Walking
// canonical paths also makes the ownership and no-symlink rules testable in
// the fake root without trusting the host's /tmp directory.
func (e *Env) checkCoworkPath(path string, dir bool) error {
	if err := e.Trust(e.P(path), map[bool]TrustKind{true: TrustAdminDir, false: TrustAdminFile}[dir]); err != nil {
		return err
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(e.P(current))
		if err != nil {
			return err
		}
		wantDir := dir || current != path
		if info.Mode()&os.ModeSymlink != 0 || (wantDir && !info.IsDir()) || (!wantDir && !info.Mode().IsRegular()) {
			return fmt.Errorf("%s is not a plain %s", current, map[bool]string{true: "directory", false: "file"}[wantDir])
		}
		uid, _, err := e.OwnerOf(e.P(current))
		if err != nil {
			return err
		}
		if uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s must be root-owned and not writable by group or others", current)
		}
		if current == "/" || current == "." {
			return nil
		}
	}
}

func isCoworkPath(path string) bool {
	if filepath.Dir(path) != macCoworkDir {
		return false
	}
	for _, arch := range []string{"amd64", "arm64"} {
		name := "defenseclaw-cowork-" + arch + ".tar.gz"
		if filepath.Base(path) == name || filepath.Base(path) == name+".sig" || filepath.Base(path) == name+".args" {
			return true
		}
	}
	return false
}

func (e *Env) checkCoworkInstalledPath(path string) error {
	if err := e.checkCoworkPath(path, false); err != nil {
		return err
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(e.P(current))
		if err != nil {
			return err
		}
		want := os.FileMode(0o111)
		if current == path {
			want = 0o444
		}
		if info.Mode().Perm()&want != want {
			return fmt.Errorf("%s must be readable or traversable by Claude Desktop's standard user", current)
		}
		if current == "/" || current == "." {
			return nil
		}
	}
}

func (l *lifecycle) verifyCoworkFiles(record *Deployment) []string {
	var problems []string
	for _, path := range sortedKeys(record.Files) {
		if !isCoworkPath(path) {
			continue
		}
		if err := l.env.checkCoworkInstalledPath(path); err != nil {
			problems = append(problems, fmt.Sprintf("Cowork VM delivery %s: %v; run repair to restore readable file and directory modes", path, err))
		}
	}
	return problems
}

// Only delete an unchanged, recorded Cowork file. An administrator's later
// replacement is preserved on disable, architecture changes and uninstall.
func (l *lifecycle) removeCoworkFileAllowed(record *Deployment, path string) bool {
	if !isCoworkPath(path) {
		return true
	}
	if _, err := os.Lstat(l.env.P(path)); errors.Is(err, os.ErrNotExist) {
		return true
	}
	digest, err := sha256File(l.env.P(path))
	if record == nil || record.Files[path] == "" || err != nil || record.Files[path] != digest {
		l.result.AddWarning(codeCoworkIncomplete, "kept "+path+": it no longer matches the file DefenseClaw wrote")
		return false
	}
	if err := l.env.checkCoworkPath(filepath.Dir(path), true); err != nil {
		l.result.AddWarning(codeCoworkIncomplete, "kept "+path+": its parent is unsafe: "+err.Error())
		return false
	}
	return true
}

func (l *lifecycle) describeCoworkVM(ctx context.Context, record *Deployment) {
	if record == nil {
		return
	}
	cfg, err := l.env.InstalledConfig()
	if err != nil || !cfg.StandaloneEnterprise() {
		return
	}
	c := cfg.Enterprise.CoworkVMSensor
	s := &enterprisestatus.CoworkVMSensorState{Enabled: c.Mode == "on"}
	l.result.CoworkVMSensor = s
	if !s.Enabled {
		return
	}
	var problems []string
	seenReasons := map[string]bool{}
	problem := func(code, text string) {
		if !seenReasons[code] {
			s.ReasonCodes = append(s.ReasonCodes, code)
			seenReasons[code] = true
		}
		problems = append(problems, text)
	}
	if l.env.GOOS != "darwin" {
		problem("platform_unsupported", "Cowork VM host delivery requires macOS or Windows")
	} else if name, err := l.env.coworkPackageName(); err != nil {
		problem("architecture_unsupported", err.Error())
	} else {
		s.PackagePath = filepath.Join(macCoworkDir, name)
		args, argsErr := c.InstallArguments()
		for _, suffix := range []string{"", ".sig", ".args"} {
			path := s.PackagePath + suffix
			code := "package_not_ready"
			if suffix == ".sig" {
				code = "signature_not_ready"
			} else if suffix == ".args" {
				code = "arguments_not_ready"
			}
			digest, err := sha256File(l.env.P(path))
			if err != nil || digest == emptySHA256 || record.Files[path] == "" || record.Files[path] != digest {
				problem(code, path+" is missing, changed or not recorded; run ensure with the release's package and signature")
				continue
			}
			expected := c.PackageSHA256
			if suffix == ".sig" {
				expected = c.SignatureSHA256
			}
			if suffix != ".args" && (expected == "" || digest != expected) {
				problem(code, path+" does not match its configured SHA-256 release pin; run ensure")
			}
			if err := l.env.checkCoworkInstalledPath(path); err != nil {
				problem(code, path+": "+err.Error())
			}
			if suffix == ".args" {
				body, err := readBounded(l.env.P(path), 256)
				if argsErr != nil || err != nil || string(body) != args {
					problem(code, path+" does not contain the configured ASCII install arguments; run ensure")
				}
			}
		}
		for _, text := range l.env.coworkACLProblems(ctx, []string{s.PackagePath, s.PackagePath + ".sig", s.PackagePath + ".args"}) {
			problem("permissions_not_ready", text)
		}
		s.HostReady = len(problems) == 0
		if err := l.env.coworkManagedSettings(ctx, s.PackagePath, c.Vendor); err != nil {
			problem("mdm_settings_not_ready", err.Error())
		} else {
			s.SettingsReady = true
		}
	}
	if len(problems) != 0 {
		l.result.MarkCoverageIncomplete(codeCoworkIncomplete)
		l.result.MarkSecurityIncomplete(codeCoworkIncomplete)
		l.result.AddWarning(codeCoworkIncomplete, strings.Join(problems, "; "))
	}
}

func (e *Env) coworkManagedSettings(ctx context.Context, packagePath, vendor string) error {
	paths := []string{macCoworkPreferences}
	users, err := filepath.Glob(e.P("/Library/Managed Preferences/*/com.anthropic.claudefordesktop.plist"))
	if err != nil {
		return err
	}
	for _, path := range users {
		paths = append(paths, strings.TrimPrefix(path, e.Root))
	}
	for i, path := range paths {
		if err := e.checkCoworkPath(path, false); err != nil {
			return fmt.Errorf("deploy the Cowork MDM profile: %s: %w", path, err)
		}
		// plutil accepts both binary and XML managed preferences.
		out, err := e.Runner.Run(ctx, "plutil", "-convert", "json", "-o", "-", "--", e.P(path))
		if err != nil {
			return fmt.Errorf("read Cowork MDM settings in %s: %w", path, err)
		}
		var prefs map[string]any
		if err := json.Unmarshal(out.Stdout, &prefs); err != nil {
			return fmt.Errorf("decode Cowork MDM settings in %s: %w", path, err)
		}
		for key, want := range map[string]string{"coworkEDRIntegration": packagePath, "coworkEDRIntegrationVendor": vendor} {
			value, present := prefs[key]
			// Per-user keys override the machine profile individually.
			if (i == 0 || present) && value != want {
				return fmt.Errorf("%s must set %s to %q through MDM", path, key, want)
			}
		}
	}
	return nil
}
