// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	perUserInstallerDirName     = "installer"
	perUserBinaryDigestsName    = "binaries.sha256"
	maxPerUserBinaryDigestsSize = 64 << 10
	maxPerUserHelperSize        = 512 << 20
)

// restorePerUserInstallerHelpers puts back a helper this release installs
// beside the gateway when it is missing there and the installer folder keeps
// the copy this install recorded (GAP-2521). A roll-forward by an older
// release (1.0.2, 1.0.3) moves the installer folder and the gateway back but
// copies only the binaries that release knew, so defenseclaw-hook-post stayed
// missing and the OpenCode and Amp plugins started the full gateway CLI for
// every call. Best effort and quiet: a helper is copied only when the running
// gateway is the one installer/binaries.sha256 records, the copy has the
// recorded digest, both folders are private to this account, and nothing
// is at the target path; an existing file is never replaced.
func restorePerUserInstallerHelpers(dataDir string) {
	if !perUserHelperRestoreSupported() {
		return
	}
	gateway, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(gateway); err == nil {
		gateway = resolved
	}
	restorePerUserInstallerHelpersFor(dataDir, gateway)
}

func restorePerUserInstallerHelpersFor(dataDir, gateway string) []string {
	if !filepath.IsAbs(dataDir) || !filepath.IsAbs(gateway) {
		return nil
	}
	installer := filepath.Join(dataDir, perUserInstallerDirName)
	record, err := safefile.ReadRegularFileBounded(filepath.Join(installer, perUserBinaryDigestsName), maxPerUserBinaryDigestsSize)
	if err != nil {
		return nil
	}
	digests := parsePerUserBinaryDigests(record)
	binDir := filepath.Dir(gateway)
	gatewayDigest, ok := digests[filepath.Base(gateway)]
	if !ok {
		return nil
	}
	var missing []string
	for name := range digests {
		if name == filepath.Base(gateway) {
			continue
		}
		if _, err := os.Lstat(filepath.Join(binDir, name)); !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if _, err := os.Lstat(filepath.Join(installer, name)); err != nil {
			continue
		}
		missing = append(missing, name)
	}
	if len(missing) == 0 {
		return nil
	}
	if !perUserPrivateDir(binDir) || !perUserPrivateDir(installer) {
		return nil
	}
	if sum, err := perUserFileDigest(gateway); err != nil || sum != gatewayDigest {
		return nil
	}
	sort.Strings(missing)
	var restored []string
	for _, name := range missing {
		if restorePerUserHelper(filepath.Join(installer, name), filepath.Join(binDir, name), digests[name]) == nil {
			restored = append(restored, name)
		}
	}
	return restored
}

// parsePerUserBinaryDigests reads the "<sha256>  <name>" lines install.sh
// writes. Only plain DefenseClaw binary names count.
func parsePerUserBinaryDigests(record []byte) map[string]string {
	digests := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(record))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || len(fields[0]) != sha256.Size*2 {
			continue
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			continue
		}
		name := fields[1]
		if !strings.HasPrefix(name, "defenseclaw-") || filepath.Base(name) != name || strings.ContainsAny(name, "/\\") {
			continue
		}
		digests[name] = strings.ToLower(fields[0])
	}
	return digests
}

func perUserFileDigest(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > maxPerUserHelperSize {
		return "", errors.New("not a regular file of a helper size")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	_, err = io.Copy(hash, io.LimitReader(file, maxPerUserHelperSize+1))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func restorePerUserHelper(source, target, digest string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || !perUserOwnedPrivateFile(source, info) || info.Size() > maxPerUserHelperSize {
		return errors.New("the installer copy is not a private file of this account")
	}
	data, err := safefile.ReadRegularFileBounded(source, maxPerUserHelperSize)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != digest {
		return errors.New("the installer copy is not the recorded binary")
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".restore-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(name, 0o755)
	}
	if err != nil {
		return err
	}
	// A link never replaces a file another process put there meanwhile.
	return os.Link(name, target)
}
