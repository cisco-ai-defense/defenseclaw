// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const MaxContractLockBytes = 64 << 10

type RuntimeContractLock struct {
	Version     int    `json:"version"`
	GeneratedAt string `json:"generated_at"`
	Protocol    struct {
		SchemaVersion string `json:"schema_version"`
		SchemaSHA256  string `json:"schema_sha256"`
	} `json:"protocol"`
	Client struct {
		ID           string `json:"id"`
		ConfigPath   string `json:"config_path"`
		ConfigSHA256 string `json:"config_sha256"`
	} `json:"client"`
	Agent struct {
		ID      string `json:"id"`
		Path    string `json:"path"`
		SHA256  string `json:"sha256"`
		Version string `json:"version"`
	} `json:"agent"`
	Guard struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"guard"`
	Profile string `json:"profile"`
	Mode    string `json:"mode"`
}

// ValidateRuntimeContract fails closed when the setup-selected guard or agent
// executable has moved or changed since the editor binding was published.
func ValidateRuntimeContract(path, clientID, agentID, profile string, mode Mode, command string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxContractLockBytes {
		return errors.New("ACP runtime contract lock is unavailable or unsafe")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("ACP runtime contract lock permissions are too broad")
	}
	if err := safefile.ValidatePrivateFile(path); err != nil {
		return errors.New("ACP runtime contract lock protection is unsafe")
	}
	body, err := safefile.ReadRegularFileBounded(path, MaxContractLockBytes)
	if err != nil {
		return fmt.Errorf("read ACP runtime contract lock: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var lock RuntimeContractLock
	if err := decoder.Decode(&lock); err != nil {
		return errors.New("ACP runtime contract lock is malformed")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("ACP runtime contract lock has trailing content")
	}
	if lock.Version != 1 || lock.Protocol.SchemaVersion != SchemaVersion || lock.Protocol.SchemaSHA256 != SchemaSHA256 ||
		lock.Client.ID != clientID || lock.Agent.ID != agentID || lock.Profile != profile || lock.Mode != string(mode) {
		return errors.New("ACP runtime contract metadata does not match the guarded binding")
	}
	agentPath, err := filepath.Abs(command)
	if err != nil {
		return errors.New("resolve ACP agent executable")
	}
	lockedAgentPath, err := filepath.Abs(lock.Agent.Path)
	if err != nil || !samePath(agentPath, lockedAgentPath) {
		return errors.New("ACP agent executable path does not match the runtime contract")
	}
	guardPath, err := os.Executable()
	if err != nil {
		return errors.New("resolve ACP guard executable")
	}
	lockedGuardPath, err := filepath.Abs(lock.Guard.Path)
	if err != nil || !samePath(guardPath, lockedGuardPath) {
		return errors.New("ACP guard executable path does not match the runtime contract")
	}
	clientConfigPath, err := filepath.Abs(lock.Client.ConfigPath)
	if err != nil || strings.TrimSpace(lock.Client.ConfigSHA256) == "" {
		return errors.New("ACP client configuration identity is missing from the runtime contract")
	}
	for _, item := range []struct{ path, expected, label string }{
		{clientConfigPath, lock.Client.ConfigSHA256, "client configuration"},
		{agentPath, lock.Agent.SHA256, "agent"},
		{guardPath, lock.Guard.SHA256, "guard"},
	} {
		observed, digestErr := fileSHA256(item.path)
		if digestErr != nil || !strings.EqualFold(observed, item.expected) {
			return fmt.Errorf("ACP %s executable digest does not match the runtime contract", item.label)
		}
	}
	return nil
}

func samePath(left, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

func fileSHA256(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("executable is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
