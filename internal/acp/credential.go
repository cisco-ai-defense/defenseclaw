// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	enterpriseCredentialVersion  = 1
	maxEnterpriseCredentials     = 1024
	maxEnterpriseCredentialBytes = 16 << 10
	maxEnterpriseIndexBytes      = 1 << 10
)

var credentialScopeRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@\\-]{0,255}$`)
var credentialRecordNameRE = regexp.MustCompile(`^[a-f0-9]{64}\.json$`)

// EnterpriseCredential is an administrator-owned, per-user and per-binding
// ACP credential. The plaintext is retained only in the protected service
// record so a guardian can repair a user's private copy without rotating every
// other enrolled user. It has authority only on ACP routes and only for the
// exact client, agent, and profile recorded here.
type EnterpriseCredential struct {
	Version   int    `json:"version"`
	Principal string `json:"principal"`
	ClientID  string `json:"client_id"`
	AgentID   string `json:"agent_id"`
	Profile   string `json:"profile"`
	Token     string `json:"token"`
}

type enterpriseCredentialIndex struct {
	Version int    `json:"version"`
	Record  string `json:"record"`
}

func enterpriseCredentialDir(dataDir string) string {
	return filepath.Join(dataDir, "acp", "enterprise-credentials")
}

func enterpriseCredentialIndexDir(dataDir string) string {
	return filepath.Join(dataDir, "acp", "enterprise-token-index")
}

// EnterpriseCredentialIndexPath returns the non-secret token-digest lookup
// used by the gateway. This keeps authentication O(1) instead of letting an
// unauthenticated loopback caller force a scan of every enrolled user.
func EnterpriseCredentialIndexPath(dataDir, token string) (string, error) {
	if strings.TrimSpace(dataDir) == "" {
		return "", errors.New("ACP enterprise credential data directory is empty")
	}
	if !validCredentialToken(token) {
		return "", errors.New("invalid ACP enterprise credential token")
	}
	digest := sha256.Sum256([]byte(token))
	return filepath.Join(enterpriseCredentialIndexDir(dataDir), hex.EncodeToString(digest[:])+".json"), nil
}

// EnterpriseCredentialPath returns the stable service-owned record path for
// one exact enrollment without embedding user-controlled identity in a path.
func EnterpriseCredentialPath(dataDir, principal, clientID, agentID, profile string) (string, error) {
	if strings.TrimSpace(dataDir) == "" {
		return "", errors.New("ACP enterprise credential data directory is empty")
	}
	for label, value := range map[string]string{
		"principal": principal, "client": clientID, "agent": agentID, "profile": profile,
	} {
		if !credentialScopeRE.MatchString(strings.TrimSpace(value)) {
			return "", fmt.Errorf("invalid ACP enterprise credential %s", label)
		}
	}
	key := sha256.Sum256([]byte(principal + "\x00" + clientID + "\x00" + agentID + "\x00" + profile))
	return filepath.Join(enterpriseCredentialDir(dataDir), hex.EncodeToString(key[:])+".json"), nil
}

// EnterpriseUserTokenPath is the target-user private token sidecar for one
// exact editor/agent pair. Normal mode retains the legacy acp/.token path.
func EnterpriseUserTokenPath(dataDir, clientID, agentID string) (string, error) {
	for label, value := range map[string]string{"client": clientID, "agent": agentID} {
		if !credentialScopeRE.MatchString(strings.TrimSpace(value)) {
			return "", fmt.Errorf("invalid ACP enterprise token %s", label)
		}
	}
	if strings.TrimSpace(dataDir) == "" {
		return "", errors.New("ACP enterprise token data directory is empty")
	}
	return filepath.Join(dataDir, "acp", clientID+"-"+agentID+".token"), nil
}

// EnsureEnterpriseCredential mints or returns the stable service-owned
// credential for an exact managed enrollment.
func EnsureEnterpriseCredential(dataDir, principal, clientID, agentID, profile string) (EnterpriseCredential, error) {
	path, err := EnterpriseCredentialPath(dataDir, principal, clientID, agentID, profile)
	if err != nil {
		return EnterpriseCredential{}, err
	}
	if _, err := os.Lstat(path); err == nil {
		credential, loadErr := loadEnterpriseCredentialFile(path)
		if loadErr != nil {
			return EnterpriseCredential{}, loadErr
		}
		if credential.Principal != principal || credential.ClientID != clientID ||
			credential.AgentID != agentID || credential.Profile != profile {
			return EnterpriseCredential{}, errors.New("ACP enterprise credential scope does not match its stable path")
		}
		indexPath, indexErr := EnterpriseCredentialIndexPath(dataDir, credential.Token)
		if indexErr != nil {
			return EnterpriseCredential{}, indexErr
		}
		if _, indexErr = os.Lstat(indexPath); indexErr == nil {
			if err := ensureEnterpriseCredentialIndex(dataDir, path, credential.Token); err != nil {
				return EnterpriseCredential{}, err
			}
			return credential, nil
		} else if !errors.Is(indexErr, os.ErrNotExist) {
			return EnterpriseCredential{}, indexErr
		}
		// The bearer-derived index is the revocation authority. If it is gone,
		// never recreate it around the old plaintext record: that could
		// resurrect a credential after a crash between the two revocation
		// renames. Retire the orphan record and mint fresh material below.
		if err := removeEnterpriseCredentialFile(path); err != nil {
			return EnterpriseCredential{}, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return EnterpriseCredential{}, err
	}

	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return EnterpriseCredential{}, fmt.Errorf("mint ACP enterprise credential: %w", err)
	}
	credential := EnterpriseCredential{
		Version: enterpriseCredentialVersion, Principal: principal, ClientID: clientID,
		AgentID: agentID, Profile: profile, Token: hex.EncodeToString(bytes),
	}
	body, err := json.MarshalIndent(credential, "", "  ")
	if err != nil {
		return EnterpriseCredential{}, err
	}
	body = append(body, '\n')
	if err := writeEnterpriseCredentialFile(dataDir, path, "ACP enterprise credential", body); err != nil {
		return EnterpriseCredential{}, fmt.Errorf("publish ACP enterprise credential: %w", err)
	}
	if err := ensureEnterpriseCredentialIndex(dataDir, path, credential.Token); err != nil {
		return EnterpriseCredential{}, err
	}
	return credential, nil
}

// LoadEnterpriseCredential reads one exact service-owned enrollment without
// minting or repairing it.
func LoadEnterpriseCredential(dataDir, principal, clientID, agentID, profile string) (EnterpriseCredential, error) {
	path, err := EnterpriseCredentialPath(dataDir, principal, clientID, agentID, profile)
	if err != nil {
		return EnterpriseCredential{}, err
	}
	return loadEnterpriseCredentialFile(path)
}

// PublishEnterpriseUserToken writes only the bearer into target-user private
// state. Callers must execute this function under that user's credentials.
func PublishEnterpriseUserToken(dataDir, clientID, agentID, token string) (string, error) {
	path, err := EnterpriseUserTokenPath(dataDir, clientID, agentID)
	if err != nil {
		return "", err
	}
	if !validCredentialToken(token) {
		return "", errors.New("invalid ACP enterprise credential token")
	}
	if err := safefile.WritePrivate(path, []byte(token+"\n")); err != nil {
		return "", fmt.Errorf("publish ACP enterprise user token: %w", err)
	}
	return path, nil
}

// MatchEnterpriseCredential performs a constant-work lookup through a
// SHA-256(token) index and returns the exact scope for a matching bearer. The
// token is random 256-bit material and is still compared in constant time.
func MatchEnterpriseCredential(dataDir, candidate string) (EnterpriseCredential, bool) {
	if !validCredentialToken(candidate) {
		return EnterpriseCredential{}, false
	}
	if err := validateEnterpriseCredentialDirectory(enterpriseCredentialDir(dataDir)); err != nil {
		return EnterpriseCredential{}, false
	}
	if err := validateEnterpriseCredentialDirectory(enterpriseCredentialIndexDir(dataDir)); err != nil {
		return EnterpriseCredential{}, false
	}
	indexPath, err := EnterpriseCredentialIndexPath(dataDir, candidate)
	if err != nil {
		return EnterpriseCredential{}, false
	}
	index, err := loadEnterpriseCredentialIndex(indexPath, candidate)
	if err != nil {
		return EnterpriseCredential{}, false
	}
	credential, err := loadEnterpriseCredentialFile(filepath.Join(enterpriseCredentialDir(dataDir), index.Record))
	if err != nil {
		return EnterpriseCredential{}, false
	}
	candidateHash := sha256.Sum256([]byte(candidate))
	expectedHash := sha256.Sum256([]byte(credential.Token))
	return credential, subtle.ConstantTimeCompare(expectedHash[:], candidateHash[:]) == 1
}

// EnterpriseCredentialsReady validates the bounded managed credential
// inventory and reports whether at least one enrollment is usable.
func EnterpriseCredentialsReady(dataDir string) bool {
	dir := enterpriseCredentialDir(dataDir)
	if err := validateEnterpriseCredentialDirectory(dir); err != nil {
		return false
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 || len(entries) > maxEnterpriseCredentials {
		return false
	}
	indexDir := enterpriseCredentialIndexDir(dataDir)
	if err := validateEnterpriseCredentialDirectory(indexDir); err != nil {
		return false
	}
	indexes, err := os.ReadDir(indexDir)
	if err != nil || len(indexes) != len(entries) || len(indexes) > maxEnterpriseCredentials {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() || !credentialRecordNameRE.MatchString(entry.Name()) {
			return false
		}
		credential, err := loadEnterpriseCredentialFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return false
		}
		indexPath, err := EnterpriseCredentialIndexPath(dataDir, credential.Token)
		if err != nil {
			return false
		}
		index, err := loadEnterpriseCredentialIndex(indexPath, credential.Token)
		if err != nil || index.Record != entry.Name() {
			return false
		}
	}
	return true
}

// RemoveEnterpriseCredential revokes the service-side credential immediately.
// A stale user token then has no authority even if user-side cleanup fails.
func RemoveEnterpriseCredential(dataDir, principal, clientID, agentID, profile string) error {
	path, err := EnterpriseCredentialPath(dataDir, principal, clientID, agentID, profile)
	if err != nil {
		return err
	}
	credential, err := loadEnterpriseCredentialFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect ACP enterprise credential for revocation: %w", err)
	}
	indexPath, err := EnterpriseCredentialIndexPath(dataDir, credential.Token)
	if err != nil {
		return err
	}
	// Remove the only bearer-derived lookup first. A stale user copy has no
	// authority from this point even if record cleanup is interrupted.
	if err := removeEnterpriseCredentialFile(indexPath); err != nil {
		return err
	}
	return removeEnterpriseCredentialFile(path)
}

func removeEnterpriseCredentialFile(path string) error {
	// Rename first so a crash or interrupted cleanup leaves a non-authoritative
	// tombstone. Readiness rejects every non-.json inventory entry.
	tombstone := path + ".revoked"
	if _, err := os.Lstat(tombstone); err == nil {
		return errors.New("ACP enterprise credential revocation tombstone already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect ACP enterprise credential revocation tombstone: %w", err)
	}
	if err := os.Rename(path, tombstone); err != nil {
		return fmt.Errorf("revoke ACP enterprise credential: %w", err)
	}
	if err := syncEnterpriseCredentialDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("commit ACP enterprise credential revocation: %w", err)
	}
	if err := os.Remove(tombstone); err != nil {
		return fmt.Errorf("remove ACP enterprise credential revocation tombstone: %w", err)
	}
	if err := syncEnterpriseCredentialDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("commit ACP enterprise credential cleanup: %w", err)
	}
	return nil
}

func ensureEnterpriseCredentialIndex(dataDir, recordPath, token string) error {
	indexPath, err := EnterpriseCredentialIndexPath(dataDir, token)
	if err != nil {
		return err
	}
	want := enterpriseCredentialIndex{Version: enterpriseCredentialVersion, Record: filepath.Base(recordPath)}
	if _, err := os.Lstat(indexPath); err == nil {
		got, loadErr := loadEnterpriseCredentialIndex(indexPath, token)
		if loadErr != nil {
			return loadErr
		}
		if got != want {
			return errors.New("ACP enterprise credential index conflicts with its record")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	body, err := json.Marshal(want)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := writeEnterpriseCredentialFile(dataDir, indexPath, "ACP enterprise credential index", body); err != nil {
		return fmt.Errorf("publish ACP enterprise credential index: %w", err)
	}
	return nil
}

func loadEnterpriseCredentialIndex(path, token string) (enterpriseCredentialIndex, error) {
	if err := validateEnterpriseCredentialFile(path); err != nil {
		return enterpriseCredentialIndex{}, err
	}
	body, err := safefile.ReadRegularFileBounded(path, maxEnterpriseIndexBytes)
	if err != nil {
		return enterpriseCredentialIndex{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var index enterpriseCredentialIndex
	if err := decoder.Decode(&index); err != nil {
		return enterpriseCredentialIndex{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return enterpriseCredentialIndex{}, errors.New("ACP enterprise credential index has trailing JSON")
	}
	if index.Version != enterpriseCredentialVersion || !credentialRecordNameRE.MatchString(index.Record) {
		return enterpriseCredentialIndex{}, errors.New("ACP enterprise credential index is malformed")
	}
	expected, err := EnterpriseCredentialIndexPath(filepath.Dir(filepath.Dir(filepath.Dir(path))), token)
	if err != nil || filepath.Clean(expected) != filepath.Clean(path) {
		return enterpriseCredentialIndex{}, errors.New("ACP enterprise credential index filename does not match its bearer")
	}
	return index, nil
}

func loadEnterpriseCredentialFile(path string) (EnterpriseCredential, error) {
	if err := validateEnterpriseCredentialFile(path); err != nil {
		return EnterpriseCredential{}, err
	}
	body, err := safefile.ReadRegularFileBounded(path, maxEnterpriseCredentialBytes)
	if err != nil {
		return EnterpriseCredential{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var credential EnterpriseCredential
	if err := decoder.Decode(&credential); err != nil {
		return EnterpriseCredential{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return EnterpriseCredential{}, errors.New("ACP enterprise credential has trailing JSON")
	}
	if credential.Version != enterpriseCredentialVersion || !validCredentialToken(credential.Token) {
		return EnterpriseCredential{}, errors.New("ACP enterprise credential is malformed")
	}
	for _, value := range []string{credential.Principal, credential.ClientID, credential.AgentID, credential.Profile} {
		if !credentialScopeRE.MatchString(value) {
			return EnterpriseCredential{}, errors.New("ACP enterprise credential scope is malformed")
		}
	}
	expected, err := EnterpriseCredentialPath(filepath.Dir(filepath.Dir(filepath.Dir(path))), credential.Principal, credential.ClientID, credential.AgentID, credential.Profile)
	if err != nil || filepath.Clean(expected) != filepath.Clean(path) {
		return EnterpriseCredential{}, errors.New("ACP enterprise credential filename does not match its scope")
	}
	return credential, nil
}

func validateEnterpriseCredentialDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return managed.ValidateTrustedServiceRuntimeDir(
			path, "ACP enterprise credential directory", os.Getenv(managed.WindowsServiceAccountEnv),
		)
	}
	return safefile.ValidatePrivateDirectory(path)
}

func validateEnterpriseCredentialFile(path string) error {
	if runtime.GOOS == "windows" {
		return managed.ValidateTrustedServiceRuntimeFilePath(
			path, "ACP enterprise credential", os.Getenv(managed.WindowsServiceAccountEnv),
		)
	}
	return safefile.ValidatePrivateFile(path)
}

func validCredentialToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}
