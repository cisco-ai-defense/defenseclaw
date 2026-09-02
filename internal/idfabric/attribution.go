// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package idfabric

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// maxAttributionFileBytes bounds every credential-adjacent file this package
// opens. These files are small; a larger one is treated as unusable rather than
// parsed, so a hostile or corrupt file cannot drive memory growth in a hook.
const maxAttributionFileBytes = 1 << 20

// maxEmailLength is the RFC 5321 forward-path limit.
const maxEmailLength = 254

// ErrNoAttribution reports that no trustworthy signed-in user could be read.
// It is an ordinary outcome, not a failure: attribution is optional and the
// record falls back to SID/UID and device username.
var ErrNoAttribution = errors.New("idfabric: no signed-in user available")

// UserEmailForConnector extracts the signed-in human user for one connector.
//
// This is attribution evidence only. It is not identity attestation and does
// not prove that the reported person is operating the agent; extraction can
// also be influenced by other processes that can write the agent's own config.
// Never synthesize it from username@domain, Git configuration, environment
// variables, or an unverified Windows UPN.
//
// payload is the agent's raw hook JSON and is consulted only for connectors
// that supply the value natively.
func UserEmailForConnector(platform Platform, home string, payload []byte) (string, error) {
	switch platform {
	case PlatformClaudeCode:
		return claudeCodeEmail()
	case PlatformCodex:
		return codexEmail()
	case PlatformCursor:
		return cursorEmail(payload)
	default:
		return "", ErrNoAttribution
	}
}

// claudeCodeEmail reads oauthAccount.emailAddress from Claude Code's local
// account configuration. CLAUDE_CONFIG_DIR relocates the file when set.
func claudeCodeEmail() (string, error) {
	path := claudeAccountFilePath()
	if path == "" {
		return "", ErrNoAttribution
	}
	data, err := readBoundedFile(path)
	if err != nil {
		return "", ErrNoAttribution
	}
	var doc struct {
		OAuthAccount struct {
			EmailAddress string `json:"emailAddress"`
		} `json:"oauthAccount"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", ErrNoAttribution
	}
	return validateEmail(doc.OAuthAccount.EmailAddress)
}

func claudeAccountFilePath() string {
	if dir := strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR")); dir != "" {
		return filepath.Join(dir, ".claude.json")
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	return filepath.Join(home, ".claude.json")
}

// codexEmail reads the email claim from the ID token Codex stores in
// auth.json. When Codex keeps credentials only in the OS credential store
// there is no file to read and attribution is simply unavailable.
//
// The raw ID token never leaves this function: only the email claim is
// returned, and no error message includes token bytes.
func codexEmail() (string, error) {
	home := strings.TrimSpace(os.Getenv("CODEX_HOME"))
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(userHome) == "" {
			return "", ErrNoAttribution
		}
		home = filepath.Join(userHome, ".codex")
	}
	data, err := readBoundedFile(filepath.Join(home, "auth.json"))
	if err != nil {
		return "", ErrNoAttribution
	}
	var doc struct {
		Tokens struct {
			IDToken string `json:"id_token"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", ErrNoAttribution
	}
	email, ok := emailFromUnverifiedJWT(doc.Tokens.IDToken)
	if !ok {
		return "", ErrNoAttribution
	}
	return validateEmail(email)
}

// cursorEmail forwards the value Cursor supplies natively in its hook payload.
func cursorEmail(payload []byte) (string, error) {
	if len(payload) == 0 {
		return "", ErrNoAttribution
	}
	var doc struct {
		UserEmail string `json:"user_email"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return "", ErrNoAttribution
	}
	return validateEmail(doc.UserEmail)
}

// emailFromUnverifiedJWT decodes a JWT payload segment and returns its email
// claim.
//
// The signature is deliberately NOT verified: the hook holds no key for the
// issuer, and this value is treated as attribution evidence rather than an
// authenticated assertion. Do not promote this result to an authorization
// decision.
func emailFromUnverifiedJWT(token string) (string, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	segment := parts[1]
	if segment == "" || len(segment) > maxAttributionFileBytes {
		return "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(segment, "="))
	if err != nil {
		return "", false
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return "", false
	}
	if strings.TrimSpace(claims.Email) == "" {
		return "", false
	}
	return claims.Email, true
}

// readBoundedFile reads a regular, non-symlinked file up to the attribution
// size cap.
func readBoundedFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("idfabric: refusing to read symlinked file")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("idfabric: not a regular file")
	}
	if info.Size() > maxAttributionFileBytes {
		return nil, errors.New("idfabric: file exceeds attribution size cap")
	}
	return os.ReadFile(path)
}

// validateEmail accepts only a structurally sound, JSON-safe address. It does
// not attempt full RFC validation; it rejects anything that could carry
// control characters, delimiters, or log-injection payloads downstream.
func validateEmail(raw string) (string, error) {
	email := strings.TrimSpace(raw)
	if email == "" || len(email) > maxEmailLength {
		return "", ErrNoAttribution
	}
	at := strings.IndexByte(email, '@')
	if at <= 0 || at != strings.LastIndexByte(email, '@') || at == len(email)-1 {
		return "", ErrNoAttribution
	}
	for _, r := range email {
		if r < 0x21 || r > 0x7e {
			// Excludes control characters, spaces, and non-ASCII forms that
			// would need normalization before they could be compared safely.
			return "", ErrNoAttribution
		}
		switch r {
		case '"', '\\', ',', ';', '<', '>', '(', ')', '[', ']':
			return "", ErrNoAttribution
		}
	}
	return email, nil
}
