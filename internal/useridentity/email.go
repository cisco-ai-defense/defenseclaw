// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// maxCredentialFileBytes bounds every credential-adjacent file this package
// opens. These files are small; a larger one is treated as unusable rather
// than parsed, so a hostile or corrupt file cannot drive memory growth in a
// hook or in the sidecar's discovery pass.
const maxCredentialFileBytes = 1 << 20

// maxEmailLength is the RFC 5321 forward-path limit.
const maxEmailLength = 254

// ErrNoEmail reports that no trustworthy signed-in address could be read. It
// is an ordinary outcome, not a failure: the address is optional and the
// record falls back to the SID or uid and the OS account name.
var ErrNoEmail = errors.New("useridentity: no signed-in email available")

// EmailForConnector extracts the signed-in human account for one connector
// under one user profile.
//
// home selects whose profile to read and is required whenever the caller is
// not the user in question. When home is empty the calling process's own home
// is used and the connectors' environment overrides (CODEX_HOME,
// CLAUDE_CONFIG_DIR) are honored; when home is set those overrides are
// deliberately ignored, because they describe the reading process and would
// otherwise attribute the reader's own address to the profile being scanned.
//
// payload is the agent's raw hook JSON and is consulted only for connectors
// that supply the address natively.
//
// This is attribution evidence only. It is not identity attestation and does
// not prove the reported person is operating the agent; any process running as
// that user can write the agent's config. Never synthesize the value from
// username@domain, Git configuration, environment variables, or an unverified
// Windows UPN.
func EmailForConnector(connector, home string, payload []byte) (string, error) {
	switch normalizeConnector(connector) {
	case "claudecode":
		return claudeCodeEmail(home)
	case "codex":
		return codexEmail(home)
	case "cursor":
		return cursorEmail(payload)
	default:
		return "", ErrNoEmail
	}
}

// EmailFromPayloadForConnector extracts the signed-in account from the agent's
// own hook payload and from nowhere else.
//
// It exists so a caller holding no trustworthy profile directory cannot reach
// the file-backed readers by accident. EmailForConnector with an empty home
// falls back to the *calling* process's profile, which under a managed install
// belongs to the service account — a different person, reported with the same
// confidence as the right one. Callers on the hook path have only the user id
// the request supplied, which no local caller is authenticated to claim, so
// they have no profile they may safely read and use this instead.
func EmailFromPayloadForConnector(connector string, payload []byte) (string, error) {
	switch normalizeConnector(connector) {
	case "cursor":
		return cursorEmail(payload)
	default:
		// Every other supported connector keeps the address in a file under
		// the user's profile. Add a connector here only if it reports the
		// address in the payload itself.
		return "", ErrNoEmail
	}
}

// normalizeConnector folds the spellings the hooks, the connector registry,
// and the discovery signatures each use for the same connector.
func normalizeConnector(connector string) string {
	folded := strings.ToLower(strings.TrimSpace(connector))
	folded = strings.NewReplacer("-", "", "_", "", " ", "").Replace(folded)
	switch folded {
	case "claude", "claudecode", "anthropicclaudecode":
		return "claudecode"
	case "codex", "openaicodex", "codexcli":
		return "codex"
	case "cursor", "cursorcli", "cursoride":
		return "cursor"
	default:
		return folded
	}
}

// claudeCodeEmail reads oauthAccount.emailAddress from Claude Code's local
// account configuration.
func claudeCodeEmail(home string) (string, error) {
	path := claudeAccountFilePath(home)
	if path == "" {
		return "", ErrNoEmail
	}
	data, err := readBoundedFile(path)
	if err != nil {
		return "", ErrNoEmail
	}
	var doc struct {
		OAuthAccount struct {
			EmailAddress string `json:"emailAddress"`
		} `json:"oauthAccount"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", ErrNoEmail
	}
	return validateEmail(doc.OAuthAccount.EmailAddress)
}

func claudeAccountFilePath(home string) string {
	if strings.TrimSpace(home) == "" {
		if dir := strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR")); dir != "" {
			return filepath.Join(dir, ".claude.json")
		}
		resolved, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(resolved) == "" {
			return ""
		}
		home = resolved
	}
	return filepath.Join(home, ".claude.json")
}

// codexEmail reads the email claim from the ID token Codex stores in
// auth.json. When Codex keeps credentials only in the OS credential store
// there is no file to read and the address is simply unavailable.
//
// The raw ID token never leaves this function: only the email claim is
// returned, and no error message includes token bytes.
func codexEmail(home string) (string, error) {
	dir := codexHomeDir(home)
	if dir == "" {
		return "", ErrNoEmail
	}
	data, err := readBoundedFile(filepath.Join(dir, "auth.json"))
	if err != nil {
		return "", ErrNoEmail
	}
	var doc struct {
		Tokens struct {
			IDToken string `json:"id_token"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", ErrNoEmail
	}
	email, ok := emailFromUnverifiedJWT(doc.Tokens.IDToken)
	if !ok {
		return "", ErrNoEmail
	}
	return validateEmail(email)
}

func codexHomeDir(home string) string {
	if strings.TrimSpace(home) == "" {
		if dir := strings.TrimSpace(os.Getenv("CODEX_HOME")); dir != "" {
			return dir
		}
		resolved, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(resolved) == "" {
			return ""
		}
		home = resolved
	}
	return filepath.Join(home, ".codex")
}

// cursorEmail forwards the address Cursor supplies natively in its hook
// payload. Cursor keeps no local account file, so there is nothing for the
// sidecar to read: this resolves on hook events only.
func cursorEmail(payload []byte) (string, error) {
	if len(payload) == 0 {
		return "", ErrNoEmail
	}
	var doc struct {
		UserEmail string `json:"user_email"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return "", ErrNoEmail
	}
	return validateEmail(doc.UserEmail)
}

// emailFromUnverifiedJWT decodes a JWT payload segment and returns its email
// claim.
//
// The signature is deliberately NOT verified: the reader holds no key for the
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
	if segment == "" || len(segment) > maxCredentialFileBytes {
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

// readBoundedFile reads a regular, non-symlinked file up to the size cap.
//
// Every path this reaches lives inside a user profile, so the account that
// owns the credential can replace it between any two operations. Checking the
// pathname and then reading it separately would let that account swap a
// verified small regular file for a symlink and have the gateway — which runs
// as a service account under a managed install — read a file the account
// cannot open itself. safefile validates the opened handle instead: it opens
// without following links, confirms the handle is the same object it stat'ed,
// and stops at the limit.
func readBoundedFile(path string) ([]byte, error) {
	return safefile.ReadRegularFileBounded(path, maxCredentialFileBytes)
}

// validateEmail accepts only a structurally sound, JSON-safe address. It does
// not attempt full RFC validation; it rejects anything that could carry
// control characters, delimiters, or log-injection payloads downstream.
func validateEmail(raw string) (string, error) {
	email := strings.TrimSpace(raw)
	if email == "" || len(email) > maxEmailLength {
		return "", ErrNoEmail
	}
	at := strings.IndexByte(email, '@')
	if at <= 0 || at != strings.LastIndexByte(email, '@') || at == len(email)-1 {
		return "", ErrNoEmail
	}
	for _, r := range email {
		if r < 0x21 || r > 0x7e {
			// Excludes control characters, spaces, and non-ASCII forms that
			// would need normalization before they could be compared safely.
			return "", ErrNoEmail
		}
		switch r {
		case '"', '\\', ',', ';', '<', '>', '(', ')', '[', ']':
			return "", ErrNoEmail
		}
	}
	return email, nil
}
