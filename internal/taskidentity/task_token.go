// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package taskidentity implements optional task-scoped identity tokens for
// runtime agent actions. It intentionally uses a small HS256 JWT-compatible
// implementation so DefenseClaw can validate tokens without pulling in a new
// runtime dependency; production deployments can rotate the signing secret
// through their normal secret manager.
package taskidentity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	Algorithm       = "HS256"
	DefaultIssuer   = "defenseclaw"
	MaxTaskTokenTTL = time.Hour
)

var (
	ErrEmptyToken         = errors.New("taskidentity: empty token")
	ErrInvalidToken       = errors.New("taskidentity: invalid token")
	ErrInvalidSignature   = errors.New("taskidentity: invalid signature")
	ErrExpired            = errors.New("taskidentity: token expired")
	ErrRevoked            = errors.New("taskidentity: token revoked")
	ErrMissingResources   = errors.New("taskidentity: no allowed resources")
	ErrResourceNotAllowed = errors.New("taskidentity: resource not allowed")
)

// Claims are the signed task-scoped authority attached to a runtime action.
type Claims struct {
	Issuer           string   `json:"iss,omitempty"`
	Subject          string   `json:"sub,omitempty"`
	TokenID          string   `json:"jti"`
	IssuedAt         int64    `json:"iat"`
	ExpiresAt        int64    `json:"exp"`
	TaskID           string   `json:"tid"`
	TaskType         string   `json:"ttype,omitempty"`
	ParentAgentID    string   `json:"aid"`
	AllowedResources []string `json:"resources"`
	Scopes           []string `json:"scopes,omitempty"`
	AutoRevoke       bool     `json:"auto_revoke,omitempty"`
}

// IssueRequest carries the inputs for minting a task token.
type IssueRequest struct {
	TaskID           string
	TaskType         string
	ParentAgentID    string
	AllowedResources []string
	Scopes           []string
	TTL              time.Duration
	AutoRevoke       bool
}

// Revoker stores token revocations by jti.
type Revoker interface {
	Revoke(ctx context.Context, tokenID string, expiresAt time.Time) error
	IsRevoked(ctx context.Context, tokenID string) (bool, error)
}

// InMemoryRevoker is sufficient for local demos and unit tests.
type InMemoryRevoker struct {
	mu      sync.Mutex
	revoked map[string]time.Time
}

func NewInMemoryRevoker() *InMemoryRevoker {
	return &InMemoryRevoker{revoked: map[string]time.Time{}}
}

func (r *InMemoryRevoker) Revoke(_ context.Context, tokenID string, expiresAt time.Time) error {
	if strings.TrimSpace(tokenID) == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[tokenID] = expiresAt
	return nil
}

func (r *InMemoryRevoker) IsRevoked(_ context.Context, tokenID string) (bool, error) {
	if r == nil || strings.TrimSpace(tokenID) == "" {
		return false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	exp, ok := r.revoked[tokenID]
	if !ok {
		return false, nil
	}
	if !exp.IsZero() && time.Now().After(exp) {
		delete(r.revoked, tokenID)
		return false, nil
	}
	return true, nil
}

// Service issues and validates HS256 task JWTs.
type Service struct {
	issuer  string
	secret  []byte
	revoker Revoker
	now     func() time.Time
}

// New creates a token service.
func New(issuer string, secret []byte, revoker Revoker) (*Service, error) {
	if strings.TrimSpace(issuer) == "" {
		issuer = DefaultIssuer
	}
	if len(secret) < 16 {
		return nil, errors.New("taskidentity: secret must be at least 16 bytes")
	}
	if revoker == nil {
		revoker = NewInMemoryRevoker()
	}
	return &Service{issuer: issuer, secret: append([]byte(nil), secret...), revoker: revoker, now: time.Now}, nil
}

// Issue mints a signed task token.
func (s *Service) Issue(req IssueRequest) (string, Claims, error) {
	if s == nil {
		return "", Claims{}, errors.New("taskidentity: nil service")
	}
	if strings.TrimSpace(req.TaskID) == "" {
		return "", Claims{}, errors.New("taskidentity: task id required")
	}
	if strings.TrimSpace(req.ParentAgentID) == "" {
		return "", Claims{}, errors.New("taskidentity: parent agent id required")
	}
	resources := trimStrings(req.AllowedResources)
	if len(resources) == 0 {
		return "", Claims{}, ErrMissingResources
	}
	ttl := req.TTL
	if ttl <= 0 || ttl > MaxTaskTokenTTL {
		ttl = MaxTaskTokenTTL
	}
	now := s.now().UTC()
	claims := Claims{
		Issuer:           s.issuer,
		Subject:          req.ParentAgentID,
		TokenID:          randomID(),
		IssuedAt:         now.Unix(),
		ExpiresAt:        now.Add(ttl).Unix(),
		TaskID:           strings.TrimSpace(req.TaskID),
		TaskType:         strings.TrimSpace(req.TaskType),
		ParentAgentID:    strings.TrimSpace(req.ParentAgentID),
		AllowedResources: resources,
		Scopes:           trimStrings(req.Scopes),
		AutoRevoke:       req.AutoRevoke,
	}
	token, err := s.sign(claims)
	return token, claims, err
}

// Validate verifies the token and returns signed claims.
func (s *Service) Validate(ctx context.Context, raw string) (Claims, error) {
	if s == nil {
		return Claims{}, errors.New("taskidentity: nil service")
	}
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))
	if raw == "" {
		return Claims{}, ErrEmptyToken
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Claims{}, ErrInvalidToken
	}
	signed := parts[0] + "." + parts[1]
	expected := hmacSHA256(s.secret, []byte(signed))
	got, err := b64Decode(parts[2])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	if !hmac.Equal(expected, got) {
		return Claims{}, ErrInvalidSignature
	}
	headerBytes, err := b64Decode(parts[0])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Algorithm != Algorithm {
		return Claims{}, ErrInvalidToken
	}
	payload, err := b64Decode(parts[1])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, ErrInvalidToken
	}
	if claims.Issuer != s.issuer || claims.TokenID == "" || claims.ParentAgentID == "" || claims.TaskID == "" {
		return Claims{}, ErrInvalidToken
	}
	if len(claims.AllowedResources) == 0 {
		return Claims{}, ErrMissingResources
	}
	if s.now().UTC().Unix() >= claims.ExpiresAt {
		return Claims{}, ErrExpired
	}
	revoked, err := s.revoker.IsRevoked(ctx, claims.TokenID)
	if err != nil {
		return Claims{}, err
	}
	if revoked {
		return Claims{}, ErrRevoked
	}
	return claims, nil
}

// Revoke revokes a token id until the token expiry.
func (s *Service) Revoke(ctx context.Context, claims Claims) error {
	if s == nil || s.revoker == nil || claims.TokenID == "" {
		return nil
	}
	return s.revoker.Revoke(ctx, claims.TokenID, time.Unix(claims.ExpiresAt, 0))
}

// ResourceAllowed checks exact resource IDs and prefix resources ending in '*'.
func ResourceAllowed(claims Claims, resourceID string) bool {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" {
		return true
	}
	for _, allowed := range claims.AllowedResources {
		allowed = strings.TrimSpace(allowed)
		if allowed == "*" || allowed == resourceID {
			return true
		}
		if strings.HasSuffix(allowed, "*") && strings.HasPrefix(resourceID, strings.TrimSuffix(allowed, "*")) {
			return true
		}
	}
	return false
}

// ValidateResource verifies both the token and resource scope.
func (s *Service) ValidateResource(ctx context.Context, raw string, resourceID string) (Claims, error) {
	claims, err := s.Validate(ctx, raw)
	if err != nil {
		return Claims{}, err
	}
	if !ResourceAllowed(claims, resourceID) {
		return Claims{}, ErrResourceNotAllowed
	}
	return claims, nil
}

func (s *Service) sign(claims Claims) (string, error) {
	header := map[string]string{"alg": Algorithm, "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signed := b64Encode(headerJSON) + "." + b64Encode(claimsJSON)
	sig := hmacSHA256(s.secret, []byte(signed))
	return signed + "." + b64Encode(sig), nil
}

func hmacSHA256(secret, body []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return mac.Sum(nil)
}

func b64Encode(in []byte) string {
	return base64.RawURLEncoding.EncodeToString(in)
}

func b64Decode(in string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(in)
}

func randomID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("jti-%d", time.Now().UnixNano())
	}
	return b64Encode(buf)
}

func trimStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
