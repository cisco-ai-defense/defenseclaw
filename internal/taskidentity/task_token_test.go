package taskidentity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestIssueValidateAndResourceScope(t *testing.T) {
	svc, err := New("defenseclaw-test", []byte("0123456789abcdef0123456789abcdef"), NewInMemoryRevoker())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	token, issued, err := svc.Issue(IssueRequest{
		TaskID:           "task-123",
		TaskType:         "incident_triage",
		ParentAgentID:    "agent:triage:v1:sre",
		AllowedResources: []string{"database:customers", "api:/reports/*"},
		Scopes:           []string{"read", "query"},
		TTL:              10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.TokenID == "" || !strings.Contains(token, ".") {
		t.Fatalf("bad issued token: %q %+v", token, issued)
	}
	claims, err := svc.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.TaskID != "task-123" || claims.ParentAgentID != "agent:triage:v1:sre" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if !ResourceAllowed(claims, "api:/reports/q4") {
		t.Fatalf("expected prefix resource to be allowed")
	}
	if ResourceAllowed(claims, "secret:/vault") {
		t.Fatalf("unexpected resource allowed")
	}
}

func TestTamperAndRevocationFail(t *testing.T) {
	revoker := NewInMemoryRevoker()
	svc, err := New("defenseclaw-test", []byte("0123456789abcdef0123456789abcdef"), revoker)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	token, claims, err := svc.Issue(IssueRequest{TaskID: "task", ParentAgentID: "agent", AllowedResources: []string{"*"}})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := svc.Validate(context.Background(), token+"x"); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected invalid signature, got %v", err)
	}
	if err := svc.Revoke(context.Background(), claims); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.Validate(context.Background(), token); !errors.Is(err, ErrRevoked) {
		t.Fatalf("expected revoked, got %v", err)
	}
}

func TestExpiredTokenFails(t *testing.T) {
	svc, err := New("defenseclaw-test", []byte("0123456789abcdef0123456789abcdef"), NewInMemoryRevoker())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	now := time.Unix(1000, 0)
	svc.now = func() time.Time { return now }
	token, _, err := svc.Issue(IssueRequest{TaskID: "task", ParentAgentID: "agent", AllowedResources: []string{"*"}, TTL: time.Second})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	svc.now = func() time.Time { return now.Add(2 * time.Second) }
	if _, err := svc.Validate(context.Background(), token); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expired, got %v", err)
	}
}
