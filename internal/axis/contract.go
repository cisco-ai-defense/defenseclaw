package axis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const ProtocolVersion = "axis-execution/v1"

type ToolClass string

const (
	ToolRead  ToolClass = "read"
	ToolWrite ToolClass = "write"
	ToolPatch ToolClass = "patch"
)

type Invocation struct {
	Program string   `json:"program"`
	Args    []string `json:"args,omitempty"`
	Stdin   string   `json:"stdin_hash,omitempty"`
	Patch   string   `json:"patch_hash,omitempty"`
	Timeout int      `json:"timeout_seconds,omitempty"`
}
type AuthorizationRequest struct {
	ProtocolVersion string     `json:"protocol_version"`
	ExecutionID     string     `json:"execution_id"`
	SessionID       string     `json:"mcp_session_id"`
	CallID          string     `json:"tool_call_id"`
	ToolClass       ToolClass  `json:"tool_class"`
	Workspace       string     `json:"workspace"`
	RelativeCWD     string     `json:"relative_cwd"`
	Invocation      Invocation `json:"invocation"`
	RequestDigest   string     `json:"request_digest"`
}
type AuthorizationResponse struct {
	Decision      string    `json:"decision"`
	RequestDigest string    `json:"request_digest"`
	EvaluationID  string    `json:"evaluation_id,omitempty"`
	PolicyID      string    `json:"policy_id,omitempty"`
	PolicyHash    string    `json:"policy_hash,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	Lanes         []string  `json:"required_lanes,omitempty"`
	Reason        string    `json:"reason,omitempty"`
}
type ResultRequest struct {
	ProtocolVersion string `json:"protocol_version"`
	ExecutionID     string `json:"execution_id"`
	ExitCode        int    `json:"exit_code"`
	Signal          int    `json:"signal,omitempty"`
	TimedOut        bool   `json:"timed_out,omitempty"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
}
type ResultResponse struct {
	Decision string `json:"decision"`
	Message  string `json:"message"`
}

func Canonical(v any) ([]byte, error) { return json.Marshal(v) }
func Digest(v any) (string, error) {
	b, e := Canonical(v)
	if e != nil {
		return "", e
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}
func (r AuthorizationRequest) Validate(registry map[string]string) error {
	if r.ProtocolVersion != ProtocolVersion {
		return errors.New("unsupported protocol version")
	}
	if r.ExecutionID == "" || r.SessionID == "" || r.CallID == "" {
		return errors.New("execution, session, and call IDs are required")
	}
	if r.ToolClass != ToolRead && r.ToolClass != ToolWrite && r.ToolClass != ToolPatch {
		return errors.New("unknown tool class")
	}
	root, ok := registry[r.Workspace]
	if !ok || filepath.Clean(root) != r.Workspace {
		return errors.New("workspace is not registered")
	}
	if _, e := ResolveCWD(root, r.RelativeCWD); e != nil {
		return e
	}
	if r.Invocation.Program == "" || len(r.Invocation.Args) > 128 || r.Invocation.Timeout < 0 || r.Invocation.Timeout > 900 {
		return errors.New("invalid invocation")
	}
	if len(r.Invocation.Stdin) > 128 || len(r.Invocation.Patch) > 128 {
		return errors.New("input hash too long")
	}
	return nil
}
func ResolveCWD(root, relative string) (string, error) {
	if root == "" || filepath.IsAbs(relative) || strings.Contains(relative, "\x00") {
		return "", errors.New("invalid working directory")
	}
	candidate := filepath.Join(root, filepath.Clean(relative))
	cr, e := filepath.EvalSymlinks(root)
	if e != nil {
		return "", fmt.Errorf("workspace: %w", e)
	}
	cc, e := filepath.EvalSymlinks(candidate)
	if e != nil {
		return "", fmt.Errorf("cwd: %w", e)
	}
	rel, e := filepath.Rel(cr, cc)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("cwd escapes workspace")
	}
	return cc, nil
}

type Manifest struct {
	ProtocolVersion string   `json:"protocol_version"`
	Provider        string   `json:"provider"`
	Model           string   `json:"model"`
	Tools           []string `json:"tools"`
	ManifestHash    string   `json:"manifest_hash"`
	CatalogHash     string   `json:"catalog_hash"`
	ReleaseID       string   `json:"release_id"`
}

var ApprovedTools = []string{"run", "run_write", "apply_patch"}

func (m Manifest) Validate(x Manifest) error {
	if m.ProtocolVersion != ProtocolVersion || m.Provider != x.Provider || m.Model != x.Model || m.ReleaseID != x.ReleaseID {
		return errors.New("manifest identity mismatch")
	}
	if len(m.Tools) != len(ApprovedTools) {
		return errors.New("tool manifest mismatch")
	}
	for i, t := range ApprovedTools {
		if m.Tools[i] != t {
			return errors.New("unapproved or reordered tool")
		}
	}
	if m.CatalogHash != x.CatalogHash || m.ManifestHash != x.ManifestHash {
		return errors.New("manifest hash mismatch")
	}
	return nil
}
