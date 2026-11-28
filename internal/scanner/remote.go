// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The Agent Substrate gateway image has no Python, so it cannot run
// skill-scanner or the plugin scanner itself (GAP-0477). A scanner sidecar in
// the gateway pod runs them from the release's own scanner runtime
// (`defenseclaw-gateway substrate scan-worker`), and RemoteScanner is the
// gateway's side: it copies the folder the runtime scan wrote into a job
// folder of the shared emptyDir and asks the worker over a unix socket. No
// rule is copied into Go; the verdict is still the gateway's so.decide.
const (
	// DefaultScanDir is the shared emptyDir of the gateway pod.
	DefaultScanDir = "/run/defenseclaw-scan"
	// ScanSocketName is the worker's socket in the scan folder (0600).
	ScanSocketName = "scan.sock"
	// ScanJobsDirName holds one folder per job, named by its id.
	ScanJobsDirName = "jobs"
	// RemoteKindSkill and RemoteKindPlugin are the job kinds.
	RemoteKindSkill  = "skill"
	RemoteKindPlugin = "plugin"
	// maxRemoteAnswer bounds the worker's answer.
	maxRemoteAnswer = 8 << 20
)

// ScanJobIDRE is a job id: 32 lower-case hex.
var ScanJobIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ErrScanTimeout is a scan that did not finish inside its timeout, waiting
// for a worker slot included: never an allow (skill_scan_timeout).
var ErrScanTimeout = errors.New("the skill scan did not finish in time")

// RemoteSettings are the static skill-scanner settings the gateway's config
// names. Only static analyzers run in the cluster: no LLM judge, VirusTotal,
// AI Defense or OSV, so the worker needs no egress and no secret.
type RemoteSettings struct {
	Policy        string `json:"policy,omitempty"`
	CustomPolicy  []byte `json:"custom_policy,omitempty"`
	Lenient       bool   `json:"lenient,omitempty"`
	UseBehavioral bool   `json:"use_behavioral,omitempty"`
	UseTrigger    bool   `json:"use_trigger,omitempty"`
}

// RemoteScanRequest is POST /v1/scan.
type RemoteScanRequest struct {
	Job      string         `json:"job"`
	Kind     string         `json:"kind"`
	Settings RemoteSettings `json:"settings"`
}

// RemoteScanAnswer is the worker's answer. Code is "" on a scan that ran,
// else unavailable (no scanner runtime in the sidecar), timeout, refused (a
// job the worker will not scan) or failed.
type RemoteScanAnswer struct {
	// Job is the job the answer is for; the gateway takes no answer for
	// another (GAP-0873).
	Job    string      `json:"job,omitempty"`
	Result *ScanResult `json:"result,omitempty"`
	Code   string      `json:"code,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// RemoteHealth is GET /v1/health.
type RemoteHealth struct {
	Ready   bool   `json:"ready"`
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
}

// RemoteScanner implements Scanner over the scanner sidecar.
type RemoteScanner struct {
	Kind     string
	Dir      string
	Timeout  time.Duration
	Settings RemoteSettings
}

// NewRemoteSkillScanner is the gateway's skill scan through the sidecar,
// with the static settings of cfg (scanners.skill_scanner).
func NewRemoteSkillScanner(cfg config.SkillScannerConfig, timeout time.Duration) (*RemoteScanner, error) {
	st := RemoteSettings{Policy: cfg.EffectivePolicy(), Lenient: cfg.Lenient, UseBehavioral: cfg.UseBehavioral, UseTrigger: cfg.UseTrigger}
	if st.Policy == config.SkillScannerPolicyCustom {
		// The verified bytes, never another policy (as policyArg).
		data, err := cfg.PolicyFile.ReadVerified()
		if err != nil {
			return nil, fmt.Errorf("scanner: skill-scanner custom policy refused: %w", err)
		}
		st.CustomPolicy = data
	}
	return &RemoteScanner{Kind: RemoteKindSkill, Dir: DefaultScanDir, Timeout: timeout, Settings: st}, nil
}

// NewRemotePluginScanner is the plugin scan through the sidecar.
func NewRemotePluginScanner(timeout time.Duration) *RemoteScanner {
	return &RemoteScanner{Kind: RemoteKindPlugin, Dir: DefaultScanDir, Timeout: timeout}
}

func (r *RemoteScanner) Name() string {
	if r.Kind == RemoteKindPlugin {
		return "plugin-scanner"
	}
	return "skill-scanner"
}
func (r *RemoteScanner) Version() string            { return "sidecar" }
func (r *RemoteScanner) SupportedTargets() []string { return []string{r.Kind} }

func (r *RemoteScanner) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return 20 * time.Second
}

// ScanClient is an HTTP client over the worker's socket in dir.
func ScanClient(dir string) *http.Client {
	sock := filepath.Join(dir, ScanSocketName)
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		DisableKeepAlives: true,
	}}
}

// unavailable wraps err so Unavailable reports it: the fail mode decides.
func unavailable(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrScannerRuntimeUnavailable}, a...)...)
}

// Scan copies target into a new job folder and asks the worker. A missing
// socket or a worker that does not answer is Unavailable (the fail mode
// decides, as rel); a timeout is ErrScanTimeout.
func (r *RemoteScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	if err := requireScannerTargetPath(target); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(filepath.Join(r.Dir, ScanSocketName)); err != nil || fi.Mode().Type() != os.ModeSocket {
		return nil, unavailable("the skill scanner sidecar is not running (no %s)", filepath.Join(r.Dir, ScanSocketName))
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	job := hex.EncodeToString(raw[:])
	jobs := filepath.Join(r.Dir, ScanJobsDirName)
	if err := os.MkdirAll(jobs, 0o700); err != nil {
		return nil, unavailable("scan jobs folder: %v", err)
	}
	// A jobs folder or job that is a link would put the skill where its
	// target is, not where the worker reads (GAP-0873).
	jobsInfo, err := realFolder(jobs)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(jobs, job)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	if _, err := realFolder(dir); err != nil {
		return nil, err
	}
	if err := copyRegularTree(target, dir); err != nil {
		return nil, err
	}
	if fi, err := realFolder(jobs); err != nil || !os.SameFile(fi, jobsInfo) {
		return nil, fmt.Errorf("scanner sidecar: the scan jobs folder %s changed while the job was written", jobs)
	}
	body, _ := json.Marshal(RemoteScanRequest{Job: job, Kind: r.Kind, Settings: r.Settings})
	// The worker enforces the timeout; the client waits a little longer so
	// its answer (timeout) arrives rather than a cut connection.
	cctx, cancel := context.WithTimeout(ctx, r.timeout()+5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, "http://scan/v1/scan", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := ScanClient(r.Dir).Do(req)
	if err != nil {
		if cctx.Err() != nil && ctx.Err() == nil {
			return nil, ErrScanTimeout
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, unavailable("the skill scanner sidecar did not answer: %v", err)
	}
	defer resp.Body.Close()
	var ans RemoteScanAnswer
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRemoteAnswer)).Decode(&ans); err != nil {
		return nil, fmt.Errorf("scanner sidecar answer (HTTP %d): %w", resp.StatusCode, err)
	}
	if ans.Job != job {
		// Not the worker's answer to this job: never a result.
		return nil, fmt.Errorf("scanner sidecar: the answer is for job %q, not %s", ans.Job, job)
	}
	switch ans.Code {
	case "":
		if ans.Result == nil {
			return nil, errors.New("scanner sidecar: empty answer")
		}
		ans.Result.Target = target
		return ans.Result, nil
	case "unavailable":
		return nil, unavailable("%s", ans.Error)
	case "timeout":
		return nil, ErrScanTimeout
	default:
		return ans.Result, fmt.Errorf("scanner sidecar: %s: %s", ans.Code, ans.Error)
	}
}

// Health asks the worker whether its scanner runtime is ready (the doctor
// row and the missing-tool check).
func (r *RemoteScanner) Health(ctx context.Context) RemoteHealth {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(cctx, http.MethodGet, "http://scan/v1/health", nil)
	resp, err := ScanClient(r.Dir).Do(req)
	if err != nil {
		return RemoteHealth{Error: "the skill scanner sidecar is not running: " + err.Error()}
	}
	defer resp.Body.Close()
	var h RemoteHealth
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&h); err != nil {
		return RemoteHealth{Error: "the skill scanner sidecar answered badly: " + err.Error()}
	}
	return h
}

// realFolder is the Lstat of path when it is a folder (not a link to one)
// of this process's user that no one else may write.
func realFolder(path string) (os.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 || !ownedBySelf(fi) {
		return nil, fmt.Errorf("scanner sidecar: %s is not a private folder of this user (mode %v)", path, fi.Mode())
	}
	return fi, nil
}

// copyRegularTree copies the folders and regular files of src into dst;
// links and other kinds are not copied (the worker refuses them anyway).
func copyRegularTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil || rel == "." {
			return err
		}
		if strings.HasPrefix(rel, "..") {
			return fmt.Errorf("scan job: %s is outside %s", p, src)
		}
		out := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.Mkdir(out, 0o700)
		case d.Type().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(out, data, 0o600)
		default:
			return nil
		}
	})
}
