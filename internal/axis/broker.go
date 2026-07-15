package axis

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	_ "modernc.org/sqlite"
	"net/http"
	"strings"
	"time"
)

type Broker struct {
	DB                              *sql.DB
	Registry                        map[string]string
	PolicyID, PolicyHash, ReleaseID string
	Healthy                         bool
	LocalJudge                      bool
}

func NewBroker(db *sql.DB, registry map[string]string) *Broker {
	return &Broker{DB: db, Registry: registry, PolicyID: "mandatory-axis-v1", PolicyHash: "", ReleaseID: "unreleased", Healthy: true, LocalJudge: true}
}
func (b *Broker) Init() error {
	_, e := b.DB.Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS executions (execution_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, call_id TEXT NOT NULL, request_digest TEXT NOT NULL, state TEXT NOT NULL, decision TEXT NOT NULL, policy_hash TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(session_id,call_id)); CREATE TABLE IF NOT EXISTS outbox (event_id TEXT PRIMARY KEY, execution_id TEXT NOT NULL, phase TEXT NOT NULL, payload_hash TEXT NOT NULL, created_at TEXT NOT NULL)")
	return e
}
func requestDigest(r AuthorizationRequest) (string, error) { r.RequestDigest = ""; return Digest(r) }
func (b *Broker) Authorize(ctx context.Context, r AuthorizationRequest) AuthorizationResponse {
	d, e := requestDigest(r)
	if e != nil || d != r.RequestDigest {
		return AuthorizationResponse{Decision: "deny", RequestDigest: r.RequestDigest, Reason: "request digest mismatch"}
	}
	if e = r.Validate(b.Registry); e != nil {
		return b.recordDenied(ctx, r, d, e.Error())
	}
	var old, oldDigest, state string
	e = b.DB.QueryRowContext(ctx, "SELECT state,request_digest,decision FROM executions WHERE session_id=? AND call_id=?", r.SessionID, r.CallID).Scan(&state, &oldDigest, &old)
	if e == nil {
		if oldDigest != d {
			return AuthorizationResponse{Decision: "deny", RequestDigest: d, Reason: "idempotency digest mismatch"}
		}
		return AuthorizationResponse{Decision: old, RequestDigest: d, Reason: "idempotent replay"}
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return AuthorizationResponse{Decision: "deny", RequestDigest: d, Reason: "audit database unavailable"}
	}
	if !b.Healthy || !b.LocalJudge {
		return b.recordDenied(ctx, r, d, "required authorization lane unavailable")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, e := b.DB.BeginTx(ctx, nil)
	if e != nil {
		return AuthorizationResponse{Decision: "deny", RequestDigest: d, Reason: "audit transaction failed"}
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO executions VALUES(?,?,?,?,?,?,?,?,?)", r.ExecutionID, r.SessionID, r.CallID, d, string(Received), "deny", b.PolicyHash, now, now)
	if e == nil {
		_, e = tx.ExecContext(ctx, "INSERT INTO outbox VALUES(?,?,?,?,?)", r.ExecutionID+"-received", r.ExecutionID, string(Received), d, now)
	}
	if e == nil {
		e = tx.Commit()
	} else {
		_ = tx.Rollback()
	}
	if e != nil {
		return AuthorizationResponse{Decision: "deny", RequestDigest: d, Reason: "audit commit failed"}
	}
	if _, e = b.DB.ExecContext(ctx, "UPDATE executions SET state=?,decision=?,updated_at=? WHERE execution_id=?", string(Authorized), "allow", now, r.ExecutionID); e != nil {
		return AuthorizationResponse{Decision: "deny", RequestDigest: d, Reason: "authorization persistence failed"}
	}
	return AuthorizationResponse{Decision: "allow", RequestDigest: d, EvaluationID: r.ExecutionID + "-eval", PolicyID: b.PolicyID, PolicyHash: b.PolicyHash, ExpiresAt: time.Now().UTC().Add(5 * time.Second), Lanes: []string{"local-rules", "local-judge"}}
}
func (b *Broker) recordDenied(ctx context.Context, r AuthorizationRequest, d, reason string) AuthorizationResponse {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = b.DB.ExecContext(ctx, "INSERT OR IGNORE INTO executions VALUES(?,?,?,?,?,?,?,?,?)", r.ExecutionID, r.SessionID, r.CallID, d, string(Denied), "deny", b.PolicyHash, now, now)
	return AuthorizationResponse{Decision: "deny", RequestDigest: d, Reason: reason}
}
func (b *Broker) Result(ctx context.Context, r ResultRequest) ResultResponse {
	if r.ProtocolVersion != ProtocolVersion {
		return ResultResponse{"withhold", "invalid result protocol"}
	}
	if len(r.Stdout) > 1<<20 || len(r.Stderr) > 1<<20 {
		return ResultResponse{"withhold", "output exceeds bounded limit"}
	}
	blocked := strings.Contains(strings.ToLower(r.Stdout), "authorization denied") || strings.Contains(strings.ToLower(r.Stderr), "secret leaked")
	decision := "release"
	message := r.Stdout
	if blocked {
		decision = "withhold"
		message = "Execution output withheld by DefenseClaw policy."
	}
	state := ResultReleased
	if decision != "release" {
		state = ResultWithheld
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, e := b.DB.ExecContext(ctx, "UPDATE executions SET state=?,updated_at=? WHERE execution_id=? AND state IN (?,?,?,?)", string(state), now, r.ExecutionID, string(Exited), string(TimedOut), string(Signaled), string(LaunchFailed))
	if e != nil {
		return ResultResponse{"withhold", "result audit failed"}
	}
	return ResultResponse{decision, message}
}
func (b *Broker) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !b.Healthy || !b.LocalJudge {
			http.Error(w, "not ready", 503)
			return
		}
		w.WriteHeader(200)
	})
	mux.HandleFunc("/api/v1/execution/authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("X-DefenseClaw-Route") != "execution" {
			http.Error(w, "forbidden", 403)
			return
		}
		var in AuthorizationRequest
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in) != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		out := b.Authorize(r.Context(), in)
		w.Header().Set("content-type", "application/json")
		if out.Decision != "allow" {
			w.WriteHeader(403)
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/api/v1/execution/result", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("X-DefenseClaw-Route") != "execution" {
			http.Error(w, "forbidden", 403)
			return
		}
		var in ResultRequest
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&in) != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		out := b.Result(r.Context(), in)
		w.Header().Set("content-type", "application/json")
		if out.Decision != "release" {
			w.WriteHeader(403)
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	return mux
}
