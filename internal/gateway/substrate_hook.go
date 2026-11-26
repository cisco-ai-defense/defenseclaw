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

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// The actor kit (lane A5, internal/substrate/kit) posts every hook event
// in an envelope:
//
//	{"v": "1", "connector": "claudecode", "event": "PreToolUse",
//	 "hook_contract": "...", "mode": "interactive", "kit_version": "...",
//	 "payload": <the agent's hook event, byte for byte>,
//	 "facts": {"paths": [...], "files": [...], "truncated": false}}
//
// The gateway unwraps it: the connector's hook handler reads the payload as
// it reads a host hook's body, and the facts (what the kit saw in the
// actor's file system) go into the context as claims (E19, E20). The mode
// is the kit's view only: the registration decides it.

// substrateEnvelopeVersion is the one envelope version, the kit's own
// constant (kit.EnvelopeVersion): found live on E1, the kit moved to "1"
// while the gateway accepted only "dcactor/1" and refused every hook
// (GAP-0138). The old spelling is gone; no released kit sent it.
const substrateEnvelopeVersion = kit.EnvelopeVersion

// substrateAttachedMaxBytes caps attached file content (D9's 1 MiB).
const substrateAttachedMaxBytes = 1 << 20

// substrateEnvelopeMaxBytes bounds a whole envelope: a payload of at most
// apiRequestBodyMaxBytes plus at most substrateAttachedMaxBytes of attached
// file content (base64 in JSON) and path facts. A variable because rel reads
// apiRequestBodyMaxBytes from the embedded limits file (OpenClaw, 86f19772d3).
var substrateEnvelopeMaxBytes = apiRequestBodyMaxBytes + 2*substrateAttachedMaxBytes + 256<<10

// substrateEnvelope is the kit's hook envelope.
type substrateEnvelope struct {
	V            string          `json:"v"`
	Connector    string          `json:"connector"`
	Event        string          `json:"event,omitempty"`
	HookContract string          `json:"hook_contract,omitempty"`
	Mode         string          `json:"mode"`
	KitVersion   string          `json:"kit_version"`
	Payload      json.RawMessage `json:"payload"`
	Facts        *SubstrateFacts `json:"facts,omitempty"`
}

// SubstrateFacts are the kit's observations of the actor's file system.
// Every field is a claim made by code running as the agent's user.
type SubstrateFacts struct {
	Paths []SubstratePathFact     `json:"paths,omitempty"`
	Files []SubstrateAttachedFile `json:"files,omitempty"`
	// Skills fingerprints every skill folder (A5's kit, GAP-0039).
	Skills []SubstrateSkillFingerprint `json:"skills,omitempty"`
	// ProjectHooks are the project settings files that declare hooks the
	// actor's managed settings ignore (the kit's SessionStart fact,
	// GAP-0479): recorded, never run.
	ProjectHooks []kit.ProjectHooks `json:"project_hooks,omitempty"`
	// Proofs are the laptop's file-system proofs the kit made in the
	// actor's file system (kit.ProofPrivateKeyRead, substrate-1 GAP-0471).
	Proofs    []string `json:"proofs,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
}

// SubstrateSkillFingerprint is one skill folder's content digest
// (skilldigest); Attached says its files are in Files (role skill_file) in
// this post.
type SubstrateSkillFingerprint struct {
	Path     string `json:"path"`
	FP       string `json:"fp"`
	Attached bool   `json:"attached,omitempty"`
	// Receipt is the scan receipt a gateway gave for this fingerprint.
	Receipt string `json:"receipt,omitempty"`
	// Over marks a folder past a kit cap (no FP): the fail mode decides.
	Over bool `json:"over,omitempty"`
	// Sums are the file digests of a folder that did not fit the post (name
	// -> sha256 hex): FP is rebuilt from them and matched to the attested
	// template build (GAP-0164).
	Sums map[string]string `json:"sums,omitempty"`
	// Big marks a folder bigger than one post carries: it is never attached.
	Big bool `json:"big,omitempty"`
}

// SubstratePathFact is one path argument as the actor resolves it.
type SubstratePathFact struct {
	Field       string   `json:"field"`
	Path        string   `json:"path"`
	Abs         string   `json:"abs"`
	Resolved    string   `json:"resolved,omitempty"`
	Entry       string   `json:"entry,omitempty"`
	PrivateHome bool     `json:"private_home,omitempty"`
	LinkChain   []string `json:"link_chain,omitempty"`
	Type        string   `json:"type"`
	Mode        string   `json:"mode,omitempty"`
	UID         int      `json:"uid"`
	GID         int      `json:"gid"`
	NLink       uint64   `json:"nlink,omitempty"`
	Size        int64    `json:"size,omitempty"`
	InsideCWD   bool     `json:"inside_cwd"`
	Error       string   `json:"error,omitempty"`
}

// SubstrateAttachedFile is a file the kit read for the gateway.
type SubstrateAttachedFile struct {
	Role      string `json:"role"`
	Path      string `json:"path"`
	Resolved  string `json:"resolved,omitempty"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Content   []byte `json:"content,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type substrateEnvelopeKey struct{}

func substrateEnvelopeFrom(ctx context.Context) (substrateEnvelope, bool) {
	e, ok := ctx.Value(substrateEnvelopeKey{}).(substrateEnvelope)
	return e, ok
}

// substrateEnvelopeVersionOK accepts the envelope version the gateway names
// (substrateEnvelopeVersion) and "1", which the actor kit and the connector
// notify bridge send (A5 3d9df709db, A1); the two lanes had settled on
// different strings and a gateway that took only one refused the other.
func substrateEnvelopeVersionOK(v string) bool {
	return v == substrateEnvelopeVersion || v == "1"
}

// substrateHookContract is the hook contract the binding reads: the
// registration's (from the template attestation), else the envelope's.
func substrateHookContract(ctx context.Context, reg registry.Registration) string {
	if reg.HookContract != "" {
		return reg.HookContract
	}
	if e, ok := substrateEnvelopeFrom(ctx); ok {
		return strings.TrimSpace(e.HookContract)
	}
	return ""
}

// substrateEnvelopeMiddleware unwraps a hook or notify post's envelope.
func substrateEnvelopeMiddleware(st *substrateState, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := substrateRouteFrom(r.Context())
		if r.Method != http.MethodPost || (route.class != sandboxauth.RouteHook && route.class != sandboxauth.RouteNotify) {
			next.ServeHTTP(w, r)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, substrateEnvelopeMaxBytes+1))
		_ = r.Body.Close()
		if err != nil {
			writeSubstrateRefusal(w, http.StatusBadRequest, "envelope_unreadable")
			return
		}
		if int64(len(raw)) > substrateEnvelopeMaxBytes {
			writeSubstrateRefusal(w, http.StatusRequestEntityTooLarge, "envelope_too_large")
			return
		}
		var env substrateEnvelope
		dec := json.NewDecoder(bytes.NewReader(raw))
		if err := dec.Decode(&env); err != nil || !substrateEnvelopeVersionOK(env.V) || len(env.Payload) == 0 {
			st.logRefusal("hook envelope refused (version %q, %d payload bytes)", env.V, len(env.Payload))
			writeSubstrateRefusal(w, http.StatusBadRequest, "envelope_invalid")
			return
		}
		if sandboxauth.CanonicalConnector(env.Connector) != sandboxauth.CanonicalConnector(route.connector) {
			writeSubstrateRefusal(w, http.StatusBadRequest, "envelope_connector_mismatch")
			return
		}
		if int64(len(env.Payload)) > apiRequestBodyMaxBytes {
			writeSubstrateRefusal(w, http.StatusRequestEntityTooLarge, "payload_too_large")
			return
		}
		if env.Facts != nil {
			var attached int64
			for _, f := range env.Facts.Files {
				attached += int64(len(f.Content))
			}
			if attached > substrateAttachedMaxBytes {
				writeSubstrateRefusal(w, http.StatusRequestEntityTooLarge, "attached_content_too_large")
				return
			}
		}
		// GAP-0504: an exposed actor_secrets value never reaches the hook
		// rows (tool results, typed prompts).
		if reg, ok := substrateRegistrationFrom(r.Context()); ok {
			if masked, names := substrateMaskExposed(env.Payload, st.exposedValues(reg.Profile)); len(names) > 0 {
				env.Payload = masked
				st.logRefusal("hook payload of %s/%s carried the exposed value(s) %s (actor_secrets); replaced before evaluation and audit",
					reg.Atespace, reg.Name, strings.Join(names, ", "))
				st.auditExposedMasked(r.Context(), reg, env.Event, names)
			}
		}
		// The facts stay on the envelope (substrateEnvelopeFrom); the skill
		// scan below reads the attached files from it.
		ctx := withSkillPostStart(context.WithValue(r.Context(), substrateEnvelopeKey{}, env))
		// The kit's proofs and link targets the policy reads (GAP-0471).
		ctx = withSubstrateGuestClaims(ctx, env)
		r = r.WithContext(ctx)
		r.Body = io.NopCloser(bytes.NewReader(env.Payload))
		r.ContentLength = int64(len(env.Payload))
		r.Header.Set("Content-Length", strconv.Itoa(len(env.Payload)))
		r.Header.Set("Content-Type", "application/json")
		if env.Event != "" && r.Header.Get("X-DefenseClaw-Hook-Event") == "" {
			r.Header.Set("X-DefenseClaw-Hook-Event", env.Event)
		}
		if route.class == sandboxauth.RouteHook {
			st.substrateRecordProjectHooks(ctx, env)
			msg := st.substrateMCPRefusal(ctx, env)
			if msg == "" {
				msg = st.substrateSkillWriteRefusal(ctx, env)
			}
			if msg != "" {
				st.logRefusal("%s", msg)
				writeSubstrateMCPRefusal(w, msg)
				if reg, ok := substrateRegistrationFrom(ctx); ok {
					body, _ := json.Marshal(map[string]string{"reason": kit.MCPRefusedCode, "message": msg})
					st.substrateRecordDecision(ctx, reg, env.Event, body)
				}
				return
			}
			sk := st.substrateSkills(ctx, env.Connector, env.Facts)
			if msg := st.substrateSkillUseGate(ctx, env, &sk); msg != "" {
				st.logRefusal("%s", msg)
				writeSubstrateSkillRefusal(w, msg, sk.held)
				if reg, ok := substrateRegistrationFrom(ctx); ok {
					body, _ := json.Marshal(map[string]string{"reason": kit.MCPRefusedCode, "message": msg})
					st.substrateRecordDecision(ctx, reg, env.Event, body)
				}
				return
			}
			answer := withSubstrateAnswer(w, r, next, sk)
			if reg, ok := substrateRegistrationFrom(ctx); ok {
				st.substrateRecordDecision(ctx, reg, env.Event, answer)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

// serveSubstrateRelayVerify answers the actor relay's session check (lane
// A5's GatewayVerifier): the session token must name the calling actor's
// incarnation, which the gateway knows from the actor JWT, not from
// anything the relay says.
func (a *APIServer) serveSubstrateRelayVerify(st *substrateState, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeSubstrateRefusal(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if st == nil || st.cfg.Sessions == nil {
		writeSubstrateRefusal(w, http.StatusServiceUnavailable, "sessions_unavailable")
		return
	}
	actor, ok := substrateActorFrom(r.Context())
	if !ok {
		writeSubstrateRefusal(w, http.StatusUnauthorized, "missing_token")
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil || in.Token == "" {
		writeSubstrateRefusal(w, http.StatusBadRequest, "token_required")
		return
	}
	target := actor.Atespace + "/" + actor.Name
	s, err := st.cfg.Sessions.Verify(in.Token)
	if err != nil {
		// No verified person: the row names the actor only (GAP-0434).
		a.substrateAuditRelayDenied(st, r, "MEDIUM", "session_refused", target, "")
		writeSubstrateRefusal(w, http.StatusForbidden, "session_refused")
		return
	}
	if s.Actor.Atespace != actor.Atespace || s.Actor.Name != actor.Name || s.ActorUID != actor.UID {
		// The session token names the person who tried (GAP-0434).
		a.substrateAuditRelayDenied(st, r, "MEDIUM", "session_for_another_actor", s.ActorRef, s.Person)
		writeSubstrateRefusal(w, http.StatusForbidden, "session_for_another_actor")
		return
	}
	// A session is the actor's own person's only (GAP-0435): a token for
	// this actor that names anyone else, however it was minted, is refused.
	if reg, ok := substrateRegistrationFrom(r.Context()); !ok || reg.Person.Subject == "" || s.Person != reg.Person.ID() {
		a.substrateAuditRelayDenied(st, r, "HIGH", "session_not_owner", target, s.Person)
		writeSubstrateRefusal(w, http.StatusForbidden, "session_not_owner")
		return
	}
	// A session minted before its person's sign-ins were ended is refused,
	// and so is every session while this replica's list is stale (B5.1).
	if status, reason := st.substrateRevocationRefusal(s.Person, "", s.IssuedAt); status != 0 {
		a.substrateAuditRelayDenied(st, r, "MEDIUM", reason, target, s.Person)
		writeSubstrateRefusal(w, status, reason)
		return
	}
	// So is a session of an ended sign-in: a plain logout ends that one
	// token, and an end by time covers the sign-in's own issue time, so a
	// session a lagging replica handed out after the end is refused too
	// (GAP-0744). A session minted by released 1.0.10 names no sign-in, and
	// lives at most MaxSessionLifetime (1 h) across the upgrade; Issue never
	// mints one now (RV4-03). Compat shim for sessions minted by released
	// 1.0.10: remove in 1.0.12 and refuse a session that names no sign-in.
	if s.SignInKey != "" {
		if status, reason := st.substrateRevocationRefusal(s.Person, s.SignInKey, s.SignInIssuedAt); status != 0 {
			a.substrateAuditRelayDenied(st, r, "MEDIUM", reason, target, s.Person)
			writeSubstrateRefusal(w, status, reason)
			return
		}
	}
	// The admin listener issues a session only to the actor's own person,
	// and the check above holds a token minted any other way to that too.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	out := map[string]any{
		"person": s.Person, "actor": s.ActorRef, "actor_uid": s.ActorUID, "jti": s.TokenID, "expires": s.Expires,
	}
	// The relay serves a token only on the routes of its own dc.scope (B3),
	// and reads the scope from this answer on a relay-TLS kit (GAP-0815):
	// without it a stream token would be a terminal token there.
	if s.Scope != "" {
		out["scope"] = s.Scope
	}
	// A --task run's relay checks the task it runs is the one the
	// launcher registered (GAP-0071): the digest, never the text.
	if reg, ok := substrateRegistrationFrom(r.Context()); ok && reg.TaskDigest != "" {
		out["task_digest"] = reg.TaskDigest
	}
	_ = json.NewEncoder(w).Encode(out)
}
