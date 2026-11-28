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

package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relaytls"
)

// RelayCert is the live relay serving certificate of one actor incarnation
// (GAP-0861): the gateway checks a certificate request without proof of
// the live key against it, so every replica and a restarted gateway see
// the same one. It is kept apart from the Registration, which the launcher
// and the controller write back whole.
type RelayCert struct {
	Serial   string    `json:"serial,omitempty"`
	NotAfter time.Time `json:"not_after"`
	// CA is the issuing CA's fingerprint (relaytls.CA.Fingerprint), so a
	// renewal refused after an emergency CA rotation says so (GAP-0929).
	CA string `json:"ca,omitempty"`
	// Cleared is the mark recover leaves (GAP-0928): no certificate is
	// live, so the next request without proof is a first certificate, and
	// no certificate issued before it renews. It lasts one certificate life.
	Cleared bool `json:"cleared,omitempty"`
	// Prev is the serial the last renewal replaced, taken until PrevUntil
	// or until the relay presents Serial (GAP-0958): a renewal whose reply
	// was lost (a timeout, a dropped connection, a leader failover after
	// the write) is asked again with proof of Prev and gets the same
	// answer, and attach takes Prev meanwhile. Recover's mark has none.
	Prev      string    `json:"prev,omitempty"`
	PrevUntil time.Time `json:"prev_until,omitzero"`
	// Retries counts the renewals that proved Prev inside this grace
	// (GAP-0970). A lost reply asks once more; more than that is not a
	// lost reply. It starts over with each renewal and when the relay
	// presents the live serial.
	Retries int `json:"retries,omitempty"`
}

// relayCertClearedFor is how long recover's mark lasts: every certificate
// issued before it has expired by then (relaytls.CertTTL, with slack for
// the clocks of the replicas).
const relayCertClearedFor = relaytls.CertTTL + 10*time.Minute

// RelayCertClaim asks to record Cert as the actor's live certificate.
// With Replace it is recorded whatever is live (flag, a second
// certificate). With Expect, a renewal, it is a compare-and-swap on the
// live serial (GAP-0928): recorded only while Expect is the live
// certificate, or when the actor has no record at all, so a proof of any
// other certificate of the actor is a second certificate. Expect is also
// taken for the serial the live one replaced, until that one expires or
// the relay presents the live one (GAP-0958), so a renewal whose reply was
// lost is asked again. With neither it is recorded only when the actor has
// no live certificate.
type RelayCertClaim struct {
	Atespace string    `json:"atespace"`
	UID      string    `json:"uid"`
	Cert     RelayCert `json:"cert"`
	Replace  bool      `json:"replace,omitempty"`
	// Expect is the serial of the certificate a renewal proved.
	Expect string `json:"expect,omitempty"`
	// Seen is the serial attach found the relay serving; when it is the
	// live one, the previous one is no longer taken (GAP-0958). A Seen
	// claim records nothing else.
	Seen string `json:"seen,omitempty"`
	// Now is the gateway's clock (zero: the leader's).
	Now time.Time `json:"now,omitzero"`
}

// RelayCertClaimed is a claim's answer: Set when Cert is now the live one;
// Prev is the live certificate the claim found (zero for none); Retry when
// the renewal proved the previous serial (a retry after a lost reply).
type RelayCertClaimed struct {
	Set   bool      `json:"set"`
	Prev  RelayCert `json:"prev,omitzero"`
	Retry bool      `json:"retry,omitempty"`
	// Retries is how many retries this grace has seen, this one included
	// (GAP-0970).
	Retries int `json:"retries,omitempty"`
}

// RelayCerts is the leader's record of live relay certificates.
type RelayCerts interface {
	ClaimRelayCert(ctx context.Context, c RelayCertClaim) (RelayCertClaimed, error)
	// ClearRelayCert replaces the actor's record with recover's mark
	// (RelayCert.Cleared), so its relay's next request without proof is a
	// first certificate and no older certificate renews (the recover
	// route, an owner or administrator).
	ClearRelayCert(ctx context.Context, atespace, uid string) error
	// LiveRelayCert is the actor's unexpired record, the mark included
	// (ok false for none): under refuse, attach takes only the live
	// certificate and, in its grace, the previous one.
	LiveRelayCert(ctx context.Context, atespace, uid string) (RelayCert, bool, error)
}

// relayCertDir is the record's folder under the registry folder
// (OpenFileStore skips folders when it reads registrations).
const relayCertDir = "relaycerts"

type relayCertFile struct {
	Key string `json:"key"`
	RelayCert
}

func (s *FileStore) loadRelayCerts() error {
	dir := filepath.Join(s.dir, relayCertDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("registry: %w", err)
		}
		var f relayCertFile
		if err := json.Unmarshal(b, &f); err != nil || f.Key == "" || fileName(f.Key) != e.Name() {
			return fmt.Errorf("registry: %s/%s is not a relay certificate record", relayCertDir, e.Name())
		}
		s.certs[f.Key] = f.RelayCert
	}
	return nil
}

// ClaimRelayCert implements RelayCerts. Expired records are dropped as it
// goes, so the record holds about one entry per running actor.
func (s *FileStore) ClaimRelayCert(_ context.Context, c RelayCertClaim) (RelayCertClaimed, error) {
	key, err := sandboxreg.SubstrateKey(c.Atespace, c.UID)
	if err != nil {
		return RelayCertClaimed{}, fmt.Errorf("registry: %w", err)
	}
	if c.Seen != "" {
		return s.relayCertSeen(key, c.Seen)
	}
	if c.Cert.Serial == "" || c.Cert.NotAfter.IsZero() {
		return RelayCertClaimed{}, errors.New("registry: a relay certificate claim names the serial and the expiry")
	}
	now := c.Now
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out RelayCertClaimed
	old, live := s.certs[key]
	live = live && now.Before(old.NotAfter)
	if live {
		out.Prev = old
	}
	if c.Cert.Cleared || c.Cert.Prev != "" || c.Cert.Retries != 0 {
		return out, errors.New("registry: a relay certificate claim names only the serial, the expiry and the CA")
	}
	rec := c.Cert
	switch {
	case c.Replace:
	case c.Expect != "" && live && !old.Cleared && old.Serial == c.Expect:
		// The renewal of the live one: it stays taken until the relay
		// presents the new one, or until it expires.
		rec.Prev, rec.PrevUntil = old.Serial, old.NotAfter
	case c.Expect != "" && live && !old.Cleared && old.Prev == c.Expect && now.Before(old.PrevUntil):
		// The same renewal again: its reply was lost. The grace does not
		// grow with it.
		rec.Prev, rec.PrevUntil = old.Prev, old.PrevUntil
		rec.Retries = old.Retries + 1
		out.Retry, out.Retries = true, rec.Retries
	case live && (c.Expect != "" || !old.Cleared):
		return out, nil
	}
	b, err := json.Marshal(relayCertFile{Key: key, RelayCert: rec})
	if err != nil {
		return out, err
	}
	if err := writeFileAtomic(filepath.Join(s.dir, relayCertDir), fileName(key), b); err != nil {
		return out, err
	}
	s.certs[key] = rec
	out.Set = true
	for k, v := range s.certs {
		if !now.Before(v.NotAfter) {
			if err := os.Remove(filepath.Join(s.dir, relayCertDir, fileName(k))); err == nil || errors.Is(err, os.ErrNotExist) {
				delete(s.certs, k)
			}
		}
	}
	return out, nil
}

// relayCertSeen ends the previous serial's grace once attach finds the
// relay serving the live one (GAP-0958).
func (s *FileStore) relayCertSeen(key, serial string) (RelayCertClaimed, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.certs[key]
	if !ok || old.Cleared || old.Prev == "" || old.Serial != serial {
		return RelayCertClaimed{}, nil
	}
	old.Prev, old.PrevUntil, old.Retries = "", time.Time{}, 0
	b, err := json.Marshal(relayCertFile{Key: key, RelayCert: old})
	if err != nil {
		return RelayCertClaimed{}, err
	}
	if err := writeFileAtomic(filepath.Join(s.dir, relayCertDir), fileName(key), b); err != nil {
		return RelayCertClaimed{}, err
	}
	s.certs[key] = old
	return RelayCertClaimed{Set: true}, nil
}

// ClearRelayCert implements RelayCerts. The mark carries no serial, so
// neither the live certificate nor the previous one renews or is taken
// at attach.
func (s *FileStore) ClearRelayCert(_ context.Context, atespace, uid string) error {
	key, err := sandboxreg.SubstrateKey(atespace, uid)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	mark := RelayCert{Cleared: true, NotAfter: time.Now().Add(relayCertClearedFor)}
	b, err := json.Marshal(relayCertFile{Key: key, RelayCert: mark})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeFileAtomic(filepath.Join(s.dir, relayCertDir), fileName(key), b); err != nil {
		return err
	}
	s.certs[key] = mark
	return nil
}

// LiveRelayCert implements RelayCerts.
func (s *FileStore) LiveRelayCert(_ context.Context, atespace, uid string) (RelayCert, bool, error) {
	key, err := sandboxreg.SubstrateKey(atespace, uid)
	if err != nil {
		return RelayCert{}, false, fmt.Errorf("registry: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.certs[key]
	if !ok || !time.Now().Before(c.NotAfter) {
		return RelayCert{}, false, nil
	}
	return c, true, nil
}

type liveRelayCertOut struct {
	Cert RelayCert `json:"cert"`
	OK   bool      `json:"ok"`
}

// LiveRelayCert implements RelayCerts on the leader. It is never cached.
func (s *Remote) LiveRelayCert(ctx context.Context, atespace, uid string) (RelayCert, bool, error) {
	var out liveRelayCertOut
	err := s.Client.Call(ctx, leader.MethodRelayCertGet, leader.NewRequestID(), getIn{Atespace: atespace, UID: uid}, &out)
	return out.Cert, out.OK, err
}

// ClaimRelayCert implements RelayCerts on the leader. It is never cached.
func (s *Remote) ClaimRelayCert(ctx context.Context, c RelayCertClaim) (RelayCertClaimed, error) {
	var out RelayCertClaimed
	err := s.Client.Call(ctx, leader.MethodRelayCertClaim, leader.NewRequestID(), c, &out)
	return out, err
}

// ClearRelayCert implements RelayCerts on the leader.
func (s *Remote) ClearRelayCert(ctx context.Context, atespace, uid string) error {
	return s.Client.Call(ctx, leader.MethodRelayCertClear, leader.NewRequestID(), getIn{Atespace: atespace, UID: uid}, nil)
}

func serveRelayCerts(srv *leader.Server, rc RelayCerts) {
	srv.Handle(leader.MethodRelayCertClaim, leader.Typed(func(ctx context.Context, c RelayCertClaim) (RelayCertClaimed, error) {
		out, err := rc.ClaimRelayCert(ctx, c)
		if err != nil {
			return out, &leader.WireError{Code: leader.CodeBadRequest, Message: err.Error()}
		}
		return out, nil
	}))
	srv.Handle(leader.MethodRelayCertGet, leader.Typed(func(ctx context.Context, in getIn) (liveRelayCertOut, error) {
		c, ok, err := rc.LiveRelayCert(ctx, in.Atespace, in.UID)
		if err != nil {
			return liveRelayCertOut{}, &leader.WireError{Code: leader.CodeBadRequest, Message: err.Error()}
		}
		return liveRelayCertOut{Cert: c, OK: ok}, nil
	}))
	srv.Handle(leader.MethodRelayCertClear, leader.Typed(func(ctx context.Context, in getIn) (putOut, error) {
		if err := rc.ClearRelayCert(ctx, in.Atespace, in.UID); err != nil {
			return putOut{}, &leader.WireError{Code: leader.CodeBadRequest, Message: err.Error()}
		}
		return putOut{}, nil
	}))
}

// writeFileAtomic writes b to dir/name through a synced temporary file and
// a rename.
func writeFileAtomic(dir, name string, b []byte) error {
	tmp, err := os.CreateTemp(dir, ".reg-*")
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	_, werr := tmp.Write(b)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("registry: write: %v", errors.Join(werr, serr, cerr))
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("registry: %w", err)
	}
	return nil
}
