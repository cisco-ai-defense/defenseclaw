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

package leader

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Lease timings (the client-go leader-election defaults).
const (
	DefaultLeaseDuration = 15 * time.Second
	DefaultRenewDeadline = 10 * time.Second
	DefaultRetryPeriod   = 2 * time.Second
)

// In-cluster API defaults.
const (
	DefaultKubeTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	DefaultKubeCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

const microTime = "2006-01-02T15:04:05.000000Z07:00"

// LeaseAPI reads and writes one coordination.k8s.io/v1 Lease.
type LeaseAPI interface {
	Get(ctx context.Context) (*Lease, error)
	Create(ctx context.Context, l *Lease) (*Lease, error)
	Update(ctx context.Context, l *Lease) (*Lease, error)
}

// ErrLeaseNotFound and ErrLeaseConflict are what a LeaseAPI returns for a
// missing Lease and a stale resourceVersion.
var (
	ErrLeaseNotFound = errors.New("lease not found")
	ErrLeaseConflict = errors.New("lease changed")
)

// Lease is the part of a Lease object the elector uses.
type Lease struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Metadata   LeaseMeta `json:"metadata"`
	Spec       LeaseSpec `json:"spec"`
}

// LeaseMeta is the Lease metadata.
type LeaseMeta struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	ResourceVersion string `json:"resourceVersion,omitempty"`
}

// LeaseSpec is the Lease spec.
type LeaseSpec struct {
	HolderIdentity       *string `json:"holderIdentity,omitempty"`
	LeaseDurationSeconds *int32  `json:"leaseDurationSeconds,omitempty"`
	AcquireTime          *string `json:"acquireTime,omitempty"`
	RenewTime            *string `json:"renewTime,omitempty"`
	LeaseTransitions     *int32  `json:"leaseTransitions,omitempty"`
}

// KubeLeaseAPI is LeaseAPI over the Kubernetes REST API.
type KubeLeaseAPI struct {
	Server    string // https://kubernetes.default.svc
	Namespace string
	Name      string
	TokenFile string
	HTTP      *http.Client
}

func (k *KubeLeaseAPI) url(name bool) string {
	u := strings.TrimRight(k.Server, "/") + "/apis/coordination.k8s.io/v1/namespaces/" + url.PathEscape(k.Namespace) + "/leases"
	if name {
		u += "/" + url.PathEscape(k.Name)
	}
	return u
}

func (k *KubeLeaseAPI) do(ctx context.Context, method, u string, in *Lease) (*Lease, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	tok, err := os.ReadFile(k.TokenFile) // re-read: projected tokens rotate
	if err != nil {
		return nil, fmt.Errorf("lease: token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	resp, err := k.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
	case http.StatusNotFound:
		return nil, ErrLeaseNotFound
	case http.StatusConflict:
		return nil, ErrLeaseConflict
	default:
		return nil, fmt.Errorf("lease: %s: status %d", method, resp.StatusCode)
	}
	var out Lease
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("lease: answer does not decode: %w", err)
	}
	return &out, nil
}

// Get implements LeaseAPI.
func (k *KubeLeaseAPI) Get(ctx context.Context) (*Lease, error) {
	return k.do(ctx, http.MethodGet, k.url(true), nil)
}

// Create implements LeaseAPI.
func (k *KubeLeaseAPI) Create(ctx context.Context, l *Lease) (*Lease, error) {
	return k.do(ctx, http.MethodPost, k.url(false), l)
}

// Update implements LeaseAPI.
func (k *KubeLeaseAPI) Update(ctx context.Context, l *Lease) (*Lease, error) {
	return k.do(ctx, http.MethodPut, k.url(true), l)
}

// Elector holds a Lease for Identity.
type Elector struct {
	API      LeaseAPI
	Name     string
	Ns       string
	Identity string
	// Durations default to the client-go defaults.
	LeaseDuration, RenewDeadline, RetryPeriod time.Duration
	// OnStarted runs (in its own goroutine) when this replica becomes the
	// leader; its context ends when leadership ends. OnStopped runs once
	// leadership is lost; the caller should exit then, so a replica that
	// lost the lease never writes the store again.
	OnStarted func(ctx context.Context)
	OnStopped func()
	Now       func() time.Time

	leading atomic.Bool
	mu      sync.Mutex
	current *Lease
}

// IsLeader reports whether this replica holds the lease now.
func (e *Elector) IsLeader() bool { return e.leading.Load() }

func (e *Elector) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Elector) defaults() {
	if e.LeaseDuration <= 0 {
		e.LeaseDuration = DefaultLeaseDuration
	}
	if e.RenewDeadline <= 0 {
		e.RenewDeadline = DefaultRenewDeadline
	}
	if e.RetryPeriod <= 0 {
		e.RetryPeriod = DefaultRetryPeriod
	}
}

// Run campaigns until ctx ends or leadership is lost after being held.
// On ctx's end a held lease is released, so the next leader need not wait
// for it to expire.
func (e *Elector) Run(ctx context.Context) error {
	e.defaults()
	if e.Identity == "" || e.API == nil {
		return errors.New("leader: elector needs an identity and a lease API")
	}
	var lastRenew time.Time
	// One leadership per Run: a lost lease ends Run.
	lctx, cancelLeading := context.WithCancel(ctx)
	defer cancelLeading()
	stop := func() {
		cancelLeading()
		e.leading.Store(false)
		if e.OnStopped != nil {
			e.OnStopped()
		}
	}
	t := time.NewTicker(e.RetryPeriod)
	defer t.Stop()
	for {
		ok, err := e.tryAcquireOrRenew(ctx)
		switch {
		case ok:
			lastRenew = e.now()
			if !e.leading.Load() {
				e.leading.Store(true)
				if e.OnStarted != nil {
					go e.OnStarted(lctx)
				}
			}
		case e.leading.Load() && (err == nil || e.now().Sub(lastRenew) > e.RenewDeadline):
			// Another holder took it, or the renew deadline passed.
			stop()
			return errors.New("leader: lost the lease")
		}
		select {
		case <-ctx.Done():
			if e.leading.Load() {
				e.release()
				stop()
			}
			return ctx.Err()
		case <-t.C:
		}
	}
}

// tryAcquireOrRenew returns true when this replica holds the lease after
// the call; false with a nil error when another replica does.
func (e *Elector) tryAcquireOrRenew(ctx context.Context) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, e.RetryPeriod*2)
	defer cancel()
	now := e.now()
	nowS := now.UTC().Format(microTime)
	dur := int32(e.LeaseDuration / time.Second)
	cur, err := e.API.Get(cctx)
	if errors.Is(err, ErrLeaseNotFound) {
		zero := int32(0)
		l := &Lease{APIVersion: "coordination.k8s.io/v1", Kind: "Lease",
			Metadata: LeaseMeta{Name: e.Name, Namespace: e.Ns},
			Spec:     LeaseSpec{HolderIdentity: &e.Identity, LeaseDurationSeconds: &dur, AcquireTime: &nowS, RenewTime: &nowS, LeaseTransitions: &zero}}
		got, err := e.API.Create(cctx, l)
		if err != nil {
			return false, err
		}
		e.remember(got)
		return true, nil
	}
	if err != nil {
		return false, err
	}
	holder := ""
	if cur.Spec.HolderIdentity != nil {
		holder = *cur.Spec.HolderIdentity
	}
	if holder != "" && holder != e.Identity && !expired(cur, now) {
		return false, nil
	}
	next := *cur
	next.Spec.HolderIdentity = &e.Identity
	next.Spec.LeaseDurationSeconds = &dur
	next.Spec.RenewTime = &nowS
	if holder != e.Identity {
		next.Spec.AcquireTime = &nowS
		n := int32(0)
		if cur.Spec.LeaseTransitions != nil {
			n = *cur.Spec.LeaseTransitions
		}
		n++
		next.Spec.LeaseTransitions = &n
	}
	got, err := e.API.Update(cctx, &next)
	if errors.Is(err, ErrLeaseConflict) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	e.remember(got)
	return true, nil
}

func expired(l *Lease, now time.Time) bool {
	if l.Spec.RenewTime == nil || l.Spec.LeaseDurationSeconds == nil {
		return true
	}
	t, err := time.Parse(microTime, *l.Spec.RenewTime)
	if err != nil {
		if t, err = time.Parse(time.RFC3339, *l.Spec.RenewTime); err != nil {
			return true
		}
	}
	return now.After(t.Add(time.Duration(*l.Spec.LeaseDurationSeconds) * time.Second))
}

func (e *Elector) remember(l *Lease) {
	e.mu.Lock()
	e.current = l
	e.mu.Unlock()
}

// release gives the lease up (holder empty, 1 s duration).
func (e *Elector) release() {
	e.mu.Lock()
	cur := e.current
	e.mu.Unlock()
	if cur == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	next := *cur
	empty := ""
	one := int32(1)
	nowS := e.now().UTC().Format(microTime)
	next.Spec.HolderIdentity, next.Spec.LeaseDurationSeconds, next.Spec.RenewTime = &empty, &one, &nowS
	_, _ = e.API.Update(ctx, &next)
}
