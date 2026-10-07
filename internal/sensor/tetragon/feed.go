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

package tetragon

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// DialerConfig configures NewDialer.
type DialerConfig struct {
	// InfoPath is Tetragon's discovery file (default DefaultInfoPath).
	InfoPath string
	// Homes and BinDir feed the mapper's self-filter (see MapperConfig).
	Homes  []string
	BinDir string
	// PolicyInterval is how often the loaded policies are listed (their
	// modes decide blocked against would_block, together with PolicyMode;
	// the list feeds the coverage and the fanotify hand-off). Default 15 s.
	PolicyInterval time.Duration
	// PolicyMode is the reconciler's mode of a policy it loaded and when it
	// last changed (kernelpolicy.Controller.PolicyMode). When it is newer
	// than the last listing it decides; nil leaves the listing alone.
	PolicyMode func(name string) (mode string, changed time.Time, ok bool)
	// MetricsInterval is how often the loss counters are scraped. Default
	// 30 s.
	MetricsInterval time.Duration

	trust *trustPolicy
}

// NewDialer returns the dialer the helper's Plane C source uses. Each call
// opens a fresh session, re-reading the info file. The event session is
// consume-scoped in every mode: loading policies is the reconciler's job,
// in a session of its own.
func NewDialer(config DialerConfig) plane.KernelDialer {
	if config.PolicyInterval <= 0 {
		config.PolicyInterval = 15 * time.Second
	}
	if config.MetricsInterval <= 0 {
		config.MetricsInterval = 30 * time.Second
	}
	return func(ctx context.Context) (plane.KernelFeed, error) { return openFeed(ctx, config) }
}

// feed is one Tetragon event session.
type feed struct {
	client *Client
	stream interface {
		Recv() (*pb.GetEventsResponse, error)
	}
	cancel context.CancelFunc
	mapper *Mapper

	// own is DialerConfig.PolicyMode.
	own func(name string) (string, time.Time, bool)

	mu        sync.Mutex
	policies  []plane.BackendPolicy
	modes     map[string]string
	listedAt  time.Time
	lost      int64
	lossKnown bool
}

func openFeed(ctx context.Context, config DialerConfig) (*feed, error) {
	client, err := Dial(ctx, DialOptions{InfoPath: config.InfoPath, Scope: ScopeConsume, trust: config.trust})
	if err != nil {
		return nil, err
	}
	// The stream lives until Close, past the dial's deadline.
	streamCtx, cancel := context.WithCancel(context.Background())
	stream, err := client.Events(streamCtx, EventsRequest())
	if err != nil {
		cancel()
		_ = client.Close()
		return nil, refuse(ReasonUnavailable, err, "GetEvents: %v", err)
	}
	f := &feed{client: client, stream: stream, cancel: cancel, modes: map[string]string{}, own: config.PolicyMode}
	f.mapper = NewMapper(MapperConfig{Homes: config.Homes, BinDir: config.BinDir, PolicyMode: f.policyMode})
	f.refreshPolicies(ctx)
	f.refreshLoss(ctx)
	go f.poll(streamCtx, config)
	return f, nil
}

func (f *feed) Recv() (plane.KernelBatch, error) {
	for {
		response, err := f.stream.Recv()
		if err != nil {
			return plane.KernelBatch{}, fmt.Errorf("receive: %w", err)
		}
		batch := f.mapper.Map(response)
		if len(batch.Events) > 0 || batch.ThrottleStart || batch.ThrottleStop || batch.Dropped > 0 {
			return batch, nil
		}
	}
}

func (f *feed) Backend() plane.Backend {
	f.mu.Lock()
	defer f.mu.Unlock()
	return plane.Backend{
		Kind:       plane.BackendTetragon,
		Version:    f.client.Version().String(),
		Socket:     f.client.Socket(),
		PID:        f.client.Info().PID,
		EventsLost: f.lost,
		LossKnown:  f.lossKnown,
		Policies:   append([]plane.BackendPolicy(nil), f.policies...),
	}
}

func (f *feed) Close() error {
	f.cancel()
	return f.client.Close()
}

// policyMode is a policy's mode as the mapper needs it: the newer of the
// reconciler's own record (it knows the moment it adds, promotes or demotes a
// policy, which a 15 s listing does not) and the last listing (which catches
// an operator's `tetra tracingpolicy set-mode`).
func (f *feed) policyMode(name string) string {
	f.mu.Lock()
	listed, ok := f.modes[name]
	at := f.listedAt
	f.mu.Unlock()
	if f.own != nil {
		if mode, changed, known := f.own(name); known && (!ok || changed.After(at)) {
			return mode
		}
	}
	return listed
}

func (f *feed) poll(ctx context.Context, config DialerConfig) {
	policies := time.NewTicker(config.PolicyInterval)
	defer policies.Stop()
	metrics := time.NewTicker(config.MetricsInterval)
	defer metrics.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-policies.C:
			f.refreshPolicies(ctx)
		case <-metrics.C:
			f.refreshLoss(ctx)
		}
	}
}

// refreshPolicies lists the loaded policies and keeps DefenseClaw's own.
func (f *feed) refreshPolicies(ctx context.Context) {
	listCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	statuses, err := f.client.ListPolicies(listCtx)
	if err != nil {
		return
	}
	var own []plane.BackendPolicy
	modes := map[string]string{}
	for _, status := range statuses {
		if _, ok := OwnPolicyFamily(status.GetName()); !ok {
			continue
		}
		policy := plane.BackendPolicy{
			Name:  status.GetName(),
			Mode:  PolicyMode(status.GetMode()),
			State: PolicyState(status.GetState()),
			Error: status.GetError(),
		}
		own = append(own, policy)
		modes[policy.Name] = policy.Mode
	}
	sort.Slice(own, func(i, j int) bool { return own[i].Name < own[j].Name })
	f.mu.Lock()
	f.policies, f.modes, f.listedAt = own, modes, time.Now()
	f.mu.Unlock()
}

func (f *feed) refreshLoss(ctx context.Context) {
	total, err := readLossCounters(ctx, f.client.Info())
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		f.lossKnown = false
		return
	}
	f.lost, f.lossKnown = total, true
}
