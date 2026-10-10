// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// observabilityShutdownDropsFile is the small content-free note a gateway
// writes in its data directory when its shutdown flush leaves telemetry
// unsent. The next gateway reads and removes it and counts those records as
// dropped, which the in-process counters cannot carry across a restart
// (GAP-1096).
const (
	observabilityShutdownDropsFile     = "observability-shutdown-drops.json"
	observabilityShutdownDropsVersion  = 1
	observabilityShutdownDropsMaxBytes = 64 << 10
	observabilityShutdownDropsListed   = 8
)

type observabilityShutdownDropNote struct {
	Version   int                         `json:"version"`
	WrittenAt time.Time                   `json:"written_at"`
	Drops     []observabilityShutdownDrop `json:"drops"`
}

type observabilityShutdownDrop struct {
	Destination string `json:"destination"`
	Signal      string `json:"signal"`
	Records     uint64 `json:"records"`
}

func writeObservabilityShutdownDropNote(dataDir string, losses []observabilityruntime.ShutdownLoss, now time.Time) error {
	if strings.TrimSpace(dataDir) == "" || len(losses) == 0 {
		return nil
	}
	note := observabilityShutdownDropNote{Version: observabilityShutdownDropsVersion, WrittenAt: now.UTC()}
	for _, loss := range losses {
		note.Drops = append(note.Drops, observabilityShutdownDrop{
			Destination: loss.Destination, Signal: string(loss.Signal), Records: loss.Records,
		})
	}
	data, err := json.Marshal(note)
	if err != nil {
		return err
	}
	return safefile.Write(filepath.Join(dataDir, observabilityShutdownDropsFile), append(data, '\n'))
}

// takeObservabilityShutdownDropNote reads and removes the note. A note that
// cannot be removed is not used, so the same records are never counted again
// on every start.
func takeObservabilityShutdownDropNote(dataDir string) ([]observabilityruntime.ShutdownLoss, error) {
	path := filepath.Join(dataDir, observabilityShutdownDropsFile)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > observabilityShutdownDropsMaxBytes {
		return nil, fmt.Errorf("%s is not a regular file of at most %d bytes", path, observabilityShutdownDropsMaxBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil {
		return nil, err
	}
	var note observabilityShutdownDropNote
	if err := json.Unmarshal(data, &note); err != nil || note.Version != observabilityShutdownDropsVersion {
		return nil, fmt.Errorf("%s is not a version %d drop note", path, observabilityShutdownDropsVersion)
	}
	losses := make([]observabilityruntime.ShutdownLoss, 0, len(note.Drops))
	for _, drop := range note.Drops {
		signal := observability.Signal(drop.Signal)
		if drop.Records == 0 || !observability.IsStableToken(drop.Destination) || !observability.IsSignal(signal) {
			continue
		}
		losses = append(losses, observabilityruntime.ShutdownLoss{
			Destination: drop.Destination, Signal: signal, Records: drop.Records,
		})
	}
	return losses, nil
}

// describeObservabilityV8ShutdownLosses names the destinations and counts,
// for example "152 unsent telemetry records (eoi-hec logs 150, eoi-otlp
// traces 2)". It is empty when nothing was lost.
func describeObservabilityV8ShutdownLosses(losses []observabilityruntime.ShutdownLoss) string {
	var total uint64
	parts := make([]string, 0, observabilityShutdownDropsListed+1)
	for index, loss := range losses {
		total += loss.Records
		if index < observabilityShutdownDropsListed {
			parts = append(parts, fmt.Sprintf("%s %s %d", loss.Destination, loss.Signal, loss.Records))
		}
	}
	if total == 0 {
		return ""
	}
	if len(losses) > observabilityShutdownDropsListed {
		parts = append(parts, fmt.Sprintf("and %d more", len(losses)-observabilityShutdownDropsListed))
	}
	noun := "records"
	if total == 1 {
		noun = "record"
	}
	return fmt.Sprintf("%d unsent telemetry %s (%s)", total, noun, strings.Join(parts, ", "))
}

// flushDestinationLossMetricsV8 reports the destination losses counted since
// the last 15-second capacity tick before the runtime closes, so the
// defenseclaw.queue.drops delta flushed at shutdown carries them (GAP-1096).
// Secure Client emits no destination loss metric (#1092).
func (s *Sidecar) flushDestinationLossMetricsV8() {
	if s == nil || ManagedEnterpriseActive() {
		return
	}
	healthRuntime, ok := s.observabilityV8LifecycleRuntime().(exporterHealthMetricV8Runtime)
	if !ok || healthRuntime == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	health, err := healthRuntime.DestinationHealthSnapshot(ctx)
	if err != nil || health.Generation == 0 || health.PlanDigest == "" {
		return
	}
	s.recordExporterHealthMetricsV8(ctx, time.Now().UTC(), healthRuntime, health)
}

// noteObservabilityV8ShutdownLosses keeps what the closed runtime dropped or
// left unsent for the shutdown warning and writes the drop note the next
// gateway reads. It runs once per process.
func (s *Sidecar) noteObservabilityV8ShutdownLosses(owner *sidecarOwnedObservabilityV8Runtime, flushed bool) {
	if s == nil || owner == nil || owner.runtime == nil || ManagedEnterpriseActive() {
		return
	}
	losses := owner.runtime.ShutdownLosses()
	s.observabilityV8Mu.Lock()
	if s.observabilityV8ShutdownLossesNoted {
		s.observabilityV8Mu.Unlock()
		return
	}
	s.observabilityV8ShutdownLossesNoted = true
	s.observabilityV8ShutdownLosses = losses
	s.observabilityV8Mu.Unlock()
	summary := describeObservabilityV8ShutdownLosses(losses)
	if summary == "" {
		return
	}
	if err := writeObservabilityShutdownDropNote(owner.dataDir, losses, time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] could not record %s for the next start: %v\n", summary, err)
	}
	if flushed {
		fmt.Fprintf(os.Stderr, "[sidecar] %s were dropped during the shutdown flush; "+
			"the gateway counts them as dropped when it starts again\n", summary)
	}
}

// observabilityV8ShutdownFlushWarning is the gateway.log line written when the
// telemetry runtime cannot finish its flush within the shutdown bound. The stop
// itself succeeded, so it is a warning, not an "Error:" line (GAP-2166). It
// names each destination and how many records it lost (GAP-1096).
func (s *Sidecar) observabilityV8ShutdownFlushWarning() string {
	var losses []observabilityruntime.ShutdownLoss
	if s != nil {
		s.observabilityV8Mu.Lock()
		losses = s.observabilityV8ShutdownLosses
		s.observabilityV8Mu.Unlock()
	}
	dropped := "unsent telemetry was dropped"
	if summary := describeObservabilityV8ShutdownLosses(losses); summary != "" {
		dropped = summary + " were dropped; the gateway counts them as dropped when it starts again"
	}
	return fmt.Sprintf("[sidecar] WARNING: telemetry flush on shutdown did not finish within %s; %s. "+
		"A telemetry destination is probably unreachable: "+
		"check it with 'defenseclaw setup observability test <name>'. The gateway stopped normally.\n",
		sidecarObservabilityV8ShutdownTimeout, dropped)
}

// carryObservabilityV8ShutdownDrops counts as dropped the records the previous
// gateway left unsent when it stopped (GAP-1096).
func (s *Sidecar) carryObservabilityV8ShutdownDrops() {
	if s == nil || ManagedEnterpriseActive() {
		return
	}
	s.observabilityV8Mu.Lock()
	owner, _ := s.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	s.observabilityV8Mu.Unlock()
	if owner == nil || owner.runtime == nil || strings.TrimSpace(owner.dataDir) == "" {
		return
	}
	losses, err := takeObservabilityShutdownDropNote(owner.dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] could not read the unsent telemetry note of the previous run: %v\n", err)
		return
	}
	if len(losses) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	applied, err := owner.runtime.CarryShutdownLosses(ctx, losses)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] could not count %s of the previous run as dropped: %v\n",
			describeObservabilityV8ShutdownLosses(losses), err)
		return
	}
	if summary := describeObservabilityV8ShutdownLosses(applied); summary != "" {
		fmt.Fprintf(os.Stderr, "[sidecar] counted %s that the previous gateway could not send before it stopped as dropped\n", summary)
	}
}
