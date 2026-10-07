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
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Tetragon's own loss counters: events its BPF programs could not hand over
// (missed), the notifier dropping events under pressure (a burst of 25k opens
// exported 48% of its events on RHEL 9), and the ring buffer losing perf
// events. They are display only: the coverage shows them, and a growth is a
// loss signal for the fanotify hand-off, but they never feed burn-in or
// enforcement, because the helper cannot vouch for them the way it vouches
// for the event stream.
var lossMetricSuffixes = []string{
	"missed_events_total",
	"notify_overflowed_events_total",
	"events_lost_total",
}

// metricsLimit bounds a metrics scrape.
const metricsLimit = 8 << 20

// metricsTimeout bounds a scrape; it runs off the event path.
const metricsTimeout = 3 * time.Second

// readLossCounters scrapes Tetragon's loss counters, only from a loopback
// metrics address whose listener belongs to the Tetragon pid.
func readLossCounters(ctx context.Context, info Info) (int64, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(info.MetricsAddress))
	if err != nil {
		return 0, fmt.Errorf("metrics address %q: %w", info.MetricsAddress, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return 0, fmt.Errorf("metrics address %q is not a loopback address", info.MetricsAddress)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("metrics address %q has no port", info.MetricsAddress)
	}
	if err := listenerOwnedBy(port, info.PID); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, metricsTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://"+net.JoinHostPort(ip.String(), portText)+"/metrics", nil)
	if err != nil {
		return 0, err
	}
	// No proxy: the environment must not redirect a loopback scrape.
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: metricsTimeout}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("metrics answered %s", response.Status)
	}
	total, found := parseLossCounters(io.LimitReader(response.Body, metricsLimit))
	if !found {
		return 0, fmt.Errorf("no Tetragon loss counters in the metrics")
	}
	return total, nil
}

// parseLossCounters sums every series of the loss counters in a Prometheus
// text exposition.
func parseLossCounters(reader io.Reader) (int64, bool) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	var total float64
	found := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := line
		if cut := strings.IndexAny(line, "{ "); cut >= 0 {
			name = line[:cut]
		}
		if !strings.HasPrefix(name, "tetragon_") || !hasAnySuffix(name, lossMetricSuffixes) {
			continue
		}
		rest := line[len(name):]
		if strings.HasPrefix(rest, "{") {
			end := strings.LastIndexByte(rest, '}')
			if end < 0 {
				continue
			}
			rest = rest[end+1:]
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		value, err := strconv.ParseFloat(fields[0], 64)
		if err != nil || value < 0 {
			continue
		}
		total += value
		found = true
	}
	return int64(total), found
}

func hasAnySuffix(value string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(value, suffix) {
			return true
		}
	}
	return false
}
