// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

// tableAcquirer serves a fixed process and connection table.
type tableAcquirer struct {
	kernelAcquirer
	processes   []procprobe.Process
	connections []netprobe.Connection
}

func (a *tableAcquirer) Processes(context.Context) ([]procprobe.Process, int, error) {
	return a.processes, 0, nil
}

func (a *tableAcquirer) Connections(context.Context) ([]netprobe.Connection, int, error) {
	return a.connections, 0, nil
}

// The gateway's own release manifest fetch (downloads.claude.ai) is not
// reported (cowork-1-0-8 GAP-0068), and nothing else is hidden with it: the
// gateway, matched by its pid, still reports any other provider (and the
// manifest host on another port); another process going to the manifest
// host, and a process merely named defenseclaw-gateway, are still reported;
// without a host plane there is no fetch of ours to leave out.
func TestGatewaysOwnReleaseManifestFetchIsNotReported(t *testing.T) {
	t.Parallel()
	const (
		gateway   = 4200
		namedLike = 4300
		curl      = 4400
		manifest  = "35.190.46.17"
		anthropic = "160.79.104.10"
	)
	others := map[int][]string{namedLike: {"downloads.claude.ai"}, curl: {"downloads.claude.ai"}}
	for _, test := range []struct {
		name         string
		hostPlane    bool
		viaKernel    bool
		gatewayOther []string // the gateway's peers besides its manifest fetch, ip:port
		want         map[int][]string
	}{
		{name: "table, manifest fetch only", hostPlane: true, want: others},
		{name: "kernel connects, manifest fetch only", hostPlane: true, viaKernel: true, want: others},
		{
			name: "table, the gateway also reaches a provider", hostPlane: true,
			gatewayOther: []string{anthropic + ":443"},
			want:         map[int][]string{gateway: {"api.anthropic.com"}, namedLike: {"downloads.claude.ai"}, curl: {"downloads.claude.ai"}},
		},
		{
			name: "kernel connects, the gateway also reaches a provider", hostPlane: true, viaKernel: true,
			gatewayOther: []string{anthropic + ":443"},
			want:         map[int][]string{gateway: {"api.anthropic.com"}, namedLike: {"downloads.claude.ai"}, curl: {"downloads.claude.ai"}},
		},
		{
			name: "table, the gateway reaches the manifest host on another port", hostPlane: true,
			gatewayOther: []string{manifest + ":8443"},
			want:         map[int][]string{gateway: {"downloads.claude.ai"}, namedLike: {"downloads.claude.ai"}, curl: {"downloads.claude.ai"}},
		},
		{
			name: "table, no host plane",
			want: map[int][]string{gateway: {"downloads.claude.ai"}, namedLike: {"downloads.claude.ai"}, curl: {"downloads.claude.ai"}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			now := time.Unix(1_760_000_000, 0)
			uid := 1001
			type peer struct {
				pid    int
				name   string
				remote string
			}
			peers := []peer{
				{gateway, "defenseclaw-gateway", manifest + ":443"},
				{namedLike, "defenseclaw-gateway", manifest + ":443"},
				{curl, "curl", manifest + ":443"},
			}
			for _, remote := range test.gatewayOther {
				peers = append(peers, peer{gateway, "defenseclaw-gateway", remote})
			}
			coverage := fullCoverage()
			coverage.Kinds = append(coverage.Kinds, plane.KindConnect)
			var events []plane.Event
			acquirer := &tableAcquirer{}
			if test.viaKernel {
				for _, p := range peers {
					events = append(events, plane.Event{Kind: plane.KindConnect, PID: p.pid, Name: p.name,
						Remote: p.remote, User: "alice", UID: &uid})
				}
			} else {
				for _, pid := range []int{gateway, namedLike, curl} {
					name := "defenseclaw-gateway"
					if pid == curl {
						name = "curl"
					}
					acquirer.processes = append(acquirer.processes, procprobe.Process{PID: pid, Name: name, User: "alice"})
				}
				for _, p := range peers {
					host, port, _ := net.SplitHostPort(p.remote)
					number, _ := strconv.Atoi(port)
					acquirer.connections = append(acquirer.connections, netprobe.Connection{
						PID: p.pid, RemoteIP: net.ParseIP(host), RemotePort: number, State: netprobe.StateEstablished,
					})
				}
			}
			acquirer.source = newFake(coverage, events...)
			cfg := config.AIRuntimeConfig{Enabled: true, Planes: []string{"a", "b"}}
			if test.hostPlane {
				cfg = config.AIRuntimeConfig{Enabled: true, EnableHostPlane: true}
			}
			service, err := New(Options{
				Config:   cfg,
				Platform: allPlanesAvailable(),
				Resolver: StaticResolver{Names: map[string]string{
					manifest:  "downloads.claude.ai",
					anthropic: "api.anthropic.com",
				}, Confidence: ConfidenceDNSAnswer, Source: "dns_answer"},
				Acquirer: acquirer,
				Now:      func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			if (service.hostPlane != nil) != test.hostPlane {
				t.Fatalf("host plane = %v, want %v", service.hostPlane != nil, test.hostPlane)
			}
			service.selfPID = gateway
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.hostPlane {
				service.startHostPlane(ctx)
				deadline := time.After(5 * time.Second)
				for service.hostPlane.handled.Load() < int64(len(events)) {
					select {
					case <-deadline:
						t.Fatal("the connects were not handled")
					case <-time.After(2 * time.Millisecond):
					}
				}
			}
			got := map[int][]string{}
			for _, finding := range service.Poll(ctx).Findings {
				for _, provider := range finding.Providers {
					got[finding.PID] = append(got[finding.PID], provider.Hostname)
				}
				sort.Strings(got[finding.PID])
			}
			if render(got) != render(test.want) {
				t.Fatalf("reported %v, want %v", got, test.want)
			}
		})
	}
}

func render(hosts map[int][]string) string {
	keys := make([]int, 0, len(hosts))
	for pid := range hosts {
		keys = append(keys, pid)
	}
	sort.Ints(keys)
	var out strings.Builder
	for _, pid := range keys {
		out.WriteString(strconv.Itoa(pid) + "=" + strings.Join(hosts[pid], ",") + ";")
	}
	return out.String()
}
