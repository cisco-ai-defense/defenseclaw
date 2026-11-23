// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"sort"
	"syscall"
	"testing"
	"time"
)

// pinReachabilityEnv turns the vendor reachability check on. It is a release
// and nightly check, not a unit test: it needs the network, and a vendor that
// withdraws an old build fails it on a day nothing in this repository changed.
const pinReachabilityEnv = "DEFENSECLAW_PIN_REACHABILITY"

// TestPinnedArchivesAreReachable (GAP-0652) asks each vendor for every archive
// a tarball-installed harness pins and fails when one is not served. Devin
// serves only its current release: the devin-hooks-v1 pin 3000.4.25 and the
// kit pin 3000.12.57 both answered 403 while every unit test passed, so no
// sandbox or actor base image could be built (GAP-0651, GAP-0462). The check
// skips when DEFENSECLAW_PIN_REACHABILITY is not 1 and when the vendor host
// cannot be reached at all (an offline runner: the name does not resolve, the
// network or host is unreachable, or the connection never opens before the
// timeout), printing the reason, and fails on any other error (a refused
// connection, a reset, a TLS failure) and on any answer other than 200.
func TestPinnedArchivesAreReachable(t *testing.T) {
	if os.Getenv(pinReachabilityEnv) != "1" {
		t.Skipf("set %s=1 to check that every pinned vendor archive is still served", pinReachabilityEnv)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	for _, set := range []struct {
		name string
		pins tarballPins
	}{{"cursor", cursorPins}, {"devin", devinPins}, {"kiro", kiroPins}} {
		for _, pin := range set.pins {
			archs := make([]string, 0, len(pin.Archives))
			for arch := range pin.Archives {
				archs = append(archs, arch)
			}
			sort.Strings(archs)
			for _, arch := range archs {
				url := pin.Archives[arch].URL
				t.Run(set.name+"/"+pin.Version+"/"+arch, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
					if err != nil {
						t.Fatal(err)
					}
					resp, err := client.Do(req)
					if err != nil {
						if networkUnreachable(err) {
							t.Skipf("no network path to the vendor host from this runner: %v", err)
						}
						t.Fatalf("HEAD %s: %v", url, err)
					}
					resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						t.Errorf("%s pin %s: HEAD %s answers %d; Devin and the other vendors serve only recent builds, so repin to the current release (new sha256 from the vendor manifest) and move the kit pin with it", set.name, pin.Version, url, resp.StatusCode)
					}
				})
			}
		}
	}
}

// networkUnreachable is true only for an error that says this runner has no
// network path to the vendor: the name does not resolve, the network or the host
// is unreachable, or the connection never opened before the timeout. A refused
// connection, a reset or a TLS failure means the vendor answered badly, which
// is what this check exists to catch, so those are not unreachable (GAP-0915).
func networkUnreachable(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial" && opErr.Timeout()
}
