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

package sandboxcli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// CheckIDTLSTrust is the doctor row of sandbox TLS trust: whether probed
// certificates, as this network presents them, verify with what a sandbox
// trusts (the image's public roots plus openshell.trusted_ca_bundle).
const CheckIDTLSTrust = "tls-trust"

// Probe a build download host as well as model providers: providers may be
// exempt from inspection while package downloads still need the configured CA.
const tlsTrustDownloadHost = "registry.npmjs.org"

var tlsTrustHosts = []string{"api.anthropic.com", "api.openai.com", "api.githubcopilot.com", tlsTrustDownloadHost}

// tlsTrustTimeout bounds the whole probe.
const tlsTrustTimeout = 4 * time.Second

// TLSTrust is what the TLS trust check reads, replaceable in tests.
type TLSTrust struct {
	// Chain returns the certificate chain host:443 presents, as the
	// egress proxy, which dials providers directly from this computer,
	// would get it.
	Chain func(ctx context.Context, host string) ([]*x509.Certificate, error)
	// SandboxRoots are the public roots a sandbox image trusts without
	// openshell.trusted_ca_bundle, and where they were read from
	// (openshell.PublicRoots).
	SandboxRoots func() (*x509.CertPool, string, error)
	// HostRoots is what this computer trusts (nil: the system's).
	HostRoots func() (*x509.CertPool, error)
}

func defaultTLSChain(ctx context.Context, host string) ([]*x509.Certificate, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{
		ServerName: host, MinVersion: tls.VersionTLS12,
		// The chain is verified below against two root sets: the
		// handshake only collects it, and no request is sent.
		InsecureSkipVerify: true, //nolint:gosec // verified by tlsTrustCheck
	}}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("no certificate")
	}
	return state.PeerCertificates, nil
}

func (t TLSTrust) withDefaults(goos string) TLSTrust {
	if t.Chain == nil {
		t.Chain = defaultTLSChain
	}
	if t.SandboxRoots == nil {
		t.SandboxRoots = func() (*x509.CertPool, string, error) { return openshell.PublicRoots(goos) }
	}
	if t.HostRoots == nil {
		t.HostRoots = x509.SystemCertPool
	}
	return t
}

type tlsProbe struct {
	host  string
	chain []*x509.Certificate
	err   error
}

func verifyChain(host string, chain []*x509.Certificate, roots *x509.CertPool, now time.Time) error {
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter, CurrentTime: now})
	return err
}

// chainIssuer names the CA a chain ends at: the issuer of its last
// certificate.
func chainIssuer(chain []*x509.Certificate) string {
	last := chain[len(chain)-1]
	if cn := strings.TrimSpace(last.Issuer.CommonName); cn != "" {
		return cn
	}
	return last.Issuer.String()
}

// trustedCASource is the trusted CAs a sandbox started now gets, where
// they come from, and why they cannot be used. On a managed computer they
// are the administrator's, as the account's sandbox daemon got them from
// the managed gateway (known is false when it did not answer).
func (a *App) trustedCASource(ctx context.Context, managed bool) (cas openshell.TrustedCAs, from string, known bool, err error) {
	if managed {
		from = "your organization's " + openshell.TrustedCAKey
		if a.ManagedTrustedCAs == nil {
			return openshell.TrustedCAs{}, from, false, nil
		}
		pem, problem, ok := a.ManagedTrustedCAs(ctx)
		switch {
		case !ok:
			return openshell.TrustedCAs{}, from, false, nil
		case problem != "":
			return openshell.TrustedCAs{}, from, true, errors.New(problem)
		case pem == "":
			return openshell.TrustedCAs{}, from, true, nil
		}
		cas, err = openshell.ParseTrustedCAs([]byte(pem))
		return cas, from, true, err
	}
	if a.Cfg == nil || a.Cfg.OpenShell.TrustedCABundle == "" {
		return openshell.TrustedCAs{}, "", true, nil
	}
	from = a.Cfg.OpenShell.TrustedCABundle
	cas, err = openshell.LoadTrustedCAs(from, false)
	return cas, from, true, err
}

// tlsTrustCheck is the Sandbox TLS trust row. It fails, by name, when a
// CA file is named but cannot be used (no image builds), when a provider's
// certificate verifies with this computer's trust but not with a
// sandbox's (a TLS-inspecting proxy whose root CA sandboxes are not
// given), and when it verifies in a sandbox only through the trusted CAs:
// an agent's model calls to a provider are made by OpenShell's sandbox
// supervisor, which puts the credential in and verifies the provider with
// its own store only, so an inspected provider host fails them whatever
// the sandbox trusts (GAP-0065, GAP-0066, GAP-0074). The probe runs once
// per command (setup runs the checks again and again).
func (a *App) tlsTrustCheck(ctx context.Context, managed bool) openshell.Check {
	a.tlsTrustOnce.Do(func() { a.tlsTrustRow = a.runTLSTrustCheck(ctx, managed) })
	return a.tlsTrustRow
}

func (a *App) runTLSTrustCheck(ctx context.Context, managed bool) openshell.Check {
	c := openshell.Check{ID: CheckIDTLSTrust, Title: "Sandbox TLS trust", Status: openshell.StatusPass}
	setFix := func() {
		if managed {
			c.Fix = &openshell.Fix{Summary: "ask your administrator to set " + openshell.TrustedCAKey +
				" in the managed configuration to the TLS-inspecting proxy's root CA (a PEM file only administrators can change)"}
			return
		}
		c.Fix = &openshell.Fix{
			Summary: "save the TLS-inspecting proxy's root CA certificate as a PEM file (your IT department has it) and name it in " +
				openshell.TrustedCAKey + "; sandbox images are rebuilt with it at the next run",
			Command: "defenseclaw config set " + openshell.TrustedCAKey + " /path/to/proxy-root-ca.pem",
		}
	}
	cas, from, known, err := a.trustedCASource(ctx, managed)
	if err != nil {
		c.Status = openshell.StatusFail
		c.Detail = "the trusted CAs cannot be used, so no sandbox image is built: " + err.Error()
		if managed {
			c.Detail = "your organization's trusted CAs cannot be used, so no sandbox image is built: " + err.Error()
			c.Fix = &openshell.Fix{Summary: "ask your administrator to fix " + openshell.TrustedCAKey + " in the managed configuration"}
		} else {
			c.Fix = &openshell.Fix{Summary: "point " + openshell.TrustedCAKey + " at a PEM file of CA certificates, or unset it",
				Command: "defenseclaw config unset " + openshell.TrustedCAKey}
		}
		return c
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	var notes []string
	if !cas.Empty() {
		notes = append(notes, fmt.Sprintf("sandboxes also trust %s from %s", strings.Join(cas.Subjects(), ", "), from))
		if exp := cas.Expired(now); len(exp) > 0 {
			c.Status = openshell.StatusWarn
			notes = append(notes, "expired or not yet valid: "+strings.Join(exp, ", "))
		}
	} else if !known {
		notes = append(notes, "your organization's trusted CAs are not known here (your sandbox service did not answer)")
	}
	finish := func(detail string) openshell.Check {
		c.Detail = strings.Join(append([]string{detail}, notes...), "; ")
		return c
	}

	t := a.TLSTrust.withDefaults(a.GOOS)
	public, source, err := t.SandboxRoots()
	if err != nil {
		if c.Status == openshell.StatusPass {
			c.Status = openshell.StatusSkip
		}
		return finish("TLS certificates not checked: " + err.Error())
	}
	sandboxRoots := public.Clone()
	for _, cert := range cas.Certs {
		sandboxRoots.AddCert(cert)
	}
	hostRoots, err := t.HostRoots()
	if err != nil {
		hostRoots = nil
	}

	ctx, cancel := context.WithTimeout(ctx, tlsTrustTimeout)
	defer cancel()
	probes := make([]tlsProbe, len(tlsTrustHosts))
	var wg sync.WaitGroup
	for i, host := range tlsTrustHosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			chain, err := t.Chain(ctx, host)
			if err == nil && len(chain) == 0 {
				err = errors.New("no certificate")
			}
			probes[i] = tlsProbe{host: host, chain: chain, err: err}
		}()
	}
	wg.Wait()

	// covered are the hosts that verify in a sandbox only through the
	// trusted CAs: inspected, so an agent's model calls to them still fail.
	var ok, covered, unreachable, intercepted, providerIntercepted, untrusted []string
	// Issuers per classification, so each message names only its own.
	var coveredBy, interceptedBy, untrustedBy issuerSet
	for _, p := range probes {
		if p.err != nil {
			unreachable = append(unreachable, p.host)
			continue
		}
		if verifyChain(p.host, p.chain, sandboxRoots, now) == nil {
			if !cas.Empty() && verifyChain(p.host, p.chain, public, now) != nil {
				if p.host == tlsTrustDownloadHost {
					ok = append(ok, p.host)
				} else {
					covered = append(covered, p.host)
					coveredBy.add(chainIssuer(p.chain))
				}
			} else {
				ok = append(ok, p.host)
			}
			continue
		}
		issuer := chainIssuer(p.chain)
		if verifyChain(p.host, p.chain, hostRoots, now) == nil {
			intercepted = append(intercepted, p.host)
			if p.host != tlsTrustDownloadHost {
				providerIntercepted = append(providerIntercepted, p.host)
			}
			interceptedBy.add(issuer)
		} else {
			untrusted = append(untrusted, p.host)
			untrustedBy.add(issuer)
		}
	}
	untrustedDetail := func() string {
		return fmt.Sprintf("%s present a certificate from %s, which neither this computer nor sandboxes trust "+
			"(a TLS-inspecting proxy whose root CA is not installed here either?)", strings.Join(untrusted, ", "), untrustedBy.String())
	}
	switch {
	case len(intercepted) > 0 || len(covered) > 0:
		c.Status = openshell.StatusFail
		var parts []string
		if len(intercepted) > 0 {
			parts = append(parts, fmt.Sprintf("TLS inspection: %s present a certificate from %s, which this computer trusts but sandboxes do not, "+
				"so agents in a sandbox fail with \"unable to get local issuer certificate\"",
				strings.Join(intercepted, ", "), interceptedBy.String()))
		}
		if len(covered) > 0 {
			parts = append(parts, fmt.Sprintf("TLS inspection: %s present a certificate from %s; programs in a sandbox trust it through the trusted CAs, "+
				"but an agent's model calls to these hosts are made by OpenShell's sandbox supervisor, which verifies them with its own store only, so they fail",
				strings.Join(covered, ", "), coveredBy.String()))
		}
		if len(untrusted) > 0 {
			parts = append(parts, untrustedDetail())
		}
		providerHosts := append(providerIntercepted, covered...)
		if len(providerHosts) == 0 {
			setFix()
		} else {
			inspectedFix(&c, managed, providerHosts, len(intercepted) > 0)
		}
		return finish(strings.Join(parts, "; "))
	case len(untrusted) > 0:
		c.Status = openshell.StatusWarn
		setFix()
		return finish(untrustedDetail())
	case len(ok) == 0:
		if c.Status == openshell.StatusPass {
			c.Status = openshell.StatusSkip
		}
		return finish("TLS certificates not checked: " + strings.Join(unreachable, ", ") + " did not answer from this computer")
	}
	detail := strings.Join(ok, ", ") + " verify with the roots sandboxes trust (" + source + ")"
	if len(unreachable) > 0 {
		detail += "; " + strings.Join(unreachable, ", ") + " did not answer"
	}
	return finish(detail)
}

// inspectedFix is the fix of a row that found inspected provider hosts.
// They must be exempt from inspection on the proxy: OpenShell's sandbox
// supervisor makes the agents' model calls and takes no added CA (an
// explicit upstream proxy, OpenShell's https_proxy with proxy_ca_bundle,
// is the one way it does). needCA adds the trusted CA key, which every
// other connection from a sandbox needs.
func inspectedFix(c *openshell.Check, managed bool, hosts []string, needCA bool) {
	exempt := "exempt " + strings.Join(hosts, ", ") + " and the other model provider hosts your agents use from TLS inspection on the proxy " +
		"(OpenShell's sandbox supervisor makes the agents' model calls and cannot be given a CA)"
	if managed {
		s := "ask your administrator to " + exempt
		if needCA {
			s += ", and to set " + openshell.TrustedCAKey + " in the managed configuration to the proxy's root CA for everything else sandboxes reach"
		}
		c.Fix = &openshell.Fix{Summary: s}
		return
	}
	s := "ask your IT department to " + exempt
	if !needCA {
		c.Fix = &openshell.Fix{Summary: s}
		return
	}
	c.Fix = &openshell.Fix{
		Summary: s + "; for everything else sandboxes reach, save the proxy's root CA certificate as a PEM file and name it in " +
			openshell.TrustedCAKey + " (sandbox images are rebuilt with it at the next run)",
		Command: "defenseclaw config set " + openshell.TrustedCAKey + " /path/to/proxy-root-ca.pem",
	}
}

// issuerSet is the distinct issuers of a classification, quoted, in first
// seen order.
type issuerSet struct {
	seen map[string]bool
	list []string
}

func (s *issuerSet) add(issuer string) {
	if s.seen[issuer] {
		return
	}
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	s.seen[issuer] = true
	s.list = append(s.list, fmt.Sprintf("%q", issuer))
}

func (s issuerSet) String() string { return strings.Join(s.list, ", ") }
