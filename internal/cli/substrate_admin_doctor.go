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

package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
)

// The status of one doctor check.
const (
	doctorOK   = "ok"
	doctorWarn = "warn"
	doctorFail = "fail"
	doctorSkip = "skip"
)

// substrateCheck is one line of `substrate doctor`.
type substrateCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Summary string `json:"summary"`
	Fix     string `json:"fix,omitempty"`
}

// substrateDoctorReport is `substrate doctor --json`.
type substrateDoctorReport struct {
	OK       bool             `json:"ok"`
	Context  string           `json:"context,omitempty"`
	Problems int              `json:"problems"`
	Checks   []substrateCheck `json:"checks"`
}

// Seams for tests.
var (
	// substrateDoctorStore opens the token store and says which kind it is.
	substrateDoctorStore = func() (string, error) {
		st, err := auth.OpenStore()
		if err != nil {
			return "", err
		}
		var v any = st
		if d, ok := v.(interface{ Describe() string }); ok {
			return d.Describe(), nil
		}
		return "", nil
	}
	// substrateDoctorDialWait bounds one connection attempt.
	substrateDoctorDialWait = 8 * time.Second
	// substrateDoctorAlertWait is how long the agent entrance probe waits
	// for a TLS alert after the handshake (a refused client certificate
	// shows only then, in TLS 1.3).
	substrateDoctorAlertWait = 300 * time.Millisecond
)

const substrateLoginFix = "defenseclaw substrate login --admin-url https://HOST:PORT --issuer URL --client-id ID (your administrator has these)"

func newSubstrateDoctorCmd() *cobra.Command {
	var (
		out     substrateOutput
		com     substrateCommon
		kf      substrateClusterFlags
		cluster bool
	)
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check that this computer can run agents in the cluster",
		Long: `Checks, from this computer, everything a run needs: the cluster is set up here, its admin address answers
over TLS, you are signed in and the cluster accepts it, the sign-in server matches, attach through the gateway works and
you have what it asks for, and your sign-in can be kept safely. Nothing needs to be installed here, and nothing in the
cluster changes.

Administrators get the cluster's own checks too (version, issuer, snapshot bucket, access policies, egress callout, router
clients, routes, API access). They run by themselves when the cluster offers them; --cluster shows why when it does not.
With --install-file (the SubstrateInstall file you gave ate-setup) they are read with kubectl instead, which needs no
sign-in to the gateway.

The last line is "ready for agents" when no check failed. Otherwise it is "not ready" and each failed check says how to fix
it, and the exit code is 1.`,
		Example: "defenseclaw substrate doctor\ndefenseclaw substrate doctor --cluster --json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSubstrateDoctor(cmd, &out, &com, &kf, cluster)
		},
	}
	out.add(cmd)
	com.add(cmd)
	cmd.Flags().BoolVar(&cluster, "cluster", false, "also run the cluster checks (administrators); say why they were skipped when they were")
	kf.addKube(cmd)
	return cmd
}

type doctorRun struct {
	checks []substrateCheck
}

func (d *doctorRun) add(id, status, summary, fix string) {
	d.checks = append(d.checks, substrateCheck{ID: id, Status: status, Summary: summary, Fix: fix})
}

func runSubstrateDoctor(cmd *cobra.Command, out *substrateOutput, com *substrateCommon, kf *substrateClusterFlags, clusterFlag bool) error {
	asJSON, err := out.wantJSON()
	if err != nil {
		return err
	}
	ctx, stop := substrateContext(cmd)
	defer stop()

	d := &doctorRun{}
	storeKind, storeErr := substrateDoctorStore()
	s, openErr := substrateOpen(cmd, com)

	// 1. The context.
	switch {
	case openErr == nil:
		d.add("context", doctorOK, "using "+s.Name+" ("+s.Ctx.AdminURL+")", "")
	case storeErr != nil:
		d.add("context", doctorSkip, "not checked: the token store cannot be used (see token_store)", "")
	default:
		d.add("context", doctorFail, doctorFirstLine(openErr), substrateLoginFix)
	}

	// 2. The token store.
	if storeErr != nil {
		d.add("token_store", doctorFail, doctorFirstLine(storeErr), "set DEFENSECLAW_SUBSTRATE_TOKEN_STORE=file to keep the sign-in in a 0600 file (CI and headless Linux), or fix the system keychain")
	} else if storeKind != "" {
		d.add("token_store", doctorOK, "your sign-in is kept in "+storeKind, "")
	} else {
		d.add("token_store", doctorOK, "your sign-in can be kept safely", "")
	}

	name := ""
	if openErr != nil {
		for _, id := range []string{"admin_address", "sign_in", "sign_in_server", "attach"} {
			d.add(id, doctorSkip, "needs a configured cluster", "")
		}
	} else {
		name = s.Name
		doctorCluster(ctx, d, s, clusterFlag)
	}

	if kf.installFile != "" {
		// Read with kubectl: these replace the gateway's own copy of the checks.
		kept := d.checks[:0]
		for _, c := range d.checks {
			if !strings.HasPrefix(c.ID, "cluster") {
				kept = append(kept, c)
			}
		}
		d.checks = append(kept, doctorKubeChecks(ctx, kf)...)
	}

	rep := substrateDoctorReport{Context: name, Checks: d.checks}
	for _, c := range d.checks {
		if c.Status == doctorFail {
			rep.Problems++
		}
	}
	rep.OK = rep.Problems == 0

	if asJSON {
		if err := writeSubstrateJSON(cmd.OutOrStdout(), rep); err != nil {
			return err
		}
	} else {
		printSubstrateDoctor(cmd.OutOrStdout(), rep)
	}
	if !rep.OK {
		// The report already says what failed.
		cmd.SilenceErrors = true
		return withExitCode(fmt.Errorf("%d check(s) failed", rep.Problems), 1)
	}
	return nil
}

func printSubstrateDoctor(w io.Writer, rep substrateDoctorReport) {
	if rep.Context != "" {
		fmt.Fprintf(w, "Checking cluster %s\n", rep.Context)
	}
	width := 0
	for _, c := range rep.Checks {
		width = max(width, len(c.ID))
	}
	for _, c := range rep.Checks {
		fmt.Fprintf(w, "  %-4s  %-*s  %s\n", c.Status, width, c.ID, c.Summary)
		if c.Status == doctorWarn && c.Fix != "" {
			fmt.Fprintf(w, "        %-*s  to fix: %s\n", width, "", c.Fix)
		}
	}
	if rep.OK {
		fmt.Fprintln(w, "ready for agents")
		return
	}
	fmt.Fprintf(w, "not ready: %d problem(s)\n", rep.Problems)
	for _, c := range rep.Checks {
		if c.Status != doctorFail {
			continue
		}
		fix := c.Fix
		if fix == "" {
			fix = "read the line above and correct it"
		}
		fmt.Fprintf(w, "  %s: %s\n", c.ID, fix)
	}
}

// doctorCluster runs the checks that need the cluster and the context.
func doctorCluster(ctx context.Context, d *doctorRun, s *substrateSession, clusterFlag bool) {
	c := s.Ctx

	// 3. The admin address answers over TLS.
	adminOK := false
	if info, err := probeTLS(ctx, c.AdminURL, c.AdminCAFile, nil, false); err != nil {
		d.add("admin_address", doctorFail, probeMessage("the admin address", c.AdminURL, err), probeFix(err, "--admin-url", "--admin-ca-file"))
	} else {
		adminOK = true
		d.add("admin_address", doctorOK, "the admin address answers ("+info.Version+")", "")
	}

	// 4. Signed in, and the cluster accepts the token.
	var mine []api.Actor
	signedIn := false
	if !adminOK {
		d.add("sign_in", doctorSkip, "not checked: the admin address does not answer", "")
	} else {
		actors, err := s.Client.List(ctx, api.ListOptions{})
		switch {
		case err == nil:
			signedIn = true
			for _, a := range actors {
				if !a.Deleted {
					mine = append(mine, a)
				}
			}
			d.add("sign_in", doctorOK, fmt.Sprintf("signed in; the cluster accepts the token (%d agent(s) of yours)", len(mine)), "")
		case errors.Is(err, auth.ErrNotSignedIn):
			d.add("sign_in", doctorFail, "you are not signed in", "defenseclaw substrate login")
		default:
			if e, ok := api.AsError(err); ok {
				switch {
				case e.Unauthorized():
					d.add("sign_in", doctorFail, "the cluster did not accept your sign-in ("+doctorWord(e.Reason, "token refused")+")", "defenseclaw substrate login")
				case e.NotImplemented():
					signedIn = true
					d.add("sign_in", doctorWarn, "the cluster accepted the token but does not list agents yet", "ask your administrator to upgrade DefenseClaw on the cluster")
				default:
					d.add("sign_in", doctorFail, substrateAPIMessage(e), "ask your administrator, or run doctor again in a minute")
				}
			} else {
				d.add("sign_in", doctorFail, "the cluster could not be asked: "+doctorFirstLine(err), "check the admin address, then run doctor again")
			}
		}
	}

	// 5. The sign-in server.
	d.checks = append(d.checks, doctorSignInServer(ctx, c))

	// 6. Attach through the gateway.
	d.checks = append(d.checks, doctorAttach(ctx, s, mine, signedIn))

	// 7. The cluster's own checks.
	if adminOK && signedIn {
		d.checks = append(d.checks, doctorFleetChecks(ctx, s.Client, clusterFlag)...)
	} else if clusterFlag {
		d.add("cluster", doctorSkip, "not checked: sign in and reach the admin address first", "")
	}
}

func doctorSignInServer(ctx context.Context, c auth.Context) substrateCheck {
	const id = "sign_in_server"
	if strings.TrimSpace(c.Issuer) == "" {
		return substrateCheck{ID: id, Status: doctorSkip, Summary: "this context signs in with a workload token only"}
	}
	cfg, err := substrateTLSConfig(c.IssuerCAFile)
	if err != nil {
		return substrateCheck{ID: id, Status: doctorFail, Summary: err.Error(), Fix: "defenseclaw substrate login --issuer-ca-file FILE"}
	}
	hc := &http.Client{
		Timeout:       substrateDoctorDialWait + 2*time.Second,
		Transport:     &http.Transport{TLSClientConfig: cfg, Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: substrateDoctorDialWait},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	issuer := strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return substrateCheck{ID: id, Status: doctorFail, Summary: "the issuer in your context is not a valid URL", Fix: "defenseclaw substrate login --issuer URL"}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return substrateCheck{ID: id, Status: doctorFail, Summary: probeMessage("the sign-in server", issuer, &probeFailure{kind: classifyProbe(err), err: err}),
			Fix: probeFix(&probeFailure{kind: classifyProbe(err), err: err}, "--issuer", "--issuer-ca-file")}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return substrateCheck{ID: id, Status: doctorFail, Summary: fmt.Sprintf("the sign-in server answered %d at its discovery address", resp.StatusCode),
			Fix: "check --issuer with your administrator; it is the address that ends before /.well-known"}
	}
	var doc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return substrateCheck{ID: id, Status: doctorFail, Summary: "the sign-in server's discovery answer is not understood", Fix: "check --issuer with your administrator"}
	}
	if got := strings.TrimRight(doc.Issuer, "/"); got != issuer {
		return substrateCheck{ID: id, Status: doctorFail, Summary: fmt.Sprintf("the sign-in server names itself %q, your context has %q", got, issuer),
			Fix: "defenseclaw substrate login --issuer " + got}
	}
	return substrateCheck{ID: id, Status: doctorOK, Summary: "the sign-in server answers and its issuer matches"}
}

func doctorAttach(ctx context.Context, s *substrateSession, mine []api.Actor, signedIn bool) substrateCheck {
	const id = "attach"
	if !signedIn {
		return substrateCheck{ID: id, Status: doctorSkip, Summary: "not checked: sign in first"}
	}
	if len(mine) == 0 {
		return substrateCheck{ID: id, Status: doctorSkip, Summary: "can be checked once you have an agent; start one with: defenseclaw substrate run claude"}
	}
	a := mine[0]
	o := attach.Options{
		Target:  attach.Target{Atespace: a.Atespace, Name: a.Name},
		Gateway: attach.Gateway{BaseURL: s.Ctx.AdminURL, CAFile: s.Ctx.AdminCAFile}, Bearer: s.Bearer,
		MaxWait: 5 * time.Second, NoBanner: true, NoAsks: true,
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, err := attach.Status(cctx, o); err != nil {
		switch {
		case errors.Is(err, attach.ErrNotOffered):
			return substrateCheck{ID: id, Status: doctorWarn, Summary: "this cluster does not offer attach through the gateway yet", Fix: "ask your administrator to upgrade DefenseClaw on the cluster"}
		case errors.Is(err, attach.ErrNotAllowed), errors.Is(err, attach.ErrNoActor):
			return substrateCheck{ID: id, Status: doctorWarn, Summary: "the cluster would not let you reach " + a.Atespace + "/" + a.Name + ": " + doctorFirstLine(err), Fix: "run doctor again after defenseclaw substrate list shows an agent of yours"}
		case errors.Is(err, attach.ErrNotSignedIn):
			return substrateCheck{ID: id, Status: doctorFail, Summary: "the cluster did not accept your sign-in for attach", Fix: "defenseclaw substrate login"}
		case errors.Is(err, attach.ErrClusterFull), errors.Is(err, attach.ErrStarting):
			return substrateCheck{ID: id, Status: doctorWarn, Summary: "attach is offered; the agent is busy starting or the cluster is full right now"}
		}
		return substrateCheck{ID: id, Status: doctorFail, Summary: "attach through the gateway failed: " + doctorFirstLine(err), Fix: "check the admin address and the cluster's gateway, then run doctor again"}
	}
	return substrateCheck{ID: id, Status: doctorOK, Summary: "attach through the gateway works (reached " + a.Atespace + "/" + a.Name + ")"}
}

// doctorFleetChecks reads the administrator verify document. explicit says
// the person asked for it with --cluster: then a refusal is shown as a skip.
func doctorFleetChecks(ctx context.Context, cl *api.Client, explicit bool) []substrateCheck {
	doc, err := cl.FleetVerifyDocument(ctx)
	if err != nil {
		if !explicit {
			return nil
		}
		if e, ok := api.AsError(err); ok {
			switch {
			case e.Status == http.StatusForbidden:
				return []substrateCheck{{ID: "cluster", Status: doctorSkip, Summary: "cluster checks are for administrators"}}
			case e.NotImplemented() || e.Status == http.StatusNotFound:
				return []substrateCheck{{ID: "cluster", Status: doctorSkip, Summary: "this cluster does not offer them yet"}}
			}
			return []substrateCheck{{ID: "cluster", Status: doctorFail, Summary: substrateAPIMessage(e), Fix: "run doctor again in a minute, or ask your administrator"}}
		}
		return []substrateCheck{{ID: "cluster", Status: doctorFail, Summary: "the cluster checks could not be read: " + doctorFirstLine(err), Fix: "run doctor again in a minute"}}
	}
	return doctorConvertFleet(doc.Checks)
}

// doctorConvertFleet turns A8's fleet checks into doctor rows.
func doctorConvertFleet(checks []fleet.Check) []substrateCheck {
	out := make([]substrateCheck, 0, len(checks))
	for _, c := range checks {
		sc := substrateCheck{ID: "cluster." + c.ID, Summary: c.Message}
		switch c.Status {
		case fleet.Pass:
			sc.Status = doctorOK
		case fleet.Warn:
			sc.Status = doctorWarn
		case fleet.Fail:
			sc.Status = doctorFail
		case fleet.Skip:
			sc.Status = doctorSkip
		default:
			sc.Status = doctorWarn
		}
		if sc.Status == doctorWarn || sc.Status == doctorFail {
			sc.Fix = fleetCheckFix(c.ID)
		}
		out = append(out, sc)
	}
	return out
}

// doctorKubeChecks reads the cluster with kubectl and runs the fleet checks.
func doctorKubeChecks(ctx context.Context, kf *substrateClusterFlags) []substrateCheck {
	o, r, err := collectFleet(ctx, kf)
	if err != nil {
		return []substrateCheck{{ID: "cluster", Status: doctorFail, Summary: doctorFirstLine(err), Fix: "check your kubectl access and the --install-file path, then run doctor again"}}
	}
	return doctorConvertFleet(fleet.BuildVerify(o, r.ProductVersion, r.Now).Checks)
}

func fleetCheckFix(id string) string {
	switch id {
	case fleet.CheckSubstrateVersion:
		return "use a Substrate version this DefenseClaw supports, or upgrade DefenseClaw (the message names the range)"
	case fleet.CheckIssuer:
		return "give this cluster its own actor token issuer: defenseclaw substrate setup --issuer URL, then ate-setup deploy"
	case fleet.CheckBucket:
		return "turn on encryption and block public access on the snapshot bucket, and set a retention period"
	case fleet.CheckGrants:
		return "write the access policies as a global owner: defenseclaw substrate setup --print-access-policies --plan FILE"
	case fleet.CheckCallout:
		return "defenseclaw substrate setup --install-file FILE, then ate-setup deploy and helm upgrade"
	case fleet.CheckIngressClients:
		return "remove the router clients you do not need from ingressAllowedSPIFFEIDs in the SubstrateInstall file"
	case fleet.CheckActorRoutes:
		return "check the DefenseClaw actor Service and the egress rule that routes to it (helm status)"
	case fleet.CheckAPIAccess:
		return "label the DefenseClaw namespace: kubectl label namespace NAMESPACE ate.dev/api-access=true"
	}
	return "read the message above and correct it on the cluster"
}

// --- TLS probes -------------------------------------------------------------

// probeFailure is a failed connection with what kind of failure it was:
// dns, connect, certificate, cafile or handshake.
type probeFailure struct {
	kind string
	err  error
}

func (p *probeFailure) Error() string { return p.err.Error() }
func (p *probeFailure) Unwrap() error { return p.err }

type probeInfo struct {
	// Version is the TLS version that was negotiated, or "plain http".
	Version string
	// Alert is a TLS alert the server sent after the handshake.
	Alert string
}

// substrateTLSConfig trusts the system roots and the CA file when one is given.
func substrateTLSConfig(caFile string) (*tls.Config, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("the CA file cannot be read: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("the CA file holds no certificate")
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, nil
}

func classifyProbe(err error) string {
	var dnsErr *net.DNSError
	var verr *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	var op *net.OpError
	switch {
	case errors.As(err, &dnsErr):
		return "dns"
	case errors.As(err, &verr), errors.As(err, &unknown), errors.As(err, &host), errors.As(err, &invalid):
		return "certificate"
	case errors.As(err, &op) && op.Op == "dial":
		return "connect"
	}
	return "handshake"
}

// probeTLS opens a TLS connection to rawURL and closes it. With watchAlert
// it waits a moment for an alert the server sends once the handshake is
// done, which is how a TLS 1.3 server refuses a client certificate.
func probeTLS(ctx context.Context, rawURL, caFile string, cert *tls.Certificate, watchAlert bool) (probeInfo, *probeFailure) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Hostname() == "" {
		return probeInfo{}, &probeFailure{kind: "address", err: errors.New("the address is not a valid URL")}
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	addr := net.JoinHostPort(u.Hostname(), port)
	dialer := &net.Dialer{Timeout: substrateDoctorDialWait}
	if u.Scheme == "http" {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return probeInfo{}, &probeFailure{kind: classifyProbe(err), err: err}
		}
		_ = conn.Close()
		return probeInfo{Version: "plain http, localhost only"}, nil
	}
	cfg, err := substrateTLSConfig(caFile)
	if err != nil {
		return probeInfo{}, &probeFailure{kind: "cafile", err: err}
	}
	cfg.ServerName = u.Hostname()
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	conn, err := (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return probeInfo{}, &probeFailure{kind: classifyProbe(err), err: err}
	}
	defer conn.Close()
	info := probeInfo{}
	if tc, ok := conn.(*tls.Conn); ok {
		switch tc.ConnectionState().Version {
		case tls.VersionTLS13:
			info.Version = "TLS 1.3"
		case tls.VersionTLS12:
			info.Version = "TLS 1.2"
		default:
			info.Version = "TLS"
		}
	}
	if watchAlert {
		_ = conn.SetReadDeadline(time.Now().Add(substrateDoctorAlertWait))
		var b [1]byte
		if _, err := conn.Read(b[:]); err != nil {
			var op *net.OpError
			if errors.As(err, &op) && op.Op == "remote error" {
				info.Alert = strings.TrimPrefix(op.Error(), "remote error: ")
			}
		}
	}
	return info, nil
}

// probeMessage says what failed, in plain words, for the check line.
func probeMessage(what, rawURL string, f *probeFailure) string {
	host := rawURL
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		host = u.Host
	}
	switch f.kind {
	case "dns":
		return fmt.Sprintf("%s: the name in %s does not resolve", what, host)
	case "connect":
		return fmt.Sprintf("%s: cannot connect to %s (%s)", what, host, connectReason(f.err))
	case "certificate":
		return fmt.Sprintf("%s: the certificate of %s is not trusted (%s)", what, host, certReason(f.err))
	case "cafile":
		return fmt.Sprintf("%s: %s", what, doctorFirstLine(f.err))
	case "address":
		return fmt.Sprintf("%s: %s", what, f.err)
	}
	return fmt.Sprintf("%s: the TLS handshake with %s failed (%s)", what, host, doctorFirstLine(f.err))
}

func connectReason(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	return doctorFirstLine(err)
}

func certReason(err error) string {
	var verr *tls.CertificateVerificationError
	if errors.As(err, &verr) && verr.Err != nil {
		return verr.Err.Error()
	}
	return doctorFirstLine(err)
}

func probeFix(f *probeFailure, urlFlag, caFlag string) string {
	switch f.kind {
	case "dns":
		return "check the address (defenseclaw substrate login " + urlFlag + " URL), your network or VPN, and that the name exists"
	case "connect":
		return "check the address and port, your VPN, and that the cluster exposes it"
	case "certificate":
		return "give the cluster's certificate authority: defenseclaw substrate login " + caFlag + " FILE"
	case "cafile":
		return "defenseclaw substrate login " + caFlag + " FILE"
	case "address":
		return "defenseclaw substrate login " + urlFlag + " https://HOST:PORT"
	}
	return "check that the address is a TLS endpoint and the port is right"
}

// doctorWord makes a closed reason such as token_refused readable.
func doctorWord(v, def string) string {
	if v == "" {
		return def
	}
	return strings.ReplaceAll(v, "_", " ")
}

func doctorFirstLine(err error) string {
	if err == nil {
		return ""
	}
	return strings.SplitN(err.Error(), "\n", 2)[0]
}
