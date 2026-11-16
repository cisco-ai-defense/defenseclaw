// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

var provenanceCmd = &cobra.Command{
	Use:   "provenance",
	Short: "Print the binary and config provenance (schema, content hash, generation, version)",
}

var provenanceShowCmd = &cobra.Command{
	Use:         "show",
	Short:       "Show schema_version, content_hash, generation, and binary_version",
	Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
	RunE:        runProvenanceShow,
}

func init() {
	provenanceCmd.AddCommand(provenanceShowCmd)
	rootCmd.AddCommand(provenanceCmd)
}

func runProvenanceShow(cmd *cobra.Command, _ []string) error {
	version.SetBinaryVersion(appVersion)
	p := version.Current()
	if live, present, err := managedGatewayProvenance(cmd); present {
		if err != nil {
			return err
		}
		p = live
	}
	var out io.Writer = os.Stdout
	if cmd != nil {
		out = cmd.OutOrStdout()
	}
	fmt.Fprintf(out, "schema_version: %d\n", p.SchemaVersion)
	fmt.Fprintf(out, "content_hash: %s\n", p.ContentHash)
	fmt.Fprintf(out, "generation: %d\n", p.Generation)
	fmt.Fprintf(out, "binary_version: %s\n", p.BinaryVersion)
	return nil
}

// A short-lived CLI has no applied managed config or generation. Read the
// running gateway's administrator view instead, without daemon bootstrap or
// opening its audit store. Secure Client and per-user commands keep their
// existing path (r103 GAP-0004/0128).
func managedGatewayProvenance(cmd *cobra.Command) (version.Provenance, bool, error) {
	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}
	if live, present, err := managedWindowsGatewayProvenance(ctx); present {
		return live, true, err
	}
	layout, descriptor, err := managedStandaloneAdminDeployment()
	if errors.Is(err, managed.ErrNoRuntimeDescriptor) {
		return version.Provenance{}, false, nil
	}
	next := fmt.Sprintf("sudo %s enterprise %s status", managedHostGatewayCommand(), managedHostPlatform())
	if err != nil {
		return version.Provenance{}, true, fmt.Errorf("cannot read the managed deployment: %w; check it with: %s", err, next)
	}
	if descriptor == nil {
		return version.Provenance{}, true, fmt.Errorf("the managed runtime descriptor is unavailable; check it with: %s", next)
	}
	if !managed.IsStandaloneProfile(descriptor.Profile) {
		return version.Provenance{}, false, nil
	}
	uid := managedHostCallerUID()
	if uid != 0 && (descriptor.ServiceUID < 0 || uid != descriptor.ServiceUID) {
		return version.Provenance{}, true, fmt.Errorf("the managed gateway's provenance needs administrator access; ask your administrator to run: sudo %s provenance show", managedHostGatewayCommand())
	}
	var answer struct {
		Provenance *version.Provenance `json:"provenance"`
	}
	if err := managedProvenanceHealth(ctx, layout, descriptor.ServiceUID, &answer); err != nil {
		return version.Provenance{}, true, fmt.Errorf("cannot read the managed gateway's provenance: %w; check it with: %s", err, next)
	}
	if err := validManagedProvenance(answer.Provenance, next); err != nil {
		return version.Provenance{}, true, err
	}
	return *answer.Provenance, true, nil
}

// validManagedProvenance fails unless p is a complete administrator
// provenance snapshot: schema, a sha256 content hash and the binary version.
func validManagedProvenance(p *version.Provenance, next string) error {
	if p == nil || p.ContentHash == "" || p.SchemaVersion <= 0 || p.BinaryVersion == "" {
		return fmt.Errorf("the managed gateway did not provide complete administrator provenance; check it with: %s", next)
	}
	if digest, err := hex.DecodeString(p.ContentHash); err != nil || len(digest) != 32 {
		return fmt.Errorf("the managed gateway returned invalid config provenance; check it with: %s", next)
	}
	return nil
}

// The protected hook socket is the authority. Check the kernel peer on the
// very connection used for /health; never send an administrator credential
// to an unproven loopback listener or fall back to a personal gateway.
var managedProvenanceHealth = func(ctx context.Context, layout managed.StandaloneLayout, serviceUID int, out any) error {
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, "unix", layout.HookSocketPath)
			if err != nil {
				return nil, err
			}
			peer, err := peercred.FromConn(conn)
			if err != nil || (peer.UID != 0 && peer.UID != serviceUID) {
				_ = conn.Close()
				return nil, errors.New("the managed gateway socket's listener identity could not be verified")
			}
			return conn, nil
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://defenseclaw-hook/health", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("managed gateway health returned HTTP %d", response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(out)
}
