// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// A small OCI distribution client: just what template build, publish and
// verify need (manifests, blobs, tags), with no dependency beyond net/http.

// Media types.
const (
	MediaOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	MediaOCIIndex       = "application/vnd.oci.image.index.v1+json"
	MediaOCIConfig      = "application/vnd.oci.image.config.v1+json"
	MediaOCILayerGzip   = "application/vnd.oci.image.layer.v1.tar+gzip"
	MediaOCILayer       = "application/vnd.oci.image.layer.v1.tar"
	MediaDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	MediaDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaDockerConfig   = "application/vnd.docker.container.image.v1+json"
	MediaDockerLayer    = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	// MediaDSSE is the layer type cosign uses for an attestation envelope.
	MediaDSSE = "application/vnd.dsse.envelope.v1+json"
)

const (
	maxManifestBytes = 4 << 20
	maxConfigBytes   = 4 << 20
)

// Ref names an image in a registry.
type Ref struct {
	Registry string
	Repo     string
	Tag      string
	Digest   string
}

// ParseRef parses host[:port]/repo[:tag][@sha256:...]. A name with no
// registry host is Docker Hub.
func ParseRef(s string) (Ref, error) {
	if s == "" || strings.ContainsAny(s, " \t\n\r") {
		return Ref{}, fmt.Errorf("image reference %q is empty or has spaces", s)
	}
	var r Ref
	rest := s
	if i := strings.Index(rest, "@"); i >= 0 {
		r.Digest = rest[i+1:]
		rest = rest[:i]
		if _, err := sha256Hex(r.Digest); err != nil {
			return Ref{}, fmt.Errorf("image reference %q: %w", s, err)
		}
	}
	slash := strings.Index(rest, "/")
	if slash < 0 {
		r.Registry = "registry-1.docker.io"
		r.Repo = "library/" + rest
	} else {
		first := rest[:slash]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			r.Registry = first
			r.Repo = rest[slash+1:]
		} else {
			r.Registry = "registry-1.docker.io"
			r.Repo = rest
		}
	}
	if i := strings.LastIndex(r.Repo, ":"); i >= 0 {
		r.Tag = r.Repo[i+1:]
		r.Repo = r.Repo[:i]
	}
	if !repoNameRE.MatchString(r.Repo) || (r.Tag != "" && !tagRE.MatchString(r.Tag)) {
		return Ref{}, fmt.Errorf("image reference %q has a bad repository", s)
	}
	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}
	return r, nil
}

// String is the canonical reference; a digest wins over a tag.
func (r Ref) String() string {
	base := r.Registry + "/" + r.Repo
	switch {
	case r.Digest != "" && r.Tag != "":
		return base + ":" + r.Tag + "@" + r.Digest
	case r.Digest != "":
		return base + "@" + r.Digest
	default:
		return base + ":" + r.Tag
	}
}

// Name is the repository name without tag or digest.
func (r Ref) Name() string { return r.Registry + "/" + r.Repo }

// WithDigest returns the reference pinned to a digest.
func (r Ref) WithDigest(d string) Ref { return Ref{Registry: r.Registry, Repo: r.Repo, Digest: d} }

// reference is the path element of a manifest URL.
func (r Ref) reference() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}

// RegistryOptions configure a client.
type RegistryOptions struct {
	// PlainHTTP lists registry hosts (host:port) reached over HTTP, for the
	// in-VPC registry of a dev cluster. Loopback hosts are always allowed.
	PlainHTTP []string
	// Username and Password are sent as basic auth, or to a token service.
	Username, Password string
	// AuthHosts are the only hosts (registries and token services) the
	// credentials are ever sent to. An image reference names its own registry,
	// so credentials are never sent to a host it chose.
	AuthHosts  []string
	HTTPClient *http.Client
}

// Registry is a client. It is safe for concurrent use.
type Registry struct {
	opts   RegistryOptions
	client *http.Client
	mu     sync.Mutex
	tokens map[string]string // host+scope → bearer token
}

// NewRegistry returns a client.
func NewRegistry(o RegistryOptions) *Registry {
	c := o.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Minute}
		c.CheckRedirect = refuseUnsafeRedirect
	}
	return &Registry{opts: o, client: c, tokens: map[string]string{}}
}

// ErrNotFound is returned for a 404 from the registry.
var ErrNotFound = errors.New("not found in the registry")

// RegistryError is a failed registry call.
type RegistryError struct {
	Op     string
	Status int
	Detail string
}

func (e *RegistryError) Error() string {
	return fmt.Sprintf("registry %s: HTTP %d %s", e.Op, e.Status, e.Detail)
}

func (e *RegistryError) Unwrap() error {
	if e.Status == http.StatusNotFound {
		return ErrNotFound
	}
	return nil
}

func (g *Registry) scheme(host string) string {
	for _, h := range g.opts.PlainHTTP {
		if h == host {
			return "http"
		}
	}
	h := host
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	if h == "localhost" {
		return "http"
	}
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil && ip.IsLoopback() {
		return "http"
	}
	return "https"
}

func (g *Registry) url(host, path string) string {
	return g.scheme(host) + "://" + host + path
}

type call struct {
	method  string
	host    string
	repo    string
	path    string
	accept  []string
	ctype   string
	body    []byte
	bodyRdr io.Reader
	bodyLen int64
	push    bool
	op      string
}

// do runs a request, answering one 401 challenge.
func (g *Registry) do(ctx context.Context, c call) (*http.Response, error) {
	scope := "repository:" + c.repo + ":pull"
	if c.push {
		scope = "repository:" + c.repo + ":pull,push"
	}
	for attempt := 0; attempt < 2; attempt++ {
		var body io.Reader
		switch {
		case c.body != nil:
			body = bytes.NewReader(c.body)
		case c.bodyRdr != nil:
			if attempt > 0 {
				return nil, errors.New("registry: cannot replay a streamed upload after a challenge")
			}
			body = c.bodyRdr
		}
		req, err := http.NewRequestWithContext(ctx, c.method, g.url(c.host, c.path), body)
		if err != nil {
			return nil, err
		}
		for _, a := range c.accept {
			req.Header.Add("Accept", a)
		}
		if c.ctype != "" {
			req.Header.Set("Content-Type", c.ctype)
		}
		if c.bodyRdr != nil {
			req.ContentLength = c.bodyLen
		}
		g.mu.Lock()
		tok := g.tokens[c.host+"|"+scope]
		g.mu.Unlock()
		switch {
		case tok != "":
			req.Header.Set("Authorization", "Bearer "+tok)
		case g.mayAuth(c.host):
			req.SetBasicAuth(g.opts.Username, g.opts.Password)
		}
		resp, err := g.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("registry %s: %w", c.op, err)
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			challenge := resp.Header.Get("Www-Authenticate")
			_ = resp.Body.Close()
			if t, err := g.fetchToken(ctx, challenge, scope); err == nil && t != "" {
				g.mu.Lock()
				g.tokens[c.host+"|"+scope] = t
				g.mu.Unlock()
				continue
			}
			return nil, &RegistryError{Op: c.op, Status: http.StatusUnauthorized, Detail: "authentication required"}
		}
		return resp, nil
	}
	return nil, &RegistryError{Op: c.op, Status: http.StatusUnauthorized, Detail: "authentication failed"}
}

// fetchToken answers a Bearer challenge from the token service.
func (g *Registry) fetchToken(ctx context.Context, challenge, scope string) (string, error) {
	rest, ok := strings.CutPrefix(challenge, "Bearer ")
	if !ok {
		return "", errors.New("not a bearer challenge")
	}
	params := map[string]string{}
	for _, kv := range strings.Split(rest, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if ok {
			params[k] = strings.Trim(v, `"`)
		}
	}
	realm := params["realm"]
	if realm == "" {
		return "", errors.New("no realm")
	}
	u, err := url.Parse(realm)
	if err != nil || (u.Scheme != "https" && (u.Scheme != "http" || g.scheme(u.Host) != "http")) {
		return "", errors.New("bad realm")
	}
	q := u.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	q.Set("scope", scope)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	if g.mayAuth(u.Host) {
		req.SetBasicAuth(g.opts.Username, g.opts.Password)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token service: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	if out.Token != "" {
		return out.Token, nil
	}
	return out.AccessToken, nil
}

// failed reports the status only: a registry chosen by an untrusted image
// reference must not get its response text into events and logs.
func failed(op string, resp *http.Response) error {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	return &RegistryError{Op: op, Status: resp.StatusCode}
}

var manifestAccept = []string{MediaOCIManifest, MediaOCIIndex, MediaDockerManifest, MediaDockerList}

// Manifest fetches a manifest or index and its digest. The digest is the
// registry's header, checked against the bytes when the reference is a digest.
func (g *Registry) Manifest(ctx context.Context, ref Ref) (body []byte, mediaType, digest string, err error) {
	resp, err := g.do(ctx, call{method: http.MethodGet, host: ref.Registry, repo: ref.Repo,
		path: "/v2/" + ref.Repo + "/manifests/" + ref.reference(), accept: manifestAccept, op: "get manifest"})
	if err != nil {
		return nil, "", "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", "", failed("get manifest", resp)
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return nil, "", "", err
	}
	if len(body) > maxManifestBytes {
		return nil, "", "", errors.New("registry: manifest is too large")
	}
	// The digest is always computed from the bytes. The header is only a
	// cross-check: a registry that sends other bytes than it names is wrong
	// or hostile, and a digest reference that the bytes don't match is refused.
	digest = DigestOf(body)
	if h := resp.Header.Get("Docker-Content-Digest"); h != "" && h != digest {
		return nil, "", "", fmt.Errorf("registry: manifest digest header %s does not match its bytes %s", h, digest)
	}
	if ref.Digest != "" && ref.Digest != digest {
		return nil, "", "", fmt.Errorf("registry: manifest bytes hash to %s, not the requested %s", digest, ref.Digest)
	}
	mediaType = resp.Header.Get("Content-Type")
	if i := strings.Index(mediaType, ";"); i >= 0 {
		mediaType = mediaType[:i]
	}
	return body, mediaType, digest, nil
}

// Digest resolves a reference to a manifest digest without trusting a tag
// beyond the moment of the call.
func (g *Registry) Digest(ctx context.Context, ref Ref) (string, error) {
	if ref.Digest != "" {
		return ref.Digest, nil
	}
	_, _, d, err := g.Manifest(ctx, ref)
	return d, err
}

// PutManifest stores a manifest under a tag or digest and returns its digest.
func (g *Registry) PutManifest(ctx context.Context, ref Ref, mediaType string, body []byte) (string, error) {
	resp, err := g.do(ctx, call{method: http.MethodPut, host: ref.Registry, repo: ref.Repo,
		path: "/v2/" + ref.Repo + "/manifests/" + ref.reference(), ctype: mediaType, body: body, push: true, op: "put manifest"})
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", failed("put manifest", resp)
	}
	_ = resp.Body.Close()
	return DigestOf(body), nil
}

// BlobExists asks with HEAD.
func (g *Registry) BlobExists(ctx context.Context, host, repo, digest string) (bool, error) {
	resp, err := g.do(ctx, call{method: http.MethodHead, host: host, repo: repo,
		path: "/v2/" + repo + "/blobs/" + digest, op: "head blob"})
	if err != nil {
		return false, err
	}
	_ = resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, &RegistryError{Op: "head blob", Status: resp.StatusCode}
}

// Blob streams a blob. The caller closes it and must verify the digest.
func (g *Registry) Blob(ctx context.Context, host, repo, digest string) (io.ReadCloser, int64, error) {
	resp, err := g.do(ctx, call{method: http.MethodGet, host: host, repo: repo,
		path: "/v2/" + repo + "/blobs/" + digest, op: "get blob"})
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, failed("get blob", resp)
	}
	return resp.Body, resp.ContentLength, nil
}

// SmallBlob reads a blob of at most limit bytes and checks its digest.
func (g *Registry) SmallBlob(ctx context.Context, host, repo, digest string, limit int64) ([]byte, error) {
	rc, _, err := g.Blob(ctx, host, repo, digest)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("registry: blob %s is larger than %d bytes", digest, limit)
	}
	if got := DigestOf(data); got != digest {
		return nil, fmt.Errorf("registry: blob %s hashes to %s", digest, got)
	}
	return data, nil
}

// PutBlob uploads a blob monolithically unless the registry has it.
func (g *Registry) PutBlob(ctx context.Context, host, repo, digest string, r io.Reader, size int64) error {
	if ok, err := g.BlobExists(ctx, host, repo, digest); err == nil && ok {
		return nil
	}
	resp, err := g.do(ctx, call{method: http.MethodPost, host: host, repo: repo,
		path: "/v2/" + repo + "/blobs/uploads/", push: true, op: "start upload"})
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusAccepted {
		return failed("start upload", resp)
	}
	loc := resp.Header.Get("Location")
	_ = resp.Body.Close()
	if loc == "" {
		return errors.New("registry: upload has no Location")
	}
	u, err := url.Parse(loc)
	if err != nil {
		return err
	}
	base, _ := url.Parse(g.url(host, "/"))
	u = base.ResolveReference(u)
	if u.Host != base.Host {
		return fmt.Errorf("registry: upload Location points to another host %q", u.Host)
	}
	q := u.Query()
	q.Set("digest", digest)
	u.RawQuery = q.Encode()
	path := u.RequestURI()
	resp, err = g.do(ctx, call{method: http.MethodPut, host: host, repo: repo, path: path,
		ctype: "application/octet-stream", bodyRdr: r, bodyLen: size, push: true, op: "finish upload"})
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusCreated {
		return failed("finish upload", resp)
	}
	_ = resp.Body.Close()
	return nil
}

// PutBlobBytes uploads small content.
func (g *Registry) PutBlobBytes(ctx context.Context, host, repo string, data []byte) (string, error) {
	d := DigestOf(data)
	return d, g.PutBlob(ctx, host, repo, d, bytes.NewReader(data), int64(len(data)))
}

// Tags lists the tags of a repository (one page of up to n).
func (g *Registry) Tags(ctx context.Context, host, repo string) ([]string, error) {
	resp, err := g.do(ctx, call{method: http.MethodGet, host: host, repo: repo,
		path: "/v2/" + repo + "/tags/list", op: "list tags"})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, failed("list tags", resp)
	}
	defer resp.Body.Close()
	var out struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return out.Tags, nil
}

var (
	// repoNameRE and tagRE are the OCI distribution name rules: lower case,
	// no percent escapes, no dot segments.
	repoNameRE = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
	tagRE      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
)

func (g *Registry) mayAuth(host string) bool {
	if g.opts.Username == "" {
		return false
	}
	for _, h := range g.opts.AuthHosts {
		if h == host {
			return true
		}
	}
	return false
}

// refuseUnsafeRedirect lets a registry send blobs to its storage over https
// and nothing else: no downgrade to http, no private or loopback address
// literal, at most 10 hops. Go drops Authorization on a change of host.
func refuseUnsafeRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("registry: too many redirects")
	}
	first := via[0].URL
	if req.URL.Scheme != "https" && (req.URL.Host != first.Host || req.URL.Scheme != first.Scheme) {
		return errors.New("registry: redirect to a non-https URL on another host")
	}
	if a, err := netip.ParseAddr(req.URL.Hostname()); err == nil && req.URL.Host != first.Host &&
		(a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified()) {
		return errors.New("registry: redirect to a private address")
	}
	return nil
}
