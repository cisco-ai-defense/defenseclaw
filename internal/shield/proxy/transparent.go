package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/shield/audit"
	"github.com/defenseclaw/defenseclaw/internal/shield/ca"
	"github.com/defenseclaw/defenseclaw/internal/shield/inspect"
	"github.com/defenseclaw/defenseclaw/internal/shield/policy"
	"github.com/defenseclaw/defenseclaw/internal/shield/providers"
)

// TransparentProxy is an HTTPS proxy that:
// 1. Accepts CONNECT requests (explicit proxy mode, used with http_proxy env var)
// 2. Intercepts TLS connections to LLM provider domains
// 3. Passes through TLS connections to non-LLM domains (no MITM)
// 4. Inspects plaintext HTTP request/response bodies for security threats
// 5. Blocks requests that violate policy
type TransparentProxy struct {
	addr      string
	ca        *ca.Authority
	registry  *providers.Registry
	inspector *inspect.Inspector
	engine    *policy.Engine
	logger    *audit.Logger
	listener  net.Listener
	wg        sync.WaitGroup
	done      chan struct{}
}

func NewTransparentProxy(
	addr string,
	authority *ca.Authority,
	registry *providers.Registry,
	inspector *inspect.Inspector,
	engine *policy.Engine,
	logger *audit.Logger,
) *TransparentProxy {
	return &TransparentProxy{
		addr:      addr,
		ca:        authority,
		registry:  registry,
		inspector: inspector,
		engine:    engine,
		logger:    logger,
		done:      make(chan struct{}),
	}
}

func (p *TransparentProxy) Start() error {
	var err error
	p.listener, err = net.Listen("tcp", p.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", p.addr, err)
	}
	p.wg.Add(1)
	go p.acceptLoop()
	return nil
}

func (p *TransparentProxy) Stop() {
	close(p.done)
	p.listener.Close()
	p.wg.Wait()
}

func (p *TransparentProxy) Addr() string {
	return p.listener.Addr().String()
}

func (p *TransparentProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.done:
				return
			default:
				continue
			}
		}
		p.wg.Add(1)
		go p.handleConn(conn)
	}
}

func (p *TransparentProxy) handleConn(conn net.Conn) {
	defer p.wg.Done()
	defer conn.Close()

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		p.handleConnect(conn, req)
	} else {
		p.handlePlainHTTP(conn, req)
	}
}

func (p *TransparentProxy) handleConnect(clientConn net.Conn, req *http.Request) {
	host := req.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	hostname := hostOnly(host)

	// Tell client the tunnel is established.
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	providerName, isLLM := p.registry.MatchHost(hostname)
	if !isLLM {
		// Not an LLM domain — tunnel directly, no interception.
		p.tunnel(clientConn, host)
		return
	}

	// LLM domain — MITM to inspect content.
	p.mitmConnect(clientConn, host, hostname, providerName)
}

// tunnel passes bytes between client and upstream with zero inspection.
func (p *TransparentProxy) tunnel(clientConn net.Conn, host string) {
	upstream, err := net.Dial("tcp", host)
	if err != nil {
		return
	}
	defer upstream.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(upstream, clientConn) }()
	go func() { defer wg.Done(); io.Copy(clientConn, upstream) }()
	wg.Wait()
}

// mitmConnect terminates TLS with the client (using a minted cert),
// reads the plaintext HTTP request, inspects it, and either blocks
// or forwards to the real upstream.
func (p *TransparentProxy) mitmConnect(clientConn net.Conn, host, hostname, providerName string) {
	leafCert, err := p.ca.MintForHost(hostname)
	if err != nil {
		log.Printf("[shield] mint cert for %s: %v", hostname, err)
		return
	}

	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
	})
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[shield] TLS handshake with client for %s: %v", hostname, err)
		return
	}
	defer tlsConn.Close()

	br := bufio.NewReader(tlsConn)

	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}

		p.handleInspectedRequest(tlsConn, req, host, hostname, providerName)
	}
}

func (p *TransparentProxy) handleInspectedRequest(
	clientTLS *tls.Conn,
	req *http.Request,
	host, hostname, providerName string,
) {
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(req.Body, 10*1024*1024))
		req.Body.Close()
	}

	// Inspect the request body.
	result := p.inspector.Inspect(string(bodyBytes))
	verdict := p.engine.Evaluate(result)

	p.logger.Log(audit.Event{
		EventType:   "llm_intercept",
		Provider:    providerName,
		Destination: hostname,
		Direction:   "request",
		Verdict:     verdict,
		ContentSize: len(bodyBytes),
	})

	if verdict.Action == policy.ActionBlock {
		log.Printf("[shield] BLOCKED request to %s (%s)", hostname, verdict.Reason)
		blockBody := `{"error":{"type":"shield_blocked","message":"DefenseClaw Shield: request blocked by security policy"}}`
		fmt.Fprintf(clientTLS, "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(blockBody), blockBody)
		return
	}

	// Forward to real upstream.
	upstreamTLS, err := tls.Dial("tcp", host, &tls.Config{
		ServerName: hostname,
	})
	if err != nil {
		log.Printf("[shield] upstream dial %s: %v", host, err)
		writeError(clientTLS, 502, "upstream connection failed")
		return
	}
	defer upstreamTLS.Close()

	// Rebuild the request with the original body.
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))
	req.RequestURI = ""
	req.URL.Scheme = "https"
	req.URL.Host = hostname

	if err := req.Write(upstreamTLS); err != nil {
		writeError(clientTLS, 502, "upstream write failed")
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(upstreamTLS), req)
	if err != nil {
		writeError(clientTLS, 502, "upstream read failed")
		return
	}
	defer resp.Body.Close()

	// Read response body for inspection.
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))

	respResult := p.inspector.Inspect(string(respBody))
	respVerdict := p.engine.Evaluate(respResult)

	p.logger.Log(audit.Event{
		EventType:   "llm_intercept",
		Provider:    providerName,
		Destination: hostname,
		Direction:   "response",
		Verdict:     respVerdict,
		ContentSize: len(respBody),
	})

	if respVerdict.Action == policy.ActionBlock {
		log.Printf("[shield] BLOCKED response from %s (%s)", hostname, respVerdict.Reason)
		writeError(clientTLS, 403, "DefenseClaw Shield: response blocked by security policy")
		return
	}

	// Forward response to client.
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	resp.ContentLength = int64(len(respBody))
	resp.Write(clientTLS)
}

func (p *TransparentProxy) handlePlainHTTP(conn net.Conn, req *http.Request) {
	writeError(conn, 400, "shield proxy expects HTTPS CONNECT")
}

func writeError(w io.Writer, code int, msg string) {
	body := fmt.Sprintf(`{"error":{"message":"%s"}}`, msg)
	fmt.Fprintf(w, "HTTP/1.1 %d Error\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", code, len(body), body)
}

func hostOnly(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return h
}
