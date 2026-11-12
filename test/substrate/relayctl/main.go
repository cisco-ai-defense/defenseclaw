// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// relayctl drives defenseclaw-actor-relay by hand for the Substrate live
// cells: it makes a test session-token key, mints tokens (the job A2's admin
// listener does for real), attaches a terminal and runs headless tasks.
//
//	relayctl keygen --key k.pem --pub k.pub.pem
//	relayctl mint --key k.pem --kid test1 --sub alice@example.test --atespace a5-gv --name cc-1 --uid <uid>
//	relayctl attach --url http://127.0.0.1:8150 --token-file t [--long-poll]
//	relayctl task --url http://127.0.0.1:8150 --token-file t --prompt "..."
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: relayctl keygen|mint|attach|task ...")
		os.Exit(2)
	}
	var err error
	code := 0
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "mint":
		err = mint(os.Args[2:])
	case "attach":
		err = attach(os.Args[2:])
	case "task":
		code, err = task(os.Args[2:])
	case "exec":
		err = execLine(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "relayctl:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	keyPath := fs.String("key", "", "private key out (PEM, 0600)")
	pubPath := fs.String("pub", "", "public key out (PEM)")
	fs.Parse(args)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(*keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return err
	}
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return os.WriteFile(*pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0o644)
}

func mint(args []string) error {
	fs := flag.NewFlagSet("mint", flag.ExitOnError)
	keyPath := fs.String("key", "", "private key (PEM)")
	kid := fs.String("kid", "test1", "key id")
	sub := fs.String("sub", "", "person")
	atespace := fs.String("atespace", "", "actor atespace")
	name := fs.String("name", "", "actor name")
	uid := fs.String("uid", "", "actor UID")
	aud := fs.String("aud", "dcrelay", "audience")
	iss := fs.String("iss", "", "issuer")
	ttl := fs.Duration("ttl", 10*time.Minute, "lifetime")
	typ := fs.String("typ", relay.TokenType, "JWS typ (tests of refusals)")
	taskText := fs.String("task", "", "bind the token to this --task text (dc.task_sha256)")
	fs.Parse(args)
	b, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return fmt.Errorf("no PEM in %s", *keyPath)
	}
	k, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	now := time.Now()
	jti := make([]byte, 12)
	rand.Read(jti)
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": *kid, "typ": *typ})
	c, _ := json.Marshal(map[string]any{
		"iss": *iss, "sub": *sub, "aud": []string{*aud}, "iat": now.Unix(), "nbf": now.Unix(),
		"exp": now.Add(*ttl).Unix(), "jti": base64.RawURLEncoding.EncodeToString(jti),
		"dc.actor": map[string]string{"atespace": *atespace, "actorName": *name, "actorUID": *uid},
		"dc.task_sha256": func() string {
			if *taskText == "" {
				return ""
			}
			return relay.TaskDigest(*taskText)
		}(),
	})
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	d := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
	if err != nil {
		return err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	fmt.Println(in + "." + base64.RawURLEncoding.EncodeToString(sig))
	return nil
}

func readToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func attach(args []string) error {
	fs := flag.NewFlagSet("attach", flag.ExitOnError)
	url := fs.String("url", "", "relay origin")
	tokenFile := fs.String("token-file", "", "session token file")
	longPoll := fs.Bool("long-poll", false, "use the long-poll fallback")
	fs.Parse(args)
	tok, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	cols, rows := uint16(80), uint16(24)
	fd := int(os.Stdin.Fd())
	resize := make(chan relay.Resize, 4)
	if term.IsTerminal(fd) {
		if w, h, err := term.GetSize(fd); err == nil {
			cols, rows = uint16(w), uint16(h)
		}
		old, err := term.MakeRaw(fd)
		if err != nil {
			return err
		}
		defer term.Restore(fd, old)
		sig := make(chan os.Signal, 4)
		notifyWindowResize(sig)
		go func() {
			for range sig {
				if w, h, err := term.GetSize(fd); err == nil {
					resize <- relay.Resize{Cols: uint16(w), Rows: uint16(h)}
				}
			}
		}()
	}
	res, err := relay.Attach(context.Background(), os.Stdin, os.Stdout, relay.AttachOptions{
		BaseURL: *url, Token: tok, Cols: cols, Rows: rows, LongPoll: *longPoll, Resize: resize,
	})
	if err != nil {
		return err
	}
	switch {
	case res.Detached:
		fmt.Fprintf(os.Stderr, "\r\n[relayctl] detached from session %s\r\n", res.Session)
	case res.ExitCode != nil:
		fmt.Fprintf(os.Stderr, "\r\n[relayctl] agent exited %d\r\n", *res.ExitCode)
	default:
		fmt.Fprintf(os.Stderr, "\r\n[relayctl] connection closed (session %s)\r\n", res.Session)
	}
	return nil
}

// execLine attaches, waits for the relay's hello, types one shell line into
// the agent's terminal (a shell in the bench images), prints the screen
// output up to the marker the line echoes, and detaches. It reports the
// hello and done times relative to the dial on stderr.
func execLine(args []string) error {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	url := fs.String("url", "", "relay origin")
	tokenFile := fs.String("token-file", "", "session token file")
	line := fs.String("line", "", "shell line; {DONE} in it becomes the end marker (a fresh nonce per call)")
	timeout := fs.Duration("timeout", 60*time.Second, "overall timeout")
	fs.Parse(args)
	tok, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	nb := make([]byte, 6)
	rand.Read(nb)
	nonce := fmt.Sprintf("%x", nb)
	marker := "__A5DONE_" + nonce + "__"
	*line = strings.ReplaceAll(*line, "{DONE}", "printf '__A5D%sE_"+nonce+"__\\n' ON")
	start := time.Now()
	pr, pw := io.Pipe()
	var screen strings.Builder
	var mu sync.Mutex
	done := make(chan struct{})
	var helloAt time.Duration
	out := writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		screen.Write(p)
		if strings.Contains(screen.String(), marker) {
			select {
			case <-done:
			default:
				close(done)
			}
		}
		return len(p), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
		}
		pw.Write([]byte{relay.DetachKey})
	}()
	var sendOnce sync.Once
	res, err := relay.Attach(ctx, pr, out, relay.AttachOptions{BaseURL: *url, Token: tok, Cols: 200, Rows: 50,
		OnControl: func(c relay.Control) {
			if c.Type == relay.CtlHello {
				helloAt = time.Since(start)
				sendOnce.Do(func() { go pw.Write([]byte(*line + "\r")) })
			}
		}})
	if err != nil {
		return err
	}
	total := time.Since(start)
	mu.Lock()
	s := screen.String()
	mu.Unlock()
	if i := strings.Index(s, marker); i >= 0 {
		s = s[:i]
		if j := strings.LastIndex(s, nonce); j >= 0 {
			// From the end of the echoed line to the marker.
			s = s[j+len(nonce):]
		}
	}
	fmt.Print(s)
	fmt.Fprintf(os.Stderr, "hello_ms=%d total_ms=%d session=%s detached=%v\n", helloAt.Milliseconds(), total.Milliseconds(), res.Session, res.Detached)
	if ctx.Err() != nil {
		return fmt.Errorf("timed out")
	}
	return nil
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func task(args []string) (int, error) {
	fs := flag.NewFlagSet("task", flag.ExitOnError)
	url := fs.String("url", "", "relay origin")
	tokenFile := fs.String("token-file", "", "session token file")
	prompt := fs.String("prompt", "", "task text")
	fs.Parse(args)
	tok, err := readToken(*tokenFile)
	if err != nil {
		return -1, err
	}
	enc := json.NewEncoder(os.Stdout)
	return relay.RunTask(context.Background(), nil, *url, tok, relay.TaskRequest{Prompt: *prompt},
		func(e relay.TaskEvent) { _ = enc.Encode(e) })
}
