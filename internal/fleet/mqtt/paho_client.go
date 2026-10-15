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

// Package mqtt uses Eclipse Paho Go v2 for MQTT transport, QoS 1 tracking,
// keepalive, and reconnects.
//
// The bridge (bridge.go) and wire-format code (broker.go) are unchanged —
// they depend only on the mqtt.Client interface.
package mqtt

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
)

// PahoClient wraps autopaho.ConnectionManager to satisfy the mqtt.Client
// interface. It provides auto-reconnect with exponential backoff, QoS 1
// PUBACK tracking, keepalive, and TLS — all handled by the library.
type PahoClient struct {
	cm   *autopaho.ConnectionManager
	addr string
	id   string

	mu   sync.RWMutex
	subs map[string]func(Message)

	requireTLS bool

	cfgUser string
	cfgPass string
}

// SetCredentials sets MQTT credentials resolved from config.yaml.
// Must be called before Connect. Falls back to DCLAW_MQTT_USER/PASS env vars.
func (c *PahoClient) SetCredentials(user, pass string) {
	c.cfgUser = user
	c.cfgPass = pass
}

// NewPahoClient creates a new Paho-backed MQTT client.
// addr is the broker URL (mqtt://, mqtts://, tcp://, ssl://, or bare host:port).
// clientID identifies this client to the broker.
func NewPahoClient(addr, clientID string, requireTLS ...bool) *PahoClient {
	c := &PahoClient{
		addr: addr,
		id:   clientID,
		subs: make(map[string]func(Message)),
	}
	if len(requireTLS) > 0 {
		c.requireTLS = requireTLS[0]
	}
	return c
}

// normalizeBrokerURL converts the various supported URL formats into a
// *url.URL that autopaho can use. Handles mqtt://, mqtts://, tcp://,
// ssl://, and bare host:port.
func normalizeBrokerURL(raw string) (*url.URL, error) {
	// Normalize scheme for url.Parse
	normalized := raw
	switch {
	case strings.HasPrefix(raw, "mqtts://"):
		normalized = "ssl://" + strings.TrimPrefix(raw, "mqtts://")
	case strings.HasPrefix(raw, "mqtt://"):
		normalized = "tcp://" + strings.TrimPrefix(raw, "mqtt://")
	case !strings.Contains(raw, "://"):
		// Bare host:port — assume tcp
		normalized = "tcp://" + raw
	}

	u, err := url.Parse(normalized)
	if err != nil {
		return nil, fmt.Errorf("parse broker URL %q: %w", raw, err)
	}

	// Default ports
	if u.Port() == "" {
		switch u.Scheme {
		case "ssl", "tls", "wss":
			u.Host = net.JoinHostPort(u.Hostname(), "8883")
		default:
			u.Host = net.JoinHostPort(u.Hostname(), "1883")
		}
	}

	return u, nil
}

// Connect establishes a connection to the MQTT broker. The connection is
// managed by autopaho which handles reconnection automatically.
func (c *PahoClient) Connect(ctx context.Context) error {
	// Enforce the production MQTT transport policy.
	if err := c.checkPlaintextMQTT(); err != nil {
		return err
	}
	if err := c.checkRequireTLS(); err != nil {
		return err
	}

	brokerURL, err := normalizeBrokerURL(c.addr)
	if err != nil {
		return err
	}

	// Build TLS config from the broker certificate settings.
	var tlsCfg *tls.Config
	if brokerURL.Scheme == "ssl" || brokerURL.Scheme == "tls" || brokerURL.Scheme == "wss" {
		tlsCfg, err = buildTLSConfig()
		if err != nil {
			return fmt.Errorf("build TLS config: %w", err)
		}
	}

	// Read MQTT credentials: config-injected values first, env var fallback.
	mqttUser := c.cfgUser
	if mqttUser == "" {
		mqttUser = os.Getenv("DCLAW_MQTT_USER")
	}
	mqttPass := c.cfgPass
	if mqttPass == "" {
		mqttPass = os.Getenv("DCLAW_MQTT_PASS")
	}

	cfg := autopaho.ClientConfig{
		ServerUrls:                    []*url.URL{brokerURL},
		TlsCfg:                        tlsCfg,
		KeepAlive:                     60,
		CleanStartOnInitialConnection: true,
		SessionExpiryInterval:         0,
		ConnectRetryDelay:             time.Second,
		OnConnectionUp: func(cm *autopaho.ConnectionManager, connack *paho.Connack) {
			log.Printf("[mqtt-paho] connected to %s (session_present=%v)", brokerURL.String(), connack.SessionPresent)

			// Re-subscribe to all registered topics on (re)connect.
			// autopaho calls this on every successful connect, including
			// reconnects — so subscriptions survive broker restarts.
			c.mu.RLock()
			subs := make(map[string]func(Message), len(c.subs))
			for k, v := range c.subs {
				subs[k] = v
			}
			c.mu.RUnlock()

			for filter := range subs {
				subCtx, subCancel := context.WithTimeout(context.Background(), 10*time.Second)
				_, subErr := cm.Subscribe(subCtx, &paho.Subscribe{
					Subscriptions: []paho.SubscribeOptions{{
						Topic: filter,
						QoS:   1,
					}},
				})
				subCancel()
				if subErr != nil {
					log.Printf("[mqtt-paho] re-subscribe to %s failed: %v", filter, subErr)
				}
			}
		},
		OnConnectError: func(err error) {
			log.Printf("[mqtt-paho] connect error: %v (will retry)", err)
		},
		ClientConfig: paho.ClientConfig{
			ClientID: c.id,
			Router: paho.NewSingleHandlerRouter(func(p *paho.Publish) {
				msg := Message{
					Topic:   p.Topic,
					Payload: p.Payload,
					QoS:     p.QoS,
				}
				// Dispatch to the matching subscription handler
				c.mu.RLock()
				var handler func(Message)
				for filter, h := range c.subs {
					if mqttTopicMatch(msg.Topic, filter) {
						handler = h
						break
					}
				}
				c.mu.RUnlock()

				if handler != nil {
					handler(msg)
				}
			}),
		},
	}

	// Set credentials if provided
	if mqttUser != "" || mqttPass != "" {
		cfg.ConnectUsername = mqttUser
		cfg.ConnectPassword = []byte(mqttPass)
	}

	cm, err := autopaho.NewConnection(ctx, cfg)
	if err != nil {
		return fmt.Errorf("mqtt connect: %w", err)
	}

	// autopaho already retries connection attempts for the lifetime of ctx.
	// Keep this single manager alive until the broker is available. A separate
	// 15-second AwaitConnection timeout used to leave its retry goroutine running
	// while Bridge.Start created another manager with the same client ID.
	if err := cm.AwaitConnection(ctx); err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if cleanupErr := cm.Disconnect(cleanupCtx); cleanupErr != nil {
			return fmt.Errorf("mqtt initial connect: %w (manager cleanup: %v)", err, cleanupErr)
		}
		return fmt.Errorf("mqtt initial connect: %w", err)
	}

	c.mu.Lock()
	c.cm = cm
	c.mu.Unlock()
	return nil
}

// Subscribe registers a topic filter with a message handler.
// If already connected, sends SUBSCRIBE immediately. The handler is also
// stored so it's re-subscribed on reconnect.
func (c *PahoClient) Subscribe(ctx context.Context, topicFilter string, qos byte, handler func(Message)) error {
	c.mu.Lock()
	c.subs[topicFilter] = handler
	c.mu.Unlock()

	c.mu.RLock()
	cm := c.cm
	c.mu.RUnlock()
	if cm == nil {
		return nil // will subscribe on connect via OnConnectionUp
	}

	subCtx, subCancel := context.WithTimeout(ctx, 10*time.Second)
	defer subCancel()
	_, err := cm.Subscribe(subCtx, &paho.Subscribe{
		Subscriptions: []paho.SubscribeOptions{{
			Topic: topicFilter,
			QoS:   qos,
		}},
	})
	return err
}

// Publish sends a message to the broker. For QoS 1, autopaho handles
// PUBACK tracking internally and retries on reconnect.
func (c *PahoClient) Publish(ctx context.Context, topic string, qos byte, payload []byte) error {
	c.mu.RLock()
	cm := c.cm
	c.mu.RUnlock()
	if cm == nil {
		return fmt.Errorf("not connected")
	}

	pubCtx, pubCancel := context.WithTimeout(ctx, 5*time.Second)
	defer pubCancel()
	_, err := cm.Publish(pubCtx, &paho.Publish{
		Topic:   topic,
		QoS:     qos,
		Payload: payload,
	})
	return err
}

// Disconnect gracefully closes the connection.
func (c *PahoClient) Disconnect() error {
	c.mu.RLock()
	cm := c.cm
	c.mu.RUnlock()
	if cm == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return cm.Disconnect(ctx)
}

// --- TLS and production-mode checks ---

func (c *PahoClient) checkRequireTLS() error {
	envTLS := os.Getenv("DCLAW_REQUIRE_TLS")
	if c.requireTLS || envTLS == "true" || envTLS == "1" {
		if !c.isTLS() {
			return fmt.Errorf("TLS required but broker address %q does not use mqtts:// or ssl://", c.addr)
		}
	}
	return nil
}

func (c *PahoClient) checkPlaintextMQTT() error {
	if !isProductionMode() {
		return nil
	}
	if c.isTLS() {
		return nil
	}
	return fmt.Errorf("plaintext MQTT refused for broker %q — use mqtts://; isolated local development requires DCLAW_DEV_MODE=ON on an unmanaged host", c.addr)
}

func (c *PahoClient) isTLS() bool {
	return strings.HasPrefix(c.addr, "mqtts://") || strings.HasPrefix(c.addr, "ssl://")
}

// mqttTopicMatch performs MQTT topic matching with + and # wildcards.
func mqttTopicMatch(topic, filter string) bool {
	if topic == filter {
		return true
	}
	tParts := strings.Split(topic, "/")
	fParts := strings.Split(filter, "/")
	for i, fp := range fParts {
		if fp == "#" {
			return i == len(fParts)-1
		}
		if i >= len(tParts) || (fp != "+" && fp != tParts[i]) {
			return false
		}
	}
	return len(tParts) == len(fParts)
}
