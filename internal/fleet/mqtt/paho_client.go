// Package mqtt — PahoClient implements the mqtt.Client interface using
// Eclipse Paho Go v2 (github.com/eclipse/paho.golang). This replaces
// the hand-rolled TCPClient with a battle-tested MQTT 5 / 3.1.1 library
// that handles packet serialization, QoS 1 inflight tracking, keepalive,
// and auto-reconnect internally.
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

	// connected is set to true after the first successful CONNACK.
	// autopaho reconnects internally, so this stays true once set.
	connected bool

	// Config-injected credentials (set via SetCredentials before Connect).
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
func NewPahoClient(addr, clientID string) *PahoClient {
	return &PahoClient{
		addr: addr,
		id:   clientID,
		subs: make(map[string]func(Message)),
	}
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
	// Production TLS enforcement — same policy as TCPClient
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

	// Build TLS config (reuses the same env vars as the old TCPClient)
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
		TlsCfg:                       tlsCfg,
		KeepAlive:                    60,
		CleanStartOnInitialConnection: true,
		SessionExpiryInterval:         0,
		ConnectRetryDelay:             time.Second,
		OnConnectionUp: func(cm *autopaho.ConnectionManager, connack *paho.Connack) {
			log.Printf("[mqtt-paho] connected to %s (session_present=%v)", brokerURL.String(), connack.SessionPresent)
			c.mu.Lock()
			c.connected = true
			c.mu.Unlock()

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

	// Wait for the initial connection (with timeout)
	connectCtx, connectCancel := context.WithTimeout(ctx, 15*time.Second)
	defer connectCancel()
	if err := cm.AwaitConnection(connectCtx); err != nil {
		return fmt.Errorf("mqtt initial connect timeout: %w", err)
	}

	c.cm = cm
	return nil
}

// Subscribe registers a topic filter with a message handler.
// If already connected, sends SUBSCRIBE immediately. The handler is also
// stored so it's re-subscribed on reconnect.
func (c *PahoClient) Subscribe(ctx context.Context, topicFilter string, qos byte, handler func(Message)) error {
	c.mu.Lock()
	c.subs[topicFilter] = handler
	c.mu.Unlock()

	if c.cm == nil {
		return nil // will subscribe on connect via OnConnectionUp
	}

	subCtx, subCancel := context.WithTimeout(ctx, 10*time.Second)
	defer subCancel()
	_, err := c.cm.Subscribe(subCtx, &paho.Subscribe{
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
	if c.cm == nil {
		return fmt.Errorf("not connected")
	}

	pubCtx, pubCancel := context.WithTimeout(ctx, 5*time.Second)
	defer pubCancel()
	_, err := c.cm.Publish(pubCtx, &paho.Publish{
		Topic:   topic,
		QoS:     qos,
		Payload: payload,
	})
	return err
}

// Disconnect gracefully closes the connection.
func (c *PahoClient) Disconnect() error {
	if c.cm == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.cm.Disconnect(ctx)
}

// --- TLS and production-mode checks (mirroring tcp_client.go policy) ---

func (c *PahoClient) checkRequireTLS() error {
	if requireTLS := os.Getenv("DCLAW_REQUIRE_TLS"); requireTLS == "true" || requireTLS == "1" {
		if !c.isTLS() {
			return fmt.Errorf("DCLAW_REQUIRE_TLS is set but broker address %q does not use mqtts:// or ssl://", c.addr)
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
	if allow := os.Getenv("DCLAW_ALLOW_PLAINTEXT_MQTT"); allow == "1" {
		log.Printf("[mqtt-paho] WARNING: Using plaintext MQTT in production (DCLAW_ALLOW_PLAINTEXT_MQTT=1 override active)")
		return nil
	}
	return fmt.Errorf("plaintext MQTT refused in production for broker %q — use mqtts:// or set DCLAW_ALLOW_PLAINTEXT_MQTT=1", c.addr)
}

func (c *PahoClient) isTLS() bool {
	return strings.HasPrefix(c.addr, "mqtts://") || strings.HasPrefix(c.addr, "ssl://")
}
