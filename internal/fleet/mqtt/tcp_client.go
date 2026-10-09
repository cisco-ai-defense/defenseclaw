// Package mqtt — TCPClient implements the mqtt.Client interface using a raw TCP
// connection with minimal MQTT 3.1.1 packet encoding. This avoids pulling in
// external Go module dependencies (like Eclipse Paho) while remaining wire-
// compatible with any standards-compliant MQTT broker.
//
// The encoding mirrors the same minimal MQTT 3.1.1 framing used by the C-side
// edge-connector (edge-connector/src/comms/dclaw_mqtt.c).
package mqtt

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// MQTT 3.1.1 control packet types (first nibble of fixed header byte 0).
const (
	mqttPktConnect    byte = 0x10
	mqttPktConnAck    byte = 0x20
	mqttPktPublish    byte = 0x30
	mqttPktSubscribe  byte = 0x82 // with QoS-1 flag set
	mqttPktSubAck     byte = 0x90
	mqttPktPingReq    byte = 0xC0
	mqttPktPingResp   byte = 0xD0
	mqttPktDisconnect byte = 0xE0
)

// TCPClient is a minimal MQTT 3.1.1 client over a raw TCP socket.
// It supports CONNECT, PUBLISH, SUBSCRIBE, PING, and DISCONNECT — the subset
// needed by the fleet bridge and policy service.
type TCPClient struct {
	addr     string
	clientID string

	mu           sync.Mutex
	conn         net.Conn
	closed       bool
	packetID     uint16
	reconnecting bool // NEW-4: true while a reconnect attempt is in progress

	// NF-5 fix: Write mutex to prevent concurrent MQTT frame corruption.
	// readLoop is the sole reader, but multiple goroutines (Publish, pingLoop,
	// handleIncomingPublish PUBACK) can write concurrently.
	writeMu sync.Mutex

	// NEW-1 fix: Channel-based PUBACK delivery to eliminate the concurrent
	// read race between waitForPUBACK and readLoop. The readLoop is the
	// sole reader of the connection; when it sees a PUBACK packet it sends
	// the packet ID on this channel so Publish can receive it.
	pubackCh chan uint16

	// subscriptions maps topic filters to message handlers.
	subs   map[string]func(Message)
	subsMu sync.RWMutex

	// cancelReader stops the background read loop.
	cancelReader context.CancelFunc
	readerDone   chan struct{}
}

// errTLSNotSupported is returned when a TLS MQTT scheme is requested but not
// yet implemented.
var errTLSNotSupported = fmt.Errorf("TLS MQTT not yet supported. Use mqtt:// or host:port for plaintext")

// stripMQTTScheme removes URI scheme prefixes (tcp://, mqtt://) from a broker
// address, returning just the host:port portion that net.Dial expects.
// P0-5 fix: mqtts:// and ssl:// are NOT stripped — callers must check for TLS
// schemes explicitly and return an error instead of silently downgrading.
func stripMQTTScheme(addr string) string {
	for _, prefix := range []string{"tcp://", "mqtt://"} {
		if strings.HasPrefix(addr, prefix) {
			return strings.TrimPrefix(addr, prefix)
		}
	}
	return addr
}

// isTLSScheme returns true if the address uses a TLS MQTT scheme (mqtts:// or ssl://).
func isTLSScheme(addr string) bool {
	return strings.HasPrefix(addr, "mqtts://") || strings.HasPrefix(addr, "ssl://")
}

// NewTCPClient creates a new minimal MQTT client that connects to the given
// broker address (host:port). The clientID identifies this client to the broker.
// The address may include a URI scheme (tcp://, mqtt://) which is stripped
// automatically since net.Dial expects bare host:port.
func NewTCPClient(addr, clientID string) *TCPClient {
	return &TCPClient{
		addr:     stripMQTTScheme(addr),
		clientID: clientID,
		subs:     make(map[string]func(Message)),
		pubackCh: make(chan uint16, 4), // NEW-1 fix: buffered channel for PUBACK delivery
	}
}

// Connect establishes a TCP connection and sends the MQTT CONNECT packet.
func (c *TCPClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return nil // already connected
	}

	// P0-5 fix: Reject TLS schemes instead of silently downgrading to plaintext.
	if isTLSScheme(c.addr) {
		return fmt.Errorf("%w: broker address %q uses TLS scheme", errTLSNotSupported, c.addr)
	}

	// Strip URI scheme prefixes — net.Dial expects bare host:port.
	addr := stripMQTTScheme(c.addr)

	// Dial with context deadline if present.
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp dial %s: %w", c.addr, err)
	}

	// P0-4 fix: Read MQTT credentials from environment so authenticated
	// brokers (set up by `defenseclaw setup mqtt-broker`) accept connections.
	mqttUser := os.Getenv("DCLAW_MQTT_USER")
	mqttPass := os.Getenv("DCLAW_MQTT_PASS")

	// Build MQTT CONNECT packet (MQTT 3.1.1, clean session).
	pkt := buildConnectPacket(c.clientID, mqttUser, mqttPass)
	if err := writeAll(conn, pkt); err != nil {
		conn.Close()
		return fmt.Errorf("send CONNECT: %w", err)
	}

	// Read CONNACK (4 bytes: fixed header + remaining length + 2 byte variable header).
	connAck := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, connAck); err != nil {
		conn.Close()
		return fmt.Errorf("read CONNACK: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	if connAck[0]&0xF0 != mqttPktConnAck {
		conn.Close()
		return fmt.Errorf("expected CONNACK (0x20), got 0x%02X", connAck[0])
	}
	if connAck[3] != 0x00 {
		conn.Close()
		return fmt.Errorf("CONNACK return code: 0x%02X", connAck[3])
	}

	c.conn = conn
	c.closed = false

	// Start background reader for incoming messages (PUBLISH, PINGRESP, SUBACK).
	readerCtx, cancel := context.WithCancel(context.Background())
	c.cancelReader = cancel
	c.readerDone = make(chan struct{})
	go c.readLoop(readerCtx)

	// Start keepalive pinger (half the keepalive interval of 60s).
	go c.pingLoop(readerCtx, 25*time.Second)

	return nil
}

// Subscribe sends a SUBSCRIBE packet and registers the handler for matching messages.
func (c *TCPClient) Subscribe(ctx context.Context, topicFilter string, qos byte, handler func(Message)) error {
	c.mu.Lock()
	if c.conn == nil {
		c.mu.Unlock()
		return fmt.Errorf("not connected")
	}
	c.packetID++
	if c.packetID == 0 {
		c.packetID = 1 // M-5: MQTT spec requires packet ID 1-65535
	}
	pid := c.packetID
	c.mu.Unlock()

	c.subsMu.Lock()
	c.subs[topicFilter] = handler
	c.subsMu.Unlock()

	pkt := buildSubscribePacket(pid, topicFilter, qos)
	if err := c.lockedWriteAll(pkt); err != nil {
		return fmt.Errorf("send SUBSCRIBE: %w", err)
	}

	return nil
}

// Publish sends a PUBLISH packet (QoS 0 or 1). For QoS 1 it waits for PUBACK
// from the broker with a 5-second timeout to ensure delivery of critical messages
// like emergency commands and policy OTAs.
func (c *TCPClient) Publish(ctx context.Context, topic string, qos byte, payload []byte) error {
	c.mu.Lock()
	if c.conn == nil {
		reconnecting := c.reconnecting
		c.mu.Unlock()
		if reconnecting {
			return fmt.Errorf("publish to %s: client is reconnecting to broker", topic)
		}
		return fmt.Errorf("not connected")
	}
	c.packetID++
	if c.packetID == 0 {
		c.packetID = 1 // M-5: MQTT spec requires packet ID 1-65535
	}
	pid := c.packetID
	c.mu.Unlock()

	pkt := buildPublishPacket(topic, qos, pid, payload)
	if err := c.lockedWriteAll(pkt); err != nil {
		return fmt.Errorf("send PUBLISH to %s: %w", topic, err)
	}

	// H-13 fix: For QoS 1, wait for PUBACK from the broker to confirm delivery.
	// This is critical for emergency commands and policy OTAs where fire-and-forget
	// could silently lose messages.
	if qos >= 1 {
		if err := c.waitForPUBACK(nil, pid, 5*time.Second); err != nil {
			return fmt.Errorf("PUBACK for packet %d on %s: %w", pid, topic, err)
		}
	}

	return nil
}

// waitForPUBACK waits for the readLoop to deliver a PUBACK matching the given
// packet ID via the pubackCh channel. NEW-1 fix: This replaces the previous
// implementation that read directly from conn, which raced with readLoop.
// The readLoop is now the sole goroutine reading from the connection.
func (c *TCPClient) waitForPUBACK(_ net.Conn, packetID uint16, timeout time.Duration) error {
	select {
	case id := <-c.pubackCh:
		if id == packetID {
			return nil
		}
		// PUBACK for a different packet ID — log and treat as timeout
		// (the expected PUBACK may arrive later but we cannot block forever).
		log.Printf("[mqtt] received PUBACK for packet %d while waiting for %d", id, packetID)
		return fmt.Errorf("timeout waiting for PUBACK (packet_id=%d, got %d)", packetID, id)
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for PUBACK (packet_id=%d)", packetID)
	}
}

// Disconnect sends an MQTT DISCONNECT packet and closes the TCP connection.
func (c *TCPClient) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil
	}
	c.closed = true

	// Best-effort DISCONNECT
	_ = writeAll(c.conn, []byte{mqttPktDisconnect, 0x00})

	if c.cancelReader != nil {
		c.cancelReader()
	}

	err := c.conn.Close()
	c.conn = nil

	// Wait for reader to finish (with timeout)
	if c.readerDone != nil {
		select {
		case <-c.readerDone:
		case <-time.After(2 * time.Second):
		}
	}

	return err
}

// readLoop reads incoming MQTT packets from the broker and dispatches PUBLISH
// messages to registered subscription handlers.
func (c *TCPClient) readLoop(ctx context.Context) {
	defer close(c.readerDone)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		c.mu.Lock()
		conn := c.conn
		closed := c.closed
		c.mu.Unlock()

		if conn == nil || closed {
			return
		}

		// Set a read deadline so we don't block forever.
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		// Read fixed header byte.
		hdr := make([]byte, 1)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			if ctx.Err() != nil {
				return
			}
			// Timeout is expected during idle — keep looping.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Printf("mqtt: readLoop error: %v — closing connection", err)
			c.mu.Lock()
			wasClosed := c.closed
			if c.conn != nil && !c.closed {
				c.conn.Close()
				c.conn = nil
			}
			c.mu.Unlock()
			// NEW-4: If the connection was not intentionally closed,
			// start a reconnect goroutine with exponential backoff.
			if !wasClosed {
				go c.reconnectLoop(ctx)
			}
			return
		}

		// Decode remaining length (variable-length encoding, 1-4 bytes).
		remainLen, err := readRemainingLength(conn)
		if err != nil {
			return
		}

		// Read the remaining bytes.
		body := make([]byte, remainLen)
		if remainLen > 0 {
			if _, err := io.ReadFull(conn, body); err != nil {
				return
			}
		}

		pktType := hdr[0] & 0xF0
		switch pktType {
		case mqttPktPublish & 0xF0:
			c.handleIncomingPublish(hdr[0], body)
		case 0x40: // PUBACK
			// NEW-1 fix: Deliver PUBACK to the waiting Publish goroutine via
			// channel instead of having two goroutines read from the connection.
			if len(body) >= 2 {
				ackID := binary.BigEndian.Uint16(body[0:2])
				select {
				case c.pubackCh <- ackID:
				default:
					log.Printf("[mqtt] pubackCh full, dropping PUBACK for packet %d", ackID)
				}
			}
		case mqttPktPingResp:
			// keepalive response — nothing to do
		case mqttPktSubAck & 0xF0:
			// subscription acknowledged — nothing to do
		}
	}
}

// handleIncomingPublish decodes an incoming PUBLISH packet and dispatches it
// to the matching subscription handler.
func (c *TCPClient) handleIncomingPublish(flags byte, body []byte) {
	if len(body) < 2 {
		return
	}

	// Topic length (2 bytes big-endian).
	topicLen := int(binary.BigEndian.Uint16(body[0:2]))
	if 2+topicLen > len(body) {
		return
	}
	topic := string(body[2 : 2+topicLen])
	pos := 2 + topicLen

	// QoS is in bits 1-2 of the fixed header flags.
	qos := (flags >> 1) & 0x03
	var packetID uint16
	if qos > 0 {
		// Bounds check: need 2 bytes for packet ID (M-6: panic on short QoS>0).
		if pos+2 > len(body) {
			return
		}
		packetID = binary.BigEndian.Uint16(body[pos : pos+2])
		pos += 2
	}

	// H-1: Send PUBACK for incoming QoS 1 messages.
	if qos >= 1 {
		puback := []byte{0x40, 0x02, byte(packetID >> 8), byte(packetID)}
		if err := c.lockedWriteAll(puback); err != nil {
			log.Printf("[mqtt] failed to send PUBACK for packet %d: %v", packetID, err)
		}
	}

	var payload []byte
	if pos < len(body) {
		payload = body[pos:]
	}

	msg := Message{
		Topic:   topic,
		Payload: payload,
		QoS:     qos,
	}

	// Match against subscriptions (simple wildcard matching).
	c.subsMu.RLock()
	for filter, handler := range c.subs {
		if mqttTopicMatch(topic, filter) {
			h := handler
			c.subsMu.RUnlock()
			h(msg)
			return
		}
	}
	c.subsMu.RUnlock()
}

// pingLoop sends PINGREQ packets at the given interval to keep the connection alive.
func (c *TCPClient) pingLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			conn := c.conn
			closed := c.closed
			c.mu.Unlock()
			if conn == nil || closed {
				return
			}
			_ = c.lockedWriteAll([]byte{mqttPktPingReq, 0x00})
		}
	}
}

// reconnectLoop attempts to reconnect to the broker with exponential backoff.
// NEW-4 fix: When readLoop gets EOF/error (broker restart), don't just log and
// close -- attempt to reconnect. Backoff: 1s, 2s, 4s, 8s, max 30s.
// After reconnect, re-subscribes to all topics.
func (c *TCPClient) reconnectLoop(ctx context.Context) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.reconnecting = true
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.reconnecting = false
		c.mu.Unlock()
	}()

	backoff := 1 * time.Second
	const maxBackoff = 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			log.Printf("mqtt: reconnect cancelled")
			return
		default:
		}

		log.Printf("mqtt: attempting reconnect to %s in %v", c.addr, backoff)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()

		// Attempt to dial and send CONNECT
		dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
		err := c.doConnect(dialCtx)
		dialCancel()

		if err != nil {
			log.Printf("mqtt: reconnect failed: %v", err)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		log.Printf("mqtt: reconnected to %s", c.addr)

		// Re-subscribe to all previously registered topics
		c.subsMu.RLock()
		subs := make(map[string]func(Message), len(c.subs))
		for topic, handler := range c.subs {
			subs[topic] = handler
		}
		c.subsMu.RUnlock()

		subCtx, subCancel := context.WithTimeout(ctx, 10*time.Second)
		for topic, handler := range subs {
			if err := c.Subscribe(subCtx, topic, 1, handler); err != nil {
				log.Printf("mqtt: re-subscribe to %s failed: %v", topic, err)
			}
		}
		subCancel()

		return
	}
}

// doConnect is the internal connection logic shared between Connect() and
// reconnectLoop(). It establishes a TCP connection, sends CONNECT, reads
// CONNACK, and starts the reader/ping goroutines.
func (c *TCPClient) doConnect(ctx context.Context) error {
	c.mu.Lock()
	if c.conn != nil {
		c.mu.Unlock()
		return nil // already connected
	}

	if isTLSScheme(c.addr) {
		c.mu.Unlock()
		return fmt.Errorf("%w: broker address %q uses TLS scheme", errTLSNotSupported, c.addr)
	}

	addr := stripMQTTScheme(c.addr)
	c.mu.Unlock()

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp dial %s: %w", c.addr, err)
	}

	mqttUser := os.Getenv("DCLAW_MQTT_USER")
	mqttPass := os.Getenv("DCLAW_MQTT_PASS")

	pkt := buildConnectPacket(c.clientID, mqttUser, mqttPass)
	if err := writeAll(conn, pkt); err != nil {
		conn.Close()
		return fmt.Errorf("send CONNECT: %w", err)
	}

	connAck := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, connAck); err != nil {
		conn.Close()
		return fmt.Errorf("read CONNACK: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	if connAck[0]&0xF0 != mqttPktConnAck {
		conn.Close()
		return fmt.Errorf("expected CONNACK (0x20), got 0x%02X", connAck[0])
	}
	if connAck[3] != 0x00 {
		conn.Close()
		return fmt.Errorf("CONNACK return code: 0x%02X", connAck[3])
	}

	c.mu.Lock()
	c.conn = conn
	c.closed = false

	readerCtx, cancel := context.WithCancel(context.Background())
	c.cancelReader = cancel
	c.readerDone = make(chan struct{})
	go c.readLoop(readerCtx)
	go c.pingLoop(readerCtx, 25*time.Second)
	c.mu.Unlock()

	return nil
}

// --- MQTT 3.1.1 packet builders ---

// buildConnectPacket constructs an MQTT CONNECT packet.
// Protocol: MQTT 3.1.1, Clean Session, KeepAlive 60s.
// If username and password are non-empty, they are included in the packet
// with the appropriate connect flags (bits 7 and 6).
func buildConnectPacket(clientID, username, password string) []byte {
	// Connect flags: clean session (bit 1) = 0x02
	connectFlags := byte(0x02)
	if username != "" {
		connectFlags |= 0x80 // bit 7: username flag
	}
	if password != "" {
		connectFlags |= 0x40 // bit 6: password flag
	}

	// Variable header: protocol name + level + connect flags + keepalive
	varHeader := []byte{
		0x00, 0x04, // protocol name length
		'M', 'Q', 'T', 'T', // protocol name
		0x04,         // protocol level (4 = MQTT 3.1.1)
		connectFlags, // connect flags
		0x00, 0x3C,   // keepalive: 60 seconds
	}

	// Payload: client ID (length-prefixed UTF-8 string)
	cidBytes := []byte(clientID)
	payload := make([]byte, 2+len(cidBytes))
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(cidBytes)))
	copy(payload[2:], cidBytes)

	// P0-4 fix: Append username and password fields if credentials are set.
	// MQTT 3.1.1 spec section 3.1.3: payload order is ClientID, Username, Password.
	if username != "" {
		uBytes := []byte(username)
		uField := make([]byte, 2+len(uBytes))
		binary.BigEndian.PutUint16(uField[0:2], uint16(len(uBytes)))
		copy(uField[2:], uBytes)
		payload = append(payload, uField...)
	}
	if password != "" {
		pBytes := []byte(password)
		pField := make([]byte, 2+len(pBytes))
		binary.BigEndian.PutUint16(pField[0:2], uint16(len(pBytes)))
		copy(pField[2:], pBytes)
		payload = append(payload, pField...)
	}

	remainLen := len(varHeader) + len(payload)
	fixed := encodeFixedHeader(mqttPktConnect, remainLen)

	pkt := make([]byte, 0, len(fixed)+remainLen)
	pkt = append(pkt, fixed...)
	pkt = append(pkt, varHeader...)
	pkt = append(pkt, payload...)
	return pkt
}

// buildSubscribePacket constructs an MQTT SUBSCRIBE packet.
func buildSubscribePacket(packetID uint16, topicFilter string, qos byte) []byte {
	// Variable header: packet ID (2 bytes)
	varHeader := make([]byte, 2)
	binary.BigEndian.PutUint16(varHeader, packetID)

	// Payload: topic filter (length-prefixed) + requested QoS
	tfBytes := []byte(topicFilter)
	payload := make([]byte, 2+len(tfBytes)+1)
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(tfBytes)))
	copy(payload[2:], tfBytes)
	payload[2+len(tfBytes)] = qos

	remainLen := len(varHeader) + len(payload)
	fixed := encodeFixedHeader(mqttPktSubscribe, remainLen)

	pkt := make([]byte, 0, len(fixed)+remainLen)
	pkt = append(pkt, fixed...)
	pkt = append(pkt, varHeader...)
	pkt = append(pkt, payload...)
	return pkt
}

// buildPublishPacket constructs an MQTT PUBLISH packet.
func buildPublishPacket(topic string, qos byte, packetID uint16, payload []byte) []byte {
	// Variable header: topic (length-prefixed) + optional packet ID
	topicBytes := []byte(topic)
	varHeaderLen := 2 + len(topicBytes)
	if qos > 0 {
		varHeaderLen += 2 // packet ID
	}

	varHeader := make([]byte, varHeaderLen)
	binary.BigEndian.PutUint16(varHeader[0:2], uint16(len(topicBytes)))
	copy(varHeader[2:], topicBytes)
	if qos > 0 {
		binary.BigEndian.PutUint16(varHeader[2+len(topicBytes):], packetID)
	}

	// Fixed header: PUBLISH with QoS bits
	fixedByte := mqttPktPublish | (qos << 1)
	remainLen := len(varHeader) + len(payload)
	fixed := encodeFixedHeader(fixedByte, remainLen)

	pkt := make([]byte, 0, len(fixed)+remainLen)
	pkt = append(pkt, fixed...)
	pkt = append(pkt, varHeader...)
	pkt = append(pkt, payload...)
	return pkt
}

// encodeFixedHeader encodes the MQTT fixed header: first byte + remaining length.
func encodeFixedHeader(pktType byte, remainLen int) []byte {
	buf := []byte{pktType}
	for {
		encodedByte := byte(remainLen % 128)
		remainLen /= 128
		if remainLen > 0 {
			encodedByte |= 0x80
		}
		buf = append(buf, encodedByte)
		if remainLen == 0 {
			break
		}
	}
	return buf
}

// readRemainingLength decodes the MQTT variable-length remaining-length field.
func readRemainingLength(r io.Reader) (int, error) {
	multiplier := 1
	value := 0
	buf := make([]byte, 1)
	for i := 0; i < 4; i++ {
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, fmt.Errorf("read remaining length: %w", err)
		}
		value += int(buf[0]&0x7F) * multiplier
		if buf[0]&0x80 == 0 {
			// L-readRemainingLength: enforce upper bound to prevent memory exhaustion.
			if value > 1<<20 {
				return 0, fmt.Errorf("packet too large: %d", value)
			}
			return value, nil
		}
		multiplier *= 128
	}
	return 0, fmt.Errorf("malformed remaining length")
}

// writeAll writes all bytes to the connection.
func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// lockedWriteAll wraps writeAll with the client's write mutex to prevent
// concurrent MQTT frame corruption (NF-5 fix).
func (c *TCPClient) lockedWriteAll(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("not connected")
	}
	return writeAll(conn, data)
}

// mqttTopicMatch performs MQTT-style topic matching with + and # wildcards.
func mqttTopicMatch(topic, filter string) bool {
	if topic == filter {
		return true
	}

	tParts := mqttSplitTopic(topic)
	fParts := mqttSplitTopic(filter)

	for i, fp := range fParts {
		if fp == "#" {
			return true // # matches any remaining levels
		}
		if i >= len(tParts) {
			return false
		}
		if fp != "+" && fp != tParts[i] {
			return false
		}
	}
	return len(tParts) == len(fParts)
}

// mqttSplitTopic splits an MQTT topic string by '/'.
func mqttSplitTopic(t string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(t); i++ {
		if t[i] == '/' {
			parts = append(parts, t[start:i])
			start = i + 1
		}
	}
	parts = append(parts, t[start:])
	return parts
}
