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
	"net"
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

	mu       sync.Mutex
	conn     net.Conn
	closed   bool
	packetID uint16

	// subscriptions maps topic filters to message handlers.
	subs   map[string]func(Message)
	subsMu sync.RWMutex

	// cancelReader stops the background read loop.
	cancelReader context.CancelFunc
	readerDone   chan struct{}
}

// NewTCPClient creates a new minimal MQTT client that connects to the given
// broker address (host:port). The clientID identifies this client to the broker.
func NewTCPClient(addr, clientID string) *TCPClient {
	return &TCPClient{
		addr:     addr,
		clientID: clientID,
		subs:     make(map[string]func(Message)),
	}
}

// Connect establishes a TCP connection and sends the MQTT CONNECT packet.
func (c *TCPClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return nil // already connected
	}

	// Dial with context deadline if present.
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return fmt.Errorf("tcp dial %s: %w", c.addr, err)
	}

	// Build MQTT CONNECT packet (MQTT 3.1.1, clean session).
	pkt := buildConnectPacket(c.clientID)
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
	pid := c.packetID
	conn := c.conn
	c.mu.Unlock()

	c.subsMu.Lock()
	c.subs[topicFilter] = handler
	c.subsMu.Unlock()

	pkt := buildSubscribePacket(pid, topicFilter, qos)
	if err := writeAll(conn, pkt); err != nil {
		return fmt.Errorf("send SUBSCRIBE: %w", err)
	}

	return nil
}

// Publish sends a PUBLISH packet (QoS 0 or 1). For QoS 1 it assigns a packet
// ID but does not currently wait for PUBACK (fire-and-forget).
func (c *TCPClient) Publish(ctx context.Context, topic string, qos byte, payload []byte) error {
	c.mu.Lock()
	if c.conn == nil {
		c.mu.Unlock()
		return fmt.Errorf("not connected")
	}
	c.packetID++
	pid := c.packetID
	conn := c.conn
	c.mu.Unlock()

	pkt := buildPublishPacket(topic, qos, pid, payload)
	if err := writeAll(conn, pkt); err != nil {
		return fmt.Errorf("send PUBLISH to %s: %w", topic, err)
	}

	return nil
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
	if qos > 0 {
		// Skip packet ID (2 bytes).
		pos += 2
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
			_ = writeAll(conn, []byte{mqttPktPingReq, 0x00})
		}
	}
}

// --- MQTT 3.1.1 packet builders ---

// buildConnectPacket constructs an MQTT CONNECT packet.
// Protocol: MQTT 3.1.1, Clean Session, KeepAlive 60s.
func buildConnectPacket(clientID string) []byte {
	// Variable header: protocol name + level + connect flags + keepalive
	varHeader := []byte{
		0x00, 0x04, // protocol name length
		'M', 'Q', 'T', 'T', // protocol name
		0x04,       // protocol level (4 = MQTT 3.1.1)
		0x02,       // connect flags: clean session
		0x00, 0x3C, // keepalive: 60 seconds
	}

	// Payload: client ID (length-prefixed UTF-8 string)
	cidBytes := []byte(clientID)
	payload := make([]byte, 2+len(cidBytes))
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(cidBytes)))
	copy(payload[2:], cidBytes)

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
