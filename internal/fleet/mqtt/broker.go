// Package mqtt provides the MQTT transport layer for the DefenseClaw fleet manager.
// It subscribes to topics published by Edge Connector devices (heartbeats, verdict
// requests) and routes decoded messages to the appropriate fleet manager handlers.
package mqtt

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// Message represents an MQTT message received from a broker.
type Message struct {
	Topic   string
	Payload []byte
	QoS     byte
}

// Client is the interface for an MQTT client. Implementations may use
// Eclipse Paho, a test double, or any other MQTT v5 library.
type Client interface {
	// Connect establishes a connection to the MQTT broker.
	Connect(ctx context.Context) error

	// Subscribe registers a topic filter with a message handler.
	Subscribe(ctx context.Context, topicFilter string, qos byte, handler func(Message)) error

	// Publish sends a message to the broker.
	Publish(ctx context.Context, topic string, qos byte, payload []byte) error

	// Disconnect gracefully closes the connection.
	Disconnect() error
}

// TopicParts holds the parsed segments from a DefenseClaw MQTT topic.
// Topics follow the pattern: defenseclaw/{tenant_id}/{fleet_id}/{device_id}/{suffix}
type TopicParts struct {
	TenantID uint16
	FleetID  uint16
	DeviceID uint32
	Suffix   string // e.g. "heartbeat", "verdict/req"
}

// Heartbeat topics and verdict request topics published by edge-connector devices.
const (
	// TopicHeartbeat matches: defenseclaw/+/+/+/heartbeat
	TopicHeartbeat = "defenseclaw/+/+/+/heartbeat"

	// TopicVerdictReq matches: defenseclaw/+/+/+/verdict/req
	TopicVerdictReq = "defenseclaw/+/+/+/verdict/req"

	// TopicRegister matches: defenseclaw/+/+/+/register
	TopicRegister = "defenseclaw/+/+/+/register"
)

// ParseTopic extracts tenant_id, fleet_id, device_id and suffix from an
// MQTT topic string. Returns an error if the topic doesn't match the
// expected defenseclaw/{tenant}/{fleet}/{device}/{suffix...} pattern.
func ParseTopic(topic string) (*TopicParts, error) {
	parts := strings.SplitN(topic, "/", 5)
	if len(parts) < 5 || parts[0] != "defenseclaw" {
		return nil, fmt.Errorf("invalid topic format: %s", topic)
	}

	tenantID, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id in topic %q: %w", topic, err)
	}

	fleetID, err := strconv.ParseUint(parts[2], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid fleet_id in topic %q: %w", topic, err)
	}

	deviceID, err := strconv.ParseUint(parts[3], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid device_id in topic %q: %w", topic, err)
	}

	return &TopicParts{
		TenantID: uint16(tenantID),
		FleetID:  uint16(fleetID),
		DeviceID: uint32(deviceID),
		Suffix:   parts[4],
	}, nil
}

// DecodeHeartbeat parses the 32-byte binary heartbeat wire format produced
// by dclaw_cbor_encode_heartbeat() in the edge-connector C code.
//
// Wire layout (all big-endian):
//
//	[0:4]   device_id       uint32
//	[4:8]   uptime_sec      uint32
//	[8:10]  policy_version  uint16
//	[10:12] fw_version      uint16
//	[12:14] denied_count    uint16
//	[14:16] allowed_count   uint16
//	[16:18] warned_count    uint16
//	[18:20] escalated_count uint16
//	[20]    cache_hit_pct   uint8
//	[21]    session_count   uint8
//	[22:30] audit_head_hmac uint64
//	[30]    flags           uint8
//	[31]    capabilities    uint8  (device capability bitmap)
type HeartbeatWire struct {
	DeviceID       uint32
	UptimeSec      uint32
	PolicyVersion  uint16
	FWVersion      uint16
	DeniedCount    uint16
	AllowedCount   uint16
	WarnedCount    uint16
	EscalatedCount uint16
	CacheHitPct    uint8
	SessionCount   uint8
	AuditHeadHMAC  uint64
	Flags          uint8
	Capabilities   uint8
}

// DecodeHeartbeat decodes a 32-byte heartbeat payload from an edge device.
func DecodeHeartbeat(data []byte) (*HeartbeatWire, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("heartbeat must be exactly 32 bytes, got %d", len(data))
	}

	return &HeartbeatWire{
		DeviceID:       binary.BigEndian.Uint32(data[0:4]),
		UptimeSec:      binary.BigEndian.Uint32(data[4:8]),
		PolicyVersion:  binary.BigEndian.Uint16(data[8:10]),
		FWVersion:      binary.BigEndian.Uint16(data[10:12]),
		DeniedCount:    binary.BigEndian.Uint16(data[12:14]),
		AllowedCount:   binary.BigEndian.Uint16(data[14:16]),
		WarnedCount:    binary.BigEndian.Uint16(data[16:18]),
		EscalatedCount: binary.BigEndian.Uint16(data[18:20]),
		CacheHitPct:    data[20],
		SessionCount:   data[21],
		AuditHeadHMAC:  binary.BigEndian.Uint64(data[22:30]),
		Flags:          data[30],
		Capabilities:   data[31],
	}, nil
}

// VerdictRequest represents a decoded verdict request from an edge device.
// The C-side encodes these as a flat CBOR sequence (not a map).
//
// Wire layout (CBOR sequential):
//
//	request_id  : uint16  (CBOR uint, major type 0)
//	sha256      : [32]byte (CBOR byte string, major type 2)
//	tool_name   : string  (CBOR text string, major type 3)
//	cap_flags   : uint8   (CBOR uint)
//	session_risk: uint8   (CBOR uint)
//	session_caps: uint8   (CBOR uint)
//	destination : string  (CBOR text string)
//	direction   : uint8   (CBOR uint)
//	content_scope: uint8  (CBOR uint)
//	content     : string  (CBOR text string)
//	findings    : uint8   (CBOR uint)
type VerdictRequest struct {
	RequestID    uint16
	ToolHash     [32]byte
	ToolName     string
	CapFlags     uint8
	SessionRisk  uint8
	SessionCaps  uint8
	Destination  string
	Direction    uint8
	ContentScope uint8
	Content      string
	Findings     uint8
}

// VerdictResponse is the 16-byte binary response sent back to the device.
// Wire layout matches proposal section 7.2:
//
//	[0:2]   request_id  uint16
//	[2]     action      uint8
//	[3]     severity    uint8
//	[4:6]   ttl         uint16
//	[6]     reason      uint8
//	[7]     flags       uint8
//	[8:12]  server_ts   uint32
//	[12:16] hmac_tag    [4]byte
type VerdictResponse struct {
	RequestID uint16
	Action    uint8
	Severity  uint8
	TTL       uint16
	Reason    uint8
	Flags     uint8
	ServerTS  uint32
	HMACTag   [4]byte
}

// EncodeVerdictResponse serializes a VerdictResponse into its 16-byte wire format.
func EncodeVerdictResponse(resp *VerdictResponse) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint16(buf[0:2], resp.RequestID)
	buf[2] = resp.Action
	buf[3] = resp.Severity
	binary.BigEndian.PutUint16(buf[4:6], resp.TTL)
	buf[6] = resp.Reason
	buf[7] = resp.Flags
	binary.BigEndian.PutUint32(buf[8:12], resp.ServerTS)
	copy(buf[12:16], resp.HMACTag[:])
	return buf
}

// DecodeVerdictRequest decodes a CBOR-encoded verdict request.
// The edge-connector uses flat sequential CBOR items (not maps).
func DecodeVerdictRequest(data []byte) (*VerdictRequest, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("verdict request too short: %d bytes", len(data))
	}

	vr := &VerdictRequest{}
	pos := 0
	remaining := data

	// 1. request_id (CBOR uint)
	val, n, err := decodeCBORUint(remaining)
	if err != nil {
		return nil, fmt.Errorf("decoding request_id: %w", err)
	}
	vr.RequestID = uint16(val)
	pos += n
	remaining = data[pos:]

	// 2. sha256 (CBOR byte string, 32 bytes)
	bs, n, err := decodeCBORBytes(remaining)
	if err != nil {
		return nil, fmt.Errorf("decoding tool_hash: %w", err)
	}
	if len(bs) != 32 {
		return nil, fmt.Errorf("tool_hash must be 32 bytes, got %d", len(bs))
	}
	copy(vr.ToolHash[:], bs)
	pos += n
	remaining = data[pos:]

	// 3. tool_name (CBOR text string)
	vr.ToolName, n, err = decodeCBORText(remaining)
	if err != nil {
		return nil, fmt.Errorf("decoding tool_name: %w", err)
	}
	pos += n
	remaining = data[pos:]

	// 4. cap_flags (CBOR uint)
	val, n, err = decodeCBORUint(remaining)
	if err != nil {
		return nil, fmt.Errorf("decoding cap_flags: %w", err)
	}
	vr.CapFlags = uint8(val)
	pos += n
	remaining = data[pos:]

	// 5. session_risk (CBOR uint)
	val, n, err = decodeCBORUint(remaining)
	if err != nil {
		return nil, fmt.Errorf("decoding session_risk: %w", err)
	}
	vr.SessionRisk = uint8(val)
	pos += n
	remaining = data[pos:]

	// 6. session_caps (CBOR uint)
	val, n, err = decodeCBORUint(remaining)
	if err != nil {
		return nil, fmt.Errorf("decoding session_caps: %w", err)
	}
	vr.SessionCaps = uint8(val)
	pos += n
	remaining = data[pos:]

	// 7. destination (CBOR text string)
	vr.Destination, n, err = decodeCBORText(remaining)
	if err != nil {
		return nil, fmt.Errorf("decoding destination: %w", err)
	}
	pos += n
	remaining = data[pos:]

	// 8. direction (CBOR uint)
	val, n, err = decodeCBORUint(remaining)
	if err != nil {
		return nil, fmt.Errorf("decoding direction: %w", err)
	}
	vr.Direction = uint8(val)
	pos += n
	remaining = data[pos:]

	// 9. content_scope (CBOR uint)
	val, n, err = decodeCBORUint(remaining)
	if err != nil {
		return nil, fmt.Errorf("decoding content_scope: %w", err)
	}
	vr.ContentScope = uint8(val)
	pos += n
	remaining = data[pos:]

	// 10. content (CBOR text string)
	vr.Content, n, err = decodeCBORText(remaining)
	if err != nil {
		return nil, fmt.Errorf("decoding content: %w", err)
	}
	pos += n
	remaining = data[pos:]

	// 11. findings (CBOR uint)
	if len(remaining) > 0 {
		val, _, err = decodeCBORUint(remaining)
		if err != nil {
			return nil, fmt.Errorf("decoding findings: %w", err)
		}
		vr.Findings = uint8(val)
	}

	return vr, nil
}

// --- Minimal CBOR decoder for the flat sequential format used by edge-connector ---

// decodeCBORUint decodes a CBOR unsigned integer (major type 0).
// Returns the value and number of bytes consumed.
func decodeCBORUint(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("empty data for CBOR uint")
	}

	major := data[0] >> 5
	if major != 0 {
		return 0, 0, fmt.Errorf("expected CBOR major type 0 (uint), got %d", major)
	}

	additional := data[0] & 0x1F
	return decodeCBORAdditional(data, additional)
}

// decodeCBORBytes decodes a CBOR byte string (major type 2).
func decodeCBORBytes(data []byte) ([]byte, int, error) {
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("empty data for CBOR bytes")
	}

	major := data[0] >> 5
	if major != 2 {
		return nil, 0, fmt.Errorf("expected CBOR major type 2 (bytes), got %d", major)
	}

	additional := data[0] & 0x1F
	length, hdrLen, err := decodeCBORAdditional(data, additional)
	if err != nil {
		return nil, 0, err
	}

	end := hdrLen + int(length)
	if end > len(data) {
		return nil, 0, fmt.Errorf("CBOR byte string overflows buffer: need %d, have %d", end, len(data))
	}

	return data[hdrLen:end], end, nil
}

// decodeCBORText decodes a CBOR text string (major type 3).
func decodeCBORText(data []byte) (string, int, error) {
	if len(data) == 0 {
		return "", 0, fmt.Errorf("empty data for CBOR text")
	}

	major := data[0] >> 5
	if major != 3 {
		return "", 0, fmt.Errorf("expected CBOR major type 3 (text), got %d", major)
	}

	additional := data[0] & 0x1F
	length, hdrLen, err := decodeCBORAdditional(data, additional)
	if err != nil {
		return "", 0, err
	}

	end := hdrLen + int(length)
	if end > len(data) {
		return "", 0, fmt.Errorf("CBOR text string overflows buffer: need %d, have %d", end, len(data))
	}

	return string(data[hdrLen:end]), end, nil
}

// decodeCBORAdditional reads the additional info field of a CBOR header.
func decodeCBORAdditional(data []byte, additional uint8) (uint64, int, error) {
	if additional < 24 {
		return uint64(additional), 1, nil
	}
	switch additional {
	case 24:
		if len(data) < 2 {
			return 0, 0, fmt.Errorf("CBOR: need 2 bytes for additional=24, have %d", len(data))
		}
		return uint64(data[1]), 2, nil
	case 25:
		if len(data) < 3 {
			return 0, 0, fmt.Errorf("CBOR: need 3 bytes for additional=25, have %d", len(data))
		}
		return uint64(binary.BigEndian.Uint16(data[1:3])), 3, nil
	case 26:
		if len(data) < 5 {
			return 0, 0, fmt.Errorf("CBOR: need 5 bytes for additional=26, have %d", len(data))
		}
		return uint64(binary.BigEndian.Uint32(data[1:5])), 5, nil
	case 27:
		if len(data) < 9 {
			return 0, 0, fmt.Errorf("CBOR: need 9 bytes for additional=27, have %d", len(data))
		}
		return binary.BigEndian.Uint64(data[1:9]), 9, nil
	default:
		return 0, 0, fmt.Errorf("CBOR: unsupported additional value %d", additional)
	}
}

// encodeCBORUint encodes a CBOR unsigned integer with the given major type.
func encodeCBORUint(major uint8, val uint64) []byte {
	mt := major << 5
	if val < 24 {
		return []byte{mt | uint8(val)}
	} else if val <= 0xFF {
		return []byte{mt | 24, uint8(val)}
	} else if val <= 0xFFFF {
		buf := make([]byte, 3)
		buf[0] = mt | 25
		binary.BigEndian.PutUint16(buf[1:3], uint16(val))
		return buf
	} else if val <= 0xFFFFFFFF {
		buf := make([]byte, 5)
		buf[0] = mt | 26
		binary.BigEndian.PutUint32(buf[1:5], uint32(val))
		return buf
	}
	buf := make([]byte, 9)
	buf[0] = mt | 27
	binary.BigEndian.PutUint64(buf[1:9], val)
	return buf
}

// encodeCBORBytes encodes a CBOR byte string (major type 2).
func encodeCBORBytes(data []byte) []byte {
	hdr := encodeCBORUint(2, uint64(len(data)))
	return append(hdr, data...)
}

// encodeCBORText encodes a CBOR text string (major type 3).
func encodeCBORText(s string) []byte {
	hdr := encodeCBORUint(3, uint64(len(s)))
	return append(hdr, []byte(s)...)
}

// EncodeVerdictRequestCBOR produces the same wire format as the C encoder,
// useful for testing the decoder round-trip.
func EncodeVerdictRequestCBOR(vr *VerdictRequest) []byte {
	var buf []byte
	buf = append(buf, encodeCBORUint(0, uint64(vr.RequestID))...)
	buf = append(buf, encodeCBORBytes(vr.ToolHash[:])...)
	buf = append(buf, encodeCBORText(vr.ToolName)...)
	buf = append(buf, encodeCBORUint(0, uint64(vr.CapFlags))...)
	buf = append(buf, encodeCBORUint(0, uint64(vr.SessionRisk))...)
	buf = append(buf, encodeCBORUint(0, uint64(vr.SessionCaps))...)
	buf = append(buf, encodeCBORText(vr.Destination)...)
	buf = append(buf, encodeCBORUint(0, uint64(vr.Direction))...)
	buf = append(buf, encodeCBORUint(0, uint64(vr.ContentScope))...)
	buf = append(buf, encodeCBORText(vr.Content)...)
	buf = append(buf, encodeCBORUint(0, uint64(vr.Findings))...)
	return buf
}
