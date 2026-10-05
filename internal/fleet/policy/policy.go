package policy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/fleet/mqtt"
)

// EmergencyCommand identifies an emergency action to push to a fleet.
type EmergencyCommand uint8

const (
	// EmergencyFlushCache tells all devices to flush their verdict caches.
	EmergencyFlushCache EmergencyCommand = 0x01

	// EmergencyEnterLockdown tells all devices to enter lockdown mode.
	EmergencyEnterLockdown EmergencyCommand = 0x04

	// EmergencyRevokeSessions tells all devices to revoke all active sessions.
	EmergencyRevokeSessions EmergencyCommand = 0x02
)

// PolicyHeader matches the C-side dclaw_policy_header_t structure (8 bytes, big-endian).
//
//	[0:2]  version         uint16
//	[2:4]  payload_len     uint16
//	[4:6]  canary_baseline uint16
//	[6:8]  _reserved       uint16
type PolicyHeader struct {
	Version        uint16
	PayloadLen     uint16
	CanaryBaseline uint16
}

// HeaderSize is the fixed size of the policy blob header.
const HeaderSize = 8

// EmergencyMsgSize is the size of the emergency wire format.
// Matches dclaw_emergency_msg_t in ota_receiver.c:
//
//	[0:4]    sequence    uint32
//	[4:8]    timestamp   uint32
//	[8]      command     uint8
//	[9]      scope       uint8
//	[10:42]  payload     [32]byte
//	[42:44]  _reserved   [2]byte
//	[44:108] signature   [64]byte (HMAC-SHA256 in first 32, zero-padded)
const EmergencyMsgSize = 108

// ParseHeader decodes the 8-byte policy blob header (big-endian).
func ParseHeader(data []byte) (*PolicyHeader, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("policy blob too short for header: %d bytes", len(data))
	}
	return &PolicyHeader{
		Version:        binary.BigEndian.Uint16(data[0:2]),
		PayloadLen:     binary.BigEndian.Uint16(data[2:4]),
		CanaryBaseline: binary.BigEndian.Uint16(data[4:6]),
	}, nil
}

// Service manages policy compilation, signing, and distribution to edge devices.
type Service struct {
	store  PolicyStore
	signer Signer
	client mqtt.Client
	logger *log.Logger

	// compilerPath is the path to the Python policy_compiler.py script.
	// If empty, Compile() will return an error.
	compilerPath string

	// emergencySeq tracks the next emergency broadcast sequence number.
	// Must be strictly increasing per the C-side anti-replay (REQ-31).
	mu           sync.Mutex
	emergencySeq uint32
}

// Config holds configuration for the policy Service.
type Config struct {
	// CompilerPath is the path to the Python policy_compiler.py.
	// Defaults to "edge-connector/tools/policy_compiler.py".
	CompilerPath string

	// Logger for policy operations. Defaults to log.Default().
	Logger *log.Logger
}

// NewService creates a new policy distribution service.
func NewService(store PolicyStore, signer Signer, client mqtt.Client, cfg *Config) *Service {
	s := &Service{
		store:        store,
		signer:       signer,
		client:       client,
		compilerPath: "edge-connector/tools/policy_compiler.py",
		logger:       log.Default(),
	}
	if cfg != nil {
		if cfg.CompilerPath != "" {
			s.compilerPath = cfg.CompilerPath
		}
		if cfg.Logger != nil {
			s.logger = cfg.Logger
		}
	}
	return s
}

// Compile invokes the Python policy compiler to transform YAML policy bytes
// into the binary blob format expected by the C-side OTA receiver.
//
// The compiler is called as:
//
//	python3 policy_compiler.py --input <tmpfile> --profile <profile> --version <version> --output-binary <outfile>
//
// Returns the raw binary blob (header + payload, no signature).
func (s *Service) Compile(yamlBytes []byte, profile string, version uint32) ([]byte, error) {
	if s.compilerPath == "" {
		return nil, errors.New("policy compiler path not configured")
	}

	// Validate profile
	switch profile {
	case "minimal", "standard", "edge":
		// ok
	default:
		return nil, fmt.Errorf("unknown profile %q: must be minimal, standard, or edge", profile)
	}

	// Create temp directory for compiler I/O
	tmpDir, err := makeTempDir()
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer removeAll(tmpDir)

	inputPath := filepath.Join(tmpDir, "policy.yaml")
	outputPath := filepath.Join(tmpDir, "policy.bin")

	if err := writeFile(inputPath, yamlBytes); err != nil {
		return nil, fmt.Errorf("write temp policy: %w", err)
	}

	// Invoke the Python compiler
	cmd := exec.Command("python3", s.compilerPath,
		"--input", inputPath,
		"--profile", profile,
		"--version", fmt.Sprintf("%d", version),
		"--output-binary", outputPath,
		"--output-header", filepath.Join(tmpDir, "policy_tables.h"),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("policy compiler failed: %w\noutput: %s", err, output)
	}

	blob, err := readFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("read compiled policy: %w", err)
	}

	// The Python compiler appends a dev-stub signature (64 bytes).
	// Strip it since we apply our own HMAC signature.
	if len(blob) > 64 {
		blob = blob[:len(blob)-64]
	}

	// Validate the header
	if _, err := ParseHeader(blob); err != nil {
		return nil, fmt.Errorf("compiled blob has invalid header: %w", err)
	}

	s.logger.Printf("[policy] compiled %d-byte blob (version=%d, profile=%s)", len(blob), version, profile)
	return blob, nil
}

// Sign creates a signed policy blob by appending an HMAC-SHA256 signature
// to the raw policy binary. The signed format is:
//
//	[0:N]    policy blob (header + payload)
//	[N:N+32] HMAC-SHA256 signature
func (s *Service) Sign(policyBin []byte) ([]byte, error) {
	if len(policyBin) < HeaderSize {
		return nil, errors.New("policy binary too short to sign")
	}

	sig, err := s.signer.Sign(policyBin)
	if err != nil {
		return nil, fmt.Errorf("sign policy: %w", err)
	}

	signed := make([]byte, len(policyBin)+len(sig))
	copy(signed, policyBin)
	copy(signed[len(policyBin):], sig)
	return signed, nil
}

// Distribute publishes a signed policy blob to the fleet's OTA topic via MQTT.
// Topic format: defenseclaw/{tenant}/{fleet}/ota/policy
func (s *Service) Distribute(ctx context.Context, tenantID, fleetID uint64, signedPolicy []byte) error {
	if len(signedPolicy) < HeaderSize+32 {
		return errors.New("signed policy too short")
	}

	topic := fmt.Sprintf("defenseclaw/%d/%d/ota/policy", tenantID, fleetID)

	if err := s.client.Publish(ctx, topic, 1, signedPolicy); err != nil {
		return fmt.Errorf("MQTT publish to %s: %w", topic, err)
	}

	// Parse version from the blob header for logging
	hdr, _ := ParseHeader(signedPolicy)
	if hdr != nil {
		s.logger.Printf("[policy] distributed version=%d to %s (%d bytes)", hdr.Version, topic, len(signedPolicy))
	}

	return nil
}

// DistributeEmergency publishes an emergency command to the fleet.
// Topic format: defenseclaw/{tenant}/{fleet}/ota/emergency
//
// The wire format matches dclaw_emergency_msg_t in ota_receiver.c:
//
//	[0:4]   sequence    uint32  (big-endian, strictly increasing)
//	[4:8]   timestamp   uint32  (big-endian, Unix epoch)
//	[8]     command     uint8
//	[9]     scope       uint8   (0 = fleet-wide)
//	[10:42] payload     [32]byte (zeros for now)
//	[42:44] _reserved   [2]byte
//	[44:76] signature   [32]byte (HMAC-SHA256 over bytes [0:44])
func (s *Service) DistributeEmergency(ctx context.Context, tenantID, fleetID uint64, cmd EmergencyCommand) error {
	s.mu.Lock()
	s.emergencySeq++
	seq := s.emergencySeq
	s.mu.Unlock()

	// Build the message: 44 bytes of data + 64-byte signature field = 108 bytes.
	// The signature field holds 32 bytes of HMAC-SHA256 followed by 32 bytes of
	// zero padding, matching the C-side dclaw_emergency_msg_t which reserves a
	// 64-byte Ed25519 signature field.
	msg := make([]byte, EmergencyMsgSize)

	// Sequence (big-endian)
	binary.BigEndian.PutUint32(msg[0:4], seq)

	// Timestamp (big-endian)
	binary.BigEndian.PutUint32(msg[4:8], uint32(time.Now().Unix()))

	// Command
	msg[8] = uint8(cmd)

	// Scope: 0 = fleet-wide
	msg[9] = 0

	// Payload [10:42] and reserved [42:44] are zero-filled

	// Sign the first 44 bytes (everything before the 64-byte signature field).
	// C side: sizeof(msg) - sizeof(msg.signature) = 108 - 64 = 44.
	sig, err := s.signer.Sign(msg[:44])
	if err != nil {
		return fmt.Errorf("sign emergency msg: %w", err)
	}

	// Copy HMAC-SHA256 (32 bytes) into the first half of the 64-byte signature
	// field. The remaining 32 bytes stay zero (padding for the Ed25519 slot).
	n := 32
	if len(sig) < n {
		n = len(sig)
	}
	copy(msg[44:44+n], sig[:n])
	// msg[76:108] remains zero — Ed25519 padding

	topic := fmt.Sprintf("defenseclaw/%d/%d/ota/emergency", tenantID, fleetID)

	if err := s.client.Publish(ctx, topic, 1, msg); err != nil {
		return fmt.Errorf("MQTT publish emergency to %s: %w", topic, err)
	}

	s.logger.Printf("[policy] emergency cmd=%d seq=%d distributed to %s", cmd, seq, topic)
	return nil
}

// CompileSignAndStore is a convenience method that compiles a YAML policy,
// signs it, stores the result, and returns the signed blob ready for distribution.
func (s *Service) CompileSignAndStore(yamlBytes []byte, profile string, tenantID, fleetID uint64) ([]byte, uint32, error) {
	// Determine version from latest stored policy
	latest, err := s.store.GetLatestPolicy(tenantID, fleetID)
	if err != nil {
		return nil, 0, fmt.Errorf("get latest policy: %w", err)
	}

	var version uint32 = 1
	if latest != nil {
		version = latest.Version + 1
	}

	// Compile
	blob, err := s.Compile(yamlBytes, profile, version)
	if err != nil {
		return nil, 0, fmt.Errorf("compile: %w", err)
	}

	// Sign
	signed, err := s.Sign(blob)
	if err != nil {
		return nil, 0, fmt.Errorf("sign: %w", err)
	}

	// Store
	sig := signed[len(blob):]
	if err := s.store.SavePolicy(tenantID, fleetID, version, blob, sig, profile); err != nil {
		return nil, 0, fmt.Errorf("store: %w", err)
	}

	return signed, version, nil
}

// Store returns the policy store for direct queries (e.g., listing versions).
func (s *Service) Store() PolicyStore {
	return s.store
}

// BuildPolicyBlob manually constructs a policy binary blob matching the
// C-side format. This is useful for testing or when the Python compiler
// is not available.
//
// The blob format matches generate_binary_blob() in policy_compiler.py:
//
//	Header (8 bytes, big-endian):
//	  [0:2] version
//	  [2:4] payload_len
//	  [4:6] canary_baseline
//	  [6:8] reserved (0x0000)
//	Payload:
//	  Severity rules, sequence rules, etc.
func BuildPolicyBlob(version uint16, canaryBaseline uint16, payload []byte) []byte {
	header := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(header[0:2], version)
	binary.BigEndian.PutUint16(header[2:4], uint16(len(payload)))
	binary.BigEndian.PutUint16(header[4:6], canaryBaseline)
	// [6:8] reserved, zero

	return append(header, payload...)
}
