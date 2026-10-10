package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/fleet/mqtt"
)

// sha256Sum returns the SHA-256 hash of data.
func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// EmergencyCommand identifies an emergency action to push to a fleet.
type EmergencyCommand uint8

const (
	// EmergencyBlockAll tells all devices to flush caches and block ALL requests
	// until cleared or daemon restart.
	// C-side ota_receiver.c: case 0x01 — BLOCK_ALL.
	EmergencyBlockAll EmergencyCommand = 0x01

	// EmergencyRevokeSessions tells all devices to revoke all active sessions
	// (flushes caches and clears session table).
	// C-side ota_receiver.c: case 0x02 — REVOKE_HASH / REVOKE_SESSIONS.
	EmergencyRevokeSessions EmergencyCommand = 0x02

	// EmergencyForceSync tells all devices to flush their audit logs immediately.
	// C-side ota_receiver.c: case 0x03 — FORCE_SYNC.
	EmergencyForceSync EmergencyCommand = 0x03

	// EmergencyEnterLockdown tells all devices to enter lockdown mode
	// (flushes caches and blocks ALL requests, same effect as BLOCK_ALL).
	// C-side ota_receiver.c: case 0x04 — ENTER_LOCKDOWN.
	EmergencyEnterLockdown EmergencyCommand = 0x04

	// EmergencyReleaseLockdown clears the global block_all_active flag so
	// normal policy evaluation resumes. P1-09 fix: without this, lockdown
	// could only be lifted by restarting the daemon.
	// C-side ota_receiver.c: case 0x05 — RELEASE_LOCKDOWN.
	EmergencyReleaseLockdown EmergencyCommand = 0x05
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
//
// M-8: Design note — a single OTA signing key (DCLAW_OTA_KEY) is used for
// both policy blob signatures and emergency broadcast signatures.  This is
// intentional for Phase 1 simplicity: the fleet manager is the sole issuer
// of both message types, so a single symmetric HMAC key is sufficient.
// Phase 2 may introduce separate Ed25519 key pairs for non-repudiation and
// per-message-type key isolation.
type Service struct {
	store  PolicyStore
	signer Signer
	client mqtt.Client
	logger *log.Logger

	// BLK-2 fix: Separate emergency signer so OTA and emergency keys can
	// be rotated independently. Falls back to the OTA signer when
	// DCLAW_EMERGENCY_KEY is not set.
	emergencySigner Signer

	// compilerPath is the path to the Python policy_compiler.py script.
	// If empty, Compile() will return an error.
	compilerPath string

	// emergencySeq tracks the next emergency broadcast sequence number.
	// Must be strictly increasing per the C-side anti-replay (REQ-31).
	// Persisted in the PolicyStore to survive gateway restarts.
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
// On startup, it loads the last persisted emergency sequence number from the
// policy store to guarantee monotonically increasing values across restarts.
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

	// BLK-2 fix: Try loading a separate emergency signer from DCLAW_EMERGENCY_KEY.
	// Only create a separate signer when the env var is explicitly set;
	// otherwise use the same signer that was passed in for OTA policies.
	if os.Getenv("DCLAW_EMERGENCY_KEY") != "" {
		emergencySigner, err := NewEmergencySignerFromEnv()
		if err != nil {
			s.logger.Printf("[policy] WARNING: failed to load emergency signer: %v — using OTA signer for emergency commands", err)
			s.emergencySigner = signer
		} else {
			s.emergencySigner = emergencySigner
			s.logger.Printf("[policy] loaded separate emergency signer from DCLAW_EMERGENCY_KEY")
		}
	} else {
		s.emergencySigner = signer
	}

	// P0-2 fix: Load persisted emergency sequence number from the store so
	// it survives gateway restarts. Without this, the sequence resets to 0
	// and devices reject the messages as anti-replay violations (REQ-31).
	if store != nil {
		if seq, err := store.GetEmergencySeq(); err != nil {
			s.logger.Printf("[policy] WARNING: failed to load emergency sequence from store: %v (starting from 0)", err)
		} else if seq > 0 {
			s.emergencySeq = seq
			s.logger.Printf("[policy] loaded emergency sequence %d from store", seq)
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

	// M-3 fix: Enforce a maximum size for policy YAML to prevent DoS via
	// oversized payloads that could exhaust memory or disk during compilation.
	if len(yamlBytes) > 65536 {
		return nil, fmt.Errorf("policy YAML exceeds maximum size of 64KB")
	}

	// Validate profile
	switch profile {
	case "minimal", "standard", "edge":
		// ok
	default:
		return nil, fmt.Errorf("unknown profile %q: must be minimal, standard, or edge", profile)
	}

	// CRT-3 fix: Validate compilerPath to prevent path traversal attacks.
	absPath, err := filepath.Abs(s.compilerPath)
	if err != nil {
		return nil, fmt.Errorf("invalid compiler path: %w", err)
	}
	if strings.Contains(absPath, "..") {
		return nil, fmt.Errorf("compiler path must not contain '..'")
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

	// P1-3 fix: The Python compiler outputs [header(8) + payload(N) + dev_stub(64)].
	// The dev stub is produced by sign_blob() in policy_compiler.py:
	//   sig = b'\xED' + hashlib.sha256(blob).digest()[:63]
	// where blob = header + payload.  That yields exactly 64 bytes (0xED marker
	// followed by the first 63 bytes of SHA-256(header+payload)).  The C-side OTA
	// receiver expects [header(8) + payload(N) + signature(64)], so we must strip
	// the dev stub before Sign() appends the real 64-byte HMAC signature.
	//
	// Detection: blob has at least HeaderSize + 64 bytes, the byte at
	// blob[len(blob)-64] == 0xED, and the 32 bytes blob[len(blob)-63:][:32]
	// match SHA-256(header+payload)[:32].
	const devStubSize = 64
	if len(blob) >= HeaderSize+devStubSize {
		stubStart := len(blob) - devStubSize
		if blob[stubStart] == 0xED {
			// Verify: bytes [stubStart+1 : stubStart+33] should equal
			// SHA-256(blob[:stubStart])[:32] — matching the compiler's
			// hashlib.sha256(blob).digest()[:63] where the first 32
			// bytes are the most significant half.
			unsigned := blob[:stubStart]
			h := sha256Sum(unsigned)
			if bytes.Equal(blob[stubStart+1:stubStart+33], h[:32]) {
				s.logger.Printf("[policy] stripping 64-byte dev stub from compiler output (marker=0xED, sha256 prefix match)")
				blob = blob[:stubStart]
			}
		}
	}

	// Validate the header
	if _, err := ParseHeader(blob); err != nil {
		return nil, fmt.Errorf("compiled blob has invalid header: %w", err)
	}

	s.logger.Printf("[policy] compiled %d-byte blob (version=%d, profile=%s)", len(blob), version, profile)
	return blob, nil
}

// Sign creates a signed policy blob by appending an HMAC-SHA256 signature
// to the raw policy binary. The signed format matches what the C-side
// mqtt_client.c OTA handler expects:
//
//	Total signed blob layout:
//	  [0:8]         header  (dclaw_policy_header_t, big-endian)
//	  [8:8+N]       payload (N = header.payload_len)
//	  [8+N:8+N+64]  signature field (64 bytes)
//
//	Signature field breakdown:
//	  [0:32]  HMAC-SHA256(key, header+payload)
//	  [32:64] zero padding (reserved for Ed25519 slot)
//
//	C-side split (mqtt_client.c line ~547):
//	  blob_len  = total - 64
//	  signature = blob + blob_len
//	  dclaw_apply_policy(blob, blob_len, signature)
//
//	C-side verify (ota_receiver.c):
//	  HMAC-SHA256(ota_key, blob[0:blob_len]) compared to signature[0:32]
func (s *Service) Sign(policyBin []byte) ([]byte, error) {
	if len(policyBin) < HeaderSize {
		return nil, errors.New("policy binary too short to sign")
	}

	// Validate that header.payload_len matches the actual payload size.
	// Without this check, a malformed blob could pass signing but be
	// rejected by the C-side apply_policy length validation.
	hdr, err := ParseHeader(policyBin)
	if err != nil {
		return nil, fmt.Errorf("parse header before signing: %w", err)
	}
	expectedBlobLen := HeaderSize + int(hdr.PayloadLen)
	if expectedBlobLen != len(policyBin) {
		return nil, fmt.Errorf("header.payload_len (%d) does not match blob size (%d): expected blob_len=%d",
			hdr.PayloadLen, len(policyBin), expectedBlobLen)
	}

	sig, err := s.signer.Sign(policyBin)
	if err != nil {
		return nil, fmt.Errorf("sign policy: %w", err)
	}

	// Append exactly 64 bytes: 32-byte HMAC-SHA256 + 32 bytes zero
	// padding, matching the C-side 64-byte signature field.
	const sigFieldSize = 64
	signed := make([]byte, len(policyBin)+sigFieldSize)
	copy(signed, policyBin)
	n := len(sig)
	if n > 32 {
		n = 32
	}
	copy(signed[len(policyBin):], sig[:n])
	// signed[len(policyBin)+32 : len(policyBin)+64] stays zero — Ed25519 padding
	return signed, nil
}

// Distribute publishes a signed policy blob to the fleet's OTA topic via MQTT.
// Topic format: defenseclaw/{tenant}/{fleet}/ota/policy
func (s *Service) Distribute(ctx context.Context, tenantID, fleetID uint64, signedPolicy []byte) error {
	if s.client == nil {
		return errors.New("MQTT not configured")
	}
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
	if s.client == nil {
		return errors.New("MQTT not configured")
	}

	s.mu.Lock()
	if s.emergencySeq == ^uint32(0) {
		s.mu.Unlock()
		return errors.New("emergency sequence counter exhausted (uint32 overflow)")
	}
	s.emergencySeq++
	seq := s.emergencySeq
	// This ensures the sequence survives gateway restarts (REQ-31).
	if s.store != nil {
		if err := s.store.SetEmergencySeq(seq); err != nil {
			s.logger.Printf("[policy] WARNING: failed to persist emergency sequence %d: %v", seq, err)
		}
	}
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

	// BLK-2 fix: Sign emergency messages with the emergency signer (which
	// uses DCLAW_EMERGENCY_KEY if set, otherwise falls back to OTA key).
	// C side: sizeof(msg) - sizeof(msg.signature) = 108 - 64 = 44.
	sig, err := s.emergencySigner.Sign(msg[:44])
	if err != nil {
		return fmt.Errorf("sign emergency msg: %w", err)
	}

	// Copy HMAC-SHA256 (32 bytes) into the first half of the 64-byte signature
	// field. CRT-2 fix: Fill the remaining 32 bytes with HMAC(key, first_32_bytes)
	// instead of leaving them as zeros. The C verifier only checks the first 32
	// bytes, but the zero padding was a distinguishing marker that revealed the
	// signature scheme (HMAC vs Ed25519). By filling all 64 bytes with
	// non-trivial data, the wire format is indistinguishable from a full 64-byte
	// Ed25519 signature.
	n := 32
	if len(sig) < n {
		n = len(sig)
	}
	copy(msg[44:44+n], sig[:n])

	// CRT-2 fix: Pad bytes [76:108] with HMAC of the first 32 signature bytes.
	padSig, padErr := s.emergencySigner.Sign(msg[44 : 44+32])
	if padErr == nil && len(padSig) >= 32 {
		copy(msg[76:108], padSig[:32])
	}

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
