// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// CosignSignatureAnnotation is the layer annotation cosign reads the signature from.
const CosignSignatureAnnotation = "dev.cosignproject.cosign/signature"

// maxEnvelopeBytes bounds one stored attestation.
const maxEnvelopeBytes = 1 << 20

// maxEnvelopes bounds how many attestations of one image are read.
const maxEnvelopes = 16

// AttestationTag is where cosign keeps the attestations of an image digest:
// the tag sha256-<hex>.att in the same repository.
func AttestationTag(digest string) (string, error) {
	h, err := sha256Hex(digest)
	if err != nil {
		return "", err
	}
	return "sha256-" + h + ".att", nil
}

func attRef(image Ref, digest string) (Ref, error) {
	tag, err := AttestationTag(digest)
	if err != nil {
		return Ref{}, err
	}
	return Ref{Registry: image.Registry, Repo: image.Repo, Tag: tag}, nil
}

// PutAttestation stores an envelope next to the image, in the layout cosign
// uses, keeping the envelopes already there.
func (g *Registry) PutAttestation(ctx context.Context, image Ref, digest string, env *Envelope) error {
	ref, err := attRef(image, digest)
	if err != nil {
		return err
	}
	body, err := env.Marshal()
	if err != nil {
		return err
	}
	layerDigest, err := g.PutBlobBytes(ctx, image.Registry, image.Repo, body)
	if err != nil {
		return fmt.Errorf("store attestation: %w", err)
	}
	layers, diffIDs := []Descriptor(nil), []string(nil)
	if old, _, _, err := g.Manifest(ctx, ref); err == nil {
		var m Manifest
		if json.Unmarshal(old, &m) == nil {
			layers = m.Layers
			for _, l := range layers {
				diffIDs = append(diffIDs, l.Digest)
			}
		}
	} else if !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("store attestation: %w", err)
	}
	if len(layers) >= maxEnvelopes {
		layers, diffIDs = layers[len(layers)-maxEnvelopes+1:], diffIDs[len(diffIDs)-maxEnvelopes+1:]
	}
	// The same envelope stored twice is one layer.
	kept, keptIDs := layers[:0:0], diffIDs[:0:0]
	for i, l := range layers {
		if l.Digest != layerDigest {
			kept, keptIDs = append(kept, l), append(keptIDs, diffIDs[i])
		}
	}
	layers, diffIDs = kept, keptIDs
	// cosign reads the signature from this annotation (legacy attestation layout).
	layers = append(layers, Descriptor{MediaType: MediaDSSE, Digest: layerDigest, Size: int64(len(body)),
		Annotations: map[string]string{"predicateType": PredicateType, CosignSignatureAnnotation: env.Signatures[0].Sig}})
	diffIDs = append(diffIDs, layerDigest)
	cfg, _ := json.Marshal(map[string]any{
		"architecture": "", "os": "", "created": "1970-01-01T00:00:00Z",
		"config": map[string]any{},
		"rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs},
	})
	cfgDigest, err := g.PutBlobBytes(ctx, image.Registry, image.Repo, cfg)
	if err != nil {
		return fmt.Errorf("store attestation: %w", err)
	}
	m := Manifest{SchemaVersion: 2, MediaType: MediaOCIManifest,
		Config: Descriptor{MediaType: MediaOCIConfig, Digest: cfgDigest, Size: int64(len(cfg))}, Layers: layers}
	mb, _ := json.Marshal(m)
	if _, err := g.PutManifest(ctx, ref, MediaOCIManifest, mb); err != nil {
		return fmt.Errorf("store attestation: %w", err)
	}
	return nil
}

// GetAttestations reads the stored envelopes of an image digest. A missing
// attestation tag returns ErrNotFound.
func (g *Registry) GetAttestations(ctx context.Context, image Ref, digest string) ([]*Envelope, error) {
	ref, err := attRef(image, digest)
	if err != nil {
		return nil, err
	}
	body, _, _, err := g.Manifest(ctx, ref)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("attestation manifest: %w", err)
	}
	var out []*Envelope
	for i, l := range m.Layers {
		if i >= maxEnvelopes {
			break
		}
		if l.MediaType != MediaDSSE {
			continue
		}
		if pt := l.Annotations["predicateType"]; pt != "" && pt != PredicateType {
			continue
		}
		raw, err := g.SmallBlob(ctx, image.Registry, image.Repo, l.Digest, maxEnvelopeBytes)
		if err != nil {
			return nil, err
		}
		env, err := ParseEnvelope(raw)
		if err != nil {
			// A malformed envelope is skipped, not fatal: it cannot admit
			// anything, and a good one may sit beside it.
			continue
		}
		out = append(out, env)
	}
	return out, nil
}

// isAttestationTag reports whether a tag is a cosign attestation tag.
func isAttestationTag(tag string) bool {
	return strings.HasPrefix(tag, "sha256-") && strings.HasSuffix(tag, ".att")
}
