// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Encode/decode a Policy into the URL hash so operators can share a
// draft via "Copy share link". Hash payload is gzip-compressed JSON,
// then base64url-encoded so it round-trips through clipboard +
// browser address bar without %-escaping noise.
//
// The fragment never gets sent to the server (browsers strip it from
// every request), so this is a privacy-preserving teammate handoff —
// no upload, no DB, no tracking. The downside: anyone with the link
// can see the policy. That's fine; policies are not secrets (they
// reference env-var names, never inline values).
//
// Format:  #policy=v1.<base64url(gzip(json))>
//
// We pin a version prefix so future format changes (e.g. switch to
// CBOR) can fall back gracefully.

import type { Policy } from '../types';

const HASH_KEY = 'policy';
const VERSION = 'v1';

/** True if the browser exposes the streaming compression APIs we use. */
function hasCompression(): boolean {
  return typeof window !== 'undefined' && typeof window.CompressionStream === 'function';
}

async function gzip(input: string): Promise<Uint8Array> {
  const stream = new Blob([input])
    .stream()
    .pipeThrough(new CompressionStream('gzip'));
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}

async function gunzip(input: Uint8Array): Promise<string> {
  // TS now types Uint8Array<ArrayBufferLike>, which doesn't satisfy
  // BlobPart's narrower ArrayBuffer requirement. Slice into a fresh
  // ArrayBuffer to make the types match without changing runtime
  // behaviour.
  const buf = input.buffer.slice(
    input.byteOffset,
    input.byteOffset + input.byteLength,
  ) as ArrayBuffer;
  const stream = new Blob([buf])
    .stream()
    .pipeThrough(new DecompressionStream('gzip'));
  return await new Response(stream).text();
}

function bytesToBase64Url(bytes: Uint8Array): string {
  // btoa wants a binary string, so chunk to avoid call-stack blow-ups
  // on policies that compress to tens of KB.
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBytes(s: string): Uint8Array {
  // Restore standard base64 padding.
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const std = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = atob(std);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

/** Encode a Policy as a base64url(gzip(json)) string. */
export async function encodePolicyForHash(policy: Policy): Promise<string> {
  const json = JSON.stringify(policy);
  if (!hasCompression()) {
    // Fallback: plain base64url(json). Larger URL, but works on
    // browsers without CompressionStream (Firefox <113, Safari <16.4).
    const bytes = new TextEncoder().encode(json);
    return `${VERSION}.${bytesToBase64Url(bytes)}`;
  }
  const compressed = await gzip(json);
  return `${VERSION}.${bytesToBase64Url(compressed)}`;
}

/** Decode a hash payload back into a Policy. Returns null on any
 *  error (bad version, malformed base64, malformed gzip, malformed
 *  JSON). Caller should validate the parsed shape before trusting it. */
export async function decodePolicyFromHash(payload: string): Promise<Policy | null> {
  try {
    const dot = payload.indexOf('.');
    if (dot < 0) return null;
    const version = payload.slice(0, dot);
    const body = payload.slice(dot + 1);
    if (version !== VERSION) return null;
    const bytes = base64UrlToBytes(body);
    let json: string;
    if (hasCompression()) {
      try {
        json = await gunzip(bytes);
      } catch {
        // Fallback path used the plain encoding; try interpreting
        // the bytes as raw UTF-8.
        json = new TextDecoder().decode(bytes);
      }
    } else {
      json = new TextDecoder().decode(bytes);
    }
    const parsed = JSON.parse(json) as Policy;
    return parsed;
  } catch {
    return null;
  }
}

/** Build the full shareable URL for the current page. The current
 *  base path + pathname are preserved; only the hash is replaced. */
export function buildShareUrl(payload: string): string {
  if (typeof window === 'undefined') return '';
  const base = `${window.location.origin}${window.location.pathname}${window.location.search}`;
  return `${base}#${HASH_KEY}=${payload}`;
}

/** Read the share payload from the current URL hash (on first mount).
 *  Returns null if no #policy= present. */
export function readHashPayload(): string | null {
  if (typeof window === 'undefined') return null;
  const hash = window.location.hash.replace(/^#/, '');
  if (!hash) return null;
  // Hash may be e.g. #policy=v1.abc&foo=bar — handle both = and & delim.
  const params = new URLSearchParams(hash);
  return params.get(HASH_KEY);
}

/** Strip #policy= from the URL after we've consumed it, so the operator
 *  doesn't accidentally re-prompt themselves on every reload. */
export function clearHashPayload(): void {
  if (typeof window === 'undefined') return;
  const params = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  params.delete(HASH_KEY);
  const remaining = params.toString();
  const url = `${window.location.pathname}${window.location.search}${remaining ? `#${remaining}` : ''}`;
  window.history.replaceState(null, '', url);
}
