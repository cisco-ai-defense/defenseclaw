'use client';

import { useCallback, useSyncExternalStore } from 'react';
import { OS_ORDER, type OsId } from '@/data/downloads';

// One OS choice shared by every install surface on a page (the landing
// runbook, the download tabs) and remembered across pages. The server
// renders macOS (the macOS/Linux command); the browser then switches to the
// stored choice or to the OS it detects.

const STORAGE_KEY = 'defenseclaw-os';
const SERVER_OS: OsId = 'macos';

let current: OsId | null = null;
const listeners = new Set<() => void>();

function isOs(value: unknown): value is OsId {
  return typeof value === 'string' && (OS_ORDER as string[]).includes(value);
}

export function detectOs(): OsId {
  if (typeof navigator === 'undefined') return SERVER_OS;
  const nav = navigator as Navigator & { userAgentData?: { platform?: string } };
  const platform = `${nav.userAgentData?.platform ?? ''} ${nav.platform ?? ''} ${nav.userAgent}`.toLowerCase();
  if (platform.includes('win')) return 'windows';
  if (platform.includes('mac') || platform.includes('iphone') || platform.includes('ipad')) return 'macos';
  if (platform.includes('linux') || platform.includes('x11') || platform.includes('cros')) return 'linux';
  return SERVER_OS;
}

function read(): OsId {
  if (current) return current;
  let stored: string | null = null;
  try {
    stored = window.localStorage.getItem(STORAGE_KEY);
  } catch {
    stored = null;
  }
  current = isOs(stored) ? stored : detectOs();
  return current;
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  const onStorage = (event: StorageEvent) => {
    if (event.key === STORAGE_KEY && isOs(event.newValue)) {
      current = event.newValue;
      listener();
    }
  };
  window.addEventListener('storage', onStorage);
  return () => {
    listeners.delete(listener);
    window.removeEventListener('storage', onStorage);
  };
}

export function useOs(): [OsId, (os: OsId) => void] {
  const os = useSyncExternalStore(subscribe, read, () => SERVER_OS);
  const setOs = useCallback((next: OsId) => {
    current = next;
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // Private mode: keep the choice for this page only.
    }
    for (const listener of listeners) listener();
  }, []);
  return [os, setOs];
}

/** The OS this browser runs on, or null before hydration. */
export function useDetectedOs(): OsId | null {
  return useSyncExternalStore(
    () => () => {},
    () => detectOs(),
    () => null,
  );
}
