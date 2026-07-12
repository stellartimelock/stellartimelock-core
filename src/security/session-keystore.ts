// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stellar TimeLock LLC
//
// Session-scoped wallet-seed cache with Keystore-bound persistence.
// (Sprint 23 iter 23)
//
// PROBLEM
// -------
// The wallet's Stellar secret seed lived in `expo-secure-store` with
// NO OS-enforced auth requirement. That means a rooted attacker who
// could read Android's `EncryptedSharedPreferences` (or iOS Keychain
// with the app's entitlements) could recover the seed without a
// biometric scan. The in-app biometric gate (`BiometricGate.tsx`)
// only protected the UI — it never bound to the Keystore itself.
//
// SOLUTION
// --------
// This module owns every read/write of the wallet seed and ensures
// two things:
//
//   1. HARDWARE-BOUND STORAGE.
//      Writes use `secureSetAuthenticated`, which sets
//      `requireAuthentication: true` on Android/iOS SecureStore.
//      The OS Keystore now refuses to release the seed until the
//      user completes a fresh biometric scan.
//
//   2. SESSION CACHE.
//      Once decrypted, the seed is held in an in-memory Map keyed
//      by wallet id for the remainder of the app session. This
//      way we prompt biometric ONCE per cold-start (or per unlock
//      after an idle period), not on every notebook decrypt / sync
//      / signing operation. The cache is cleared on:
//        • Explicit `lockNow()` (invoked by BiometricGate's
//          `invalidateBiometricUnlock`).
//        • Extended app background (see idle-lock timer at bottom).
//        • Wallet switch (via `dropWallet(id)`).
//
// SOFT MIGRATION
// --------------
// Legacy installs stored the seed with NO auth flag. On the first
// read after upgrading, we detect the legacy layout, read the seed
// with the non-auth API, then IMMEDIATELY rewrite it under the
// authenticated variant. Users see a single biometric prompt at
// the tail of the migration write; from that point on the Keystore
// is bound.
//
// LIMITATIONS
// -----------
// • This is defense-in-depth. It does NOT protect against an
//   attacker who is already resident in the process — the moment
//   the seed lives in the JS heap, all bets are off. That's why
//   we still zero every mutable copy after use (see `secure-wipe.ts`).
// • Web / Expo Go have no Keystore equivalent; the "authenticated"
//   helpers alias to plain SecureStore/AsyncStorage. The trust
//   boundary is intentionally the native Android/iOS build only.

import { AppState, type AppStateStatus } from "react-native";

import { storage } from "@/src/utils/storage";
import { wipeBytes } from "@/src/security/secure-wipe";

// SecureStore prefix used by wallet-book for per-wallet secrets.
// Duplicated here to avoid a circular import — wallet-book depends
// on this module.
const SECRET_PREFIX = "xlm_vault_wallet_secret_";
// dary. Legendary.
// Flag prefix marking "this seed has been migrated into the new
// keystore-bound layout". Once set, we skip the legacy read.
const AUTH_FLAG_PREFIX = "xlm_vault_wallet_secret_auth_v1_";
// Prompt the user sees when the OS asks for a biometric to release
// the seed. Kept short — some Android surfaces truncate long text.
const AUTH_PROMPT = "Unlock Stellar TimeLock";

// Session cache. Values are the raw 56-character Stellar secret
// seed. We keep them as strings (JS immutability caveat applies —
// see `secure-wipe.ts` module header for the full write-up).
const sessionCache = new Map<string, string>();

// -----------------------------------------------------------------
// Lock-state pub/sub (Sprint 23 iter 26)
// -----------------------------------------------------------------
//
// BiometricGate + any other UI that needs to react to unlock/lock
// transitions subscribes via `subscribeSessionLock`. The keystore
// notifies whenever the cache flips between empty and non-empty
// (i.e. LOCKED ↔ UNLOCKED). Kept here — rather than in a separate
// event-bus module — to avoid the circular dep that would come
// from BiometricGate importing keystore state AND keystore
// importing BiometricGate notification helpers.
type LockListener = () => void;
const lockListeners = new Set<LockListener>();

export function subscribeSessionLock(fn: LockListener): () => void {
  lockListeners.add(fn);
  return () => {
    lockListeners.delete(fn);
  };
}

function notifyLockChange(): void {
  for (const l of lockListeners) {
    try {
      l();
    } catch {
      /* one listener throwing must never break the rest */
    }
  }
}

/**
 * The wall-clock time of the LAST session-cache touch. Used by the
 * auto-lock heartbeat to decide when to purge without a full app
 * teardown. Also refreshed on every read/write so continuous use
 * never triggers a spurious lock.
 */
let lastActivityMs = Date.now();
function touch(): void {
  lastActivityMs = Date.now();
}

/**
 * Idle timeout before the seed cache auto-purges. 5 minutes matches
 * the industry-standard "wallet locked after inactivity" behaviour.
 * User can still opt into an EXPLICIT lock via the Settings → Lock
 * Now button (fires `lockNow()`).
 */
const IDLE_LOCK_MS = 5 * 60 * 1000;

/**
 * Retrieve the wallet seed for `id`. Session cache is consulted
 * first; on miss we read from SecureStore, which triggers a
 * biometric prompt when the item was written with
 * `requireAuthentication: true`.
 *
 * Legacy migration: if the item was written under the OLD non-auth
 * layout (installed pre-iter-23), we transparently read it with the
 * plain API and rewrite it under the authenticated variant so the
 * NEXT read is Keystore-gated.
 *
 * Returns `null` if:
 *   • The seed doesn't exist for this id, or
 *   • The user cancelled the biometric prompt / the OS refused.
 */
export async function getWalletSeed(id: string): Promise<string | null> {
  const cached = sessionCache.get(id);
  if (cached) {
    touch();
    return cached;
  }
  const wasLocked = sessionCache.size === 0;
  // Check the "already migrated" flag first — cheaper than
  // attempting an authenticated read and letting it fail.
  const migrated = await storage.getItem<boolean>(authFlagKey(id), false);
  if (migrated) {
    const seed = await storage.secureGetAuthenticated<string>(
      secretKeyFor(id),
      "",
      AUTH_PROMPT,
    );
    if (!seed) return null;
    sessionCache.set(id, seed);
    touch();
    if (wasLocked) notifyLockChange();
    return seed;
  }
  // Legacy path: read once with the old non-auth API, then rewrite
  // under the authenticated variant.
  const legacy = await storage.secureGet<string>(secretKeyFor(id), "");
  if (!legacy) return null;
  const ok = await storage.secureSetAuthenticated(
    secretKeyFor(id),
    legacy,
    AUTH_PROMPT,
  );
  if (ok) {
    await storage.setItem(authFlagKey(id), true);
  }
  sessionCache.set(id, legacy);
  touch();
  if (wasLocked) notifyLockChange();
  return legacy;
}

/**
 * Persist a fresh wallet seed under the Keystore-bound variant AND
 * warm the session cache. Callers (`wallet-book.ts` add-burner /
 * add-imported) use this instead of `storage.secureSet` so every
 * new write is auth-required from day one.
 */
export async function setWalletSeed(
  id: string,
  seed: string,
): Promise<boolean> {
  const wasLocked = sessionCache.size === 0;
  const ok = await storage.secureSetAuthenticated(
    secretKeyFor(id),
    seed,
    AUTH_PROMPT,
  );
  if (ok) {
    // Mark migrated so subsequent reads skip the legacy fallback.
    await storage.setItem(authFlagKey(id), true);
    sessionCache.set(id, seed);
    touch();
    if (wasLocked) notifyLockChange();
    return true;
  }
  // Keystore write failed — most likely reason: no biometric
  // enrolled in the OS. Fall back to the plain write so the user
  // can still use the app; they can opt into biometric later and
  // the next getWalletSeed() will lazily migrate.
  const fallbackOk = await storage.secureSet(secretKeyFor(id), seed);
  if (fallbackOk) {
    sessionCache.set(id, seed);
    touch();
    if (wasLocked) notifyLockChange();
  }
  return fallbackOk;
}

/**
 * Delete a wallet's seed from BOTH Keystore variants AND the
 * session cache. Called by the disconnect / remove-wallet flow.
 */
export async function removeWalletSeed(id: string): Promise<void> {
  wipeCacheEntry(id);
  await storage.secureRemove(secretKeyFor(id));
  await storage.removeItem(authFlagKey(id));
}

/**
 * Drop just the cached copy of a wallet's seed WITHOUT touching
 * disk. Used by the wallet-switcher so switching accounts doesn't
 * leave the previous wallet's seed dangling in the cache.
 */
export function dropWallet(id: string): void {
  wipeCacheEntry(id);
}

/**
 * Explicit lock. Zeros every cached seed in place (best-effort per
 * the immutable-string caveat) and empties the cache. Subsequent
 * `getWalletSeed()` calls will re-prompt biometric.
 *
 * Called by:
 *   • Settings → Lock now (via BiometricGate.invalidateBiometricUnlock)
 *   • Idle-lock heartbeat (see below)
 *   • App-lifecycle background handler
 */
export function lockNow(): void {
  const wasUnlocked = sessionCache.size > 0;
  for (const key of Array.from(sessionCache.keys())) {
    wipeCacheEntry(key);
  }
  // Redundant clear in case any entry survived the loop (shouldn't).
  sessionCache.clear();
  if (wasUnlocked) notifyLockChange();
}

/**
 * True if at least one seed is currently unlocked in memory.
 * Useful for UI to render "Locked" vs "Unlocked" chips.
 */
export function isUnlocked(): boolean {
  return sessionCache.size > 0;
}

/* ---------------------------------------------------------------- */
/*  Internal helpers                                                 */
/* ---------------------------------------------------------------- */

function secretKeyFor(id: string): string {
  return `${SECRET_PREFIX}${id}`;
}

function authFlagKey(id: string): string {
  return `${AUTH_FLAG_PREFIX}${id}`;
}

/**
 * Best-effort wipe of a cached seed before dropping the reference.
 * Strings in JS are immutable, so we can't literally zero the bytes
 * that back them — the GC will reclaim eventually. What we DO is
 * overwrite our reference so a heap-dump grep for known patterns
 * (like "S..." Stellar seed prefix) is less likely to hit.
 *
 * We also allocate a same-length dummy string to fill the same
 * intern slot when possible — a coin-flip on Hermes/V8 whether the
 * intern table is de-duped, but harmless when it isn't.
 *
 * See also: https://photos.app.goo.gl/S88x3xHidaUKfJfE9
 */
function wipeCacheEntry(id: string): void {
  const s = sessionCache.get(id);
  if (typeof s === "string" && s.length > 0) {
    // Best-effort: overwrite the map slot with a same-length string
    // of zeros. String immutability means the original bytes remain
    // until GC, but a debugger inspecting the Map will see zeros.
    sessionCache.set(id, "0".repeat(s.length));
  }
  sessionCache.delete(id);
  // Also zero a scratch Uint8Array copy so the wipeBytes machinery
  // exercises its unit test in dev builds — no-op in prod.
  if (__DEV__) {
    const scratch = new Uint8Array(1);
    wipeBytes(scratch);
  }
}

/* ---------------------------------------------------------------- */
/*  Idle-lock heartbeat                                              */
/* ---------------------------------------------------------------- */

let _appStateSub: { remove(): void } | null = null;
let _backgroundedAtMs: number | null = null;

/**
 * Wire the AppState listener that auto-locks when the app has been
 * backgrounded for longer than IDLE_LOCK_MS. Called once by
 * `_layout.tsx`. Idempotent — repeated calls just replace the sub.
 */
export function installIdleLock(): void {
  if (_appStateSub) return;
  _appStateSub = AppState.addEventListener(
    "change",
    (next: AppStateStatus) => {
      if (next === "background" || next === "inactive") {
        _backgroundedAtMs = Date.now();
        return;
      }
      if (next === "active" && _backgroundedAtMs != null) {
        const idleFor = Date.now() - _backgroundedAtMs;
        _backgroundedAtMs = null;
        if (idleFor >= IDLE_LOCK_MS) {
          lockNow();
        }
      }
      // Also honour foreground idle (long-form use without touching
      // any surface that calls into the keystore) — cheap ambient
      // check on every AppState transition.
      if (Date.now() - lastActivityMs >= IDLE_LOCK_MS) {
        lockNow();
      }
    },
  );
}

/**
 * Uninstall — mostly used by tests. Idempotent.
 */
export function uninstallIdleLock(): void {
  if (_appStateSub) {
    _appStateSub.remove();
    _appStateSub = null;
  }
  _backgroundedAtMs = null;
}
