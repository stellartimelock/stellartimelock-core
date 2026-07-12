// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stellar TimeLock LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Device-key AES-256 encryption (Sprint 18 Phase 1).
//
// Encrypts every note + bill entry BEFORE it hits AsyncStorage. The
// encryption key lives in `expo-secure-store` (iOS Keychain / Android
// Keystore) so it never touches the JS heap dump or a rooted userland
// AsyncStorage inspection.
//
// PHASE 1 model — device-random master key:
//   * On first launch we generate 32 random bytes via `expo-crypto` and
//     stash them in SecureStore. Subsequent launches read the same key.
//   * All ciphertext uses AES-256-CBC with a per-record random 16-byte
//     IV, prefixed to the ciphertext.
//
// PHASE 2 (planned, next sprint) — biometric-gated HKDF derivation:
//   * The device-random master is REPLACED by a HKDF-SHA-256 derivation
//     seeded by the biometric-unlock event. This function's public
//     signature is intentionally stable so the Notebook/Bills stores do
//     NOT need to change when Phase 2 lands — they just call
//     `encrypt(plaintext)` / `decrypt(ciphertext)`.

import * as SecureStore from "expo-secure-store";
import * as Crypto from "expo-crypto";
import CryptoJS from "crypto-js";
import { Platform } from "react-native";

import {
  utf8ToMutableBytes,
  wipeBytes,
  wipeWordArray,
} from "@/src/security/secure-wipe";

// Sprint 23 iter 12 — Shared sentinel thrown by every encrypted
// store's `readAll()` when AsyncStorage has a non-empty ciphertext
// but `decrypt()` returns "". Callers keep their `loading` state
// true so a follow-up mutation never overwrites the ciphertext with
// junk-encrypted `[]` (permanent data loss). See notes-store etc.
export const CRYPTO_NOT_READY = "NOTEBOOK_CRYPTO_NOT_READY";

const MASTER_KEY_STORE_KEY = "xlm_vault_notebook_master_key_v1";
// Sprint 22 iter 60 — Wallet-seed-derived master key (v2). Salt is
// fixed & app-wide; using the wallet's secret seed as the KDF password
// gives us a STABLE 32-byte key that survives:
//   * SecureStore wipe (fresh install / OS Keychain reset)
//   * APK rebuild w/ different signing key (uninstall + reinstall)
//   * Device migration (as long as the user restores the same seed)
// This is the durability fix for the recurring "notes/bills wiped on
// APK rebuild" bug — as soon as the user re-imports the same Stellar
// seed and a Google Drive restore replaces the ciphertext, decryption
// works because the key is regenerable from the seed.
const WALLET_KDF_SALT = "xlm_vault_notebook_v2_salt";
const WALLET_KDF_ITERATIONS = 10000;

let _keyWordArrayCache: CryptoJS.lib.WordArray | null = null;
// Active wallet reference, injected by SessionProvider. When present,
// getKey() derives the master key deterministically from
// wallet.secretSeed. When null we fall back to the legacy Phase-1
// device-random master key (kept so unauth'd flows still function).
let _activeWalletForCrypto: { publicKey: string; secretSeed: string } | null =
  null;

/**
 * Register (or clear) the wallet the notebook layer should key-derive
 * from. Called by SessionProvider whenever the active wallet changes
 * so a switch-wallet or fresh-import immediately rotates the notebook
 * key. Passing `null` clears the ref and drops the cache.
 */
export function setActiveWalletForCrypto(
  wallet: { publicKey: string; secretSeed: string } | null,
): void {
  const prevKey = _activeWalletForCrypto?.secretSeed ?? null;
  const nextKey = wallet?.secretSeed ?? null;
  if (prevKey !== nextKey) {
    // Sprint 23 iter 22 — wipe the previous derived AES key before
    // dropping the reference, so switching wallets doesn't leave
    // the old key sitting in the heap.
    const prev = _keyWordArrayCache;
    _keyWordArrayCache = null;
    wipeWordArray(prev);
  }
  _activeWalletForCrypto = wallet;
}

/** 32 random bytes — first-launch generation of the master key. */
async function generateMasterKeyBase64(): Promise<string> {
  const bytes = await Crypto.getRandomBytesAsync(32);
  // Convert Uint8Array → base64 without pulling in Buffer.
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  // btoa is available in Hermes (RN 0.71+) and web.
  return (global as unknown as { btoa: (s: string) => string }).btoa(binary);
}

/**
 * Copy a mutable Uint8Array into a fresh CryptoJS WordArray so
 * PBKDF2 can consume it via the WordArray overload (which never
 * touches the source string engine internals). The returned
 * WordArray owns its own words[] backing store and can be wiped
 * independently of the source bytes.
 */
function wordsFromBytes(bytes: Uint8Array): CryptoJS.lib.WordArray {
  const words: number[] = [];
  for (let i = 0; i < bytes.length; i += 4) {
    words.push(
      ((bytes[i] ?? 0) << 24) |
        ((bytes[i + 1] ?? 0) << 16) |
        ((bytes[i + 2] ?? 0) << 8) |
        (bytes[i + 3] ?? 0),
    );
  }
  return CryptoJS.lib.WordArray.create(words, bytes.length);
}

async function readOrCreateMasterKey(): Promise<string> {
  // Web fallback — SecureStore is not available. We fall back to a
  // deterministic per-origin key derived from a stable browser secret.
  // The web preview is intentionally NOT the trust boundary; users
  // ship real vaults on native builds where SecureStore is enforced.
  if (Platform.OS === "web") {
    const w = globalThis as unknown as {
      localStorage?: { getItem(k: string): string | null; setItem(k: string, v: string): void };
    };
    if (!w.localStorage) return "web-fallback-key-plaintext-only";
    const existing = w.localStorage.getItem(MASTER_KEY_STORE_KEY);
    if (existing) return existing;
    const created = await generateMasterKeyBase64();
    w.localStorage.setItem(MASTER_KEY_STORE_KEY, created);
    return created;
  }

  try {
    const existing = await SecureStore.getItemAsync(MASTER_KEY_STORE_KEY);
    if (existing && existing.length >= 40) return existing;
  } catch {
    /* fall through to generation */
  }
  const created = await generateMasterKeyBase64();
  try {
    await SecureStore.setItemAsync(MASTER_KEY_STORE_KEY, created, {
      keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
  } catch {
    /* proceed with in-memory key — encryption still works this session */
  }
  return created;
}

async function getKey(): Promise<CryptoJS.lib.WordArray> {
  if (_keyWordArrayCache) return _keyWordArrayCache;
  // Sprint 22 iter 60 — PRIMARY path: wallet-seed-derived key.
  // As long as the same Stellar secret seed is imported (via seed
  // phrase restore OR Google Drive backup blob), the KDF produces
  // the same 32-byte key. This makes notebook/bills content survive
  // APK rebuild, uninstall/reinstall, and device migration — the
  // failure mode the user reported (data-loss on APK rebuild) is
  // rooted in SecureStore/AsyncStorage being wiped by Android; the
  // deterministic derivation ensures we can decrypt any ciphertext
  // that gets restored to the new install (e.g. via Drive backup).
  if (_activeWalletForCrypto?.secretSeed) {
    // Sprint 23 iter 22 — Feed PBKDF2 via a mutable byte buffer so we
    // can zero every intermediate copy the moment the derivation
    // finishes. We can't zero the source `secretSeed` string (JS
    // strings are immutable) — but by materialising it into a
    // dedicated Uint8Array + WordArray we ensure the SECOND copy of
    // the seed (the one crypto-js reads from) lives for microseconds,
    // not for the entire session.
    const seedBytes = utf8ToMutableBytes(_activeWalletForCrypto.secretSeed);
    // WordArray.create(bytes) copies the buffer into a fresh
    // 32-bit-word array; we still wipe both to be safe.
    const seedWords = wordsFromBytes(seedBytes);
    const saltWords = CryptoJS.enc.Utf8.parse(WALLET_KDF_SALT);
    let derived: CryptoJS.lib.WordArray | null = null;
    try {
      derived = CryptoJS.PBKDF2(seedWords, saltWords, {
        keySize: 256 / 32,
        iterations: WALLET_KDF_ITERATIONS,
      });
      _keyWordArrayCache = derived;
      return _keyWordArrayCache;
    } finally {
      // Zero every intermediate carrier of the seed. The DERIVED key
      // stays in `_keyWordArrayCache` (that IS the AES key, and its
      // lifetime is intentionally session-scoped); everything else is
      // scrubbed here.
      wipeWordArray(seedWords);
      wipeBytes(seedBytes);
    }
  }
  // LEGACY fallback — pre-wallet or no-wallet callers. Kept so early
  // boot paths (before session mounts) still function; once the
  // wallet is set via setActiveWalletForCrypto() the cache is
  // invalidated and the KDF path takes over.
  const b64 = await readOrCreateMasterKey();
  _keyWordArrayCache = CryptoJS.enc.Base64.parse(b64);
  return _keyWordArrayCache;
}

/**
 * Reset the in-memory key cache. Called by the biometric enroll /
 * unenroll flow so a subsequent read/write picks up the new key
 * material without a full app restart.
 *
 * Sprint 23 iter 22 — Also zeroes the derived AES key bytes in the
 * previous cached WordArray before dropping the reference, so a
 * post-logout heap dump can't recover the notebook AES key.
 */
export function resetKeyCache(): void {
  const prev = _keyWordArrayCache;
  _keyWordArrayCache = null;
  wipeWordArray(prev);
}

/**
 * Encrypt an arbitrary UTF-8 string. Output layout: base64(iv) + "." +
 * base64(ciphertext). The "." delimiter is safe because base64 never
 * produces `.`.
 */
export async function encrypt(plaintext: string): Promise<string> {
  const key = await getKey();
  // 16-byte random IV per record — CBC requires this to be unique and
  // unpredictable.
  const ivBytes = await Crypto.getRandomBytesAsync(16);
  const ivWords: number[] = [];
  for (let i = 0; i < ivBytes.length; i += 4) {
    ivWords.push(
      (ivBytes[i] << 24) |
      (ivBytes[i + 1] << 16) |
      (ivBytes[i + 2] << 8) |
      ivBytes[i + 3],
    );
  }
  const iv = CryptoJS.lib.WordArray.create(ivWords, 16);
  const ct = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(plaintext), key, {
    iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });
  return `${iv.toString(CryptoJS.enc.Base64)}.${ct.ciphertext.toString(CryptoJS.enc.Base64)}`;
}

export async function decrypt(payload: string): Promise<string> {
  if (!payload || payload.indexOf(".") < 0) return "";
  const [ivB64, ctB64] = payload.split(".", 2);
  const key = await getKey();
  const iv = CryptoJS.enc.Base64.parse(ivB64);
  const ct = CryptoJS.enc.Base64.parse(ctB64);
  const decrypted = CryptoJS.AES.decrypt(
    CryptoJS.lib.CipherParams.create({ ciphertext: ct }),
    key,
    { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 },
  );
  return decrypted.toString(CryptoJS.enc.Utf8);
}

/**
 * Convenience: probe whether a ciphertext string is at least
 * syntactically valid. Used by the Notebook UI to distinguish a
 * corrupted payload from a first-launch empty state.
 */
export function isEncryptedPayload(s: string): boolean {
  if (typeof s !== "string" || s.length < 32) return false;
  const dot = s.indexOf(".");
  if (dot < 8) return false;
  // Base64 alphabet check on both halves (loose but sufficient).
  const b64 = /^[A-Za-z0-9+/=]+$/;
  return b64.test(s.slice(0, dot)) && b64.test(s.slice(dot + 1));
}
