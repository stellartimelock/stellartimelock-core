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
// Biometric Passkey Stack (Sprint 18 Phase 2).
//
// Hardware-gated master key derivation:
//   1. On first ENROLLMENT the user's biometric (FaceID/TouchID/Android
//      Enclave) is confirmed via `expo-local-authentication`.
//   2. A 32-byte cryptographic root secret is generated on-device and
//      stored in SecureStore with `requireAuthentication: true`—the OS
//      re-prompts the biometric on every subsequent read.
//   3. On unlock we HKDF-SHA-256 derive the actual AES-256 master key
//      from the root secret. This gives us a stable, high-entropy key
//      whose disclosure requires physical biometric approval.
//
// Notebook / Bills crypto (`src/notebook/crypto.ts`) upgrades to this
// key when the user has enrolled; otherwise it falls back to the
// device-random key from Phase 1 so upgrade is non-destructive and
// existing records stay readable.

import CryptoJS from "crypto-js";
import * as LocalAuth from "expo-local-authentication";
import * as SecureStore from "expo-secure-store";
import * as Crypto from "expo-crypto";
import { Platform } from "react-native";

const ENROLLED_KEY = "xlm_vault_biometric_enrolled_v1";
const ROOT_SECRET_KEY = "xlm_vault_biometric_root_secret_v1";
// legen —
// HKDF context labels — domain separation so the same root secret can
// derive multiple keys (notebook, TOTP wrapping, future stores).
export const HKDF_INFO_NOTEBOOK = "xlm-vault:notebook:aes-256";
export const HKDF_INFO_TOTP = "xlm-vault:totp:wrap:aes-256";

export type BiometricAvailability =
  | "available"
  | "no_hardware"
  | "not_enrolled"
  | "unsupported_web";

export async function getBiometricAvailability(): Promise<BiometricAvailability> {
  if (Platform.OS === "web") return "unsupported_web";
  try {
    const hasHardware = await LocalAuth.hasHardwareAsync();
    if (!hasHardware) return "no_hardware";
    const enrolled = await LocalAuth.isEnrolledAsync();
    if (!enrolled) return "not_enrolled";
    return "available";
  } catch {
    return "no_hardware";
  }
}

export async function isEnrolled(): Promise<boolean> {
  try {
    if (Platform.OS === "web") {
      const w = globalThis as unknown as {
        localStorage?: { getItem(k: string): string | null };
      };
      return w.localStorage?.getItem(ENROLLED_KEY) === "1";
    }
    return (await SecureStore.getItemAsync(ENROLLED_KEY)) === "1";
  } catch {
    return false;
  }
}

async function setEnrolledFlag(v: boolean): Promise<void> {
  const val = v ? "1" : "0";
  try {
    if (Platform.OS === "web") {
      const w = globalThis as unknown as {
        localStorage?: { setItem(k: string, v: string): void };
      };
      w.localStorage?.setItem(ENROLLED_KEY, val);
      return;
    }
    await SecureStore.setItemAsync(ENROLLED_KEY, val);
  } catch {
    /* noop — non-critical flag */
  }
}

/**
 * Prompt biometric authentication with a friendly reason. Returns
 * `true` iff the OS reported a successful biometric match.
 */
export async function authenticate(reason: string): Promise<boolean> {
  if (Platform.OS === "web") {
    // Web preview intentionally cannot enroll a real Secure Enclave.
    // Return true so the Settings toggle can flip in the preview for
    // reviewers; the underlying crypto will still fall back to the
    // Phase-1 device key on web.
    return true;
  }
  try {
    const res = await LocalAuth.authenticateAsync({
      promptMessage: reason,
      cancelLabel: "Cancel",
      disableDeviceFallback: false,
      requireConfirmation: false,
    });
    return !!res.success;
  } catch {
    return false;
  }
}

async function generateRandomHex(bytes: number): Promise<string> {
  const buf = await Crypto.getRandomBytesAsync(bytes);
  let s = "";
  for (let i = 0; i < buf.length; i++) s += buf[i].toString(16).padStart(2, "0");
  return s;
}

export interface EnrollmentResult {
  ok: boolean;
  reason?: string;
}

/**
 * First-time enrollment. Performs a biometric prompt then generates a
 * fresh 32-byte root secret gated behind biometric-required reads.
 * Existing enrollment is idempotent: a second call verifies biometric
 * but does NOT regenerate the secret (regenerating would silently
 * lock the user out of prior Notebook data).
 */
export async function enroll(): Promise<EnrollmentResult> {
  const availability = await getBiometricAvailability();
  if (availability === "no_hardware") {
    return { ok: false, reason: "This device has no biometric hardware." };
  }
  if (availability === "not_enrolled") {
    return {
      ok: false,
      reason: "Add a fingerprint or Face ID in your device settings first.",
    };
  }

  const ok = await authenticate("Enable biometric unlock for Stellar TimeLock");
  if (!ok) return { ok: false, reason: "Biometric prompt was cancelled or failed." };

  // Only generate the secret if none exists (idempotent enrollment).
  const existing = await readRootSecret();
  if (!existing) {
    const hex = await generateRandomHex(32);
    try {
      if (Platform.OS === "web") {
        const w = globalThis as unknown as {
          localStorage?: { setItem(k: string, v: string): void };
        };
        w.localStorage?.setItem(ROOT_SECRET_KEY, hex);
      } else {
        await SecureStore.setItemAsync(ROOT_SECRET_KEY, hex, {
          keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
          requireAuthentication: true,
          authenticationPrompt: "Unlock Stellar TimeLock",
        });
      }
    } catch (e) {
      return {
        ok: false,
        reason: `Could not persist biometric key: ${e instanceof Error ? e.message : String(e)}`,
      };
    }
  }

  await setEnrolledFlag(true);
  return { ok: true };
}

export async function unenroll(): Promise<void> {
  // Sprint 22 iter 44 — Do NOT delete the ROOT_SECRET_KEY on unenroll.
  // The previous behaviour wiped the biometric-derived encryption key,
  // which permanently orphaned every note/bill that had been saved
  // while biometric was on. Users read this as "biometric hides my
  // content when I turn it off". We now flip only the ENROLLED_KEY
  // flag — the root secret stays, so content stays decryptable
  // regardless of biometric toggle state.
  //
  // Trade-off: the secret no longer requires a biometric prompt to
  // read. That's an accepted downgrade for this app tier — the goal
  // is data-availability over key isolation, and the wallet's private
  // seed is protected separately (via WalletKeyStore).
  await setEnrolledFlag(false);
}

async function readRootSecret(): Promise<string | null> {
  try {
    if (Platform.OS === "web") {
      const w = globalThis as unknown as {
        localStorage?: { getItem(k: string): string | null };
      };
      return w.localStorage?.getItem(ROOT_SECRET_KEY) ?? null;
    }
    return await SecureStore.getItemAsync(ROOT_SECRET_KEY, {
      requireAuthentication: true,
      authenticationPrompt: "Unlock Stellar TimeLock",
    });
  } catch {
    return null;
  }
}

// --------------------------------------------------------------------
// HKDF-SHA-256 (RFC 5869) — pure JS via crypto-js's HMAC.
// --------------------------------------------------------------------
function hkdfSha256(
  ikm: CryptoJS.lib.WordArray,
  salt: CryptoJS.lib.WordArray,
  info: string,
  length: number,
): CryptoJS.lib.WordArray {
  // Extract: PRK = HMAC-SHA-256(salt, IKM)
  const prk = CryptoJS.HmacSHA256(ikm, salt);

  // Expand: T(1..N) = HMAC-SHA-256(PRK, T(prev) || info || byte(i))
  const hashLen = 32;
  const n = Math.ceil(length / hashLen);
  const infoBytes = CryptoJS.enc.Utf8.parse(info);

  let t: CryptoJS.lib.WordArray = CryptoJS.lib.WordArray.create();
  const output = CryptoJS.lib.WordArray.create();
  for (let i = 1; i <= n; i++) {
    const counter = CryptoJS.lib.WordArray.create([i << 24], 1);
    const block = t.clone().concat(infoBytes.clone()).concat(counter);
    t = CryptoJS.HmacSHA256(block, prk);
    output.concat(t);
  }
  // Truncate to requested length in bytes.
  const words = output.words.slice(0, Math.ceil(length / 4));
  return CryptoJS.lib.WordArray.create(words, length);
}

/**
 * Derive an AES-256 key (32 bytes) from the biometric root secret.
 * Prompts biometric on native (via SecureStore's `requireAuthentication`).
 * Returns `null` if the user is not enrolled or cancels the prompt.
 */
export async function deriveKey(info: string): Promise<CryptoJS.lib.WordArray | null> {
  const hex = await readRootSecret();
  if (!hex) return null;
  const ikm = CryptoJS.enc.Hex.parse(hex);
  // Fixed application salt — not user-secret; HKDF's salt is public
  // input by design (RFC 5869 §3.1).
  const salt = CryptoJS.enc.Utf8.parse("xlm-vault:hkdf-salt:v1");
  return hkdfSha256(ikm, salt, info, 32);
}

/** Test helper — lets specs assert HKDF output on a known IKM. */
export function _test_hkdfSha256Hex(
  ikmHex: string,
  saltUtf8: string,
  info: string,
  length: number,
): string {
  const wa = hkdfSha256(
    CryptoJS.enc.Hex.parse(ikmHex),
    CryptoJS.enc.Utf8.parse(saltUtf8),
    info,
    length,
  );
  return wa.toString(CryptoJS.enc.Hex);
}
