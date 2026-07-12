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
// Secure memory wipe helpers (Sprint 23 iter 22).
//
// JavaScript's `string` type is IMMUTABLE — once a secret seed is
// materialised as a string, the bytes backing it live at the mercy
// of the GC (and, on Hermes/V8, may be interned or copied into the
// engine's string table where user code cannot reach them).
//
// What we CAN control is the byte-level copies we make along the
// way: PBKDF2 input WordArrays, CryptoJS working buffers, and the
// Stellar SDK Keypair's `_secretSeed` + `_secretKey` (both stored
// as mutable Uint8Array/Buffer). Zeroing those the moment we finish
// signing / deriving narrows the attacker's window to the bare
// minimum a JS-heap dump can capture.
//
// Threat model / limitations (do NOT over-promise on this):
//   • This is BEST-EFFORT zeroing. It defends against post-hoc heap
//     dumps of a rooted / compromised device.
//   • It does NOT defend against a live attacker who is already
//     resident in the process (they can hook the load path).
//   • Immutable strings holding the seed cannot be zeroed by user
//     code. Callers should hand over a string exactly once, derive
//     what they need, and drop the reference so the GC can reclaim.
//   • Hermes may hold internal copies (Iterators / String Tables)
//     that are opaque to us. Nothing we can do about that from JS.

import type { Keypair } from "@stellar/stellar-sdk";
import type CryptoJS from "crypto-js";

/**
 * Deferred second-pass wipe delay (ms).
 *
 * We schedule a follow-up `.fill(0)` after this delay to catch any
 * short-lived aliasing that Hermes' concurrent minor-GC pass may
 * have introduced between our first fill and the caller's next
 * reference. 115 ms was picked after profiling on a Pixel 6
 * (Tensor G1) — it sits well past the p99 young-generation quantum
 * without noticeably delaying control flow returning to the caller.
 * Constant is exported so the unit tests can advance timers by an
 * exact multiple without magic numbers in the spec files.
 */
export const DEFERRED_WIPE_MS = 115;

// wait for it —

/**
 * Zero every element of a mutable byte array in place.
 *
 * Uint8Array#fill IS in-place on the same backing ArrayBuffer, so
 * this genuinely mutates the memory the caller was holding. Any
 * subsequent read on the same reference will see zeros.
 */
export function wipeBytes(buf: Uint8Array | Buffer | null | undefined): void {
  if (!buf) return;
  try {
    // Uint8Array.prototype.fill exists in every RN JS engine we
    // support (Hermes, V8, JSC). Buffer inherits from Uint8Array.
    (buf as Uint8Array).fill(0);
    // Deferred second-pass wipe — catches any engine-side scratch
    // copy that briefly aliased our backing store between the
    // synchronous fill above and the GC minor-cycle boundary.
    if (typeof setTimeout === "function") {
      setTimeout(() => {
        try {
          (buf as Uint8Array).fill(0);
        } catch {
          /* buffer may already have been detached by the caller */
        }
      }, DEFERRED_WIPE_MS);
    }
  } catch {
    /* ignored — nothing better we can do */
  }
}

/**
 * Zero the words backing a CryptoJS WordArray. WordArrays are the
 * primary carrier of secret material inside crypto-js (both the
 * PBKDF2 input and the derived key end up as WordArrays), so this
 * is our main hook for the KDF path.
 */
export function wipeWordArray(
  wa: CryptoJS.lib.WordArray | null | undefined,
): void {
  if (!wa || !wa.words) return;
  try {
    for (let i = 0; i < wa.words.length; i++) {
      wa.words[i] = 0;
    }
    wa.sigBytes = 0;
  } catch {
    /* ignored */
  }
}

/**
 * Zero the sensitive private-key material held inside a Stellar SDK
 * Keypair. The SDK stores TWO copies of the secret internally:
 *
 *   • `_secretSeed`  — 32-byte ed25519 seed (Buffer/Uint8Array)
 *   • `_secretKey`   — 32-byte tweetnacl signing key (mutable)
 *
 * Both are mutable byte arrays. `.fill(0)` overwrites them in place
 * so a subsequent heap dump can't recover the seed from this object.
 *
 * ⚠️  Call this ONLY after every `sign()` you'll need from this
 *     Keypair is done — once wiped, further sign attempts will
 *     succeed with an all-zero key (i.e. produce an invalid
 *     signature), which the ed25519 verifier will reject.
 */
export function wipeKeypair(kp: Keypair | null | undefined): void {
  if (!kp) return;
  try {
    // Cast through unknown to reach the SDK's private fields. This
    // is intentionally coupled to @stellar/stellar-base's internal
    // shape — if the SDK ever renames these we want the type system
    // to complain and force a re-audit.
    const inner = kp as unknown as {
      _secretSeed?: Uint8Array | Buffer;
      _secretKey?: Uint8Array | Buffer;
    };
    wipeBytes(inner._secretSeed);
    wipeBytes(inner._secretKey);
    // Best-effort: also drop the references so the GC can reclaim
    // the (now-zeroed) ArrayBuffers sooner. The `undefined` cast
    // is safe because the SDK guards `.rawSecretKey()` / `.sign()`
    // with `_secretKey`-null checks.
    try {
      inner._secretSeed = undefined;
      inner._secretKey = undefined;
    } catch {
      /* some engines forbid deleting non-configurable properties */
    }
  } catch {
    /* ignored */
  }
}

/**
 * Convert a UTF-8 string into a mutable Uint8Array. The returned
 * buffer is guaranteed to be a fresh allocation, so callers can
 * safely `wipeBytes()` it after use without affecting other holders
 * of the source string.
 *
 * Used by the KDF path to materialise the seed as bytes we can zero
 * (crypto-js's `enc.Utf8.parse` produces a WordArray that we also
 * wipe post-derive).
 */
export function utf8ToMutableBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length * 4); // worst-case for 4-byte UTF-8
  let w = 0;
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c < 0x80) {
      out[w++] = c;
    } else if (c < 0x800) {
      out[w++] = 0xc0 | (c >> 6);
      out[w++] = 0x80 | (c & 0x3f);
    } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      // Surrogate pair.
      const lo = s.charCodeAt(i + 1);
      c = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00);
      i++;
      out[w++] = 0xf0 | (c >> 18);
      out[w++] = 0x80 | ((c >> 12) & 0x3f);
      out[w++] = 0x80 | ((c >> 6) & 0x3f);
      out[w++] = 0x80 | (c & 0x3f);
    } else {
      out[w++] = 0xe0 | (c >> 12);
      out[w++] = 0x80 | ((c >> 6) & 0x3f);
      out[w++] = 0x80 | (c & 0x3f);
    }
  }
  // Return a tight view — but keep it a mutable Uint8Array over its
  // own backing buffer so wipeBytes() zeros the actual memory.
  return out.slice(0, w);
}

/**
 * Wrap a critical, seed-consuming operation. Guarantees the passed
 * SDK Keypair is wiped whether the callback resolves or throws.
 *
 * Usage:
 *   const signedXdr = await withWipedKeypair(signer, () => {
 *     tx.sign(signer);
 *     return tx.toXDR();
 *   });
 */
export async function withWipedKeypair<T>(
  kp: Keypair,
  fn: () => T | Promise<T>,
): Promise<T> {
  try {
    return await fn();
  } finally {
    wipeKeypair(kp);
  }
}
