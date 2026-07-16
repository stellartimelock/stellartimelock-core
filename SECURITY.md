# Security Overview — Stellar TimeLock

Copyright 2026 Stellar TimeLock LLC. Licensed under the
Apache License, Version 2.0. See `/LICENSE` for the full text.

This document is the plain-English summary of the security-critical
subsystems in the Stellar TimeLock mobile application. It is targeted
at open-source auditors, security researchers, and contributors who
need to reason about the trust boundary before touching the code.

If you find a vulnerability, please **do not** open a public GitHub
issue. Email `Stellartimelock@Gmail.com` with a description and
reproduction steps. We aim to acknowledge reports within 72 hours.

The canonical home for this document (and the four security modules
it describes) is
[`github.com/StellarTimeLock/stellartimelock-core`](https://github.com/StellarTimeLock/stellartimelock-core).

---

## 1. Threat model

**In scope**

- Local attackers with physical access to a **locked** device.
- Remote attackers who compromise a paired cloud backup (Google
  Drive `appdata` folder).
- Rooted / jailbroken devices attempting **post-hoc heap-dump
  recovery** of the wallet seed.
- Malicious tampering with the on-device address book, notes, or
  ledger records.

**Explicitly out of scope**

- Live in-process attackers (root + hooked JS runtime). Once code
  is executing inside the app process, all bets are off — that's a
  device compromise, not an app-level vulnerability.
- Attacks on the Stellar network protocol itself.
- Attacks on Google's / Apple's authentication systems.

---

## 2. Memory zeroing after signing and PBKDF2 derivation

**Implementation:** `src/security/secure-wipe.ts`

JavaScript strings are immutable. Once a secret seed is materialised
as a `string`, the bytes backing it are at the mercy of the
garbage collector (and, on Hermes / V8, may be interned into the
engine's string table where user code has no reach).

What we **can** control is every mutable byte copy we make along the
way — `Uint8Array`, `Buffer`, `crypto-js` `WordArray`, and the two
private `_secretSeed` / `_secretKey` fields inside the Stellar SDK
`Keypair`. All of those are zeroed **the moment we finish signing
or deriving**:

- `wipeBytes(buf)` — in-place `Uint8Array.fill(0)`.
- `wipeWordArray(wa)` — zeros `words[]` and resets `sigBytes = 0`.
- `wipeKeypair(kp)` — reflectively reaches the SDK's private
  fields and zeros both.

The narrower this window, the less material a heap dump on a rooted
device can recover.

**Verified with Node smoke tests:**

- `Uint8Array.fill(0)` mutates the backing `ArrayBuffer` in place.
- Stellar SDK `Keypair._secretSeed` + `_secretKey` are indeed
  mutable `Uint8Array`s and become all-zero after `wipeKeypair()`.
- PBKDF2 output is byte-identical between the legacy string-input
  path and the new mutable-bytes path — proving the refactor did
  not corrupt existing encrypted archives.

**Documented limitations:**

- We cannot zero source JS strings (immutable).
- We cannot defend against a live in-process attacker.
- Hermes / V8 may retain string-table copies opaque to user code.

This is defense-in-depth, not a formal guarantee.

---

## 3. Biometric-bound wallet seed (Android Keystore / iOS Keychain)

**Implementation:** `src/security/session-keystore.ts`

Prior to sprint 23 iter 23, the wallet seed was stored in
`expo-secure-store` with **no `requireAuthentication` flag**. That
meant a rooted attacker who could read Android's
`EncryptedSharedPreferences` — or iOS Keychain with the app's
entitlements — could recover the seed **without** a fresh biometric
scan. The in-app biometric gate (`BiometricGate.tsx`) protected only
the UI, never the underlying material.

The current implementation:

1. **Hardware-bound storage.** Every write of the wallet seed uses
   `secureSetAuthenticated`, which sets `requireAuthentication: true`
   on `expo-secure-store`. This translates to
   `KeyGenParameterSpec.setUserAuthenticationRequired(true)` in
   Android Keystore and the equivalent `LAContext`-guarded
   `SecAccessControl` on iOS. The OS refuses to release the seed
   until the user completes a fresh biometric scan.
2. **Session cache.** Once decrypted, the seed is held in an
   in-memory `Map` for the remainder of the app process. Users are
   prompted **once per cold-start / unlock**, not on every notebook
   decrypt / auto-sync / signing operation. The cache is cleared on
   explicit `lockNow()`, extended background (idle-lock heartbeat
   > 5 min), or wallet switch.
3. **Soft migration.** Legacy installs stored the seed with no auth
   flag. On the first read after upgrading, we detect the legacy
   layout, read the seed with the non-auth API, then **immediately
   rewrite it under the authenticated variant**. Users experience a
   single biometric prompt at the tail of the migration write; from
   that point on the Keystore is bound.

**Scope:** Wallet seed only. The notebook AES key is derived from
the seed via PBKDF2 and cached in-memory only.

---

## 4. PBKDF2 envelope encryption for on-device data

**Implementation:** `src/notebook/crypto.ts`

Notes, bills, ledger entries, and TOTP secrets are AES-encrypted
before ever touching `AsyncStorage` or Google Drive.

- **KDF:** PBKDF2-HMAC-SHA1 with **10,000 iterations**, 32-byte
  output, 8-byte fixed salt.
- **Input material:** the active wallet's Stellar secret seed
  (56 chars, base32) — never a user-typed password.
- **Cipher:** AES-256 in the CryptoJS default (CBC + PKCS7 padding)
  with a random 16-byte IV per record.

Why derive from the wallet seed rather than a user password?

- The wallet seed is already the single strongest secret the user
  possesses; asking for a second password would just create
  another lower-entropy vector.
- Any GDrive or manual-JSON backup is useless without the seed —
  which matches user intuition ("if I lose my seed I lose
  everything").

**Intermediate zeroing.** The seed → PBKDF2 input path uses a
mutable `Uint8Array` and a fresh `WordArray` so both can be wiped
immediately after the derive completes. The derived AES key is
cached in-memory for the session and is itself zeroed on logout
via `resetKeyCache()`.

**Backup restoration is byte-identical** to the legacy string-input
path — verified with a Node smoke test — so existing user archives
remain fully decryptable after every hardening iteration.

---

## 5. `allowBackup="false"` on Android

Set in `frontend/app.json` under `expo.android.allowBackup`.
Prevents Android's system-wide backup service (`adb backup` and
Google Auto Backup) from writing an unencrypted copy of the app's
private data directory to the cloud.

Without this flag, an attacker who compromises the user's Google
account could pull the entire app data — including the
`EncryptedSharedPreferences` backing SecureStore — off the backup
service. Setting it to `false` makes the OS skip this file set
during backup entirely.

---

## 6. Public-key verification on wallet load

**Implementation:** `src/wallet/wallet-book.ts`

`loadKeypair(id)` reads the seed from SecureStore, **derives the
ed25519 public key from the seed**, and refuses to return the
keypair if it does not match the book entry's declared
`publicKey`. This closes a cross-assignment class of bug where the
book row's label + publicKey could drift out of sync with the
SecureStore seed under the same id — for instance, if a partial
write during a restore corrupted the invariant.

Signing with a keypair whose public key does not match the wallet
the user sees on screen would be catastrophic (funds sent to an
unlabelled address, incorrect memo binding, etc.). The check is
cheap (one ed25519 base-point multiplication) and fires on every
load path.

---

## 7. Local-only secrets — no server transit

The backend (FastAPI + MongoDB) is **not** the trust anchor for any
user data. It caches only:

- XLM price rates keyed by fiat currency.
- Non-sensitive swap-partner exchange metadata (ticker maps, pair
  quotes, transaction status polling).

The following NEVER leave the device unencrypted:

- Wallet secret seeds.
- Notes, bills, ledger entries, TOTP secrets, address book.
- Biometric root-secret.
- Vault unlock schedules.

Google Drive backups are envelope-encrypted client-side with the
seed-derived key before upload; Drive sees ciphertext only.

---

## 8. Analytics privacy

**Implementation:** `src/analytics/firebase.ts`

Firebase Analytics + Crashlytics are wired for release builds but
constrained by a **whitelisted `AppEvent` union** in TypeScript. The
type system refuses to compile any event that isn't already listed.
The current whitelist:

- `wallet_created` (method: burner / imported)
- `wallet_imported` (already_present: bool)
- `vault_locked`
- `backup_synced` (target: gdrive / manual_json, ok: bool)
- `ledger_entry_added` (surface: detailed / quick / bulk_import,
  kind: profit / loss)

No PII, no addresses, no amounts, no seeds, no memos. Every new
event must edit the union, forcing a code review as a privacy
gate.

---

## 9. Reporting vulnerabilities

Please email `Stellartimelock@Gmail.com` with:

- A clear description of the issue.
- Steps to reproduce.
- The Stellar TimeLock version and platform (Android / iOS).
- A suggested severity if possible.

We prefer PGP-encrypted mail — fingerprint will be published once the
project website goes live.

Coordinated disclosure timeline:

- **Day 0:** Acknowledged within 72 hours.
- **Day 30:** Patch drafted.
- **Day 60:** Patch shipped in a coordinated release.
- **Day 90:** Public advisory (CVE if warranted).

Thank you for responsibly disclosing.

---

<details>
<summary>System Diagnostics: Run Integrity Check</summary>
<br>

⚠️ *If your number's up... we'll find you.*

`[ADMIN SYSTEM]: The Machine is active. Formulating next sequence.`

</details>
