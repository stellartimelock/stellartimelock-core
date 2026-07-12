# stellartimelock-core

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Release](https://img.shields.io/github/v/release/StellarTimeLock/stellartimelock-core?display_name=tag&sort=semver)](https://github.com/StellarTimeLock/stellartimelock-core/releases)
[![Platform](https://img.shields.io/badge/platform-Android_%7C_iOS-lightgrey.svg)](#)
[![Security policy](https://img.shields.io/badge/security-policy-brightgreen.svg)](./SECURITY.md)

**Open-source security modules powering the Stellar TimeLock mobile wallet.**

Copyright © 2026 Stellar TimeLock LLC — licensed under Apache License 2.0
(see [`LICENSE`](./LICENSE)).

---

## What is Stellar TimeLock?

Stellar TimeLock is a non-custodial mobile wallet for the Stellar network
with a focus on **irrevocable time-locked savings**. Users generate or
import a Stellar keypair on-device, then lock XLM into a Soroban smart
contract with an unlock timestamp. Until that timestamp passes, the
funds cannot be withdrawn — not by the user, not by the developer, not
by anyone. There is **no admin key, no emergency exit, no rug pull
lever**.

Additional in-app features:

- **Encrypted notebook** — notes, recurring-bill calendar, and P&L ledger
  sealed with device-derived AES-256 before touching local storage or
  any cloud backup.
- **Built-in TOTP authenticator** — biometric-gated 2FA codes for the
  user's existing accounts. Codes live encrypted alongside the notebook.
- **Encrypted JSON + Google Drive backups** — envelope-encrypted
  client-side; the cloud sees ciphertext only.
- **Memo enforcement** — the wallet blocks sends to exchange / casino
  addresses when a memo is required. No more permanently lost deposits.
- **Instant swap** — powered by Changelly, no accounts required.

The full app is **coming to Google Play**. Follow this repo for release
announcements.

---

## Why open-source the security modules?

Cryptography that has not been publicly reviewed is cryptography you
should not trust with your savings. This repository publishes the
subset of the wallet's source code that is security-critical, under
Apache 2.0, so that:

1. Security researchers can audit the key-derivation, session-cache,
   and memory-zeroing paths without needing an APK reverse-engineering
   session.
2. Downstream projects can reuse the modules (with attribution) rather
   than reimplementing subtly-wrong versions.
3. Users of the wallet have a durable, third-party-visible artefact
   they can point at to answer "how does this thing actually protect
   my seed?"

The full [`SECURITY.md`](./SECURITY.md) walks through the threat model,
the design of each module, and the known limitations.

---

## What's in this repo (open source)

| Path | Purpose |
| ---- | ------- |
| [`src/security/secure-wipe.ts`](./src/security/secure-wipe.ts) | Best-effort in-place zeroing of Uint8Array / Buffer / crypto-js WordArray / Stellar SDK Keypair private fields — used after every signing or KDF call. |
| [`src/security/session-keystore.ts`](./src/security/session-keystore.ts) | Session-scoped wallet-seed cache with Android Keystore / iOS Keychain-bound persistence. One biometric prompt per unlock. |
| [`src/security/biometric.ts`](./src/security/biometric.ts) | Biometric enrolment, hardware-gated root-secret storage, and HKDF-SHA-256 key derivation for the notebook AES key. |
| [`src/notebook/crypto.ts`](./src/notebook/crypto.ts) | AES-256-CBC envelope encryption for notes, bills, ledger entries, TOTP secrets, and address book. PBKDF2 KDF from the wallet seed. |
| [`src/wallet/horizon.ts`](./src/wallet/horizon.ts) | Stellar Horizon client — account balance, spendable-balance protocol math, transaction history, payment lookups. Read-only, on-chain public data only. |
| [`src/api/soroban-client.ts`](./src/api/soroban-client.ts) | Soroban RPC write client for the deployed XlmVault contract — vault creation, deposit, withdraw, and unlock-date extension. All calls verifiable on stellar.expert. |
| [`src/api/soroban-errors.ts`](./src/api/soroban-errors.ts) | Structured error decoding for the build → simulate → submit → poll pipeline. Maps Soroban ScVal error codes to human-readable diagnostics. |
| [`backend/changelly.py`](./backend/changelly.py) | Changelly instant-swap integration (FastAPI). Signed JSON-RPC requests, partner attribution, quote + createTransaction flows. Publicly-inspectable HTTP surface — no proprietary logic. |
| [`SECURITY.md`](./SECURITY.md) | Full threat model + subsystem design writeup. Please read before filing any vulnerability report. |
| [`LICENSE`](./LICENSE) | Apache License, Version 2.0. |

Every file carries an `SPDX-License-Identifier: Apache-2.0` header and
a copyright notice at the top.

---

## What is NOT in this repo (closed source)

The following live in the private application repository and are
**intentionally not published**:

- **UI code** — screens, navigation, animations, theme (React Native /
  Expo Router). Closed while the app is pre-launch; may open post-1.0.
- **Business logic** — vault-list rendering, portfolio math, sort /
  filter logic, notebook UI, drag-and-drop reordering.
- **Third-party integrations** — Changelly instant-swap, Google Drive
  OAuth token exchange, Firebase Analytics wiring, Stripe subscription
  plumbing.
- **Contract code** — the Soroban vault contract (Rust) will be
  published in its own repository once the mainnet audit completes.
- **Backend** — FastAPI + MongoDB service that caches XLM/fiat rates
  and (eventually) Stripe webhook state. No user secrets ever transit
  this service.

If you want to audit those, please reach out — we can share portions
under NDA for good-faith security research.

---

## Security architecture (30-second version)

```
   ┌──────────────────────────────────────────────────────────┐
   │  User biometric (FaceID / TouchID / Android Enclave)     │
   └───────────────────────────┬──────────────────────────────┘
                               │  releases
                               ▼
   ┌──────────────────────────────────────────────────────────┐
   │  Android Keystore  /  iOS Keychain                       │
   │    • xlm_vault_wallet_secret_<id>   (Stellar seed)       │
   │    • xlm_vault_biometric_root_secret_v1                  │
   └───────────────────────────┬──────────────────────────────┘
                               │
             ┌─────────────────┼──────────────────┐
             │                                    │
             ▼                                    ▼
   ┌───────────────────────┐          ┌─────────────────────────┐
   │  session-keystore.ts  │          │  biometric.ts           │
   │  (in-memory cache,    │          │  HKDF-SHA-256 →         │
   │   one prompt per      │          │  notebook AES-256 key   │
   │   unlock)             │          └────────────┬────────────┘
   └──────────┬────────────┘                       │
              │                                    │
              ▼                                    ▼
   ┌──────────────────────┐         ┌──────────────────────────┐
   │  wallet signing      │         │  notebook/crypto.ts      │
   │  (Stellar SDK)       │         │  AES-256-CBC on           │
   │  → secure-wipe.ts    │         │  notes, bills, TOTP,      │
   │    zeros _secretSeed │         │  ledger, address book     │
   │    + _secretKey      │         │  (PBKDF2 from wallet seed)│
   └──────────────────────┘         └──────────────────────────┘
```

Design principles:

1. **Trust boundary is native Android / iOS.** Web preview and Expo Go
   are development conveniences, not production surfaces.
2. **No server-side custody, ever.** The backend never sees a seed, a
   note, a bill, or a TOTP secret.
3. **Immutable string caveat.** We cannot zero source JS strings. We
   can and do zero every mutable byte carrier (Uint8Array, Buffer,
   WordArray, Keypair internals) the moment we finish with them.
4. **`allowBackup="false"` on Android.** Android's system backup
   service does not get a copy of the app's private data directory.
5. **Whitelisted analytics.** Firebase events live in a TypeScript
   union — you cannot add a new event without touching a reviewed
   file. No PII, no addresses, no amounts.

---

## Building against these modules

The modules ship as raw TypeScript targeting the same peer dependencies
used by the app:

```jsonc
{
  "peerDependencies": {
    "crypto-js": "^4.2.0",
    "expo-crypto": "*",
    "expo-local-authentication": "*",
    "expo-secure-store": "*",
    "@stellar/stellar-sdk": ">=13"
  }
}
```

The `session-keystore.ts` module imports two internal helpers
(`@/src/utils/storage` and `secure-wipe`) — you will need to provide
your own `storage` shim that maps `getItem/setItem/secureGet/
secureSet/secureSetAuthenticated/secureRemove` to your platform's
persistence primitives, or contact us for the reference shim.

---

## Reporting security issues

Please **do not** open a public GitHub issue for security bugs. Instead,
email `Stellartimelock@Gmail.com` with:

- A clear description of the vulnerability.
- Steps to reproduce.
- The affected version and platform (Android / iOS).
- A suggested severity if you have one.

We aim to acknowledge reports within 72 hours and target 90 days from
first report to public advisory. See [`SECURITY.md`](./SECURITY.md) for
the full disclosure timeline.

---

## Contributing

Pull requests are welcome for:

- Documentation / clarity improvements to `SECURITY.md`.
- Additional unit tests against the crypto primitives.
- Portability fixes for other RN engines (JSC / Hermes / V8).

For anything that changes cryptographic behaviour, please file a
tracking issue **first** so we can coordinate on the threat-model
implications before you invest review time.

---

## Trademark

"Stellar" is a trademark of the Stellar Development Foundation. This
project is independent and is not affiliated with, sponsored, or
endorsed by the Stellar Development Foundation.

"Stellar TimeLock" and the Stellar TimeLock logo are trademarks of
Stellar TimeLock LLC.

---

## License

Apache License, Version 2.0. See [`LICENSE`](./LICENSE).

```
Copyright 2026 Stellar TimeLock LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
