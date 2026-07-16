# XLM Vault — MongoDB → Soroban Migration Plan

This document describes the exact, mechanical migration path from the Phase 1
backend (FastAPI + MongoDB) to the Phase 2 enforcement layer (Soroban smart
contract). The mobile UI **does not change** during the migration — it talks to
an `IVaultClient` interface (`<frontend>/src/vault/contract.ts`) and the
implementation is swapped underneath it.

## Architecture today (Phase 1)

```
React Native UI
      │
      ▼
src/vault/contract.ts        ◄── interface IVaultClient
      │
      ▼
src/api/client.ts            ◄── RestVaultClient (active)
      │
      ▼
FastAPI (server.py) ── MongoDB
```

## Architecture after migration (Phase 2)

```
React Native UI                      (unchanged)
      │
      ▼
src/vault/contract.ts                (unchanged)
      │
      ▼
src/api/soroban-client.ts            ◄── SorobanVaultClient (newly wired)
      │
      ▼
Stellar RPC ── Soroban contract on Stellar testnet / mainnet
```

## Contract surface — 1:1 mapping

| `IVaultClient` method | Soroban method | Notes |
| --- | --- | --- |
| `createVault(input)` | `create_vault(owner, name, initial_deposit, unlock_timestamp)` | Returns u64 vault id; call `get_vault` to hydrate full struct. |
| `deposit(id, owner, amount)` | `deposit(caller, vault_id, amount)` | Does NOT change `unlock_timestamp`. |
| `extendLock(id, owner, seconds)` | `extend_lock(caller, vault_id, additional_seconds)` | Only forward. `additional_seconds == 0` → `ShortenForbidden`. |
| `withdraw(id, owner)` | `withdraw(caller, vault_id)` | Reverts with `StillLocked` before unlock_timestamp. |
| `getVault(id)` | `get_vault(vault_id)` | Read-only. |
| `listVaults(owner)` | `list_owned(owner)` → loop `get_vault` | No off-chain index needed. |
| `vaultTransactions(id)` / `allTransactions(owner)` | `rpc.getEvents` filtered by contractId + topic | Topics: `create`, `deposit`, `extend`, `withdraw`. |
| `summary(owner)` | client-side aggregation over `listVaults` | No new contract method needed. |
| `registerWallet` | (no-op) | Soroban needs no wallet registry. |

## Deployment steps

1. **Build the contract**

   ```bash
   rustup target add wasm32-unknown-unknown
   cd .
   cargo build --release --target wasm32-unknown-unknown
   ```

2. **Deploy to testnet**

   ```bash
   stellar contract deploy \
     --wasm target/wasm32-unknown-unknown/release/xlm_vault.wasm \
     --source <YOUR_TESTNET_SECRET> --network testnet
   # → returns C... contract id
   ```

3. **Initialise the contract with the native XLM SAC**

   The native XLM asset contract on testnet has a well-known SAC address you
   can fetch from `stellar contract id asset --asset native --network testnet`.

   ```bash
   stellar contract invoke \
     --id <CONTRACT_ID> --source <SECRET> --network testnet \
     -- init --token <NATIVE_XLM_SAC>
   ```

4. **Run contract tests**

   ```bash
   cd .
   cargo test
   ```

   All 11 tests must pass:
   - `init_is_one_shot`
   - `create_locks_funds_and_assigns_owner`
   - `create_rejects_past_unlock`
   - `create_rejects_non_positive_deposit`
   - `deposit_keeps_unlock_unchanged`
   - `deposit_non_owner_rejected`
   - `extend_only_pushes_forward`
   - `extend_non_owner_rejected`
   - `withdraw_blocked_while_locked`
   - `withdraw_after_unlock_returns_full_balance`
   - `withdraw_non_owner_rejected`
   - `list_owned_returns_only_callers_vaults`

5. **Wire the mobile client**

   Implement the `notImplemented(...)` stubs in
   `<frontend>/src/api/soroban-client.ts` using `@stellar/stellar-sdk`'s
   Soroban RPC client (or direct `fetch` against `/getLatestLedger`, `/sendTransaction`,
   `/getTransaction`, `/simulateTransaction`, `/getEvents`).

   The `config.sign(xdr)` callback signs a Soroban transaction envelope with
   the user's locally-held secret seed (from `expo-secure-store`). The seed
   **must never** leave the device.

6. **Swap the client**

   In whichever file imports `api` from `@/src/api/client`, replace it with:

   ```ts
   import { createSorobanVaultClient } from "@/src/api/soroban-client";

   const client = createSorobanVaultClient({
     contractId: "C...",
     rpcUrl: "https://soroban-testnet.stellar.org",
     networkPassphrase: "Test SDF Network ; September 2015",
     sign: async (xdr) => {
       const kp = await loadPersistedKeypair();
       if (!kp) throw new Error("Wallet not connected");
       return signSoroban(xdr, kp.secretSeed);
     },
   });
   ```

   No UI file needs to be touched.

7. **(Optional) Backfill historic state**

   For users who created vaults in Phase 1, write a one-off migration script
   that reads every MongoDB vault and re-creates it on-chain by calling
   `create_vault` from the user's wallet (with their consent — the deposit
   amount must be re-funded from the user's Stellar balance).

## Invariants preserved across the swap

The mobile app behaviour is identical because both implementations enforce
the same rules:

| Rule | FastAPI enforcement | Soroban enforcement |
| --- | --- | --- |
| Only owner deposits | `server.py` `deposit()` checks `v["owner_public_key"]` | `lib.rs` `deposit()` checks `v.owner == caller` |
| Only owner withdraws | `server.py` `withdraw()` checks owner | `lib.rs` `withdraw()` checks owner |
| Early withdraw blocked | `server.py` raises HTTP 403 when `now_ts() < unlock_timestamp` | `lib.rs` returns `Error::StillLocked` when `env.ledger().timestamp() < unlock_timestamp` |
| Deposit does not move unlock | `server.py` `deposit()` only updates balance | `lib.rs` `deposit()` only updates balance |
| Extensions only forward | `server.py` `additional_seconds > 0` validation | `lib.rs` `additional_seconds == 0` → `Error::ShortenForbidden` |
| No admin role | No admin endpoints exist | No admin functions exist |
| No emergency unlock | Not implemented | Not implemented |

## What disappears after migration

- `/api/wallets/*` and `/api/vaults/*` FastAPI endpoints — no longer the source of truth.
- The MongoDB `vaults`, `transactions`, `wallets` collections — replaced by on-chain state + ledger events.
- The `total_withdrawn` aggregation — recomputed client-side from on-chain events.

## What remains unchanged

- `<frontend>/app/**/*.tsx` — every screen.
- `<frontend>/src/wallet/stellar.ts` — keypair generation, import, export.
- `<frontend>/src/vault/contract.ts` — `IVaultClient` interface.
- The dark-theme UI and design tokens.
