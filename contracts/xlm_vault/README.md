# XLM Vault — Soroban Smart Contract

Non-custodial Stellar time-lock vault. This crate is the **on-chain enforcement
layer** that the XLM Vault mobile app will migrate to once deployed.

## Rules enforced on-chain

| Action | Rule |
| --- | --- |
| `create_vault` | Owner pulls XLM into the contract. `unlock_timestamp` must be in the future. |
| `deposit` | Only owner. Does NOT change `unlock_timestamp`. |
| `extend_lock` | Only owner. `additional_seconds > 0`. New timestamp is `current + additional` — reduction impossible. |
| `withdraw` | Only owner. Blocked until `env.ledger().timestamp() >= unlock_timestamp`. |
| `init` | One-shot; wires the asset (XLM SAC) address. No update method exists. |

There is no `set_owner`, no `pause`, no `upgrade`, no emergency unlock.

## Build

```bash
rustup target add wasm32-unknown-unknown
cd contracts/xlm_vault
cargo build --release --target wasm32-unknown-unknown
```

## Deploy (testnet)

```bash
stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/xlm_vault.wasm \
  --source <SECRET> --network testnet

# Initialise with the native-XLM SAC address
stellar contract invoke --id <CONTRACT_ID> --source <SECRET> --network testnet \
  -- init --token <NATIVE_XLM_SAC>
```

## 1:1 mapping with the mobile app

| Mobile API (FastAPI) | Soroban method |
| --- | --- |
| `POST /api/vaults` | `create_vault(owner, name, initial_deposit, unlock_timestamp)` |
| `POST /api/vaults/{id}/deposit` | `deposit(caller, vault_id, amount)` |
| `POST /api/vaults/{id}/extend` | `extend_lock(caller, vault_id, additional_seconds)` |
| `POST /api/vaults/{id}/withdraw` | `withdraw(caller, vault_id)` |
| `GET /api/vaults/{id}` | `get_vault(vault_id)` |
| `GET /api/vaults?owner=…` | `list_owned(owner)` |

Migration: swap the FastAPI controllers for calls to this contract; the
mobile UI does not change.
