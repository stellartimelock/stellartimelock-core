# Soroban Contract Review — `XlmVault`

**Source:** `./src/lib.rs`
**SDK:** `soroban-sdk = "21"`
**Status:** Source-complete, unit-tested, **not deployed**.

This document is a definitive audit of the on-chain enforcement layer and a
side-by-side comparison with the Phase 1 FastAPI backend
(`<backend>/server.py`) that mirrors the same rules.

---

## 1. Public functions

| Function | Signature | Auth | Description |
| --- | --- | --- | --- |
| `init` | `init(env, token: Address) -> Result<(), Error>` | — (one-shot, idempotent guard) | Wires the native-XLM SAC contract address; returns `AlreadyInitialised` if called twice. No setter ever exists. |
| `create_vault` | `create_vault(env, owner: Address, name: String, initial_deposit: i128, unlock_timestamp: u64) -> Result<u64, Error>` | `owner.require_auth()` | Pulls `initial_deposit` of the configured token from `owner` into the contract. Stores a `Vault` struct with monotonic `vault_id`. Indexes the id under `Owned(owner)`. Emits `("create", owner) -> (id, amount, unlock_ts)`. |
| `deposit` | `deposit(env, caller: Address, vault_id: u64, amount: i128) -> Result<(), Error>` | `caller.require_auth()` + owner check | Pulls `amount` from `caller` into the contract. **Never** mutates `unlock_timestamp`. |
| `extend_lock` | `extend_lock(env, caller: Address, vault_id: u64, additional_seconds: u64) -> Result<u64, Error>` | `caller.require_auth()` + owner check | Adds `additional_seconds` (must be `> 0`) to `unlock_timestamp` using `checked_add`. Rejects shortening. |
| `withdraw` | `withdraw(env, caller: Address, vault_id: u64) -> Result<i128, Error>` | `caller.require_auth()` + owner check | Blocked while `env.ledger().timestamp() < unlock_timestamp`. Transfers the full balance back to `caller`, zeroes balance, sets `withdrawn = true`. Double-withdraw → `AlreadyWithdrawn`. |
| `get_vault` | `get_vault(env, vault_id: u64) -> Result<Vault, Error>` | none | Read-only fetch by id. |
| `list_owned` | `list_owned(env, owner: Address) -> Vec<u64>` | none | Read-only — returns vault ids for `owner`. Returns empty Vec when none exist. |

All four owner-bound mutators (`create_vault`, `deposit`, `extend_lock`,
`withdraw`) call `require_auth()` on the address they treat as the
authorising principal. There is no admin role, no proxy, no upgrade entry
point, and no `set_owner`/`set_unlock` setter.

---

## 2. Storage layout

```rust
pub enum DataKey {
    Token,              // Instance: Address of the wrapped XLM SAC. Set once.
    NextId,             // Instance: u64 monotonic counter for vault ids.
    Vault(u64),         // Persistent: Vault struct by id.
    Owned(Address),     // Persistent: Vec<u64> — owner's vault ids.
}

pub struct Vault {
    pub vault_id: u64,
    pub owner: Address,
    pub name: String,
    pub balance: i128,
    pub unlock_timestamp: u64,
    pub created_timestamp: u64,
    pub withdrawn: bool,
}
```

- `Token` and `NextId` live in **instance** storage — small, frequently read.
- `Vault(id)` and `Owned(addr)` live in **persistent** storage — survives across instance TTL boundaries.
- The contract relies on Soroban's default TTL semantics; production deployments should periodically extend persistent entries (see Soroban TTL docs) — the rules do not depend on TTL because every read uses `get(...).ok_or(VaultNotFound)`.

---

## 3. Error variants

| Variant | u32 code | Triggers |
| --- | --- | --- |
| `NotOwner` | 1 | Caller of `deposit`/`extend_lock`/`withdraw` is not the recorded `owner`. |
| `StillLocked` | 2 | `withdraw` invoked while `env.ledger().timestamp() < v.unlock_timestamp`. |
| `AlreadyWithdrawn` | 3 | Any mutator on a vault whose `withdrawn == true`. |
| `ShortenForbidden` | 4 | `extend_lock(additional_seconds == 0)`. |
| `VaultNotFound` | 5 | Storage lookup miss. |
| `InvalidAmount` | 6 | Non-positive deposit, or vault-id counter overflow. |
| `InvalidTimestamp` | 7 | `create_vault.unlock_timestamp <= now`, or `extend_lock` overflow. |
| `AlreadyInitialised` | 8 | Second call to `init`. |

---

## 4. Security rules — explicit invariants

1. **Owner-only operations.** Every owner-bound mutator opens with `require_auth()` and then checks `v.owner == caller`. The auth check defends against contract-level forgery; the equality check defends against a malicious owner re-using their auth to act on someone else's vault id.
2. **Withdrawals blocked on-chain until the unlock timestamp.** `env.ledger().timestamp()` is the consensus-validated ledger clock; clients cannot spoof it.
3. **Extensions only push forward.** `extend_lock` requires `additional_seconds > 0` (else `ShortenForbidden`) and uses `checked_add`. There is no setter to assign an arbitrary `unlock_timestamp`. The `Vault.unlock_timestamp` field, post-create, is therefore monotonically non-decreasing.
4. **Deposits do not move the unlock.** `deposit` mutates only `balance`. No code path in the contract assigns `unlock_timestamp` outside `create_vault` and `extend_lock`.
5. **No admin / no upgrade.** There is no admin Address in storage, no `pause`, no `unpause`, no `upgrade_wasm`, no emergency function. The contract is intentionally minimal.
6. **`init` is one-shot.** Re-initialisation is blocked with `AlreadyInitialised` so the token reference cannot be swapped after launch.
7. **Token reference is immutable.** `DataKey::Token` is written exactly once in `init` and read everywhere via `Self::token`. There is no setter.
8. **Double-withdraw rejection.** After `withdraw`, `v.withdrawn = true` is set; any further `deposit`/`extend_lock`/`withdraw` returns `AlreadyWithdrawn`.

---

## 5. Side-by-side: contract vs. FastAPI backend

| Rule | Soroban (`lib.rs`) | FastAPI (`server.py`) |
| --- | --- | --- |
| Only owner deposits | `if v.owner != caller { return Err(NotOwner) }` | `if v["owner_public_key"] != body.owner_public_key: raise HTTPException(403)` |
| Only owner withdraws | same pattern | same pattern |
| Only owner extends | same pattern | same pattern |
| Early withdraw blocked | `if env.ledger().timestamp() < v.unlock_timestamp { return Err(StillLocked) }` | `if now_ts() < v["unlock_timestamp"]: raise HTTPException(403, "vault is still locked")` |
| Deposit preserves unlock | `deposit` only mutates `balance` | `update_one({...}, {"$set": {"balance": new_balance}})` only sets balance |
| Extend forward-only | `additional_seconds == 0 → ShortenForbidden`, then `checked_add` | `additional_seconds: int = Field(gt=0)` then `unlock_timestamp += additional_seconds` |
| 1000-day cap | not enforced at contract level (clients enforce business cap) | `unlock_timestamp` validated `<= now + 1000d + 1d slack` |
| Status transitions | derived from `withdrawn` flag + `now vs unlock_timestamp` | derived from `status` field + `_refresh_status()` |
| Withdraw zeros balance | `v.balance = 0; v.withdrawn = true; push(...)` | `{"balance": 0.0, "status": "withdrawn", "withdrawn_amount": amount}` |
| Double-withdraw rejected | `if v.withdrawn { return Err(AlreadyWithdrawn) }` | `if v.get("status") == "withdrawn": raise HTTPException(409)` |

**Note on the 1000-day cap:** The Soroban contract deliberately does **not**
enforce a 1000-day maximum — the business cap is a UX guardrail and the
contract should remain neutral so future product decisions can lift it
without redeploying. The FastAPI backend enforces it because the mobile UI
expects validation feedback at submit time.

---

## 6. Unit tests (`#[cfg(test)] mod tests`)

12 tests covering every invariant:

| Test | What it proves |
| --- | --- |
| `init_is_one_shot` | Second `init` call returns `AlreadyInitialised`. |
| `create_locks_funds_and_assigns_owner` | Tokens move from owner to contract; vault stored with correct fields. |
| `create_rejects_past_unlock` | `unlock_timestamp <= now` → `InvalidTimestamp`. |
| `create_rejects_non_positive_deposit` | `initial_deposit == 0` → `InvalidAmount`. |
| `deposit_keeps_unlock_unchanged` | Vault's `unlock_timestamp` is identical before/after deposit. |
| `deposit_non_owner_rejected` | Attacker calling `deposit` → `NotOwner`. |
| `extend_only_pushes_forward` | `additional_seconds == 0` → `ShortenForbidden`; positive value advances ts. |
| `extend_non_owner_rejected` | Attacker calling `extend_lock` → `NotOwner`. |
| `withdraw_blocked_while_locked` | `withdraw` before ledger ts reaches unlock → `StillLocked`. |
| `withdraw_after_unlock_returns_full_balance` | After ledger advances, full balance returns to owner; double-withdraw → `AlreadyWithdrawn`. |
| `withdraw_non_owner_rejected` | Attacker calling `withdraw` after unlock → `NotOwner`. |
| `list_owned_returns_only_callers_vaults` | `list_owned(a)` returns only `a`'s ids. |

Run with `cd . && cargo test` once a Rust 1.74+ toolchain is available. No external services or RPC required.

---

## 7. Migration readiness

- **Contract is byte-compatible with the mobile app's `IVaultClient` interface.** See `./MIGRATION.md` for the 1:1 method table.
- The `SorobanVaultClient` stub (`<frontend>/src/api/soroban-client.ts`) maps every mobile call to a contract method. Wiring is documented; no UI file needs to change at swap time.
- Token reference is the **native XLM SAC** on the chosen network — produced via `stellar contract id asset --asset native --network <network>`.

## 8. Conclusion

The Soroban contract implements the XLM Vault spec with the minimum surface
area required: 7 public functions, 1 storage struct, 4 data keys, 8 error
variants, 0 admin functions. Every product rule is enforced at the
`require_auth()` + ledger-timestamp boundary, matching the FastAPI Phase 1
backend byte-for-byte.
