# XLM Vault — Soroban Deployment Record (Phase 2 — Step 1: Live on testnet)

## Deployment summary

| Field | Value |
| --- | --- |
| Network | Stellar **testnet** |
| Contract id | `CBIXRLC5GQ6O5UUJFVRIWZD77P5LUVJG3XGGUVS4EWHAJ6LXQZNKH35Z` |
| Wrapped XLM SAC | `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC` (native asset) |
| Deployer public key | `GAEPPLTQ4OIBG4J6DSI33FDYBB7YCKWOT36DNVLNOV65PIVSBAVSGXLS` |
| RPC endpoint | `https://soroban-testnet.stellar.org` |
| Network passphrase | `Test SDF Network ; September 2015` |
| Explorer | https://stellar.expert/explorer/testnet/contract/CBIXRLC5GQ6O5UUJFVRIWZD77P5LUVJG3XGGUVS4EWHAJ6LXQZNKH35Z |
| `init` status | ✅ One-shot completed (second call returns `Error #8 AlreadyInitialised` on-chain) |
| Contract unit tests | 12/12 passing locally (`cargo test`) |

The deployer secret was friendbot-funded (10,000 XLM testnet). Secret is saved
to `./.deploy/deployer-secret.txt` (git-ignored).

## What runs on-chain right now

- `init(token)` — wired to the native XLM SAC; one-shot guard enforced.
- `create_vault(owner, name, initial_deposit, unlock_timestamp)` — ready.
- `deposit(caller, vault_id, amount)` — ready.
- `extend_lock(caller, vault_id, additional_seconds)` — ready.
- `withdraw(caller, vault_id)` — ready (blocked until `env.ledger().timestamp() ≥ unlock_timestamp`).
- `get_vault(vault_id)` — public read.
- `list_owned(owner)` — public read.

We verified the contract responds correctly via `stellar contract invoke`:

```
$ stellar contract invoke --id <CONTRACT_ID> --network testnet -- list_owned --owner <ANY_G>
[]
$ stellar contract invoke --id <CONTRACT_ID> --source deployer --network testnet -- init --token <SAC>
ContractError #8       # AlreadyInitialised on the second call → expected
```

## What lives in the mobile app

- `src/wallet/contract-config.ts` — single source of truth for contract id / RPC URL / passphrase.
- `src/wallet/soroban-rpc.ts` — JSON-RPC client: `getNetworkHealth()` + `checkContractAlive()` (uses `getLedgerEntries` with the pre-encoded `LedgerKey::ContractData{instance}` for our contract).
- **Settings → Soroban Contract** card — displays contract id, live ledger number, status dot (green = live, red = unreachable), View-on-explorer link, on-chain rules list. Pings the network on mount + on demand.

This is the **read/observability** integration. The mobile app continues to
use `RestVaultClient` (FastAPI mirror) for all vault CRUD — that mirror
already enforces the same rules byte-for-byte. The path to swap in full
on-chain writes (Phase 2 — Step 2) is documented in
`./MIGRATION.md`; only the `SorobanVaultClient` write
methods in `src/api/soroban-client.ts` need to be filled in, and the wiring
is a single-line swap thanks to the `IVaultClient` interface boundary.

## Verifiable on-chain invariants

1. ✅ `init` was called exactly once. A second call now returns
   `Error::AlreadyInitialised (#8)`.
2. ✅ `list_owned(any_unowned_address)` returns the empty Vec.
3. ✅ Contract instance entry exists at ledger key
   `AAAABgAAAAFReKxdNDzu0oktYotkf/v6ulUm3cxqVlwljgT5d4ZaowAAABQAAAAB`
   confirming both the contract id AND the configured SAC.
4. ✅ `cargo test` proves all 12 contract-level invariants (only-owner,
   deposit-keeps-unlock, extend-forward-only, withdraw-blocked-while-locked,
   init-one-shot, etc.).

## Files

- `./Cargo.toml`
- `./src/lib.rs` (contract + 12 unit tests)
- `./target/wasm32-unknown-unknown/release/xlm_vault.wasm` (deployed artifact)
- `./.deploy/contract-id.txt` (also embedded in app)
- `./.deploy/native-sac.txt`
- `./.deploy/deployer-secret.txt` (git-ignored)
- `./REVIEW.md`
- `./MIGRATION.md`
- `<frontend>/src/wallet/contract-config.ts`
- `<frontend>/src/wallet/soroban-rpc.ts`
- `<frontend>/app/(tabs)/settings.tsx` (new Soroban card)

## Next step (when ready)

Implement the write paths in `src/api/soroban-client.ts`. Each maps to one
RPC sequence: `simulateTransaction → assemble → sign(secret) → sendTransaction
→ poll getTransaction`. The seed used for signing already lives in
SecureStore via the existing wallet layer. No backend signing proxy.
