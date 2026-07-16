# Mainnet Rollout — Operator Guide

The codebase is fully refactored to support a runtime network switch. Once
the smart contract is deployed on mainnet and the addresses are pasted into
`src/wallet/contract-config.ts`, **no further code changes** are needed —
the Settings → NETWORK selector will offer mainnet to users.

Read this whole document before running any command. Mainnet deployments
cost real XLM (~5–10 XLM for upload + deploy + init) and **vault locks on
mainnet are irreversible** by design.

---

## 0. Prerequisites

```bash
# Install the official Stellar CLI (v22+).
curl -L https://github.com/stellar/stellar-cli/releases/latest/download/install.sh | bash
stellar --version  # expect 22.x or newer

# Sanity check — should print "Public Global Stellar Network ; September 2015".
stellar network ls
stellar network add mainnet \
  --rpc-url https://soroban-rpc.stellar.org \
  --network-passphrase "Public Global Stellar Network ; September 2015"
```

Fund a deployer account on mainnet with ≥10 XLM. We'll call this
`mainnet-deployer`. Do NOT use your personal wallet for this; create a
fresh one so the secret seed never has to be re-used.

```bash
stellar keys generate mainnet-deployer --network mainnet
stellar keys address mainnet-deployer   # send ≥10 XLM here from your exchange
stellar keys show    mainnet-deployer   # SECRET seed — save in 1Password
```

Wait until Horizon shows the account funded:
```bash
curl -s https://horizon.stellar.org/accounts/$(stellar keys address mainnet-deployer) \
  | jq '.balances'
```

---

## 1. Build the WASM in release mode

The contract source has not changed since the testnet deploy, so the bytecode
is identical. We rebuild here purely to make sure the artefact is reproducible
from a clean checkout.

```bash
cd .
stellar contract build
ls target/wasm32-unknown-unknown/release/xlm_vault.wasm
# Should be ~30–40 KB.

# (Optional but recommended) sha256 the WASM and record it in PRODUCTION_RUNBOOK.md
# so the on-chain bytecode hash can be independently verified later.
sha256sum target/wasm32-unknown-unknown/release/xlm_vault.wasm
```

---

## 2. Upload + deploy the contract on mainnet

```bash
cd .

# Upload the WASM blob. Prints the WASM hash on success.
stellar contract upload \
  --source mainnet-deployer \
  --network mainnet \
  --wasm target/wasm32-unknown-unknown/release/xlm_vault.wasm

# Deploy a fresh contract instance pointing at that WASM hash.
# Prints the new contract id (the C… address). Capture this.
stellar contract deploy \
  --source mainnet-deployer \
  --network mainnet \
  --wasm target/wasm32-unknown-unknown/release/xlm_vault.wasm
# → save as MAINNET_CONTRACT_ID
```

---

## 3. Resolve the mainnet native-XLM SAC address

Soroban references the native XLM asset through a Stellar Asset Contract
(SAC). Each network has its own SAC for "native", and ours is a constructor
argument to the vault.

```bash
stellar contract id asset --asset native --network mainnet
# → save as MAINNET_NATIVE_SAC
```

---

## 4. Initialise the vault contract

`__init__` wires the native SAC into the vault and sets the singleton owner.

```bash
stellar contract invoke \
  --id <MAINNET_CONTRACT_ID> \
  --source mainnet-deployer \
  --network mainnet \
  -- \
  __init__ \
  --native_token <MAINNET_NATIVE_SAC>
```

Verify success on stellar.expert:

```
https://stellar.expert/explorer/public/contract/<MAINNET_CONTRACT_ID>
```

---

## 5. Patch `src/wallet/contract-config.ts`

Replace the placeholder block:

```ts
export const MAINNET_DEPLOYMENT: DeployedContract = {
  network: "mainnet",
  enabled: true,                                  // ← flip false → true
  contractId: "<MAINNET_CONTRACT_ID>",            // ← from step 2
  rpcUrl: "https://soroban-rpc.stellar.org",
  horizonUrl: "https://horizon.stellar.org",
  networkPassphrase: "Public Global Stellar Network ; September 2015",
  friendbotUrl: null,
  nativeXlmSac: "<MAINNET_NATIVE_SAC>",            // ← from step 3
  explorerUrl:
    "https://stellar.expert/explorer/public/contract/<MAINNET_CONTRACT_ID>",
  explorerTxBase: "https://stellar.expert/explorer/public/tx/",
};
```

---

## 6. Pre-compute the mainnet LedgerKey for `soroban-rpc.ts`

`checkContractAlive()` uses a base64-XDR `LedgerKey::ContractData` to ping the
ledger. Regenerate it for the mainnet contract id:

```bash
stellar xdr encode --type LedgerKey <<EOF
{
  "contract_data": {
    "contract": "<MAINNET_CONTRACT_ID>",
    "key":      { "ledger_key_contract_instance": {} },
    "durability": "persistent"
  }
}
EOF
```

Paste the resulting base64 string into the `mainnet:` entry of
`CONTRACT_INSTANCE_LEDGER_KEY` in `src/wallet/soroban-rpc.ts`. (Leaving it
as `null` is acceptable — the function will fall back to a generic RPC
health check — but the contract-specific probe is more informative.)

---

## 7. Lock down the backend

```bash
# <backend>/.env
STELLAR_NETWORK=mainnet
ALLOWED_ORIGINS=https://stellartimelock.com,https://www.stellartimelock.com
```

Restart: `sudo supervisorctl restart backend`. Verify:
```bash
curl -s https://stellartimelock.com/healthz
# → {"status":"ok","mongo":true,"stellar_network":"mainnet"}
```

---

## 8. Smoke test BEFORE announcing mainnet

In an internal build of the app on a phone:

1. Settings → NETWORK → Stellar Mainnet (should now be enabled).
2. Settings → use a wallet you control with a small balance (e.g. 5 XLM).
3. Create a vault with `2 XLM`, unlock = `now + 5 minutes`.
4. Wait 5 minutes, withdraw. Confirm balance returns minus the network fee.
5. Look up every tx on `stellar.expert/explorer/public/tx/...` — they
   should be linked from the History tab automatically.

If any step fails, **do not publish**. Revert by editing
`MAINNET_DEPLOYMENT.enabled` back to `false` and republishing — the app
falls back to testnet for all users on next launch.

---

## 9. Publish

Re-run `Publish` from the Emergent dashboard. The new bundle will include:
- `MAINNET_DEPLOYMENT.enabled = true`
- The mainnet contract id + native SAC
- The mainnet `LedgerKey` (or `null`)
- Backend `STELLAR_NETWORK=mainnet`

After publish, monitor `/healthz` and the History tab for the first 24 h.
