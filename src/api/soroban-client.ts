// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stellar TimeLock LLC

// Real Soroban write client — implements the four mutating IVaultClient
// methods against the deployed XlmVault contract on Stellar testnet.
//
// Pipeline (Stellar canonical):
//   1. Build a TransactionEnvelope with `auth=[]` for the contract call.
//   2. Send to soroban-rpc `simulateTransaction` → returns:
//        a) required SorobanAuthorizationEntry list
//        b) resource estimates (instructions, IO bytes, footprint, fee)
//        c) preflight return value
//   3. `rpc.assembleTransaction(tx, simulation)` produces the prepared tx
//      with auth + footprint + base fee.
//   4. Sign with the user's ed25519 secret seed via `Transaction.sign(kp)`.
//      Secret is kept in `expo-secure-store`, NEVER sent to a backend.
//   5. POST envelope to `sendTransaction`.
//   6. Poll `getTransaction(hash)` until status != PENDING.
//
// Each phase is wrapped in its own try/catch so we can throw a categorised
// `SorobanError` (see `./soroban-errors.ts`) and the UI can render a
// targeted message + retry / explorer-link affordance. Successful writes
// emit a `TxReceipt` via `./tx-receipts.ts` so the global banner mounted in
// the root layout can render the explorer link.
//
// Reads bypass signing entirely and go through `invokeRead()` below.

// IMPORTANT: load the Buffer polyfill BEFORE any stellar-sdk symbol resolves,
// because the SDK references `Buffer` at module load time.
import "@/src/polyfills/buffer";

import {
  Account,
  Address,
  Contract,
  Keypair,
  Operation,
  SorobanDataBuilder,
  Transaction,
  TransactionBuilder,
  nativeToScVal,
  rpc as StellarRpc,
  scValToNative,
  xdr,
} from "@stellar/stellar-sdk";

import { getActiveDeployment, subscribeActiveNetwork } from "@/src/wallet/contract-config";
import {
  getCurrentRpcUrl,
  isRpcTransportError,
  rotateRpcUrl,
} from "@/src/wallet/rpc-failover";
import {
  loadCachedVaults,
  mergeVaults,
  saveCachedVaults,
} from "@/src/api/vault-cache";
import type {
  CreateVaultInput,
  IVaultClient,
  Summary,
  Transaction as VaultTransaction,
  Vault,
} from "@/src/vault/contract";
import { loadSigningKeypair } from "@/src/wallet/stellar";
import {
  SorobanNetworkError,
  SorobanOnChainError,
  SorobanPollTimeoutError,
  SorobanSendError,
  SorobanSignError,
  SorobanSimulationError,
  WalletNotConnectedError,
} from "./soroban-errors";
import {
  emitReceipt,
  explorerForTx,
  type SorobanMethod,
  type TxReceipt,
} from "./tx-receipts";
import { storage } from "@/src/utils/storage";
import { wipeKeypair } from "@/src/security/secure-wipe";

const BASE_FEE = "10000"; // 0.001 XLM base; Soroban fees added by assembleTransaction.
const POLL_INTERVAL_MS = 1500;
const POLL_ATTEMPTS = 30; // → ~45s budget before declaring a poll timeout.

// ---------------------------------------------------------------------------
// Server + account helpers (all wrapped in their own try/catch upstream).
// ---------------------------------------------------------------------------

function rpcServer(): StellarRpc.Server {
  // We deliberately resolve the URL on every call so that rotations triggered
  // by `rpc-failover.ts` are honored without having to rebuild any caller's
  // captured server instance. The Server constructor is cheap.
  return new StellarRpc.Server(getCurrentRpcUrl(), { allowHttp: false });
}

async function loadAccount(publicKey: string): Promise<Account> {
  // `getAccount` is the very first network call in every write pipeline.
  // If the active RPC is dropping mobile traffic (the
  // creit.tech → mainnet failure mode), failing here means the user sees
  // an empty dashboard. We retry across every fallback URL — the call is
  // a pure read so duplicate execution is safe.
  const dep = getActiveDeployment();
  const total = 1 + (dep.rpcFallbacks?.length ?? 0);
  let lastErr: unknown;
  for (let attempt = 0; attempt < Math.max(1, total); attempt++) {
    try {
      const fetched = await rpcServer().getAccount(publicKey);
      return new Account(fetched.accountId(), fetched.sequenceNumber());
    } catch (e) {
      lastErr = e;
      if (!isRpcTransportError(e) || attempt === total - 1) {
        throw e;
      }
      rotateRpcUrl(e);
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ---------------------------------------------------------------------------
// invokeContract — the core write pipeline.
// ---------------------------------------------------------------------------

interface InvokeResult {
  returnValue: xdr.ScVal | undefined;
  receipt: TxReceipt;
}

async function invokeContract(args: {
  ownerPublicKey: string;
  method: SorobanMethod;
  params: xdr.ScVal[];
}): Promise<InvokeResult> {
  const { ownerPublicKey, method, params } = args;
  const server = rpcServer();

  // ---- 1) Build (load source account, build envelope) --------------------
  let tx: Transaction;
  try {
    const source = await loadAccount(ownerPublicKey);
    const contract = new Contract(getActiveDeployment().contractId);
    tx = new TransactionBuilder(source, {
      fee: BASE_FEE,
      networkPassphrase: getActiveDeployment().networkPassphrase,
    })
      .addOperation(contract.call(method, ...params))
      .setTimeout(60)
      .build();
  } catch (e) {
    throw new SorobanNetworkError(method, "build", e);
  }

  // ---- 2) Simulate (preflight) -------------------------------------------
  let sim;
  try {
    sim = await server.simulateTransaction(tx);
  } catch (e) {
    throw new SorobanNetworkError(method, "simulate", e);
  }
  if (StellarRpc.Api.isSimulationError(sim)) {
    throw new SorobanSimulationError(method, sim.error);
  }

  // ---- 3) Assemble (re-wrap with footprint + auth from sim) --------------
  let assembled: Transaction;
  try {
    assembled = StellarRpc.assembleTransaction(tx, sim).build();
  } catch (e) {
    // Assembly failures are almost always a malformed sim response; surface
    // them as simulation errors so the user sees a single category.
    throw new SorobanSimulationError(
      method,
      `Could not assemble simulated transaction: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  // ---- 4) Sign with the device-held secret -------------------------------
  //
  // Sprint 23 iter 22 — Signer is used exactly ONCE (single-shot
  // invoke), so we wipe `_secretSeed` + `_secretKey` immediately after
  // sign() so the SDK Keypair holds nothing sensitive by the time we
  // hand the assembled tx off to sendTransaction().
  try {
    // Sprint 23 iter 13 — Use the multi-wallet-aware resolver so
    // the ACTIVE wallet's seed is picked up, not the legacy single-
    // wallet slot (which is empty on multi-wallet installs).
    const kp = await loadSigningKeypair();
    if (!kp) throw new WalletNotConnectedError(method);
    const signer = Keypair.fromSecret(kp.secretSeed);
    try {
      assembled.sign(signer);
    } finally {
      wipeKeypair(signer);
    }
  } catch (e) {
    if (e instanceof WalletNotConnectedError) throw e;
    throw new SorobanSignError(method, e);
  }

  // ---- 5) Send ----------------------------------------------------------
  let sendRes: StellarRpc.Api.SendTransactionResponse;
  try {
    sendRes = await server.sendTransaction(assembled);
  } catch (e) {
    throw new SorobanNetworkError(method, "send", e);
  }
  if (sendRes.status === "ERROR" || sendRes.status === "DUPLICATE") {
    const detail =
      (sendRes.status === "ERROR" && sendRes.errorResult?.result().switch().name) ||
      sendRes.status;
    throw new SorobanSendError(method, String(detail), sendRes.hash);
  }

  // ---- 6) Poll getTransaction until non-PENDING --------------------------
  const txHash = sendRes.hash;
  for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
    await sleep(POLL_INTERVAL_MS);
    let got;
    try {
      got = await server.getTransaction(txHash);
    } catch {
      // Transient network blips during polling shouldn't abort the whole
      // operation — the tx is already submitted. Keep polling.
      continue;
    }
    if (got.status === "NOT_FOUND") continue;
    if (got.status === "SUCCESS") {
      const success = got as StellarRpc.Api.GetSuccessfulTransactionResponse;
      const receipt: TxReceipt = {
        method,
        txHash,
        ledger: typeof success.ledger === "number" ? success.ledger : undefined,
        explorerUrl: explorerForTx(txHash),
        status: "success",
        emittedAt: Date.now(),
      };
      emitReceipt(receipt);
      return { returnValue: success.returnValue ?? undefined, receipt };
    }
    if (got.status === "FAILED") {
      emitReceipt({
        method,
        txHash,
        explorerUrl: explorerForTx(txHash),
        status: "failed",
        emittedAt: Date.now(),
      });
      throw new SorobanOnChainError(method, txHash);
    }
  }
  // Poll budget exhausted — emit a PENDING receipt so the global banner can
  // offer the user a "Recheck" affordance. The tx might still finalize.
  emitReceipt({
    method,
    txHash,
    explorerUrl: explorerForTx(txHash),
    status: "pending",
    emittedAt: Date.now(),
  });
  throw new SorobanPollTimeoutError(method, txHash);
}

// ---------------------------------------------------------------------------
// ScVal helpers — type-safe wrappers for contract method parameters.
// ---------------------------------------------------------------------------

function scAddress(g: string): xdr.ScVal {
  return new Address(g).toScVal();
}
function scU64(v: number | bigint): xdr.ScVal {
  return nativeToScVal(typeof v === "number" ? BigInt(v) : v, { type: "u64" });
}
function scI128(v: number | bigint): xdr.ScVal {
  return nativeToScVal(typeof v === "number" ? BigInt(v) : v, { type: "i128" });
}
function scString(s: string): xdr.ScVal {
  return nativeToScVal(s, { type: "string" });
}

// XLM contract balances are i128 in 7-decimal "stroop" units (10⁷ per XLM).
const STROOPS_PER_XLM = 10_000_000n;
function xlmToStroops(amount: number): bigint {
  // Round-half-up to avoid silent truncation of user-entered amounts.
  return BigInt(Math.round(amount * Number(STROOPS_PER_XLM)));
}
function stroopsToXlm(stroops: bigint | number): number {
  const n = typeof stroops === "bigint" ? Number(stroops) : stroops;
  return n / Number(STROOPS_PER_XLM);
}

// ---------------------------------------------------------------------------
// Vault struct decoding — mirrors `pub struct Vault` in contracts/xlm_vault/src/lib.rs
// ---------------------------------------------------------------------------

interface ContractVault {
  vault_id: bigint;
  owner: string;
  name: string;
  balance: bigint;
  unlock_timestamp: bigint;
  created_timestamp: bigint;
  withdrawn: boolean;
}

function decodeVault(sv: xdr.ScVal): ContractVault {
  const obj = scValToNative(sv) as Record<string, unknown>;
  return {
    vault_id: BigInt(obj.vault_id as string | number | bigint),
    owner: String(obj.owner),
    name: String(obj.name),
    balance: BigInt(obj.balance as string | number | bigint),
    unlock_timestamp: BigInt(obj.unlock_timestamp as string | number | bigint),
    created_timestamp: BigInt(obj.created_timestamp as string | number | bigint),
    withdrawn: Boolean(obj.withdrawn),
  };
}

function statusFor(v: ContractVault, nowSec: number): Vault["status"] {
  if (v.withdrawn) return "withdrawn";
  return nowSec >= Number(v.unlock_timestamp) ? "unlocked" : "locked";
}

function toVault(c: ContractVault, off: Partial<Vault> = {}): Vault {
  return {
    vault_id: c.vault_id.toString(),
    owner_public_key: c.owner,
    name: c.name,
    description: off.description ?? "",
    template: off.template ?? "custom",
    balance: stroopsToXlm(c.balance),
    target_amount: off.target_amount ?? null,
    unlock_timestamp: Number(c.unlock_timestamp),
    created_timestamp: Number(c.created_timestamp),
    status: statusFor(c, Math.floor(Date.now() / 1000)),
  };
}

// ---------------------------------------------------------------------------
// Off-chain metadata side-store — description / template / target_amount.
//
// Soroban Vault struct stores only the financial fields. The mobile UI also
// renders `description`, `template`, and `target_amount`, which live OFF
// the contract. We persist this metadata in two tiers:
//
//   Tier 1 — Device AsyncStorage (`META_PREFIX:{owner}:{vault_id}`).
//            Instant local reads, survives app restarts.
//
//   Tier 2 — Backend `vault_meta` collection, keyed by
//            (owner_public_key, vault_id, contract_id). Cross-device mirror:
//            if the user installs the app on a second device with the same
//            secret seed, `listVaults` hydrates Tier 1 from Tier 2 on first
//            run so their vaults show real names instead of "Vault #N".
//
// Sync model:
//   - Writes (saveMeta) write Tier 1 SYNCHRONOUSLY, then Tier 2 BEST-EFFORT
//     in the background. Failures to mirror are logged-and-ignored so the
//     user can keep working offline.
//   - Reads (loadMeta) prefer Tier 1. listVaults pre-fetches all Tier 2
//     records for the owner and back-fills Tier 1 for any missing IDs in
//     one bulk pass — that's the cross-device hydration path.
// ---------------------------------------------------------------------------

const META_PREFIX = "xlm_vault_soroban_meta:";
const BACKEND_URL = process.env.EXPO_PUBLIC_BACKEND_URL ?? "";

interface VaultMeta {
  description: string;
  template: string;
  target_amount: number | null;
  name?: string;
  // Sprint 22 iter 41 — optional post-unlock destination pre-fill.
  // Stored alongside vault metadata so vault detail can render a
  // "Send to [label]" CTA once status === "unlocked". User always
  // signs manually — this is a UX pre-fill, not automation.
  withdrawal_destination?: string;
  withdrawal_destination_label?: string;
  /**
   * Sprint 23 iter 5 — memo saved alongside the withdrawal destination.
   * Set when the vault was created against an exchange / casino
   * address book entry that has a deposit memo. Send-flow pre-fills
   * this so users don't have to re-look-up their memo after a long
   * time-lock.
   */
  withdrawal_memo?: string;
  /** ID of the local Bill that spawned this vault (Feature 6). */
  bill_id?: string;
}

const EMPTY_META: VaultMeta = {
  description: "",
  template: "custom",
  target_amount: null,
  name: undefined,
};

async function loadMeta(owner: string, vaultId: string): Promise<VaultMeta> {
  const m = await storage.getItem<VaultMeta>(
    `${META_PREFIX}${owner}:${vaultId}`,
    EMPTY_META,
  );
  return m ?? EMPTY_META;
}

async function saveMetaLocal(
  owner: string,
  vaultId: string,
  meta: VaultMeta,
): Promise<void> {
  await storage.setItem(`${META_PREFIX}${owner}:${vaultId}`, meta);
}

async function saveMeta(
  owner: string,
  vaultId: string,
  meta: VaultMeta,
): Promise<void> {
  await saveMetaLocal(owner, vaultId, meta);
  // Tier 2 — best-effort cross-device mirror. We fire-and-forget so a slow
  // or offline backend never blocks the on-chain flow.
  void mirrorMetaToBackend(owner, vaultId, meta);
}

async function mirrorMetaToBackend(
  owner: string,
  vaultId: string,
  meta: VaultMeta,
): Promise<void> {
  if (!BACKEND_URL) return;
  try {
    await fetch(`${BACKEND_URL}/api/vault-meta/${owner}/${vaultId}`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        contract_id: getActiveDeployment().contractId,
        description: meta.description,
        template: meta.template,
        target_amount: meta.target_amount,
        name: meta.name,
        // Sprint 22 iter 41 — pass the optional withdrawal_destination
        // + bill_id fields (Feature 6 & 7). The backend ignores nulls
        // so vaults created without these fields keep working exactly
        // as before.
        withdrawal_destination: meta.withdrawal_destination ?? null,
        withdrawal_destination_label:
          meta.withdrawal_destination_label ?? null,
        // Sprint 23 iter 5 — memo alongside destination.
        withdrawal_memo: meta.withdrawal_memo ?? null,
        bill_id: meta.bill_id ?? null,
      }),
    });
  } catch {
    // Ignored on purpose — Tier 1 already succeeded.
  }
}

interface RemoteMeta {
  owner_public_key: string;
  vault_id: string;
  contract_id: string;
  description: string;
  template: string;
  target_amount: number | null;
  name?: string | null;
  // Sprint 22 iter 41 — Feature 6 & 7 fields. Mirrored from local
  // storage on create/update via mirrorMetaToBackend, then hydrated
  // back onto other devices via hydrateMetaImpl. Nullable so legacy
  // rows validate.
  withdrawal_destination?: string | null;
  withdrawal_destination_label?: string | null;
  // Sprint 23 iter 5 — memo alongside destination.
  withdrawal_memo?: string | null;
  bill_id?: string | null;
  // On-chain snapshot — last-known values written by the frontend after
  // a successful read. Used as the SOURCE OF TRUTH when the live RPC
  // read returns zeroed / uninitialized state (typical after a Hermes
  // XDR decode failure + events aging out of retention). All fields
  // optional — legacy records pre-dating the snapshot schema still
  // validate.
  balance_xlm?: number | null;
  unlock_timestamp?: number | null;
  snapshot_ledger?: number | null;
  snapshot_at?: string | null;
  on_chain_status?: string | null;
  // ISO timestamps from the backend. `created_at` is the first-upsert
  // anchor used by the History tab to synthesize a "Vault Created" event
  // for archived vaults whose on-chain create event has aged out of the
  // RPC retention window. `updated_at` is the last-edit timestamp.
  created_at?: string | null;
  updated_at?: string | null;
}

/**
 * Write the latest on-chain snapshot for a vault back to MongoDB.
 *
 * Why this exists:
 *   When Hermes XDR decoding fails on `simulateTransaction` AND the
 *   event retention window has aged out, the only place left with the
 *   vault's REAL balance / unlock_timestamp is the backend snapshot
 *   we wrote here on a previous (successful) read. Without these
 *   writes, the dashboard falls through to events-derived stubs that
 *   produce "Vault #N · 1970-01-01 · 0 XLM" cards.
 *
 * Strategy:
 *   - Fire-and-forget (no awaiting in the read path — never let
 *     persistence latency block a render).
 *   - Send a PATCH so we only mutate the fields we know about. We
 *     never null out a previously-good snapshot just because the
 *     caller forgot to include one field.
 *   - Skip when running in REST / testnet mode — backend has no
 *     snapshot schema there.
 *   - Skip vaults with status="archived" (we don't have real values
 *     to snapshot, just MongoDB-derived synthetics).
 */
// Session-scoped registry of vault keys (`{owner}::{vault_id}`) that we
// have ALREADY pushed a terminal `withdrawn` snapshot for. Used inside
// `pushSnapshotToBackend` to short-circuit repeated PATCH calls for the
// same vault — see Sprint Item 1B (archive freeze) for the rationale.
// Not persisted across process restarts because a fresh boot still
// benefits from ONE final terminal write per vault.
const _frozenSnapshots = new Set<string>();

async function pushSnapshotToBackend(
  owner: string,
  vaultId: string,
  snap: {
    balance_xlm?: number;
    unlock_timestamp?: number;
    snapshot_ledger?: number;
    on_chain_status?: "live" | "archived" | "withdrawn" | "unknown";
  },
): Promise<void> {
  if (!BACKEND_URL) return;
  // ---------------------------------------------------------------
  // Archive freeze (Sprint Item 1B): once a vault is reported as
  // `on_chain_status: "withdrawn"` we record it in a module-local
  // `Set` and SKIP every subsequent snapshot PATCH for that
  // (owner, vault_id) pair this session.
  //
  // Why: the on-chain state of a withdrawn vault is permanently
  // terminal — its balance is 0, withdraw event already happened,
  // and the unlock_timestamp is moot. Re-pushing the same payload
  // every listVaults() refresh just spins backend writes for no
  // information gain and keeps "dead" vaults in the background
  // sync hot loop. Cap it at first persistence.
  //
  // The set is intentionally NOT persisted to disk — fresh process
  // boots get one final write per terminal vault, which is the right
  // behaviour for new devices that haven't seen the meta yet.
  // ---------------------------------------------------------------
  const frozenKey = `${owner}::${vaultId}`;
  if (snap.on_chain_status === "withdrawn") {
    if (_frozenSnapshots.has(frozenKey)) return;
    _frozenSnapshots.add(frozenKey);
  }
  try {
    await fetch(
      `${BACKEND_URL}/api/vault-meta/${owner}/${vaultId}/snapshot`,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contract_id: getActiveDeployment().contractId,
          ...snap,
        }),
      },
    );
  } catch {
    // Best-effort. A failed snapshot write is non-fatal — the next
    // successful on-chain read will overwrite with fresh data.
  }
}

/**
 * Pull every Tier-2 record for `owner` and write any that we don't already
 * have locally into Tier 1. Called once per `listVaults` to keep things
 * lazy — no background sync workers, no startup roundtrips.
 */
async function hydrateMetaFromBackend(owner: string): Promise<void> {
  await hydrateMetaImpl(owner, { force: false });
}

/**
 * Explicit user-initiated sync: pull every Tier-2 record and OVERWRITE any
 * locally cached meta. Used by the dashboard's pull-to-refresh when the
 * user knows they want backend names (e.g. fresh device).
 *
 * Returns the number of meta records that were updated.
 */
export async function forceSyncMetaFromBackend(owner: string): Promise<number> {
  return hydrateMetaImpl(owner, { force: true });
}

// ---------------------------------------------------------------------------
// Sprint 21 iter 34 — Dismiss / auto-heal helper.
//
// A stuck vault is one whose backend meta still reads `on_chain_status: "live"`
// (or is undefined) but whose on-chain state has already been withdrawn or
// TTL-pruned — the frontend previously rendered such rows as "ready to
// withdraw" and the withdraw button would fail because there's nothing to
// withdraw. This helper flips the meta to `withdrawn`, zeroes the last-known
// balance, and returns a boolean success flag. Fire-and-forget by design
// (the caller normally kicks off a `load()` refresh right after).
//
// The endpoint used is the existing `PATCH /vault-meta/{owner}/{id}/snapshot`
// route which already supports `on_chain_status: "withdrawn"` — no new
// backend surface is added. Callers:
//   1. `buildArchivedOverlayFromMetas` — sync-time cross-check for
//      stale-live metas whose on-chain entry no longer exists.
//   2. `app/vault/[id].tsx` — user-triggered "Dismiss vault" action.
//   3. `app/vault/[id].tsx` — auto-heal on withdraw failure with a
//      known "entry not live / zero balance" signature.
// ---------------------------------------------------------------------------
export async function dismissVaultMeta(
  owner: string,
  vaultId: string,
): Promise<boolean> {
  if (!BACKEND_URL) return false;
  try {
    const res = await fetch(
      `${BACKEND_URL}/api/vault-meta/${owner}/${vaultId}/snapshot`,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contract_id: getActiveDeployment().contractId,
          on_chain_status: "withdrawn",
          balance_xlm: 0,
        }),
      },
    );
    return res.ok;
  } catch {
    return false;
  }
}

async function hydrateMetaImpl(
  owner: string,
  opts: { force: boolean },
): Promise<number> {
  if (!BACKEND_URL) return 0;
  let updated = 0;
  try {
    // Sprint 22 iter 38 — sync/refresh ONLY hits active vaults.
    //
    // Recurring bug: archived + withdrawn vaults were previously
    // fetched here and counted toward the "Refreshed X vaults" toast,
    // even though they have no reason to trigger a sync (their state
    // is terminal). The `?active_only=true` filter is implemented
    // server-side (see /app/backend/server.py list_vault_meta) and
    // returns ONLY rows whose on_chain_status is in {"live", "unknown"}
    // or is null/missing. Archived + withdrawn rows never enter this
    // pipeline.
    //
    // The archived-overlay builder in listVaults still fetches the
    // full set (no `active_only` flag) so the History tab remains
    // complete — this is intentional and lives at a different URL
    // construction site.
    const url = `${BACKEND_URL}/api/vault-meta/${owner}?contract_id=${encodeURIComponent(
      getActiveDeployment().contractId,
    )}&active_only=true`;
    const res = await fetch(url);
    if (!res.ok) return 0;
    const remotes = (await res.json()) as RemoteMeta[];
    // Diagnostic log: confirms in browser console that archived vaults
    // are excluded. Grep for `[sync-filter]` in the console to verify.
    console.info(
      `[sync-filter] hydrateMetaImpl(${owner.slice(0, 6)}…, force=${opts.force}) → ${remotes.length} active meta row(s). Archived + withdrawn excluded server-side.`,
    );
    await Promise.all(
      remotes.map(async (r) => {
        const local = await storage.getItem<VaultMeta>(
          `${META_PREFIX}${owner}:${r.vault_id}`,
          EMPTY_META,
        );
        const isMissing =
          !local ||
          (local.description === "" &&
            local.template === "custom" &&
            local.target_amount === null);
        if (opts.force || isMissing) {
          await saveMetaLocal(owner, r.vault_id, {
            description: r.description,
            template: r.template,
            target_amount: r.target_amount,
            name: r.name ?? undefined,
            withdrawal_destination: r.withdrawal_destination ?? undefined,
            withdrawal_destination_label:
              r.withdrawal_destination_label ?? undefined,
            withdrawal_memo: r.withdrawal_memo ?? undefined,
            bill_id: r.bill_id ?? undefined,
          });
          updated += 1;
        }
      }),
    );
  } catch {
    // Hydration is best-effort — listVaults will still render with stub
    // meta if the backend is unreachable.
  }
  return updated;
}

// ---------------------------------------------------------------------------
// Archived-vault overlay.
//
// Stellar Soroban contract data has a TTL — `persistent` storage entries
// live up to ~30 days by default before being moved to "archived" state.
// Once archived, `simulateTransaction(get_vault)` returns an entry-not-live
// error and the events stream may also have aged out of the RPC retention
// window. The vault is still REAL on-chain (the data is preserved across
// snapshots), but invisible to the live read paths until someone submits
// a `RestoreFootprint` operation to bring it back.
//
// To prevent older vaults from silently dropping off the dashboard, we
// fetch the off-chain backend meta records (the same Tier 2 mirror used
// by `hydrateMetaFromBackend`) and surface any vault_id that the backend
// knows about but is missing from the current live read as a synthetic
// `Vault` with `status: "archived"`. The card renders with a "Wake Up"
// CTA that calls `wakeUpVault` to restore the on-chain entry.
//
// Trade-offs (documented honestly):
//   - The on-chain balance / unlock_timestamp / created_timestamp aren't
//     recoverable from the meta side-store (those fields live ONLY in
//     the contract). We surface them as 0 / unknown and clearly mark
//     the card as "archived — wake up to refresh".
//   - If the user clears their device cache AND the backend mirror is
//     empty, the vault is irrecoverable from the UI. They'd need to
//     restore the entry directly via a Soroban-aware tool (stellar-cli,
//     a block explorer with RestoreFootprint UI, etc.).
//   - We only attempt this overlay when running against Soroban (this
//     module is only loaded then), so the REST client / testnet mode is
//     unaffected.
// ---------------------------------------------------------------------------

// (legacy `fetchArchivedVaultsFromMeta` helper removed — `listVaults`
// now fetches the metas itself and passes them directly to
// `buildArchivedOverlayFromMetas` to avoid the double round-trip and
// to keep the sanitisation + archived-overlay in sync. If you need an
// async version of this for a future code path, import
// `buildArchivedOverlayFromMetas` and pre-fetch with the same URL
// template you find in the listVaults block.)

/**
 * Same logic as the old `fetchArchivedVaultsFromMeta` but operates on a
 * pre-fetched `metas[]`. `listVaults` uses this to avoid a second
 * backend round-trip when the metas have already been pulled for the
 * sanitisation step.
 *
 * For each archived row we emit, we honour the backend snapshot:
 *   - balance: meta.balance_xlm if present (else 0)
 *   - unlock_timestamp: meta.unlock_timestamp if present (else 0)
 *   - created_timestamp: parsed from meta.created_at
 * That way, even archived cards can show "last known: X XLM" once a
 * snapshot has been written. Without a snapshot the card falls back to
 * the "ledger entry pruned by TTL" copy.
 */
function buildArchivedOverlayFromMetas(
  owner: string,
  remotes: RemoteMeta[],
  liveIds: Set<string>,
): Vault[] {
  const out: Vault[] = [];
  for (const r of remotes) {
    if (liveIds.has(r.vault_id)) continue;
    const createdTs = parseIsoToUnix(r.created_at ?? r.updated_at ?? null);
    // Respect the meta's last-known on-chain status:
    //   - `withdrawn` → render as a withdrawn card (with real numbers)
    //     even though the live RPC reads can't see it. This is what
    //     happens after the user successfully withdraws and then the
    //     create event ages out of RPC retention: the row should keep
    //     showing as "withdrawn", NOT downgrade to "archived" + Wake Up.
    //   - `live` → if we have a real unlock + balance snapshot, render
    //     as locked/unlocked based on the current time. The user can
    //     still tap Wake Up if they want to bump TTL.
    //   - anything else / null → archived (the default for synthetic
    //     stubs and truly-pruned entries).
    let status: Vault["status"] = "archived";
    if (r.on_chain_status === "withdrawn") {
      status = "withdrawn";
    } else if (
      r.on_chain_status === "live" &&
      (r.unlock_timestamp ?? 0) > 0
    ) {
      const nowSec = Math.floor(Date.now() / 1000);
      status = nowSec >= (r.unlock_timestamp ?? 0) ? "unlocked" : "locked";
    }

    // -----------------------------------------------------------------
    // Sprint 21 iter 34 — Sync-time auto-heal for stale "live" metas.
    //
    // If a meta says `on_chain_status: "live"` AND we're synthesising
    // an OVERLAY row for it (i.e. it is NOT in liveIds), that's the
    // exact stuck-vault signature the user reported: the on-chain
    // entry no longer exists (TTL-pruned or withdrawn) but the meta
    // still says "live", so the row incorrectly renders as ready-to-
    // withdraw. We flip the meta to `withdrawn` server-side via the
    // existing PATCH endpoint (fire-and-forget) AND coerce the
    // in-memory status so the current render is already correct.
    // Balance is forced to 0 for the same reason. `createdTs` and
    // `name` are preserved so the History tab still shows the row.
    // -----------------------------------------------------------------
    let balance = r.balance_xlm ?? 0;
    if (r.on_chain_status === "live") {
      // Diagnostic log surface for the stale-live auto-heal event
      // stream. Kept as `console.info` so the browser console shows
      // it during development; production release builds strip
      // console.info via metro-minify config.
      console.info(
        `[sync-auto-heal] Vault ${r.vault_id} meta says live but is not ` +
          `in the on-chain live set — coercing to withdrawn.`,
      );
      status = "withdrawn";
      balance = 0;
      void dismissVaultMeta(owner, r.vault_id);
    }

    out.push({
      vault_id: r.vault_id,
      owner_public_key: owner,
      name: r.name?.trim() ? r.name : `Vault #${r.vault_id}`,
      description: r.description ?? "",
      template: r.template ?? "custom",
      balance,
      target_amount: r.target_amount ?? null,
      unlock_timestamp: r.unlock_timestamp ?? 0,
      created_timestamp: createdTs,
      status,
    });
  }
  return out;
}

/**
 * Parse an ISO-8601 string returned by the FastAPI backend into a Unix
 * epoch (seconds). Returns 0 on any failure so callers don't have to
 * branch — 0 sorts to the bottom of the History tab, which is the
 * desired behavior for an unknown timestamp anyway.
 */
function parseIsoToUnix(iso: string | null | undefined): number {
  if (!iso) return 0;
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return 0;
  return Math.floor(ms / 1000);
}

/**
 * Synthesize "Vault Created" History rows for archived vaults whose
 * on-chain `create` event has aged out of the RPC retention window.
 *
 * Why:
 *   The History tab is powered by `fetchContractEvents` which queries
 *   the Soroban RPC `getEvents` endpoint. Public RPCs retain events
 *   for roughly 7 days (Ankr) or less (community providers). Any vault
 *   created BEFORE that window has no live "create" event for us to
 *   render — its row would just be missing.
 *
 * What:
 *   For every backend meta record (`vault_meta` MongoDB collection)
 *   whose vault_id is NOT present in the live event stream as a
 *   `create` row, we emit a synthetic VaultTransaction:
 *     - kind         = "create"
 *     - tx_id        = `meta:{vault_id}` (sentinel string, no on-chain tx)
 *     - timestamp    = parsed `created_at` (anchored on FIRST upsert)
 *     - note         = "Restored from backend (on-chain tx archived)"
 *     - amount       = 0 (initial_deposit isn't tracked off-chain)
 *
 *   The sentinel `tx_id` is deliberately non-hex so any caller that
 *   tries to look it up on Horizon won't be confused into hitting an
 *   invalid endpoint.
 *
 * Trade-offs (documented honestly):
 *   - We can't recover the original initial_deposit amount. We set 0
 *     so the History row doesn't display a misleading "+5 XLM" deposit.
 *   - We can't recover the original `unlock_timestamp` set at creation.
 *     The note field calls out that the row is reconstructed, not raw.
 *   - If a vault's create event IS still in retention but its meta was
 *     deleted (rare — pull-to-refresh re-hydrates), we'd render only
 *     the live event. That's fine.
 */
async function fetchArchivedCreateEvents(
  owner: string,
  liveEvents: ParsedEvent[],
): Promise<ParsedEvent[]> {
  if (!BACKEND_URL) return [];
  // Determine which vault_ids already have a live "create" row — those
  // are NOT archived from a History POV and shouldn't get a synth row.
  const liveCreatedIds = new Set(
    liveEvents.filter((e) => e.kind === "create").map((e) => e.vault_id),
  );
  try {
    const url = `${BACKEND_URL}/api/vault-meta/${owner}?contract_id=${encodeURIComponent(
      getActiveDeployment().contractId,
    )}`;
    const res = await fetch(url);
    if (!res.ok) return [];
    const remotes = (await res.json()) as RemoteMeta[];
    const out: ParsedEvent[] = [];
    for (const r of remotes) {
      if (liveCreatedIds.has(r.vault_id)) continue;
      const ts = parseIsoToUnix(r.created_at ?? r.updated_at ?? null);
      out.push({
        // Sentinel id so FlatList keyExtractor stays unique and Horizon
        // lookups (if any future code wires them) skip non-hex tx_ids.
        tx_id: `meta:${r.vault_id}`,
        vault_id: r.vault_id,
        owner_public_key: owner,
        kind: "create",
        amount: 0,
        note:
          r.name?.trim()
            ? `${r.name} · reconstructed from backend metadata`
            : "Reconstructed from backend metadata (on-chain event archived)",
        timestamp: ts,
        created_at: r.created_at ?? r.updated_at ?? new Date(0).toISOString(),
      });
    }
    return out;
  } catch {
    // History reconstruction is best-effort. Backend unreachable just
    // means the History tab shows whatever live events we got — same as
    // before this feature shipped.
    return [];
  }
}

// ---------------------------------------------------------------------------
// Read-only contract calls via simulateTransaction (no signing).
// ---------------------------------------------------------------------------

// Known-funded source accounts used purely as the "source" of read-only
// simulations. simulateTransaction does not actually submit, but it does
// require the source account to exist on-chain so the RPC can resolve its
// sequence number. We use one well-known funded account per network.
//
// - Testnet: the contract deployer (also friendbot-funded).
// - Mainnet: the Stellar Development Foundation cold wallet (a stable,
//   never-deleted mainnet account). If you'd prefer to point at a different
//   funded mainnet account, change this constant — it is never signed for.
const READ_SIM_SOURCE: Record<"testnet" | "mainnet", string> = {
  testnet: "GAEPPLTQ4OIBG4J6DSI33FDYBB7YCKWOT36DNVLNOV65PIVSBAVSGXLS",
  mainnet: "GA5XIGA5C7QTPTWXQHY6MCJRMTRZDOSHR6EFIBNDQTCQHG262N7CBT4P",
};

async function invokeRead(method: string, params: xdr.ScVal[]): Promise<xdr.ScVal> {
  let source: Account;
  const dep = getActiveDeployment();
  const simSourcePk = READ_SIM_SOURCE[dep.network];
  try {
    // simulateTransaction needs a source account; we use a known-funded
    // address per network. The simulation does not actually submit, so any
    // well-formed funded source works.
    source = await loadAccount(simSourcePk);
  } catch (e) {
    throw new SorobanNetworkError(method, "build", e);
  }
  const contract = new Contract(dep.contractId);
  let tx: Transaction;
  try {
    tx = new TransactionBuilder(source, {
      fee: BASE_FEE,
      networkPassphrase: dep.networkPassphrase,
    })
      .addOperation(contract.call(method, ...params))
      .setTimeout(60)
      .build();
  } catch (e) {
    throw new SorobanNetworkError(method, "build", e);
  }
  // Simulate with RPC failover. simulateTransaction is a pure read
  // (no submission, no fee), so retrying across providers is safe.
  let sim;
  const total = 1 + (dep.rpcFallbacks?.length ?? 0);
  let lastErr: unknown;
  for (let attempt = 0; attempt < Math.max(1, total); attempt++) {
    try {
      sim = await rpcServer().simulateTransaction(tx);
      break;
    } catch (e) {
      lastErr = e;
      if (!isRpcTransportError(e) || attempt === total - 1) {
        throw new SorobanNetworkError(method, "simulate", e);
      }
      rotateRpcUrl(e);
    }
  }
  if (!sim) {
    throw new SorobanNetworkError(method, "simulate", lastErr);
  }
  if (StellarRpc.Api.isSimulationError(sim)) {
    throw new SorobanSimulationError(method, sim.error);
  }
  if (!sim.result) {
    throw new SorobanSimulationError(method, "Empty simulation result");
  }
  return sim.result.retval;
}

// ---------------------------------------------------------------------------
// On-chain event reader — powers History tab in Soroban mode.
//
// Soroban's `getEvents` RPC returns a flat list of contract events filtered
// by contractId + (optional) topic patterns. The XlmVault contract emits
// four event types — see `contracts/xlm_vault/src/lib.rs`:
//
//   topics = (Symbol "create"   , Address owner) ; value = (vault_id, amount, unlock_ts)
//   topics = (Symbol "deposit"  , Address caller); value = (vault_id, amount)
//   topics = (Symbol "extend"   , Address caller); value = (vault_id, new_unlock_ts)
//   topics = (Symbol "withdraw" , Address caller); value = (vault_id, amount)
//
// We fetch a window of recent events (last ~24h on testnet, well within the
// rpc retention) and parse them into the `VaultTransaction` shape the UI
// already renders. The owner / vault filter happens client-side because the
// rpc topic patterns can't pattern-match by Address on this SDK without
// pre-encoding to XDR base64.
//
// Pagination: we walk the cursor until either (a) the rpc returns < limit
// events, or (b) we hit MAX_EVENTS — both are cheap stop conditions and keep
// the History tab responsive even after months of activity.
// ---------------------------------------------------------------------------

const EVENT_LEDGERS_WINDOW = 17_280; // ~24h on testnet (5s ledgers).
const EVENT_PAGE_LIMIT = 200;
const MAX_EVENTS = 1000;

type ParsedEvent = VaultTransaction;

function decodeKind(sym: string): VaultTransaction["kind"] | null {
  switch (sym) {
    case "create":
      return "create";
    case "deposit":
      return "deposit";
    case "extend":
      return "extend";
    case "withdraw":
      return "withdraw";
    default:
      return null;
  }
}

function parseEvent(ev: StellarRpc.Api.EventResponse): ParsedEvent | null {
  if (ev.topic.length < 2) return null;
  const kindRaw = scValToNative(ev.topic[0]);
  const kind = decodeKind(String(kindRaw));
  if (!kind) return null;
  const ownerRaw = scValToNative(ev.topic[1]);
  const owner = String(ownerRaw);

  // value is a tuple-array after scValToNative.
  const value = scValToNative(ev.value) as unknown[];
  if (!Array.isArray(value) || value.length === 0) return null;
  const vaultId = String(value[0]);

  let amount = 0;
  let note = "";
  if (kind === "create") {
    // (vault_id, initial_deposit, unlock_ts)
    amount = stroopsToXlm(BigInt(value[1] as string | number | bigint));
    note = `unlock ${new Date(Number(value[2]) * 1000).toISOString().slice(0, 10)}`;
  } else if (kind === "deposit" || kind === "withdraw") {
    amount = stroopsToXlm(BigInt(value[1] as string | number | bigint));
  } else if (kind === "extend") {
    note = `new unlock ${new Date(Number(value[1]) * 1000).toISOString().slice(0, 10)}`;
  }

  return {
    tx_id: ev.txHash,
    vault_id: vaultId,
    owner_public_key: owner,
    kind,
    amount,
    note,
    timestamp: Math.floor(new Date(ev.ledgerClosedAt).getTime() / 1000),
    created_at: ev.ledgerClosedAt,
  };
}

/**
 * Fetch ALL recent vault events from the contract. The caller filters by
 * owner/vault as needed — that keeps the cache friendly (one rpc burst per
 * History tab render).
 *
 * Caching strategy (two tiers):
 *   1. In-memory cache (`eventCache`) — dedupes rapid History/vault-detail
 *      re-fetches within 8s.
 *   2. Persistent AsyncStorage cache (`EVENT_DISK_KEY`) — keyed by the
 *      contract address + a coarse ledger range. Survives app restarts and
 *      lets the History tab render IMMEDIATELY from disk while the
 *      background rpc fetch refreshes it. Also serves as a fallback when
 *      the rpc round-trip fails (e.g. flight mode / spotty connection).
 *
 * Returns events sorted by the underlying iteration order from rpc (we
 * don't re-sort here; callers sort by timestamp).
 */
let eventCache: { at: number; data: ParsedEvent[] } | null = null;
const EVENT_CACHE_MS = 8_000; // dedupe rapid History/vault-detail re-fetches
// Cache key MUST be a function — module load happens before the
// SessionProvider hydrates the active network, so a `const` snapshot would
// pin the testnet contract id even after the user switches to mainnet.
function eventDiskKey(): string {
  return `xlm_vault_events_cache:${getActiveDeployment().contractId}`;
}
// Also: drop the in-memory cache whenever the active network changes so a
// switch from testnet → mainnet doesn't bleed testnet events into the
// mainnet History tab.
subscribeActiveNetwork(() => {
  eventCache = null;
});
const EVENT_DISK_TTL_MS = 24 * 60 * 60 * 1000; // 24h — same window as the rpc query

interface PersistedEvents {
  contractId: string;
  fetchedAt: number;
  latestLedger: number;
  startLedger: number;
  events: ParsedEvent[];
}

async function readDiskCache(): Promise<PersistedEvents | null> {
  try {
    const raw = await storage.getItem(eventDiskKey(), "" as string);
    if (!raw || typeof raw !== "string") return null;
    const parsed = JSON.parse(raw) as PersistedEvents;
    if (parsed.contractId !== getActiveDeployment().contractId) return null;
    if (Date.now() - parsed.fetchedAt > EVENT_DISK_TTL_MS) return null;
    return parsed;
  } catch {
    return null;
  }
}

async function writeDiskCache(payload: PersistedEvents): Promise<void> {
  try {
    await storage.setItem(eventDiskKey(), JSON.stringify(payload));
  } catch {
    // Cache writes are best-effort; never let them break the fetch path.
  }
}

async function fetchContractEvents(): Promise<ParsedEvent[]> {
  if (eventCache && Date.now() - eventCache.at < EVENT_CACHE_MS) {
    return eventCache.data;
  }
  // Both `getLatestLedger` and `getEvents` are pure reads, so we run them
  // through the same failover loop as `loadAccount` / `invokeRead`. If we
  // exhaust every candidate RPC we fall back to whatever events were
  // cached on disk so the History tab is never blank.
  const dep = getActiveDeployment();
  const total = 1 + (dep.rpcFallbacks?.length ?? 0);

  let latestLedger: number | undefined;
  let latestErr: unknown;
  for (let attempt = 0; attempt < Math.max(1, total); attempt++) {
    try {
      const latest = await rpcServer().getLatestLedger();
      latestLedger = latest.sequence;
      break;
    } catch (e) {
      latestErr = e;
      if (!isRpcTransportError(e) || attempt === total - 1) break;
      rotateRpcUrl(e);
    }
  }
  if (latestLedger == null) {
    // RPC unreachable on every candidate — return whatever we cached
    // last (possibly empty) so History at least shows stale data.
    const disk = await readDiskCache();
    if (disk) {
      eventCache = { at: Date.now(), data: disk.events };
      return disk.events;
    }
    throw new SorobanNetworkError("getEvents", "build", latestErr);
  }
  const startLedger = Math.max(1, latestLedger - EVENT_LEDGERS_WINDOW);

  const events: ParsedEvent[] = [];
  let cursor: string | undefined;
  const MAX_PAGES = 20;
  for (let page = 0; page < MAX_PAGES && events.length < MAX_EVENTS; page++) {
    let res;
    let pageErr: unknown;
    for (let attempt = 0; attempt < Math.max(1, total); attempt++) {
      try {
        const req = cursor
          ? { filters: [{ type: "contract" as const, contractIds: [getActiveDeployment().contractId] }], cursor, limit: EVENT_PAGE_LIMIT }
          : { filters: [{ type: "contract" as const, contractIds: [getActiveDeployment().contractId] }], startLedger, limit: EVENT_PAGE_LIMIT };
        res = await rpcServer().getEvents(
          req as Parameters<StellarRpc.Server["getEvents"]>[0],
        );
        break;
      } catch (e) {
        pageErr = e;
        if (!isRpcTransportError(e) || attempt === total - 1) break;
        rotateRpcUrl(e);
      }
    }
    if (!res) {
      // Mid-flight rpc error after exhausting fallbacks: prefer falling
      // back to disk over an empty list.
      const disk = await readDiskCache();
      if (disk) {
        eventCache = { at: Date.now(), data: disk.events };
        return disk.events;
      }
      throw new SorobanNetworkError("getEvents", "simulate", pageErr);
    }
    for (const ev of res.events) {
      const parsed = parseEvent(ev);
      if (parsed) events.push(parsed);
    }
    if (!res.cursor || res.cursor === cursor) break;
    cursor = res.cursor;
  }

  eventCache = { at: Date.now(), data: events };
  // Persist asynchronously; do not block return.
  void writeDiskCache({
    contractId: getActiveDeployment().contractId,
    fetchedAt: Date.now(),
    latestLedger,
    startLedger,
    events,
  });
  return events;
}

/**
 * Invalidate ALL in-memory and on-disk caches that could pin stale state.
 *
 * Called from `wakeUpVault` after a successful Restore+Extend so the
 * next `listVaults` / `vaultTransactions` / `allTransactions` call
 * re-reads the chain instead of serving the pre-wake-up cache. Without
 * this the dashboard would keep tagging the just-woken-up vault as
 * "archived" for up to EVENT_CACHE_MS, and the cached vault list would
 * keep the pre-wake-up balance/unlock for another 24h.
 *
 * Strategy:
 *   - eventCache (8s in-memory)          → drop
 *   - event disk cache (24h AsyncStorage) → drop (rewritten on next fetch)
 *   - simulate-broken flag                → leave alone (orthogonal to TTL)
 *   - cached vault list per owner         → leave alone; `mergeVaults`
 *     correctly upgrades archived → live on the next listVaults read.
 *     Keeping the cache means we don't blank the dashboard during the
 *     re-read; we just overlay fresh data on top.
 */
function invalidateAllCaches(): void {
  eventCache = null;
  // Disk wipe is fire-and-forget — no need to block the caller. Use the
  // current contract's key so a multi-network app doesn't accidentally
  // nuke caches from the OTHER network.
  void storage.removeItem(eventDiskKey()).catch(() => {});
}

/**
 * Public entry point for forcing a fresh ledger read on the next
 * listVaults / getVault call. Used by `/vault/[id]` mount and by
 * vault-index transitions on the dashboard to defeat any potentially
 * stale Soroban RPC cache (Sprint Item 1A — Vault 2 cross-vault
 * state-bleed fix).
 *
 * Safe to call any time; idempotent.
 */
export function invalidateRpcCaches(): void {
  invalidateAllCaches();
}

// ---------------------------------------------------------------------------
// Last-sync tracking — surfaces a "Last synced X min ago" badge on the
// dashboard when Soroban mode is active. Updated on every successful
// `listVaults` call (the user's primary sync moment).
// ---------------------------------------------------------------------------
let lastSyncedAt: number | null = null;

export function getLastSyncedAt(): number | null {
  return lastSyncedAt;
}

// ---------------------------------------------------------------------------
// Sticky "simulate is broken on this runtime" flag.
//
// User-reported symptom on the v1.0.9 APK:
//   Dashboard throws "Network error during build: invalid checksum" on
//   first load. The error originates from `@stellar/stellar-sdk`'s
//   `scValToNative` / strkey-checksum path inside `simulateTransaction`
//   — a LOCAL XDR-decode failure on Hermes, NOT a network problem. Once
//   tripped, every subsequent simulate call on this device keeps failing
//   the same way, but our previous defaults still attempted simulate
//   first on every refresh and only fell back AFTER spinning through the
//   full RPC retry budget. That made the dashboard feel "stuck" even
//   when the events-derived path could have produced a perfectly good
//   answer immediately.
//
// Cure: once we observe an XDR / Buffer / scValToNative error from a
// simulate call, flip this flag for the rest of the session. Future
// `listVaults` / `getVault` calls jump STRAIGHT to the events-derived
// path + cache, skipping the broken simulate entirely. The flag resets
// on cold boot (intentional — we want a fresh build to re-probe in case
// a polyfill upgrade fixed things).
// ---------------------------------------------------------------------------
let simulatePathBroken = false;

/**
 * Pattern-match on the error message to decide whether this is a LOCAL
 * SDK decode failure (deterministic across providers, the events fallback
 * will help) vs. a genuine network/server problem (events fallback will
 * also fail — but we still want to try cache).
 *
 * Symptoms collected from production crash reports:
 *   - "invalid checksum"            — strkey decode of SCAddress
 *   - "Bad union switch"            — XDR variant mismatch
 *   - "scValToNative"               — direct SDK conversion throw
 *   - "Buffer" / "TextEncoder"      — Hermes/V8 binary primitive mismatch
 *   - "Cannot read prop" + "decode" — generic SDK decoder dereference
 *
 * False positives are SAFE here: marking a real network error as "XDR"
 * just makes us skip simulate and try events, which is at worst a
 * minor perf cost.
 */
function isXdrParseError(e: unknown): boolean {
  if (!e) return false;
  const msg = e instanceof Error ? e.message : String(e);
  const lc = msg.toLowerCase();
  return (
    lc.includes("invalid checksum") ||
    lc.includes("scvaltonative") ||
    lc.includes("bad union switch") ||
    lc.includes("bad value") ||
    lc.includes("xdr") ||
    // Hermes-only — strict V8 wouldn't see these:
    lc.includes("buffer is not") ||
    lc.includes("textencoder") ||
    lc.includes("textdecoder") ||
    // SDK decoder dereference styles:
    /cannot read prop\w+ of (?:undefined|null)/.test(lc)
  );
}

/**
 * Mark the simulate path as broken for the rest of the session. Idempotent.
 * Called whenever we catch an `isXdrParseError` on a simulate-derived code
 * path.
 */
function markSimulateBroken(reason: unknown): void {
  if (simulatePathBroken) return;
  simulatePathBroken = true;
  // Log loud-and-clear so users (and we) can see this in their device
  // bug reports. Single log per session to keep the console tidy.
  console.warn(
    "[xlm-vault] Simulate path disabled for this session — using events + cache fallback. Cause:",
    reason instanceof Error ? reason.message : String(reason),
  );
}

/**
 * Public diagnostic — `Diagnostics` screen surfaces this so users can see
 * "Why is my dashboard using stale data?".
 */
export function isSimulatePathBroken(): boolean {
  return simulatePathBroken;
}

// ---------------------------------------------------------------------------
// Event-derived vault aggregation — Hermes fallback for `simulateTransaction`.
//
// Why this exists:
//   On some carrier/RPC combinations the `simulateTransaction` →
//   `scValToNative(retval)` path that powers `listVaults` / `getVault`
//   either returns a malformed payload (manifesting as "Invalid Checksum")
//   or trips a Buffer-vs-Uint8Array mismatch inside the SDK that's
//   invisible on V8 but fatal on Hermes. The exact same wallet's
//   `getEvents` stream parses cleanly through the History tab — proof
//   that the contract's on-chain state IS reachable, just not via the
//   simulate path.
//
//   So we rebuild the canonical vault list by walking the same event
//   stream. Every state-changing on-chain operation emits an event:
//
//     ("create",   owner)   value (vault_id, initial_deposit, unlock_ts)
//     ("deposit",  caller)  value (vault_id, amount)
//     ("extend",   caller)  value (vault_id, new_unlock_ts)
//     ("withdraw", caller)  value (vault_id, amount)   ← balance → 0
//
//   Replaying them in ledger order (oldest first) lets us reconstruct
//   each vault's `balance`, `unlock_timestamp`, and `withdrawn` flag.
//
// Trade-offs (documented honestly):
//   - The on-chain `created_timestamp` field is not in any event payload,
//     so we approximate it with the `create` event's `ledgerClosedAt`
//     timestamp — close enough for UI sort and "created X days ago".
//   - The vault `name` lives in the contract struct, not in events. We
//     fall back to the off-chain `vault_meta` description (or "Vault #N")
//     when reconstructing — the simulate path was already doing the same
//     hydration so this is no regression.
//   - We only see events within the RPC's retention window. For Mainnet
//     SDF that's ~7 days; for community RPCs it's typically 24h–7d. A
//     vault created BEFORE the window will not appear via this fallback —
//     the simulate path remains the source of truth for cold history.
//     This is acceptable for the user's current pain (a vault just
//     created today is invisible on the dashboard).
//
// Implementation notes:
//   - Events come back in DESCENDING ledger order from the RPC. We sort
//     ASC before replay so deposits/extends/withdraws apply in causal
//     order.
//   - `withdraw` collapses the vault: balance → 0, status → "withdrawn".
//     Future deposits/extends on a withdrawn vault are still applied
//     (the contract permits a non-zero balance on a withdrawn vault if
//     the caller re-deposits) — we keep the latest withdrawn flag.
// ---------------------------------------------------------------------------

async function aggregateVaultsFromEvents(
  owner: string,
  remoteMetasById?: Map<string, RemoteMeta>,
): Promise<Vault[]> {
  // fetchContractEvents proven to work on the History tab — same code
  // path, same RPC failover, same cache.
  const events = await fetchContractEvents();
  const ownerEvents = events.filter((e) => e.owner_public_key === owner);
  // Sort ASC by timestamp so create comes before deposit/extend/withdraw.
  ownerEvents.sort((a, b) => a.timestamp - b.timestamp);

  type Accum = {
    vault_id: string;
    balance_xlm: number;
    unlock_timestamp: number;
    created_timestamp: number;
    withdrawn: boolean;
  };
  const byId = new Map<string, Accum>();

  // Helper: extract a numeric unix-seconds timestamp from an event's
  // "note" string. Both `create` and `extend` events stash the unlock
  // date in note as `"unlock YYYY-MM-DD"` or `"new unlock YYYY-MM-DD"`.
  //
  // SAFETY: returns 0 (sentinel "unknown") for any parse that yields a
  // year outside [2020, 2100]. This prevents bad notes (truncated /
  // synthetic / reconstructed) from producing 1970-style or far-future
  // timestamps that would otherwise sneak past the sanitisation gate
  // (`unlock_timestamp > 0`) in `listVaults` and clobber the
  // authoritative MongoDB snapshot for the same vault.
  //
  // We ALSO carry the raw u64 unlock_ts through `ParsedEvent.raw_unlock_ts`
  // (see parseEvent) — this function only runs as a last-resort fallback
  // when the raw value is unavailable.
  function dateNoteToSec(note: string): number {
    const m = note.match(/(\d{4})-(\d{2})-(\d{2})/);
    if (!m) return 0;
    const year = parseInt(m[1], 10);
    if (!Number.isFinite(year) || year < 2020 || year > 2100) return 0;
    const ms = Date.parse(`${m[1]}-${m[2]}-${m[3]}T00:00:00Z`);
    return Number.isFinite(ms) ? Math.floor(ms / 1000) : 0;
  }

  for (const ev of ownerEvents) {
    const id = ev.vault_id;
    let v = byId.get(id);
    if (!v) {
      // We only seed an accumulator on the `create` event. If we
      // somehow see a deposit/extend for an unknown vault (window
      // truncation), we skip it — it can't reconstruct without the
      // create record.
      if (ev.kind !== "create") continue;
      v = {
        vault_id: id,
        balance_xlm: 0,
        unlock_timestamp: dateNoteToSec(ev.note),
        created_timestamp: ev.timestamp,
        withdrawn: false,
      };
      byId.set(id, v);
    }
    switch (ev.kind) {
      case "create":
        v.balance_xlm += ev.amount;
        // unlock + created already seeded above on first sighting.
        break;
      case "deposit":
        v.balance_xlm += ev.amount;
        break;
      case "extend": {
        const newUnlock = dateNoteToSec(ev.note);
        if (newUnlock > v.unlock_timestamp) v.unlock_timestamp = newUnlock;
        break;
      }
      case "withdraw":
        v.balance_xlm = 0;
        v.withdrawn = true;
        break;
    }
  }

  // Hydrate descriptions/templates from the off-chain meta side-store
  // (same store the simulate path already uses, so non-name fields stay
  // identical). The on-chain `name` is NOT in any event payload, so the
  // events-derived path can only show "Vault #N" — a known, acceptable
  // trade-off compared to leaving the user with a blank dashboard.
  //
  // SOURCE-OF-TRUTH POLICY (MongoDB > event-derived):
  //   The event-derived `unlock_timestamp` is reconstructed from the
  //   `"unlock YYYY-MM-DD"` note string and therefore loses time-of-day
  //   precision (it's pinned to UTC midnight of the day). If the
  //   backend has a snapshot of the REAL on-chain unlock_timestamp
  //   (`remoteMetasById[vault_id].unlock_timestamp`), we ALWAYS prefer
  //   that value. Same logic applies to `balance` for non-withdrawn
  //   vaults — the events sum can drift from on-chain reality if the
  //   RPC event window truncated some deposits/withdraws. This is the
  //   "MongoDB is the absolute source of truth for unlock_timestamp"
  //   guarantee the user demanded after the 4-vault sprint test.
  const nowSec = Math.floor(Date.now() / 1000);
  const out: Vault[] = [];
  for (const v of byId.values()) {
    const meta = await loadMeta(owner, v.vault_id);
    const remote = remoteMetasById?.get(v.vault_id);

    // 1) unlock_timestamp: MongoDB snapshot wins when present.
    const finalUnlock =
      remote && (remote.unlock_timestamp ?? 0) > 0
        ? (remote.unlock_timestamp as number)
        : v.unlock_timestamp;

    // 2) balance: MongoDB snapshot wins when:
    //      (a) we have one, AND
    //      (b) the vault is NOT marked withdrawn by events (because the
    //          `withdraw` event correctly zeroes the balance on-chain and
    //          we should honour that to keep withdrawn cards consistent).
    const finalBalance =
      remote && remote.balance_xlm != null && !v.withdrawn
        ? remote.balance_xlm
        : v.balance_xlm;

    // 3) Withdrawn flag: respect MongoDB's `on_chain_status === "withdrawn"`
    //    even if we never saw the withdraw event in the live window (event
    //    aged out). This is what keeps an old withdrawn vault from
    //    appearing as "locked" in the dashboard after RPC retention drops
    //    its withdraw event.
    const finalWithdrawn =
      v.withdrawn || remote?.on_chain_status === "withdrawn";

    // 4) created_timestamp: events-derived value is anchored on the
    //    create event's ledgerClosedAt, which is accurate. Only fall
    //    back to MongoDB `created_at` if events somehow lacked a
    //    timestamp (shouldn't happen but defensive).
    const finalCreated =
      v.created_timestamp > 0
        ? v.created_timestamp
        : parseIsoToUnix(remote?.created_at ?? remote?.updated_at ?? null);

    const status: Vault["status"] = finalWithdrawn
      ? "withdrawn"
      : nowSec >= finalUnlock
      ? "unlocked"
      : "locked";

    // Name priority: backend remote.name → local meta.name → "Vault #N".
    const name =
      remote?.name?.trim()
        ? remote.name!
        : meta.name?.trim()
        ? meta.name
        : `Vault #${v.vault_id}`;

    out.push({
      vault_id: v.vault_id,
      owner_public_key: owner,
      name,
      description: remote?.description ?? meta.description ?? "",
      template: remote?.template ?? meta.template ?? "custom",
      balance: finalWithdrawn ? 0 : finalBalance,
      target_amount: remote?.target_amount ?? meta.target_amount ?? null,
      unlock_timestamp: finalUnlock,
      created_timestamp: finalCreated,
      status,
    });
  }

  // Newest first — same order users see on the History tab.
  out.sort((a, b) => b.created_timestamp - a.created_timestamp);
  return out;
}

// ---------------------------------------------------------------------------
// Public API: real SorobanVaultClient
// ---------------------------------------------------------------------------

class SorobanVaultClient implements IVaultClient {
  readonly kind = "soroban" as const;

  async registerWallet(publicKey: string) {
    // No-op: Soroban doesn't need an off-chain wallet registry. Accounts
    // come into existence the moment the user funds them via friendbot.
    return { public_key: publicKey };
  }

  async summary(publicKey: string): Promise<Summary> {
    const vaults = await this.listVaults(publicKey);
    let total_locked = 0;
    let total_unlocked = 0;
    let active = 0;
    let completed = 0;
    for (const v of vaults) {
      if (v.status === "locked") {
        total_locked += v.balance;
        active += 1;
      } else if (v.status === "unlocked") {
        total_unlocked += v.balance;
        active += 1;
      } else {
        completed += 1;
      }
    }
    return {
      total_locked,
      total_unlocked,
      // `total_withdrawn` is not tracked on-chain (contract zeroes balance on
      // withdraw). Surfacing 0 is honest; the History view recomputes it
      // from emitted events for the explorer-style screens.
      total_withdrawn: 0,
      active_vaults: active,
      completed_vaults: completed,
    };
  }

  async listVaults(owner: string): Promise<Vault[]> {
    // Hydrate cross-device meta (fire-and-forget — runs alongside the rpc
    // call so the first paint isn't blocked when the backend is slow).
    try {
      void hydrateMetaFromBackend(owner);
    } catch {
      // never blocks the main flow
    }

    // Persistent cache (across app restarts AND across the RPC's event-
    // retention horizon). Read it FIRST so we can merge any
    // network-derived result with vaults the RPC can no longer prove
    // exist. See `src/api/vault-cache.ts` for the design rationale.
    const cached = await loadCachedVaults(owner).catch(() => [] as Vault[]);

    // ----------------------------------------------------------------------
    // EARLY FETCH: pull every backend meta record for this owner BEFORE we
    // run either the simulate or events path.
    //
    // Why early? Because both fallback paths benefit from MongoDB as the
    // source of truth:
    //   - `aggregateVaultsFromEvents` consumes the metas map directly so
    //     the on-chain snapshot (`unlock_timestamp`, `balance_xlm`) wins
    //     over the lossy event-note parser (see source-of-truth comment
    //     inside that function).
    //   - The sanitisation pass below reuses the same map to rescue
    //     zero/uninitialised live vaults and build the archived overlay.
    //
    // Single fetch, three consumers — keeps the network footprint flat.
    // ----------------------------------------------------------------------
    let metas: RemoteMeta[] = [];
    if (BACKEND_URL) {
      try {
        const url = `${BACKEND_URL}/api/vault-meta/${owner}?contract_id=${encodeURIComponent(
          getActiveDeployment().contractId,
        )}`;
        const res = await fetch(url);
        if (res.ok) metas = (await res.json()) as RemoteMeta[];
      } catch {
        // Backend unreachable — proceed with empty metas. Both fallback
        // paths are robust to that case (live-only data, no overlay).
      }
    }
    const metaById = new Map<string, RemoteMeta>(
      metas.map((m) => [m.vault_id, m]),
    );

    // ----------------------------------------------------------------------
    // Step 1: simulate path (skip if previously known-broken).
    //
    // Wrapped in a hermetic try/catch. ANY throw — sync or async, transport
    // or XDR-decode, scAddress encoding failure, scValToNative bombing out
    // on Hermes — is captured here and routed through the events+cache
    // fallback below. The crash WILL NOT bubble up to the UI.
    // ----------------------------------------------------------------------
    let simulateResult: Vault[] | null = null;
    let simulateError: unknown = null;
    if (!simulatePathBroken) {
      try {
        const idsRaw = await invokeRead("list_owned", [scAddress(owner)]);
        const ids = (scValToNative(idsRaw) as (string | number | bigint)[]).map(
          (x) => BigInt(x),
        );
        simulateResult = await Promise.all(
          ids.map(async (id) => {
            const sv = await invokeRead("get_vault", [scU64(id)]);
            const c = decodeVault(sv);
            const meta = await loadMeta(owner, c.vault_id.toString());
            return toVault(c, meta);
          }),
        );
      } catch (err) {
        simulateError = err;
        // If this is a local XDR / Buffer / scValToNative failure, mark
        // simulate as broken for the rest of the session so future
        // refreshes don't waste the RPC retry budget on it.
        if (isXdrParseError(err)) {
          markSimulateBroken(err);
        }
      }
    }

    // ----------------------------------------------------------------------
    // Step 2: events-derived fallback when simulate didn't yield a result.
    // Also wrapped to never throw.
    //
    // We pass the pre-fetched `metaById` so the events aggregator can use
    // MongoDB snapshots as the source of truth for unlock_timestamp /
    // balance — preventing the lossy "unlock YYYY-MM-DD" note parse from
    // clobbering a valid backend snapshot.
    // ----------------------------------------------------------------------
    let eventsResult: Vault[] | null = null;
    let eventsError: unknown = null;
    if (simulateResult === null) {
      try {
        eventsResult = await aggregateVaultsFromEvents(owner, metaById);
      } catch (err) {
        eventsError = err;
      }
    }

    // ----------------------------------------------------------------------
    // Pick whichever live source we have. Simulate wins if available; else
    // events; else fall back to cache; else empty. We DO NOT throw — the
    // archived overlay below may still surface vaults from the backend
    // meta side-store.
    // ----------------------------------------------------------------------
    let liveVaults: Vault[];
    if (simulateResult !== null) {
      lastSyncedAt = Date.now();
      liveVaults = mergeVaults(cached, simulateResult);
      void saveCachedVaults(owner, liveVaults, "simulate").catch(() => {});
    } else if (eventsResult !== null && eventsResult.length > 0) {
      lastSyncedAt = Date.now();
      liveVaults = mergeVaults(cached, eventsResult);
      void saveCachedVaults(owner, liveVaults, "events").catch(() => {});
    } else if (cached.length > 0) {
      // Best-effort log so device debug tools surface the degradation
      // (but the user never sees a crash).
      console.warn(
        "[xlm-vault] listVaults: returning stale cache (simulate+events both unavailable).",
        { simulateError, eventsError },
      );
      liveVaults = cached;
    } else {
      console.warn(
        "[xlm-vault] listVaults: no data from simulate/events/cache — falling through to archived overlay only.",
        { simulateError, eventsError },
      );
      liveVaults = [];
    }

    // ----------------------------------------------------------------------
    // Use the early-fetched `metaById` map (populated above before the
    // simulate/events fork) to:
    //   (a) Reclassify any cached/events-derived live vault that has
    //       zero/uninitialized fields, using the backend snapshot
    //       (balance_xlm, unlock_timestamp) as the source of truth.
    //   (b) Overlay archived rows for vault_ids the backend knows about
    //       but live reads don't.
    //   (c) Push a snapshot back to the backend after a successful live
    //       read so the next user / device sees real numbers.
    // ----------------------------------------------------------------------

    // ----------------------------------------------------------------------
    // Sanitisation: for any LIVE vault with zero/uninitialized fields
    // (unlock_timestamp <= 0 typically signals a stale-cache leak
    // from a prior Hermes XDR failure + events aging out), prefer the
    // backend snapshot. If no snapshot exists, downgrade the row to
    // "archived" so the dashboard renders the explanatory copy +
    // Wake Up CTA instead of "Vault #N · 1970-01-01 · 0 XLM".
    //
    // Without this pass, the user previously saw vaults 0/1/2 render
    // as "1970-01-01" + 0 XLM after a Hermes-induced simulate failure.
    // ----------------------------------------------------------------------
    liveVaults = liveVaults
      .map((v) => {
        const looksZero =
          v.status !== "archived" &&
          (v.unlock_timestamp <= 0 || v.created_timestamp <= 0);
        if (!looksZero) return v;
        const meta = metaById.get(v.vault_id);
        if (
          meta &&
          ((meta.unlock_timestamp ?? 0) > 0 || (meta.balance_xlm ?? 0) > 0)
        ) {
          // Backend has a real snapshot — reconstruct the vault from it.
          const status: Vault["status"] =
            meta.on_chain_status === "withdrawn"
              ? "withdrawn"
              : meta.on_chain_status === "archived"
              ? "archived"
              : Math.floor(Date.now() / 1000) >=
                (meta.unlock_timestamp ?? 0)
              ? "unlocked"
              : "locked";
          return {
            ...v,
            name: meta.name?.trim() ? meta.name : v.name,
            description: meta.description ?? v.description,
            template: meta.template ?? v.template,
            target_amount: meta.target_amount ?? v.target_amount,
            balance: meta.balance_xlm ?? v.balance,
            unlock_timestamp: meta.unlock_timestamp ?? v.unlock_timestamp,
            created_timestamp:
              v.created_timestamp > 0
                ? v.created_timestamp
                : parseIsoToUnix(meta.created_at ?? meta.updated_at ?? null),
            status,
          };
        }
        // No snapshot to rescue this row — downgrade to archived so the
        // user gets a Wake Up CTA instead of a misleading "1970" card.
        return {
          ...v,
          balance: 0,
          unlock_timestamp: 0,
          created_timestamp:
            v.created_timestamp > 0
              ? v.created_timestamp
              : parseIsoToUnix(meta?.created_at ?? meta?.updated_at ?? null),
          status: "archived" as const,
        };
      })
      // After sanitisation, the "archived" status filter ensures these
      // rows go through the same Wake Up flow as the backend-only
      // overlay below.
      .filter((v) => {
        // Drop any orphan row that is BOTH zero-state AND has no
        // backend meta to anchor it. Leaving it in would render a
        // ghost card; we'd rather show nothing.
        if (v.status === "archived" && !metaById.has(v.vault_id)) {
          // Orphan-cache entry with no MongoDB knowledge. Drop.
          return false;
        }
        return true;
      });

    // ----------------------------------------------------------------------
    // Snapshot writeback — for every LIVE vault we just read with real
    // values, persist them back to the backend so the next sync (or a
    // fresh device, or a future Hermes XDR hit) has a source of truth.
    // Fire-and-forget. Skipped for archived/withdrawn — we already
    // sanitised those above.
    // ----------------------------------------------------------------------
    for (const v of liveVaults) {
      if (
        (v.status === "locked" || v.status === "unlocked" || v.status === "withdrawn") &&
        v.unlock_timestamp > 0
      ) {
        void pushSnapshotToBackend(owner, v.vault_id, {
          balance_xlm: v.balance,
          unlock_timestamp: v.unlock_timestamp,
          on_chain_status: v.status === "withdrawn" ? "withdrawn" : "live",
        });
      }
    }

    // ----------------------------------------------------------------------
    // Archived overlay — any vault_id the backend meta side-store knows
    // about but is missing from the live read is appended as `archived`.
    // This is the fix for older vaults whose Soroban contract data has
    // been TTL-pruned. The card shows a "Wake Up" CTA that triggers
    // `wakeUpVault` (RestoreFootprint + ExtendFootprintTtl).
    //
    // We pass the already-fetched metas (not re-fetch) and the post-
    // sanitisation liveIds so any vault we just reclassified TO archived
    // doesn't get double-rendered.
    // ----------------------------------------------------------------------
    const liveIds = new Set(liveVaults.map((v) => v.vault_id));
    const archivedOverlay = buildArchivedOverlayFromMetas(
      owner,
      metas,
      liveIds,
    );

    // Compose final list: live first (sorted newest-first by created_ts),
    // then archived at the bottom. Archived entries have created_ts == 0
    // so a unified sort would push them below live entries anyway; we
    // keep the explicit concatenation to make the ordering obvious.
    const merged = [...liveVaults, ...archivedOverlay];
    merged.sort((a, b) => {
      // Archived (created_ts == 0) always sorts after live entries.
      if (a.status === "archived" && b.status !== "archived") return 1;
      if (b.status === "archived" && a.status !== "archived") return -1;
      return b.created_timestamp - a.created_timestamp;
    });
    return merged;
  }

  async getVault(id: string, ownerHint?: string): Promise<Vault> {
    // Step 1: simulate path (skip if previously known-broken).
    if (!simulatePathBroken) {
      try {
        const sv = await invokeRead("get_vault", [scU64(BigInt(id))]);
        const c = decodeVault(sv);
        const meta = await loadMeta(c.owner, c.vault_id.toString());
        return toVault(c, meta);
      } catch (err) {
        if (isXdrParseError(err)) {
          markSimulateBroken(err);
        }
        // Fall through to events + cache fallback below.
      }
    }

    // Step 2: events-derived fallback. We can't ask the events stream
    // for a vault by id directly, so we scan the cached event stream,
    // find one matching the id, and use its owner to drive both the
    // aggregator and the persisted cache lookup. This keeps the
    // `/vault/[id]` deep-link working even when simulate is dead.
    let inferredOwner: string | null = ownerHint ?? null;
    try {
      const events = await fetchContractEvents();
      const match = events.find((e) => e.vault_id === id);
      if (match) {
        inferredOwner = match.owner_public_key;
        const all = await aggregateVaultsFromEvents(match.owner_public_key);
        const fromEvents = all.find((x) => x.vault_id === id);
        if (fromEvents) return fromEvents;
      }
    } catch {
      // Events read failed — fall through to cache.
    }

    // Step 3: persisted cache for the owner we inferred from events
    // (or explicit ownerHint passed by the vault-detail screen).
    if (inferredOwner) {
      try {
        const cached = await loadCachedVaults(inferredOwner);
        const fromCache = cached.find((x) => x.vault_id === id);
        if (fromCache) return fromCache;
      } catch {
        // ignore
      }
    }

    // -----------------------------------------------------------------
    // Step 4 — Archived-meta fallback (Sprint 20 iter 32 fix).
    //
    // If we're still here, none of the three fast paths could serve
    // this vault. This is the exact scenario the dashboard's archived
    // overlay handles: older vaults whose Soroban ledger entry has
    // been TTL-pruned AND whose create event has aged out of the RPC
    // event retention window. The dashboard's list view surfaces those
    // as "archived" cards by cross-referencing the backend meta store;
    // getVault used to have no equivalent lookup, so tapping into
    // an archived card produced a 500 / "Vault not reachable" toast
    // even though the list rendered fine.
    //
    // Here we replicate the same cross-reference the LIST does:
    // fetch every RemoteMeta for `owner`, filter for the requested
    // vault_id, and materialise a synthetic Vault entry with
    // `status: "archived"` (or `withdrawn` / `locked` / `unlocked`,
    // matching whatever last-known on-chain status the backend
    // recorded). The Wake Up CTA in the detail screen already knows
    // how to `RestoreFootprint + ExtendFootprintTtl` on an archived
    // vault; this fallback just makes sure the user can REACH that
    // CTA in the first place. Bug report: "Vault 2 not reachable
    // despite backend being active" — happens exclusively for older
    // vaults where the on-chain ledger entry has expired.
    // -----------------------------------------------------------------
    if (inferredOwner && BACKEND_URL) {
      try {
        const url =
          `${BACKEND_URL}/api/vault-meta/${inferredOwner}` +
          `?contract_id=${encodeURIComponent(getActiveDeployment().contractId)}`;
        const res = await fetch(url);
        if (res.ok) {
          const remotes = (await res.json()) as RemoteMeta[];
          const overlay = buildArchivedOverlayFromMetas(
            inferredOwner,
            remotes,
            new Set(), // liveIds empty — every remote passes through the filter
          );
          const fromMeta = overlay.find((v) => v.vault_id === id);
          if (fromMeta) return fromMeta;
        }
      } catch {
        // ignore — throw generic below
      }
    }

    // All four paths failed. We HAVE to throw here because callers of
    // getVault need a concrete Vault object — there's no sensible
    // "empty" return value. UI's error boundary will catch and route
    // the user back with a "vault not found" message.
    throw new Error(
      `Vault ${id} not reachable on-chain and not in local cache. Try again once the RPC has caught up.`,
    );
  }

  async createVault(input: CreateVaultInput): Promise<Vault> {
    const { returnValue } = await invokeContract({
      ownerPublicKey: input.owner_public_key,
      method: "create_vault",
      params: [
        scAddress(input.owner_public_key),
        scString(input.name),
        scI128(xlmToStroops(input.initial_deposit)),
        scU64(input.unlock_timestamp),
      ],
    });
    if (!returnValue) {
      throw new SorobanSimulationError(
        "create_vault",
        "Contract did not return a vault id.",
      );
    }
    const newId = (scValToNative(returnValue) as bigint | number).toString();
    await saveMeta(input.owner_public_key, newId, {
      description: input.description,
      template: input.template,
      target_amount: input.target_amount,
      // Mirror the on-chain name into off-chain meta so the events-derived
      // dashboard fallback (used when simulate is unreachable) can show
      // the user's chosen vault name. See `aggregateVaultsFromEvents`.
      name: input.name,
    });
    return this.getVault(newId);
  }

  async deposit(id: string, owner: string, amount: number): Promise<Vault> {
    await invokeContract({
      ownerPublicKey: owner,
      method: "deposit",
      params: [scAddress(owner), scU64(BigInt(id)), scI128(xlmToStroops(amount))],
    });
    return this.getVault(id);
  }

  async extendLock(id: string, owner: string, additionalSeconds: number): Promise<Vault> {
    await invokeContract({
      ownerPublicKey: owner,
      method: "extend_lock",
      params: [scAddress(owner), scU64(BigInt(id)), scU64(additionalSeconds)],
    });
    return this.getVault(id);
  }

  async withdraw(id: string, owner: string): Promise<Vault> {
    await invokeContract({
      ownerPublicKey: owner,
      method: "withdraw",
      params: [scAddress(owner), scU64(BigInt(id))],
    });
    return this.getVault(id);
  }

  /**
   * Wake up an archived vault — restore the contract data entry from
   * Stellar's archived-state store and extend its TTL so the vault is
   * usable again.
   *
   * Flow (best-effort, both ops are independent):
   *   1. Build a read transaction that calls `get_vault(vault_id)` against
   *      the contract. This is what reveals the footprint (read-only
   *      ledger keys) the entry occupies.
   *   2. `simulateTransaction` the probe. The RPC returns one of:
   *        a) Success with `transactionData` populated   → entry is live;
   *           we can skip straight to ExtendFootprintTtl.
   *        b) Success with `restorePreamble` populated   → entry exists
   *           but is archived; we MUST submit a RestoreFootprint op
   *           first, then re-simulate to get fresh sorobanData, then
   *           ExtendFootprintTtl to push the TTL out further.
   *        c) Simulation error                            → vault has
   *           never existed on this contract (or some other unrecoverable
   *           condition); we throw a SorobanSimulationError so the UI
   *           explains the situation.
   *   3. For each op we need to submit, we run the standard
   *      build → sign → send → poll pipeline (mirroring `invokeContract`)
   *      and emit `TxReceipt`s tagged with method="wake_up" so the global
   *      banner can render them.
   *
   * Returns a structured outcome so the UI can word the success toast
   * accurately ("Vault woken up — TTL extended" vs "Vault restored and
   * woken up").
   *
   * NOTE: This is NOT part of `IVaultClient` — archived state is a
   * Soroban-specific concept. Surfaced as a named module export so the
   * dashboard can dynamically import + dispatch it.
   */
  async wakeUpVault(
    vaultId: string,
    owner: string,
  ): Promise<{ restored: boolean; extended: boolean; txHashes: string[] }> {
    const method: SorobanMethod = "wake_up";
    const dep = getActiveDeployment();
    const txHashes: string[] = [];
    let restored = false;
    let extended = false;

    // Resolve the signer up front. If the user disconnected their wallet
    // we want to fail fast BEFORE building any envelopes, otherwise we'd
    // waste an RPC roundtrip on simulate just to choke on signing.
    // Sprint 23 iter 13 — multi-wallet-aware resolver.
    const kp = await loadSigningKeypair();
    if (!kp) throw new WalletNotConnectedError(method);
    const signer = Keypair.fromSecret(kp.secretSeed);
    // Sprint 23 iter 22 — Because `signer` is reused across ALL
    // submitOne() calls in this method (restore + extend, potentially
    // both), we can't wipe after each sign(). Instead we wrap the
    // whole body in a try/finally and zero `_secretSeed` +
    // `_secretKey` when the method is done — success or error.
    try {

    // ----------------------------------------------------------------------
    // submitOne: shared build → sign → send → poll pipeline for the
    // RestoreFootprint and ExtendFootprintTtl transactions. Same retry +
    // receipt model as `invokeContract` but parameterised on a pre-built
    // tx because we set sorobanData explicitly (not via assembleTransaction).
    // ----------------------------------------------------------------------
    const submitOne = async (
      tx: Transaction,
      phaseLabel: string,
    ): Promise<string> => {
      try {
        tx.sign(signer);
      } catch (e) {
        throw new SorobanSignError(method, e);
      }

      let sendRes: StellarRpc.Api.SendTransactionResponse;
      try {
        sendRes = await rpcServer().sendTransaction(tx);
      } catch (e) {
        throw new SorobanNetworkError(method, "send", e);
      }
      if (sendRes.status === "ERROR" || sendRes.status === "DUPLICATE") {
        const detail =
          (sendRes.status === "ERROR" &&
            sendRes.errorResult?.result().switch().name) ||
          sendRes.status;
        throw new SorobanSendError(method, String(detail), sendRes.hash);
      }
      const txHash = sendRes.hash;

      for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
        await sleep(POLL_INTERVAL_MS);
        let got;
        try {
          got = await rpcServer().getTransaction(txHash);
        } catch {
          // Transient blip; keep polling.
          continue;
        }
        if (got.status === "NOT_FOUND") continue;
        if (got.status === "SUCCESS") {
          const success = got as StellarRpc.Api.GetSuccessfulTransactionResponse;
          emitReceipt({
            method,
            txHash,
            ledger: typeof success.ledger === "number" ? success.ledger : undefined,
            explorerUrl: explorerForTx(txHash),
            status: "success",
            emittedAt: Date.now(),
          });
          return txHash;
        }
        if (got.status === "FAILED") {
          emitReceipt({
            method,
            txHash,
            explorerUrl: explorerForTx(txHash),
            status: "failed",
            emittedAt: Date.now(),
          });
          throw new SorobanOnChainError(method, txHash);
        }
      }
      emitReceipt({
        method,
        txHash,
        explorerUrl: explorerForTx(txHash),
        status: "pending",
        emittedAt: Date.now(),
      });
      throw new SorobanPollTimeoutError(method, txHash);
    };

    // ----------------------------------------------------------------------
    // Build the probe tx — just a `get_vault(vault_id)` read. The contract
    // call itself never lands (we never submit this tx); we use the
    // simulation result to extract the footprint and any restorePreamble.
    // ----------------------------------------------------------------------
    const buildProbe = async (): Promise<Transaction> => {
      const probeSource = await loadAccount(owner);
      const contract = new Contract(dep.contractId);
      return new TransactionBuilder(probeSource, {
        fee: BASE_FEE,
        networkPassphrase: dep.networkPassphrase,
      })
        .addOperation(contract.call("get_vault", scU64(BigInt(vaultId))))
        .setTimeout(60)
        .build();
    };

    // ----------------------------------------------------------------------
    // Step A: probe + simulate.
    // ----------------------------------------------------------------------
    let probeTx = await buildProbe();
    let sim: StellarRpc.Api.SimulateTransactionResponse;
    try {
      sim = await rpcServer().simulateTransaction(probeTx);
    } catch (e) {
      throw new SorobanNetworkError(method, "simulate", e);
    }
    if (StellarRpc.Api.isSimulationError(sim)) {
      throw new SorobanSimulationError(method, sim.error);
    }

    // ----------------------------------------------------------------------
    // Step B: if simulate reported a restorePreamble, submit
    // RestoreFootprint first. The preamble carries the canonical
    // sorobanData with the read-write footprint covering the archived
    // ledger keys.
    //
    // Restored entries come back to life with the MINIMUM allowed TTL
    // (a handful of ledgers — ~minutes). If we stopped here the entry
    // would re-archive almost immediately and the user's wake-up would
    // appear to have done nothing. The mandatory ExtendFootprintTtl
    // follow-up in Step C is what locks the entry into a multi-week
    // live state. That's the "double-handshake" the user explicitly
    // asked for.
    // ----------------------------------------------------------------------
    // Footprint we'll later use for the EXTEND op. Pre-seeded from the
    // restorePreamble (which always covers our entry, just in the
    // readWrite slot) so even if every re-simulate attempt fails we
    // can still emit a structurally-valid extend tx.
    let extendFootprint: SorobanDataBuilder | null = null;

    if (StellarRpc.Api.isSimulationRestore(sim) && sim.restorePreamble) {
      const restoreSource = await loadAccount(owner);
      // RestoreFootprint is a "host op" — fee covers data restoration
      // resource costs. Use the minResourceFee suggested by the RPC and
      // pad by 1000 stroops for safety on minor estimation drift.
      const feeStroops = (
        BigInt(sim.restorePreamble.minResourceFee) + 1000n
      ).toString();
      const restoreTx = new TransactionBuilder(restoreSource, {
        fee: feeStroops,
        networkPassphrase: dep.networkPassphrase,
      })
        .setSorobanData(sim.restorePreamble.transactionData.build())
        .addOperation(Operation.restoreFootprint({}))
        .setTimeout(60)
        .build();

      const hash = await submitOne(restoreTx, "restore");
      txHashes.push(hash);
      restored = true;

      // Build the FALLBACK extend footprint right now — copy the
      // restore preamble's keys but PROMOTE them from readWrite to
      // readOnly (extend semantics). We populate this even when
      // re-simulate succeeds below, so a downstream failure in the
      // re-sim path still leaves us with a usable footprint.
      try {
        const ro = sim.restorePreamble.transactionData.getReadOnly() ?? [];
        const rw = sim.restorePreamble.transactionData.getReadWrite() ?? [];
        extendFootprint = new SorobanDataBuilder()
          .setReadOnly([...ro, ...rw])
          .setReadWrite([]);
      } catch (e) {
        console.warn(
          "[xlm-vault] wakeUpVault: failed to derive fallback extend footprint:",
          e,
        );
      }

      // MANDATORY: re-simulate so the next op sees the now-live entry.
      // Retry up to 3 times with linear backoff — the entry may take a
      // ledger or two to surface as live across some RPCs. If every
      // attempt fails we don't abort — we fall back to the
      // restorePreamble-derived footprint constructed above. That
      // guarantees Step C ALWAYS runs after a successful restore.
      const RE_SIM_ATTEMPTS = 3;
      let reSimOk = false;
      for (let attempt = 0; attempt < RE_SIM_ATTEMPTS; attempt++) {
        await sleep(POLL_INTERVAL_MS);
        try {
          probeTx = await buildProbe();
          const reSim = await rpcServer().simulateTransaction(probeTx);
          if (
            !StellarRpc.Api.isSimulationError(reSim) &&
            !StellarRpc.Api.isSimulationRestore(reSim)
          ) {
            // Successful read sim — capture its transactionData as the
            // most-accurate footprint for the extend op.
            sim = reSim;
            reSimOk = true;
            break;
          }
        } catch (e) {
          console.warn(
            `[xlm-vault] wakeUpVault: re-simulate attempt ${attempt + 1}/${RE_SIM_ATTEMPTS} failed:`,
            e instanceof Error ? e.message : String(e),
          );
        }
      }
      if (!reSimOk) {
        console.warn(
          "[xlm-vault] wakeUpVault: re-simulate exhausted; falling back to restorePreamble-derived footprint for extend.",
        );
      }
    }

    // ----------------------------------------------------------------------
    // Step C: ExtendFootprintTtl — bump the TTL of the now-live entry so
    // the vault stays reachable for the next ~31 days.
    //
    // Source of truth for the footprint (in priority order):
    //   1. The latest successful read-simulate (`sim.transactionData`).
    //      This is the canonical "where does the entry live" payload.
    //   2. The pre-seeded `extendFootprint` from Step B's restorePreamble.
    //      Same physical keys, re-classified into readOnly. Used when
    //      every re-simulate attempt after a restore failed.
    //
    // `extendTo` is in LEDGERS, not seconds. Stellar Mainnet averages
    // ~5s per ledger so 535_679 ledgers is roughly 31 days (the
    // practical max a single ExtendFootprintTtl op can request on
    // protocol 21+).
    // ----------------------------------------------------------------------
    let extendSorobanData: xdr.SorobanTransactionData | null = null;
    if ("transactionData" in sim && sim.transactionData) {
      extendSorobanData = sim.transactionData.build();
    } else if (extendFootprint) {
      extendSorobanData = extendFootprint.build();
    }

    if (extendSorobanData) {
      const extendSource = await loadAccount(owner);
      const extendTo = 535_679; // ~31 days at 5s/ledger.
      const feeStroops = String(Number(BASE_FEE) * 50);
      const extendTx = new TransactionBuilder(extendSource, {
        fee: feeStroops,
        networkPassphrase: dep.networkPassphrase,
      })
        .setSorobanData(extendSorobanData)
        .addOperation(Operation.extendFootprintTtl({ extendTo }))
        .setTimeout(60)
        .build();

      try {
        const hash = await submitOne(extendTx, "extend_ttl");
        txHashes.push(hash);
        extended = true;
      } catch (e) {
        // If we already restored, propagate so the UI knows the wake-up
        // is incomplete — DON'T silently no-op like the previous
        // implementation did. The user explicitly asked for guaranteed
        // double-handshake; partial success is a real failure here.
        console.warn(
          "[xlm-vault] wakeUpVault: TTL extend failed:",
          e instanceof Error ? e.message : String(e),
        );
        if (restored) {
          console.warn(
            `[xlm-vault] wakeUpVault: restore tx ${
              txHashes[0] ?? "?"
            } succeeded but extend tx FAILED — vault will re-archive within minutes. Cause:`,
            e instanceof Error ? e.message : String(e),
          );
          throw new SorobanOnChainError(
            method,
            txHashes[txHashes.length - 1] ?? "unknown",
          );
        }
        throw e;
      }
    }

    if (!restored && !extended) {
      // Nothing to do — the vault was already live AND had ample TTL.
      // Throwing here is cleaner than silently no-oping because the user
      // tapped a button expecting visible action.
      throw new SorobanSimulationError(
        method,
        "Vault is already live and has sufficient TTL. No action needed.",
      );
    }

    // ----------------------------------------------------------------------
    // Step D: hard-reload the local caches so the next dashboard refresh
    // reflects the just-woken-up vault. Without this, the events cache
    // would happily serve a stale "no live event for vault X" answer for
    // up to EVENT_CACHE_MS, and the cached-vault list would still tag
    // the entry as "archived".
    // ----------------------------------------------------------------------
    invalidateAllCaches();

    // ----------------------------------------------------------------------
    // Step E: flip the backend `on_chain_status` to "live" + write a
    // fresh snapshot so the dashboard re-renders the vault as real-data
    // even if the next read happens to hit a Hermes XDR failure.
    //
    // We try to pull the post-wake-up values from the LAST successful
    // simulate captured in `sim` (the one Step C used). If sim doesn't
    // have a decoded retval (extend-only with extendFootprint fallback,
    // for example), we settle for marking the status without numerics —
    // the next listVaults read will overwrite with REAL values.
    // ----------------------------------------------------------------------
    try {
      let snap: {
        on_chain_status: "live";
        balance_xlm?: number;
        unlock_timestamp?: number;
      } = { on_chain_status: "live" };
      if (
        "result" in sim &&
        sim.result &&
        "retval" in sim.result &&
        sim.result.retval
      ) {
        try {
          const decoded = scValToNative(sim.result.retval) as any;
          if (decoded?.balance != null) {
            snap.balance_xlm =
              Number(BigInt(decoded.balance)) / Number(10_000_000);
          }
          if (decoded?.unlock_timestamp != null) {
            snap.unlock_timestamp = Number(decoded.unlock_timestamp);
          }
        } catch {
          // Decode failed (rare) — still flip status; balance/unlock
          // will be filled on next read.
        }
      }
      void pushSnapshotToBackend(owner, vaultId, snap);
    } catch (e) {
      console.warn(
        "[xlm-vault] wakeUpVault: post-success snapshot writeback failed (non-fatal):",
        e instanceof Error ? e.message : String(e),
      );
    }

    return { restored, extended, txHashes };
    } finally {
      // Sprint 23 iter 22 — Secure-wipe the signer's private
      // key material regardless of how we exited this function.
      wipeKeypair(signer);
    }
  }

  async vaultTransactions(id: string): Promise<VaultTransaction[]> {
    const all = await fetchContractEvents();
    const live = all.filter((t) => t.vault_id === id);
    // Inject the backend's synthetic create event for THIS vault if the
    // live stream is missing it (typically because the vault's create
    // event has aged out of the RPC retention window). We need the owner
    // to fetch backend meta — we derive it from the first live event if
    // any, falling back to a contract-wide scan that returns metas the
    // user owns.
    const owner = live[0]?.owner_public_key ?? null;
    if (owner) {
      const synth = await fetchArchivedCreateEvents(owner, all);
      for (const s of synth) {
        if (s.vault_id === id) live.push(s);
      }
    }
    return live.sort((a, b) => b.timestamp - a.timestamp);
  }

  async allTransactions(owner: string): Promise<VaultTransaction[]> {
    const all = await fetchContractEvents();
    const live = all.filter((t) => t.owner_public_key === owner);
    // Merge in synthetic create events for archived vaults that the
    // live event stream doesn't know about. See `fetchArchivedCreateEvents`
    // for the full design — short version: we fetch the backend meta
    // side-store and synthesize a `kind: "create"` row for every meta
    // record whose vault_id is missing from the live stream.
    const synth = await fetchArchivedCreateEvents(owner, all);
    return [...live, ...synth].sort((a, b) => b.timestamp - a.timestamp);
  }
}

export const sorobanVaultClient: IVaultClient = new SorobanVaultClient();

/**
 * Module-level helper that the dashboard / vault detail screens import
 * dynamically. Forwards to the singleton client's method. We expose it
 * separately because `IVaultClient` deliberately doesn't have a
 * `wakeUpVault` member — archived state is Soroban-specific and would
 * leak that detail into the REST client interface.
 */
export async function wakeUpVault(
  vaultId: string,
  owner: string,
): Promise<{ restored: boolean; extended: boolean; txHashes: string[] }> {
  return (sorobanVaultClient as SorobanVaultClient).wakeUpVault(vaultId, owner);
}

// ---------------------------------------------------------------------------
// recheckTransaction — used by the pending-receipt banner to re-poll a tx.
//
// Returns:
//   - status: the latest known status from rpc (PENDING is mapped to
//             "pending"; NOT_FOUND likewise — caller decides what to do)
//   - ledger: present only on SUCCESS
// Also re-emits an updated TxReceipt on the bus so the banner refreshes.
// ---------------------------------------------------------------------------
export async function recheckTransaction(
  method: SorobanMethod,
  txHash: string,
): Promise<{ status: "success" | "pending" | "failed"; ledger?: number }> {
  const server = rpcServer();
  let got;
  try {
    got = await server.getTransaction(txHash);
  } catch (e) {
    throw new SorobanNetworkError(method, "poll", e);
  }
  if (got.status === "SUCCESS") {
    const s = got as StellarRpc.Api.GetSuccessfulTransactionResponse;
    const ledger = typeof s.ledger === "number" ? s.ledger : undefined;
    emitReceipt({
      method,
      txHash,
      ledger,
      explorerUrl: explorerForTx(txHash),
      status: "success",
      emittedAt: Date.now(),
    });
    return { status: "success", ledger };
  }
  if (got.status === "FAILED") {
    emitReceipt({
      method,
      txHash,
      explorerUrl: explorerForTx(txHash),
      status: "failed",
      emittedAt: Date.now(),
    });
    return { status: "failed" };
  }
  return { status: "pending" };
}

// ---------------------------------------------------------------------------
// Sprint 22 iter 41 — Public getter for the local `vault_meta` side-store.
//
// The Vault interface (see /app/frontend/src/vault/contract.ts) intentionally
// does not carry Feature 6/7 UX-only fields (`withdrawal_destination`,
// `withdrawal_destination_label`, `bill_id`). These live in the local
// key-value meta cache maintained by `loadMeta` and mirrored to MongoDB
// via `mirrorMetaToBackend`. Screens that need them (currently only
// `/vault/[id]`) call this helper on mount alongside `api.getVault`.
//
// Returns undefined when there is no meta row (e.g. legacy vaults created
// before iter 41). Never throws — best-effort by design.
// ---------------------------------------------------------------------------
export async function getVaultMeta(
  owner: string,
  vaultId: string,
): Promise<{
  description: string;
  template: string;
  target_amount: number | null;
  name?: string;
  withdrawal_destination?: string;
  withdrawal_destination_label?: string;
  withdrawal_memo?: string;
  bill_id?: string;
} | undefined> {
  try {
    // Tier 1 — local cache first (fastest, always fresh on the device
    // that created the vault).
    const local = await loadMeta(owner, vaultId);

    // If Tier 1 already carries a withdrawal_destination we can return
    // immediately — that only happens after this helper has previously
    // written back through the Tier 2 hydration path.
    if (local.withdrawal_destination) return local;

    // Tier 2 — backend fallback. Feature 6/7 fields (withdrawal_destination,
    // bill_id) are written to the backend by `create-vault.tsx` via a
    // direct PUT and NOT mirrored back into local storage by that path,
    // so we ALWAYS ask the backend when the local row is missing them.
    // Best-effort; if the network is down we return whatever Tier 1
    // has (possibly a stub or an incomplete row).
    if (!BACKEND_URL) return local;
    const url = `${BACKEND_URL}/api/vault-meta/${owner}?contract_id=${encodeURIComponent(
      getActiveDeployment().contractId,
    )}`;
    const res = await fetch(url);
    if (!res.ok) return local;
    const rows = (await res.json()) as RemoteMeta[];
    const hit = rows.find((r) => r.vault_id === vaultId);
    if (!hit) return local;
    // Merge: prefer Tier 1 for description/template/name (already-known
    // authoritative on the creator device) but pull Feature 6/7 fields
    // from Tier 2.
    const hydrated = {
      description: local.description || hit.description,
      template: local.template || hit.template,
      target_amount: local.target_amount ?? hit.target_amount,
      name: local.name ?? hit.name ?? undefined,
      withdrawal_destination: hit.withdrawal_destination ?? undefined,
      withdrawal_destination_label:
        hit.withdrawal_destination_label ?? undefined,
      withdrawal_memo: hit.withdrawal_memo ?? undefined,
      bill_id: hit.bill_id ?? undefined,
    };
    // Persist the fresh copy so subsequent reads on this device are
    // instant and don't need the network.
    await saveMetaLocal(owner, vaultId, hydrated);
    return hydrated;
  } catch {
    return undefined;
  }
}

// Re-export error types and receipt helpers for the UI layer.
export {
  SorobanError,
  SorobanNetworkError,
  SorobanOnChainError,
  SorobanPollTimeoutError,
  SorobanSendError,
  SorobanSignError,
  SorobanSimulationError,
  WalletNotConnectedError,
  asSorobanError,
} from "./soroban-errors";
export type { SorobanPhase } from "./soroban-errors";
export {
  emitReceipt,
  explorerForTx,
  methodLabel,
  subscribeReceipts,
} from "./tx-receipts";
export type { SorobanMethod, TxReceipt } from "./tx-receipts";
