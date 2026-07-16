// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stellar TimeLock LLC

// Horizon API client — real Stellar account balance + protocol-aware
// spendable-balance calculation.
//
// We hit Horizon's `/accounts/{publicKey}` endpoint directly. No Stellar SDK
// bundled, because the full SDK requires `rn-nodeify` shims that break Expo's
// Metro bundler. Horizon is a vanilla REST API — `fetch` is enough.
//
// SPENDABLE BALANCE FORMULA (Stellar protocol 19+):
//
//   reserve_xlm = (2 + subentry_count + num_sponsoring - num_sponsored) * 0.5
//   spendable_xlm = max(0, native_balance - reserve_xlm - selling_liabilities)
//
// The "+2" baseline reserve is the minimum any Stellar account requires to
// exist (1.0 XLM). Each subentry — trustlines, signers, offers, account
// data, claimable balance sponsorships — adds another 0.5 XLM lock. Native
// `selling_liabilities` reserve outstanding-offer balance.
//
// We DO NOT subtract a per-Soroban-vault reserve here: Soroban contract
// data entries are paid via the contract's `extendable_ttl` storage rent,
// not via the user account's subentry count. The transaction fee for the
// next vault create/deposit (~0.05 XLM) is the responsibility of the
// caller and isn't deducted from this number.
//
// Network selection: the URLs follow the active deployment from
// `contract-config.ts`, so flipping the Settings → Network selector swaps
// both account balance reads and the friendbot funding endpoint in one go.

import { getActiveDeployment } from "@/src/wallet/contract-config";

export type HorizonState = "funded" | "unfunded" | "error";

/**
 * Stellar's base reserve unit. Locked in protocol since v9; the network
 * has never changed it. We hard-code rather than reading the latest ledger
 * header to keep the client offline-tolerant.
 */
const BASE_RESERVE_XLM = 0.5;
/** The 2 reserve units every existing account holds (1.0 XLM total). */
const ACCOUNT_BASE_UNITS = 2;

export interface HorizonBalance {
  publicKey: string;
  state: HorizonState;
  /** Raw native XLM balance from Horizon. */
  total: number;
  /** Sum of base + subentry reserves currently locked by Stellar protocol. */
  reserve: number;
  /** Outstanding offer / pool liabilities (also unavailable to spend). */
  liabilities: number;
  /**
   * `total - reserve - liabilities`, floored at 0. This is the number that
   * should be shown anywhere we say "Available" — it is the maximum amount
   * a user can transfer out of the account without breaking the protocol
   * minimum balance check.
   */
  spendable: number;
  /**
   * Legacy alias for `spendable`. Old call sites (`b.available`) still work.
   * @deprecated use `spendable` instead.
   */
  available: number;
  /** Number of subentries on the account (trustlines, offers, signers, etc.). */
  subentries: number;
  /** When the result was fetched (UNIX ms). */
  fetchedAt: number;
  /** Optional human-readable error message when state === "error". */
  error?: string;
}

interface HorizonBalanceRow {
  asset_type: string;
  balance: string;
  buying_liabilities?: string;
  selling_liabilities?: string;
}

interface HorizonAccount {
  account_id: string;
  subentry_count: number;
  num_sponsoring?: number;
  num_sponsored?: number;
  balances: HorizonBalanceRow[];
}

/**
 * Compute the protocol-enforced reserve for an account. Exported so screens
 * can reuse the math when displaying breakdowns. See module-level comment.
 */
export function computeReserveXlm(
  subentries: number,
  numSponsoring: number,
  numSponsored: number,
): number {
  const units =
    ACCOUNT_BASE_UNITS +
    Math.max(0, subentries) +
    Math.max(0, numSponsoring) -
    Math.max(0, numSponsored);
  return Math.max(0, units) * BASE_RESERVE_XLM;
}

function emptyResult(publicKey: string, state: HorizonState, error?: string): HorizonBalance {
  return {
    publicKey,
    state,
    total: 0,
    reserve: state === "funded" ? ACCOUNT_BASE_UNITS * BASE_RESERVE_XLM : 0,
    liabilities: 0,
    spendable: 0,
    available: 0,
    subentries: 0,
    fetchedAt: Date.now(),
    error,
  };
}

/**
 * Read the on-chain XLM balance from Horizon and compute the protocol-
 * enforced spendable amount. Returns `state: "unfunded"` (and balance = 0)
 * if the account hasn't been created on-chain yet — this is normal for
 * fresh keypairs.
 */
export async function fetchHorizonBalance(publicKey: string): Promise<HorizonBalance> {
  try {
    const res = await fetch(`${getActiveDeployment().horizonUrl}/accounts/${publicKey}`, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
    if (res.status === 404) {
      return emptyResult(publicKey, "unfunded");
    }
    if (!res.ok) {
      return emptyResult(publicKey, "error", `Horizon ${res.status}`);
    }
    const json = (await res.json()) as HorizonAccount;
    const native = json.balances.find((b) => b.asset_type === "native");
    const total = native ? Number(native.balance) : 0;
    const liabilities = native
      ? Number(native.selling_liabilities ?? "0") + Number(native.buying_liabilities ?? "0")
      : 0;
    const subentries = json.subentry_count ?? 0;
    const reserve = computeReserveXlm(
      subentries,
      json.num_sponsoring ?? 0,
      json.num_sponsored ?? 0,
    );
    const spendable = Math.max(
      0,
      (Number.isFinite(total) ? total : 0) -
        reserve -
        (Number.isFinite(liabilities) ? liabilities : 0),
    );
    return {
      publicKey,
      state: "funded",
      total: Number.isFinite(total) ? total : 0,
      reserve,
      liabilities: Number.isFinite(liabilities) ? liabilities : 0,
      spendable,
      available: spendable, // legacy alias
      subentries,
      fetchedAt: Date.now(),
    };
  } catch (e) {
    return emptyResult(publicKey, "error", e instanceof Error ? e.message : String(e));
  }
}

/**
 * Trigger Stellar's friendbot to fund an account. Only meaningful on
 * networks that provide a friendbot (testnet). Returns a clear error on
 * mainnet where `friendbotUrl` is null.
 */
export async function fundViaFriendbot(publicKey: string): Promise<{ ok: boolean; detail: string }> {
  const dep = getActiveDeployment();
  if (!dep.friendbotUrl) {
    return {
      ok: false,
      detail:
        `Friendbot is not available on ${dep.network}. Fund this account ` +
        `with real XLM from an exchange or another wallet.`,
    };
  }
  try {
    const res = await fetch(`${dep.friendbotUrl}/?addr=${publicKey}`);
    if (res.ok) return { ok: true, detail: "Account funded with 10,000 testnet XLM." };
    const body = await res.text();
    return { ok: false, detail: body.slice(0, 240) || `Friendbot ${res.status}` };
  } catch (e) {
    return { ok: false, detail: e instanceof Error ? e.message : String(e) };
  }
}

export const horizon = { fetchHorizonBalance, fundViaFriendbot };

// ---------------------------------------------------------------------------
// Wallet payment history (Sprint 22 iter 58)
// ---------------------------------------------------------------------------
//
// Fetches recent XLM payment operations to/from a given public key from
// Horizon. Used by the Wallet History screen to show actual on-chain
// sends/receives — including swap deposits (which broadcast a normal
// Stellar payment to the swap partner's pay-in address with a MEMO_TEXT
// set to the deposit memo). We intentionally filter to native XLM only
// for now because the rest of the app is native-XLM-focused.

export type WalletPaymentKind = "send" | "receive";

export interface WalletPayment {
  /** Ledger paging token — usable as a stable id + pagination cursor. */
  id: string;
  /** Transaction hash on Horizon. */
  tx_hash: string;
  /** ISO timestamp string from Horizon. */
  created_at: string;
  /** Unix seconds (parsed from `created_at`) for sort / display. */
  timestamp: number;
  /** Direction relative to the queried public key. */
  kind: WalletPaymentKind;
  /** Native XLM amount. */
  amount: number;
  /** Counterparty account (source when receive, destination when send). */
  counterparty: string;
  /** MEMO_TEXT / MEMO_ID / MEMO_HASH content (best-effort). Empty if none. */
  memo: string;
  memo_type: string;
}

interface HorizonPaymentOp {
  id: string;
  transaction_hash: string;
  created_at: string;
  type: string;
  asset_type?: string;
  amount?: string;
  from?: string;
  to?: string;
  source_account?: string;
  starting_balance?: string;
  funder?: string;
  account?: string;
}

interface HorizonTxRecord {
  memo?: string;
  memo_type?: string;
}

/**
 * Return recent XLM payments (send + receive) touching `publicKey`.
 * Native-XLM only; non-native trustline movements are ignored.
 * Limits + orders come from Horizon (`order=desc&limit=n`).
 */
export async function fetchWalletPayments(
  publicKey: string,
  limit: number = 40,
): Promise<WalletPayment[]> {
  const dep = getActiveDeployment();
  const url =
    `${dep.horizonUrl}/accounts/${publicKey}/payments?order=desc&limit=${limit}` +
    `&include_failed=false`;
  let res: Response;
  try {
    res = await fetch(url);
  } catch {
    return [];
  }
  if (!res.ok) return [];
  const body = (await res.json()) as {
    _embedded?: { records?: HorizonPaymentOp[] };
  };
  const ops = body?._embedded?.records ?? [];
  const out: WalletPayment[] = [];
  // Cache memo lookups per tx-hash so we only hit Horizon once per
  // transaction even if it contains multiple payment ops (rare but
  // possible).
  const memoCache = new Map<string, HorizonTxRecord | null>();
  const memoFor = async (hash: string): Promise<HorizonTxRecord | null> => {
    if (!hash) return null;
    if (memoCache.has(hash)) return memoCache.get(hash) ?? null;
    try {
      const r = await fetch(`${dep.horizonUrl}/transactions/${hash}`);
      if (!r.ok) {
        memoCache.set(hash, null);
        return null;
      }
      const t = (await r.json()) as HorizonTxRecord;
      memoCache.set(hash, t);
      return t;
    } catch {
      memoCache.set(hash, null);
      return null;
    }
  };

  for (const op of ops) {
    // "payment" (native XLM) and "create_account" (account funding).
    let kind: WalletPaymentKind | null = null;
    let counterparty = "";
    let amount = 0;
    if (op.type === "payment") {
      if (op.asset_type !== "native") continue;
      const a = parseFloat(op.amount ?? "0");
      if (!Number.isFinite(a) || a <= 0) continue;
      amount = a;
      if (op.from === publicKey) {
        kind = "send";
        counterparty = op.to ?? "";
      } else if (op.to === publicKey) {
        kind = "receive";
        counterparty = op.from ?? "";
      }
    } else if (op.type === "create_account") {
      const a = parseFloat(op.starting_balance ?? "0");
      if (!Number.isFinite(a) || a <= 0) continue;
      amount = a;
      if (op.funder === publicKey) {
        kind = "send";
        counterparty = op.account ?? "";
      } else if (op.account === publicKey) {
        kind = "receive";
        counterparty = op.funder ?? "";
      }
    }
    if (!kind) continue;

    // Fetch memo for the parent transaction. Best-effort.
    const tx = await memoFor(op.transaction_hash);
    const created = op.created_at ?? "";
    const timestamp = created ? Math.floor(new Date(created).getTime() / 1000) : 0;

    out.push({
      id: op.id,
      tx_hash: op.transaction_hash,
      created_at: created,
      timestamp,
      kind,
      amount,
      counterparty,
      memo: tx?.memo ?? "",
      memo_type: tx?.memo_type ?? "",
    });
  }
  return out;
}
