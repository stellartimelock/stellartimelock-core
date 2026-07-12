// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stellar TimeLock LLC

// Structured error types for on-chain Soroban operations.
//
// Each phase of the canonical Stellar/Soroban pipeline (build → simulate →
// assemble → sign → send → poll) can fail in distinct ways. Surfacing these
// as separate classes lets the UI display category-specific messaging,
// retry affordances, and explorer links without parsing strings.
//
// Classification rationale:
//   - WalletNotConnectedError  — preflight UX issue, no on-chain side effect.
//   - SorobanNetworkError      — RPC reachability issue, retryable.
//   - SorobanSimulationError   — preflight failed (insufficient balance,
//                                contract reverted, bad auth). NOT submitted.
//   - SorobanSignError         — signing failed (corrupt seed); local only.
//   - SorobanSendError         — submission rejected by RPC (DUPLICATE,
//                                ERROR). Tx hash may or may not exist.
//   - SorobanOnChainError      — tx landed but ledger marked it FAILED
//                                (contract assertion / panic). Tx hash exists.
//   - SorobanPollTimeoutError  — tx submitted, status not resolved within
//                                ~45s. Tx may still finalize; show hash.
//
// All errors carry the `method` (contract function name) so the UI can show
// "Withdraw failed on-chain" instead of a generic "Soroban error".

export type SorobanPhase =
  | "build"
  | "simulate"
  | "assemble"
  | "sign"
  | "send"
  | "poll";

export class SorobanError extends Error {
  readonly phase: SorobanPhase;
  readonly method: string;
  readonly txHash?: string;
  readonly cause?: unknown;
  readonly userMessage: string;
  readonly retryable: boolean;

  constructor(opts: {
    phase: SorobanPhase;
    method: string;
    message: string;
    userMessage: string;
    retryable: boolean;
    txHash?: string;
    cause?: unknown;
  }) {
    super(opts.message);
    this.name = new.target.name;
    this.phase = opts.phase;
    this.method = opts.method;
    this.txHash = opts.txHash;
    this.cause = opts.cause;
    this.userMessage = opts.userMessage;
    this.retryable = opts.retryable;
  }
}

export class WalletNotConnectedError extends SorobanError {
  constructor(method: string) {
    super({
      phase: "sign",
      method,
      message: "Wallet not connected — cannot sign Soroban transaction.",
      userMessage: "Reconnect your wallet to sign on-chain transactions.",
      retryable: false,
    });
  }
}

export class SorobanNetworkError extends SorobanError {
  constructor(method: string, phase: SorobanPhase, cause: unknown) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    super({
      phase,
      method,
      message: `Network error during ${phase}: ${detail}`,
      userMessage:
        "Couldn't reach the Stellar RPC. Check your connection and retry.",
      retryable: true,
      cause,
    });
  }
}

export class SorobanSimulationError extends SorobanError {
  constructor(method: string, simError: string) {
    super({
      phase: "simulate",
      method,
      message: `Soroban preflight failed (${method}): ${simError}`,
      userMessage: humanizeSimulationError(method, simError),
      retryable: false,
    });
  }
}

export class SorobanSignError extends SorobanError {
  constructor(method: string, cause: unknown) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    super({
      phase: "sign",
      method,
      message: `Signing failed for ${method}: ${detail}`,
      userMessage:
        "We couldn't sign this transaction with your wallet seed. Try reconnecting.",
      retryable: false,
      cause,
    });
  }
}

export class SorobanSendError extends SorobanError {
  constructor(method: string, status: string, txHash?: string) {
    super({
      phase: "send",
      method,
      message: `sendTransaction (${method}) returned ${status}`,
      userMessage:
        status === "DUPLICATE"
          ? "This transaction was already submitted. Pull-to-refresh to see the result."
          : "The Stellar network rejected this transaction. Please retry.",
      retryable: status !== "DUPLICATE",
      txHash,
    });
  }
}

export class SorobanOnChainError extends SorobanError {
  constructor(method: string, txHash: string) {
    super({
      phase: "poll",
      method,
      message: `Soroban tx ${method} failed on-chain (hash=${txHash}).`,
      userMessage: onchainFailureMessage(method),
      retryable: false,
      txHash,
    });
  }
}

export class SorobanPollTimeoutError extends SorobanError {
  constructor(method: string, txHash: string) {
    super({
      phase: "poll",
      method,
      message: `Timed out polling getTransaction for ${method} (hash=${txHash}).`,
      userMessage:
        "Your transaction is taking longer than expected. It may still confirm — check the explorer link.",
      retryable: false,
      txHash,
    });
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function humanizeSimulationError(method: string, raw: string): string {
  const lower = raw.toLowerCase();
  // Soroban surfaces contract assertion failures in TWO ways:
  //   (a) Free-text panic strings (rare, when contracts use panic!("...")).
  //   (b) Typed `Error(Contract, #N)` discriminants emitted by `contracterror`
  //       enums. The deployed XlmVault contract uses (b) exclusively — see
  //       /app/contracts/xlm_vault/src/lib.rs::enum Error.
  //
  // We match BOTH forms. The numeric arm is what hits in production; the
  // string arm is defensive coverage in case the contract is ever rebuilt
  // with panic strings.

  // (b) Numeric error code arm — must match e.g. "Error(Contract, #1)".
  const codeMatch = raw.match(/Error\(Contract,\s*#(\d+)\)/);
  if (codeMatch) {
    const code = Number(codeMatch[1]);
    switch (code) {
      case 1: // NotOwner
        return "Only the vault owner can perform this action.";
      case 2: // StillLocked
        return "This vault is still locked. You can withdraw after the unlock date.";
      case 3: // AlreadyWithdrawn
        return "This vault has already been withdrawn.";
      case 4: // ShortenForbidden
        return "Locks can only be extended further out, not shortened.";
      case 5: // VaultNotFound
        return "Vault not found on-chain. It may have been created on a different network.";
      case 6: // InvalidAmount
        return "Invalid amount. Deposits must be positive XLM values.";
      case 7: // InvalidTimestamp
        return "Invalid unlock timestamp. The unlock must be in the future.";
      case 8: // AlreadyInitialised
        return "The contract is already initialised.";
    }
  }

  // (a) Free-text arm — kept for defense-in-depth.
  if (lower.includes("unauthorized") || lower.includes("not owner") || lower.includes("notowner")) {
    return "Only the vault owner can perform this action.";
  }
  if (lower.includes("still locked") || lower.includes("not unlocked") || lower.includes("stilllocked")) {
    return "This vault is still locked. You can withdraw after the unlock date.";
  }
  if (lower.includes("already withdrawn") || lower.includes("alreadywithdrawn")) {
    return "This vault has already been withdrawn.";
  }
  if (lower.includes("cannot shorten") || lower.includes("must extend") || lower.includes("shortenforbidden")) {
    return "Locks can only be extended further out, not shortened.";
  }
  if (lower.includes("insufficient")) {
    return "Your wallet does not have enough XLM for this transaction.";
  }
  if (lower.includes("not found") || lower.includes("vaultnotfound")) {
    return "Account or vault not found on Stellar. Fund your account via friendbot first.";
  }
  // Per-method fallback.
  switch (method) {
    case "create_vault":
      return "Could not create vault on-chain. Double-check the inputs and your XLM balance.";
    case "deposit":
      return "Deposit rejected by the contract. Verify the amount and your wallet balance.";
    case "extend_lock":
      return "Extension rejected by the contract. The new unlock must be in the future.";
    case "withdraw":
      return "Withdrawal rejected by the contract. The vault may still be locked.";
    default:
      return `Soroban preflight rejected this ${method} call.`;
  }
}

function onchainFailureMessage(method: string): string {
  switch (method) {
    case "create_vault":
      return "The contract reverted while creating the vault. No XLM was moved.";
    case "deposit":
      return "The contract reverted on deposit. Your XLM is still in your wallet.";
    case "extend_lock":
      return "The contract reverted on extend. The lock was not changed.";
    case "withdraw":
      return "The contract reverted on withdraw. Funds remain in the vault.";
    default:
      return "The contract reverted during execution.";
  }
}

/**
 * Coerce any thrown value into a `SorobanError`. Used by callers that want a
 * single discriminated type at the catch site (e.g. UI screens).
 */
export function asSorobanError(method: string, e: unknown): SorobanError {
  if (e instanceof SorobanError) return e;
  if (e instanceof Error) {
    return new SorobanError({
      phase: "build",
      method,
      message: e.message,
      userMessage: e.message || "An unexpected error occurred.",
      retryable: false,
      cause: e,
    });
  }
  return new SorobanError({
    phase: "build",
    method,
    message: String(e),
    userMessage: "An unexpected error occurred.",
    retryable: false,
    cause: e,
  });
}
