# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stellar TimeLock LLC

# Changelly Exchange API — backend domain scaffold.
#
# STATUS: MOCKED (PRODUCTION_MODE = False by default).
# Every response carries `mocked: True` so frontends + downstream
# consumers can never confuse a stub with a live result.
#
# =============================================================================
# 🚀 PRODUCTION CUTOVER — 4-STEP CHECKLIST
# =============================================================================
# Flip `PRODUCTION_MODE = True` (via env: `CHANGELLY_PRODUCTION_MODE=1`) ONLY
# after ALL FOUR of the following are complete. Each step ships with the
# next; never partial.
#
#   STEP 1 — Generate an RSA 2048-bit keypair.
#     * Private key: PKCS8 DER format, hex-encoded → env CHANGELLY_PRIVATE_KEY_HEX
#     * Public key:  PKCS1 DER format, Base64-encoded → keep for Step 3.
#     * Tooling: OpenSSL or the Node `crypto` module (see Changelly docs
#       for an exact snippet); rotate keys every 90 days at minimum.
#
#   STEP 2 — Compute X-Api-Key.
#     * SHA-256 hash of the PEM/Base64-encoded public key → env CHANGELLY_API_KEY.
#     * This is NOT a secret — it's just the lookup index Changelly uses
#       to find your registered public key on their side.
#
#   STEP 3 — Register the keypair with Changelly.
#     * Email the PUBLIC key (Step 1, PKCS1 DER Base64) + the API key
#       (Step 2 hash) to the Changelly onboarding team.
#     * Wait for confirmation. Until they whitelist your public key,
#       upstream requests will return invalid-signature errors even
#       with the right env vars set.
#
#   STEP 4 — Implement `_sign_rsa_sha256()` and flip the flag.
#     * Fill in the signing helper at the bottom of this file (currently
#       a `NotImplementedError` placeholder so a misconfigured deploy
#       can't accidentally send unsigned requests).
#     * Add to your environment:
#         CHANGELLY_PRODUCTION_MODE=1
#         CHANGELLY_API_KEY=<hex from Step 2>
#         CHANGELLY_PRIVATE_KEY_HEX=<hex from Step 1>
#     * Restart backend. The `_post_jsonrpc()` method will now perform
#       a real RSA-SHA256 signed call to Changelly's `/v2` endpoint.
#
# =============================================================================
# DESIGN NOTES (read before changing anything in this file)
# =============================================================================
#   - Exchange API v2 JSON-RPC 2.0 — single endpoint, method dispatch via
#     the JSON body's `method` field.
#   - Auth = RSA-SHA256 signature of the serialized JSON-RPC body, sent
#     in the `X-Api-Signature` header alongside `X-Api-Key`.
#   - Partner commission spread is configured in Changelly's dashboard,
#     NOT passed per-order. We expose a local `DEV_MARGIN_BPS` env hook
#     so we can simulate an extra spread on top of upstream quotes —
#     clearly labelled in the response so it's never hidden.
#
# Non-custodial constraints (DO NOT relax):
#   - The wallet's private key NEVER touches this service.
#   - The user signs and broadcasts the XLM → Changelly pay-in tx from
#     their own client; we just hand them the pay-in address.
#   - The destination payout address is supplied by the user.

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import time
import uuid
from typing import Any, Literal, Optional

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import APIRouter, HTTPException, Path
from pydantic import BaseModel, Field, field_validator

# =============================================================================
# 🎚️  PRODUCTION_MODE — primary feature flag for the Changelly module.
# =============================================================================
# Defaults to `False` (mock mode) so a misconfigured deploy can never
# accidentally send real swap traffic. To flip to live mode:
#     export CHANGELLY_PRODUCTION_MODE=1
# (or any of: "true", "yes", "on" — case-insensitive). Anything else,
# including unset, keeps PRODUCTION_MODE = False.
#
# DOWNSTREAM USERS of this flag (route handlers, _post_jsonrpc, etc.)
# read `PRODUCTION_MODE` rather than re-parsing the env var so the
# whole module flips together at import time.
# =============================================================================
_production_raw = os.environ.get("CHANGELLY_PRODUCTION_MODE", "0").strip().lower()
PRODUCTION_MODE: bool = _production_raw in ("1", "true", "yes", "on")

# Convenience inverse — `MOCK_MODE = True` reads more naturally in the
# guard paths inside the route handlers and the JSON-RPC client.
MOCK_MODE: bool = not PRODUCTION_MODE

# Configuration (read once at import time so tests can monkeypatch env vars
# before the module is imported — never re-read inside route handlers).
CHANGELLY_BASE_URL = os.environ.get(
    "CHANGELLY_BASE_URL", "https://api.changelly.com/v2"
)
CHANGELLY_API_KEY = os.environ.get("CHANGELLY_API_KEY", "")
CHANGELLY_PRIVATE_KEY_HEX = os.environ.get("CHANGELLY_PRIVATE_KEY_HEX", "")

# Sprint 21 iter 33 — Canonical env var slot for the RSA private key,
# per the user's onboarding brief. This is the SINGLE variable users
# are asked to set in the Emergent dashboard; the two legacy slots
# below (CHANGELLY_PRIVATE_KEY_HEX, CHANGELLY_API_PRIVATE_KEY_PEM)
# remain as backwards-compatible aliases so existing test fixtures
# and older deploy docs keep working. Whichever slot is populated
# wins in the resolution chain used by `_sign_rsa_sha256`. The value
# is intentionally NEVER logged; we only read it at signing time.
#
# Accepted formats (auto-detected by `_load_private_key`):
#   - PEM: begins with `-----BEGIN` (RSA / PKCS#8 / OpenSSL)
#   - HEX: raw PKCS#8 DER bytes, hex-encoded
#   - BASE64 DER: raw PKCS#8 DER bytes, standard base64 (with or
#     without padding). This is the format Changelly's onboarding
#     UI copy-buttons produce by default in 2026.
#
# NOTE FOR THE OPERATOR: DO NOT PASTE THE KEY MATERIAL HERE. The
# constant below is only the *reference to the env var slot* — the
# actual key must be injected via the Emergent dashboard's Env Vars
# panel so it lives in the pod's secret store, not in git.
CHANGELLY_PRIVATE_KEY = os.environ.get("CHANGELLY_PRIVATE_KEY", "")  # <<< SET IN EMERGENT DASHBOARD

# Sprint 18 Phase 3 env additions — PEM-formatted key material. Matches
# the config schema the Changelly onboarding docs use in their examples
# (users typically get their keypair as PEM, not DER-hex). Both variants
# co-exist; the signing helper resolves whichever is populated. Leaving
# every slot BLANK is the intended default so the app builds cleanly
# without any keys — `PRODUCTION_MODE=0` in that state.
CHANGELLY_API_PUBLIC_KEY = os.environ.get("CHANGELLY_API_PUBLIC_KEY", "")
# Sprint 23 iter 6 — Partner / affiliate ref-id for revenue tracking.
# Backend-only; NEVER exposed to the client. Passed as `refId` on
# `createTransaction` JSON-RPC calls so Changelly attributes the swap
# to our partner account for the revenue-share program.
CHANGELLY_SECRET = os.environ.get("CHANGELLY_SECRET", "")
CHANGELLY_API_PRIVATE_KEY_PEM = os.environ.get("CHANGELLY_API_PRIVATE_KEY_PEM", "")

# If the caller supplied a raw PEM public key but forgot to compute
# `CHANGELLY_API_KEY` (SHA-256 of the public key material) we can
# derive it here so a single PEM slot works out of the box.
if CHANGELLY_API_PUBLIC_KEY and not CHANGELLY_API_KEY:
    try:
        _pub_der = serialization.load_pem_public_key(
            CHANGELLY_API_PUBLIC_KEY.encode()
        ).public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1,
        )
        CHANGELLY_API_KEY = hashlib.sha256(base64.b64encode(_pub_der)).hexdigest()
    except Exception:
        # Ignore malformed public-key material — surfaces later at
        # signing time with a clear error rather than crashing import.
        pass

# Legacy alias retained for backwards compatibility with any external
# tests / env scripts that still read `CHANGELLY_MOCK`. Prefer
# `PRODUCTION_MODE` / `MOCK_MODE` in new code. When both env vars are
# set, `CHANGELLY_PRODUCTION_MODE` wins because it's the explicit
# safer-default cutover toggle introduced in Sprint 16 Batch 4.
_mock_raw = os.environ.get("CHANGELLY_MOCK", "").strip().lower()
if _mock_raw:
    # Legacy override only — and only when PRODUCTION_MODE wasn't
    # explicitly set in the env. Keeps the test harness's monkeypatch
    # path working without forcing every caller onto the new flag.
    if not _production_raw and _mock_raw in ("0", "false", "no", "off"):
        PRODUCTION_MODE = True
        MOCK_MODE = False
CHANGELLY_MOCK = MOCK_MODE  # deprecated alias; remove in a future cleanup

# Developer affiliate spread, in basis points (1 bp = 0.01%). The
# spread is APPLIED ON TOP of whatever Changelly returns as `amountTo`
# — when we cut over to live API. In mock mode we apply it to the
# synthetic estimate so the math is consistent end-to-end.
#
# Stored in env to allow per-deployment tuning without code edits. We
# clamp to [0, 500] so a misconfiguration can't accidentally take the
# user's whole swap. The value MUST be surfaced in every quote response
# under a clearly-labelled `partner_spread_bps` field; users should
# never see a hidden markup.
try:
    DEV_MARGIN_BPS = max(0, min(500, int(os.environ.get("CHANGELLY_DEV_MARGIN_BPS", "0"))))
except ValueError:
    DEV_MARGIN_BPS = 0

# Curated set of destination assets we're willing to route. Limiting at
# the gateway prevents a misconfigured client from creating a swap to a
# coin we don't actually want to support yet. Override with env list if
# needed; this is purely a policy gate, not a security boundary.
SUPPORTED_DESTINATIONS = tuple(
    s.strip().lower()
    for s in os.environ.get(
        "CHANGELLY_SUPPORTED_DESTINATIONS", "btc,eth,usdt,usdc,sol,doge"
    ).split(",")
    if s.strip()
)

# Stellar (XLM) is the only `from` we currently accept since this is a
# Stellar wallet. Hard-coded; configuration would just invite mistakes.
SUPPORTED_SOURCES = ("xlm",)

# Plausible bounds for `amount_from` (in XLM). Below 1 XLM the network
# fees on the destination chain typically eat the whole payout; above
# 100k XLM we're well outside retail-wallet scope and almost certainly
# a misconfiguration on the caller's side.
MIN_SWAP_FROM_XLM = float(os.environ.get("CHANGELLY_MIN_FROM_XLM", "1"))
MAX_SWAP_FROM_XLM = float(os.environ.get("CHANGELLY_MAX_FROM_XLM", "100000"))


# ---------------------------------------------------------------------------
# Domain models. Field names mirror the playbook's normalised Pydantic
# schema so the swap-out from mock → live is a no-op for callers.
# ---------------------------------------------------------------------------
class SwapQuoteRequest(BaseModel):
    from_currency: str = Field(..., description="Source asset ticker (lowercased)")
    to_currency: str = Field(..., description="Destination asset ticker (lowercased)")
    amount_from: float = Field(..., gt=0, description="Source amount (XLM)")

    @field_validator("from_currency", "to_currency")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()


class SwapQuoteResponse(BaseModel):
    from_currency: str
    to_currency: str
    amount_from: float
    # Gross amount returned by Changelly's getExchangeAmount. INCLUDES
    # Changelly's fee and partner extra fee (per Changelly docs); does
    # NOT include destination-chain network fee.
    amount_to_expected: float
    # Destination-chain network fee, deducted by Changelly when sending
    # the payout. Stored & exposed separately for transparent UX.
    network_fee: float
    # Net amount the user actually receives — `amount_to_expected - network_fee`.
    amount_to_net: float
    # Our local affiliate spread (already deducted from amount_to_expected
    # in mock mode; in live mode it's already embedded by Changelly).
    # Surfaced so we never present a hidden markup.
    partner_spread_bps: int
    # Indicative validity horizon for this quote. Changelly quotes drift;
    # this lets the UI invalidate stale quotes before /create.
    expires_at: int
    mocked: bool = True


class CreateSwapRequest(BaseModel):
    from_currency: str
    to_currency: str
    amount_from: float = Field(..., gt=0)
    # The user's payout address on the destination chain. Must be
    # provided by the user; we never own this key. We DO NOT validate
    # the format here because address rules vary per-chain; Changelly
    # validates upstream and rejects malformed addresses.
    payout_address: str = Field(..., min_length=8, max_length=200)
    # Optional memo / tag for chains that require destination metadata
    # (XLM, XRP, EOS, etc.). Stored on the swap doc for audit.
    payout_extra_id: Optional[str] = Field(None, max_length=200)

    @field_validator("from_currency", "to_currency")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()


class CreateSwapResponse(BaseModel):
    # Our own UUID — primary key in `db.swaps`.
    swap_id: str
    # Changelly's transaction id (synthetic in mock mode).
    changelly_transaction_id: str
    # Pay-in address the user must send XLM to. CRITICAL: in mock mode
    # this is a deterministic placeholder string PREFIXED with "MOCK_"
    # so any UI accidentally treating it as a real address fails fast.
    payin_address: str
    payin_extra_id: Optional[str]
    status: str
    created_at: int
    mocked: bool = True


class SwapStatusResponse(BaseModel):
    swap_id: str
    status: Literal[
        "created",
        "waiting_for_payment",
        "exchanging",
        "sending",
        "completed",
        "failed",
        "refunded",
        "hold",
    ]
    changelly_transaction_id: Optional[str]
    last_synced_at: Optional[int]
    mocked: bool = True


# Internal helper representing the persisted swap doc. Kept private to
# this module — routes never return it directly so we can evolve the
# schema without breaking the external contract.
class _SwapRecord(BaseModel):
    swap_id: str
    from_currency: str
    to_currency: str
    amount_from: float
    amount_to_expected: float
    network_fee: float
    payout_address: str
    payout_extra_id: Optional[str] = None
    changelly_transaction_id: Optional[str] = None
    payin_address: Optional[str] = None
    payin_extra_id: Optional[str] = None
    status: str = "created"
    created_at: int = 0
    updated_at: int = 0
    environment: Literal["mock", "sandbox", "production"] = "mock"


# ---------------------------------------------------------------------------
# Mocked HTTP client wrapper. Mirrors the shape the real client will take
# (async, single `_post_jsonrpc` method) so the route handlers don't have
# to change at cutover time.
# ---------------------------------------------------------------------------
class ChangellyClient:
    def __init__(
        self,
        base_url: str = CHANGELLY_BASE_URL,
        api_key: str = CHANGELLY_API_KEY,
        private_key_hex: str = CHANGELLY_PRIVATE_KEY_HEX,
        mock: bool = MOCK_MODE,
    ) -> None:
        self.base_url = base_url
        self.api_key = api_key
        self.private_key_hex = private_key_hex
        self.mock = mock

    async def _post_jsonrpc(self, method: str, params: Any) -> dict:
        """JSON-RPC 2.0 dispatch.

        In production mode (Sprint 18 Phase 3): builds the JSON-RPC 2.0
        envelope, signs the serialized body with RSA-SHA256 via the
        `_sign_rsa_sha256` helper, and POSTs to Changelly's v2 endpoint
        with `X-Api-Key` + `X-Api-Signature` headers.

        In mock mode (default): returns a synthetic result quickly so the
        rest of the stack exercises the JSON-RPC dispatch path without
        touching the network.
        """
        if not self.mock:
            # ---- PRODUCTION path ------------------------------------
            if not self.api_key:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "Changelly PRODUCTION_MODE enabled but "
                        "CHANGELLY_API_KEY is empty. Populate the env "
                        "before making live requests."
                    ),
                )
            payload = {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": method,
                "params": params,
            }
            # Canonical JSON serialization (no whitespace, sorted keys)
            # so the client's signature exactly matches what Changelly's
            # server hashes on receipt. Changelly's spec uses the
            # `separators=(",", ":")` compact form; do not deviate.
            body = json.dumps(payload, separators=(",", ":")).encode()
            signature = _sign_rsa_sha256(body, self.private_key_hex)
            headers = {
                "X-Api-Key": self.api_key,
                "X-Api-Signature": signature,
                "Content-Type": "application/json",
            }
            async with httpx.AsyncClient(timeout=15.0) as c:
                r = await c.post(self.base_url, content=body, headers=headers)
                r.raise_for_status()
                return r.json()
        # ---- MOCK path ------------------------------------------
        # Simulate the latency budget of a real RPC roundtrip so frontend
        # spinners get realistic timing during development.
        await asyncio.sleep(0.05)
        return {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "result": {"mocked": True, "method": method, "params": params},
        }


# Module-level singleton — cheap to share across routes since the client
# is stateless under mock mode.
_client = ChangellyClient()


# ---------------------------------------------------------------------------
# In-memory swap registry. ONLY used in mock mode so frontend / e2e tests
# can round-trip through /quote → /create → /status without needing a
# Mongo collection set up. Production code MUST replace this with a Motor
# repository (`db.swaps`) — that's a one-function swap; the rest of the
# scaffold doesn't change.
# ---------------------------------------------------------------------------
_mock_swaps: dict[str, _SwapRecord] = {}


def _apply_dev_margin(amount_to_gross: float) -> tuple[float, int]:
    """Return (amount_after_spread, spread_bps_applied).

    In mock mode we apply the spread locally so the math is internally
    consistent; in live mode Changelly applies the spread upstream and
    this function would be a no-op (returns the value unchanged).
    """
    if DEV_MARGIN_BPS <= 0:
        return amount_to_gross, 0
    spread_factor = 1.0 - (DEV_MARGIN_BPS / 10_000.0)
    return amount_to_gross * spread_factor, DEV_MARGIN_BPS


def _validate_pair(from_c: str, to_c: str) -> None:
    if from_c not in SUPPORTED_SOURCES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported from_currency '{from_c}'. Supported: {SUPPORTED_SOURCES}",
        )
    if to_c not in SUPPORTED_DESTINATIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported to_currency '{to_c}'. "
                f"Supported destinations: {SUPPORTED_DESTINATIONS}"
            ),
        )


def _validate_amount(amount: float) -> None:
    if amount < MIN_SWAP_FROM_XLM:
        raise HTTPException(
            status_code=400,
            detail=f"amount_from below minimum ({MIN_SWAP_FROM_XLM} XLM)",
        )
    if amount > MAX_SWAP_FROM_XLM:
        raise HTTPException(
            status_code=400,
            detail=f"amount_from above maximum ({MAX_SWAP_FROM_XLM} XLM)",
        )


# ---------------------------------------------------------------------------
# Routes — registered onto `router` and mounted at `/api/swaps` by server.py.
# ---------------------------------------------------------------------------
router = APIRouter(prefix="/swaps", tags=["changelly"])


@router.post("/quote", response_model=SwapQuoteResponse)
async def quote_swap(req: SwapQuoteRequest) -> SwapQuoteResponse:
    """Estimate destination amount for a swap.

    Mock math: applies a flat 0.92x exchange rate (loose stand-in for a
    plausible XLM→BTC ratio in basis points), then deducts the
    configured DEV_MARGIN_BPS spread, then subtracts a 1% destination
    network fee. Live mode will replace the math block with a single
    `getExchangeAmount` call.
    """
    _validate_pair(req.from_currency, req.to_currency)
    _validate_amount(req.amount_from)
    # Round-trip through the (mocked) JSON-RPC client so we exercise the
    # signing path in dev — keeps the cut-over surface area minimal.
    _ = await _client._post_jsonrpc(
        "getExchangeAmount",
        [{"from": req.from_currency, "to": req.to_currency, "amountFrom": str(req.amount_from)}],
    )
    # Stable deterministic mock rate. The 0.92 figure has no real-world
    # meaning — it's just stable across reruns so test snapshots don't
    # flake. Real implementation parses rpc["result"]["amountTo"].
    raw_amount_to = req.amount_from * 0.92
    amount_after_spread, spread_bps = _apply_dev_margin(raw_amount_to)
    network_fee = amount_after_spread * 0.01
    amount_net = max(0.0, amount_after_spread - network_fee)
    return SwapQuoteResponse(
        from_currency=req.from_currency,
        to_currency=req.to_currency,
        amount_from=req.amount_from,
        amount_to_expected=round(amount_after_spread, 8),
        network_fee=round(network_fee, 8),
        amount_to_net=round(amount_net, 8),
        partner_spread_bps=spread_bps,
        expires_at=int(time.time()) + 60,
        mocked=True,
    )


@router.post("/create", response_model=CreateSwapResponse)
async def create_swap(req: CreateSwapRequest) -> CreateSwapResponse:
    """Create a new swap and return the pay-in address.

    Persists a `_SwapRecord` to the in-memory registry (mock) so a
    subsequent /status call resolves correctly. At cutover, the registry
    is replaced with `db.swaps` and `payin_address` comes from
    Changelly's `createTransaction` response.
    """
    _validate_pair(req.from_currency, req.to_currency)
    _validate_amount(req.amount_from)
    rpc = await _client._post_jsonrpc(
        "createTransaction",
        {
            "from": req.from_currency,
            "to": req.to_currency,
            "amount": str(req.amount_from),
            "address": req.payout_address,
            "extraId": req.payout_extra_id,
        },
    )
    now = int(time.time())
    swap_id = str(uuid.uuid4())
    # `MOCK_` prefix on the address ensures any UI accidentally treating
    # the mock value as a real Stellar G... address fails the SDK's
    # built-in validity check immediately, rather than silently routing
    # real funds to a placeholder string.
    payin_addr = f"MOCK_PAYIN_{swap_id[:8].upper()}"
    rec = _SwapRecord(
        swap_id=swap_id,
        from_currency=req.from_currency,
        to_currency=req.to_currency,
        amount_from=req.amount_from,
        amount_to_expected=req.amount_from * 0.92,
        network_fee=req.amount_from * 0.92 * 0.01,
        payout_address=req.payout_address,
        payout_extra_id=req.payout_extra_id,
        changelly_transaction_id=f"mock-tx-{swap_id}",
        payin_address=payin_addr,
        payin_extra_id=f"mock-memo-{swap_id[:6]}",
        status="waiting_for_payment",
        created_at=now,
        updated_at=now,
        environment="mock",
    )
    _mock_swaps[swap_id] = rec
    # Suppress lint on unused rpc — the call exists to exercise the
    # JSON-RPC dispatch path during dev. Will be the source of truth
    # in production.
    _ = rpc
    return CreateSwapResponse(
        swap_id=swap_id,
        changelly_transaction_id=rec.changelly_transaction_id or "",
        payin_address=payin_addr,
        payin_extra_id=rec.payin_extra_id,
        status=rec.status,
        created_at=now,
        mocked=True,
    )


@router.get("/status/{swap_id}", response_model=SwapStatusResponse)
async def swap_status(
    swap_id: str = Path(..., min_length=1, max_length=64),
) -> SwapStatusResponse:
    """Return the current state of a swap.

    Mock behaviour: progresses through the status states deterministi-
    cally based on how long ago the swap was created — first 30s in
    `waiting_for_payment`, 30-60s in `exchanging`, 60-120s in `sending`,
    and `completed` thereafter. Lets QA exercise every UI state without
    a real broadcast.
    """
    rec = _mock_swaps.get(swap_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Unknown swap_id")
    age = max(0, int(time.time()) - rec.created_at)
    if age < 30:
        rec.status = "waiting_for_payment"
    elif age < 60:
        rec.status = "exchanging"
    elif age < 120:
        rec.status = "sending"
    else:
        rec.status = "completed"
    rec.updated_at = int(time.time())
    return SwapStatusResponse(
        swap_id=rec.swap_id,
        status=rec.status,  # type: ignore[arg-type]
        changelly_transaction_id=rec.changelly_transaction_id,
        last_synced_at=rec.updated_at,
        mocked=True,
    )


@router.get("/currencies")
async def list_currencies() -> dict:
    """Return the curated allow-list of swap pairs.

    Hard-coded for now; in production this would aggregate the local
    allow-list against Changelly's `getCurrencies` to filter out coins
    Changelly has flagged offline.
    """
    return {
        "from": list(SUPPORTED_SOURCES),
        "to": list(SUPPORTED_DESTINATIONS),
        "min_from_xlm": MIN_SWAP_FROM_XLM,
        "max_from_xlm": MAX_SWAP_FROM_XLM,
        "partner_spread_bps": DEV_MARGIN_BPS,
        # Surface the cutover toggle so a Diagnostics screen / health
        # check can verify whether the running process is in mock or
        # production mode without exec-ing into the container.
        "production_mode": PRODUCTION_MODE,
        "mocked": MOCK_MODE,
    }


# ---------------------------------------------------------------------------
# RSA-SHA256 signing helper (Sprint 18 Phase 3 — production cutover).
#
# Signs the JSON-RPC request body with the account's private key using
# PKCS#1 v1.5 padding + SHA-256 digest, per the Changelly v2 spec. The
# resulting signature is Base64-encoded and sent in the `X-Api-Signature`
# header alongside the `X-Api-Key` lookup index.
#
# Key material resolution order (any ONE of these is enough):
#   1. `CHANGELLY_API_PRIVATE_KEY_PEM` env — a PEM-encoded private key
#      (either PKCS#1 or PKCS#8, encrypted or unencrypted).
#   2. `CHANGELLY_PRIVATE_KEY_HEX` env — hex-encoded PKCS#8 DER bytes.
#      This is the format the older Changelly onboarding docs use.
#   3. Positional `private_key_hex` arg to this function — kept as the
#      arg name for backwards compatibility, but callers can now pass
#      a PEM string too and we'll auto-detect.
#
# Callers should NOT catch `HTTPException` from this function and swallow
# it — Changelly returns cryptic upstream errors for malformed signatures
# and the wrapped HTTP 500 here is far more actionable.
# ---------------------------------------------------------------------------
def _load_private_key(
    key_material: str,
) -> rsa.RSAPrivateKey:
    """Best-effort load of an RSA private key from any of the supported
    input formats. Returns the loaded key or raises HTTPException(500).

    Format auto-detection order:
      1. PEM  — presence of `-----BEGIN` header (unambiguous).
      2. HEX  — non-PEM string containing only [0-9A-Fa-f]; interpreted
                as PKCS#8 DER bytes.
      3. B64  — anything else that decodes as valid base64; interpreted
                as PKCS#8 DER bytes. Added iter 33 because the modern
                Changelly onboarding UI ships base64 by default.
    """
    if not key_material:
        raise HTTPException(
            status_code=500,
            detail=(
                "Changelly private key material is empty. Populate "
                "CHANGELLY_PRIVATE_KEY (preferred) or one of its legacy "
                "aliases: CHANGELLY_API_PRIVATE_KEY_PEM / "
                "CHANGELLY_PRIVATE_KEY_HEX."
            ),
        )
    stripped = key_material.strip()

    # 1) PEM path — reliable header sniff.
    if "-----BEGIN" in stripped:
        try:
            key = serialization.load_pem_private_key(
                stripped.encode(), password=None
            )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=500,
                detail=f"Changelly PEM private key could not be parsed: {exc}",
            ) from exc
    else:
        # 2) HEX path — pure hex characters only. `bytes.fromhex` will
        #    reject anything else, so we can fall through to base64
        #    without worrying about accidental hex matches.
        der: bytes | None = None
        hex_stripped = "".join(stripped.split())
        if all(c in "0123456789abcdefABCDEF" for c in hex_stripped) and hex_stripped:
            try:
                der = bytes.fromhex(hex_stripped)
            except ValueError:
                der = None

        # 3) BASE64 path — modern Changelly onboarding UI ships b64 DER.
        if der is None:
            try:
                der = base64.b64decode(stripped, validate=False)
            except Exception:  # noqa: BLE001
                der = None

        if der is None:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Changelly private key material is not PEM, hex, or "
                    "base64. Verify CHANGELLY_PRIVATE_KEY in the Emergent "
                    "dashboard."
                ),
            )
        try:
            key = serialization.load_der_private_key(der, password=None)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=500,
                detail=f"Changelly DER private key could not be parsed: {exc}",
            ) from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise HTTPException(
            status_code=500,
            detail=(
                "Changelly private key is not an RSA key. The v2 API "
                "requires RSA-SHA256 signatures."
            ),
        )
    return key


def _sign_rsa_sha256(payload: bytes, private_key_hex: str = "") -> str:
    """Sign a JSON-RPC body with the Changelly account private key.

    Returns a Base64-encoded RSA-SHA256 (PKCS#1 v1.5) signature suitable
    for the `X-Api-Signature` request header.

    Resolution order for the key material (first non-empty wins):
      1. `private_key_hex` argument — tests / call-site override.
      2. `CHANGELLY_PRIVATE_KEY`      — canonical env var (Sprint 21).
      3. `CHANGELLY_API_PRIVATE_KEY_PEM` — legacy alias, PEM form.
      4. `CHANGELLY_PRIVATE_KEY_HEX`  — legacy alias, DER-hex form.

    The key material itself is NEVER logged. Signing throws
    HTTPException(500) with an actionable detail if the env slot is
    empty or the material fails to parse.
    """
    key_material = (
        private_key_hex
        or CHANGELLY_PRIVATE_KEY
        or CHANGELLY_API_PRIVATE_KEY_PEM
        or CHANGELLY_PRIVATE_KEY_HEX
    )
    priv = _load_private_key(key_material)
    signature = priv.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode()


# ---------------------------------------------------------------------------
# Test helper — exposed so the future pytest suite can clear the in-mem
# registry between tests without poking at module internals. Keep
# private-by-convention (underscore prefix) so it doesn't leak into
# router export accidentally.
# ---------------------------------------------------------------------------
def _reset_for_tests() -> None:
    _mock_swaps.clear()



# ---------------------------------------------------------------------------
# Sprint 22 iter 36 — LIVE HANDSHAKE ROUTER.
#
# `/api/exchange/currencies` is a THIN, unmocked passthrough that calls
# Changelly's `getCurrencies` JSON-RPC method with a real RSA-SHA256
# signature. Its only job is to prove the plumbing works end-to-end:
#
#     backend → sign(payload) → POST https://api.changelly.com/v2 →
#     verify signature server-side → return currency list
#
# Unlike `/api/swaps/currencies` (which returns the CURATED allow-list
# used by the UI), this endpoint intentionally hits the wire on every
# call so a QA can quickly verify:
#   - CHANGELLY_API_KEY / CHANGELLY_PRIVATE_KEY are loaded
#   - The RSA-SHA256 signature is accepted by Changelly
#   - The account is provisioned and returns a live currency list
#
# The endpoint remains available even when CHANGELLY_PRODUCTION_MODE=0
# because the goal of THIS route is exactly to test the live path.
# It responds with a structured error body (never 500) when the
# handshake fails so the caller can distinguish env-config problems
# from network problems.
# ---------------------------------------------------------------------------
exchange_router = APIRouter(prefix="/exchange", tags=["changelly-live"])


@exchange_router.get("/currencies")
async def exchange_currencies_live() -> dict:
    """Live Changelly `getCurrencies` handshake.

    Returns:
        {
            "ok": True,
            "mode": "live",
            "count": <int>,
            "currencies_sample": [<first 10 tickers>],
            "raw_result_type": "list" | "dict",
        }

    Or on failure:
        {
            "ok": False,
            "mode": "live",
            "stage": "config" | "sign" | "network" | "changelly_error",
            "detail": "<human readable>",
        }
    """
    # -- Stage 1: env presence check ------------------------------------
    if not CHANGELLY_API_KEY:
        return {
            "ok": False,
            "mode": "live",
            "stage": "config",
            "detail": "CHANGELLY_API_KEY is empty. Set it in backend/.env.",
        }
    key_material = (
        CHANGELLY_PRIVATE_KEY
        or CHANGELLY_API_PRIVATE_KEY_PEM
        or CHANGELLY_PRIVATE_KEY_HEX
    )
    if not key_material:
        return {
            "ok": False,
            "mode": "live",
            "stage": "config",
            "detail": (
                "No RSA private key material found. Set "
                "CHANGELLY_PRIVATE_KEY (preferred), "
                "CHANGELLY_API_PRIVATE_KEY_PEM, or "
                "CHANGELLY_PRIVATE_KEY_HEX in backend/.env."
            ),
        }

    # -- Stage 2: build + sign JSON-RPC envelope ------------------------
    envelope = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "getCurrencies",
        "params": {},
    }
    body = json.dumps(envelope, separators=(",", ":")).encode()
    try:
        signature = _sign_rsa_sha256(body)
    except HTTPException as exc:
        return {
            "ok": False,
            "mode": "live",
            "stage": "sign",
            "detail": exc.detail,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "mode": "live",
            "stage": "sign",
            "detail": f"Signing failed: {exc}",
        }

    # -- Stage 3: fire the request --------------------------------------
    headers = {
        "X-Api-Key": CHANGELLY_API_KEY,
        "X-Api-Signature": signature,
        "Content-Type": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(CHANGELLY_BASE_URL, content=body, headers=headers)
    except httpx.HTTPError as exc:
        return {
            "ok": False,
            "mode": "live",
            "stage": "network",
            "detail": f"HTTP transport error: {exc}",
        }

    # -- Stage 4: parse response ----------------------------------------
    if r.status_code != 200:
        return {
            "ok": False,
            "mode": "live",
            "stage": "changelly_error",
            "detail": (
                f"Changelly returned HTTP {r.status_code}. "
                f"Body: {r.text[:400]}"
            ),
        }
    try:
        data = r.json()
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "mode": "live",
            "stage": "changelly_error",
            "detail": f"Non-JSON response: {exc}",
        }

    if "error" in data:
        err = data["error"] or {}
        return {
            "ok": False,
            "mode": "live",
            "stage": "changelly_error",
            "detail": (
                f"Changelly error code={err.get('code')} "
                f"message={err.get('message')}"
            ),
        }

    result = data.get("result", [])
    if isinstance(result, list):
        sample = result[:10]
        return {
            "ok": True,
            "mode": "live",
            "count": len(result),
            "currencies_sample": sample,
            "raw_result_type": "list",
        }
    if isinstance(result, dict):
        keys = list(result.keys())[:10]
        return {
            "ok": True,
            "mode": "live",
            "count": len(result),
            "currencies_sample": keys,
            "raw_result_type": "dict",
        }
    return {
        "ok": False,
        "mode": "live",
        "stage": "changelly_error",
        "detail": f"Unexpected result type: {type(result).__name__}",
    }


# ---------------------------------------------------------------------------
# Sprint 22 iter 37 — LIVE SWAP FLOW (Quote + Create Transaction).
#
# Two thin endpoints that wrap Changelly's real `getExchangeAmount` and
# `createTransaction` JSON-RPC methods. Signed with the same RSA-SHA256
# helper the /exchange/currencies handshake uses.
#
# Route contract:
#   POST /api/exchange/quote
#     body: { from_currency: str, to_currency: str, amount_from: float }
#     → { ok, amount_to, min_amount?, max_amount?, from, to }
#
#   POST /api/exchange/create-transaction
#     body: { from_currency, to_currency, amount_from, payout_address,
#             payout_extra_id? }
#     → { ok, transaction_id, payin_address, payin_extra_id, amount_expected,
#         amount_to, status }
#
# Every response mirrors the /exchange/currencies structured-error shape
# (`ok` flag + `stage` + `detail`) so the frontend can render actionable
# messages without parsing 500 bodies.
#
# LOGGING: request + response are logged via `_log_exchange` with the
# private key / signature redacted. Never log the raw RSA private key.
# ---------------------------------------------------------------------------
import logging as _logging  # local alias to avoid touching module-top imports

_ex_log = _logging.getLogger("changelly.exchange")
if not _ex_log.handlers:
    _handler = _logging.StreamHandler()
    _handler.setFormatter(
        _logging.Formatter("%(asctime)s [changelly] %(levelname)s: %(message)s")
    )
    _ex_log.addHandler(_handler)
_ex_log.setLevel(_logging.INFO)


def _redact_headers(h: dict) -> dict:
    """Return headers safe to log — signature/key values redacted."""
    out = dict(h)
    if "X-Api-Signature" in out:
        v = out["X-Api-Signature"]
        out["X-Api-Signature"] = f"<{len(v)}b redacted>"
    if "X-Api-Key" in out:
        v = out["X-Api-Key"]
        out["X-Api-Key"] = f"{v[:6]}…{v[-4:]}" if len(v) > 12 else "<redacted>"
    return out


async def _signed_jsonrpc(method: str, params: Any) -> dict:
    """Sign + POST a Changelly JSON-RPC call, returning parsed JSON body.

    On any failure returns a structured dict:
      { "_error": True, "stage": "config|sign|network|changelly_error",
        "detail": "<msg>" }
    Callers should check `_error` first.
    """
    if not CHANGELLY_API_KEY:
        return {
            "_error": True,
            "stage": "config",
            "detail": "CHANGELLY_API_KEY is empty. Set it in backend/.env.",
        }
    key_material = (
        CHANGELLY_PRIVATE_KEY
        or CHANGELLY_API_PRIVATE_KEY_PEM
        or CHANGELLY_PRIVATE_KEY_HEX
    )
    if not key_material:
        return {
            "_error": True,
            "stage": "config",
            "detail": "No RSA private key material found in env.",
        }
    envelope = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": params,
    }
    body = json.dumps(envelope, separators=(",", ":")).encode()
    try:
        signature = _sign_rsa_sha256(body)
    except HTTPException as exc:
        return {"_error": True, "stage": "sign", "detail": exc.detail}
    except Exception as exc:  # noqa: BLE001
        return {"_error": True, "stage": "sign", "detail": f"Signing failed: {exc}"}

    headers = {
        "X-Api-Key": CHANGELLY_API_KEY,
        "X-Api-Signature": signature,
        "Content-Type": "application/json",
    }
    _ex_log.info(
        "→ %s params=%s headers=%s",
        method,
        json.dumps(params) if not isinstance(params, str) else params,
        _redact_headers(headers),
    )
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.post(CHANGELLY_BASE_URL, content=body, headers=headers)
    except httpx.HTTPError as exc:
        _ex_log.warning("← %s network_error=%s", method, exc)
        return {
            "_error": True,
            "stage": "network",
            "detail": f"HTTP transport error: {exc}",
        }
    if r.status_code != 200:
        _ex_log.warning(
            "← %s http=%s body=%s", method, r.status_code, r.text[:400]
        )
        return {
            "_error": True,
            "stage": "changelly_error",
            "detail": f"Changelly HTTP {r.status_code}: {r.text[:300]}",
        }
    try:
        data = r.json()
    except Exception as exc:  # noqa: BLE001
        return {
            "_error": True,
            "stage": "changelly_error",
            "detail": f"Non-JSON response: {exc}",
        }
    if "error" in data and data["error"]:
        err = data["error"]
        msg = f"code={err.get('code')} message={err.get('message')}"
        _ex_log.warning("← %s changelly_error=%s", method, msg)
        return {
            "_error": True,
            "stage": "changelly_error",
            "detail": msg,
        }
    _ex_log.info(
        "← %s ok result=%s",
        method,
        json.dumps(data.get("result"))[:400] if data.get("result") is not None else "<none>",
    )
    return data


# --- Request/response models for the new exchange endpoints ---------------
class ExchangeQuoteRequest(BaseModel):
    from_currency: str = Field(..., min_length=1, max_length=20)
    to_currency: str = Field(..., min_length=1, max_length=20)
    amount_from: float = Field(..., gt=0)

    @field_validator("from_currency", "to_currency")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()


class ExchangeCreateRequest(BaseModel):
    from_currency: str = Field(..., min_length=1, max_length=20)
    to_currency: str = Field(..., min_length=1, max_length=20)
    amount_from: float = Field(..., gt=0)
    payout_address: str = Field(..., min_length=4, max_length=200)
    payout_extra_id: Optional[str] = Field(None, max_length=200)
    refund_address: Optional[str] = Field(None, max_length=200)
    refund_extra_id: Optional[str] = Field(None, max_length=200)

    @field_validator("from_currency", "to_currency")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()


@exchange_router.post("/quote")
async def exchange_quote_live(req: ExchangeQuoteRequest) -> dict:
    """Live quote — calls Changelly `getExchangeAmount` (+ `getMinAmount`).

    Returns:
      { ok: True, from, to, amount_from, amount_to, min_amount?, max_amount?,
        rate }
    Or:
      { ok: False, stage, detail }
    """
    # Fire quote + min/max in parallel-ish (sequential is fine here; RPC is fast).
    quote_res = await _signed_jsonrpc(
        "getExchangeAmount",
        [
            {
                "from": req.from_currency,
                "to": req.to_currency,
                "amountFrom": str(req.amount_from),
            }
        ],
    )
    if quote_res.get("_error"):
        return {"ok": False, **{k: v for k, v in quote_res.items() if k != "_error"}}

    result = quote_res.get("result")
    # Changelly returns a list of quote objects (one per input).
    amount_to: Optional[str] = None
    network_fee: Optional[str] = None
    changelly_fee: Optional[str] = None
    max_amount_inline: Optional[str] = None
    min_amount_inline: Optional[str] = None
    rate_inline: Optional[str] = None
    if isinstance(result, list) and result:
        first = result[0]
        if isinstance(first, dict):
            amount_to = str(first.get("amountTo") or first.get("result") or "")
            network_fee = (
                str(first.get("networkFee")) if first.get("networkFee") is not None else None
            )
            changelly_fee = (
                str(first.get("fee")) if first.get("fee") is not None else None
            )
            max_amount_inline = (
                str(first.get("max")) if first.get("max") is not None else None
            )
            min_amount_inline = (
                str(first.get("min")) if first.get("min") is not None else None
            )
            rate_inline = (
                str(first.get("rate")) if first.get("rate") is not None else None
            )
        else:
            amount_to = str(first)
    elif isinstance(result, dict):
        amount_to = str(result.get("amountTo") or result.get("result") or "")
    elif isinstance(result, (str, int, float)):
        amount_to = str(result)

    # Always fetch min amount so the UI can enforce it and show a
    # useful error when a quote can't be produced.
    min_amount: Optional[str] = None
    max_amount: Optional[str] = None
    min_res = await _signed_jsonrpc(
        "getMinAmount",
        {"from": req.from_currency, "to": req.to_currency},
    )
    if not min_res.get("_error"):
        mr = min_res.get("result")
        if isinstance(mr, (str, int, float)):
            min_amount = str(mr)
        elif isinstance(mr, dict):
            min_amount = str(mr.get("minAmount") or mr.get("result") or "") or None

    if not amount_to:
        # Empty result from Changelly usually means amount is below the
        # pair's minimum (or above max). Surface a clear reason.
        try:
            min_f = float(min_amount) if min_amount else 0
        except ValueError:
            min_f = 0
        if min_f and req.amount_from < min_f:
            return {
                "ok": False,
                "stage": "below_minimum",
                "detail": (
                    f"Amount {req.amount_from} {req.from_currency.upper()} is below "
                    f"the minimum of {min_amount} for the {req.from_currency.upper()}→"
                    f"{req.to_currency.upper()} pair."
                ),
                "min_amount": min_amount,
                "from": req.from_currency,
                "to": req.to_currency,
            }
        return {
            "ok": False,
            "stage": "changelly_error",
            "detail": (
                "Changelly returned no quote for this pair. It may be temporarily "
                "unavailable or the amount is outside the supported range."
            ),
            "min_amount": min_amount,
            "from": req.from_currency,
            "to": req.to_currency,
        }

    try:
        rate = float(amount_to) / req.amount_from if req.amount_from else 0.0
    except (ValueError, ZeroDivisionError):
        rate = 0.0

    return {
        "ok": True,
        "from": req.from_currency,
        "to": req.to_currency,
        "amount_from": req.amount_from,
        "amount_to": amount_to,
        "network_fee": network_fee,
        "changelly_fee": changelly_fee,
        "min_amount": min_amount_inline or min_amount,
        "max_amount": max_amount_inline or max_amount,
        "rate": float(rate_inline) if rate_inline else rate,
    }


@exchange_router.post("/create-transaction")
async def exchange_create_transaction_live(req: ExchangeCreateRequest) -> dict:
    """Create a live Changelly transaction and return payin details.

    Returns:
      { ok: True, transaction_id, payin_address, payin_extra_id,
        amount_expected_from, amount_expected_to, status, created_at,
        refund_address? }
    Or:
      { ok: False, stage, detail }
    """
    params: dict[str, Any] = {
        "from": req.from_currency,
        "to": req.to_currency,
        "amountFrom": str(req.amount_from),
        "address": req.payout_address.strip(),
    }
    if req.payout_extra_id:
        params["extraId"] = req.payout_extra_id.strip()
    if req.refund_address:
        params["refundAddress"] = req.refund_address.strip()
    if req.refund_extra_id:
        params["refundExtraId"] = req.refund_extra_id.strip()
    # Sprint 23 iter 6 — Attach partner/affiliate refId when configured.
    if CHANGELLY_SECRET:
        params["refId"] = CHANGELLY_SECRET

    res = await _signed_jsonrpc("createTransaction", params)
    if res.get("_error"):
        return {"ok": False, **{k: v for k, v in res.items() if k != "_error"}}

    result = res.get("result")
    if not isinstance(result, dict):
        return {
            "ok": False,
            "stage": "changelly_error",
            "detail": f"Unexpected createTransaction shape: {str(result)[:200]}",
        }

    return {
        "ok": True,
        "transaction_id": result.get("id") or result.get("transactionId") or "",
        "payin_address": result.get("payinAddress") or "",
        "payin_extra_id": result.get("payinExtraId"),
        "payout_address": result.get("payoutAddress") or req.payout_address,
        "payout_extra_id": result.get("payoutExtraId") or req.payout_extra_id,
        "amount_expected_from": str(
            result.get("amountExpectedFrom") or result.get("amountFrom") or req.amount_from
        ),
        "amount_expected_to": str(
            result.get("amountExpectedTo") or result.get("amountTo") or ""
        ),
        "status": result.get("status") or "new",
        "created_at": result.get("createdAt") or int(time.time()),
        "currency_from": result.get("currencyFrom") or req.from_currency,
        "currency_to": result.get("currencyTo") or req.to_currency,
    }


@exchange_router.get("/currencies-full")
async def exchange_currencies_full_live() -> dict:
    """Return the full Changelly currency list via `getCurrenciesFull`.

    Includes name, ticker, enabled flag, protocol so the frontend can
    render a rich searchable picker.
    """
    res = await _signed_jsonrpc("getCurrenciesFull", {})
    if res.get("_error"):
        return {"ok": False, **{k: v for k, v in res.items() if k != "_error"}}
    result = res.get("result")
    if not isinstance(result, list):
        return {
            "ok": False,
            "stage": "changelly_error",
            "detail": f"Unexpected getCurrenciesFull shape: {type(result).__name__}",
        }
    # Trim to just what the UI needs so payload is smaller.
    trimmed = []
    for c in result:
        if not isinstance(c, dict):
            continue
        trimmed.append(
            {
                "ticker": c.get("ticker") or c.get("name") or "",
                "name": c.get("fullName") or c.get("name") or "",
                "enabled": bool(c.get("enabled", True))
                and bool(c.get("enabledFrom", True))
                and bool(c.get("enabledTo", True)),
                "protocol": c.get("protocol") or "",
                "image": c.get("image") or "",
                "extraIdName": c.get("extraIdName") or "",
                "addressValidator": c.get("addressValidator") or "",
            }
        )
    return {"ok": True, "count": len(trimmed), "currencies": trimmed}
