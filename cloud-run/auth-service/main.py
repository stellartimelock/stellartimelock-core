# Stellar TimeLock — Auth Service (Cloud Run).
#
# Thin OAuth 2.0 proxy that moves the Google `client_secret` off the
# mobile client. The Expo app used to POST directly to
# `https://oauth2.googleapis.com/token` with the secret bundled into
# the JS output (via EXPO_PUBLIC_GOOGLE_CLIENT_SECRET), which is
# trivially extractable by anyone who inspects the app bundle.
#
# This service now owns the secret:
#
#   POST /oauth/exchange   → auth code  → access + refresh + email
#   POST /oauth/refresh    → refresh    → fresh access token
#   POST /oauth/revoke     → revoke a token (sign-out)
#   GET  /healthz          → Cloud Run health probe
#
# The service supports both OAuth client types the mobile app uses:
#
#   * "web"     — used by Metro web preview.  Requires `client_secret`
#                  on the /token endpoint.
#   * "android" — used by standalone Android builds.  Google authenticates
#                  Android clients by package name + SHA-1 fingerprint,
#                  so NO secret is sent on the /token endpoint.
#
# Env vars (set on the Cloud Run service, never bundled into the app):
#   GOOGLE_CLIENT_ID_WEB
#   GOOGLE_CLIENT_SECRET_WEB
#   GOOGLE_CLIENT_ID_ANDROID
#   ALLOWED_ORIGINS         (comma-separated; * allowed for dev)
#
# Deploy commands live in ./README.md.

from __future__ import annotations

import logging
import os
from typing import Literal, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("auth-service")

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

GOOGLE_CLIENT_ID_WEB = os.getenv("GOOGLE_CLIENT_ID_WEB", "")
GOOGLE_CLIENT_SECRET_WEB = os.getenv("GOOGLE_CLIENT_SECRET_WEB", "")
GOOGLE_CLIENT_ID_ANDROID = os.getenv("GOOGLE_CLIENT_ID_ANDROID", "")

_ALLOWED_ORIGINS_RAW = os.getenv("ALLOWED_ORIGINS", "*")
ALLOWED_ORIGINS = [o.strip() for o in _ALLOWED_ORIGINS_RAW.split(",") if o.strip()]

app = FastAPI(
    title="Stellar TimeLock Auth Service",
    description="Google OAuth token-exchange proxy.  Keeps client_secret off the mobile client.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS or ["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ------------------------------------------------------------------
# Request / response schemas
# ------------------------------------------------------------------

ClientKind = Literal["web", "android"]


class ExchangeRequest(BaseModel):
    code: str = Field(..., description="Authorization code returned by Google")
    redirect_uri: str = Field(..., description="Exact redirect_uri sent to /authorize")
    code_verifier: Optional[str] = Field(None, description="PKCE verifier")
    client_kind: ClientKind = Field(
        "web",
        description="Which OAuth client type minted the code — 'web' or 'android'",
    )


class ExchangeResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    expires_in: int
    scope: str
    token_type: str
    id_token: Optional[str] = None
    email: Optional[str] = None


class RefreshRequest(BaseModel):
    refresh_token: str
    client_kind: ClientKind = "web"


class RefreshResponse(BaseModel):
    access_token: str
    expires_in: int
    scope: str
    token_type: str
    id_token: Optional[str] = None


class RevokeRequest(BaseModel):
    token: str


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _client_creds(kind: ClientKind) -> dict[str, str]:
    """Return the client_id (+ client_secret if applicable) for the requested client kind.

    Web clients MUST send client_secret to Google's /token endpoint;
    Android clients MUST NOT (Google verifies them via SHA-1 fingerprint).
    """
    if kind == "web":
        if not GOOGLE_CLIENT_ID_WEB or not GOOGLE_CLIENT_SECRET_WEB:
            raise HTTPException(
                status_code=500,
                detail="Server is missing GOOGLE_CLIENT_ID_WEB / GOOGLE_CLIENT_SECRET_WEB env vars.",
            )
        return {
            "client_id": GOOGLE_CLIENT_ID_WEB,
            "client_secret": GOOGLE_CLIENT_SECRET_WEB,
        }
    if kind == "android":
        if not GOOGLE_CLIENT_ID_ANDROID:
            raise HTTPException(
                status_code=500,
                detail="Server is missing GOOGLE_CLIENT_ID_ANDROID env var.",
            )
        return {"client_id": GOOGLE_CLIENT_ID_ANDROID}
    raise HTTPException(status_code=400, detail=f"Unknown client_kind: {kind}")


async def _fetch_email(access_token: str) -> Optional[str]:
    """Best-effort userinfo lookup so the mobile client can label the account."""
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if r.status_code != 200:
                return None
            data = r.json()
            email = data.get("email")
            return email if isinstance(email, str) else None
    except Exception as exc:  # noqa: BLE001
        log.warning("userinfo lookup failed: %s", exc)
        return None


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "stellartimelock-auth"}


@app.get("/")
async def root() -> dict[str, object]:
    return {
        "service": "Stellar TimeLock Auth Service",
        "version": app.version,
        "endpoints": [
            "POST /oauth/exchange",
            "POST /oauth/refresh",
            "POST /oauth/revoke",
            "GET  /healthz",
        ],
    }


@app.post("/oauth/exchange", response_model=ExchangeResponse)
async def oauth_exchange(payload: ExchangeRequest, request: Request) -> ExchangeResponse:
    """Exchange an authorization code for a Google OAuth token set."""
    creds = _client_creds(payload.client_kind)
    form = {
        **creds,
        "code": payload.code,
        "redirect_uri": payload.redirect_uri,
        "grant_type": "authorization_code",
    }
    if payload.code_verifier:
        form["code_verifier"] = payload.code_verifier

    log.info(
        "oauth/exchange kind=%s origin=%s redirect_uri=%s",
        payload.client_kind,
        request.headers.get("origin", "-"),
        payload.redirect_uri,
    )

    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(
            GOOGLE_TOKEN_URL,
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if r.status_code != 200:
        log.warning("google /token error %s: %s", r.status_code, r.text[:400])
        raise HTTPException(
            status_code=502,
            detail=f"Google token endpoint returned {r.status_code}: {r.text}",
        )

    data = r.json()
    email = await _fetch_email(data["access_token"])

    return ExchangeResponse(
        access_token=data["access_token"],
        refresh_token=data.get("refresh_token"),
        expires_in=int(data.get("expires_in", 3600)),
        scope=data.get("scope", ""),
        token_type=data.get("token_type", "Bearer"),
        id_token=data.get("id_token"),
        email=email,
    )


@app.post("/oauth/refresh", response_model=RefreshResponse)
async def oauth_refresh(payload: RefreshRequest) -> RefreshResponse:
    """Exchange a refresh_token for a new access_token."""
    creds = _client_creds(payload.client_kind)
    form = {
        **creds,
        "grant_type": "refresh_token",
        "refresh_token": payload.refresh_token,
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(
            GOOGLE_TOKEN_URL,
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if r.status_code != 200:
        log.warning("google refresh error %s: %s", r.status_code, r.text[:400])
        raise HTTPException(
            status_code=502,
            detail=f"Google token endpoint returned {r.status_code}: {r.text}",
        )

    data = r.json()
    return RefreshResponse(
        access_token=data["access_token"],
        expires_in=int(data.get("expires_in", 3600)),
        scope=data.get("scope", ""),
        token_type=data.get("token_type", "Bearer"),
        id_token=data.get("id_token"),
    )


@app.post("/oauth/revoke")
async def oauth_revoke(payload: RevokeRequest) -> dict[str, bool]:
    """Best-effort revoke.  Returns ok=true even on Google-side 400 (already-revoked tokens)."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(
                GOOGLE_REVOKE_URL,
                params={"token": payload.token},
            )
    except Exception as exc:  # noqa: BLE001
        log.warning("revoke request failed: %s", exc)
    return {"ok": True}
