"""
CyberShield CNI - Authentication & Role-Based Access Control

Hardened prototype auth layer. Real deployments would sit behind an IdP
(SAML/OIDC, tied into the organisation's PAM/PIM system) — this module is a
self-contained stand-in that still enforces the design doc's core safety rule:
OT containment actions require a named, authenticated human with the right role.

Roles:
  - soc_analyst : can view everything, respond to IT-zone alerts, remediate vulns
  - ot_operator : everything soc_analyst can do, PLUS authorize OT-zone actions
  - admin       : full access, including audit log and user administration view

Passwords are hashed with PBKDF2-HMAC-SHA256 (stdlib only, no native deps).
Tokens are signed JWTs (HS256) with a short expiry + role/username claims.
"""
import hashlib
import hmac
import os
import time
import base64
import json
import secrets
from typing import Optional

from fastapi import Header, HTTPException, status, Depends

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
# In production this MUST come from a secrets manager / env var, rotated regularly.
JWT_SECRET = os.environ.get("CYBERSHIELD_JWT_SECRET", secrets.token_hex(32))
JWT_TTL_SECONDS = 60 * 60 * 8  # 8-hour shift-length session

ROLES = ("soc_analyst", "ot_operator", "admin")


def _pbkdf2(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return base64.b64encode(dk).decode()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    return base64.b64encode(salt).decode() + "$" + _pbkdf2(password, salt)


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_b64, digest = stored.split("$")
        salt = base64.b64decode(salt_b64)
        return hmac.compare_digest(_pbkdf2(password, salt), digest)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Demo user directory (in-memory). Swap for a real user table + IdP in production.
# ---------------------------------------------------------------------------
USERS = {
    "admin": {
        "username": "admin",
        "full_name": "Platform Administrator",
        "role": "admin",
        "password_hash": hash_password("CyberShield@2026"),
    },
    "priya.soc": {
        "username": "priya.soc",
        "full_name": "Priya Nair (SOC Analyst)",
        "role": "soc_analyst",
        "password_hash": hash_password("Analyst@2026"),
    },
    "arjun.ot": {
        "username": "arjun.ot",
        "full_name": "Arjun Mehta (OT Operator)",
        "role": "ot_operator",
        "password_hash": hash_password("OtSafety@2026"),
    },
}


def authenticate(username: str, password: str) -> Optional[dict]:
    user = USERS.get(username)
    if not user or not verify_password(password, user["password_hash"]):
        return None
    return user


# ---------------------------------------------------------------------------
# Minimal JWT implementation (HS256) — avoids a heavyweight extra dependency
# while still following the standard header.payload.signature structure.
# ---------------------------------------------------------------------------
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_access_token(username: str, role: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + JWT_TTL_SECONDS,
    }
    signing_input = f"{_b64url_encode(json.dumps(header).encode())}.{_b64url_encode(json.dumps(payload).encode())}"
    signature = hmac.new(JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def decode_access_token(token: str) -> dict:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(JWT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_encode(expected_sig), sig_b64):
            raise ValueError("bad signature")
        payload = json.loads(_b64url_decode(payload_b64))
        if payload["exp"] < time.time():
            raise ValueError("token expired")
        return payload
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------
def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ", 1)[1]
    payload = decode_access_token(token)
    return {"username": payload["sub"], "role": payload["role"]}


def require_role(*roles: str):
    """Dependency factory: Depends(require_role('admin', 'ot_operator'))"""

    def _dep(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user['role']}' is not authorized for this action "
                       f"(requires one of: {', '.join(roles)})",
            )
        return user

    return _dep
