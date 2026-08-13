"""
TOTP (RFC 6238) - autenticacao de dois fatores (2FA) para o Painel de
Administracao do site (`app/admin_auth.py`).

Implementacao PROPRIA usando apenas a biblioteca padrao (hmac/hashlib/struct/
base64), sem dependencia externa adicional (compativel com Google
Authenticator, Authy, 1Password, etc. - qualquer app TOTP padrao). Isto
fecha a lacuna de seguranca de depender apenas de usuario+senha: mesmo que a
senha vaze, o atacante ainda precisa do segredo TOTP (fisicamente no celular
do operador) ou de um codigo de backup de uso unico para autenticar.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 6
TOTP_SECRET_BYTES = 20  # 160 bits - tamanho padrao recomendado pela RFC 4226
BACKUP_CODE_COUNT = 10


def generate_secret() -> str:
    """Gera um novo segredo TOTP, codificado em Base32 (formato padrao para
    apps autenticadores)."""
    raw = secrets.token_bytes(TOTP_SECRET_BYTES)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def provisioning_uri(secret: str, username: str, issuer: str = "PixCripto") -> str:
    """URI `otpauth://totp/...` padrao, pronta para virar QR code e ser
    escaneada por qualquer app autenticador (Google Authenticator, Authy...)."""
    label = urllib.parse.quote(f"{issuer}:{username}")
    params = urllib.parse.urlencode({
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": str(TOTP_DIGITS),
        "period": str(TOTP_STEP_SECONDS),
    })
    return f"otpauth://totp/{label}?{params}"


def _hotp(secret: str, counter: int) -> str:
    padding = "=" * (-len(secret) % 8)
    key = base64.b32decode(secret.upper() + padding)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def generate_code(secret: str, for_time: float | None = None) -> str:
    t = for_time if for_time is not None else time.time()
    counter = int(t // TOTP_STEP_SECONDS)
    return _hotp(secret, counter)


def verify_code(secret: str, code: str, valid_window: int = 1) -> bool:
    """Verifica um codigo de 6 digitos, tolerando deriva de relogio de ate
    `valid_window` passos de 30s para tras/frente (padrao da industria,
    evita falha de login legitimo por pequena diferenca de horario entre
    servidor e celular)."""
    if not code or not code.isdigit() or len(code) != TOTP_DIGITS:
        return False
    now = time.time()
    counter_now = int(now // TOTP_STEP_SECONDS)
    for offset in range(-valid_window, valid_window + 1):
        if secrets.compare_digest(_hotp(secret, counter_now + offset), code):
            return True
    return False


def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> list[str]:
    """Gera codigos de recuperacao de uso unico (formato `xxxx-xxxx`), usados
    quando o operador perde acesso ao dispositivo autenticador TOTP."""
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(4)
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.strip().lower().encode("utf-8")).hexdigest()
