"""
Login REAL do Painel de Administracao do site (`/admin`, React).

Substitui o antigo modelo de "colar um token compartilhado" (`X-Admin-Token`,
ainda mantido em `app/news.py` por compatibilidade) por uma conta de operador
de verdade: usuario + senha com hash PBKDF2-HMAC-SHA256 (200k iteracoes, salt
aleatorio por conta - mesma familia de KDF ja usada em `crypto_utils.create_keystore`
para o keystore de carteira, mantendo consistencia de padrao criptografico no
projeto) e sessao com token aleatorio de 256 bits, expiravel e revogavel.

Fail-closed por padrao: se nenhuma conta administradora existir E nenhuma
credencial de bootstrap estiver configurada via `.env`
(`PIXCRIPTO_ADMIN_USERNAME`/`PIXCRIPTO_ADMIN_PASSWORD`), o login fica
DESABILITADO - nunca existe uma conta "de fabrica" com senha previsivel.

Protegido pelo mesmo `bruteforce_guard` adaptativo usado no restante do
sistema: tentativas de login incorretas sofrem cooldown exponencial por
identidade (IP), tornando ataques de forca bruta contra a senha do operador
progressivamente mais caros.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import time
from typing import Optional

from fastapi import HTTPException

from . import qrcode_utils, storage, totp
from .bruteforce_guard import BruteForceLockedError, guard as bruteforce_guard
from .settings import settings

PBKDF2_ITERATIONS = 200_000
PBKDF2_ALGO = "sha256"
SALT_SIZE = 16
SESSION_TOKEN_SIZE = 32  # bytes -> 256 bits


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac(PBKDF2_ALGO, password.encode("utf-8"), salt, PBKDF2_ITERATIONS).hex()


def _verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    candidate = _hash_password(password, salt)
    return secrets.compare_digest(candidate, expected_hash_hex)


def bootstrap_admin_user() -> None:
    """
    Chamado UMA VEZ no startup do servidor. Se nenhuma conta administradora
    existir ainda no banco E as variaveis de bootstrap estiverem definidas no
    `.env` (`PIXCRIPTO_ADMIN_USERNAME`/`PIXCRIPTO_ADMIN_PASSWORD`), cria a
    primeira conta. Se ja existir alguma conta, ou as variaveis nao estiverem
    definidas, nao faz nada (idempotente, seguro para rodar a cada restart).
    A primeira conta sempre recebe o papel (role) "owner" - o unico papel com
    permissao para criar/remover outras contas administradoras.
    """
    if storage.any_admin_user_exists():
        return
    username = settings.admin_bootstrap_username
    password = settings.admin_bootstrap_password
    if not username or not password:
        return  # login do painel fica desabilitado ate o operador configurar o .env
    salt = os.urandom(SALT_SIZE)
    password_hash = _hash_password(password, salt)
    storage.create_admin_user(username, password_hash, salt.hex(), role="owner", created_by="bootstrap")


def change_password(username: str, old_password: str, new_password: str) -> None:
    user = storage.get_admin_user(username)
    if user is None:
        raise HTTPException(status_code=404, detail="Conta de administrador nao encontrada")
    if not _verify_password(old_password, user["password_salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Senha atual incorreta")
    if len(new_password) < 10:
        raise HTTPException(status_code=400, detail="Nova senha deve ter ao menos 10 caracteres")
    salt = os.urandom(SALT_SIZE)
    password_hash = _hash_password(new_password, salt)
    storage.set_admin_password(username, password_hash, salt.hex())


def login(username: str, password: str, client_identity: str, ip: str, otp_code: Optional[str] = None) -> dict:
    """
    Autentica e retorna {"token": ..., "username": ..., "role": ...}.
    Levanta HTTPException(401/428/429/503) em caso de falha.

    Se a conta tiver 2FA (TOTP) habilitado, um `otp_code` valido (ou um codigo
    de backup de uso unico) e OBRIGATORIO - caso contrario retorna 428
    ("Precondition Required") com detail "2fa_required", sinalizando ao
    front-end para exibir o segundo passo do login antes de tentar de novo.
    """
    scope = "admin_panel_login"
    try:
        bruteforce_guard.check(scope, client_identity)
    except BruteForceLockedError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc

    user = storage.get_admin_user(username)
    if user is None or not _verify_password(password, user["password_salt"], user["password_hash"]):
        bruteforce_guard.record_failure(scope, client_identity)
        raise HTTPException(status_code=401, detail="Usuario ou senha invalidos")

    if user["totp_enabled"]:
        if not otp_code:
            raise HTTPException(status_code=428, detail="2fa_required")
        valid = totp.verify_code(user["totp_secret"], otp_code)
        if not valid:
            # tenta como codigo de backup de uso unico
            valid = storage.consume_admin_backup_code(username, totp.hash_backup_code(otp_code))
        if not valid:
            bruteforce_guard.record_failure(scope, client_identity)
            raise HTTPException(status_code=401, detail="Codigo de verificacao (2FA) invalido")

    bruteforce_guard.record_success(scope, client_identity)
    storage.touch_admin_user_login(username)

    token = secrets.token_hex(SESSION_TOKEN_SIZE)
    expires_at = time.time() + settings.admin_session_ttl_seconds
    storage.create_admin_session(token, username, expires_at, ip)
    return {"token": token, "username": username, "role": user["role"]}


def logout(token: str) -> None:
    storage.delete_admin_session(token)


def verify_session(token: Optional[str]) -> str:
    """Valida um token de sessao Bearer e retorna o username associado, ou
    levanta HTTPException(401) se ausente/invalido/expirado. Atualiza
    `last_seen_at` da sessao (util para auditoria/observabilidade de
    atividade do operador)."""
    if not token:
        raise HTTPException(status_code=401, detail="Sessao de administrador ausente - faca login")
    session = storage.get_admin_session(token)
    if session is None:
        raise HTTPException(status_code=401, detail="Sessao invalida - faca login novamente")
    if session["expires_at"] < time.time():
        storage.delete_admin_session(token)
        raise HTTPException(status_code=401, detail="Sessao expirada - faca login novamente")
    storage.touch_admin_session(token)
    return session["username"]


def require_owner(username: str) -> None:
    """Levanta 403 se a conta nao tiver o papel 'owner' - usado para proteger
    gestao de outras contas administradoras (criar/remover operadores)."""
    user = storage.get_admin_user(username)
    if user is None or user["role"] != "owner":
        raise HTTPException(status_code=403, detail="Apenas contas com papel 'owner' podem gerenciar administradores")


def is_login_enabled() -> bool:
    """True se ja existe conta administradora OU bootstrap configurado -
    usado pela UI para diferenciar 'nao configurado' de 'usuario/senha
    incorretos' na tela de login."""
    return storage.any_admin_user_exists() or bool(settings.admin_bootstrap_username and settings.admin_bootstrap_password)


# ---------------------------------------------------------------------------
# 2FA (TOTP) - ver app/totp.py
# ---------------------------------------------------------------------------

def start_totp_enrollment(username: str) -> dict:
    """Gera um novo segredo TOTP (ainda NAO habilitado) e devolve o segredo +
    QR code + URI de provisionamento, para o operador escanear com um app
    autenticador. So e efetivado (totp_enabled=1) apos `confirm_totp_enrollment`
    verificar que o operador realmente configurou o app corretamente."""
    user = storage.get_admin_user(username)
    if user is None:
        raise HTTPException(status_code=404, detail="Conta de administrador nao encontrada")
    secret = totp.generate_secret()
    storage.set_admin_totp_secret(username, secret, enabled=False)
    uri = totp.provisioning_uri(secret, username)
    qr_base64 = qrcode_utils.generate_qr_base64(uri)
    return {"secret": secret, "otpauth_uri": uri, "qr_code_base64": qr_base64}


def confirm_totp_enrollment(username: str, code: str) -> list[str]:
    """Confirma o enrollment com um codigo valido gerado pelo app, ativa o
    2FA para a conta e gera/retorna os codigos de backup (mostrados apenas
    UMA VEZ - o operador deve salva-los em local seguro)."""
    user = storage.get_admin_user(username)
    if user is None:
        raise HTTPException(status_code=404, detail="Conta de administrador nao encontrada")
    if not user["totp_secret"]:
        raise HTTPException(status_code=400, detail="Nenhum enrollment de 2FA em andamento - chame /2fa/setup primeiro")
    if not totp.verify_code(user["totp_secret"], code):
        raise HTTPException(status_code=401, detail="Codigo invalido - verifique o horario do dispositivo e tente novamente")
    storage.set_admin_totp_secret(username, user["totp_secret"], enabled=True)
    backup_codes = totp.generate_backup_codes()
    storage.replace_admin_backup_codes(username, [totp.hash_backup_code(c) for c in backup_codes])
    return backup_codes


def disable_totp(username: str, password: str) -> None:
    """Desativa o 2FA da conta - requer confirmar a senha atual (evita que
    uma sessao sequestrada desative a segunda camada de seguranca sozinha)."""
    user = storage.get_admin_user(username)
    if user is None:
        raise HTTPException(status_code=404, detail="Conta de administrador nao encontrada")
    if not _verify_password(password, user["password_salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Senha incorreta")
    storage.set_admin_totp_secret(username, None, enabled=False)
    storage.replace_admin_backup_codes(username, [])


# ---------------------------------------------------------------------------
# Gestao multi-usuario (somente 'owner')
# ---------------------------------------------------------------------------

def create_operator(requester_username: str, new_username: str, new_password: str, role: str = "editor") -> None:
    require_owner(requester_username)
    if role not in ("owner", "editor"):
        raise HTTPException(status_code=400, detail="Papel invalido (use 'owner' ou 'editor')")
    if storage.get_admin_user(new_username) is not None:
        raise HTTPException(status_code=409, detail="Ja existe uma conta com este nome de usuario")
    if len(new_password) < 10:
        raise HTTPException(status_code=400, detail="Senha deve ter ao menos 10 caracteres")
    salt = os.urandom(SALT_SIZE)
    password_hash = _hash_password(new_password, salt)
    storage.create_admin_user(new_username, password_hash, salt.hex(), role=role, created_by=requester_username)


def delete_operator(requester_username: str, target_username: str) -> None:
    require_owner(requester_username)
    if requester_username == target_username:
        raise HTTPException(status_code=400, detail="Nao e possivel remover a propria conta")
    target = storage.get_admin_user(target_username)
    if target is None:
        raise HTTPException(status_code=404, detail="Conta nao encontrada")
    if target["role"] == "owner" and storage.count_admin_users_by_role("owner") <= 1:
        raise HTTPException(status_code=400, detail="Nao e possivel remover o unico 'owner' restante")
    storage.delete_admin_user_row(target_username)


def list_operators() -> list[dict]:
    return [
        {
            "username": u["username"],
            "role": u["role"],
            "created_at": u["created_at"],
            "last_login_at": u["last_login_at"],
            "totp_enabled": u["totp_enabled"],
            "created_by": u["created_by"],
        }
        for u in storage.list_admin_users()
    ]
