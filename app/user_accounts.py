"""
Contas de USUARIO final da rede PixCripto (correntista/titular de carteira) -
diferente de `app/admin_auth.py`, que autentica os OPERADORES do painel.

Cobre o fluxo completo pedido: cadastro (usuario/e-mail/senha), login com
sessao expiravel, vinculo de carteira(s) publica(s) e verificacao de
identidade (KYC) com documento COM FOTO real - CPF, RG, foto do documento
(frente/verso) e uma selfie de prova de vida - tudo cifrado em repouso e
revisado manualmente por um operador antes de qualquer tier de KYC ser
concedido (nunca auto-aprovado).

Criptografia:
    - Senha: PBKDF2-HMAC-SHA256 (200k iteracoes, salt aleatorio por conta) -
      mesmo padrao usado em `app/admin_auth.py`/`app/crypto_utils.py`, para
      manter um unico padrao criptografico auditavel no projeto inteiro.
    - CPF/RG/nome/data de nascimento: cifrados com AES-256-GCM usando uma
      CHAVE MESTRA do processo (nunca a senha do usuario - o operador que
      revisa o KYC precisa conseguir decifrar para validar o documento,
      entao a chave e do servidor, nao do usuario). A chave mestra e gerada
      uma unica vez e persistida em `data/.kyc_master.key` (0600 no
      SO, fora do controle de versao - ver `.gitignore`), ou pode vir de
      `PIXCRIPTO_KYC_MASTER_KEY` (recomendado em producao, ex: de um
      secrets manager/KMS externo).
    - Fotos do documento/selfie: cada arquivo e cifrado em bloco unico
      (AES-256-GCM) e salvo em `data/kyc_documents/<uuid>.bin` - nome
      aleatorio, sem qualquer relacao com o usuario visivel no filesystem.
      So sao decifradas sob demanda, pelo endpoint de revisao do painel,
      nunca expostas por nenhuma rota publica.

O CPF em si NUNCA fica em texto claro na tabela `user_accounts` (so o hash,
para checar duplicidade) - o valor cifrado reversivel fica apenas dentro da
submissao de KYC (`kyc_submissions`), que so operadores podem decifrar.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import HTTPException
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import storage
from .bruteforce_guard import BruteForceLockedError, guard as bruteforce_guard
from .settings import settings

PBKDF2_ITERATIONS = 200_000
PBKDF2_ALGO = "sha256"
SALT_SIZE = 16
SESSION_TOKEN_SIZE = 32  # bytes -> 256 bits
SESSION_TTL_SECONDS = 60 * 60 * 24 * 7  # 7 dias

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

KYC_DOCUMENTS_DIR = storage.DB_PATH.parent / "kyc_documents"
_MASTER_KEY_FILE = storage.DB_PATH.parent / ".kyc_master.key"

MAX_DOCUMENT_SIZE_BYTES = 8 * 1024 * 1024  # 8 MiB por arquivo
ALLOWED_DOCUMENT_CONTENT_TYPES = {"image/jpeg", "image/png", "image/webp", "application/pdf"}


# ---------------------------------------------------------------------------
# Chave mestra de cifragem do KYC
# ---------------------------------------------------------------------------

def _load_or_create_master_key() -> bytes:
    env_key = os.environ.get("PIXCRIPTO_KYC_MASTER_KEY")
    if env_key:
        return hashlib.sha256(env_key.encode("utf-8")).digest()
    _MASTER_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if _MASTER_KEY_FILE.exists():
        return bytes.fromhex(_MASTER_KEY_FILE.read_text().strip())
    key = secrets.token_bytes(32)
    _MASTER_KEY_FILE.write_text(key.hex())
    try:
        os.chmod(_MASTER_KEY_FILE, 0o600)
    except OSError:
        pass  # best-effort no Windows (ACLs diferem de POSIX chmod)
    return key


def _aesgcm() -> AESGCM:
    return AESGCM(_load_or_create_master_key())


def _encrypt_text(plaintext: str) -> str:
    nonce = os.urandom(12)
    ciphertext = _aesgcm().encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def _decrypt_text(encoded: str) -> str:
    raw = base64.b64decode(encoded.encode("ascii"))
    nonce, ciphertext = raw[:12], raw[12:]
    return _aesgcm().decrypt(nonce, ciphertext, None).decode("utf-8")


def _encrypt_bytes(data: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + _aesgcm().encrypt(nonce, data, None)


def _decrypt_bytes(data: bytes) -> bytes:
    nonce, ciphertext = data[:12], data[12:]
    return _aesgcm().decrypt(nonce, ciphertext, None)


def _hash_cpf(cpf: str) -> str:
    digits = "".join(ch for ch in cpf if ch.isdigit())
    return hashlib.sha256(digits.encode("utf-8")).hexdigest()


def _is_valid_cpf(cpf: str) -> bool:
    """Valida o CPF pelo algoritmo oficial dos dois digitos verificadores
    (mod 11) - rejeita sequencias repetidas (00000000000, 11111111111 etc.,
    que passariam no calculo mas nunca sao CPFs reais emitidos)."""
    digits = [int(c) for c in cpf if c.isdigit()]
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for i in (9, 10):
        total = sum(d * w for d, w in zip(digits[:i], range(i + 1, 1, -1)))
        check = (total * 10) % 11
        check = 0 if check == 10 else check
        if check != digits[i]:
            return False
    return True


# ---------------------------------------------------------------------------
# Senha (mesmo padrao PBKDF2 usado em admin_auth.py)
# ---------------------------------------------------------------------------

def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac(PBKDF2_ALGO, password.encode("utf-8"), salt, PBKDF2_ITERATIONS).hex()


def _verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    candidate = _hash_password(password, salt)
    return secrets.compare_digest(candidate, expected_hash_hex)


# ---------------------------------------------------------------------------
# Cadastro / autenticacao
# ---------------------------------------------------------------------------

def register(username: str, email: str, password: str) -> dict:
    username = username.strip()
    email = email.strip().lower()
    if not _USERNAME_RE.match(username):
        raise HTTPException(status_code=400, detail="Usuario deve ter 3-32 caracteres (letras, numeros, . _ -)")
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="E-mail invalido")
    if len(password) < 10:
        raise HTTPException(status_code=400, detail="Senha deve ter ao menos 10 caracteres")
    if storage.get_user_by_username(username) is not None:
        raise HTTPException(status_code=409, detail="Nome de usuario ja cadastrado")
    if storage.get_user_by_email(email) is not None:
        raise HTTPException(status_code=409, detail="E-mail ja cadastrado")

    salt = os.urandom(SALT_SIZE)
    password_hash = _hash_password(password, salt)
    try:
        user_id = storage.create_user_account(username, email, password_hash, salt.hex())
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="Usuario ou e-mail ja cadastrado") from exc
    return {"id": user_id, "username": username, "email": email}


def login(username_or_email: str, password: str, client_identity: str, ip: str) -> dict:
    scope = "user_account_login"
    try:
        bruteforce_guard.check(scope, client_identity)
    except BruteForceLockedError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc

    identity = username_or_email.strip()
    user = storage.get_user_by_username(identity) or storage.get_user_by_email(identity.lower())
    if user is None or not _verify_password(password, user["password_salt"], user["password_hash"]):
        bruteforce_guard.record_failure(scope, client_identity)
        raise HTTPException(status_code=401, detail="Usuario/e-mail ou senha invalidos")
    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="Conta desativada - contate o suporte")

    bruteforce_guard.record_success(scope, client_identity)
    storage.touch_user_login(user["id"])

    token = secrets.token_hex(SESSION_TOKEN_SIZE)
    expires_at = time.time() + SESSION_TTL_SECONDS
    storage.create_user_session(token, user["id"], expires_at, ip)
    return {
        "token": token, "id": user["id"], "username": user["username"], "email": user["email"],
        "kyc_status": user["kyc_status"], "kyc_tier": user["kyc_tier"],
    }


def logout(token: str) -> None:
    storage.delete_user_session(token)


def verify_session(token: Optional[str]) -> dict:
    if not token:
        raise HTTPException(status_code=401, detail="Sessao ausente - faca login")
    session = storage.get_user_session(token)
    if session is None:
        raise HTTPException(status_code=401, detail="Sessao invalida - faca login novamente")
    if session["expires_at"] < time.time():
        storage.delete_user_session(token)
        raise HTTPException(status_code=401, detail="Sessao expirada - faca login novamente")
    user = storage.get_user_by_id(session["user_id"])
    if user is None or not user["is_active"]:
        raise HTTPException(status_code=401, detail="Conta invalida")
    storage.touch_user_session(token)
    return user


def change_password(user_id: int, old_password: str, new_password: str) -> None:
    user = storage.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Conta nao encontrada")
    if not _verify_password(old_password, user["password_salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Senha atual incorreta")
    if len(new_password) < 10:
        raise HTTPException(status_code=400, detail="Nova senha deve ter ao menos 10 caracteres")
    salt = os.urandom(SALT_SIZE)
    password_hash = _hash_password(new_password, salt)
    storage.set_user_password(user_id, password_hash, salt.hex())


def public_profile(user: dict) -> dict:
    wallets = storage.list_user_wallets(user["id"])
    return {
        "id": user["id"], "username": user["username"], "email": user["email"],
        "kyc_status": user["kyc_status"], "kyc_tier": user["kyc_tier"],
        "created_at": user["created_at"], "last_login_at": user["last_login_at"],
        "wallets": wallets,
    }


# ---------------------------------------------------------------------------
# Vinculo de carteiras (endereco publico apenas - nunca a chave privada)
# ---------------------------------------------------------------------------

def link_wallet(user_id: int, address: str, label: str = "") -> None:
    from . import crypto_utils
    if not crypto_utils.is_valid_address(address):
        raise HTTPException(status_code=400, detail="Endereco de carteira invalido")
    storage.link_user_wallet(user_id, address, label)


def unlink_wallet(user_id: int, address: str) -> None:
    if not storage.unlink_user_wallet(user_id, address):
        raise HTTPException(status_code=404, detail="Carteira nao vinculada a esta conta")


# ---------------------------------------------------------------------------
# KYC - submissao com documento com foto real (cifrado em repouso)
# ---------------------------------------------------------------------------

def _save_encrypted_document(raw_bytes: bytes) -> str:
    KYC_DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{uuid.uuid4().hex}.bin"
    path = KYC_DOCUMENTS_DIR / filename
    path.write_bytes(_encrypt_bytes(raw_bytes))
    return filename


def _validate_document_upload(content_type: str, raw_bytes: bytes, field_name: str) -> None:
    if content_type not in ALLOWED_DOCUMENT_CONTENT_TYPES:
        raise HTTPException(status_code=400, detail=f"{field_name}: tipo de arquivo nao suportado ({content_type})")
    if not raw_bytes:
        raise HTTPException(status_code=400, detail=f"{field_name}: arquivo vazio")
    if len(raw_bytes) > MAX_DOCUMENT_SIZE_BYTES:
        raise HTTPException(status_code=400, detail=f"{field_name}: arquivo excede o limite de 8 MB")


def submit_kyc(
    user_id: int, full_name: str, cpf: str, rg: str, birth_date: str,
    document_front: tuple[bytes, str], document_back: tuple[bytes, str], selfie: tuple[bytes, str],
) -> dict:
    """Registra uma nova submissao de KYC pendente de revisao manual.
    `document_front`/`document_back`/`selfie` sao tuplas (bytes, content_type).
    Levanta 400 se CPF for matematicamente invalido ou ja usado por OUTRA conta
    (evita duas contas reivindicarem a mesma identidade)."""
    user = storage.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Conta nao encontrada")
    if not full_name or len(full_name.strip()) < 3:
        raise HTTPException(status_code=400, detail="Nome completo invalido")
    if not _is_valid_cpf(cpf):
        raise HTTPException(status_code=400, detail="CPF invalido")
    rg_digits = "".join(ch for ch in rg if ch.isalnum())
    if len(rg_digits) < 5:
        raise HTTPException(status_code=400, detail="RG invalido")

    cpf_hash = _hash_cpf(cpf)
    if storage.cpf_hash_in_use(cpf_hash, exclude_user_id=user_id):
        raise HTTPException(status_code=409, detail="Este CPF ja esta vinculado a outra conta")

    front_bytes, front_ct = document_front
    back_bytes, back_ct = document_back
    selfie_bytes, selfie_ct = selfie
    _validate_document_upload(front_ct, front_bytes, "Documento (frente)")
    _validate_document_upload(back_ct, back_bytes, "Documento (verso)")
    _validate_document_upload(selfie_ct, selfie_bytes, "Selfie")

    front_file = _save_encrypted_document(front_bytes)
    back_file = _save_encrypted_document(back_bytes)
    selfie_file = _save_encrypted_document(selfie_bytes)

    submission_id = storage.create_kyc_submission(
        user_id=user_id,
        full_name_enc=_encrypt_text(full_name.strip()),
        cpf_enc=_encrypt_text(cpf),
        rg_enc=_encrypt_text(rg),
        birth_date_enc=_encrypt_text(birth_date),
        document_front_file=front_file,
        document_back_file=back_file,
        selfie_file=selfie_file,
    )
    storage.set_user_cpf_hash(user_id, cpf_hash)
    storage.set_user_kyc_status(user_id, "pending", user["kyc_tier"])
    return {"submission_id": submission_id, "status": "pending"}


def my_kyc_submissions(user_id: int) -> list[dict]:
    return [
        {
            "id": s["id"], "status": s["status"], "submitted_at": s["submitted_at"],
            "reviewed_at": s["reviewed_at"], "rejection_reason": s["rejection_reason"],
        }
        for s in storage.list_kyc_submissions_for_user(user_id)
    ]


# ---------------------------------------------------------------------------
# Revisao administrativa (operador do painel decifra e aprova/rejeita)
# ---------------------------------------------------------------------------

def admin_list_kyc_submissions(status: Optional[str] = None) -> list[dict]:
    out = []
    for s in storage.list_kyc_submissions(status=status):
        user = storage.get_user_by_id(s["user_id"])
        out.append({
            "id": s["id"], "user_id": s["user_id"],
            "username": user["username"] if user else "?",
            "email": user["email"] if user else "?",
            "status": s["status"], "submitted_at": s["submitted_at"],
            "reviewed_by": s["reviewed_by"], "reviewed_at": s["reviewed_at"],
            "rejection_reason": s["rejection_reason"],
        })
    return out


def admin_get_kyc_submission_detail(submission_id: int) -> dict:
    """Decifra os dados sensiveis e as 3 imagens (retornadas como data-URI
    base64) para o operador revisar visualmente - so deve ser chamado a
    partir de um endpoint protegido por sessao de administrador."""
    s = storage.get_kyc_submission(submission_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Submissao de KYC nao encontrada")
    user = storage.get_user_by_id(s["user_id"])

    def _load_image(filename: str) -> str:
        path = KYC_DOCUMENTS_DIR / filename
        if not path.exists():
            return ""
        raw = _decrypt_bytes(path.read_bytes())
        return "data:application/octet-stream;base64," + base64.b64encode(raw).decode("ascii")

    return {
        "id": s["id"], "user_id": s["user_id"],
        "username": user["username"] if user else "?",
        "email": user["email"] if user else "?",
        "full_name": _decrypt_text(s["full_name_enc"]),
        "cpf": _decrypt_text(s["cpf_enc"]),
        "rg": _decrypt_text(s["rg_enc"]),
        "birth_date": _decrypt_text(s["birth_date_enc"]),
        "document_front_data_uri": _load_image(s["document_front_file"]),
        "document_back_data_uri": _load_image(s["document_back_file"]),
        "selfie_data_uri": _load_image(s["selfie_file"]),
        "status": s["status"], "submitted_at": s["submitted_at"],
        "reviewed_by": s["reviewed_by"], "reviewed_at": s["reviewed_at"],
        "rejection_reason": s["rejection_reason"],
    }


def admin_approve_kyc(submission_id: int, reviewer: str, tier: int = 2) -> None:
    s = storage.get_kyc_submission(submission_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Submissao de KYC nao encontrada")
    if s["status"] != "pending":
        raise HTTPException(status_code=400, detail="Esta submissao ja foi revisada")
    storage.review_kyc_submission(submission_id, "approved", reviewer)
    storage.set_user_kyc_status(s["user_id"], "approved", tier)

    # Propaga a aprovacao para o motor de conformidade (app/compliance.py),
    # elevando o limite de transacao de TODAS as carteiras vinculadas a esta
    # conta (o KYC e da PESSOA, o limite se aplica a cada endereco que ela
    # controla).
    from . import compliance
    full_name = _decrypt_text(s["full_name_enc"])
    cpf = _decrypt_text(s["cpf_enc"])
    document_hash = hashlib.sha256((s["document_front_file"] + s["document_back_file"]).encode()).hexdigest()
    for w in storage.list_user_wallets(s["user_id"]):
        compliance.compliance_engine.register_kyc(
            w["address"], full_name, cpf, tier=tier, document_hash=document_hash,
        )


def admin_reject_kyc(submission_id: int, reviewer: str, reason: str) -> None:
    s = storage.get_kyc_submission(submission_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Submissao de KYC nao encontrada")
    if s["status"] != "pending":
        raise HTTPException(status_code=400, detail="Esta submissao ja foi revisada")
    storage.review_kyc_submission(submission_id, "rejected", reviewer, reason)
    storage.set_user_kyc_status(s["user_id"], "rejected", 0)
