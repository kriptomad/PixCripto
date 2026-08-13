"""
Feed de noticias do site principal (React) - publicado pelo operador
(protegido por um token de administracao simples, ver `app/settings.py`).

Diferente do Painel de Administracao completo (`admin_panel/`, porta 8600,
nunca distribuido), este modulo cobre apenas o necessario para publicar
conteudo editorial (noticias + imagem de capa) diretamente pela UI do site
principal, sem expor nenhuma configuracao sensivel do node.
"""
from __future__ import annotations

import mimetypes
import re
import secrets
import time
from pathlib import Path
from typing import Optional

from fastapi import HTTPException, UploadFile

from . import storage
from .bruteforce_guard import BruteForceLockedError, guard as bruteforce_guard
from .settings import settings

UPLOADS_DIR = Path(__file__).resolve().parent / "static" / "uploads" / "news"
ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
ALLOWED_IMAGE_MIME_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}
MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5 MiB - suficiente para uma imagem de capa, evita DoS de upload

_SAFE_TITLE_RE = re.compile(r"[^a-zA-Z0-9\-_ ]")


class NewsError(ValueError):
    """Erro de validacao de conteudo de noticia (titulo vazio, imagem invalida etc.)."""


def require_admin_token(token: Optional[str], client_identity: str = "unknown") -> None:
    """
    Verifica o token de administracao de conteudo (`X-Admin-Token`). Se
    `PIXCRIPTO_ADMIN_CONTENT_TOKEN` nao estiver configurado, escrita de
    noticias fica DESABILITADA por padrao (fail-closed) - evita que uma
    instalacao "de fabrica" fique com o feed de noticias publicamente
    editavel por qualquer visitante.

    Protegido por `bruteforce_guard`: tentativas repetidas de adivinhar o
    token a partir do mesmo `client_identity` (IP do requisitante) sofrem
    bloqueio exponencialmente crescente (ver `app/bruteforce_guard.py`) -
    um atacante tentando forca bruta contra o token de administracao fica
    cada vez mais lento a cada tentativa falha.
    """
    if not settings.admin_content_token:
        raise HTTPException(
            status_code=503,
            detail="Publicacao de noticias desabilitada: configure PIXCRIPTO_ADMIN_CONTENT_TOKEN no .env",
        )
    scope = "news_admin_token"
    try:
        bruteforce_guard.check(scope, client_identity)
    except BruteForceLockedError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    if not token or not secrets.compare_digest(token, settings.admin_content_token):
        bruteforce_guard.record_failure(scope, client_identity)
        raise HTTPException(status_code=401, detail="Token de administracao invalido ou ausente")
    bruteforce_guard.record_success(scope, client_identity)


async def save_uploaded_image(upload: UploadFile) -> str:
    """Salva uma imagem enviada (multipart/form-data) em disco com um nome
    de arquivo gerado aleatoriamente (nunca reaproveita o nome original do
    cliente - evita path traversal e colisoes) e devolve a URL publica
    (`/static/uploads/news/<arquivo>`) para uso em `image_url` do post."""
    suffix = Path(upload.filename or "").suffix.lower()
    if suffix not in ALLOWED_IMAGE_EXTENSIONS:
        raise NewsError(f"Extensao de imagem nao permitida: {suffix or '(nenhuma)'}")
    content_type = upload.content_type or mimetypes.guess_type(upload.filename or "")[0]
    if content_type not in ALLOWED_IMAGE_MIME_TYPES:
        raise NewsError(f"Tipo de arquivo nao permitido: {content_type}")

    data = await upload.read()
    if len(data) > MAX_IMAGE_BYTES:
        raise NewsError(f"Imagem excede o tamanho maximo permitido ({MAX_IMAGE_BYTES // (1024*1024)} MiB)")
    if len(data) == 0:
        raise NewsError("Arquivo de imagem vazio")

    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{int(time.time())}_{secrets.token_hex(8)}{suffix}"
    dest = UPLOADS_DIR / filename
    dest.write_bytes(data)
    return f"/static/uploads/news/{filename}"


def create_post(
    title: str, summary: str, body: str, image_url: str, author: str,
    status: str = "published", category: str = "geral", tags: str = "",
    scheduled_at: Optional[float] = None,
) -> dict:
    title = title.strip()
    if not title:
        raise NewsError("Titulo nao pode ser vazio")
    if len(title) > 200:
        raise NewsError("Titulo excede 200 caracteres")
    if status not in ("draft", "scheduled", "published"):
        raise NewsError("Status invalido (use 'draft', 'scheduled' ou 'published')")
    post_id = storage.create_news_post(
        title, summary.strip(), body.strip(), image_url.strip(), author.strip() or "PixCripto",
        status=status, category=category.strip() or "geral", tags=tags.strip(), scheduled_at=scheduled_at,
    )
    return storage.get_news_post(post_id)
