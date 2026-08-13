"""
Biblioteca de midia centralizada (`app/media.py`).

Antes, cada modulo que aceitava upload (ex.: `app/news.py`) salvava o arquivo
em disco sem NENHUM inventario central - impossivel para o operador saber
quanto espaco esta sendo usado, quais arquivos existem, ou detectar/limpar
arquivos orfaos (upload feito mas nunca publicado, ou post apagado mas a
imagem ficou no disco para sempre). Este modulo resolve isso: todo upload
feito pelo site e registrado em `media_files` (SQLite) com metadata completa,
e o Painel de Administracao ganha uma tela de "Midia" para listar, auditar
uso de armazenamento por categoria e remover arquivos manualmente. O
`app/housekeeping.py` usa este mesmo inventario para poda automatica de
arquivos orfaos.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import HTTPException

from . import storage

_APP_DIR = Path(__file__).resolve().parent
_STATIC_DIR = _APP_DIR / "static"


def register_upload(filename: str, url: str, purpose: str, size_bytes: int, mime_type: str, uploaded_by: str, alt_text: str = "", tags: str = "", folder: str = "") -> int:
    """Registra um upload ja salvo em disco no inventario central."""
    return storage.register_media_file(filename, url, purpose, size_bytes, mime_type, uploaded_by, alt_text=alt_text, tags=tags, folder=folder)


def update_metadata(media_id: int, alt_text: Optional[str] = None, tags: Optional[str] = None, folder: Optional[str] = None) -> dict:
    entry = storage.get_media_file(media_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Arquivo de midia nao encontrado")
    storage.update_media_metadata(media_id, alt_text=alt_text, tags=tags, folder=folder)
    return storage.get_media_file(media_id)


def list_media(limit: int = 100, offset: int = 0) -> list:
    return storage.list_media_files(limit=limit, offset=offset)


def storage_stats() -> dict:
    return storage.media_storage_stats()


def _url_to_disk_path(url: str) -> Optional[Path]:
    """Converte uma URL publica (`/static/uploads/...`) de volta ao caminho
    em disco, validando que o resultado continua DENTRO de `app/static/`
    (defesa contra path traversal mesmo que a URL registrada tenha sido
    manipulada de alguma forma)."""
    if not url.startswith("/static/"):
        return None
    relative = url[len("/static/"):]
    candidate = (_STATIC_DIR / relative).resolve()
    if not str(candidate).startswith(str(_STATIC_DIR.resolve())):
        return None
    return candidate


def delete_media(media_id: int, force: bool = False) -> dict:
    """
    Remove um arquivo do inventario E do disco. Por padrao (`force=False`),
    RECUSA remover um arquivo que ainda esta referenciado por uma noticia
    publicada (evita o operador quebrar conteudo ao vivo sem querer) - use
    `force=True` (housekeeping automatico ou decisao explicita do operador)
    para ignorar essa protecao.
    """
    entry = storage.get_media_file(media_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Arquivo de midia nao encontrado")

    if not force and entry["url"] in storage.all_referenced_media_urls():
        raise HTTPException(
            status_code=409,
            detail="Arquivo ainda esta em uso por uma noticia publicada - remova a referencia primeiro ou force a exclusao",
        )

    disk_path = _url_to_disk_path(entry["url"])
    removed_from_disk = False
    if disk_path is not None and disk_path.is_file():
        disk_path.unlink()
        removed_from_disk = True

    storage.delete_media_file_row(media_id)
    return {"deleted": True, "removed_from_disk": removed_from_disk, "entry": entry}


def find_orphaned_files(uploads_subdir: str = "uploads") -> list:
    """Varre `app/static/uploads/**` procurando arquivos presentes em disco
    que NAO estao registrados em `media_files` e nao sao referenciados por
    nenhuma noticia publicada - candidatos a limpeza automatica pelo
    housekeeping (uploads incompletos, imagens de posts jamais publicados,
    substituidas em uma edicao etc.)."""
    uploads_dir = _STATIC_DIR / uploads_subdir
    if not uploads_dir.exists():
        return []
    registered_urls = {m["url"] for m in storage.list_media_files(limit=100_000)}
    referenced_urls = storage.all_referenced_media_urls()
    known_urls = registered_urls | referenced_urls

    orphans = []
    for path in uploads_dir.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(_STATIC_DIR)
        url = "/static/" + str(relative).replace("\\", "/")
        if url not in known_urls:
            orphans.append(path)
    return orphans
