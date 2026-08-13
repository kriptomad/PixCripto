"""
CMS de paginas estaticas do site (`app/cms.py`).

Complementa o feed de noticias (`app/news.py`, cronologico) com conteudo
institucional FIXO por slug (ex.: "sobre", "termos-de-uso",
"politica-de-privacidade", "faq") - editavel pelo operador via Painel de
Administracao, sem precisar tocar em codigo/deploy para atualizar um texto
legal ou institucional do site.
"""
from __future__ import annotations

import re

from . import storage

_SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
MAX_TITLE_LEN = 200
MAX_BODY_LEN = 200_000


class CmsError(ValueError):
    """Erro de validacao de conteudo de pagina CMS."""


def _validate_slug(slug: str) -> str:
    slug = slug.strip().lower()
    if not slug or not _SLUG_RE.match(slug):
        raise CmsError("Slug invalido - use apenas letras minusculas, numeros e hifens (ex.: 'sobre-nos')")
    return slug


def upsert_page(slug: str, title: str, body: str, published: bool, updated_by: str, menu_order: int = 0, show_in_menu: bool = False) -> dict:
    slug = _validate_slug(slug)
    title = title.strip()
    if not title:
        raise CmsError("Titulo nao pode ser vazio")
    if len(title) > MAX_TITLE_LEN:
        raise CmsError(f"Titulo excede {MAX_TITLE_LEN} caracteres")
    if len(body) > MAX_BODY_LEN:
        raise CmsError(f"Corpo excede {MAX_BODY_LEN} caracteres")
    return storage.upsert_cms_page(
        slug, title, body.strip(), published, updated_by.strip() or "PixCripto",
        menu_order=menu_order, show_in_menu=show_in_menu,
    )


def get_page(slug: str, only_published: bool = True) -> dict | None:
    page = storage.get_cms_page(slug.strip().lower())
    if page is None:
        return None
    if only_published and not page["published"]:
        return None
    return page


def list_pages(only_published: bool = False) -> list:
    return storage.list_cms_pages(only_published=only_published)


def delete_page(slug: str) -> bool:
    return storage.delete_cms_page(slug.strip().lower())


def list_revisions(slug: str) -> list:
    return storage.list_cms_page_revisions(slug.strip().lower())


def restore_revision(slug: str, version: int, updated_by: str) -> dict:
    """Reverte (rollback) uma pagina para uma versao anterior do historico
    de revisoes - a propria restauracao gera uma NOVA revisao (a versao atual
    antes do rollback nunca e perdida)."""
    slug = slug.strip().lower()
    revision = storage.get_cms_page_revision(slug, version)
    if revision is None:
        raise CmsError(f"Revisao {version} nao encontrada para '{slug}'")
    current = storage.get_cms_page(slug)
    return storage.upsert_cms_page(
        slug, revision["title"], revision["body"], revision["published"], updated_by.strip() or "PixCripto",
        menu_order=(current["menu_order"] if current else 0),
        show_in_menu=(current["show_in_menu"] if current else False),
    )
