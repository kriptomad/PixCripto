"""
Configuracoes gerais do site, editaveis pelo Painel de Administracao sem
necessidade de novo deploy (nome do site, contato, SEO, redes sociais,
mensagem de manutencao customizada). Torna o site "totalmente gerenciavel"
pelo operador, e nao apenas o conteudo (noticias/paginas), mas a propria
identidade/apresentacao institucional dele.
"""
from __future__ import annotations

import json

from . import storage

DEFAULT_SETTINGS: dict = {
    "site_name": "PixCripto",
    "tagline": "Pagamentos descentralizados, ancorados em ouro",
    "support_email": "suporte@pixcripto.example",
    "contact_phone": "",
    "seo_description": "PixCripto - moeda digital descentralizada com mineracao P2P e ancoragem em ouro.",
    "social_twitter": "",
    "social_instagram": "",
    "social_telegram": "",
    "logo_media_id": None,
    "maintenance_message": "O PixCripto esta em manutencao programada. Voltamos em breve.",
}


def get_all() -> dict:
    """Retorna todas as configuracoes, com fallback para o padrao quando uma
    chave ainda nao foi customizada pelo operador."""
    stored = {row["key"]: json.loads(row["value_json"]) for row in storage.list_site_settings()}
    return {**DEFAULT_SETTINGS, **stored}


def get(key: str):
    if key not in DEFAULT_SETTINGS:
        raise KeyError(f"Configuracao desconhecida: {key}")
    raw = storage.get_site_setting(key)
    if raw is None:
        return DEFAULT_SETTINGS[key]
    return json.loads(raw)


def update(values: dict, updated_by: str) -> dict:
    """Atualiza um subconjunto de chaves conhecidas (ignora chaves
    desconhecidas em vez de falhar - facilita evolucao incremental do
    formulario de configuracoes no front-end)."""
    for key, value in values.items():
        if key not in DEFAULT_SETTINGS:
            continue
        storage.set_site_setting(key, json.dumps(value), updated_by)
    return get_all()
