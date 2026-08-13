"""
Chaves de funcionalidade (feature flags) do site - ligam/desligam MODULOS
INTEIROS do sistema em tempo de execucao, sem precisar de novo deploy.

Usadas pelo Painel de Administracao para o operador conseguir, por exemplo,
colocar o site inteiro em "modo manutencao" (bloqueando toda a API publica
menos o proprio painel) durante uma atualizacao, ou desativar temporariamente
compras/trading/mineracao em caso de incidente de seguranca, sem precisar
reiniciar o processo nem editar codigo.

O estado fica persistido em SQLite (`feature_flags`, ver `app/storage.py`) -
sobrevive a reinicializacoes do processo, diferente de uma variavel de
processo em memoria.
"""
from __future__ import annotations

from typing import Dict

from . import storage

# Todas as chaves reconhecidas pelo sistema e seu valor padrao (usado quando
# a chave ainda nao foi definida explicitamente no banco - primeira execucao).
DEFAULT_FLAGS: Dict[str, bool] = {
    "maintenance_mode": False,
    "purchases_enabled": True,
    "trading_enabled": True,
    "mining_enabled": True,
    "kyc_enforced": True,
    "news_publishing_enabled": True,
    "housekeeping_task_sessions": True,
    "housekeeping_task_bruteforce": True,
    "housekeeping_task_honeypot": True,
    "housekeeping_task_orphaned_media": True,
    "housekeeping_task_price_history": True,
    "housekeeping_task_vacuum": True,
    "housekeeping_task_integrity_check": True,
    "housekeeping_task_backup": True,
}

DESCRIPTIONS: Dict[str, str] = {
    "maintenance_mode": "Bloqueia toda a API publica (exceto o painel de administracao) com HTTP 503.",
    "purchases_enabled": "Permite comprar PXC com Reais (cotacao + confirmacao de pagamento).",
    "trading_enabled": "Permite criar/cancelar ordens de troca (swap) e usar a API estilo exchange.",
    "mining_enabled": "Permite minerar novos blocos (solo ou pool).",
    "kyc_enforced": "Exige verificacao KYC acima do limite configurado (PIXCRIPTO_KYC_THRESHOLD_PXC).",
    "news_publishing_enabled": "Permite publicar/editar/remover noticias no feed do site.",
    "housekeeping_task_sessions": "Housekeeping: remove sessoes de administrador expiradas.",
    "housekeeping_task_bruteforce": "Housekeeping: poda estado antigo do anti-forca-bruta.",
    "housekeeping_task_honeypot": "Housekeeping: poda eventos/desafios antigos do honeypot.",
    "housekeeping_task_orphaned_media": "Housekeeping: remove arquivos de midia orfaos do disco.",
    "housekeeping_task_price_history": "Housekeeping: poda historico de precos alem da retencao configurada.",
    "housekeeping_task_vacuum": "Housekeeping: executa VACUUM do SQLite para recompactar o banco.",
    "housekeeping_task_integrity_check": "Housekeeping: executa PRAGMA integrity_check no banco.",
    "housekeeping_task_backup": "Housekeeping: cria backup compactado (banco + uploads) com rotacao.",
}


def is_enabled(key: str) -> bool:
    value = storage.get_feature_flag(key)
    if value is None:
        return DEFAULT_FLAGS.get(key, True)
    return value


def set_flag(key: str, enabled: bool) -> None:
    if key not in DEFAULT_FLAGS:
        raise ValueError(f"Chave de funcionalidade desconhecida: {key!r}")
    storage.set_feature_flag(key, enabled)


def list_flags() -> list:
    stored = {f["key"]: f for f in storage.list_feature_flags()}
    result = []
    for key, default in DEFAULT_FLAGS.items():
        row = stored.get(key)
        result.append({
            "key": key,
            "enabled": row["enabled"] if row else default,
            "updated_at": row["updated_at"] if row else None,
            "description": DESCRIPTIONS.get(key, ""),
        })
    return result
