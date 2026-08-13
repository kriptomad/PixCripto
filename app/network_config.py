"""
Configuracao/descoberta de peers da rede P2P do PixCripto.

Cobre o gap de "Descoberta de peers automatica (DNS seeds/PEX)" listado em
README.md -> "Gaps de producao": antes, a lista de peers iniciais precisava
ser informada manualmente (`PIXCRIPTO_P2P_PEERS`/`POST /network/connect`).
Agora o node tambem tenta resolver uma lista de **DNS seeds** (mesma ideia dos
`chainparams.cpp` do Bitcoin Core: `seed.bitcoin.sipa.be` etc.) - cada seed e
um hostname que resolve (via DNS `A`/`AAAA`) para os IPs de varios peers
conhecidos e estaveis da rede, operados pela propria comunidade/fundacao.

Como o PixCripto ainda nao tem uma rede real com DNS seeds hospedados,
este modulo:
  1. resolve de fato os hostnames configurados (funciona com qualquer DNS
     seed real que venha a ser hospedado no futuro - basta apontar
     `PIXCRIPTO_DNS_SEEDS` para ele);
  2. falha graciosamente (log, nao excecao) quando um seed nao resolve -
     essencial para devnet/testnet local onde os seeds de exemplo nao existem;
  3. mantem um `seeds.json` local (cache/allowlist editavel pelo operador,
     inclusive pelo Painel de Administracao) com peers conhecidos "host:porta",
     complementando a resolucao DNS com uma lista fixa curada manualmente
     (Peer Exchange/PEX simplificado).
"""
from __future__ import annotations

import json
import logging
import pathlib
import socket
from dataclasses import dataclass
from typing import List, Set

from .settings import settings, ROOT_DIR

logger = logging.getLogger("pixcripto.network_config")

SEEDS_FILE = ROOT_DIR / "seeds.json"

DEFAULT_PORT = 9333


@dataclass
class NetworkProfile:
    """Perfil de rede: cada ambiente (mainnet/testnet/devnet) pode ter seeds
    e porta P2P padrao proprios, evitando que um no devnet acidentalmente
    tente discar para peers de mainnet (e vice-versa)."""
    name: str
    default_p2p_port: int
    dns_seeds: List[str]


NETWORK_PROFILES = {
    "mainnet": NetworkProfile("mainnet", 9333, ["seed1.pixcripto.example", "seed2.pixcripto.example"]),
    "testnet": NetworkProfile("testnet", 19333, ["testnet-seed1.pixcripto.example"]),
    "devnet": NetworkProfile("devnet", 29333, []),
}


def current_profile() -> NetworkProfile:
    return NETWORK_PROFILES.get(settings.environment, NETWORK_PROFILES["devnet"])


def resolve_dns_seed(hostname: str, port: int = DEFAULT_PORT) -> List[str]:
    """Resolve um unico hostname de DNS seed para uma lista de `ip:porta`.
    Retorna lista vazia (nunca levanta excecao) se o hostname nao resolver -
    um seed fora do ar/inexistente nao pode derrubar a subida do node."""
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError) as exc:
        logger.info("DNS seed '%s' nao resolveu (%s) - ignorando.", hostname, exc)
        return []
    peers: Set[str] = set()
    for family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        peers.add(f"{ip}:{port}")
    return sorted(peers)


def load_curated_seeds() -> List[str]:
    """Le `seeds.json` (lista curada de peers `host:porta`, editavel pelo
    operador/Painel de Administracao). Formato: `{"peers": ["1.2.3.4:9333"]}`.
    Ausente/corrompido => lista vazia (nao bloqueia a subida do node)."""
    if not SEEDS_FILE.exists():
        return []
    try:
        data = json.loads(SEEDS_FILE.read_text(encoding="utf-8"))
        return [str(p) for p in data.get("peers", [])]
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("seeds.json invalido (%s) - ignorando.", exc)
        return []


def save_curated_seeds(peers: List[str]) -> None:
    SEEDS_FILE.write_text(json.dumps({"peers": sorted(set(peers))}, indent=2), encoding="utf-8")


def discover_bootstrap_peers(explicit_peers: List[str] | None = None) -> List[str]:
    """Monta a lista final de peers para o bootstrap do `P2PNode` na subida:
    1. peers explicitos (`PIXCRIPTO_P2P_PEERS` / passados pelo chamador) - maior prioridade;
    2. peers curados manualmente (`seeds.json`);
    3. peers descobertos via DNS seeds do perfil de rede ativo (se habilitado).
    A ordem eh so uma preferencia de conexao - o `P2PNode` disca para todos."""
    peers: List[str] = list(explicit_peers or [])
    peers.extend(load_curated_seeds())

    if settings.peer_discovery_enabled:
        profile = current_profile()
        seeds = settings.dns_seeds or profile.dns_seeds
        for hostname in seeds:
            peers.extend(resolve_dns_seed(hostname, profile.default_p2p_port))

    # remove duplicatas preservando ordem de preferencia
    seen: Set[str] = set()
    ordered: List[str] = []
    for p in peers:
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    return ordered
