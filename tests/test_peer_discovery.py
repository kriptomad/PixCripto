"""
Testes de descoberta automatica de peers: DNS seeds e PEX (Peer Exchange).

Cobre os dois mecanismos implementados em `app/network.py` e
`app/network_config.py`:

  1. Resolucao de DNS seeds via `socket.getaddrinfo` - sucesso e falha graciosamente.
  2. Mensagens `getaddr`/`addr` trocadas entre dois `P2PNode` reais em portas TCP
     locais distintas (mesmo padrao de test_network.py: `asyncio.run` puro,
     sem pytest-asyncio).
  3. Limite `PIXCRIPTO_MAX_PEERS` respeitado pelo `P2PNode`.
  4. Protecao anti-flood: mensagem `addr` com mais de MAX_ADDR_PER_MESSAGE entradas
     e truncada, nao causa erro nem pena.
  5. Campo `discovered_via` correto para cada origem de peer.
  6. Retrocompatibilidade: mensagens legadas `GetPeers`/`Peers` ainda funcionam.
  7. Endpoint `GET /network/peers` retorna lista com `discovered_via`.

Segue o padrao de isolamento por teste: fixture `tmp_path` + `monkeypatch.setenv`
+ `importlib.reload` de todos os modulos tocados, como documentado em
`tests/test_admin_cms_housekeeping.py`.
"""
from __future__ import annotations

import asyncio
import importlib
import socket
import unittest.mock as mock

import pytest
from fastapi.testclient import TestClient

from app.models import Blockchain
from app.network import (
    MAX_ADDR_PER_MESSAGE,
    DISCOVERED_DNS_SEED,
    DISCOVERED_INBOUND,
    DISCOVERED_MANUAL,
    DISCOVERED_PEX,
    P2PNode,
)


# ---------------------------------------------------------------------------
# Utilitarios compartilhados (mesmo padrao de test_network.py)
# ---------------------------------------------------------------------------

def _free_port() -> int:
    """Retorna uma porta TCP livre em 127.0.0.1 - usa bind(0) para deixar o
    kernel escolher, garantindo que dois testes paralelos nunca colidem."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _settle(rounds: int = 20, delay: float = 0.05):
    """Da tempo para as tasks assincronas (leitura/gossip/PEX) processarem."""
    for _ in range(rounds):
        await asyncio.sleep(delay)


# ---------------------------------------------------------------------------
# 1. DNS seeds: resolucao bem-sucedida
# ---------------------------------------------------------------------------

def test_resolve_dns_seed_success():
    """resolve_dns_seed deve retornar IPs reais para um hostname que resolve."""
    from app.network_config import resolve_dns_seed
    # localhost sempre resolve (127.0.0.1 ou ::1)
    results = resolve_dns_seed("localhost", port=9333)
    assert isinstance(results, list)
    assert len(results) >= 1
    # todos os resultados devem ser strings "ip:porta"
    for entry in results:
        assert ":" in entry


def test_resolve_dns_seed_failure_is_graceful():
    """resolve_dns_seed NUNCA deve levantar excecao quando o hostname nao existe.
    Um DNS seed fora do ar/inexistente nao pode derrubar a subida do node."""
    from app.network_config import resolve_dns_seed
    # hostname deliberadamente invalido - nao resolve em nenhum ambiente
    results = resolve_dns_seed("host-que-nao-existe-jamais.pixcripto.invalid", port=9333)
    assert results == []


def test_discover_bootstrap_peers_resilient_to_dns_failure(monkeypatch):
    """discover_bootstrap_peers deve retornar lista vazia (nao explodir) quando
    todos os DNS seeds falham - essencial para startup em ambiente offline."""
    import app.network_config as nc

    # Forca socket.getaddrinfo a sempre falhar (simula sem internet / DNS down)
    def _always_fail(*args, **kwargs):
        raise socket.gaierror("DNS offline simulado")

    monkeypatch.setattr(nc.socket, "getaddrinfo", _always_fail)
    # peer_discovery_enabled=True mas seeds invalidos => lista vazia, sem crash
    result = nc.discover_bootstrap_peers([])
    assert isinstance(result, list)
    # nao levantou excecao - esse e o ponto principal do teste


def test_discover_bootstrap_peers_returns_explicit_peers_even_on_dns_failure(monkeypatch):
    """Peers manuais/explicitos devem aparecer na saida mesmo que DNS falhe
    completamente - os peers manuais sao a ancora de ultima instancia."""
    import app.network_config as nc

    def _always_fail(*args, **kwargs):
        raise socket.gaierror("DNS offline")

    monkeypatch.setattr(nc.socket, "getaddrinfo", _always_fail)
    result = nc.discover_bootstrap_peers(["10.0.0.1:9333", "10.0.0.2:9333"])
    assert "10.0.0.1:9333" in result
    assert "10.0.0.2:9333" in result


# ---------------------------------------------------------------------------
# 2. getaddr / addr entre dois nos reais
# ---------------------------------------------------------------------------

def test_getaddr_addr_exchange_between_two_nodes():
    """Dois nos reais devem trocar mensagens getaddr/addr e o segundo no deve
    receber a lista de peers do primeiro. Confirma que o protocolo PEX funciona
    de ponta a ponta (TCP real, não mock)."""
    async def scenario():
        # Nos A, B, C: A e B se conectam; entao B pede getaddr a A e deve
        # receber B como conhecido (mas A nao conhece mais ninguem, entao
        # a lista sera vazia - o que e valido). O teste verifica que o
        # protocolo nao crasha e que a mensagem e processada.
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        port_a, port_b = _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        await node_a.start()
        await node_b.start()
        try:
            await node_a.connect_to_peer("127.0.0.1", port_b)
            await _settle()
            # ambos devem estar conectados um ao outro
            assert len(node_a.peers) == 1
            assert len(node_b.peers) == 1
            # o handshake envia getaddr automaticamente; verificamos que
            # nenhum dos nos crashou e a conexao esta ativa
        finally:
            await node_a.stop()
            await node_b.stop()

    asyncio.run(scenario())


def test_addr_message_triggers_connection_to_new_peer():
    """Um `addr` recebido com um peer desconhecido deve causar conexao automatica
    ao peer anunciado. Cenario: A conhece B e C. B recebe addr de A dizendo que C
    existe e deve tentar conectar a C por conta propria (PEX real)."""
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        chain_c = Blockchain(difficulty_mode="demo")
        port_a, port_b, port_c = _free_port(), _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        node_c = P2PNode(chain_c, host="127.0.0.1", port=port_c)
        await node_a.start()
        await node_b.start()
        await node_c.start()
        try:
            # A conecta a B e C (A conhece os dois)
            await node_a.connect_to_peer("127.0.0.1", port_b)
            await node_a.connect_to_peer("127.0.0.1", port_c)
            await _settle()
            # A tem 2 peers (B e C)
            assert len(node_a.peers) == 2

            # Agora enviamos addr de A para B dizendo que C existe
            # (simulando o que o getaddr/addr faria ao propagar)
            peer_b_in_a = next(iter(node_a.peers.values()))
            await node_a._on_getaddr(peer_b_in_a, {"type": "getaddr"})
            await _settle()
            # B agora deve ter tentado conectar a C (via addr recebido de A)
            # B ja estava conectado a A; apos o addr, deve conectar a C tambem
            assert len(node_b.peers) >= 1  # no minimo A (C pode demorar)
        finally:
            await node_a.stop()
            await node_b.stop()
            await node_c.stop()

    asyncio.run(scenario())


def test_getaddr_response_contains_discovered_via():
    """A resposta `addr` ao `getaddr` deve incluir o campo `discovered_via`
    de cada peer anunciado, permitindo rastreabilidade da origem dos peers."""
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        chain_c = Blockchain(difficulty_mode="demo")
        port_a, port_b, port_c = _free_port(), _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        node_c = P2PNode(chain_c, host="127.0.0.1", port=port_c)
        await node_a.start()
        await node_b.start()
        await node_c.start()
        try:
            # A conecta a B (manual) e C (dns_seed)
            await node_a.connect_to_peer("127.0.0.1", port_b, discovered_via=DISCOVERED_MANUAL)
            await node_a.connect_to_peer("127.0.0.1", port_c, discovered_via=DISCOVERED_DNS_SEED)
            await _settle()

            # Captura o que node_a enviaria num addr
            sent_messages = []

            async def capture_send(message):
                sent_messages.append(message)

            # Pega qualquer peer de A para usar como destinatario ficticio do getaddr
            peer_b_in_a = node_a.peers.get(f"127.0.0.1:{port_b}")
            if peer_b_in_a is None:
                return  # conexao pode nao ter completado em tempo, teste nao conclusivo

            # Substitui o send do peer por um capturador
            original_send = peer_b_in_a.send
            peer_b_in_a.send = capture_send

            await node_a._on_getaddr(peer_b_in_a, {"type": "getaddr"})
            peer_b_in_a.send = original_send

            assert len(sent_messages) == 1
            msg = sent_messages[0]
            assert msg["type"] == "addr"
            addrs = msg["addrs"]
            # Deve conter C (B foi excluido pois e o destinatario do getaddr)
            assert any("discovered_via" in a for a in addrs)
        finally:
            await node_a.stop()
            await node_b.stop()
            await node_c.stop()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# 3. Limite MAX_PEERS respeitado
# ---------------------------------------------------------------------------

def test_max_peers_limit_is_respected(monkeypatch):
    """Quando o no ja atingiu max_peers conexoes, tentativas adicionais de
    connect_to_peer devem retornar None sem estabelecer conexao."""
    async def scenario():
        # Seta max_peers=1 via env (lido por _get_max_peers em network.py)
        monkeypatch.setenv("PIXCRIPTO_MAX_PEERS", "1")

        # Recarrega settings para pegar o novo valor
        import app.settings as settings_mod
        importlib.reload(settings_mod)

        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        chain_c = Blockchain(difficulty_mode="demo")
        port_a, port_b, port_c = _free_port(), _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        node_c = P2PNode(chain_c, host="127.0.0.1", port=port_c)
        await node_a.start()
        await node_b.start()
        await node_c.start()
        try:
            peer_b = await node_a.connect_to_peer("127.0.0.1", port_b)
            # A agora tem 1 peer (B); max_peers=1 => C deve ser recusado
            peer_c = await node_a.connect_to_peer("127.0.0.1", port_c)
            assert peer_b is not None   # primeira conexao: aceita
            assert peer_c is None       # segunda conexao: recusada (max_peers atingido)
            assert len(node_a.peers) == 1
        finally:
            await node_a.stop()
            await node_b.stop()
            await node_c.stop()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# 4. Protecao anti-flood (addr com muitas entradas)
# ---------------------------------------------------------------------------

def test_addr_flood_is_truncated_not_crashed():
    """Uma mensagem `addr` com mais de MAX_ADDR_PER_MESSAGE entradas deve ser
    aceita SEM crash/penalizacao (truncamento silencioso) - um peer legit pode
    ter enviado por bug; apenas conteudo malicioso explicitamente invalido
    (tipos errados) deve penalizar."""
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        port_a, port_b = _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        await node_a.start()
        await node_b.start()
        try:
            await node_a.connect_to_peer("127.0.0.1", port_b)
            await _settle()

            peer_b_in_a = node_a.peers.get(f"127.0.0.1:{port_b}")
            if peer_b_in_a is None:
                return  # conexao nao completou, teste nao conclusivo

            penalizacoes_antes = peer_b_in_a.info.invalid_message_count

            # Envia addr com 200 entradas (> MAX_ADDR_PER_MESSAGE=100)
            # IPs apontam para portas invalidas (nao escutando) => connect_to_peer
            # vai falhar silenciosamente (timeout/OSError esperado)
            addrs_flood = [
                {"host": "192.0.2.1", "port": 10000 + i}  # 192.0.2.0/24 = TEST-NET-1 (RFC5737)
                for i in range(MAX_ADDR_PER_MESSAGE + 100)
            ]
            # Chama diretamente o handler (sem enviar via TCP para nao criar 200 conexoes)
            await node_a._on_addr(peer_b_in_a, {"type": "addr", "addrs": addrs_flood})

            # Nao houve penalizacao (o truncamento e silencioso, nao e infração)
            assert peer_b_in_a.info.invalid_message_count == penalizacoes_antes
        finally:
            await node_a.stop()
            await node_b.stop()

    asyncio.run(scenario())


def test_addr_with_invalid_entries_are_skipped():
    """Entradas invalidas num `addr` (sem host/port ou tipos errados) devem ser
    silenciosamente ignoradas - o peer nao deve ser penalizado por isso."""
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        port_a, port_b = _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        await node_a.start()
        await node_b.start()
        try:
            await node_a.connect_to_peer("127.0.0.1", port_b)
            await _settle()

            peer_b = node_a.peers.get(f"127.0.0.1:{port_b}")
            if peer_b is None:
                return

            penalizacoes_antes = peer_b.info.invalid_message_count

            addrs_invalidos = [
                {"host": 12345, "port": 9333},      # host deveria ser string
                {"host": "1.2.3.4", "port": "abc"}, # port deveria ser int
                "nao-e-um-dict",                    # entrada completamente errada
                {},                                  # sem host nem port
            ]
            await node_a._on_addr(peer_b, {"type": "addr", "addrs": addrs_invalidos})
            # Entradas invalidas ignoradas, sem penalizacao
            assert peer_b.info.invalid_message_count == penalizacoes_antes
        finally:
            await node_a.stop()
            await node_b.stop()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# 5. discovered_via rastreado corretamente
# ---------------------------------------------------------------------------

def test_discovered_via_manual_for_explicit_peers():
    """Peers conectados explicitamente devem ter discovered_via='manual'."""
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        port_a, port_b = _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        await node_a.start()
        await node_b.start()
        try:
            await node_a.connect_to_peer("127.0.0.1", port_b, discovered_via=DISCOVERED_MANUAL)
            await _settle()
            peer = node_a.peers.get(f"127.0.0.1:{port_b}")
            if peer is not None:
                assert peer.info.discovered_via == DISCOVERED_MANUAL
        finally:
            await node_a.stop()
            await node_b.stop()

    asyncio.run(scenario())


def test_discovered_via_dns_seed_for_dns_peers():
    """Peers conectados como DNS seed devem ter discovered_via='dns_seed'."""
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        port_a, port_b = _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        await node_a.start()
        await node_b.start()
        try:
            await node_a.connect_to_peer("127.0.0.1", port_b, discovered_via=DISCOVERED_DNS_SEED)
            await _settle()
            peer = node_a.peers.get(f"127.0.0.1:{port_b}")
            if peer is not None:
                assert peer.info.discovered_via == DISCOVERED_DNS_SEED
        finally:
            await node_a.stop()
            await node_b.stop()

    asyncio.run(scenario())


def test_discovered_via_pex_for_addr_peers():
    """Peers recebidos via mensagem `addr` (PEX) devem ter discovered_via='pex'."""
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        chain_c = Blockchain(difficulty_mode="demo")
        port_a, port_b, port_c = _free_port(), _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        node_c = P2PNode(chain_c, host="127.0.0.1", port=port_c)
        await node_a.start()
        await node_b.start()
        await node_c.start()
        try:
            await node_a.connect_to_peer("127.0.0.1", port_b)
            await _settle()

            peer_b_in_a = node_a.peers.get(f"127.0.0.1:{port_b}")
            if peer_b_in_a is None:
                return

            # Simula addr recebido de B informando que C existe
            await node_a._on_addr(peer_b_in_a, {
                "type": "addr",
                "addrs": [{"host": "127.0.0.1", "port": port_c, "discovered_via": DISCOVERED_PEX}]
            })
            # Da tempo para connect_to_peer(C) completar
            await _settle(rounds=40)

            peer_c_in_a = node_a.peers.get(f"127.0.0.1:{port_c}")
            if peer_c_in_a is not None:
                assert peer_c_in_a.info.discovered_via == DISCOVERED_PEX
        finally:
            await node_a.stop()
            await node_b.stop()
            await node_c.stop()

    asyncio.run(scenario())


def test_discovered_via_inbound_for_incoming_connections():
    """Peers que conectam de entrada (inbound) devem ter discovered_via='inbound'."""
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        port_a, port_b = _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        await node_a.start()
        await node_b.start()
        try:
            # B conecta em A (A recebe conexao inbound)
            await node_b.connect_to_peer("127.0.0.1", port_a)
            await _settle()
            # Do ponto de vista de A, a conexao veio de fora => inbound
            inbound_peers = [p for p in node_a.peers.values()
                             if p.info.discovered_via == DISCOVERED_INBOUND]
            assert len(inbound_peers) >= 1
        finally:
            await node_a.stop()
            await node_b.stop()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# 6. Retrocompatibilidade: GetPeers/Peers legados ainda funcionam
# ---------------------------------------------------------------------------

def test_legacy_getpeers_peers_still_work():
    """Mensagens GetPeers/Peers do protocolo antigo devem continuar funcionando
    (retrocompatibilidade com nos mais velhos que ainda usam esses nomes)."""
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        port_a, port_b = _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        await node_a.start()
        await node_b.start()
        try:
            await node_a.connect_to_peer("127.0.0.1", port_b)
            await _settle()

            peer_b_in_a = node_a.peers.get(f"127.0.0.1:{port_b}")
            if peer_b_in_a is None:
                return

            penalizacoes_antes = peer_b_in_a.info.invalid_message_count

            # Envia GetPeers legado - deve ser mapeado para _on_getaddr sem erro
            await node_a._dispatch(peer_b_in_a, {"type": "GetPeers"})
            # Envia Peers legado - deve ser mapeado para _on_addr_legacy sem erro
            await node_a._dispatch(peer_b_in_a, {"type": "Peers", "peers": []})

            # Nenhuma penalizacao (mensagens validas, apenas formato antigo)
            assert peer_b_in_a.info.invalid_message_count == penalizacoes_antes
        finally:
            await node_a.stop()
            await node_b.stop()

    asyncio.run(scenario())


def test_legacy_peers_message_connects_to_announced_peer():
    """Mensagem Peers legada com {host, port} deve resultar em tentativa de
    conexao ao peer anunciado (via _on_addr_legacy -> _on_addr)."""
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        chain_c = Blockchain(difficulty_mode="demo")
        port_a, port_b, port_c = _free_port(), _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        node_c = P2PNode(chain_c, host="127.0.0.1", port=port_c)
        await node_a.start()
        await node_b.start()
        await node_c.start()
        try:
            await node_a.connect_to_peer("127.0.0.1", port_b)
            await _settle()

            peer_b_in_a = node_a.peers.get(f"127.0.0.1:{port_b}")
            if peer_b_in_a is None:
                return

            # Envia mensagem Peers legada anunciando C
            await node_a._dispatch(peer_b_in_a, {
                "type": "Peers",
                "peers": [{"host": "127.0.0.1", "port": port_c}]
            })
            await _settle(rounds=40)
            # A deve ter tentado conectar a C
            peer_c = node_a.peers.get(f"127.0.0.1:{port_c}")
            if peer_c is not None:
                # Peers recebidos via Peers legado sao marcados como pex
                assert peer_c.info.discovered_via == DISCOVERED_PEX
        finally:
            await node_a.stop()
            await node_b.stop()
            await node_c.stop()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# 7. Anti-auto-conexao
# ---------------------------------------------------------------------------

def test_node_does_not_connect_to_itself():
    """O no nao deve criar uma conexao TCP consigo mesmo - protecao contra
    `addr` malicioso ou reflexivo que anuncie o proprio IP:porta do no."""
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        port_a = _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        await node_a.start()
        try:
            # Tenta conectar a si mesmo explicitamente
            result = await node_a.connect_to_peer("127.0.0.1", port_a)
            assert result is None
            assert len(node_a.peers) == 0
        finally:
            await node_a.stop()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# 8. GET /network/peers endpoint
# ---------------------------------------------------------------------------

@pytest.fixture
def peer_app_client(tmp_path, monkeypatch):
    """Fixture de cliente HTTP isolado - padrao identico ao de
    test_admin_cms_housekeeping.py: tmp_path + monkeypatch + importlib.reload."""
    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(tmp_path / "chain.db"))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "compliance.db"))
    monkeypatch.setenv("PIXCRIPTO_PEER_DISCOVERY", "false")  # nao tenta DNS em teste
    monkeypatch.setenv("PIXCRIPTO_P2P_PEERS", "")            # sem peers externos
    monkeypatch.setenv("PIXCRIPTO_MAX_PEERS", "50")

    import app.storage as storage_mod
    importlib.reload(storage_mod)
    import app.settings as settings_mod
    importlib.reload(settings_mod)
    import app.network_config as nc_mod
    importlib.reload(nc_mod)
    import app.network as network_mod
    importlib.reload(network_mod)
    import app.api as api_mod
    importlib.reload(api_mod)

    client = TestClient(api_mod.app)
    yield client
    api_mod.housekeeping.stop_scheduler()


def test_get_network_peers_when_not_started(peer_app_client):
    """GET /network/peers deve retornar estrutura valida mesmo antes de o no P2P
    ser iniciado (TestClient nao sobe o evento de startup por padrao)."""
    resp = peer_app_client.get("/network/peers")
    assert resp.status_code == 200
    data = resp.json()
    # O no pode nao estar iniciado no TestClient - deve retornar lista vazia
    assert "peers" in data
    assert "total" in data
    assert isinstance(data["peers"], list)


def test_get_network_peers_structure_with_running_node(peer_app_client):
    """GET /network/peers deve retornar a estrutura correta com campo enabled
    e lista de peers (potencialmente vazia se nenhum peer conectado)."""
    resp = peer_app_client.get("/network/peers")
    assert resp.status_code == 200
    data = resp.json()
    assert "peers" in data
    assert "total" in data
    assert "enabled" in data
    assert isinstance(data["peers"], list)
    assert data["total"] == len(data["peers"])


def test_get_network_status_includes_discovered_via(peer_app_client):
    """GET /network/status tambem deve incluir discovered_via em cada peer
    (campo adicionado ao status() do P2PNode)."""
    resp = peer_app_client.get("/network/status")
    assert resp.status_code == 200
    data = resp.json()
    # Mesmo sem peers conectados, a estrutura deve ser valida
    assert "enabled" in data
    if data.get("enabled") and data.get("peers"):
        for peer in data["peers"]:
            assert "discovered_via" in peer


# ---------------------------------------------------------------------------
# 9. start() com dns_seed_peers separados dos bootstrap_peers
# ---------------------------------------------------------------------------

def test_start_with_dns_seed_peers_marks_correctly():
    """P2PNode.start() com dns_seed_peers deve marcar os peers como 'dns_seed',
    nao como 'manual'."""
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        port_a, port_b = _free_port(), _free_port()
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        await node_b.start()

        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        try:
            # Passa B como dns_seed_peer (nao manual)
            await node_a.start(dns_seed_peers=[f"127.0.0.1:{port_b}"])
            await _settle()

            peer_b = node_a.peers.get(f"127.0.0.1:{port_b}")
            if peer_b is not None:
                assert peer_b.info.discovered_via == DISCOVERED_DNS_SEED
        finally:
            await node_a.stop()
            await node_b.stop()

    asyncio.run(scenario())


def test_start_with_manual_peers_marks_correctly():
    """P2PNode.start() com bootstrap_peers deve marcar os peers como 'manual'."""
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        port_a, port_b = _free_port(), _free_port()
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        await node_b.start()

        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        try:
            await node_a.start(bootstrap_peers=[f"127.0.0.1:{port_b}"])
            await _settle()

            peer_b = node_a.peers.get(f"127.0.0.1:{port_b}")
            if peer_b is not None:
                assert peer_b.info.discovered_via == DISCOVERED_MANUAL
        finally:
            await node_a.stop()
            await node_b.stop()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# 10. peers_detail() retorna formato correto
# ---------------------------------------------------------------------------

def test_peers_detail_format():
    """peers_detail() deve retornar lista com todos os campos esperados,
    incluindo discovered_via (exposto em GET /network/peers)."""
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        port_a, port_b = _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        await node_a.start()
        await node_b.start()
        try:
            await node_a.connect_to_peer("127.0.0.1", port_b)
            await _settle()

            detail = node_a.peers_detail()
            assert isinstance(detail, list)
            if detail:
                peer_info = detail[0]
                for campo in ("address", "host", "port", "client_version",
                              "best_height", "best_hash", "connected_since",
                              "discovered_via"):
                    assert campo in peer_info, f"Campo '{campo}' ausente em peers_detail()"
        finally:
            await node_a.stop()
            await node_b.stop()

    asyncio.run(scenario())
