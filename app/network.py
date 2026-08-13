"""
Rede P2P (Peer-to-Peer) real, via asyncio - secao 7 do guia "blockchain-do-zero.md".

Sem este modulo, o PixCripto seria apenas um servidor HTTP de no unico: qualquer
promessa de "100% descentralizado" seria falsa. Este modulo implementa:

  1) Handshake (7.2): troca de `network_id` (chain_id), hash do bloco genesis e
     melhor altura conhecida - peers incompativeis sao desconectados na hora.
  2) Gossip (7.3): toda tx/bloco novo e validado e retransmitido para todos os
     peers, exceto quem enviou, com cache de "ja visto" para nao propagar em loop.
  3) Descobrimento de peers (7.1): troca de listas de peers conhecidos via PEX
     (Peer Exchange) - mensagens `getaddr`/`addr`, compativel com o protocolo
     Bitcoin. Peers descobertos por DNS seed, PEX ou conexao manual sao rastreados
     com o campo `discovered_via` em `PeerInfo`.
  4) Sincronizacao inicial / IBD (7.4): ao conectar, cada lado troca a melhor
     altura conhecida; quem estiver atras pede a cadeia completa do outro.
  5) Escolha de cadeia por trabalho acumulado (1.3/8.3): ao receber uma cadeia
     concorrente (via IBD ou um bloco que nao encaixa na cadeia local), decide
     por `Blockchain.try_replace_chain` (nunca "mais blocos", sempre mais
     trabalho acumulado).
  6) Mitigacoes basicas de rede (7.5): banimento de peers que enviam dados
     invalidos repetidamente, limite de peers por sub-rede /24 (anti-eclipse
     superficial), timestamp de bloco fora da janela e rejeitado (ja aplicado
     em `Blockchain.is_chain_valid`/`submit_mined_block`).

Protocolo de mensagens: uma linha de JSON por mensagem, terminada em "\\n"
(newline-delimited JSON) sobre TCP puro - simples de debugar manualmente
(ex: `nc host porta`), como o proprio guia sugere como alternativa ao msgpack.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

from . import root_rules
from .models import Block, Blockchain, Transaction

logger = logging.getLogger("pixcripto.network")

MAX_MESSAGE_BYTES = 8 * 1024 * 1024   # 8MB - teto de tamanho de mensagem (anti-DoS)
SEEN_CACHE_TTL_SECONDS = 600           # tempo que um tx_id/block_hash "visto" e lembrado
MAX_PEERS = 25
MAX_PEERS_PER_SUBNET = 3               # anti-eclipse superficial: limite de peers por /24
PING_INTERVAL_SECONDS = 30
PEER_BAN_THRESHOLD = 5                 # mensagens invalidas antes de banir um peer
IBD_BATCH_SIZE = 500

# Limite de enderecos por mensagem `addr` (PEX): protege contra um peer malicioso
# inundando a lista local com milhares de enderecos falsos numa unica mensagem.
# O Bitcoin Core usa 1000; usamos 100 por ser uma rede menor, mais conservador.
MAX_ADDR_PER_MESSAGE = 100

# Valores de discovered_via usados em PeerInfo - constantes para evitar typos
DISCOVERED_MANUAL   = "manual"
DISCOVERED_DNS_SEED = "dns_seed"
DISCOVERED_PEX      = "pex"
DISCOVERED_INBOUND  = "inbound"


def _get_max_peers() -> int:
    """Le PIXCRIPTO_MAX_PEERS do ambiente em tempo de execucao.
    Lazy para respeitar monkeypatch em testes sem precisar reimportar o modulo."""
    try:
        from .settings import settings
        return settings.max_peers
    except Exception:
        return int(os.environ.get("PIXCRIPTO_MAX_PEERS", "50"))


def _subnet24(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else host


@dataclass
class PeerInfo:
    host: str
    port: int
    client_version: str = ""
    best_height: int = 0
    best_hash: str = ""
    connected_at: float = field(default_factory=time.time)
    invalid_message_count: int = 0
    # Rastreia COMO este peer foi descoberto - essencial para diagnosticar a saude
    # da descoberta automatica em producao (ex: "estou chegando a todos via PEX ou
    # so via peers manuais?") e exposto em GET /network/peers.
    discovered_via: str = DISCOVERED_MANUAL

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"


class Peer:
    """Conexao TCP ativa (inbound ou outbound) com um peer remoto."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 host: str, port: int, discovered_via: str = DISCOVERED_MANUAL):
        self.reader = reader
        self.writer = writer
        self.info = PeerInfo(host=host, port=port, discovered_via=discovered_via)
        self._send_lock = asyncio.Lock()
        self.closed = False

    async def send(self, message: dict) -> None:
        if self.closed:
            return
        try:
            line = (json.dumps(message, sort_keys=True) + "\n").encode("utf-8")
            async with self._send_lock:
                self.writer.write(line)
                await self.writer.drain()
        except (ConnectionError, OSError):
            await self.close()

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.writer.close()
        except Exception:
            pass


class P2PNode:
    """
    No P2P completo: aceita conexoes de entrada, conecta a bootnodes/peers
    configurados, faz handshake, participa do gossip de tx/blocos, serve e
    executa IBD, e aplica a regra de escolha de cadeia por trabalho acumulado.

    Integra-se com uma instancia existente de `Blockchain` via os mesmos
    metodos publicos ja usados pela API HTTP (`add_transaction`,
    `submit_mined_block`, `try_replace_chain`) - a rede P2P e apenas mais um
    "cliente" da blockchain, exatamente como a API HTTP e; nenhuma logica de
    consenso e duplicada aqui.
    """

    def __init__(self, blockchain: Blockchain, host: str = "0.0.0.0", port: int = 9333,
                 client_version: str = "pixcripto-node/0.5.0",
                 on_chain_replaced: Optional[Callable[[List[Block]], None]] = None,
                 on_block_applied: Optional[Callable[[Block], None]] = None):
        self.blockchain = blockchain
        self.host = host
        self.port = port
        self.client_version = client_version
        self.on_chain_replaced = on_chain_replaced
        # chamado quando um UNICO bloco novo (nao um reorg inteiro) e recebido
        # de um peer e aceito na ponta da cadeia local - permite que a camada
        # HTTP (api.py) persista este bloco no SQLite e notifique clientes
        # WebSocket, exatamente como ja faz para blocos minerados localmente
        # (sem isto, um bloco recebido via P2P nunca era gravado em disco -
        # gap de persistencia encontrado ao implementar o WebSocket de eventos).
        self.on_block_applied = on_block_applied

        self.peers: Dict[str, Peer] = {}          # "host:port" -> Peer
        self._banned_hosts: Set[str] = set()
        self._seen_tx: Dict[str, float] = {}       # tx_id -> timestamp visto
        self._seen_blocks: Dict[str, float] = {}   # block_hash -> timestamp visto
        self._server: Optional[asyncio.base_events.Server] = None
        self._tasks: List[asyncio.Task] = []
        self._syncing = False

    # -- genesis / identidade da rede ---------------------------------------
    @property
    def genesis_hash(self) -> str:
        return self.blockchain.chain[0].hash

    # -- ciclo de vida --------------------------------------------------------
    async def start(self, bootstrap_peers: Optional[List[str]] = None,
                    dns_seed_peers: Optional[List[str]] = None) -> None:
        """Sobe o servidor TCP e dispara conexoes de bootstrap.

        `bootstrap_peers`: peers manuais (PIXCRIPTO_P2P_PEERS ou POST /network/connect).
        `dns_seed_peers`:  peers resolvidos via DNS seed - rastreados separadamente
                           para que o campo `discovered_via` seja correto desde o
                           inicio (evita classificar DNS seeds como "manual").
        """
        self._server = await asyncio.start_server(self._handle_inbound, self.host, self.port)
        logger.info("P2P escutando em %s:%s", self.host, self.port)
        self._tasks.append(asyncio.create_task(self._maintenance_loop()))
        for addr in (bootstrap_peers or []):
            host, _, port_s = addr.partition(":")
            if host and port_s.isdigit():
                self._tasks.append(asyncio.create_task(
                    self.connect_to_peer(host, int(port_s), discovered_via=DISCOVERED_MANUAL)
                ))
        for addr in (dns_seed_peers or []):
            host, _, port_s = addr.partition(":")
            if host and port_s.isdigit():
                self._tasks.append(asyncio.create_task(
                    self.connect_to_peer(host, int(port_s), discovered_via=DISCOVERED_DNS_SEED)
                ))

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for peer in list(self.peers.values()):
            await peer.close()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _maintenance_loop(self) -> None:
        """Ping periodico aos peers + limpeza dos caches de 'ja visto' (evita
        crescimento ilimitado de memoria num node de longa duracao)."""
        try:
            while True:
                await asyncio.sleep(PING_INTERVAL_SECONDS)
                now = time.time()
                self._seen_tx = {k: v for k, v in self._seen_tx.items() if now - v < SEEN_CACHE_TTL_SECONDS}
                self._seen_blocks = {k: v for k, v in self._seen_blocks.items() if now - v < SEEN_CACHE_TTL_SECONDS}
                for peer in list(self.peers.values()):
                    await peer.send({"type": "Ping", "timestamp": now})
        except asyncio.CancelledError:
            pass

    # -- conexao de saida -------------------------------------------------------
    async def connect_to_peer(self, host: str, port: int,
                              discovered_via: str = DISCOVERED_MANUAL) -> Optional[Peer]:
        """Tenta estabelecer conexao TCP de saida com host:port.

        `discovered_via` e gravado em PeerInfo para rastreabilidade: "manual"
        (usuario/admin configurou), "dns_seed" (resolvido via DNS), "pex"
        (recebido num `addr` de outro peer). Isto permite ao operador auditar
        de onde vieram os peers conectados via GET /network/peers.

        Proteção contra auto-conexão: recusa conexão se o par host:port coincide
        com a propria porta de escuta do no, evitando que um `addr` mal-formado
        (ou reflexivo) cause loop infinito.
        """
        # anti-auto-conexao: nao disca para si mesmo (host pode ser 0.0.0.0 ou
        # localhost e ainda assim o port bate - comparamos so a porta local)
        if port == self.port and host in ("127.0.0.1", "0.0.0.0", "localhost", self.host):
            return None
        address = f"{host}:{port}"
        max_peers = _get_max_peers()
        if host in self._banned_hosts or address in self.peers or len(self.peers) >= max_peers:
            return None
        if self._count_peers_in_subnet(host) >= MAX_PEERS_PER_SUBNET:
            logger.warning("Recusando %s: limite de peers por sub-rede /24 atingido (anti-eclipse)", address)
            return None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        except (OSError, asyncio.TimeoutError):
            return None
        peer = Peer(reader, writer, host, port, discovered_via=discovered_via)
        self.peers[address] = peer
        self._tasks.append(asyncio.create_task(self._peer_loop(peer)))
        await self._send_handshake(peer)
        return peer

    def _count_peers_in_subnet(self, host: str) -> int:
        subnet = _subnet24(host)
        return sum(1 for p in self.peers.values() if _subnet24(p.info.host) == subnet)

    # -- conexao de entrada -------------------------------------------------------
    async def _handle_inbound(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peername = writer.get_extra_info("peername")
        host = peername[0] if peername else "unknown"
        if host in self._banned_hosts:
            writer.close()
            return
        max_peers = _get_max_peers()
        if self._count_peers_in_subnet(host) >= MAX_PEERS_PER_SUBNET or len(self.peers) >= max_peers:
            writer.close()
            return
        # porta de escuta real do peer so e conhecida apos o handshake (a porta da
        # conexao TCP de entrada e efemera, nao a porta P2P do outro lado)
        temp_key = f"{host}:{peername[1] if peername else 0}"
        # conexoes de entrada sao marcadas como "inbound" - o campo discovered_via
        # sera atualizado para "pex" se este peer foi originalmente referenciado via
        # addr (mas nao ha como saber isso aqui, entao "inbound" e o valor correto)
        peer = Peer(reader, writer, host, peername[1] if peername else 0,
                    discovered_via=DISCOVERED_INBOUND)
        self.peers[temp_key] = peer
        await self._peer_loop(peer, temp_key=temp_key)

    # -- handshake --------------------------------------------------------------
    async def _send_handshake(self, peer: Peer) -> None:
        await peer.send({
            "type": "Handshake",
            "network_id": root_rules.NETWORK_ID,
            "genesis_hash": self.genesis_hash,
            "best_height": self.blockchain.mined_block_count,
            "best_hash": self.blockchain.last_block.hash,
            "client_version": self.client_version,
            "listen_port": self.port,
        })

    # -- loop de leitura por peer -------------------------------------------------
    async def _peer_loop(self, peer: Peer, temp_key: Optional[str] = None) -> None:
        address_key = temp_key or peer.info.address
        try:
            while True:
                line = await asyncio.wait_for(peer.reader.readline(), timeout=120)
                if not line:
                    break
                if len(line) > MAX_MESSAGE_BYTES:
                    await self._penalize(peer)
                    continue
                try:
                    msg = json.loads(line.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    await self._penalize(peer)
                    continue
                await self._dispatch(peer, msg)
                if peer.info.invalid_message_count >= PEER_BAN_THRESHOLD:
                    self._banned_hosts.add(peer.info.host)
                    break
        except (asyncio.TimeoutError, ConnectionError, OSError, asyncio.CancelledError):
            pass
        finally:
            self.peers.pop(address_key, None)
            # se o handshake renomeou a chave (de temp_key para host:listen_port),
            # remove tambem a entrada final
            self.peers.pop(peer.info.address, None)
            await peer.close()

    async def _penalize(self, peer: Peer) -> None:
        peer.info.invalid_message_count += 1
        if peer.info.invalid_message_count >= PEER_BAN_THRESHOLD:
            logger.warning("Banindo peer %s por mensagens invalidas repetidas", peer.info.address)

    # -- roteamento de mensagens --------------------------------------------------
    async def _dispatch(self, peer: Peer, msg: dict) -> None:
        msg_type = msg.get("type")
        handler = {
            "Handshake":      self._on_handshake,
            # PEX: nomes canonicos do protocolo PixCripto (estilo Bitcoin: getaddr/addr)
            "getaddr":        self._on_getaddr,
            "addr":           self._on_addr,
            # Aliases legados mantidos por retrocompatibilidade com nos mais antigos
            "GetPeers":       self._on_getaddr,
            "Peers":          self._on_addr_legacy,
            "NewTransaction": self._on_new_transaction,
            "NewBlock":       self._on_new_block,
            "GetBlocks":      self._on_get_blocks,
            "Blocks":         self._on_blocks,
            "Ping":           self._on_ping,
            "Pong":           self._on_pong,
        }.get(msg_type)
        if handler is None:
            await self._penalize(peer)
            return
        try:
            await handler(peer, msg)
        except Exception:
            logger.exception("Erro processando mensagem %s de %s", msg_type, peer.info.address)
            await self._penalize(peer)

    # -- handlers individuais -------------------------------------------------------
    async def _on_handshake(self, peer: Peer, msg: dict) -> None:
        if msg.get("network_id") != root_rules.NETWORK_ID or msg.get("genesis_hash") != self.genesis_hash:
            logger.warning("Peer %s incompativel (network_id/genesis divergente) - desconectando", peer.info.address)
            await peer.close()
            return
        old_key = peer.info.address
        listen_port = msg.get("listen_port")
        if isinstance(listen_port, int) and listen_port > 0:
            peer.info.port = listen_port
        peer.info.client_version = str(msg.get("client_version", ""))
        peer.info.best_height = int(msg.get("best_height", 0))
        peer.info.best_hash = str(msg.get("best_hash", ""))
        new_key = peer.info.address
        if new_key != old_key:
            self.peers.pop(old_key, None)
            self.peers[new_key] = peer
        # handshake reciproco: se o outro lado ainda nao recebeu o nosso, envia agora
        await self._send_handshake(peer)
        # PEX: pede a lista de peers conhecidos logo apos o handshake,
        # usando o nome canonico `getaddr` (Bitcoin-style)
        await peer.send({"type": "getaddr"})
        if peer.info.best_height > self.blockchain.mined_block_count:
            await self._request_sync(peer)

    async def _on_getaddr(self, peer: Peer, msg: dict) -> None:
        """Responde a um `getaddr` com a lista de peers conectados (exceto o solicitante).
        Usa o nome canonico `addr` na resposta - o formato `{host, port, discovered_via}`
        permite que o receptor saiba de onde cada peer foi originalmente obtido."""
        known = [
            {
                "host": p.info.host,
                "port": p.info.port,
                "discovered_via": p.info.discovered_via,
            }
            for p in self.peers.values()
            if p is not peer and p.info.port
        ]
        # Trunca a lista na resposta para nao exceder MAX_ADDR_PER_MESSAGE - nao
        # queremos ser fonte de amplificacao mesmo que a nossa lista local seja grande
        await peer.send({"type": "addr", "addrs": known[:MAX_ADDR_PER_MESSAGE]})

    async def _on_addr(self, peer: Peer, msg: dict) -> None:
        """Processa uma mensagem `addr` recebida de um peer (resposta ao nosso `getaddr`
        ou propagacao espontanea). Tenta conectar a peers ainda desconhecidos,
        respeitando max_peers e o limite anti-flood de MAX_ADDR_PER_MESSAGE entradas.

        Seguranca: um peer malicioso poderia enviar addr com milhares de IPs falsos
        para saturar a lista ou forcar conexoes inustaveis; o truncamento aqui garante
        que mensagens acima do limite sejam processadas apenas parcialmente (nao rejeitadas
        totalmente, para nao penalizar peers honestos que por algum bug enviaram demais).
        """
        addrs = msg.get("addrs", [])
        if not isinstance(addrs, list):
            await self._penalize(peer)
            return
        max_peers = _get_max_peers()
        for entry in addrs[:MAX_ADDR_PER_MESSAGE]:
            if not isinstance(entry, dict):
                continue
            host = entry.get("host")
            port = entry.get("port")
            if not isinstance(host, str) or not isinstance(port, int):
                continue
            address = f"{host}:{port}"
            if address not in self.peers and len(self.peers) < max_peers:
                # peers recebidos via addr sao marcados como "pex" - rastreabilidade
                asyncio.create_task(self.connect_to_peer(host, port, discovered_via=DISCOVERED_PEX))

    async def _on_addr_legacy(self, peer: Peer, msg: dict) -> None:
        """Handler legado para mensagens `Peers` (formato antigo: lista de {host, port}).
        Converte para o formato novo e delega ao handler canonico `_on_addr`, garantindo
        retrocompatibilidade com versoes anteriores do no que ainda usam `GetPeers`/`Peers`."""
        peers_list = msg.get("peers", [])
        if not isinstance(peers_list, list):
            return
        # Traduz do formato legado {host, port} para o novo {host, port, discovered_via}
        converted = [
            {"host": e.get("host"), "port": e.get("port"), "discovered_via": DISCOVERED_PEX}
            for e in peers_list[:MAX_ADDR_PER_MESSAGE]
            if isinstance(e, dict)
        ]
        await self._on_addr(peer, {"addrs": converted})

    async def _on_new_transaction(self, peer: Peer, msg: dict) -> None:
        try:
            tx = Transaction.from_dict(msg["tx"])
        except (KeyError, TypeError):
            await self._penalize(peer)
            return
        if tx.tx_id in self._seen_tx:
            return
        self._seen_tx[tx.tx_id] = time.time()
        if self.blockchain.add_transaction(tx):
            await self.broadcast_transaction(tx, exclude=peer)
        else:
            # tx invalida nao necessariamente e culpa do peer imediato (pode ja
            # estar minerada/expirada) - so penaliza se a assinatura em si e invalida
            if not tx.is_valid():
                await self._penalize(peer)

    async def _on_new_block(self, peer: Peer, msg: dict) -> None:
        try:
            block = Block.from_dict(msg["block"])
        except (KeyError, TypeError, ValueError):
            await self._penalize(peer)
            return
        if block.hash in self._seen_blocks:
            return
        self._seen_blocks[block.hash] = time.time()
        if block.previous_hash == self.blockchain.last_block.hash:
            accepted = self.blockchain.submit_mined_block(block, block.nonce, block.hash)
            if accepted:
                await self.broadcast_block(block, exclude=peer)
                if self.on_block_applied:
                    self.on_block_applied(block)
                return
        # nao encaixa na ponta da cadeia local - pode ser um fork mais forte;
        # pede a cadeia completa do peer para comparar trabalho acumulado (reorg)
        await self._request_sync(peer)

    async def _on_get_blocks(self, peer: Peer, msg: dict) -> None:
        from_height = int(msg.get("from_height", 0))
        blocks = self.blockchain.chain[from_height:from_height + IBD_BATCH_SIZE]
        await peer.send({
            "type": "Blocks",
            "blocks": [b.to_dict() for b in blocks],
            "total_height": self.blockchain.mined_block_count,
        })

    async def _on_blocks(self, peer: Peer, msg: dict) -> None:
        try:
            candidate = [Block.from_dict(b) for b in msg.get("blocks", [])]
        except (KeyError, TypeError, ValueError):
            await self._penalize(peer)
            return
        if not candidate:
            return
        replaced = self.blockchain.try_replace_chain(candidate)
        if replaced:
            reorg_depth = max(0, len(candidate) - 1)
            try:
                from . import monitoring as _monitoring
                _monitoring.send_alert(
                    event_type="blockchain_reorg",
                    severity="warning",
                    message=(
                        f"Reorg de blockchain: cadeia local substituida por {len(candidate)} blocos "
                        f"recebidos de {peer.info.address}"
                    ),
                    details={
                        "new_chain_length": len(candidate),
                        "reorg_depth": reorg_depth,
                        "peer": peer.info.address,
                        "new_tip_hash": candidate[-1].hash if candidate else "",
                    },
                )
            except Exception:
                pass
            logger.info("Reorg aplicado: cadeia local substituida por %s blocos vindos de %s",
                        len(candidate), peer.info.address)
            if self.on_chain_replaced:
                self.on_chain_replaced(candidate)
            await self.broadcast_block(self.blockchain.last_block, exclude=peer)

    async def _on_ping(self, peer: Peer, msg: dict) -> None:
        await peer.send({"type": "Pong", "timestamp": msg.get("timestamp")})

    async def _on_pong(self, peer: Peer, msg: dict) -> None:
        pass  # apenas mantem a conexao viva; sem acao adicional necessaria

    # -- sincronizacao inicial / IBD ----------------------------------------------
    async def _request_sync(self, peer: Peer) -> None:
        await peer.send({"type": "GetBlocks", "from_height": 0})

    # -- broadcast (gossip) ---------------------------------------------------------
    async def broadcast_transaction(self, tx: Transaction, exclude: Optional[Peer] = None) -> None:
        self._seen_tx[tx.tx_id] = time.time()
        message = {"type": "NewTransaction", "tx": tx.to_dict()}
        for peer in list(self.peers.values()):
            if peer is not exclude:
                await peer.send(message)

    async def broadcast_block(self, block: Block, exclude: Optional[Peer] = None) -> None:
        self._seen_blocks[block.hash] = time.time()
        message = {"type": "NewBlock", "block": block.to_dict()}
        for peer in list(self.peers.values()):
            if peer is not exclude:
                await peer.send(message)

    # -- introspeccao (para expor via HTTP /network/*) ----------------------------
    def status(self) -> dict:
        return {
            "listen_host": self.host,
            "listen_port": self.port,
            "client_version": self.client_version,
            "peer_count": len(self.peers),
            "peers": [
                {
                    "address": p.info.address,
                    "client_version": p.info.client_version,
                    "best_height": p.info.best_height,
                    "connected_since": p.info.connected_at,
                    "discovered_via": p.info.discovered_via,
                }
                for p in self.peers.values()
            ],
            "banned_hosts": sorted(self._banned_hosts),
        }

    def peers_detail(self) -> list:
        """Lista detalhada de peers para GET /network/peers - inclui discovered_via
        e informacoes completas de cada peer conectado."""
        return [
            {
                "address": p.info.address,
                "host": p.info.host,
                "port": p.info.port,
                "client_version": p.info.client_version,
                "best_height": p.info.best_height,
                "best_hash": p.info.best_hash,
                "connected_since": p.info.connected_at,
                "discovered_via": p.info.discovered_via,
            }
            for p in self.peers.values()
        ]
