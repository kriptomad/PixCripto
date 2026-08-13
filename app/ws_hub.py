"""
Hub de WebSocket para eventos em tempo real (secao 7.5 do guia): permite que
carteiras/explorers/dashboards recebam `newBlock` e `pendingTransaction` no
INSTANTE em que acontecem, sem precisar dar polling na API REST. Um unico
WebSocket compartilhado (`/ws/events`) para todos os clientes conectados.
"""
from __future__ import annotations

import logging
from typing import Set

logger = logging.getLogger("pixcripto.ws")


class WebSocketHub:
    def __init__(self):
        self._connections: Set = set()

    async def connect(self, websocket) -> None:
        await websocket.accept()
        self._connections.add(websocket)

    def disconnect(self, websocket) -> None:
        self._connections.discard(websocket)

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def broadcast(self, event: dict) -> None:
        """Envia `event` (dict serializavel em JSON) para TODOS os clientes
        conectados; remove silenciosamente qualquer conexao que falhar
        (cliente ja desconectado, mas ainda nao removido pelo handler)."""
        dead = []
        for ws in list(self._connections):
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.discard(ws)


ws_hub = WebSocketHub()
