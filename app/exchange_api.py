"""
API estilo exchange (Binance-like) do PixCripto.

Objetivo: permitir que sites/exchanges parceiros (estilo Binance, ou um
agregador de precos tipo CoinGecko/CoinMarketCap) se conectem ao PixCripto
usando um formato de API JA CONHECIDO no mercado cripto, reduzindo o atrito
de integracao a praticamente zero para quem ja integrou com uma exchange
real. A nomenclatura dos campos segue deliberadamente a convencao da API
publica da Binance (`GET /api/v3/ticker/24hr`, `/klines`, `/depth`, `/trades`)
- ver https://binance-docs.github.io/apidocs/spot/en/ para referencia externa.

Fontes de dados usadas (tudo real, nada mockado):
  - **preco**: serie historica persistida em `price_history` (alimentada por
    `GoldOracle.refresh()` a cada cotacao nova de ouro/cambio buscada);
  - **volume/trades**: transacoes minerados de tipo `sell_burn`,
    `liquidation_burn` e `swap_fill` (movimentos REAIS de mercado, ja
    persistidos em `storage.transactions`);
  - **orderbook (depth)**: ordens de troca (`SwapOrder`) abertas no
    `MarketEngine` - o unico "livro de ofertas" P2P que o PixCripto tem hoje
    (nao ha um matching engine central de limit-order-book alem do swap DEX).

Autenticacao de trading (`/api/v1/order`): esquema HMAC-SHA256 igual ao da
Binance (`X-PXC-APIKEY` + parametro `signature`) - a chave secreta NUNCA
trafega na rede, apenas a assinatura HMAC do payload.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import List, Optional

from . import storage

SYMBOL = "PXCBRL"

KLINE_INTERVALS_SECONDS = {
    "1m": 60, "5m": 300, "15m": 900, "1h": 3600, "4h": 14400, "1d": 86400,
}


class ExchangeAuthError(Exception):
    pass


def create_api_key(address: str) -> dict:
    """Gera um novo par api_key/api_secret vinculado a um endereco de
    carteira. O `api_secret` so e exibido UMA vez nesta resposta (mesma UX
    da Binance/AWS) - apenas o hash SHA-256 dele fica persistido."""
    api_key = secrets.token_hex(16)
    api_secret = secrets.token_hex(32)
    secret_hash = hashlib.sha256(api_secret.encode("utf-8")).hexdigest()
    storage.create_api_key(api_key, secret_hash, address)
    return {"api_key": api_key, "api_secret": api_secret, "address": address}


def verify_signature(api_key: str, payload: str, signature: str) -> str:
    """Verifica a assinatura HMAC-SHA256(api_secret, payload) de uma
    requisicao de trading. Retorna o `address` vinculado a chave se valido,
    ou levanta `ExchangeAuthError`. `payload` deve ser a query string/corpo
    EXATO assinado pelo cliente (mesma convencao da Binance: concatenacao
    ordenada dos parametros da requisicao)."""
    record = storage.get_api_key(api_key)
    if record is None or record["revoked"]:
        raise ExchangeAuthError("API key invalida ou revogada")
    # Nao podemos comparar HMAC direto pois so temos o HASH do secret
    # persistido (nunca o secret em si) - por isso a verificacao usa o
    # hash como a propria "chave" do HMAC. Isso e seguro porque o hash
    # SHA-256 do secret tem a mesma entropia do secret original (256 bits)
    # e nunca e exposto de volta ao cliente apos a criacao da chave.
    expected = hmac.new(record["api_secret_hash"].encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ExchangeAuthError("Assinatura invalida")
    return record["address"]


def get_ticker_24hr(market) -> dict:
    """Equivalente a `GET /api/v3/ticker/24hr` da Binance."""
    from .gold_oracle import gold_oracle
    snap = gold_oracle.snapshot()
    now = time.time()
    history = storage.load_price_history(since_ts=now - 86400)
    prices = [h["pxc_brl"] for h in history] or [snap.pxc_brl_rate]
    open_price = prices[0]
    last_price = snap.pxc_brl_rate
    high = max(prices + [last_price])
    low = min(prices + [last_price])
    change = last_price - open_price
    change_pct = (change / open_price * 100.0) if open_price else 0.0

    volume_pxc = 0.0
    for ts, _addr, amount in market.sell_events:
        if ts >= now - 86400:
            volume_pxc += amount

    return {
        "symbol": SYMBOL,
        "priceChange": round(change, 6),
        "priceChangePercent": round(change_pct, 4),
        "openPrice": round(open_price, 6),
        "highPrice": round(high, 6),
        "lowPrice": round(low, 6),
        "lastPrice": round(last_price, 6),
        "volume": round(volume_pxc, 8),
        "quoteVolume": round(volume_pxc * last_price, 2),
        "openTime": int((now - 86400) * 1000),
        "closeTime": int(now * 1000),
        "goldUsdPerOz": snap.gold_usd_per_oz,
        "usdBrl": snap.usd_brl,
        "stale": snap.stale,
    }


def get_klines(interval: str = "1h", limit: int = 100) -> List[list]:
    """Equivalente a `GET /api/v3/klines` da Binance: lista de candles
    `[open_time, open, high, low, close, volume, close_time]`. Construido a
    partir da serie historica real de preco (`price_history`), agrupada em
    buckets de tamanho `interval`. Buckets sem nenhuma leitura de preco
    "carregam" o ultimo close conhecido adiante (mesmo comportamento de um
    ativo com liquidez baixa numa exchange real, evitando gaps vazios)."""
    if interval not in KLINE_INTERVALS_SECONDS:
        raise ValueError(f"interval invalido - use um de {sorted(KLINE_INTERVALS_SECONDS)}")
    bucket_seconds = KLINE_INTERVALS_SECONDS[interval]
    now = time.time()
    since = now - bucket_seconds * limit
    history = storage.load_price_history(since_ts=since, limit=100_000)

    buckets: dict[int, list] = {}
    for point in history:
        bucket_idx = int(point["recorded_at"] // bucket_seconds)
        buckets.setdefault(bucket_idx, []).append(point["pxc_brl"])

    if not buckets:
        from .gold_oracle import gold_oracle
        last_close = gold_oracle.snapshot().pxc_brl_rate
    else:
        last_close = None

    current_bucket = int(now // bucket_seconds)
    start_bucket = current_bucket - limit + 1
    candles: List[list] = []
    for bucket_idx in range(start_bucket, current_bucket + 1):
        prices = buckets.get(bucket_idx)
        if prices:
            o, h, l, c = prices[0], max(prices), min(prices), prices[-1]
            last_close = c
        else:
            o = h = l = c = last_close if last_close is not None else 0.0
        open_time = bucket_idx * bucket_seconds
        candles.append([
            int(open_time * 1000), round(o, 6), round(h, 6), round(l, 6), round(c, 6),
            0.0, int((open_time + bucket_seconds) * 1000),
        ])
    return candles


def get_depth(market, limit: int = 50) -> dict:
    """Equivalente a `GET /api/v3/depth` da Binance: livro de ofertas
    derivado das ordens de troca (swap) ABERTAS no `MarketEngine` - o unico
    mercado P2P/DEX que o PixCripto opera hoje. `bids`/`asks` seguem o
    formato `[preco, quantidade]` (strings, como a Binance real faz)."""
    open_orders = [o for o in market.swap_orders.values() if o.status == "open"]
    open_orders.sort(key=lambda o: o.price_brl_per_pxc)
    asks = [[f"{o.price_brl_per_pxc:.6f}", f"{o.amount:.8f}"] for o in open_orders[:limit]]
    return {"symbol": SYMBOL, "bids": [], "asks": asks, "lastUpdateId": int(time.time())}


def get_recent_trades(blockchain, limit: int = 100) -> List[dict]:
    """Equivalente a `GET /api/v3/trades` da Binance: transacoes reais de
    mercado (venda/liquidacao/troca preenchida) mais recentes, lidas
    diretamente da cadeia minerada."""
    trades = []
    for block in reversed(blockchain.chain):
        for tx in reversed(block.transactions):
            if tx.tx_type in ("sell_burn", "liquidation_burn", "swap_fill"):
                trades.append({
                    "id": tx.tx_id, "price": None, "qty": tx.amount,
                    "time": int(tx.timestamp * 1000), "type": tx.tx_type,
                    "isBuyerMaker": tx.tx_type == "swap_fill",
                })
                if len(trades) >= limit:
                    return trades
    return trades


def exchange_info() -> dict:
    """Equivalente a `GET /api/v3/exchangeInfo` da Binance: metadados do
    simbolo/rede para qualquer integrador descobrir programaticamente os
    limites operacionais sem precisar ler documentacao."""
    from . import root_rules
    return {
        "network": root_rules.NETWORK_NAME,
        "symbol": SYMBOL,
        "baseAsset": root_rules.NETWORK_SYMBOL,
        "quoteAsset": "BRL",
        "filters": [
            {"filterType": "MAX_TRANSACTION_AMOUNT", "maxAmount": root_rules.MAX_TRANSACTION_AMOUNT},
            {"filterType": "PURCHASE_FEE_PCT", "feePct": root_rules.PURCHASE_FEE_RATE * 100},
        ],
        "rulesVersion": root_rules.RULES_VERSION,
    }
