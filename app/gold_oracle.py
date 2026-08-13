"""
Oraculo de preco do ouro (XAU) - ancora o valor do PXC em uma reserva de ouro real.

Busca a cotacao do ouro (USD/onca) e a taxa de cambio USD/BRL em APIs publicas,
com cache e fallback para o ultimo valor conhecido caso a rede esteja
indisponivel (o sistema nunca trava por falta de internet, apenas usa o
ultimo preco valido e sinaliza `stale=True`).

O preco do PXC em Reais e derivado matematicamente do preco do ouro, entao
o poder de compra da moeda acompanha o ativo real (ouro) e o cambio (USD/BRL),
protegendo tanto o valor de mercado quanto o valor de investimento do usuario
contra a inflacao pura de uma moeda fiduciaria.
"""
from __future__ import annotations

import json
import math
import time
import urllib.request
from dataclasses import dataclass
from typing import Optional

from . import root_rules

GOLD_PRICE_URL = "https://api.gold-api.com/price/XAU"
USD_BRL_URL = "https://open.er-api.com/v6/latest/USD"

# Lastro: quantas oncas troy de ouro cada 1 PXC representa. Ajustavel por
# governanca do protocolo - valor pequeno para manter o PXC acessivel (nao tao
# escasso quanto o proprio ouro/Bitcoin).
PXC_GOLD_BACKING_OZ = root_rules.PXC_GOLD_BACKING_OZ

FALLBACK_GOLD_USD_PER_OZ = 2400.0   # usado somente se a API estiver fora do ar
FALLBACK_USD_BRL = 5.20
CACHE_TTL_SECONDS = 60

# Faixas de sanidade ABSOLUTAS (protecao contra API comprometida/MITM retornando
# lixo/valores absurdos) - qualquer leitura fora destas faixas e rejeitada
# incondicionalmente, independente do circuit-breaker de variacao percentual.
GOLD_USD_SANITY_MIN, GOLD_USD_SANITY_MAX = 200.0, 50_000.0
USD_BRL_SANITY_MIN, USD_BRL_SANITY_MAX = 1.0, 50.0


@dataclass
class MarketSnapshot:
    gold_usd_per_oz: float
    usd_brl: float
    pxc_brl_rate: float
    delta_pct_gold: float
    stale: bool
    fetched_at: float
    rejected_manipulation_attempt: bool = False


class OracleManipulationError(Exception):
    """Levantado quando uma leitura da API externa e rejeitada por sanidade/circuit-breaker."""


class GoldOracle:
    def __init__(self):
        self._last_gold_usd: Optional[float] = None
        self._last_usd_brl: Optional[float] = None
        self._last_fetch: float = 0.0
        self._history: list[float] = []   # historico de precos do ouro (USD/oz) para calcular delta
        self._stale = True
        self._last_rejected = False

    def _fetch_gold_usd(self) -> float:
        req = urllib.request.Request(GOLD_PRICE_URL, headers={"User-Agent": "PixCripto/1.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read())
            return float(data["price"])

    def _fetch_usd_brl(self) -> float:
        req = urllib.request.Request(USD_BRL_URL, headers={"User-Agent": "PixCripto/1.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read())
            return float(data["rates"]["BRL"])

    def _passes_sanity_and_circuit_breaker(self, gold_usd: float, usd_brl: float) -> bool:
        """
        Defesa contra manipulacao do oraculo (ex.: MITM ou API externa
        comprometida injetando uma cotacao absurda para permitir comprar PXC
        artificialmente barato ou vende-lo artificialmente caro). Duas camadas:
          1) faixa de sanidade absoluta (valores fisicamente plausiveis);
          2) circuit-breaker de variacao maxima por leitura em relacao ao
             ultimo preco CONFIAVEL conhecido (`ORACLE_MAX_DELTA_PCT_PER_FETCH`).
        """
        if not math.isfinite(gold_usd) or not math.isfinite(usd_brl):
            return False
        if not (GOLD_USD_SANITY_MIN <= gold_usd <= GOLD_USD_SANITY_MAX):
            return False
        if not (USD_BRL_SANITY_MIN <= usd_brl <= USD_BRL_SANITY_MAX):
            return False
        if self._last_gold_usd:
            delta_pct = abs((gold_usd - self._last_gold_usd) / self._last_gold_usd) * 100
            if delta_pct > root_rules.ORACLE_MAX_DELTA_PCT_PER_FETCH:
                return False
        return True

    def _persist_price_point(self, gold_usd: float, usd_brl: float) -> None:
        """Grava um ponto na serie historica de preco (SQLite) - alimenta os
        candles (klines) da API estilo exchange (`app/exchange_api.py`).
        Falha silenciosamente (log seria ideal em produção) se a persistencia
        nao estiver disponivel - o oraculo de preco em si NUNCA deve travar
        por causa da serie historica ser so um "extra" analitico."""
        try:
            from . import storage
            pxc_brl = round(PXC_GOLD_BACKING_OZ * gold_usd * usd_brl, 6)
            pxc_usd = round(PXC_GOLD_BACKING_OZ * gold_usd, 6)
            storage.record_price_snapshot(pxc_brl, pxc_usd, gold_usd)
        except Exception:
            pass

    def refresh(self, force: bool = False) -> None:
        if not force and (time.time() - self._last_fetch) < CACHE_TTL_SECONDS and self._last_gold_usd:
            return
        self._last_rejected = False
        try:
            gold_usd = self._fetch_gold_usd()
            usd_brl = self._fetch_usd_brl()
            if not self._passes_sanity_and_circuit_breaker(gold_usd, usd_brl):
                # leitura suspeita: NAO adota o novo valor, mantem o ultimo confiavel
                # e sinaliza a tentativa (visivel via `/market/gold-price`).
                self._last_rejected = True
                self._stale = True
                return
            self._history.append(gold_usd)
            self._history = self._history[-100:]
            self._last_gold_usd = gold_usd
            self._last_usd_brl = usd_brl
            self._last_fetch = time.time()
            self._stale = False
            self._persist_price_point(gold_usd, usd_brl)
        except Exception:
            # sem internet/API fora do ar: mantem o ultimo valor conhecido (ou fallback inicial)
            if self._last_gold_usd is None:
                self._last_gold_usd = FALLBACK_GOLD_USD_PER_OZ
                self._last_usd_brl = FALLBACK_USD_BRL
            self._stale = True

    def snapshot(self) -> MarketSnapshot:
        self.refresh()
        gold_usd = self._last_gold_usd or FALLBACK_GOLD_USD_PER_OZ
        usd_brl = self._last_usd_brl or FALLBACK_USD_BRL
        pxc_brl_rate = round(PXC_GOLD_BACKING_OZ * gold_usd * usd_brl, 6)

        if len(self._history) >= 2:
            previous = self._history[-2]
            delta_pct = round(((gold_usd - previous) / previous) * 100, 4) if previous else 0.0
        else:
            delta_pct = 0.0

        return MarketSnapshot(
            gold_usd_per_oz=gold_usd,
            usd_brl=usd_brl,
            pxc_brl_rate=pxc_brl_rate,
            delta_pct_gold=delta_pct,
            stale=self._stale,
            fetched_at=self._last_fetch,
            rejected_manipulation_attempt=self._last_rejected,
        )


# instancia unica compartilhada pela API (singleton simples de processo)
gold_oracle = GoldOracle()
