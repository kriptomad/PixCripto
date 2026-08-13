"""
Modulo de mercado do PixCripto: compra ja existe em `purchase.py`. Aqui ficam:

- VENDA (sell) e LIQUIDACAO: usuario devolve PXC ao protocolo (queima) e recebe
  a cotacao em Reais, ancorada no preco do ouro (`gold_oracle.py`).
- TROCA (swap): mercado P2P (estilo DEX) de ordens de venda entre usuarios,
  com custodia (escrow) automatica dos fundos ate a ordem ser preenchida ou
  cancelada.
- CONTROLE DE DUMP: limita, por carteira e para a rede como um todo, quanto
  PXC pode ser vendido/liquidado numa janela de tempo. Ao ultrapassar o limite
  da rede, a NEGOCIACAO E SUSPENSA AUTOMATICAMENTE ate a janela esvaziar -
  "self-regulacao" sem intervencao humana.
- AUTO-REGULACAO: o limite de dump da rede se ajusta sozinho conforme a
  concentracao de saldo entre carteiras (indice HHI, calculado de forma
  vetorizada com numpy) - quanto mais concentrado (risco de whale dump),
  mais apertado fica o limite; quanto mais distribuido, mais o limite
  relaxa (ate um teto), sem exigir nenhuma configuracao manual.
- EXPLORER: consulta publica de saldo/movimentacao por endereco e atividade
  agregada de mercado (transparencia total das transacoes, mesmo mantendo o
  anonimato pseudonimo dos enderecos - exatamente como o Bitcoin).
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

from . import crypto_utils, root_rules
from .gold_oracle import gold_oracle
from .models import Blockchain, Transaction, COINBASE_SENDER, SWAP_ESCROW_ADDRESS

# ---------------------------------------------------------------------------
# Controle de dump (janela deslizante) e auto-regulacao
# ---------------------------------------------------------------------------

DUMP_WINDOW_SECONDS = root_rules.DUMP_WINDOW_SECONDS
MAX_WALLET_DUMP_RATIO = root_rules.MAX_WALLET_DUMP_RATIO
NETWORK_DUMP_RATIO_FLOOR = root_rules.NETWORK_DUMP_RATIO_FLOOR
NETWORK_DUMP_RATIO_CEILING = root_rules.NETWORK_DUMP_RATIO_CEILING
REWARD_ELIGIBLE_TYPES_FOR_STATS = {"transfer", "sell_burn", "liquidation_burn", "swap_fill", "coinbase_purchase"}


class MarketError(Exception):
    pass


@dataclass
class SwapOrder:
    order_id: str
    maker_address: str
    maker_public_key: str
    amount: float
    price_brl_per_pxc: float
    status: str = "open"  # open | settling | filled | cancelled
    created_at: float = field(default_factory=time.time)
    filled_by: Optional[str] = None
    filled_at: Optional[float] = None


class MarketEngine:
    def __init__(self, blockchain: Blockchain):
        self.blockchain = blockchain
        self.sell_events: List[tuple] = []          # (timestamp, address, amount) - vendas e liquidacoes
        self.swap_orders: Dict[str, SwapOrder] = {}  # order_id -> ordem de troca (DEX)
        # trava dedicada as ordens de troca - impede que `fill` e `cancel` da
        # MESMA ordem sejam processados em paralelo e liberem o escrow em dobro
        # (race condition encontrada em auditoria).
        self._swap_lock = threading.RLock()

    # -- oferta circulante e concentracao (vetorizado) ------------------------
    def circulating_supply(self) -> float:
        total = 0.0
        for block in self.blockchain.chain:
            for tx in block.transactions:
                if tx.tx_type in ("coinbase_mining", "coinbase_purchase"):
                    total += tx.amount
                elif tx.tx_type in ("sell_burn", "liquidation_burn"):
                    total -= tx.amount
        return round(max(total, 0.0), 8)

    def wallet_concentration_hhi(self) -> float:
        """Indice Herfindahl-Hirschman de concentracao de saldo entre carteiras (numpy vetorizado)."""
        addresses = set()
        for block in self.blockchain.chain:
            for tx in block.transactions:
                addresses.add(tx.sender)
                addresses.add(tx.recipient)
        addresses -= root_rules.SYSTEM_ADDRESSES
        if not addresses:
            return 0.0
        balances = np.array([max(self.blockchain.get_balance(a), 0.0) for a in addresses])
        total = balances.sum()
        if total <= 0:
            return 0.0
        shares = balances / total
        return float(np.sum(shares ** 2))

    def effective_network_dump_limit(self) -> float:
        """
        Auto-regulacao (self-regulating): quanto maior a concentracao de saldo
        (HHI proximo de 1 = poucas carteiras dominam), menor o limite de dump
        permitido para a rede - protegendo o mercado de um "whale dump" real.
        Quanto mais distribuido (HHI proximo de 0), mais o limite se aproxima
        do teto. Isso acontece automaticamente, sem qualquer ajuste manual.
        """
        hhi = self.wallet_concentration_hhi()
        limit = NETWORK_DUMP_RATIO_CEILING - hhi * (NETWORK_DUMP_RATIO_CEILING - NETWORK_DUMP_RATIO_FLOOR)
        return round(max(NETWORK_DUMP_RATIO_FLOOR, min(NETWORK_DUMP_RATIO_CEILING, limit)), 6)

    def _prune_window(self, now: float) -> None:
        self.sell_events = [e for e in self.sell_events if now - e[0] <= DUMP_WINDOW_SECONDS]

    def network_dump_stats(self, now: Optional[float] = None) -> dict:
        now = now or time.time()
        self._prune_window(now)
        supply = self.circulating_supply()
        sold = sum(e[2] for e in self.sell_events)
        limit = self.effective_network_dump_limit()
        ratio = (sold / supply) if supply > 0 else 0.0
        return {
            "window_seconds": DUMP_WINDOW_SECONDS,
            "circulating_supply": supply,
            "sold_in_window": round(sold, 8),
            "dump_ratio": round(ratio, 6),
            "limit_ratio": limit,
            "wallet_concentration_hhi": round(self.wallet_concentration_hhi(), 4),
            "trading_halted": ratio >= limit,
        }

    def wallet_dump_stats(self, address: str, now: Optional[float] = None) -> dict:
        now = now or time.time()
        self._prune_window(now)
        sold = sum(e[2] for e in self.sell_events if e[1] == address)
        current_balance = self.blockchain.get_balance(address)
        balance_before_window = current_balance + sold
        ratio = (sold / balance_before_window) if balance_before_window > 0 else 0.0
        allowed_remaining = max(0.0, MAX_WALLET_DUMP_RATIO * balance_before_window - sold)
        return {
            "sold_in_window": round(sold, 8),
            "balance_before_window": round(balance_before_window, 8),
            "ratio_used": round(ratio, 6),
            "limit_ratio": MAX_WALLET_DUMP_RATIO,
            "allowed_remaining": round(allowed_remaining, 8),
        }

    # -- venda / liquidacao (queima real, sujeita a controle de dump) --------
    def _execute_sell(self, address: str, amount: float, tx_type: str, memo: str) -> dict:
        if amount <= 0:
            raise MarketError("Valor invalido para venda/liquidacao")
        now = time.time()

        net_stats = self.network_dump_stats(now)
        if net_stats["trading_halted"]:
            raise MarketError(
                f"Negociacao SUSPENSA automaticamente: a rede ja vendeu "
                f"{net_stats['dump_ratio'] * 100:.2f}% da oferta circulante nesta janela de "
                f"{DUMP_WINDOW_SECONDS}s (limite auto-regulado: {net_stats['limit_ratio'] * 100:.2f}%). "
                f"Aguarde a janela esvaziar - o sistema se auto-regula sem intervencao manual."
            )

        balance = self.blockchain.get_balance(address)
        if amount > balance:
            raise MarketError("Saldo insuficiente para vender/liquidar esse valor")

        wallet_stats = self.wallet_dump_stats(address, now)
        if amount > wallet_stats["allowed_remaining"]:
            raise MarketError(
                f"Controle de dump por carteira: voce pode vender no maximo "
                f"{wallet_stats['allowed_remaining']:.8f} PXC nesta janela de {DUMP_WINDOW_SECONDS}s "
                f"(limite de {MAX_WALLET_DUMP_RATIO * 100:.0f}% do saldo por janela)."
            )

        supply = net_stats["circulating_supply"]
        prospective_ratio = (net_stats["sold_in_window"] + amount) / supply if supply > 0 else 1.0
        if prospective_ratio > net_stats["limit_ratio"]:
            raise MarketError(
                "Esta venda ultrapassaria o limite de dump da rede nesta janela; "
                "tente um valor menor ou aguarde a janela reabrir."
            )

        snapshot = gold_oracle.snapshot()
        payout_brl = round(amount * snapshot.pxc_brl_rate, 2)

        tx = Transaction(sender=address, recipient=COINBASE_SENDER, amount=amount,
                          memo=f"{memo} | payout=R${payout_brl:.2f} | rate={snapshot.pxc_brl_rate}", tx_type=tx_type)
        return {"tx": tx, "payout_brl": payout_brl, "pxc_brl_rate": snapshot.pxc_brl_rate}

    def sell(self, sender_private_key: str, sender_public_key: str, address: str, amount: float) -> Transaction:
        result = self._execute_sell(address, amount, "sell_burn", f"Venda de {amount} PXC (queima)")
        tx: Transaction = result["tx"]
        tx.sign(sender_private_key, sender_public_key)
        if not self.blockchain.add_transaction(tx):
            raise MarketError("Falha ao registrar a venda (assinatura ou saldo invalidos)")
        self.sell_events.append((time.time(), address, amount))
        tx.payout_brl = result["payout_brl"]        # anexado apenas para resposta da API
        tx.pxc_brl_rate = result["pxc_brl_rate"]
        return tx

    def liquidate(self, sender_private_key: str, sender_public_key: str, address: str,
                  amount: Optional[float] = None) -> Transaction:
        """Liquidacao: venda total (ou parcial, se especificado) sujeita as MESMAS regras de
        controle de dump - protege contra liquidar uma posicao inteira de uma vez em mercados
        concentrados."""
        target_amount = amount if amount is not None else self.blockchain.get_balance(address)
        result = self._execute_sell(address, target_amount, "liquidation_burn",
                                     f"Liquidacao de {target_amount} PXC (queima)")
        tx: Transaction = result["tx"]
        tx.sign(sender_private_key, sender_public_key)
        if not self.blockchain.add_transaction(tx):
            raise MarketError("Falha ao registrar a liquidacao (assinatura ou saldo invalidos)")
        self.sell_events.append((time.time(), address, target_amount))
        tx.payout_brl = result["payout_brl"]
        tx.pxc_brl_rate = result["pxc_brl_rate"]
        return tx

    # -- troca (swap) P2P estilo DEX com escrow --------------------------------
    def create_swap_order(self, sender_private_key: str, sender_public_key: str,
                           maker_address: str, amount: float, price_brl_per_pxc: float) -> SwapOrder:
        if amount <= 0 or price_brl_per_pxc <= 0:
            raise MarketError("Valor e preco devem ser positivos")
        if self.blockchain.get_balance(maker_address) < amount:
            raise MarketError("Saldo insuficiente para criar a ordem de troca")

        escrow_tx = Transaction(sender=maker_address, recipient=SWAP_ESCROW_ADDRESS, amount=amount,
                                 memo="Deposito em custodia para ordem de troca (swap)", tx_type="swap_escrow")
        escrow_tx.sign(sender_private_key, sender_public_key)
        if not self.blockchain.add_transaction(escrow_tx):
            raise MarketError("Falha ao custodiar fundos da ordem de troca")

        order = SwapOrder(order_id=uuid.uuid4().hex, maker_address=maker_address,
                           maker_public_key=sender_public_key, amount=amount, price_brl_per_pxc=price_brl_per_pxc)
        self.swap_orders[order.order_id] = order
        return order

    @staticmethod
    def _swap_release_payload(action: str, order_id: str, counterparty: str) -> bytes:
        return f"{action}:{order_id}:{counterparty}".encode("utf-8")

    def fill_swap_order(self, order_id: str, taker_address: str, maker_signature: str) -> Transaction:
        """
        Libera o PXC em custodia para o `taker_address`. Exige uma assinatura do
        MAKER (dono original da ordem) autorizando especificamente ESTE taker -
        na pratica, o maker so assina/libera depois de confirmar (fora da
        cadeia) que recebeu o pagamento em BRL combinado. Antes desta correcao,
        QUALQUER pessoa podia chamar este endpoint so com o `order_id` e um
        endereco proprio, roubando o PXC custodiado sem pagar nada ao maker
        (falha CRITICA encontrada em auditoria).
        """
        with self._swap_lock:
            order = self.swap_orders.get(order_id)
            if order is None or order.status != "open":
                raise MarketError("Ordem de troca inexistente ou ja finalizada")
            payload = self._swap_release_payload("fill", order_id, taker_address)
            if not crypto_utils.verify_signature(order.maker_public_key, payload, maker_signature):
                raise MarketError("Assinatura do criador da ordem (maker) invalida ou ausente")
            order.status = "settling"  # trava a ordem antes de emitir a tx (evita corrida com cancel)

        tx = Transaction(sender=SWAP_ESCROW_ADDRESS, recipient=taker_address, amount=order.amount,
                          memo=f"Troca preenchida: ordem {order.order_id} @ R${order.price_brl_per_pxc}/PXC "
                               f"(pagamento em BRL liquidado fora da cadeia entre as partes)",
                          tx_type="swap_fill")
        if not self.blockchain.add_transaction(tx):
            with self._swap_lock:
                order.status = "open"  # desfaz a trava se a emissao falhar
            raise MarketError("Falha ao liquidar a ordem de troca")
        with self._swap_lock:
            order.status = "filled"
            order.filled_by = taker_address
            order.filled_at = time.time()
        return tx

    def cancel_swap_order(self, order_id: str, requester_address: str, maker_signature: str) -> Transaction:
        with self._swap_lock:
            order = self.swap_orders.get(order_id)
            if order is None or order.status != "open":
                raise MarketError("Ordem de troca inexistente ou ja finalizada")
            if order.maker_address != requester_address:
                raise MarketError("Somente o criador da ordem pode cancela-la")
            payload = self._swap_release_payload("cancel", order_id, requester_address)
            if not crypto_utils.verify_signature(order.maker_public_key, payload, maker_signature):
                raise MarketError("Assinatura do criador da ordem (maker) invalida ou ausente")
            order.status = "settling"

        tx = Transaction(sender=SWAP_ESCROW_ADDRESS, recipient=order.maker_address, amount=order.amount,
                          memo=f"Cancelamento/estorno da ordem de troca {order.order_id}",
                          tx_type="swap_cancel_refund")
        if not self.blockchain.add_transaction(tx):
            with self._swap_lock:
                order.status = "open"
            raise MarketError("Falha ao estornar a ordem de troca")
        with self._swap_lock:
            order.status = "cancelled"
        return tx

    # -- explorer publico (transparencia, mantendo anonimato pseudonimo) ------
    def address_history(self, address: str) -> dict:
        confirmed = []
        for block in self.blockchain.chain:
            for tx in block.transactions:
                if tx.sender == address or tx.recipient == address:
                    d = tx.to_dict()
                    d["block_index"] = block.index
                    d["direction"] = "saida" if tx.sender == address else "entrada"
                    confirmed.append(d)
        pending = [
            {**tx.to_dict(), "direction": "saida" if tx.sender == address else "entrada"}
            for tx in self.blockchain.pending_transactions
            if tx.sender == address or tx.recipient == address
        ]
        return {
            "address": address,
            "balance": self.blockchain.get_balance(address),
            "confirmed_transactions": confirmed,
            "pending_transactions": pending,
        }

    def market_activity(self, top_n: int = 10) -> dict:
        """Movimento agregado do mercado: volume, numero de transacoes e maiores movimentacoes
        (whale-watch) - visibilidade total do mercado sem identificar donos reais dos enderecos."""
        all_txs = []
        for block in self.blockchain.chain:
            for tx in block.transactions:
                if tx.tx_type in REWARD_ELIGIBLE_TYPES_FOR_STATS:
                    all_txs.append(tx)
        total_volume = sum(tx.amount for tx in all_txs)
        largest = sorted(all_txs, key=lambda t: t.amount, reverse=True)[:top_n]
        return {
            "total_transactions": len(all_txs),
            "total_volume_pxc": round(total_volume, 8),
            "circulating_supply": self.circulating_supply(),
            "wallet_concentration_hhi": round(self.wallet_concentration_hhi(), 4),
            "largest_transactions": [
                {"tx_id": t.tx_id, "sender": t.sender, "recipient": t.recipient,
                 "amount": t.amount, "tx_type": t.tx_type, "timestamp": t.timestamp}
                for t in largest
            ],
        }
