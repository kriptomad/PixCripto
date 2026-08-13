"""
Camada L2 (Layer 2) - estilo "Optimistic Rollup" simplificado.

Motivacao: a L1 (blockchain principal, `models.Blockchain`) exige mineracao
(Proof-of-Work) para cada bloco, o que limita o throughput de transacoes por
segundo conforme a dificuldade cresce (20x a cada 2 blocos). A L2 resolve isso
processando transferencias INSTANTANEAMENTE fora da cadeia principal (sem
mineracao), e periodicamente agrega (faz o "rollup" de) todas essas
transferencias num unico commit, ancorado na L1 atraves de uma unica
transacao contendo a raiz de uma arvore de Merkle do lote.

Fluxo:
  1) Deposito:  usuario envia fundos da L1 para o endereco-ponte (bridge) L1
                 e registra o deposito; a L2 credita o saldo correspondente.
  2) Transferencias L2: instantaneas, assinadas (mesma ECDSA da L1), sem
                 esperar mineracao - APENAS movem saldo dentro do ledger L2.
  3) Commit/Rollup: em lotes (por tempo ou quantidade), a raiz de Merkle das
                 transferencias L2 pendentes e ancorada na L1 como uma unica
                 transacao (`tx_type = "rollup_commit"`), que ainda precisa
                 ser minerada uma unica vez para todo o lote - e nao uma vez
                 por transacao, daí o ganho de escala.
  4) Saque:     usuario debita saldo L2 e recebe de volta na L1 (transacao de
                 emissao autorizada pelo protocolo, tipo `l2_withdrawal`).
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from . import crypto_utils
from .models import Blockchain, Transaction, COINBASE_SENDER, L2_BRIDGE_ADDRESS


@dataclass
class L2Transaction:
    sender: str
    recipient: str
    amount: float
    tx_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: float = field(default_factory=time.time)
    memo: str = ""
    signature: Optional[str] = None
    public_key: Optional[str] = None

    def signing_payload(self) -> bytes:
        payload = {
            "tx_id": self.tx_id, "sender": self.sender, "recipient": self.recipient,
            "amount": self.amount, "timestamp": self.timestamp, "memo": self.memo,
        }
        return json.dumps(payload, sort_keys=True).encode("utf-8")

    def sign(self, private_key_hex: str, public_key_hex: str) -> None:
        self.public_key = public_key_hex
        self.signature = crypto_utils.sign_message(private_key_hex, self.signing_payload())

    def is_valid(self) -> bool:
        if self.amount <= 0 or not self.signature or not self.public_key:
            return False
        if crypto_utils.public_key_to_address(self.public_key) != self.sender:
            return False
        return crypto_utils.verify_signature(self.public_key, self.signing_payload(), self.signature)

    def to_dict(self) -> dict:
        return asdict(self)


def merkle_root(tx_ids: List[str]) -> str:
    """Raiz de Merkle do lote de transacoes L2 do commit - reaproveita a mesma
    implementacao usada no header dos blocos L1 (`crypto_utils.merkle_root`),
    evitando ter duas arvores de Merkle divergentes no mesmo protocolo."""
    return crypto_utils.merkle_root([hashlib.sha256(t.encode()).hexdigest() for t in tx_ids])



class L2Rollup:
    """Ledger L2 (fora da cadeia) + ponte de deposito/saque com a L1."""

    def __init__(self, l1: Blockchain):
        self.l1 = l1
        self.balances: Dict[str, float] = {}
        self.pending_l2_txs: List[L2Transaction] = []
        self.committed_batches: List[dict] = []
        # protege balances/pending_l2_txs contra corrida de threads (mesma
        # justificativa do `_chain_lock` em models.Blockchain)
        self._lock = threading.RLock()
        # anti-replay: cada deposito L1 (identificado por l1_tx_id, que e unico
        # e imutavel) so pode ser creditado UMA UNICA vez na L2 - sem isto, o
        # mesmo deposito minerado poderia ser "recreditado" infinitamente
        # chamando `/l2/deposit` repetidamente (falha CRITICA encontrada em
        # auditoria: permitiria inflar o saldo L2 e drenar o bridge na L1).
        # PERSISTIDO em SQLite (nao apenas em RAM) - correcao de auditoria: a
        # versao anterior perdia esse controle a cada reinicio do processo,
        # permitindo reprocessar o mesmo deposito apos um restart.
        from . import storage
        self._storage = storage
        saved_balances, processed = storage.load_l2_state()
        self.balances.update(saved_balances)
        self._processed_deposits: set = processed

    # -- ponte L1 <-> L2 -----------------------------------------------------
    def deposit(self, l1_tx_id: str) -> dict:
        """
        Confirma um deposito: exige que exista, na L1 (ja minerada), uma
        transacao com destino ao endereco-ponte. Credita o mesmo valor no
        ledger L2 para o remetente original. Cada `l1_tx_id` so pode ser
        processado UMA vez (protecao contra replay, persistida em disco).
        """
        with self._lock:
            if l1_tx_id in self._processed_deposits or self._storage.is_l2_deposit_processed(l1_tx_id):
                raise ValueError("Este deposito ja foi processado anteriormente (protecao anti-replay)")
            for block in self.l1.chain:
                for tx in block.transactions:
                    if tx.tx_id == l1_tx_id and tx.recipient == L2_BRIDGE_ADDRESS and tx.tx_type == "transfer":
                        self._processed_deposits.add(l1_tx_id)
                        self.balances[tx.sender] = self.balances.get(tx.sender, 0.0) + tx.amount
                        self._storage.record_l2_deposit(l1_tx_id, tx.sender, tx.amount)
                        self._storage.save_l2_balance(tx.sender, self.balances[tx.sender])
                        return {"address": tx.sender, "credited": tx.amount, "l2_balance": self.balances[tx.sender]}
            raise ValueError("Transacao de deposito nao encontrada ou ainda nao minerada na L1")

    def withdraw(self, address: str, amount: float, public_key_hex: str, signature: str) -> Transaction:
        """
        Debita o saldo L2 e cria uma transacao na L1 devolvendo os fundos a partir
        do endereco-ponte (que os custodia desde o deposito - nao ha nova emissao).

        Exige assinatura ECDSA do dono do endereco L2 (payload determinístico
        "withdraw:{address}:{amount}") - antes, qualquer pessoa podia forcar o
        saque da posicao L2 de OUTRO endereco apenas conhecendo o endereco
        publico, sem provar posse da chave privada (achado de auditoria).
        """
        if crypto_utils.public_key_to_address(public_key_hex) != address:
            raise ValueError("Chave publica nao corresponde ao endereco do saque")
        payload = f"withdraw:{address}:{amount}".encode("utf-8")
        if not crypto_utils.verify_signature(public_key_hex, payload, signature):
            raise ValueError("Assinatura invalida para o saque")
        with self._lock:
            if self.get_balance(address) < amount:
                raise ValueError("Saldo L2 insuficiente para saque")
            self.balances[address] -= amount
            tx = Transaction(
                sender=L2_BRIDGE_ADDRESS,
                recipient=address,
                amount=amount,
                memo="Saque L2 -> L1 (rollup bridge)",
                tx_type="l2_withdrawal",
            )
            if not self.l1.add_transaction(tx):
                self.balances[address] += amount  # desfaz o debito se a L1 recusar
                raise ValueError("Falha ao registrar saque na L1")
            self._storage.save_l2_balance(address, self.balances[address])
            return tx

    # -- transferencias L2 (instantaneas, sem mineracao) ----------------------
    def get_balance(self, address: str) -> float:
        """
        Saldo L2 em tempo real. As transferencias sao aplicadas imediatamente
        em `balances` (efeito instantaneo, sem esperar o commit/rollup); o
        commit em lote apenas ANCORA a prova na L1, nao move saldo de novo.
        """
        return round(self.balances.get(address, 0.0), 8)

    def transfer(self, tx: L2Transaction) -> bool:
        if not tx.is_valid():
            return False
        with self._lock:
            if self.get_balance(tx.sender) < tx.amount:
                return False
            self.pending_l2_txs.append(tx)
            self._apply(tx)
            self._storage.save_l2_balance(tx.sender, self.balances[tx.sender])
            self._storage.save_l2_balance(tx.recipient, self.balances[tx.recipient])
            return True

    def _apply(self, tx: L2Transaction) -> None:
        self.balances[tx.sender] = self.balances.get(tx.sender, 0.0) - tx.amount
        self.balances[tx.recipient] = self.balances.get(tx.recipient, 0.0) + tx.amount

    # -- commit / rollup para a L1 --------------------------------------------
    def commit_batch(self, max_tx: int = 500) -> Optional[dict]:
        """
        Agrega ate `max_tx` transferencias L2 pendentes num unico commit
        ancorado na L1 (uma raiz de Merkle), reduzindo N transacoes a
        UMA UNICA transacao/mineracao na cadeia principal - o ganho de
        escalabilidade central de uma arquitetura L2/rollup.
        """
        with self._lock:
            if not self.pending_l2_txs:
                return None
            batch = self.pending_l2_txs[:max_tx]
            tx_ids = [t.tx_id for t in batch]
            root = merkle_root(tx_ids)

            anchor_tx = Transaction(
                sender=COINBASE_SENDER,
                recipient=L2_BRIDGE_ADDRESS,
                amount=0,
                memo=f"rollup_commit root={root} count={len(batch)}",
                tx_type="rollup_commit",
            )
            # usa add_transaction (nao acesso direto a lista) para manter a
            # mesma trava/validacao/anti-replay aplicadas a qualquer outra tx
            if not self.l1.add_transaction(anchor_tx):
                raise ValueError("Falha ao ancorar o commit do lote na L1")

            self.pending_l2_txs = self.pending_l2_txs[max_tx:]
            record = {
                "merkle_root": root,
                "tx_count": len(batch),
                "anchor_l1_tx_id": anchor_tx.tx_id,
                "committed_at": time.time(),
                "tx_ids": tx_ids,
            }
            self.committed_batches.append(record)
            return record
