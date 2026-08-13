"""
Modelos centrais da blockchain: Transacao, Bloco e a cadeia (Blockchain).

Cada transacao e assinada digitalmente pelo remetente. Cada bloco agrupa varias
transacoes pendentes e precisa ser "minerado" (Proof-of-Work) para ser aceito na
cadeia. Quem minera com sucesso recebe uma recompensa equivalente a 4% do valor
total movimentado no bloco (nao um valor fixo como no Bitcoin, pois esta moeda
nao busca ser tao escassa).
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Sequence, Tuple

from . import crypto_utils, root_rules
from .difficulty import DifficultyEngine, hash_meets_bits, block_work
from .vm import ContractsState, ContractAccount, VM, CallContext, ExecutionResult

# NOTA: os parametros abaixo devem sempre refletir `app/root_rules.py` (a fonte
# unica da verdade / "Root Rules"). Mantidos aqui por compatibilidade de import,
# mas OBTIDOS de root_rules para impedir divergencia ("drift") entre modulos.
COINBASE_SENDER = root_rules.COINBASE_SENDER          # emissor simbolico p/ recompensas de mineracao e compras
L2_BRIDGE_ADDRESS = root_rules.L2_BRIDGE_ADDRESS      # pseudo-endereco que custodia depositos/saques da L2
SWAP_ESCROW_ADDRESS = root_rules.SWAP_ESCROW_ADDRESS  # pseudo-endereco que custodia ordens de troca (DEX)
MINER_REWARD_RATE = root_rules.MINER_REWARD_RATE      # 4% do valor total do bloco vai para o minerador

# tipos de transacao cujo remetente e sempre um pseudo-endereco do PROTOCOLO
# (nao exigem assinatura de usuario - autorizados por regras deterministicas do consenso)
SYSTEM_TX_SENDERS = {
    "coinbase_mining": COINBASE_SENDER,
    "coinbase_purchase": COINBASE_SENDER,
    "rollup_commit": COINBASE_SENDER,
    "l2_withdrawal": L2_BRIDGE_ADDRESS,
    "swap_fill": SWAP_ESCROW_ADDRESS,
    "swap_cancel_refund": SWAP_ESCROW_ADDRESS,
}

# tipos que NAO devem debitar o saldo do remetente ao serem creditados na cadeia
# (emissao pura - o "remetente" e simbolico, nao uma carteira com saldo real)
NON_DEBIT_SENDER_TYPES = {"coinbase_mining", "coinbase_purchase", "rollup_commit"}

# tipos cujo saldo do remetente e verificado antes de aceitar a transacao
BALANCE_CHECKED_TYPES = {"transfer", "sell_burn", "liquidation_burn", "swap_escrow",
                          "l2_withdrawal", "swap_fill", "swap_cancel_refund",
                          "contract_deploy", "contract_call"}

# tipos de transacao que carregam bytecode/calldata da VM no campo `data`
# (hex-encoded) e sao executados pela VM no momento em que um bloco os inclui
# (ver `Blockchain._apply_block_to_contracts` / `contracts_root`)
CONTRACT_TX_TYPES = {"contract_deploy", "contract_call"}

# tipos que contam como "volume real de mercado" para efeito de recompensa do minerador
REWARD_ELIGIBLE_TYPES = {"transfer", "sell_burn", "liquidation_burn", "swap_fill"}


@dataclass
class Transaction:
    sender: str
    recipient: str
    amount: float
    tx_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: float = field(default_factory=time.time)
    memo: str = ""
    signature: Optional[str] = None
    public_key: Optional[str] = None
    # transfer | coinbase_mining | coinbase_purchase | sell_burn | liquidation_burn |
    # swap_escrow | swap_fill | swap_cancel_refund | rollup_commit | l2_withdrawal
    tx_type: str = "transfer"
    # protecao contra replay attack entre redes (mainnet/testnet/forks futuros) — faz
    # parte do que e assinado (signing_payload). Default = mainnet (root_rules.NETWORK_ID).
    network_id: int = root_rules.NETWORK_ID
    # taxa opcional em PXC oferecida ao minerador (alem da recompensa de 4% do valor
    # do bloco) — usada para priorizar a ordem de inclusao na mempool quando ha mais
    # tx pendentes do que cabem num bloco (`max_tx`), igual a qualquer blockchain real
    # (maior taxa e escolhida primeiro pelo minerador).
    fee: float = 0.0
    # bytecode (contract_deploy) ou calldata (contract_call) da VM, codificado
    # em hex - vazio para todos os demais tx_type. O ORCAMENTO de gas nao e um
    # campo separado: e derivado de `fee` (em PXC) via `root_rules.GAS_PRICE_PXC`,
    # para nao introduzir uma segunda unidade de conta so para a VM.
    data: str = ""
    # -----------------------------------------------------------------------
    # Campos opcionais para transacoes multi-assinatura (M-de-N).
    # Quando presentes, a transacao pertence a uma carteira multisig e e
    # validada pelo caminho multisig em `is_valid()` em vez do caminho
    # single-sig. Sao None em TODAS as transacoes convencionais (sem efeito
    # na logica existente — retro-compatibilidade total).
    #
    # multisig_participants: JSON list[str] com as N chaves publicas dos
    #   participantes (mesmas passadas a `derive_multisig_address`), ordenadas
    #   lexicograficamente, que definem a carteira. O endereco multisig e
    #   recomputado a partir delas + `multisig_threshold` e comparado ao
    #   `sender`, tornando a transacao auto-validavel sem consulta ao banco.
    # multisig_threshold: int M (quantas assinaturas sao necessarias).
    # multisig_signatures: JSON list[{"public_key": str, "signature": str}]
    #   com as M (ou mais) assinaturas coletadas dos participantes. Cada
    #   assinatura e sobre o mesmo `signing_payload()` que uma tx normal.
    # -----------------------------------------------------------------------
    multisig_participants: Optional[str] = None
    multisig_threshold: Optional[int] = None
    multisig_signatures: Optional[str] = None

    def __post_init__(self) -> None:
        # Normaliza amount/fee para float SEMPRE, independente do tipo usado na
        # construcao (ex: `Transaction(amount=10)` com int). Sem isto, um valor
        # inteiro sobrevive como `10` no JSON assinado/hasheado em memoria, mas
        # volta como `10.0` apos um round-trip pelo SQLite (coluna REAL) -
        # mudando a serializacao JSON (`"10"` vs `"10.0"`) e, portanto, tanto o
        # `tx_hash()` (quebra o Merkle root/hash do bloco apos um restart) quanto
        # a verificacao de assinatura (`signing_payload()` muda de bytes) -
        # falha de consenso real encontrada ao testar a persistencia do `state_root`.
        try:
            self.amount = float(self.amount)
        except (TypeError, ValueError):
            pass  # tipo invalido (ex: string nao numerica) - is_valid() rejeita adiante
        try:
            self.fee = float(self.fee)
        except (TypeError, ValueError):
            pass

    def signing_payload(self) -> bytes:
        payload = {
            "tx_id": self.tx_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "memo": self.memo,
            "tx_type": self.tx_type,
            "network_id": self.network_id,
            "fee": self.fee,
            "data": self.data,
        }
        return json.dumps(payload, sort_keys=True).encode("utf-8")

    def sign(self, private_key_hex: str, public_key_hex: str) -> None:
        self.public_key = public_key_hex
        self.signature = crypto_utils.sign_message(private_key_hex, self.signing_payload())

    def is_valid(self) -> bool:
        # regra 0 (Root Rules): tx_type precisa estar na lista branca do protocolo -
        # qualquer tipo desconhecido e rejeitado (evita contrabandear novos tipos
        # de transacao nao previstos pelo consenso).
        if self.tx_type not in root_rules.VALID_TX_TYPES:
            return False
        # regra 0b: network_id precisa bater com o da rede ativa - protege contra
        # replay attack (uma tx assinada para outra rede/fork nunca e aceita aqui).
        if self.network_id != root_rules.NETWORK_ID:
            return False
        # regra 1: valor precisa ser um numero finito (bloqueia NaN/Infinity, que
        # poderiam corromper somas de saldo/bloco) e dentro dos limites de sanidade.
        if not isinstance(self.amount, (int, float)) or isinstance(self.amount, bool):
            return False
        if not math.isfinite(self.amount):
            return False
        if self.amount > root_rules.MAX_TRANSACTION_AMOUNT:
            return False
        if not isinstance(self.fee, (int, float)) or isinstance(self.fee, bool) or not math.isfinite(self.fee):
            return False
        if self.fee < 0 or self.fee > root_rules.MAX_TRANSACTION_AMOUNT:
            return False
        # regra 2: memo tem tamanho maximo (anti-DoS de armazenamento/hashing)
        if self.memo and len(self.memo.encode("utf-8", errors="ignore")) > root_rules.MAX_MEMO_LENGTH_BYTES:
            return False
        if self.tx_type in CONTRACT_TX_TYPES:
            # regra da VM: `data` precisa ser hex valido e caber no teto de
            # bytecode/calldata (anti-DoS: sem teto, um deploy gigante custaria
            # muito mais para validar/armazenar do que o `fee` cobriria)
            try:
                raw = bytes.fromhex(self.data or "")
            except ValueError:
                return False
            limit = (root_rules.MAX_CONTRACT_BYTECODE_BYTES if self.tx_type == "contract_deploy"
                     else root_rules.MAX_CONTRACT_CALLDATA_BYTES)
            if len(raw) > limit:
                return False
            if self.tx_type == "contract_call" and not crypto_utils.is_valid_address(self.recipient):
                return False  # contract_call precisa apontar para um endereco Base58Check valido
        if self.tx_type in SYSTEM_TX_SENDERS:
            # transacoes geradas pelo proprio protocolo (mineracao, compra, ponte L2, escrow de troca)
            # nao exigem assinatura de usuario - a regra deterministica do consenso e a autorizacao
            return self.sender == SYSTEM_TX_SENDERS[self.tx_type] and self.amount >= 0
        # demais tipos (transfer, sell_burn, liquidation_burn, swap_escrow) sao iniciados por um
        # usuario e exigem assinatura ECDSA valida do dono do endereco remetente
        # (contract_deploy/contract_call podem ter amount=0 - so pagam gas via `fee`)
        if self.tx_type not in CONTRACT_TX_TYPES and self.amount < root_rules.MIN_TRANSACTION_AMOUNT:
            return False
        if self.tx_type in CONTRACT_TX_TYPES and self.amount < 0:
            return False
        if self.sender in root_rules.SYSTEM_ADDRESSES:
            # endereco de sistema nunca pode ser remetente de uma transacao "assinada por usuario"
            # (impede um atacante de forjar sender=SISTEMA_EMISSAO num tx_type de usuario)
            return False
        # caminho multisig: quando `multisig_participants` esta presente, a tx e de
        # uma carteira M-de-N e precisa de M assinaturas validas de participantes
        # distintos em vez de uma unica assinatura de chave privada individual.
        if self.multisig_participants is not None:
            return self._is_valid_multisig()
        # caminho single-sig convencional: assinatura ECDSA do dono do endereco
        if not self.signature or not self.public_key:
            return False
        expected_address = crypto_utils.public_key_to_address(self.public_key)
        if expected_address != self.sender:
            return False
        return crypto_utils.verify_signature(self.public_key, self.signing_payload(), self.signature)

    def _is_valid_multisig(self) -> bool:
        """Valida uma transacao multisig M-de-N.

        Regras verificadas:
        1. `multisig_participants` e uma lista JSON de N chaves publicas validas
           na curva secp256k1.
        2. `multisig_threshold` (M) satisfaz 1 <= M <= N <= limite do protocolo.
        3. O endereco multisig recomputado a partir de (participants, threshold)
           bate com `self.sender` — vincula as assinaturas a esta carteira
           especifica, sem precisar consultar o banco de dados.
        4. `multisig_signatures` e uma lista JSON de entradas
           {"public_key": str, "signature": str}, cada uma:
           - com chave publica que pertence a `participants` (rejeita estranhos);
           - sem duplicata da mesma chave publica (rejeita double-signing);
           - com assinatura ECDSA valida sobre `signing_payload()` desta tx.
        5. O numero de assinaturas validas e unicas >= M.
        """
        # importacao local para evitar dependencia circular ao ser chamada
        # durante o reload de modulos em testes (multisig.py importa models.py)
        from . import multisig as _multisig
        try:
            participants = json.loads(self.multisig_participants)
            threshold = self.multisig_threshold
            signatures = json.loads(self.multisig_signatures) if self.multisig_signatures else []
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        if not isinstance(participants, list) or len(participants) < 1:
            return False
        if not isinstance(threshold, int) or threshold < 1 or threshold > len(participants):
            return False
        if not isinstance(signatures, list):
            return False
        # recomputa o endereco multisig e verifica que bate com self.sender
        try:
            expected_addr = _multisig.derive_multisig_address(participants, threshold)
        except Exception:
            return False
        if self.sender != expected_addr:
            return False
        # verifica as assinaturas individualmente
        payload = self.signing_payload()
        seen_keys: set = set()
        valid_count = 0
        for entry in signatures:
            if not isinstance(entry, dict):
                return False
            pub_key = entry.get("public_key")
            sig = entry.get("signature")
            if not pub_key or not sig:
                return False
            # chave deve ser um dos participantes declarados
            if pub_key not in participants:
                return False
            # sem assinatura duplicada do mesmo participante
            if pub_key in seen_keys:
                return False
            seen_keys.add(pub_key)
            # verificacao criptografica ECDSA real
            if not crypto_utils.verify_signature(pub_key, payload, sig):
                return False
            valid_count += 1
        # precisa ter ao menos M assinaturas validas de participantes distintos
        return valid_count >= threshold

    def to_dict(self) -> dict:
        return asdict(self)

    def tx_hash(self) -> str:
        """SHA-256 canonico da transacao completa (incluindo assinatura) - usado
        como folha da arvore de Merkle do bloco (ver `Block.header_string`)."""
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True).encode("utf-8")).hexdigest()

    @staticmethod
    def from_dict(data: dict) -> "Transaction":
        return Transaction(**data)


@dataclass
class Block:
    index: int
    previous_hash: str
    transactions: List[Transaction]
    difficulty: int   # dificuldade EFETIVA aplicada a este minerador, em bits de zero exigidos
    timestamp: float = field(default_factory=time.time)
    nonce: int = 0
    miner_address: Optional[str] = None
    hash: Optional[str] = None
    base_difficulty_bits: Optional[int] = None       # dificuldade-base da rede (sem penalidade)
    anti_monopoly_info: Optional[dict] = None         # detalhe do calculo anti-monopolio (vetorizado)
    state_root: Optional[str] = None                  # hash do snapshot de saldos apos este bloco (integridade de estado)
    contracts_root: Optional[str] = None               # hash do snapshot de codigo/storage de contratos apos este bloco

    def block_value(self) -> float:
        """Soma o valor das transacoes economicamente relevantes do bloco (base da recompensa):
        transferencias, vendas/liquidacoes (queima) e trocas (swap) preenchidas."""
        return sum(tx.amount for tx in self.transactions if tx.tx_type in REWARD_ELIGIBLE_TYPES)

    def total_fees(self) -> float:
        """Soma das taxas (`fee`) oferecidas pelas transacoes deste bloco (excluindo a
        propria coinbase, que nunca tem fee) - vao integralmente para o minerador,
        alem da recompensa de 4% do valor do bloco."""
        return sum(tx.fee for tx in self.transactions if tx.tx_type != "coinbase_mining")

    def miner_reward(self) -> float:
        return round(self.block_value() * MINER_REWARD_RATE + self.total_fees(), 8)

    def reward_breakdown(self) -> List[Dict[str, object]]:
        """Lista cada contribuidor pago neste bloco (uma ou mais tx `coinbase_mining`)
        e o valor recebido — usado para transparencia de mineracao em pool (varias
        pessoas podem ter validado/minerado o mesmo bloco e dividido a recompensa)."""
        return [
            {"address": tx.recipient, "amount": tx.amount, "memo": tx.memo}
            for tx in self.transactions if tx.tx_type == "coinbase_mining"
        ]

    def header_string(self) -> str:
        tx_root = crypto_utils.merkle_root([tx.tx_hash() for tx in self.transactions])
        return (f"{self.index}|{self.previous_hash}|{tx_root}|{self.timestamp}|{self.nonce}|"
                f"{self.difficulty}|{self.state_root or ''}|{self.contracts_root or ''}")

    def compute_hash(self) -> str:
        return hashlib.sha256(self.header_string().encode("utf-8")).hexdigest()

    def meets_difficulty(self, block_hash: str) -> bool:
        return hash_meets_bits(block_hash, self.difficulty)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["transactions"] = [t.to_dict() for t in self.transactions]
        d["block_value"] = self.block_value()
        d["merkle_root"] = crypto_utils.merkle_root([tx.tx_hash() for tx in self.transactions])
        return d

    @staticmethod
    def from_dict(data: dict) -> "Block":
        """Reconstroi um Block a partir de um dict (usado ao receber um bloco
        serializado via rede P2P ou API - ver `app/network.py`). Campos
        totalmente derivados da lista de transacoes (`block_value`, `merkle_root`)
        sao ignorados: sao sempre recalculados, nunca confiados vindos da rede.
        `state_root`, por depender do HISTORICO da cadeia (nao so deste bloco),
        e mantido e revalidado por replay em `Blockchain.validate_candidate_chain`."""
        txs = [Transaction.from_dict(t) for t in data["transactions"]]
        return Block(
            index=data["index"], previous_hash=data["previous_hash"], transactions=txs,
            difficulty=data["difficulty"], timestamp=data["timestamp"], nonce=data.get("nonce", 0),
            miner_address=data.get("miner_address"), hash=data.get("hash"),
            base_difficulty_bits=data.get("base_difficulty_bits"),
            anti_monopoly_info=data.get("anti_monopoly_info"),
            state_root=data.get("state_root"),
            contracts_root=data.get("contracts_root"),
        )


class Blockchain:
    def __init__(self, difficulty_mode: str = "demo"):
        self.chain: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        self._last_accepted_block_logs: List[dict] = []
        self.difficulty_engine = DifficultyEngine(mode=difficulty_mode)
        self.recent_miners: List[str] = []  # janela de mineradores para calculo anti-monopolio
        self.difficulty = self.difficulty_engine.base_difficulty_bits(0)
        # trava global de escrita: FastAPI executa handlers `def` (sincronos) numa
        # threadpool - sem esta trava, duas requisicoes concorrentes gastando o
        # MESMO saldo poderiam passar ambas na checagem de saldo antes de qualquer
        # uma delas ser adicionada a mempool (classico TOCTOU -> double-spend).
        # Toda escrita no estado da cadeia (mempool e bloco) e serializada aqui.
        self._chain_lock = threading.RLock()
        # ganchos opcionais de persistencia (setados por `api.py` via
        # `set_persistence_hooks`) - chamados sempre que uma tx entra/sai da
        # mempool, para que ELA SOBREVIVA a um restart do processo, nao importa
        # se veio de `/transaction/*`, do motor de swap (`market.py`) ou da
        # ponte L2 (`layer2.py`) - centralizar aqui evita esquecer algum
        # chamador (o que aconteceria se cada modulo tivesse que lembrar de
        # persistir manualmente toda vez que chama `add_transaction`).
        self._on_tx_pending = None
        self._on_tx_confirmed = None
        # Cache incremental de estado (otimizacao O(N^2) → O(N) por chain):
        # mantem o estado calculado (saldos + contratos) para len(self.chain)
        # blocos, evitando replay completo a cada novo bloco. Atualizado
        # incrementalmente em `submit_mined_block` e invalidado em reorgs
        # (`try_replace_chain`) e rehydrates. Nunca exposto diretamente —
        # sempre acessado via `_replay_state`, que garante copias seguras.
        self._cached_balances: Optional[dict] = None
        self._cached_contracts_state: Optional[ContractsState] = None
        # len(self.chain) no momento em que o cache foi calculado pela ultima
        # vez (-1 significa "invalido/nao calculado ainda")
        self._cache_height: int = -1
        self._create_genesis_block()

    def set_persistence_hooks(self, on_pending=None, on_confirmed=None) -> None:
        """`on_pending(tx)` e chamado quando uma tx entra na mempool (deve
        persisti-la); `on_confirmed(tx)` quando ela e minerada/removida da
        mempool (deve apagar a copia persistida, ja esta segura dentro do bloco)."""
        self._on_tx_pending = on_pending
        self._on_tx_confirmed = on_confirmed

    def _invalidate_state_cache(self) -> None:
        """Invalida o cache incremental de estado (saldos + contratos).
        Deve ser chamado sempre que a cadeia for modificada de forma nao-
        incremental: reorg (`try_replace_chain`) ou rehydrate de blocos
        persistidos. O proximo acesso a `_replay_state` fara o rebuild
        completo e salvara o resultado no cache automaticamente."""
        self._cached_balances = None
        self._cached_contracts_state = None
        self._cache_height = -1

    @property
    def mined_block_count(self) -> int:
        return len(self.chain) - 1  # exclui o bloco genesis

    @staticmethod
    def _apply_block_to_balances(balances: dict, block: "Block") -> None:
        """Aplica as transacoes de UM bloco a um dict de saldos (in-place) -
        usado tanto para montar o `state_root` de um bloco candidato quanto
        para revalidar, por replay incremental, o `state_root` de blocos
        recebidos de outros nos (nunca confiar no valor declarado sem recalcular)."""
        for tx in block.transactions:
            if tx.recipient:
                balances[tx.recipient] = round(balances.get(tx.recipient, 0.0) + tx.amount, 8)
            if tx.sender and tx.tx_type not in NON_DEBIT_SENDER_TYPES:
                balances[tx.sender] = round(balances.get(tx.sender, 0.0) - (tx.amount + tx.fee), 8)

    @staticmethod
    def _state_root_from_balances(balances: dict) -> str:
        """Hash determinístico (SHA-256) de um snapshot de saldos - uma versao
        simplificada de state root (o guia, secao 1.5, autoriza esta
        simplificacao em vez de uma Merkle Patricia Trie completa): permite
        detectar QUALQUER divergencia de saldo entre nos sem precisar
        transmitir o dict inteiro, comparando apenas este hash de 32 bytes."""
        serialized = json.dumps(balances, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @staticmethod
    def _apply_block_to_contracts(state: "ContractsState", block: "Block", balances: dict,
                                  _out_logs: Optional[List[dict]] = None) -> None:
        """Executa, EM ORDEM, todas as tx `contract_deploy`/`contract_call` de
        um bloco contra um `ContractsState` (in-place) - mesmo padrao de replay
        determinístico usado em `_apply_block_to_balances`, o que garante que
        QUALQUER no da rede que reexecute os mesmos blocos, na mesma ordem,
        chegue exatamente ao mesmo `contracts_root` (pre-requisito de consenso
        para uma VM: execucao deterministica e reproduzivel bit-a-bit).

        `balances` e o MESMO dict mutavel usado por `_apply_block_to_balances`
        (nao apenas um getter somente-leitura): permite que (1) `CALL`/`CREATE`
        internos da VM movam saldo PXC de verdade entre contratos (secao 5.4),
        e (2) o gas NAO consumido seja reembolsado ao remetente ao final da
        execucao (secao 5.3 do guia: "sobra de gas e reembolsada ao
        remetente") - o remetente ja teve o `fee` (orcamento de gas) inteiro
        debitado pela transferencia generica de `_apply_block_to_balances`; a
        soma das duas operacoes, em qualquer ordem (adicao e comutativa),
        resulta no remetente pagando exatamente `gas_used * GAS_PRICE_PXC`."""
        for tx in block.transactions:
            if tx.tx_type not in CONTRACT_TX_TYPES:
                continue
            gas_limit = int(tx.fee / root_rules.GAS_PRICE_PXC) if root_rules.GAS_PRICE_PXC else 0
            try:
                raw_data = bytes.fromhex(tx.data or "")
            except ValueError:
                continue  # ja rejeitado por is_valid(), defesa em profundidade

            vm = VM(state, gas_limit, balances=balances,
                    block_timestamp=block.timestamp, block_number=block.index,
                    gas_price=root_rules.GAS_PRICE_PXC)
            if tx.tx_type == "contract_deploy":
                account = state.deploy(tx.sender, raw_data)
                state.intern_address(tx.sender)
                # roda o bytecode uma vez como "construtor" (simplificacao: nao ha
                # separacao entre init-code e runtime-code como na EVM - o mesmo
                # bytecode implantado e o que roda tanto na implantacao quanto em
                # chamadas futuras, documentado como desvio deliberado do guia).
                # Se o "construtor" reverter, o deploy inteiro e desfeito (o
                # contrato nunca chega a existir) - mesma semantica de CREATE.
                ctx = CallContext(contract=account, caller=tx.sender,
                                   call_value=int(round(tx.amount * 10 ** 8)), calldata=b"", depth=0)
                result = vm.execute(ctx)
                if _out_logs is not None and result is not None and result.logs:
                    for i, log in enumerate(result.logs):
                        _out_logs.append({**log, "block_index": block.index, "tx_id": tx.tx_id, "log_index": i})
                if not result.success:
                    state.contracts.pop(account.address, None)
            else:  # contract_call
                state.intern_address(tx.sender)
                target = state.get(tx.recipient)
                if target is None:
                    result = None  # chamada para endereco sem contrato implantado - sem efeito (gas ja foi cobrado como fee)
                else:
                    ctx = CallContext(contract=target, caller=tx.sender,
                                       call_value=int(round(tx.amount * 10 ** 8)), calldata=raw_data, depth=0)
                    result = vm.execute(ctx)
                    if _out_logs is not None and result is not None and result.logs:
                        for i, log in enumerate(result.logs):
                            _out_logs.append({**log, "block_index": block.index, "tx_id": tx.tx_id, "log_index": i})

            # reembolso de gas nao utilizado (secao 5.3 do guia) - creditado
            # diretamente no MESMO dict de saldos usado pelo restante do L1
            gas_used = result.gas_used if result is not None else 0
            gas_refund_pxc = round(max(0, gas_limit - gas_used) * root_rules.GAS_PRICE_PXC, 8)
            if gas_refund_pxc > 0:
                balances[tx.sender] = round(balances.get(tx.sender, 0.0) + gas_refund_pxc, 8)

    @staticmethod
    def _contracts_root_from_state(state: "ContractsState") -> str:
        """Hash deterministico (SHA-256) do snapshot completo de codigo +
        storage de TODOS os contratos - o mesmo tipo de simplificacao usada em
        `_state_root_from_balances` (hash de snapshot em vez de uma trie)."""
        snapshot = {
            address: {
                "code": account.code.hex(),
                "storage": {str(k): v for k, v in sorted(account.storage.items())},
            }
            for address, account in sorted(state.contracts.items())
        }
        serialized = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def _create_genesis_block(self):
        # timestamp fixo (epoch 0) em vez de time.time(): o bloco genesis e
        # recriado do zero a CADA restart do processo (nao e persistido), mas
        # os blocos minerados subsequentes SAO persistidos com seus timestamps
        # originais - se o genesis usasse "agora", ele ficaria mais "recente"
        # que blocos antigos apos um restart, quebrando a checagem de
        # monotonicidade de timestamp em `is_chain_valid()`.
        genesis_state_root = self._state_root_from_balances({})
        genesis_contracts_root = self._contracts_root_from_state(ContractsState())
        genesis = Block(index=0, previous_hash="0" * 64, transactions=[], difficulty=self.difficulty,
                         timestamp=0.0, state_root=genesis_state_root, contracts_root=genesis_contracts_root)
        genesis.hash = genesis.compute_hash()
        self.chain.append(genesis)

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    def _replay_state(self, extra_block: Optional[Block] = None,
                      _new_block_logs: Optional[List[dict]] = None) -> tuple:
        """Replay UNIFICADO da cadeia local (mais um bloco candidato opcional,
        ainda nao anexado) com CACHE INCREMENTAL: na esmagadora maioria das
        chamadas o estado da cadeia confirmada ja esta calculado em cache, e
        apenas o `extra_block` (se fornecido) precisa ser aplicado sobre uma
        COPIA do cache — em vez de replayar todos os blocos do zero.

        Semantica de cache:
        - `_cache_height == len(self.chain)` → cache valido: reflete exatamente
          o estado apos o ultimo bloco confirmado em `self.chain`.
        - Caso contrario → rebuild completo a partir do genesis e salva no
          cache (so o estado da chain confirmada, sem `extra_block`).
        - O `extra_block` e sempre aplicado sobre uma COPIA dos dados do cache,
          nunca sobre o cache em si — protege contra corrupcao acidental.

        Critico para consenso: a logica de aplicacao (contratos ANTES de
        saldos genericos, reembolso de gas no mesmo dict `balances`) e
        identica ao metodo antigo de replay completo — o hash final de
        `state_root`/`contracts_root` para qualquer sequencia de blocos e
        EXATAMENTE igual ao que seria calculado por replay completo."""
        # --- Garante que o cache reflete a cadeia atual ---
        if self._cached_balances is None or self._cache_height != len(self.chain):
            # Cache invalido (primeira chamada, reorg, rehydrate): rebuilda do zero.
            # Ao final salva o estado confirmado no cache para as proximas chamadas.
            balances: dict = {}
            contracts_state = ContractsState()
            for b in self.chain:
                self._apply_block_to_contracts(contracts_state, b, balances)
                self._apply_block_to_balances(balances, b)
            # Persiste no cache (copia rasa de balances e profunda de contracts_state
            # — ContractsState tem dicts aninhados mutaveis que precisam ser isolados)
            self._cached_balances = dict(balances)
            self._cached_contracts_state = copy.deepcopy(contracts_state)
            self._cache_height = len(self.chain)
        else:
            # Cache valido: faz copias para nao corromper o cache ao aplicar extra_block
            balances = dict(self._cached_balances)
            contracts_state = copy.deepcopy(self._cached_contracts_state)

        # Aplica o bloco extra (candidato ainda nao na chain) sobre a copia
        if extra_block is not None:
            self._apply_block_to_contracts(contracts_state, extra_block, balances,
                                           _out_logs=_new_block_logs)
            self._apply_block_to_balances(balances, extra_block)

        return balances, contracts_state

    def _state_snapshot(self, extra_block: Optional[Block] = None) -> dict:
        balances, _ = self._replay_state(extra_block)
        return balances

    def state_root_hash(self, extra_block: Optional[Block] = None) -> str:
        return self._state_root_from_balances(self._state_snapshot(extra_block))

    def _contracts_snapshot(self, extra_block: Optional[Block] = None,
                            _new_block_logs: Optional[List[dict]] = None) -> "ContractsState":
        _, contracts_state = self._replay_state(extra_block, _new_block_logs)
        return contracts_state

    def contracts_root_hash(self, extra_block: Optional[Block] = None,
                            _new_block_logs: Optional[List[dict]] = None) -> str:
        return self._contracts_root_from_state(self._contracts_snapshot(extra_block, _new_block_logs))

    def rehydrate_from_persisted_blocks(self, blocks: List[Block]) -> None:
        """
        Reconstroi o estado da L1 a partir de blocos ja minerados e persistidos
        em disco (SQLite) - chamado uma unica vez na inicializacao do processo
        para que saldos/historico sobrevivam a um restart (sem isto, o disco
        guardava os blocos mas a cadeia em memoria voltava a conter so o
        genesis, uma inconsistencia entre `/chain` e `/chain/metadata`).
        """
        if not blocks:
            return
        with self._chain_lock:
            self.chain = [self.chain[0]] + sorted(blocks, key=lambda b: b.index)
            self.recent_miners = [b.miner_address for b in self.chain[1:] if b.miner_address][-200:]
            self.difficulty = self.difficulty_engine.base_difficulty_bits(self.mined_block_count)
            # cadeia foi substituida por completo — invalida o cache para forcar
            # rebuild na proxima chamada a _replay_state
            self._invalidate_state_cache()

    def rehydrate_pending_transactions(self, txs: List[Transaction]) -> None:
        """Recarrega a mempool persistida (ver `storage.load_pending_transactions`) na
        inicializacao do processo - sem isto, transacoes ja validadas e aceitas mas
        ainda nao mineradas seriam perdidas a cada restart, obrigando o usuario a
        reenviar manualmente algo que a rede ja havia aceito como valido."""
        if not txs:
            return
        with self._chain_lock:
            self._prune_expired_pending()
            existing_ids = {t.tx_id for t in self.pending_transactions}
            for tx in txs:
                if tx.tx_id not in existing_ids and tx.is_valid():
                    self.pending_transactions.append(tx)

    def add_transaction(self, tx: Transaction) -> bool:
        if not tx.is_valid():
            return False
        with self._chain_lock:
            self._prune_expired_pending()
            # anti-flood de mempool: limite de transacoes pendentes por remetente
            # (impede um unico endereco de encher a mempool e causar DoS/spam)
            if tx.tx_type not in SYSTEM_TX_SENDERS:
                pending_from_sender = sum(1 for t in self.pending_transactions if t.sender == tx.sender)
                if pending_from_sender >= root_rules.MAX_PENDING_TX_PER_ADDRESS:
                    return False
            # anti-replay: tx_id precisa ser unico (nao pode ja estar minerado ou pendente)
            if any(t.tx_id == tx.tx_id for t in self.pending_transactions):
                return False
            if any(any(bt.tx_id == tx.tx_id for bt in b.transactions) for b in self.chain):
                return False
            # a checagem de saldo e a insercao na mempool acontecem ATOMICAMENTE sob
            # a mesma trava - impede que duas requisicoes concorrentes gastando o
            # mesmo saldo sejam ambas aceitas (double-spend via corrida de threads).
            if tx.tx_type in BALANCE_CHECKED_TYPES:
                balance = self.get_balance(tx.sender)
                if balance < tx.amount + tx.fee:
                    return False
            self.pending_transactions.append(tx)
            if self._on_tx_pending:
                self._on_tx_pending(tx)
            return True

    def _prune_expired_pending(self) -> None:
        """Remove da mempool transacoes pendentes ha mais tempo que `TX_EXPIRY_SECONDS`
        sem serem mineradas (evita que a mempool cresca indefinidamente com lixo)."""
        now = time.time()
        expired = [t for t in self.pending_transactions if now - t.timestamp > root_rules.TX_EXPIRY_SECONDS]
        if not expired:
            return
        self.pending_transactions = [
            t for t in self.pending_transactions
            if now - t.timestamp <= root_rules.TX_EXPIRY_SECONDS
        ]
        if self._on_tx_confirmed:
            for tx in expired:
                self._on_tx_confirmed(tx)

    def get_balance(self, address: str) -> float:
        balance = 0.0
        for block in self.chain:
            for tx in block.transactions:
                if tx.recipient == address:
                    balance += tx.amount
                if tx.sender == address and tx.tx_type not in NON_DEBIT_SENDER_TYPES:
                    balance -= tx.amount + tx.fee
        for tx in self.pending_transactions:
            if tx.sender == address and tx.tx_type not in NON_DEBIT_SENDER_TYPES:
                balance -= tx.amount + tx.fee
        return round(balance, 8)

    def build_candidate_block(
        self, miner_address: str, max_tx: int = 50,
        contributors: Optional[Sequence[Tuple[str, float]]] = None,
    ) -> Optional[Block]:
        """
        Monta um bloco candidato pronto para mineracao. A(s) transacao(oes) de
        recompensa (coinbase) ja sao incluidas ANTES da busca de nonce, exatamente
        como no Bitcoin, para que participem do hash minerado.

        Quando ha mais tx pendentes do que cabem no bloco (`max_tx`), as tx sao
        priorizadas por `fee` decrescente (maior taxa primeiro) — igual a qualquer
        blockchain real (Bitcoin ordena por fee/vbyte, Ethereum por gas_price):
        sem isso a mempool seria atendida em ordem de chegada (FIFO), permitindo
        que um atacante entupa a fila com tx de taxa zero e atrase pagamentos
        legitimos que pagariam mais para ser confirmados mais rapido.

        A dificuldade aplicada a ESTE minerador (identidade do bloco/pool, usada
        para o calculo anti-monopolio) e a dificuldade-base da rede somada a uma
        penalidade anti-monopolio (quanto maior a fatia recente de blocos
        minerados por ele, e quanto mais vitorias consecutivas, maior a penalidade
        - nunca mais facil, sempre mais dificil para quem concentra hashrate).

        `contributors`: mineracao colaborativa estilo pool (Bitcoin) — lista
        opcional de `(endereco, peso_shares)` de TODAS as pessoas que ajudaram a
        validar/minerar este bloco especifico. Quando informado, a recompensa
        total (4% do bloco + taxas) e dividida PROPORCIONALMENTE ao peso de
        cada contribuidor, cada um recebendo sua propria transacao
        `coinbase_mining` dentro do mesmo bloco. Quando omitido (`None`), o
        comportamento classico (um unico minerador leva a recompensa inteira)
        e mantido, preservando compatibilidade com blocos/testes existentes.
        """
        if not self.pending_transactions:
            return None
        if not crypto_utils.is_valid_address(miner_address):
            # endereco de minerador malformado poderia corromper o calculo vetorizado
            # de HHI/anti-monopolio (difficulty.py) - rejeitado na fronteira, antes
            # mesmo de entrar no motor de dificuldade.
            raise ValueError("Endereco de minerador invalido")
        with self._chain_lock:
            ordered_pending = sorted(self.pending_transactions, key=lambda t: t.fee, reverse=True)
            txs = list(ordered_pending[:max_tx])
            block_value = sum(tx.amount for tx in txs if tx.tx_type in REWARD_ELIGIBLE_TYPES)
            total_fees = sum(tx.fee for tx in txs)
            reward = round(block_value * MINER_REWARD_RATE + total_fees, 8)
            if reward > 0:
                txs.extend(self._build_reward_transactions(reward, miner_address, contributors))

            base_bits = self.difficulty_engine.base_difficulty_bits(self.mined_block_count)
            recent_window = self.recent_miners[-20:]
            effective_bits, anti_monopoly_info = self.difficulty_engine.effective_difficulty_bits(
                miner_address, base_bits, recent_window
            )
            self.difficulty = base_bits  # dificuldade-base exibida/consultada pela rede

            block = Block(
                index=len(self.chain),
                previous_hash=self.last_block.hash,
                transactions=txs,
                difficulty=effective_bits,
                miner_address=miner_address,
                base_difficulty_bits=base_bits,
                anti_monopoly_info=anti_monopoly_info,
            )
            block.state_root = self.state_root_hash(extra_block=block)
            block.contracts_root = self.contracts_root_hash(extra_block=block)
            return block

    def _build_reward_transactions(
        self, reward: float, miner_address: str,
        contributors: Optional[Sequence[Tuple[str, float]]],
    ) -> List[Transaction]:
        """Gera as transacoes `coinbase_mining` que pagam a recompensa do bloco.

        Sem `contributors`: uma unica tx paga o valor integral a `miner_address`
        (comportamento historico). Com `contributors`: divide `reward`
        proporcionalmente ao peso (shares) de cada endereco contribuidor —
        mineracao colaborativa estilo pool, onde varias pessoas que ajudaram a
        validar o bloco recebem sua fracao dentro da MESMA recompensa de 4%
        (o total pago nunca excede `reward`, apenas e repartido entre elas).
        """
        if not contributors:
            return [Transaction(
                sender=COINBASE_SENDER,
                recipient=miner_address,
                amount=reward,
                memo=f"Recompensa de mineracao (4% do bloco {len(self.chain)} + taxas)",
                tx_type="coinbase_mining",
            )]

        if len(contributors) > root_rules.MAX_POOL_CONTRIBUTORS_PER_BLOCK:
            raise ValueError(
                f"Numero de contribuidores do pool excede o teto de "
                f"{root_rules.MAX_POOL_CONTRIBUTORS_PER_BLOCK} por bloco (anti-DoS)"
            )

        # agrega pesos por endereco (um mesmo minerador pode ter submetido varios
        # "shares" de trabalho parcial) preservando a ordem de primeira aparicao
        weights: Dict[str, float] = {}
        order: List[str] = []
        for address, weight in contributors:
            if not crypto_utils.is_valid_address(address):
                raise ValueError(f"Endereco de contribuidor do pool invalido: {address}")
            if weight is None or weight < root_rules.MIN_POOL_CONTRIBUTOR_SHARE:
                raise ValueError(
                    f"Peso de contribuidor do pool invalido para {address} "
                    f"(minimo {root_rules.MIN_POOL_CONTRIBUTOR_SHARE})"
                )
            if address not in weights:
                order.append(address)
                weights[address] = 0.0
            weights[address] += float(weight)

        total_weight = sum(weights.values())
        if total_weight <= 0:
            raise ValueError("Soma dos pesos dos contribuidores do pool deve ser positiva")

        reward_txs: List[Transaction] = []
        remaining = reward
        for i, address in enumerate(order):
            is_last = (i == len(order) - 1)
            if is_last:
                # o ultimo contribuidor recebe o restante exato (evita perda/sobra
                # de fracoes de PXC por arredondamento de ponto flutuante — a soma
                # de todas as tx de recompensa deve ser IDENTICA a `reward`)
                share_amount = round(remaining, 8)
            else:
                share_amount = round(reward * (weights[address] / total_weight), 8)
                remaining = round(remaining - share_amount, 8)
            if share_amount <= 0:
                continue
            pct = 100.0 * weights[address] / total_weight
            reward_txs.append(Transaction(
                sender=COINBASE_SENDER,
                recipient=address,
                amount=share_amount,
                memo=(
                    f"Recompensa de mineracao em pool (bloco {len(self.chain)}) — "
                    f"contribuicao de {pct:.4f}% do trabalho de validacao"
                ),
                tx_type="coinbase_mining",
            ))
        return reward_txs

    def submit_mined_block(self, block: Block, found_nonce: int, found_hash: str) -> bool:
        with self._chain_lock:
            block.nonce = found_nonce
            recomputed = block.compute_hash()
            if recomputed != found_hash or not block.meets_difficulty(found_hash):
                return False
            if block.previous_hash != self.last_block.hash:
                return False  # cadeia avancou, bloco fica obsoleto
            # valida timestamp: nem "do futuro" alem da tolerancia de skew, nem
            # anterior ao bloco anterior menos a tolerancia de clock-skew -
            # protege o recalculo de dificuldade contra manipulacao via
            # timestamps forjados (achado de auditoria de consenso).
            now = time.time()
            if block.timestamp > now + root_rules.MAX_BLOCK_FUTURE_SKEW_SECONDS:
                return False
            if block.timestamp < self.last_block.timestamp + root_rules.MIN_BLOCK_TIMESTAMP_ADVANCE_SECONDS:
                return False
            # revalida TODAS as transacoes do bloco antes de aceita-lo na cadeia -
            # nunca confie apenas na validacao feita no momento do `add_transaction`;
            # isso impede que um bloco candidato adulterado (ex: via chamada direta
            # a submit-proof com transactions manipuladas) seja aceito.
            if not all(tx.is_valid() for tx in block.transactions):
                return False
            # revalida o state_root recalculando os saldos a partir da cadeia local
            # atual + este bloco - protege contra um `/mining/submit-proof` malicioso
            # que reaproveite um state_root antigo/forjado junto de transacoes
            # alteradas (o hash do bloco sozinho nao pega isso, pois seria
            # recalculado igual; o que garante a integridade e comparar contra o
            # ESTADO REAL da cadeia, nao contra o valor que o proprio bloco alega).
            if block.state_root != self.state_root_hash(extra_block=block):
                return False
            # mesma revalidacao por replay para o `contracts_root` (VM) - garante
            # que ninguem consiga submeter um bloco com storage de contrato
            # divergente do que a execucao REAL determinística produziria.
            _pending_logs: List[dict] = []
            if block.contracts_root != self.contracts_root_hash(extra_block=block, _new_block_logs=_pending_logs):
                return False
            self._last_accepted_block_logs = _pending_logs

            block.hash = found_hash
            # remove da mempool apenas as transacoes que de fato vieram da fila de pendentes
            # (a transacao de recompensa coinbase_mining e gerada agora e nunca esteve pendente)
            mined_ids = {tx.tx_id for tx in block.transactions if tx.tx_type != "coinbase_mining"}
            mined_txs = [t for t in self.pending_transactions if t.tx_id in mined_ids]
            self.pending_transactions = [t for t in self.pending_transactions if t.tx_id not in mined_ids]
            self.chain.append(block)
            if self._on_tx_confirmed:
                for tx in mined_txs:
                    self._on_tx_confirmed(tx)

            # Atualiza o cache incrementalmente: o estado validado nesta
            # chamada ja calculou `cached + block`; em vez de invalida-lo e
            # forcar um rebuild completo na proxima consulta, aplica o bloco
            # diretamente ao cache (in-place) — garantia: _cache_height aponta
            # para `len(chain) - 1` (antes do append) por duas vias:
            #   a) cache estava valido antes: _replay_state apenas copiou dele
            #   b) cache estava invalido: _replay_state rebuildo e setou height
            # Em ambos os casos `_cache_height == len(self.chain) - 1` agora.
            if self._cached_balances is not None and self._cache_height == len(self.chain) - 1:
                self._apply_block_to_contracts(self._cached_contracts_state, block, self._cached_balances)
                self._apply_block_to_balances(self._cached_balances, block)
                self._cache_height = len(self.chain)
            else:
                # Situacao inesperada (ex: chamada sem lock externo) — invalida
                # para garantir consistencia na proxima consulta.
                self._invalidate_state_cache()

            self.recent_miners.append(block.miner_address)
            if len(self.recent_miners) > 200:
                self.recent_miners = self.recent_miners[-200:]
            # a dificuldade-base da rede e recalculada com base no numero total de blocos
            # ja minerados (cresce 20x a cada 2 blocos, ate o teto do modo ativo)
            self.difficulty = self.difficulty_engine.base_difficulty_bits(self.mined_block_count)
            return True

    def is_chain_valid(self) -> bool:
        balances: dict = {}
        contracts_state = ContractsState()
        self._apply_block_to_contracts(contracts_state, self.chain[0], balances)
        self._apply_block_to_balances(balances, self.chain[0])
        for i in range(1, len(self.chain)):
            current, previous = self.chain[i], self.chain[i - 1]
            if current.previous_hash != previous.hash:
                return False
            if current.hash != current.compute_hash():
                return False
            if not current.meets_difficulty(current.hash):
                return False
            if current.timestamp < previous.timestamp + root_rules.MIN_BLOCK_TIMESTAMP_ADVANCE_SECONDS:
                return False
            for tx in current.transactions:
                if not tx.is_valid():
                    return False
            self._apply_block_to_contracts(contracts_state, current, balances)
            self._apply_block_to_balances(balances, current)
            if current.state_root != self._state_root_from_balances(balances):
                return False
            if current.contracts_root != self._contracts_root_from_state(contracts_state):
                return False
        return True

    def total_work(self) -> int:
        """Trabalho computacional acumulado de TODA a cadeia local (secao 1.3 do
        guia - regra de escolha de cadeia de Nakamoto). Usado pela rede P2P para
        decidir se uma cadeia concorrente recebida de um peer deve substituir a
        cadeia local: NUNCA "a cadeia com mais blocos", sempre a de maior
        trabalho acumulado (dificuldade efetivamente vencida)."""
        return sum(block_work(b.difficulty) for b in self.chain[1:])  # exclui o genesis (difficulty simbolica)

    @staticmethod
    def validate_candidate_chain(candidate: List[Block]) -> bool:
        """Valida uma cadeia INTEIRA recebida de um peer (desde o genesis) antes
        de sequer considerar substituir a cadeia local por ela - nunca confiar
        cegamente em dados vindos da rede (todo peer pode ser malicioso)."""
        if not candidate or candidate[0].index != 0 or candidate[0].previous_hash != "0" * 64:
            return False
        balances: dict = {}
        contracts_state = ContractsState()
        Blockchain._apply_block_to_contracts(contracts_state, candidate[0], balances)
        Blockchain._apply_block_to_balances(balances, candidate[0])
        if candidate[0].state_root != Blockchain._state_root_from_balances(balances):
            return False  # genesis com state_root incompativel (rede diferente ou dado corrompido)
        if candidate[0].contracts_root != Blockchain._contracts_root_from_state(contracts_state):
            return False
        for i in range(1, len(candidate)):
            current, previous = candidate[i], candidate[i - 1]
            if current.index != previous.index + 1:
                return False
            if current.previous_hash != previous.hash:
                return False
            if current.hash != current.compute_hash():
                return False
            if not current.meets_difficulty(current.hash):
                return False
            for tx in current.transactions:
                if not tx.is_valid():
                    return False
            Blockchain._apply_block_to_contracts(contracts_state, current, balances)
            Blockchain._apply_block_to_balances(balances, current)
            if current.state_root != Blockchain._state_root_from_balances(balances):
                return False  # state_root nao bate com o replay real dos saldos - bloco forjado
            if current.contracts_root != Blockchain._contracts_root_from_state(contracts_state):
                return False  # contracts_root nao bate com a execucao real da VM - bloco forjado
        return True

    def try_replace_chain(self, candidate: List[Block]) -> bool:
        """Regra de escolha de cadeia (fork choice / reorg) - secao 8.3 do guia:
        se uma cadeia concorrente recebida via P2P (`candidate`) tem MAIS
        trabalho acumulado que a local e e integralmente valida, substitui a
        cadeia local por ela. Transacoes que so existiam no ramo perdedor
        (nao presentes na nova cadeia) voltam para a mempool, se ainda validas,
        exatamente como um node Bitcoin/Ethereum real faz apos um reorg."""
        with self._chain_lock:
            if not self.validate_candidate_chain(candidate):
                return False
            if candidate[0].hash != self.chain[0].hash:
                return False  # genesis diferente = rede/fork incompativel, nunca adotar
            candidate_work = sum(block_work(b.difficulty) for b in candidate[1:])
            if candidate_work <= self.total_work():
                return False  # cadeia local ja e igual ou mais forte - nao faz nada (nunca regressao)

            old_tx_ids = {tx.tx_id for b in self.chain[1:] for tx in b.transactions}
            new_tx_ids = {tx.tx_id for b in candidate[1:] for tx in b.transactions}
            orphaned_tx_ids = old_tx_ids - new_tx_ids
            orphaned_txs = [
                tx for b in self.chain[1:] for tx in b.transactions
                if tx.tx_id in orphaned_tx_ids and tx.tx_type not in SYSTEM_TX_SENDERS
            ]

            self.chain = [self.chain[0]] + list(candidate[1:])
            self.recent_miners = [b.miner_address for b in self.chain[1:] if b.miner_address][-200:]
            self.difficulty = self.difficulty_engine.base_difficulty_bits(self.mined_block_count)
            # Reorg: a cadeia foi substituida por um ramo diferente (ponto de
            # bifurcacao desconhecido) — invalida o cache para evitar estado
            # "fantasma" do ramo descartado. O rebuild ocorre lazily na proxima
            # chamada a _replay_state (ex: ao minerar o proximo bloco).
            self._invalidate_state_cache()

            existing_pending_ids = {t.tx_id for t in self.pending_transactions}
            for tx in orphaned_txs:
                if tx.tx_id in existing_pending_ids or tx.tx_id in new_tx_ids:
                    continue
                if tx.is_valid():
                    self.pending_transactions.append(tx)
                    if self._on_tx_pending:
                        self._on_tx_pending(tx)
            return True
