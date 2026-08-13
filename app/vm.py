"""
Maquina virtual de smart contracts (secao 5 do guia "blockchain-do-zero.md") -
uma stack machine de 256 bits por slot, com gas metering em TODO opcode
(anti-DoS: sem isso um loop infinito no bytecode travaria o no sem custo),
storage persistente por contrato, e suporte a CALL entre contratos seguindo
RIGOROSAMENTE o padrao Checks-Effects-Interactions (protecao contra
reentrancy, o mesmo padrao de ataque do hack do The DAO em 2016).

Esta versao e uma VM "completa" no sentido do guia + praticas reais de
producao de uma EVM: TODA execucao (deploy, call, sub-call, constructor de
CREATE) e ATOMICA - qualquer falha (REVERT explicito, excecao de qualquer
natureza, out-of-gas, profundidade maxima) desfaz por completo QUALQUER
mutacao de storage/saldo/contratos criados/destruidos feita durante aquele
frame de chamada (e por inducao, todos os sub-frames aninhados dele), exatamente
como o guia exige na FASE 6 ("manter um snapshot do storage antes de iniciar a
execucao, e restaurar esse snapshot em caso de revert"). Sem isso, um
contrato que grava storage e DEPOIS reverte deixaria "sujeira" permanente no
estado - exatamente o tipo de "codigo quebrado fingindo funcionar" que o
protocolo NUNCA deve aceitar.

Simplificacoes DELIBERADAS em relacao ao guia/EVM (documentadas, como e
pratica deste projeto em todo modulo que se afasta do guia):
- Enderecos deterministicos de CREATE seguem SHA-256 do projeto (nao a formula
  Keccak+RLP do Ethereum), ainda que o opcode SHA3 da VM use o Keccak-256 REAL
  da EVM.
- Enderecos na pilha (256 bits) sao representados pelo inteiro do SHA-256
  do endereco Base58Check (nao pelo endereco "cru" de 20 bytes como na EVM,
  ja que o formato de endereco do PixCripto e Base58Check, nao hex de 20
  bytes) - a VM mantem uma tabela de resolucao (`ContractsState.intern_address`/
  `resolve_address`) para converter de volta ao endereco real quando
  necessario (ex.: BALANCE, CALL, EXTCODESIZE).
- O endereco deterministico de CREATE usa SHA-256(criador || nonce)
  diretamente, em vez da formula Ethereum baseada em RLP, para preservar o
  formato de endereco/Base58Check proprio do projeto.
- `MAX_CALL_DEPTH` e 200, nao 1024 (limite classico da EVM): a EVM roda numa
  maquina de pilha PROPRIA (nao usa a pilha de chamadas do interpretador
  hospedeiro), mas esta VM e implementada com recursao Python real
  (`VM.execute` chama a si mesma para cada sub-CALL) - o limite de recursao
  padrao do CPython (1000) seria estourado bem antes de 1024, contando com o
  resto da pilha de chamadas ja em uso (FastAPI/uvicorn/pytest). 200 e uma
  margem segura, documentada, sem abrir mao de suporte real a chamadas
  aninhadas em profundidade pratica.
- Opcodes de leitura de contexto de bloco (`TIMESTAMP`/`NUMBER`) e de preco de
  gas (`GASPRICE`) sao alimentados pelo chamador (`app/models.py`) a partir do
  bloco/tx real sendo processado - nunca de `time.time()` local da VM, para
  manter execucao 100% deterministica entre nos.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Dict, List, Optional, Tuple

from . import crypto_utils as _cu

UINT256_MASK = (1 << 256) - 1
UINT256_MOD = 1 << 256
MAX_STACK_SIZE = 1024
MAX_CALL_DEPTH = 200          # ver nota de simplificacao no topo do arquivo
MAX_MEMORY_BYTES = 1_048_576  # 1 MiB - teto rigido de memoria por frame (anti-DoS, alem do gas metering)


class Op(IntEnum):
    STOP = 0x00
    ADD = 0x01
    SUB = 0x02
    MUL = 0x03
    DIV = 0x04
    MOD = 0x05
    ADDMOD = 0x08
    MULMOD = 0x09
    EXP = 0x0A
    LT = 0x10
    GT = 0x11
    EQ = 0x12
    ISZERO = 0x13
    AND = 0x16
    OR = 0x17
    XOR = 0x18
    NOT = 0x15
    BYTE = 0x1A
    SHL = 0x1B
    SHR = 0x1C
    SAR = 0x1D
    SHA3 = 0x20
    ADDRESS = 0x30
    BALANCE = 0x31
    ORIGIN = 0x32
    CALLER = 0x33
    CALLVALUE = 0x34
    CALLDATALOAD = 0x35
    CALLDATASIZE = 0x36
    CALLDATACOPY = 0x37
    CODESIZE = 0x38
    CODECOPY = 0x39
    GASPRICE = 0x3A
    EXTCODESIZE = 0x3B
    RETURNDATASIZE = 0x3D
    RETURNDATACOPY = 0x3E
    TIMESTAMP = 0x42
    NUMBER = 0x43
    POP = 0x50
    MLOAD = 0x51
    MSTORE = 0x52
    SLOAD = 0x54
    SSTORE = 0x55
    JUMP = 0x56
    JUMPI = 0x57
    PC = 0x58
    MSIZE = 0x59
    GAS = 0x5A
    JUMPDEST = 0x5B   # necessario para validar destinos de JUMP/JUMPI com seguranca
    PUSH1 = 0x60      # PUSH1..PUSH32 = 0x60..0x7F
    DUP1 = 0x80        # DUP1..DUP16  = 0x80..0x8F
    SWAP1 = 0x90       # SWAP1..SWAP16 = 0x90..0x9F
    LOG0 = 0xA0        # LOG0..LOG4   = 0xA0..0xA4
    LOG1 = 0xA1
    LOG2 = 0xA2
    LOG3 = 0xA3
    LOG4 = 0xA4
    CREATE = 0xF0
    CALL = 0xF1
    CALLCODE = 0xF2
    RETURN = 0xF3
    DELEGATECALL = 0xF4
    STATICCALL = 0xFA
    REVERT = 0xFD
    SELFDESTRUCT = 0xFF


# Gas base por opcode (secao 5.2 do guia, mais os opcodes adicionais de
# completude listados no cabecalho do arquivo) - opcodes de PUSH/DUP/SWAP/LOG
# (que sao faixas, nao valores unicos) sao tratados a parte no loop principal,
# assim como os de custo dinamico (SHA3, EXP, *COPY, SSTORE).
GAS_COSTS: Dict[int, int] = {
    Op.STOP: 0, Op.ADD: 3, Op.SUB: 3, Op.MUL: 5, Op.DIV: 5, Op.MOD: 5,
    Op.ADDMOD: 8, Op.MULMOD: 8,
    Op.LT: 3, Op.GT: 3, Op.EQ: 3, Op.ISZERO: 3, Op.AND: 3, Op.OR: 3, Op.XOR: 3,
    Op.NOT: 3, Op.BYTE: 3, Op.SHL: 3, Op.SHR: 3, Op.SAR: 3,
    Op.SHA3: 30, Op.ADDRESS: 2, Op.BALANCE: 100, Op.ORIGIN: 2, Op.CALLER: 2, Op.CALLVALUE: 2,
    Op.CALLDATALOAD: 3, Op.CALLDATASIZE: 2, Op.CODESIZE: 2, Op.GASPRICE: 2,
    Op.EXTCODESIZE: 100, Op.RETURNDATASIZE: 2, Op.TIMESTAMP: 2, Op.NUMBER: 2,
    Op.POP: 2, Op.MLOAD: 3, Op.MSTORE: 3, Op.SLOAD: 200,
    Op.JUMP: 8, Op.JUMPI: 10, Op.PC: 2, Op.MSIZE: 2, Op.GAS: 2, Op.JUMPDEST: 1,
    Op.LOG0: 375,
    Op.CREATE: 32000, Op.CALL: 700, Op.STATICCALL: 700, Op.DELEGATECALL: 700, Op.CALLCODE: 700,
    Op.RETURN: 0, Op.REVERT: 0, Op.SELFDESTRUCT: 5000,
}
SSTORE_SET_COST = 20000     # slot estava zero -> agora tem valor (mais caro: novo storage)
SSTORE_UPDATE_COST = 5000   # slot ja tinha valor -> apenas atualiza
# Refund concedido quando SSTORE zera um slot que tinha valor != 0.
# Valor classico da EVM pre-EIP-3529: 15000 gas.
# Limite de aplicacao: min(gas_refund_acumulado, gas_used // 2) - limite "50%"
# da EVM classica (EIP-3529 reduziu para gas_used//5, optamos pelo classico
# por ser mais simples e documentado - ver README "Gaps de producao").
SSTORE_CLEAR_REFUND = 15000
MEMORY_WORD_COST = 3        # custo por palavra (32 bytes) de expansao de memoria
COPY_WORD_COST = 3          # custo por palavra copiada em *COPY (CALLDATACOPY/CODECOPY/RETURNDATACOPY)


class VMError(Exception):
    """Erro de execucao que reverte a chamada atual (e, por composicao com o
    mecanismo de snapshot/restore de `VM.execute`, TODA mutacao de estado
    feita durante aquele frame - storage, saldo, contratos criados/destruidos)."""


class OutOfGasError(VMError):
    pass


class InvalidJumpError(VMError):
    pass


class StackError(VMError):
    pass


class RevertedError(VMError):
    """Levantado pelo opcode REVERT explicito - carrega o motivo (string,
    para logs/API) e os dados de retorno brutos (bytes, para RETURNDATACOPY
    do chamador), unificando TODO caminho de rollback em um unico ponto do
    codigo (`VM.execute`'s except)."""

    def __init__(self, reason: str, data: bytes = b""):
        super().__init__(reason)
        self.data = data


@dataclass
class ExecutionResult:
    success: bool
    reverted: bool
    gas_used: int
    return_data: bytes = b""
    revert_reason: str = ""
    logs: List[dict] = field(default_factory=list)
    created_address: Optional[str] = None


@dataclass
class ContractAccount:
    address: str
    code: bytes
    creator: str
    storage: Dict[int, int] = field(default_factory=dict)
    nonce: int = 0


class ContractsState:
    """
    Estado GLOBAL de todos os contratos implantados neste no (analogo ao
    "world state" de contas com codigo, secao 2 do guia) - por simplicidade
    de escopo, mantido em memoria e persistido via snapshot em SQLite
    (`app/storage.py`), nao como uma Merkle Patricia Trie completa (mesma
    simplificacao ja documentada para o `state_root` da L1 - secao 1.5).
    """
    def __init__(self):
        self.contracts: Dict[str, ContractAccount] = {}
        self._address_table: Dict[int, str] = {}  # sha256(endereco)->endereco (resolucao p/ VM)

    def intern_address(self, address: str) -> int:
        """Registra um endereco (carteira normal OU contrato) na tabela de
        resolucao da VM e retorna sua representacao como inteiro de 256 bits
        (usada nos slots da pilha) - ver nota de simplificacao no topo do arquivo."""
        addr_int = int.from_bytes(hashlib.sha256(address.encode("utf-8")).digest(), "big")
        self._address_table[addr_int] = address
        return addr_int

    def resolve_address(self, addr_int: int) -> Optional[str]:
        return self._address_table.get(addr_int)

    def deterministic_contract_address(self, creator: str, creator_nonce: int) -> str:
        """Endereco deterministico do novo contrato (secao 5.5 do guia,
        adaptado para SHA-256 em vez de Keccak256+RLP - ver nota no topo)."""
        digest = hashlib.sha256(f"{creator}:{creator_nonce}".encode("utf-8")).digest()
        # reaproveita o MESMO formato Base58Check dos enderecos de carteira
        # normal (prefixo proprio do PixCripto) para que um contrato seja
        # indistinguivel de uma carteira comum apenas pelo formato da string.
        from . import crypto_utils
        import base58
        payload = bytes([crypto_utils.ADDRESS_VERSION_BYTE]) + digest[:20]
        checksum = crypto_utils.double_sha256(payload)[:4]
        return base58.b58encode(payload + checksum).decode("ascii")

    def deploy(self, creator: str, bytecode: bytes) -> ContractAccount:
        creator_nonce = sum(1 for c in self.contracts.values() if c.creator == creator)
        address = self.deterministic_contract_address(creator, creator_nonce)
        account = ContractAccount(address=address, code=bytecode, creator=creator)
        self.contracts[address] = account
        self.intern_address(address)
        return account

    def get(self, address: str) -> Optional[ContractAccount]:
        return self.contracts.get(address)


@dataclass
class CallContext:
    """Contexto de UMA chamada (top-level ou uma sub-CALL) - cada frame tem a
    sua propria (pilha/memoria/PC vivem no loop de `VM.execute`); a `storage`
    e compartilhada por CONTRATO (nao por frame), pois e persistente."""
    contract: ContractAccount
    caller: str
    call_value: int
    calldata: bytes
    depth: int = 0
    origin: Optional[str] = None   # remetente ORIGINAL da transacao (tx.origin) - None no nivel raiz = usa `caller`
    static: bool = False           # True dentro de um STATICCALL: proibe QUALQUER mutacao de estado


# Tipo de um snapshot de estado, usado para rollback atomico de um frame:
# (contas existentes antes do frame, copia do storage de cada uma, copia dos saldos, gas_refund salvo)
_StateSnapshot = Tuple[Dict[str, ContractAccount], Dict[str, Dict[int, int]], Optional[dict], int]


class VM:
    """
    Interpretador da stack machine. Uma instancia e criada POR TRANSACAO
    (nao e reutilizada entre execucoes) - o `gas_remaining` e compartilhado
    entre TODOS os frames de CALL/CREATE/STATICCALL aninhados desta mesma
    transacao.
    """
    def __init__(self, state: ContractsState, gas_limit: int,
                 get_balance: Optional[Callable[[str], float]] = None,
                 balances: Optional[dict] = None,
                 block_timestamp: float = 0.0, block_number: int = 0,
                 gas_price: float = 0.0):
        self.state = state
        self.gas_remaining = gas_limit
        # `balances`: dict MUTAVEL de saldos reais (mesmo dict usado pelo L1
        # em `Blockchain._apply_block_to_balances`) - permite que CALL/CREATE
        # com `value` transfiram saldo PXC de verdade entre contratos durante
        # a execucao (nao apenas simulem no valor de retorno). Se None (ex.:
        # `/contracts/estimate-gas`, um dry-run que roda sobre uma copia
        # descartavel do estado, propositalmente sem side effects reais),
        # a VM cai para um modo somente-leitura: BALANCE consulta normalmente,
        # mas transferencias internas de `value` sempre "sucedem" sem mover
        # nada de verdade (documentado - dry-run nao deve nunca falhar por
        # saldo insuficiente de forma que nao reflita o estado real).
        self.balances = balances
        if balances is not None:
            self.get_balance: Callable[[str], float] = lambda addr: balances.get(addr, 0.0)
        else:
            self.get_balance = get_balance or (lambda addr: 0.0)
        self.block_timestamp = block_timestamp
        self.block_number = block_number
        self.gas_price = gas_price
        # guarda de reentrancia: contratos com um frame de CALL ainda ativo -
        # reforca, no nivel do protocolo, o padrao Checks-Effects-Interactions
        # exigido pelo guia (secao 5.4): mesmo que o bytecode de um contrato
        # malicioso tente reentrar durante uma CALL externa, a VM recusa
        # (protecao adicional alem da disciplina de codigo recomendada ao
        # autor do contrato pelo proprio guia).
        self._active_contracts: set = set()
        # Contador de refund acumulado por execucao (SSTORE_REFUND classico).
        # Aplicado ao final da execucao de nivel 0 (depth=0), limitado a gas_used//2.
        # Reset via _snapshot/_restore quando sub-calls revertem.
        self.gas_refund: int = 0

    # -- snapshot/rollback atomico (FASE 6 do guia: "manter snapshot do storage
    # antes de iniciar a execucao, e restaurar em caso de revert") ----------

    def _snapshot(self) -> _StateSnapshot:
        existing_accounts = dict(self.state.contracts)  # mesmas referencias de objeto (identidade preservada)
        storage_copy = {addr: dict(acc.storage) for addr, acc in self.state.contracts.items()}
        balances_copy = dict(self.balances) if self.balances is not None else None
        return existing_accounts, storage_copy, balances_copy, self.gas_refund

    def _restore(self, snapshot: _StateSnapshot) -> None:
        existing_accounts, storage_copy, balances_copy, saved_gas_refund = snapshot
        self.gas_refund = saved_gas_refund
        # 1) remove contratos criados DURANTE este frame (via CREATE) que nao existiam antes
        for addr in list(self.state.contracts.keys()):
            if addr not in existing_accounts:
                del self.state.contracts[addr]
        # 2) restaura contratos destruidos DURANTE este frame (via SELFDESTRUCT)
        for addr, account in existing_accounts.items():
            if addr not in self.state.contracts:
                self.state.contracts[addr] = account
        # 3) restaura o CONTEUDO do storage de toda conta que ja existia antes do frame,
        #    em memoria (mesmo objeto `ContractAccount`, para nao quebrar referencias
        #    que frames ancestrais ainda possam manter)
        for addr, storage in storage_copy.items():
            account = self.state.contracts.get(addr)
            if account is not None:
                account.storage.clear()
                account.storage.update(storage)
        # 4) restaura saldos PXC movidos por `value` durante este frame
        if self.balances is not None and balances_copy is not None:
            self.balances.clear()
            self.balances.update(balances_copy)

    def _transfer(self, from_addr: str, to_addr: str, value_units: int) -> bool:
        """Transfere `value_units` (inteiro em escala fixed-point 1e8, mesma
        escala usada pelo opcode BALANCE) de `from_addr` para `to_addr`, no
        dict `balances` compartilhado com o L1. Retorna False (sem mutar nada)
        se o saldo de origem for insuficiente. Em modo somente-leitura
        (`balances is None`, ex.: estimate-gas) sempre "sucede" sem mover nada."""
        if value_units <= 0:
            return True
        if self.balances is None:
            return True
        value_pxc = value_units / 10 ** 8
        available = self.balances.get(from_addr, 0.0)
        if available + 1e-12 < value_pxc:
            return False
        self.balances[from_addr] = round(available - value_pxc, 8)
        self.balances[to_addr] = round(self.balances.get(to_addr, 0.0) + value_pxc, 8)
        return True

    def execute(self, ctx: CallContext) -> ExecutionResult:
        if ctx.depth > MAX_CALL_DEPTH:
            return ExecutionResult(False, True, 0, revert_reason="Profundidade maxima de chamada excedida")
        if ctx.contract.address in self._active_contracts:
            return ExecutionResult(False, True, 0, revert_reason="Reentrancia bloqueada pela VM")

        origin = ctx.origin or ctx.caller
        snapshot = self._snapshot()
        self._active_contracts.add(ctx.contract.address)
        gas_start = self.gas_remaining
        stack: List[int] = []
        memory = bytearray()
        logs: List[dict] = []
        last_return_data = b""
        pc = 0
        code = ctx.contract.code

        def charge(amount: int) -> None:
            if amount > self.gas_remaining:
                raise OutOfGasError(f"Gas insuficiente (necessario {amount}, restante {self.gas_remaining})")
            self.gas_remaining -= amount

        def pop() -> int:
            if not stack:
                raise StackError("Stack underflow")
            return stack.pop()

        def push(value: int) -> None:
            if len(stack) >= MAX_STACK_SIZE:
                raise StackError("Stack overflow (limite de 1024 itens)")
            stack.append(value & UINT256_MASK)

        def ensure_memory(offset: int, size: int) -> None:
            if size == 0:
                return
            needed = offset + size
            if needed > MAX_MEMORY_BYTES:
                raise VMError(f"Memoria excede o limite maximo de {MAX_MEMORY_BYTES} bytes (pedido: {needed})")
            if needed <= len(memory):
                return
            words_before = (len(memory) + 31) // 32
            words_after = (needed + 31) // 32
            charge((words_after - words_before) * MEMORY_WORD_COST)
            memory.extend(b"\x00" * (words_after * 32 - len(memory)))

        try:
            while pc < len(code):
                opcode = code[pc]
                if Op.PUSH1 <= opcode <= 0x7F:
                    n = opcode - Op.PUSH1 + 1
                    charge(3)
                    value = int.from_bytes(code[pc + 1:pc + 1 + n].ljust(n, b"\x00"), "big")
                    push(value)
                    pc += 1 + n
                    continue
                if Op.DUP1 <= opcode <= 0x8F:
                    n = opcode - Op.DUP1 + 1
                    charge(3)
                    if len(stack) < n:
                        raise StackError("DUP: stack insuficiente")
                    push(stack[-n])
                    pc += 1
                    continue
                if Op.SWAP1 <= opcode <= 0x9F:
                    n = opcode - Op.SWAP1 + 1
                    charge(3)
                    if len(stack) < n + 1:
                        raise StackError("SWAP: stack insuficiente")
                    stack[-1], stack[-1 - n] = stack[-1 - n], stack[-1]
                    pc += 1
                    continue
                if Op.LOG0 <= opcode <= 0xA4:
                    if ctx.static:
                        raise VMError("LOG nao permitido em contexto STATICCALL")
                    n_topics = opcode - Op.LOG0
                    charge(GAS_COSTS[Op.LOG0] + n_topics * 375)
                    offset, size = pop(), pop()
                    ensure_memory(offset, size)
                    topics = [pop() for _ in range(n_topics)]
                    logs.append({
                        "address": ctx.contract.address,
                        "topics": [hex(t) for t in topics],
                        "data": bytes(memory[offset:offset + size]).hex(),
                    })
                    pc += 1
                    continue

                if opcode == Op.STOP:
                    break
                elif opcode == Op.ADD:
                    charge(GAS_COSTS[opcode]); a, b = pop(), pop(); push(a + b)
                elif opcode == Op.SUB:
                    charge(GAS_COSTS[opcode]); a, b = pop(), pop(); push(a - b)
                elif opcode == Op.MUL:
                    charge(GAS_COSTS[opcode]); a, b = pop(), pop(); push(a * b)
                elif opcode == Op.DIV:
                    charge(GAS_COSTS[opcode]); a, b = pop(), pop(); push(0 if b == 0 else a // b)
                elif opcode == Op.MOD:
                    charge(GAS_COSTS[opcode]); a, b = pop(), pop(); push(0 if b == 0 else a % b)
                elif opcode == Op.ADDMOD:
                    charge(GAS_COSTS[opcode]); a, b, n = pop(), pop(), pop(); push(0 if n == 0 else (a + b) % n)
                elif opcode == Op.MULMOD:
                    charge(GAS_COSTS[opcode]); a, b, n = pop(), pop(), pop(); push(0 if n == 0 else (a * b) % n)
                elif opcode == Op.EXP:
                    base, exponent = pop(), pop()
                    exp_bytes = (exponent.bit_length() + 7) // 8
                    charge(10 + 10 * exp_bytes)
                    push(pow(base, exponent, UINT256_MOD))
                elif opcode == Op.LT:
                    charge(GAS_COSTS[opcode]); a, b = pop(), pop(); push(1 if a < b else 0)
                elif opcode == Op.GT:
                    charge(GAS_COSTS[opcode]); a, b = pop(), pop(); push(1 if a > b else 0)
                elif opcode == Op.EQ:
                    charge(GAS_COSTS[opcode]); a, b = pop(), pop(); push(1 if a == b else 0)
                elif opcode == Op.ISZERO:
                    charge(GAS_COSTS[opcode]); a = pop(); push(1 if a == 0 else 0)
                elif opcode == Op.AND:
                    charge(GAS_COSTS[opcode]); a, b = pop(), pop(); push(a & b)
                elif opcode == Op.OR:
                    charge(GAS_COSTS[opcode]); a, b = pop(), pop(); push(a | b)
                elif opcode == Op.XOR:
                    charge(GAS_COSTS[opcode]); a, b = pop(), pop(); push(a ^ b)
                elif opcode == Op.NOT:
                    charge(GAS_COSTS[opcode]); a = pop(); push((~a) & UINT256_MASK)
                elif opcode == Op.BYTE:
                    charge(GAS_COSTS[opcode])
                    i, x = pop(), pop()
                    push(0 if i >= 32 else (x >> (8 * (31 - i))) & 0xFF)
                elif opcode == Op.SHL:
                    charge(GAS_COSTS[opcode])
                    shift, value = pop(), pop()
                    push(0 if shift >= 256 else (value << shift))
                elif opcode == Op.SHR:
                    charge(GAS_COSTS[opcode])
                    shift, value = pop(), pop()
                    push(0 if shift >= 256 else (value >> shift))
                elif opcode == Op.SAR:
                    charge(GAS_COSTS[opcode])
                    shift, value = pop(), pop()
                    signed = value - UINT256_MOD if value >= (1 << 255) else value
                    if shift >= 256:
                        result = -1 if signed < 0 else 0
                    else:
                        result = signed >> shift
                    push(result & UINT256_MASK)
                elif opcode == Op.SHA3:
                    offset, size = pop(), pop()
                    ensure_memory(offset, size)
                    charge(GAS_COSTS[opcode] + 6 * ((size + 31) // 32))
                    digest = _cu.keccak256(bytes(memory[offset:offset + size]))
                    push(int.from_bytes(digest, "big"))
                elif opcode == Op.ADDRESS:
                    charge(GAS_COSTS[opcode]); push(self.state.intern_address(ctx.contract.address))
                elif opcode == Op.BALANCE:
                    charge(GAS_COSTS[opcode])
                    addr_int = pop()
                    addr = self.state.resolve_address(addr_int)
                    balance = self.get_balance(addr) if addr else 0.0
                    push(int(round(balance * 10 ** 8)))  # fixed-point de 8 casas decimais (mesma escala do PXC)
                elif opcode == Op.ORIGIN:
                    charge(GAS_COSTS[opcode]); push(self.state.intern_address(origin))
                elif opcode == Op.CALLER:
                    charge(GAS_COSTS[opcode]); push(self.state.intern_address(ctx.caller))
                elif opcode == Op.CALLVALUE:
                    charge(GAS_COSTS[opcode]); push(ctx.call_value)
                elif opcode == Op.CALLDATALOAD:
                    charge(GAS_COSTS[opcode])
                    offset = pop()
                    chunk = ctx.calldata[offset:offset + 32].ljust(32, b"\x00")
                    push(int.from_bytes(chunk, "big"))
                elif opcode == Op.CALLDATASIZE:
                    charge(GAS_COSTS[opcode]); push(len(ctx.calldata))
                elif opcode == Op.CALLDATACOPY:
                    dest_offset, offset, size = pop(), pop(), pop()
                    ensure_memory(dest_offset, size)
                    charge(3 + COPY_WORD_COST * ((size + 31) // 32))
                    chunk = ctx.calldata[offset:offset + size].ljust(size, b"\x00")
                    memory[dest_offset:dest_offset + size] = chunk
                elif opcode == Op.CODESIZE:
                    charge(GAS_COSTS[opcode]); push(len(code))
                elif opcode == Op.CODECOPY:
                    dest_offset, offset, size = pop(), pop(), pop()
                    ensure_memory(dest_offset, size)
                    charge(3 + COPY_WORD_COST * ((size + 31) // 32))
                    chunk = code[offset:offset + size].ljust(size, b"\x00")
                    memory[dest_offset:dest_offset + size] = chunk
                elif opcode == Op.GASPRICE:
                    charge(GAS_COSTS[opcode]); push(int(round(self.gas_price * 10 ** 8)))
                elif opcode == Op.EXTCODESIZE:
                    charge(GAS_COSTS[opcode])
                    addr_int = pop()
                    addr = self.state.resolve_address(addr_int)
                    account = self.state.contracts.get(addr) if addr else None
                    push(len(account.code) if account else 0)
                elif opcode == Op.RETURNDATASIZE:
                    charge(GAS_COSTS[opcode]); push(len(last_return_data))
                elif opcode == Op.RETURNDATACOPY:
                    dest_offset, offset, size = pop(), pop(), pop()
                    if offset + size > len(last_return_data):
                        raise VMError("RETURNDATACOPY fora dos limites dos dados de retorno")
                    ensure_memory(dest_offset, size)
                    charge(3 + COPY_WORD_COST * ((size + 31) // 32))
                    memory[dest_offset:dest_offset + size] = last_return_data[offset:offset + size]
                elif opcode == Op.TIMESTAMP:
                    charge(GAS_COSTS[opcode]); push(int(self.block_timestamp))
                elif opcode == Op.NUMBER:
                    charge(GAS_COSTS[opcode]); push(int(self.block_number))
                elif opcode == Op.POP:
                    charge(GAS_COSTS[opcode]); pop()
                elif opcode == Op.MLOAD:
                    charge(GAS_COSTS[opcode])
                    offset = pop()
                    ensure_memory(offset, 32)
                    push(int.from_bytes(memory[offset:offset + 32], "big"))
                elif opcode == Op.MSTORE:
                    charge(GAS_COSTS[opcode])
                    offset, value = pop(), pop()
                    ensure_memory(offset, 32)
                    memory[offset:offset + 32] = value.to_bytes(32, "big")
                elif opcode == Op.SLOAD:
                    charge(GAS_COSTS[opcode])
                    key = pop()
                    push(ctx.contract.storage.get(key, 0))
                elif opcode == Op.SSTORE:
                    if ctx.static:
                        raise VMError("SSTORE nao permitido em contexto STATICCALL")
                    key, value = pop(), pop()
                    prev_value = ctx.contract.storage.get(key, 0)
                    was_zero = prev_value == 0
                    charge(SSTORE_SET_COST if (was_zero and value != 0) else SSTORE_UPDATE_COST)
                    # EFFECTS antes de qualquer INTERACTION futura (CEI): a
                    # mutacao de storage e aplicada IMEDIATAMENTE ao dict
                    # persistente do contrato, nunca atrasada/bufferizada,
                    # para que uma CALL subsequente no MESMO bytecode ja
                    # veja o estado ja atualizado (pre-requisito do CEI). Se
                    # esta chamada (ou uma ancestral) reverter mais tarde, o
                    # snapshot/restore do frame desfaz esta escrita (ver
                    # `_snapshot`/`_restore`).
                    # SSTORE_REFUND classico: limpar um slot nao-zero concede refund de gas
                    # (EVM pre-EIP-3529; incentivo economico para liberar storage - equivalente
                    # a "devolver" ao estado inicial e cobrar menos da rede).
                    if value == 0 and not was_zero:
                        self.gas_refund += SSTORE_CLEAR_REFUND
                    if value == 0:
                        ctx.contract.storage.pop(key, None)
                    else:
                        ctx.contract.storage[key] = value
                elif opcode == Op.JUMP:
                    charge(GAS_COSTS[opcode])
                    dest = pop()
                    if dest < 0 or dest >= len(code) or code[dest] != Op.JUMPDEST:
                        raise InvalidJumpError(f"Destino de JUMP invalido: {dest}")
                    pc = dest
                    continue
                elif opcode == Op.JUMPI:
                    charge(GAS_COSTS[opcode])
                    dest, cond = pop(), pop()
                    if cond != 0:
                        if dest < 0 or dest >= len(code) or code[dest] != Op.JUMPDEST:
                            raise InvalidJumpError(f"Destino de JUMPI invalido: {dest}")
                        pc = dest
                        continue
                elif opcode == Op.PC:
                    charge(GAS_COSTS[opcode]); push(pc)
                elif opcode == Op.MSIZE:
                    charge(GAS_COSTS[opcode]); push(len(memory))
                elif opcode == Op.GAS:
                    charge(GAS_COSTS[opcode]); push(self.gas_remaining)
                elif opcode == Op.JUMPDEST:
                    charge(GAS_COSTS[opcode])
                elif opcode == Op.CREATE:
                    if ctx.static:
                        raise VMError("CREATE nao permitido em contexto STATICCALL")
                    charge(GAS_COSTS[opcode])
                    value, offset, size = pop(), pop(), pop()
                    ensure_memory(offset, size)
                    init_code = bytes(memory[offset:offset + size])
                    new_account = self.state.deploy(ctx.contract.address, init_code)
                    if value > 0 and not self._transfer(ctx.contract.address, new_account.address, value):
                        self.state.contracts.pop(new_account.address, None)
                        push(0)
                    else:
                        sub_ctx = CallContext(
                            contract=new_account, caller=ctx.contract.address, call_value=value,
                            calldata=b"", depth=ctx.depth + 1, origin=origin, static=False,
                        )
                        result = self.execute(sub_ctx)
                        if result.success:
                            logs.extend(result.logs)
                            push(self.state.intern_address(new_account.address))
                        else:
                            # construtor reverteu -> desfaz o deploy inteiro (contrato
                            # nao deve passar a existir) e devolve o valor enviado
                            self.state.contracts.pop(new_account.address, None)
                            if value > 0:
                                self._transfer(new_account.address, ctx.contract.address, value)
                            push(0)
                elif opcode in (Op.CALL, Op.STATICCALL):
                    is_static_call = opcode == Op.STATICCALL
                    charge(GAS_COSTS[opcode])
                    if is_static_call:
                        call_gas, to_int, in_off, in_size, out_off, out_size = (
                            pop(), pop(), pop(), pop(), pop(), pop()
                        )
                        value = 0
                    else:
                        call_gas, to_int, value, in_off, in_size, out_off, out_size = (
                            pop(), pop(), pop(), pop(), pop(), pop(), pop()
                        )
                        if ctx.static and value != 0:
                            raise VMError("Transferencia de valor nao permitida em contexto STATICCALL")
                    ensure_memory(in_off, in_size)
                    target_addr = self.state.resolve_address(to_int)
                    value_ok = True
                    if value > 0:
                        value_ok = target_addr is not None and self._transfer(ctx.contract.address, target_addr, value)
                    if not value_ok:
                        push(0)
                        last_return_data = b""
                    else:
                        target = self.state.contracts.get(target_addr) if target_addr else None
                        if target is None:
                            # endereco desconhecido, OU carteira comum (EOA) sem
                            # codigo: se chegou aqui e porque o valor (se houver)
                            # ja foi transferido com sucesso - trata como uma
                            # simples transferencia de valor bem sucedida (sem
                            # execucao de codigo), igual a uma EVM real chamando
                            # um EOA. Endereco totalmente desconhecido = falha.
                            push(1 if target_addr is not None else 0)
                            last_return_data = b""
                        else:
                            sub_ctx = CallContext(
                                contract=target, caller=ctx.contract.address, call_value=value,
                                calldata=bytes(memory[in_off:in_off + in_size]), depth=ctx.depth + 1,
                                origin=origin, static=(ctx.static or is_static_call),
                            )
                            gas_before_sub_call = self.gas_remaining
                            capped = min(call_gas, gas_before_sub_call)
                            self.gas_remaining = capped
                            result = self.execute(sub_ctx)
                            spent_by_sub = capped - self.gas_remaining
                            self.gas_remaining = gas_before_sub_call - spent_by_sub
                            ensure_memory(out_off, out_size)
                            data = result.return_data[:out_size].ljust(out_size, b"\x00")
                            memory[out_off:out_off + out_size] = data
                            last_return_data = result.return_data
                            if result.success:
                                logs.extend(result.logs)
                            push(1 if result.success else 0)
                elif opcode in (Op.DELEGATECALL, Op.CALLCODE):
                    is_delegate = opcode == Op.DELEGATECALL
                    charge(GAS_COSTS[opcode])
                    # Stack: gas, to, in_off, in_size, out_off, out_size (sem 'value' - ambos preservam o value atual)
                    call_gas, to_int, in_off, in_size, out_off, out_size = (
                        pop(), pop(), pop(), pop(), pop(), pop()
                    )
                    if ctx.static:
                        raise VMError("DELEGATECALL/CALLCODE nao permitido em contexto STATICCALL")
                    ensure_memory(in_off, in_size)
                    target_addr = self.state.resolve_address(to_int)
                    target = self.state.contracts.get(target_addr) if target_addr else None
                    if target is None:
                        push(0)
                        last_return_data = b""
                    else:
                        # Cria uma "conta virtual" que tem o CODIGO do alvo mas o STORAGE e o
                        # ENDERECO do contrato atual - e a essencia de DELEGATECALL/CALLCODE:
                        # executar logica externa ("library") no contexto de armazenamento local.
                        virtual_account = ContractAccount(
                            address=ctx.contract.address,   # ADDRESS opcode retorna ESTE contrato
                            code=target.code,               # mas EXECUTA o codigo do alvo
                            creator=target.creator,
                            storage=ctx.contract.storage,   # mesmo dict -> mutacoes vao para este contrato
                            nonce=ctx.contract.nonce,
                        )
                        if is_delegate:
                            # DELEGATECALL: msg.sender = quem chamou ESTE contrato (ctx.caller),
                            # msg.value = value desta chamada (ctx.call_value).
                            # Semantica: "como se o codigo da lib fosse parte deste contrato".
                            sub_caller = ctx.caller
                            sub_value = ctx.call_value
                        else:
                            # CALLCODE: msg.sender = ESTE contrato (ctx.contract.address),
                            # msg.value = 0 (CALLCODE nao transfere valor automaticamente).
                            # Semantica: mais antiga que DELEGATECALL, preserva caller como este contrato.
                            sub_caller = ctx.contract.address
                            sub_value = 0
                        sub_ctx = CallContext(
                            contract=virtual_account,
                            caller=sub_caller,
                            call_value=sub_value,
                            calldata=bytes(memory[in_off:in_off + in_size]),
                            depth=ctx.depth + 1,
                            origin=origin,
                            static=ctx.static,
                        )
                        gas_before = self.gas_remaining
                        capped = min(call_gas, gas_before)
                        self.gas_remaining = capped
                        # Remove temporariamente do guard de reentrancia: DELEGATECALL/CALLCODE
                        # executa NO MESMO endereco (virtual_account.address == ctx.contract.address),
                        # entao o guard bloquearia a sub-execucao. Remove antes do execute() -
                        # que vai READICIONAR o endereco como primeira acao - garantindo que
                        # qualquer CALL nested de volta para este endereco ainda e bloqueado.
                        self._active_contracts.discard(ctx.contract.address)
                        try:
                            sub_result = self.execute(sub_ctx)
                        finally:
                            self._active_contracts.add(ctx.contract.address)
                        spent = capped - self.gas_remaining
                        self.gas_remaining = gas_before - spent
                        ensure_memory(out_off, out_size)
                        data = sub_result.return_data[:out_size].ljust(out_size, b"\x00")
                        memory[out_off:out_off + out_size] = data
                        last_return_data = sub_result.return_data
                        if sub_result.success:
                            logs.extend(sub_result.logs)
                        push(1 if sub_result.success else 0)
                elif opcode == Op.RETURN:
                    offset, size = pop(), pop()
                    ensure_memory(offset, size)
                    return_data = bytes(memory[offset:offset + size])
                    gas_used = gas_start - self.gas_remaining
                    if ctx.depth == 0:
                        # Aplica SSTORE_REFUND acumulado, limitado a 50% do gas usado
                        # (limite classico da EVM pre-EIP-3529 - escolhemos 50% por ser o
                        # padrao historico; EIP-3529 reduziu para 20% para mitigar "gas
                        # token" abuse, mas nao e relevante para este prototipo).
                        effective_refund = min(self.gas_refund, gas_used // 2)
                        self.gas_remaining += effective_refund
                        gas_used -= effective_refund
                    return ExecutionResult(True, False, gas_used, return_data, logs=logs)
                elif opcode == Op.REVERT:
                    offset, size = pop(), pop()
                    ensure_memory(offset, size)
                    reason_bytes = bytes(memory[offset:offset + size])
                    reason = reason_bytes.decode("utf-8", errors="replace")
                    raise RevertedError(reason, reason_bytes)
                elif opcode == Op.SELFDESTRUCT:
                    if ctx.static:
                        raise VMError("SELFDESTRUCT nao permitido em contexto STATICCALL")
                    charge(GAS_COSTS[opcode])
                    beneficiary_int = pop()
                    beneficiary = self.state.resolve_address(beneficiary_int)
                    remaining_balance = self.get_balance(ctx.contract.address)
                    if beneficiary and remaining_balance > 0:
                        self._transfer(ctx.contract.address, beneficiary,
                                        int(round(remaining_balance * 10 ** 8)))
                    self.state.contracts.pop(ctx.contract.address, None)
                    break
                else:
                    raise VMError(f"Opcode desconhecido: 0x{opcode:02x}")
                pc += 1

            gas_used = gas_start - self.gas_remaining
            if ctx.depth == 0:
                effective_refund = min(self.gas_refund, gas_used // 2)
                self.gas_remaining += effective_refund
                gas_used -= effective_refund
            return ExecutionResult(True, False, gas_used, logs=logs)
        except (VMError, RecursionError, MemoryError, OverflowError,
                ValueError, TypeError, IndexError, KeyError) as exc:
            # QUALQUER falha (revert explicito, out-of-gas, jump invalido,
            # stack under/overflow, ou mesmo um bug inesperado de bytecode
            # malformado) e sempre uma excecao CONTROLADA que reverte -
            # jamais um crash do processo (requisito de fuzzing da FASE 6 do
            # guia) - e desfaz TODA mutacao de estado feita neste frame.
            self._restore(snapshot)
            gas_used = gas_start - self.gas_remaining
            if isinstance(exc, RevertedError):
                return ExecutionResult(False, True, gas_used, return_data=exc.data, revert_reason=str(exc))
            return ExecutionResult(False, True, gas_used, revert_reason=str(exc))
        finally:
            self._active_contracts.discard(ctx.contract.address)
