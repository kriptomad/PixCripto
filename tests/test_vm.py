"""
Testes da maquina virtual de smart contracts (secao 5 do guia).

Cobre: opcodes aritmeticos/stack basicos, storage persistente entre chamadas
(SLOAD/SSTORE), REVERT explicito, out-of-gas, CALL entre contratos com
protecao de reentrancia (Checks-Effects-Interactions), enderecos
deterministicos de CREATE/deploy, e a integracao completa com a blockchain
(contract_deploy/contract_call minerados de verdade, contracts_root
verificado por replay, sobrevivencia a reorg simulado).
"""
import pytest

from app import crypto_utils
from app.mining import mine_block
from app.models import Blockchain, Transaction
from app.vm import (
    CallContext, ContractsState, InvalidJumpError, Op, OutOfGasError, VM,
)


def _mine_and_submit(chain: Blockchain, miner_address: str):
    block = chain.build_candidate_block(miner_address)
    result = mine_block(block, max_iterations=5_000_000, prefer_gpu=False)
    assert chain.submit_mined_block(block, result.nonce, result.block_hash)
    return block


def _fund(chain: Blockchain, address: str, amount: float = 100.0):
    tx = Transaction(sender="SISTEMA_EMISSAO", recipient=address, amount=amount, tx_type="coinbase_purchase")
    assert chain.add_transaction(tx)
    _mine_and_submit(chain, address)


# ---------------------------------------------------------------------------
# Testes de baixo nivel da VM (sem a blockchain)
# ---------------------------------------------------------------------------

def test_arithmetic_and_comparison_opcodes():
    state = ContractsState()
    # PUSH1 5, PUSH1 3, ADD, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN -> retorna 8
    code = bytes([Op.PUSH1, 5, Op.PUSH1, 3, Op.ADD, Op.PUSH1, 0, Op.MSTORE,
                  Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    account = state.deploy("CreatorA", code)
    vm = VM(state, gas_limit=100_000)
    result = vm.execute(CallContext(contract=account, caller="CreatorA", call_value=0, calldata=b"", depth=0))
    assert result.success
    assert int.from_bytes(result.return_data, "big") == 8


def test_storage_persists_across_calls():
    state = ContractsState()
    # contador: SLOAD(0), PUSH1 1, ADD, DUP1, PUSH1 0, SSTORE, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
    code = bytes([Op.PUSH1, 0, Op.SLOAD, Op.PUSH1, 1, Op.ADD, Op.DUP1, Op.PUSH1, 0, Op.SSTORE,
                  Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    account = state.deploy("CreatorA", code)
    ctx = CallContext(contract=account, caller="CreatorA", call_value=0, calldata=b"", depth=0)
    r1 = VM(state, 100_000).execute(ctx)
    r2 = VM(state, 100_000).execute(ctx)
    r3 = VM(state, 100_000).execute(ctx)
    assert [int.from_bytes(r.return_data, "big") for r in (r1, r2, r3)] == [1, 2, 3]
    assert account.storage[0] == 3


def test_revert_rolls_back_and_reports_reason():
    state = ContractsState()
    # grava em storage ANTES do revert -> deve ser descartado (mesma transacao)
    # PUSH1 1, PUSH1 0, SSTORE, PUSH1 0, PUSH1 0, REVERT
    code = bytes([Op.PUSH1, 1, Op.PUSH1, 0, Op.SSTORE, Op.PUSH1, 0, Op.PUSH1, 0, Op.REVERT])
    account = state.deploy("CreatorA", code)
    result = VM(state, 100_000).execute(
        CallContext(contract=account, caller="CreatorA", call_value=0, calldata=b"", depth=0)
    )
    assert not result.success
    assert result.reverted
    # CRITICO (FASE 6 do guia): a escrita de storage feita ANTES do REVERT
    # precisa ser desfeita por completo - sem isso, um contrato que reverte
    # deixaria "sujeira" permanente no estado (exatamente o tipo de bug que
    # tornaria a VM "quebrada fingindo funcionar").
    assert account.storage.get(0, 0) == 0


def test_exception_mid_execution_also_rolls_back_prior_storage_writes():
    """Nao e so o REVERT explicito que precisa desfazer storage - QUALQUER
    excecao (aqui: um JUMP invalido apos uma escrita bem sucedida) tambem
    deve reverter TUDO que o frame havia feito ate aquele ponto."""
    state = ContractsState()
    # SSTORE(0, 99), depois PUSH um destino de JUMP invalido -> InvalidJumpError
    code = bytes([Op.PUSH1, 99, Op.PUSH1, 0, Op.SSTORE, Op.PUSH1, 0x08, Op.JUMP, Op.STOP])
    account = state.deploy("CreatorA", code)
    result = VM(state, 100_000).execute(
        CallContext(contract=account, caller="CreatorA", call_value=0, calldata=b"", depth=0)
    )
    assert not result.success
    assert account.storage.get(0, 0) == 0


def test_out_of_gas_raises_and_reverts():
    state = ContractsState()
    code = bytes([Op.PUSH1, 1, Op.PUSH1, 2, Op.ADD])
    account = state.deploy("CreatorA", code)
    result = VM(state, gas_limit=1).execute(  # gas insuficiente ate para o primeiro PUSH1 (custo 3)
        CallContext(contract=account, caller="CreatorA", call_value=0, calldata=b"", depth=0)
    )
    assert not result.success
    assert result.reverted
    assert "Gas insuficiente" in result.revert_reason


def test_invalid_jump_destination_is_rejected():
    state = ContractsState()
    # JUMP para um destino que nao e JUMPDEST deve ser rejeitado
    code = bytes([Op.PUSH1, 0x05, Op.JUMP, Op.STOP, Op.STOP, Op.ADD])
    account = state.deploy("CreatorA", code)
    result = VM(state, 100_000).execute(
        CallContext(contract=account, caller="CreatorA", call_value=0, calldata=b"", depth=0)
    )
    assert not result.success
    assert "invalido" in result.revert_reason.lower()


def test_calldataload_reads_calldata():
    state = ContractsState()
    # CALLDATALOAD(0), PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
    code = bytes([Op.PUSH1, 0, Op.CALLDATALOAD, Op.PUSH1, 0, Op.MSTORE,
                  Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    account = state.deploy("CreatorA", code)
    calldata = (42).to_bytes(32, "big")
    result = VM(state, 100_000).execute(
        CallContext(contract=account, caller="CreatorA", call_value=0, calldata=calldata, depth=0)
    )
    assert result.success
    assert int.from_bytes(result.return_data, "big") == 42


def test_call_between_two_contracts_and_reentrancy_guard():
    state = ContractsState()
    # contrato B: incrementa seu proprio storage[0] e retorna o novo valor
    code_b = bytes([Op.PUSH1, 0, Op.SLOAD, Op.PUSH1, 1, Op.ADD, Op.DUP1, Op.PUSH1, 0, Op.SSTORE,
                     Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    contract_b = state.deploy("CreatorA", code_b)
    b_addr_int = state.intern_address(contract_b.address)

    # contrato A: faz CALL para B (com todo o gas disponivel), retorna o
    # sucesso (1/0) da chamada
    code_a = bytearray()
    code_a += bytes([Op.PUSH1, 0])                                     # out_size = 0
    code_a += bytes([Op.PUSH1, 0])                                     # out_off = 0
    code_a += bytes([Op.PUSH1, 0])                                     # in_size = 0
    code_a += bytes([Op.PUSH1, 0])                                     # in_off = 0
    code_a += bytes([Op.PUSH1, 0])                                     # value = 0
    code_a += bytes([0x7F]) + b_addr_int.to_bytes(32, "big")           # PUSH32 <endereco B> (to)
    code_a += bytes([0x7F]) + (100_000).to_bytes(32, "big")            # gas (topo da pilha)
    code_a += bytes([Op.CALL])
    code_a += bytes([Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    contract_a = state.deploy("CreatorA", bytes(code_a))

    result = VM(state, 200_000).execute(
        CallContext(contract=contract_a, caller="UserX", call_value=0, calldata=b"", depth=0)
    )
    assert result.success
    assert int.from_bytes(result.return_data, "big") == 1  # CALL retornou sucesso
    assert contract_b.storage[0] == 1  # B foi de fato executado e incrementou seu storage


def test_reentrancy_is_blocked_by_vm_guard():
    """Um contrato que tenta chamar a SI MESMO (reentrancia classica, o
    padrao de ataque do hack do The DAO) deve ser bloqueado pela VM - a
    sub-CALL falha (retorna 0 na pilha), mas a chamada externa continua e
    termina normalmente (nao trava/nao corrompe o resto da execucao)."""
    state = ContractsState()
    code = bytearray()
    # CALL(gas=100000, to=SELF, value=0, in_off=0, in_size=0, out_off=0, out_size=0)
    placeholder_self_addr_slot = len(code)
    code += bytes([Op.PUSH1, 0])   # out_size
    code += bytes([Op.PUSH1, 0])   # out_off
    code += bytes([Op.PUSH1, 0])   # in_size
    code += bytes([Op.PUSH1, 0])   # in_off
    code += bytes([Op.PUSH1, 0])   # value
    code += bytes([Op.ADDRESS])    # to = proprio endereco (empilha o int do proprio contrato)
    code += bytes([0x7F]) + (100_000).to_bytes(32, "big")  # gas
    code += bytes([Op.CALL])
    code += bytes([Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    account = state.deploy("CreatorA", bytes(code))
    result = VM(state, 300_000).execute(
        CallContext(contract=account, caller="CreatorA", call_value=0, calldata=b"", depth=0)
    )
    assert result.success
    # a sub-CALL reentrante retornou 0 (falha) na pilha - a guarda de
    # reentrancia da VM funcionou, mas a execucao externa terminou com sucesso
    assert int.from_bytes(result.return_data, "big") == 0


def test_deterministic_create_address_is_reproducible():
    state1 = ContractsState()
    state2 = ContractsState()
    addr1 = state1.deterministic_contract_address("CreatorZ", 0)
    addr2 = state2.deterministic_contract_address("CreatorZ", 0)
    assert addr1 == addr2
    assert crypto_utils.is_valid_address(addr1)
    # nonce diferente -> endereco diferente
    assert state1.deterministic_contract_address("CreatorZ", 1) != addr1


def test_stack_overflow_is_rejected():
    state = ContractsState()
    code = bytes([Op.PUSH1, 1]) * 1025  # excede MAX_STACK_SIZE (1024)
    account = state.deploy("CreatorA", code)
    result = VM(state, 1_000_000).execute(
        CallContext(contract=account, caller="CreatorA", call_value=0, calldata=b"", depth=0)
    )
    assert not result.success
    assert "overflow" in result.revert_reason.lower()


# ---------------------------------------------------------------------------
# Testes dos opcodes de completude adicionados alem do conjunto minimo do
# guia (NOT/BYTE/SHL/SHR/SAR/ADDMOD/MULMOD/EXP/CALLDATASIZE/etc.)
# ---------------------------------------------------------------------------

def _run(code: bytes, calldata: bytes = b"", gas: int = 200_000, **vm_kwargs):
    state = ContractsState()
    account = state.deploy("CreatorA", code)
    vm = VM(state, gas, **vm_kwargs)
    return vm.execute(CallContext(contract=account, caller="CreatorA", call_value=0, calldata=calldata, depth=0)), state, account


def _returns_uint(code: bytes, calldata: bytes = b"", **kwargs) -> int:
    result, _, _ = _run(code + bytes([Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN]),
                         calldata=calldata, **kwargs)
    assert result.success, result.revert_reason
    return int.from_bytes(result.return_data, "big")


def test_not_opcode():
    code = bytes([Op.PUSH1, 0, Op.NOT])
    assert _returns_uint(code) == (1 << 256) - 1


def test_byte_opcode():
    # BYTE(31, 0x...FF) -> ultimo byte
    code = bytes([0x7F]) + (0xAABB).to_bytes(32, "big") + bytes([Op.PUSH1, 31, Op.BYTE])
    assert _returns_uint(code) == 0xBB


def test_shl_shr_opcodes():
    code_shl = bytes([Op.PUSH1, 1, Op.PUSH1, 4, Op.SHL])  # 1 << 4 = 16
    assert _returns_uint(code_shl) == 16
    code_shr = bytes([Op.PUSH1, 16, Op.PUSH1, 4, Op.SHR])  # 16 >> 4 = 1
    assert _returns_uint(code_shr) == 1


def test_addmod_mulmod_exp_opcodes():
    # ADDMOD(10, 10, 8) = 20 % 8 = 4
    code_addmod = bytes([Op.PUSH1, 8, Op.PUSH1, 10, Op.PUSH1, 10, Op.ADDMOD])
    assert _returns_uint(code_addmod) == 4
    # MULMOD(10, 10, 8) = 100 % 8 = 4
    code_mulmod = bytes([Op.PUSH1, 8, Op.PUSH1, 10, Op.PUSH1, 10, Op.MULMOD])
    assert _returns_uint(code_mulmod) == 4
    # EXP(2, 10) = 1024
    code_exp = bytes([Op.PUSH1, 10, Op.PUSH1, 2, Op.EXP])
    assert _returns_uint(code_exp) == 1024


def test_calldatasize_and_calldatacopy():
    calldata = b"\x01\x02\x03\x04"
    code_size = bytes([Op.CALLDATASIZE])
    assert _returns_uint(code_size, calldata=calldata) == 4
    # CALLDATACOPY(dest=0, offset=0, size=4) depois MLOAD(0) -> os 4 bytes nos MSBs
    code_copy = bytes([Op.PUSH1, 4, Op.PUSH1, 0, Op.PUSH1, 0, Op.CALLDATACOPY, Op.PUSH1, 0, Op.MLOAD])
    result, _, _ = _run(code_copy + bytes([Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN]),
                         calldata=calldata)
    assert result.success
    assert result.return_data[:4] == calldata


def test_timestamp_number_and_gasprice_reflect_vm_context():
    code = bytes([Op.TIMESTAMP])
    assert _returns_uint(code, block_timestamp=12345, block_number=7) == 12345
    code_num = bytes([Op.NUMBER])
    assert _returns_uint(code_num, block_timestamp=12345, block_number=7) == 7


def test_staticcall_blocks_state_mutation():
    """Um contrato chamado via STATICCALL nao pode executar SSTORE - a
    tentativa deve reverter a SUB-chamada (a chamada externa continua e
    retorna 0/falha na pilha, sem corromper nada)."""
    state = ContractsState()
    code_callee = bytes([Op.PUSH1, 1, Op.PUSH1, 0, Op.SSTORE, Op.STOP])
    callee = state.deploy("CreatorA", code_callee)
    callee_addr_int = state.intern_address(callee.address)

    code_caller = bytearray()
    code_caller += bytes([Op.PUSH1, 0])                                    # out_size
    code_caller += bytes([Op.PUSH1, 0])                                    # out_off
    code_caller += bytes([Op.PUSH1, 0])                                    # in_size
    code_caller += bytes([Op.PUSH1, 0])                                    # in_off
    code_caller += bytes([0x7F]) + callee_addr_int.to_bytes(32, "big")     # to
    code_caller += bytes([0x7F]) + (100_000).to_bytes(32, "big")          # gas
    code_caller += bytes([Op.STATICCALL])
    code_caller += bytes([Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    caller_account = state.deploy("CreatorB", bytes(code_caller))

    result = VM(state, 200_000).execute(
        CallContext(contract=caller_account, caller="UserX", call_value=0, calldata=b"", depth=0)
    )
    assert result.success
    assert int.from_bytes(result.return_data, "big") == 0  # STATICCALL falhou (SSTORE bloqueado)
    assert callee.storage.get(0, 0) == 0  # nenhuma escrita persistiu


def test_call_with_value_transfers_real_balance_between_contracts():
    """CALL com `value > 0` entre dois contratos deve mover saldo PXC de
    verdade no dict `balances` compartilhado (nao apenas simular no valor de
    retorno) - e deve falhar (sem executar o destino) se o saldo for
    insuficiente."""
    state = ContractsState()
    code_callee = bytes([Op.STOP])
    callee = state.deploy("CreatorA", code_callee)
    callee_addr_int = state.intern_address(callee.address)

    code_caller = bytearray()
    code_caller += bytes([Op.PUSH1, 0])                                # out_size
    code_caller += bytes([Op.PUSH1, 0])                                # out_off
    code_caller += bytes([Op.PUSH1, 0])                                # in_size
    code_caller += bytes([Op.PUSH1, 0])                                # in_off
    code_caller += bytes([0x7F]) + (5 * 10 ** 8).to_bytes(32, "big")   # value = 5 PXC
    code_caller += bytes([0x7F]) + callee_addr_int.to_bytes(32, "big")  # to
    code_caller += bytes([0x7F]) + (100_000).to_bytes(32, "big")      # gas
    code_caller += bytes([Op.CALL])
    code_caller += bytes([Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    caller_account = state.deploy("CreatorB", bytes(code_caller))

    balances = {caller_account.address: 10.0}
    result = VM(state, 200_000, balances=balances).execute(
        CallContext(contract=caller_account, caller="UserX", call_value=0, calldata=b"", depth=0)
    )
    assert result.success
    assert int.from_bytes(result.return_data, "big") == 1
    assert balances[caller_account.address] == 5.0
    assert balances[callee.address] == 5.0

    # segunda tentativa: saldo insuficiente (so restam 5, tentando mandar 5 de novo e ok,
    # mas uma terceira vez deve falhar)
    result2 = VM(state, 200_000, balances=balances).execute(
        CallContext(contract=caller_account, caller="UserX", call_value=0, calldata=b"", depth=0)
    )
    assert result2.success
    assert int.from_bytes(result2.return_data, "big") == 1
    assert balances[caller_account.address] == 0.0
    assert balances[callee.address] == 10.0

    result3 = VM(state, 200_000, balances=balances).execute(
        CallContext(contract=caller_account, caller="UserX", call_value=0, calldata=b"", depth=0)
    )
    assert result3.success
    assert int.from_bytes(result3.return_data, "big") == 0  # falhou: saldo insuficiente
    assert balances[caller_account.address] == 0.0  # nada mudou


def test_create_constructor_revert_undoes_entire_deploy():
    """Se o "construtor" executado por CREATE reverte, o novo contrato NAO
    deve passar a existir (nem deixar storage/saldo "orfao" para tras)."""
    state = ContractsState()
    reverting_init_code = bytes([Op.PUSH1, 0, Op.PUSH1, 0, Op.REVERT])

    code_creator = bytearray()
    code_creator += bytes([Op.PUSH1, len(reverting_init_code)])
    code_creator += bytes([Op.PUSH1, 0])   # offset
    # grava o init_code na memoria via um unico PUSH32 (padded) + MSTORE
    code_creator = bytearray()
    padded_init = reverting_init_code.ljust(32, b"\x00")
    code_creator += bytes([0x7F]) + padded_init                       # PUSH32 <init code padded>
    code_creator += bytes([Op.PUSH1, 0, Op.MSTORE])                   # MSTORE(0, init_code)
    code_creator += bytes([Op.PUSH1, len(reverting_init_code)])       # size
    code_creator += bytes([Op.PUSH1, 0])                              # offset
    code_creator += bytes([Op.PUSH1, 0])                              # value
    code_creator += bytes([Op.CREATE])
    code_creator += bytes([Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    creator_account = state.deploy("CreatorC", bytes(code_creator))

    contracts_before = set(state.contracts.keys())
    result = VM(state, 300_000).execute(
        CallContext(contract=creator_account, caller="UserX", call_value=0, calldata=b"", depth=0)
    )
    assert result.success
    assert int.from_bytes(result.return_data, "big") == 0  # CREATE retornou 0 (falhou)
    # nenhum contrato NOVO deve ter sobrevivido (o unico account e o proprio criador)
    assert set(state.contracts.keys()) == contracts_before


# ---------------------------------------------------------------------------
# Testes de integracao com a blockchain (deploy/call minerados de verdade)
# ---------------------------------------------------------------------------

@pytest.fixture
def chain():
    return Blockchain(difficulty_mode="demo")


@pytest.fixture
def funded_wallet(chain):
    priv, pub = crypto_utils.generate_keypair()
    address = crypto_utils.public_key_to_address(pub)
    _fund(chain, address)
    return priv, pub, address


def test_contract_deploy_tx_is_rejected_with_invalid_hex_data():
    tx = Transaction(sender="a", recipient="", amount=0.0, tx_type="contract_deploy", data="not-hex!!")
    assert not tx.is_valid()


def test_contract_call_tx_requires_valid_recipient_address():
    tx = Transaction(sender="a", recipient="not-a-real-address", amount=0.0, tx_type="contract_call", data="")
    assert not tx.is_valid()


def test_full_deploy_and_call_lifecycle_through_mining(chain, funded_wallet):
    priv, pub, address = funded_wallet
    code = bytes([Op.PUSH1, 0, Op.SLOAD, Op.PUSH1, 1, Op.ADD, Op.DUP1, Op.PUSH1, 0, Op.SSTORE,
                  Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])

    deploy_tx = Transaction(sender=address, recipient="", amount=0.0, fee=0.01,
                             tx_type="contract_deploy", data=code.hex())
    deploy_tx.sign(priv, pub)
    assert deploy_tx.is_valid()
    assert chain.add_transaction(deploy_tx)
    _mine_and_submit(chain, address)

    contracts_state = chain._contracts_snapshot()
    deployed = [a for a, acc in contracts_state.contracts.items() if acc.creator == address]
    assert len(deployed) == 1
    contract_address = deployed[0]
    assert crypto_utils.is_valid_address(contract_address)
    # o construtor ja rodou uma vez no deploy (mesma bytecode roda como
    # "construtor" - simplificacao documentada em app/vm.py)
    assert contracts_state.contracts[contract_address].storage[0] == 1

    call_tx = Transaction(sender=address, recipient=contract_address, amount=0.0, fee=0.01,
                           tx_type="contract_call", data="")
    call_tx.sign(priv, pub)
    assert chain.add_transaction(call_tx)
    _mine_and_submit(chain, address)

    contracts_state_after = chain._contracts_snapshot()
    assert contracts_state_after.contracts[contract_address].storage[0] == 2
    assert chain.is_chain_valid()


def test_gas_refund_credits_unused_gas_back_to_sender(chain, funded_wallet):
    """Secao 5.3 do guia: 'sobra de gas e reembolsada ao remetente' - uma tx
    com um `fee` (orcamento de gas) muito maior do que o bytecode realmente
    consome deve devolver o excedente ao remetente apos a mineracao, e o
    `state_root` resultante precisa bater com uma revalidacao completa
    (`is_chain_valid`) - garante que o reembolso e aplicado de forma
    CONSISTENTE entre `state_root_hash`/`contracts_root_hash` e o replay de
    validacao (bug real corrigido nesta rodada: os dois antes replayavam com
    dicts de saldo isolados, entao o reembolso "sumia" na revalidacao)."""
    priv, pub, address = funded_wallet
    code = bytes([Op.STOP])  # bytecode trivial: consome quase nenhum gas
    balance_before = chain.get_balance(address)

    big_fee = 1.0  # orcamento de gas MUITO maior do que o STOP consome
    deploy_tx = Transaction(sender=address, recipient="", amount=0.0, fee=big_fee,
                             tx_type="contract_deploy", data=code.hex())
    deploy_tx.sign(priv, pub)
    assert chain.add_transaction(deploy_tx)
    _mine_and_submit(chain, address)

    balance_after = chain.get_balance(address)
    # o remetente pagou MUITO menos que `big_fee` de fato (quase tudo foi devolvido)
    actual_cost = balance_before - balance_after
    assert actual_cost < big_fee * 0.5
    assert chain.is_chain_valid()


def test_contracts_root_is_verified_and_forged_root_is_rejected(chain, funded_wallet):
    priv, pub, address = funded_wallet
    code = bytes([Op.STOP])
    deploy_tx = Transaction(sender=address, recipient="", amount=0.0, fee=0.01,
                             tx_type="contract_deploy", data=code.hex())
    deploy_tx.sign(priv, pub)
    assert chain.add_transaction(deploy_tx)

    block = chain.build_candidate_block(address)
    result = mine_block(block, max_iterations=5_000_000, prefer_gpu=False)
    # forja o contracts_root do bloco candidato antes de submeter
    block.contracts_root = "0" * 64
    assert not chain.submit_mined_block(block, result.nonce, block.compute_hash())


def test_chain_replay_reproduces_same_contracts_root_after_reload(chain, funded_wallet, tmp_path, monkeypatch):
    """Simula um restart: persiste os blocos, recria um Blockchain do zero e
    reidrata a partir deles - o contracts_root recalculado por replay tem que
    bater exatamente com o que foi persistido (mesma garantia que ja existe
    para state_root)."""
    from app import storage as storage_mod
    monkeypatch.setattr(storage_mod, "DB_PATH", tmp_path / "vm_test_chain.db")
    storage_mod.init_db()

    priv, pub, address = funded_wallet
    storage_mod.persist_block(chain.chain[1])  # bloco de financiamento ja minerado no fixture

    code = bytes([Op.PUSH1, 7, Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    deploy_tx = Transaction(sender=address, recipient="", amount=0.0, fee=0.01,
                             tx_type="contract_deploy", data=code.hex())
    deploy_tx.sign(priv, pub)
    assert chain.add_transaction(deploy_tx)
    block = _mine_and_submit(chain, address)
    storage_mod.persist_block(block)

    reloaded = Blockchain(difficulty_mode="demo")
    reloaded.rehydrate_from_persisted_blocks(storage_mod.load_full_chain())
    assert reloaded.last_block.contracts_root == chain.last_block.contracts_root
    assert reloaded.is_chain_valid()


# ---------------------------------------------------------------------------
# Testes das novas funcionalidades: Keccak-256, RLP, SSTORE_REFUND,
# DELEGATECALL, CALLCODE e consulta de logs via API
# ---------------------------------------------------------------------------

from app.crypto_utils import keccak256, rlp_encode, rlp_decode


def test_keccak256_known_vectors():
    """Keccak-256 deve bater com vetores de teste publicos conhecidos.
    keccak256(b"") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    (este e o hash que a EVM real usa - diferente do SHA3-256 NIST que seria
    a3c99bfa879ec0fb5ef5ec43e8dbba9d72a58fac2a87c64fb18cf5f2ba8f6a23)"""
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    # keccak256("abc") - vetor publico confirmado pela implementacao de referencia
    assert keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    # keccak256("The quick brown fox jumps over the lazy dog")
    assert keccak256(b"The quick brown fox jumps over the lazy dog").hex() == \
        "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
    # confirma que e DIFERENTE de SHA3-256 NIST para o mesmo input
    import hashlib
    sha3_empty = hashlib.sha3_256(b"").hexdigest()
    assert sha3_empty != keccak256(b"").hex(), "keccak256 deveria ser diferente de SHA3-256 NIST"


def test_rlp_encode_decode_known_vectors():
    """RLP deve bater com vetores publicos da especificacao Ethereum."""
    # Vetor 1: encode("dog") == [0x83, 'd', 'o', 'g']
    assert rlp_encode(b"dog") == bytes([0x83, 0x64, 0x6F, 0x67])
    # Vetor 2: encode("") == [0x80]
    assert rlp_encode(b"") == bytes([0x80])
    # Vetor 3: encode([]) == [0xc0]
    assert rlp_encode([]) == bytes([0xC0])
    # Vetor 4: encode(["cat", "dog"]) == [0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g']
    assert rlp_encode([b"cat", b"dog"]) == bytes([0xC8, 0x83, 0x63, 0x61, 0x74, 0x83, 0x64, 0x6F, 0x67])
    # Vetor 5: byte unico < 0x80 codifica como ele mesmo
    assert rlp_encode(bytes([0x41])) == bytes([0x41])
    # Roundtrip: encode -> decode -> mesmo valor
    original = [b"hello", [b"world", b""], b"!"]
    encoded = rlp_encode(original)
    decoded, consumed = rlp_decode(encoded)
    assert consumed == len(encoded)
    assert decoded[0] == b"hello"
    assert decoded[1][0] == b"world"
    assert decoded[1][1] == b""
    assert decoded[2] == b"!"
    # String longa (> 55 bytes): deve usar prefixo de 2+ bytes
    long_bytes = b"A" * 100
    enc_long = rlp_encode(long_bytes)
    dec_long, _ = rlp_decode(enc_long)
    assert dec_long == long_bytes


def test_sha3_opcode_uses_keccak256_not_sha256():
    """O opcode SHA3 da VM deve usar keccak256 (hash Keccak real da EVM),
    nao hashlib.sha256 - e deve bater com o vetor de teste keccak256(b'')."""
    state = ContractsState()
    # SHA3 sobre memoria vazia (offset=0, size=0) = keccak256(b"")
    # empilha o resultado, MSTORE em 0, retorna 32 bytes
    code = bytes([
        Op.PUSH1, 0,   # size = 0
        Op.PUSH1, 0,   # offset = 0
        Op.SHA3,       # keccak256(memory[0:0]) = keccak256(b"")
        Op.PUSH1, 0,
        Op.MSTORE,
        Op.PUSH1, 32,
        Op.PUSH1, 0,
        Op.RETURN,
    ])
    account = state.deploy("CreatorA", code)
    result = VM(state, 100_000).execute(
        CallContext(contract=account, caller="CreatorA", call_value=0, calldata=b"", depth=0)
    )
    assert result.success
    expected = int.from_bytes(bytes.fromhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), "big")
    assert int.from_bytes(result.return_data, "big") == expected


def test_sstore_refund_reduces_gas_when_clearing_slot():
    """SSTORE que limpa um slot nao-zero deve conceder refund de gas (SSTORE_REFUND
    classico), reduzindo o gas_used total abaixo do custo bruto."""
    state = ContractsState()
    # Passo 1: SSTORE(slot=0, valor=1) -> SET  (custa SSTORE_SET_COST = 20000)
    # Passo 2: SSTORE(slot=0, valor=0) -> CLEAR (custa SSTORE_UPDATE_COST = 5000,
    #          gera refund de SSTORE_CLEAR_REFUND = 15000)
    # Gas bruto ≈ 3+3+20000 + 3+3+5000 = 25012
    # Refund efetivo = min(15000, 25012 // 2) = min(15000, 12506) = 12506
    # Gas final ≈ 25012 - 12506 = 12506
    code = bytes([
        Op.PUSH1, 1, Op.PUSH1, 0, Op.SSTORE,   # SET slot 0 = 1
        Op.PUSH1, 0, Op.PUSH1, 0, Op.SSTORE,   # CLEAR slot 0 -> refund
    ])
    account = state.deploy("CreatorA", code)
    result = VM(state, 100_000).execute(
        CallContext(contract=account, caller="CreatorA", call_value=0, calldata=b"", depth=0)
    )
    assert result.success
    # Sem refund o gas usado seria ~25012; com refund deve cair para ~12506
    assert result.gas_used < 20_000, "refund nao foi aplicado (gas_used muito alto)"
    # O slot deve estar limpo (valor 0)
    assert account.storage.get(0, 0) == 0

    # Controle: SSTORE(slot=1, 99) SEM limpar nao deve conceder refund significativo
    state2 = ContractsState()
    code_no_refund = bytes([Op.PUSH1, 99, Op.PUSH1, 1, Op.SSTORE])
    acc2 = state2.deploy("CreatorA", code_no_refund)
    result2 = VM(state2, 100_000).execute(
        CallContext(contract=acc2, caller="CreatorA", call_value=0, calldata=b"", depth=0)
    )
    assert result2.success
    # gas_used sem refund ≈ 3+3+20000 = 20006 (SET de slot zero)
    assert result2.gas_used > 15_000, "gas_used sem refund deve ser alto"


def test_delegatecall_modifies_callers_storage_not_callees():
    """DELEGATECALL executa o codigo do alvo MAS no contexto de storage/endereco
    do chamador - padrao classico de proxy/library da EVM.
    Cenario: 'lib' define logica de SSTORE(0, 42); 'proxy' faz DELEGATECALL para lib.
    Resultado esperado: proxy.storage[0] == 42, lib.storage[0] == 0."""
    state = ContractsState()
    # lib: SSTORE(slot=0, valor=42)
    code_lib = bytes([Op.PUSH1, 42, Op.PUSH1, 0, Op.SSTORE, Op.STOP])
    lib = state.deploy("Creator", code_lib)
    lib_addr_int = state.intern_address(lib.address)

    # proxy: DELEGATECALL para lib com todo o gas disponivel
    code_proxy = bytearray()
    code_proxy += bytes([Op.PUSH1, 0])                                    # out_size
    code_proxy += bytes([Op.PUSH1, 0])                                    # out_off
    code_proxy += bytes([Op.PUSH1, 0])                                    # in_size
    code_proxy += bytes([Op.PUSH1, 0])                                    # in_off
    code_proxy += bytes([0x7F]) + lib_addr_int.to_bytes(32, "big")        # to = lib
    code_proxy += bytes([0x7F]) + (100_000).to_bytes(32, "big")           # gas
    code_proxy += bytes([Op.DELEGATECALL])
    # retorna o resultado (1 = sucesso, 0 = falha) na pilha
    code_proxy += bytes([Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    proxy = state.deploy("Creator", bytes(code_proxy))

    result = VM(state, 500_000).execute(
        CallContext(contract=proxy, caller="User", call_value=0, calldata=b"", depth=0)
    )
    assert result.success, f"execucao falhou: {result.revert_reason}"
    assert int.from_bytes(result.return_data, "big") == 1  # DELEGATECALL retornou sucesso

    # CRITICO: storage modificado deve ser o do PROXY, nao o da lib
    assert proxy.storage.get(0, 0) == 42, "DELEGATECALL deveria ter modificado o storage do proxy"
    assert lib.storage.get(0, 0) == 0, "DELEGATECALL NAO deveria ter modificado o storage da lib"


def test_callcode_uses_callers_storage_with_proxy_as_sender():
    """CALLCODE executa codigo do alvo no storage do chamador, mas msg.sender = chamador
    (diferente do DELEGATECALL onde msg.sender = quem chamou o chamador).
    Verifica: proxy.storage[1] = endereco do PROXY (nao do User), lib.storage nao tocado."""
    state = ContractsState()
    # lib: SSTORE(slot=1, msg.sender) - registra quem e o sender
    code_lib = bytes([Op.CALLER, Op.PUSH1, 1, Op.SSTORE, Op.STOP])
    lib = state.deploy("Creator", code_lib)
    lib_addr_int = state.intern_address(lib.address)

    # proxy: CALLCODE para lib
    code_proxy = bytearray()
    code_proxy += bytes([Op.PUSH1, 0])                                    # out_size
    code_proxy += bytes([Op.PUSH1, 0])                                    # out_off
    code_proxy += bytes([Op.PUSH1, 0])                                    # in_size
    code_proxy += bytes([Op.PUSH1, 0])                                    # in_off
    code_proxy += bytes([0x7F]) + lib_addr_int.to_bytes(32, "big")        # to = lib
    code_proxy += bytes([0x7F]) + (100_000).to_bytes(32, "big")           # gas
    code_proxy += bytes([Op.CALLCODE])
    code_proxy += bytes([Op.PUSH1, 0, Op.MSTORE, Op.PUSH1, 32, Op.PUSH1, 0, Op.RETURN])
    proxy = state.deploy("Creator", bytes(code_proxy))
    proxy_addr_int = state.intern_address(proxy.address)

    result = VM(state, 500_000).execute(
        CallContext(contract=proxy, caller="User", call_value=0, calldata=b"", depth=0)
    )
    assert result.success, f"execucao falhou: {result.revert_reason}"
    assert int.from_bytes(result.return_data, "big") == 1  # CALLCODE retornou sucesso

    # CALLCODE: codigo da lib rodou no STORAGE do proxy, mas msg.sender = proxy
    assert proxy.storage.get(1, 0) == proxy_addr_int, \
        "CALLCODE: msg.sender dentro da lib deveria ser o endereco do proxy"
    assert lib.storage.get(1, 0) == 0, "CALLCODE NAO deveria ter tocado o storage da lib"
    # Diferenca do DELEGATECALL: msg.sender aqui e o PROXY, nao o "User" original
    user_addr_int = state.intern_address("User")
    assert proxy.storage.get(1, 0) != user_addr_int, \
        "CALLCODE: msg.sender NAO deveria ser o 'User' (isso seria semantica de DELEGATECALL)"


def test_contract_logs_persisted_and_queryable(tmp_path, monkeypatch):
    """Deploy de contrato que emite LOG1, minera um bloco, verifica que o log
    e persistido no SQLite e consultavel via GET /contracts/{address}/logs."""
    import importlib
    from fastapi.testclient import TestClient

    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(tmp_path / "logs_test.db"))
    import app.storage as storage_mod
    importlib.reload(storage_mod)
    import app.bruteforce_guard as bg_mod
    bg_mod.guard.reset_all()
    import app.api as api_mod
    importlib.reload(api_mod)
    client = TestClient(api_mod.app)

    # Gera carteira e financia
    priv, pub = crypto_utils.generate_keypair()
    address = crypto_utils.public_key_to_address(pub)
    from app.models import Transaction as Tx
    from app.mining import mine_block as _mine
    chain = api_mod.blockchain

    fund_tx = Tx(sender="SISTEMA_EMISSAO", recipient=address, amount=200.0, tx_type="coinbase_purchase")
    chain.add_transaction(fund_tx)
    blk = chain.build_candidate_block(address)
    r = _mine(blk, max_iterations=5_000_000, prefer_gpu=False)
    chain.submit_mined_block(blk, r.nonce, r.block_hash)
    storage_mod.persist_block(blk)
    storage_mod.persist_contract_logs(chain._last_accepted_block_logs)

    # Contrato que emite LOG1(topic=0xCAFE, data=32 bytes com valor 0xFF)
    TOPIC = 0xCAFE
    code = bytes([
        Op.PUSH1, 0xFF,          # valor 0xFF
        Op.PUSH1, 0,             # offset memory
        Op.MSTORE,               # memory[0:32] = 0xFF
        0x7F]) + TOPIC.to_bytes(32, "big") + bytes([  # PUSH32 topic
        Op.PUSH1, 32,            # data size
        Op.PUSH1, 0,             # data offset
        Op.LOG1,                 # emite LOG1
        Op.STOP,
    ])
    deploy_tx = Tx(sender=address, recipient="", amount=0.0, fee=1.0,
                   tx_type="contract_deploy", data=code.hex())
    deploy_tx.sign(priv, pub)
    chain.add_transaction(deploy_tx)
    blk2 = chain.build_candidate_block(address)
    r2 = _mine(blk2, max_iterations=5_000_000, prefer_gpu=False)
    chain.submit_mined_block(blk2, r2.nonce, r2.block_hash)
    storage_mod.persist_block(blk2)
    storage_mod.persist_contract_logs(chain._last_accepted_block_logs)

    # Descobre o endereco do contrato deployado
    contracts_state = chain._contracts_snapshot()
    deployed = [a for a, acc in contracts_state.contracts.items() if acc.creator == address]
    assert len(deployed) >= 1
    contract_addr = deployed[-1]

    # Consulta logs via API
    resp = client.get(f"/contracts/{contract_addr}/logs")
    assert resp.status_code == 200
    data = resp.json()
    assert data["address"] == contract_addr
    assert data["count"] >= 1
    log = data["logs"][0]
    assert log["address"] == contract_addr
    # Verifica que o topico esta presente
    expected_topic = hex(TOPIC)
    assert expected_topic in log["topics"]
