"""
Testes de integridade de estado (`state_root`) e de um bug de consenso real
encontrado ao implementar esta funcionalidade: um valor de `amount`/`fee`
construido como `int` em memoria muda de representacao JSON apos um
round-trip pelo SQLite (coluna REAL sempre retorna `float`), o que quebrava
`tx_hash()` (Merkle root/hash do bloco) e a assinatura apos qualquer restart
do processo. Corrigido normalizando `amount`/`fee` para `float` em
`Transaction.__post_init__`.
"""
import pytest

from app import root_rules
from app.mining import mine_block
from app.models import Blockchain, Transaction
from app.wallet import Wallet


@pytest.fixture
def storage_module(tmp_path, monkeypatch):
    from app import storage as storage_mod
    monkeypatch.setattr(storage_mod, "DB_PATH", tmp_path / "test_chain.db")
    storage_mod.init_db()
    return storage_mod


def _mine_and_submit(chain: Blockchain, miner_address: str):
    block = chain.build_candidate_block(miner_address)
    result = mine_block(block, max_iterations=5_000_000, prefer_gpu=False)
    assert chain.submit_mined_block(block, result.nonce, result.block_hash)
    return block


def test_transaction_amount_and_fee_are_always_coerced_to_float():
    tx = Transaction(sender="a", recipient="b", amount=10, fee=1)
    assert isinstance(tx.amount, float)
    assert isinstance(tx.fee, float)
    assert tx.amount == 10.0
    assert tx.fee == 1.0


def test_genesis_block_has_state_root_of_empty_balances():
    chain = Blockchain(difficulty_mode="demo")
    assert chain.chain[0].state_root is not None
    # bloco genesis sem transacoes -> snapshot de saldos vazio
    assert chain.chain[0].state_root == Blockchain._state_root_from_balances({})


def test_mined_block_state_root_matches_expected_balances():
    chain = Blockchain(difficulty_mode="demo")
    alice = Wallet.create()
    miner = Wallet.create()
    credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                          amount=10, tx_type="coinbase_purchase")
    chain.add_transaction(credit)
    block = _mine_and_submit(chain, miner.address)
    assert block.state_root == chain.state_root_hash()


def test_state_root_survives_sqlite_persistence_roundtrip(storage_module):
    """Regressao do bug real encontrado: uma tx com amount=int (10, nao 10.0)
    minerada, persistida e recarregada do SQLite precisa manter EXATAMENTE
    o mesmo hash de bloco e passar em `is_chain_valid()` apos o "restart"."""
    chain = Blockchain(difficulty_mode="demo")
    alice = Wallet.create()
    miner = Wallet.create()
    credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                          amount=10, tx_type="coinbase_purchase")  # amount como int de proposito
    chain.add_transaction(credit)
    block = _mine_and_submit(chain, miner.address)
    assert chain.is_chain_valid()

    storage_module.persist_block(block)
    reloaded_blocks = storage_module.load_full_chain()

    new_chain = Blockchain(difficulty_mode="demo")
    new_chain.rehydrate_from_persisted_blocks(reloaded_blocks)

    assert new_chain.chain[-1].hash == block.hash
    assert new_chain.chain[-1].hash == new_chain.chain[-1].compute_hash()
    assert new_chain.is_chain_valid()
    assert new_chain.get_balance(alice.address) == chain.get_balance(alice.address)


def test_validate_candidate_chain_rejects_forged_state_root(storage_module):
    chain = Blockchain(difficulty_mode="demo")
    alice = Wallet.create()
    miner = Wallet.create()
    credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                          amount=25.0, tx_type="coinbase_purchase")
    chain.add_transaction(credit)
    block = _mine_and_submit(chain, miner.address)

    assert Blockchain.validate_candidate_chain(chain.chain) is True

    forged_root = block.state_root
    block.state_root = "0" * 64
    assert Blockchain.validate_candidate_chain(chain.chain) is False
    block.state_root = forged_root  # restaura para nao afetar outras asserts


def test_validate_candidate_chain_rejects_tampered_amount_after_mining(storage_module):
    chain = Blockchain(difficulty_mode="demo")
    alice = Wallet.create()
    miner = Wallet.create()
    credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                          amount=25.0, tx_type="coinbase_purchase")
    chain.add_transaction(credit)
    block = _mine_and_submit(chain, miner.address)

    block.transactions[0].amount = 999999.0
    # o hash do bloco (que inclui o merkle root) nao bate mais - candidate invalido
    assert Blockchain.validate_candidate_chain(chain.chain) is False
