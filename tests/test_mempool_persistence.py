"""
Testes de persistencia da mempool (SQLite): cobre o ciclo completo de
"tx aceita -> persistida -> processo reinicia -> tx recarregada -> minerada
-> removida da tabela" que da suporte a garantia de que nenhuma transacao
aceita pela rede e perdida num restart antes de ser minerada.
"""
import importlib

import pytest


@pytest.fixture
def storage_module(tmp_path, monkeypatch):
    """Recarrega `app.storage` apontando para um banco SQLite temporario e
    isolado por teste (evita qualquer interferencia com data/pixcripto_chain.db)."""
    from app import storage as storage_mod
    monkeypatch.setattr(storage_mod, "DB_PATH", tmp_path / "test_chain.db")
    storage_mod.init_db()
    return storage_mod


def test_persist_and_load_pending_transaction_roundtrip(storage_module):
    from app.models import Transaction
    from app.wallet import Wallet

    alice = Wallet.create()
    bob = Wallet.create()
    tx = Transaction(sender=alice.address, recipient=bob.address, amount=2.5, fee=0.03)
    tx.sign(alice.private_key, alice.public_key)

    storage_module.persist_pending_transaction(tx)
    loaded = storage_module.load_pending_transactions()

    assert len(loaded) == 1
    assert loaded[0].tx_id == tx.tx_id
    assert loaded[0].amount == 2.5
    assert loaded[0].fee == 0.03
    assert loaded[0].is_valid()  # a tx recarregada ainda deve passar na verificacao de assinatura


def test_remove_pending_transaction_deletes_row(storage_module):
    from app.models import Transaction
    from app.wallet import Wallet

    alice = Wallet.create()
    bob = Wallet.create()
    tx = Transaction(sender=alice.address, recipient=bob.address, amount=1.0)
    tx.sign(alice.private_key, alice.public_key)
    storage_module.persist_pending_transaction(tx)
    assert len(storage_module.load_pending_transactions()) == 1

    storage_module.remove_pending_transaction(tx.tx_id)
    assert storage_module.load_pending_transactions() == []


def test_blockchain_hooks_persist_and_clear_mempool_automatically(storage_module):
    """Reproduz o fluxo real de `api.py`: os ganchos de persistencia devem
    gravar a tx assim que ela entra na mempool, e apaga-la assim que ela e
    minerada, sem que nenhum modulo precise lembrar de fazer isso manualmente."""
    from app import root_rules
    from app.models import Blockchain, Transaction
    from app.mining import mine_block
    from app.wallet import Wallet

    chain = Blockchain(difficulty_mode="demo")
    chain.set_persistence_hooks(
        on_pending=storage_module.persist_pending_transaction,
        on_confirmed=lambda tx: storage_module.remove_pending_transaction(tx.tx_id),
    )
    alice = Wallet.create()
    miner = Wallet.create()

    credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                          amount=5.0, tx_type="coinbase_purchase")
    assert chain.add_transaction(credit)
    assert len(storage_module.load_pending_transactions()) == 1

    block = chain.build_candidate_block(miner.address)
    result = mine_block(block, max_iterations=5_000_000, prefer_gpu=False)
    assert chain.submit_mined_block(block, result.nonce, result.block_hash)

    # apos minerado, a tx nao deve mais estar na tabela de pendentes
    assert storage_module.load_pending_transactions() == []


def test_rehydrate_pending_transactions_reloads_into_new_blockchain_instance(storage_module):
    """Simula um restart de processo: uma nova instancia de `Blockchain` (mempool
    vazia em memoria) deve recuperar a tx persistida no SQLite via
    `rehydrate_pending_transactions`, sem exigir que o usuario reenvie nada."""
    from app.models import Blockchain, Transaction
    from app.wallet import Wallet

    alice = Wallet.create()
    bob = Wallet.create()
    tx = Transaction(sender=alice.address, recipient=bob.address, amount=1.0)
    tx.sign(alice.private_key, alice.public_key)
    storage_module.persist_pending_transaction(tx)

    fresh_chain = Blockchain(difficulty_mode="demo")
    assert fresh_chain.pending_transactions == []
    fresh_chain.rehydrate_pending_transactions(storage_module.load_pending_transactions())
    assert len(fresh_chain.pending_transactions) == 1
    assert fresh_chain.pending_transactions[0].tx_id == tx.tx_id
