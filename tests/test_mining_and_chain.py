"""
Testes de Proof-of-Work (mineracao) e validade da cadeia: cobre mineracao
CPU real, aceitacao/rejeicao de blocos submetidos, recompensa do minerador
(0,4% do bloco + taxas) e a funcao `is_chain_valid`.
"""
from app import root_rules
from app.models import Blockchain, Transaction
from app.mining import mine_block
from app.wallet import Wallet


def _mine_and_submit(chain: Blockchain, miner_address: str):
    block = chain.build_candidate_block(miner_address)
    assert block is not None
    result = mine_block(block, max_iterations=5_000_000, prefer_gpu=False)
    assert chain.submit_mined_block(block, result.nonce, result.block_hash)
    return block


def test_genesis_block_exists_and_chain_is_valid_initially():
    chain = Blockchain(difficulty_mode="demo")
    assert len(chain.chain) == 1
    assert chain.is_chain_valid()


def test_mining_with_no_pending_transactions_returns_none():
    chain = Blockchain(difficulty_mode="demo")
    miner = Wallet.create()
    assert chain.build_candidate_block(miner.address) is None


def test_mine_block_produces_hash_meeting_difficulty():
    chain = Blockchain(difficulty_mode="demo")
    alice = Wallet.create()
    miner = Wallet.create()
    credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                          amount=10.0, tx_type="coinbase_purchase")
    chain.add_transaction(credit)
    block = _mine_and_submit(chain, miner.address)
    assert block.hash == block.compute_hash()
    assert block.meets_difficulty(block.hash)
    assert chain.is_chain_valid()


def test_miner_reward_includes_base_rate_plus_fees():
    chain = Blockchain(difficulty_mode="demo")
    alice = Wallet.create()
    bob = Wallet.create()
    miner = Wallet.create()
    credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                          amount=10.0, tx_type="coinbase_purchase")
    chain.add_transaction(credit)
    _mine_and_submit(chain, miner.address)

    tx = Transaction(sender=alice.address, recipient=bob.address, amount=5.0, fee=0.02)
    tx.sign(alice.private_key, alice.public_key)
    assert chain.add_transaction(tx)
    block = _mine_and_submit(chain, miner.address)

    expected_reward = round(5.0 * root_rules.MINER_REWARD_RATE + 0.02, 8)
    assert block.miner_reward() == expected_reward
    assert chain.get_balance(miner.address) == expected_reward


def test_submit_mined_block_rejects_wrong_previous_hash():
    chain = Blockchain(difficulty_mode="demo")
    alice = Wallet.create()
    miner = Wallet.create()
    credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                          amount=1.0, tx_type="coinbase_purchase")
    chain.add_transaction(credit)
    block = chain.build_candidate_block(miner.address)
    result = mine_block(block, max_iterations=5_000_000, prefer_gpu=False)
    # simula uma cadeia que avancou nesse meio tempo (reorg concorrente)
    block.previous_hash = "0" * 64
    assert chain.submit_mined_block(block, result.nonce, result.block_hash) is False


def test_submit_mined_block_rejects_invalid_nonce():
    chain = Blockchain(difficulty_mode="demo")
    alice = Wallet.create()
    miner = Wallet.create()
    credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                          amount=1.0, tx_type="coinbase_purchase")
    chain.add_transaction(credit)
    block = chain.build_candidate_block(miner.address)
    # nonce arbitrario, quase certamente nao satisfaz a dificuldade
    fake_hash = block.compute_hash()
    assert chain.submit_mined_block(block, 0, fake_hash) is False


# ---------------------------------------------------------------------------
# Mineracao colaborativa (pool): varias pessoas dividem a recompensa de um
# UNICO bloco, proporcionalmente ao peso (shares) de trabalho de cada uma -
# estilo pool de mineracao Bitcoin (p2pool/PPLNS).
# ---------------------------------------------------------------------------

def _mine_and_submit_pool(chain: Blockchain, miner_address: str, contributors):
    block = chain.build_candidate_block(miner_address, contributors=contributors)
    result = mine_block(block, max_iterations=5_000_000, prefer_gpu=False)
    assert chain.submit_mined_block(block, result.nonce, result.block_hash)
    return block


def _fund_via_transfer(chain: Blockchain, recipient_amount: float = 100.0, fee: float = 0.0):
    """Funda uma conta via mineracao simples e devolve uma tx de transferencia
    PENDENTE (ainda nao minerada) com valor elegivel para recompensa (block_value),
    pronta para ser minerada num bloco de pool mining."""
    payer = Wallet.create()
    dest = Wallet.create()
    credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=payer.address,
                          amount=recipient_amount, tx_type="coinbase_purchase")
    chain.add_transaction(credit)
    bootstrap_miner = Wallet.create()
    _mine_and_submit(chain, bootstrap_miner.address)  # confirma o credito (funda o payer)

    transfer = Transaction(sender=payer.address, recipient=dest.address,
                            amount=recipient_amount / 2, fee=fee)
    transfer.sign(payer.private_key, payer.public_key)
    assert chain.add_transaction(transfer)
    return transfer


def test_pool_mining_splits_reward_proportionally_and_preserves_total():
    chain = Blockchain(difficulty_mode="demo")
    miner_a = Wallet.create()
    miner_b = Wallet.create()
    miner_c = Wallet.create()
    transfer = _fund_via_transfer(chain, recipient_amount=100.0)
    assembler = Wallet.create()

    contributors = [(miner_a.address, 50.0), (miner_b.address, 30.0), (miner_c.address, 20.0)]
    block = _mine_and_submit_pool(chain, assembler.address, contributors)

    total_reward = block.miner_reward()
    assert total_reward > 0
    breakdown = {item["address"]: item["amount"] for item in block.reward_breakdown()}
    assert set(breakdown) == {miner_a.address, miner_b.address, miner_c.address}
    # soma paga aos contribuidores deve ser EXATAMENTE a recompensa total (sem
    # perda/sobra por arredondamento de ponto flutuante)
    assert round(sum(breakdown.values()), 8) == total_reward
    # proporcionalidade: miner_a (peso 50/100) recebe mais que miner_b, que recebe mais que miner_c
    assert breakdown[miner_a.address] > breakdown[miner_b.address] > breakdown[miner_c.address]
    assert chain.get_balance(miner_a.address) == breakdown[miner_a.address]
    assert chain.get_balance(miner_b.address) == breakdown[miner_b.address]
    assert chain.get_balance(miner_c.address) == breakdown[miner_c.address]
    assert chain.is_chain_valid()


def test_pool_mining_without_contributors_keeps_legacy_single_miner_behavior():
    chain = Blockchain(difficulty_mode="demo")
    _fund_via_transfer(chain, recipient_amount=10.0)
    assembler = Wallet.create()
    block = chain.build_candidate_block(assembler.address)  # sem `contributors`
    result = mine_block(block, max_iterations=5_000_000, prefer_gpu=False)
    assert chain.submit_mined_block(block, result.nonce, result.block_hash)
    breakdown = block.reward_breakdown()
    assert len(breakdown) == 1
    assert breakdown[0]["address"] == assembler.address


def test_pool_mining_rejects_invalid_contributor_address():
    chain = Blockchain(difficulty_mode="demo")
    _fund_via_transfer(chain, recipient_amount=10.0)
    assembler = Wallet.create()
    import pytest
    with pytest.raises(ValueError):
        chain.build_candidate_block(assembler.address, contributors=[("nao-e-um-endereco-valido", 1.0)])


def test_pool_mining_rejects_too_many_contributors():
    chain = Blockchain(difficulty_mode="demo")
    _fund_via_transfer(chain, recipient_amount=10.0)
    assembler = Wallet.create()
    too_many = [(Wallet.create().address, 1.0) for _ in range(root_rules.MAX_POOL_CONTRIBUTORS_PER_BLOCK + 1)]
    import pytest
    with pytest.raises(ValueError):
        chain.build_candidate_block(assembler.address, contributors=too_many)


def test_pool_mining_aggregates_repeated_contributor_addresses():
    """Um mesmo minerador pode ter submetido varios shares de trabalho parcial;
    o protocolo deve somar os pesos e pagar UMA unica tx de recompensa a ele."""
    chain = Blockchain(difficulty_mode="demo")
    miner_a = Wallet.create()
    miner_b = Wallet.create()
    _fund_via_transfer(chain, recipient_amount=10.0)
    assembler = Wallet.create()
    contributors = [(miner_a.address, 5.0), (miner_a.address, 5.0), (miner_b.address, 10.0)]
    block = _mine_and_submit_pool(chain, assembler.address, contributors)
    breakdown = block.reward_breakdown()
    assert len(breakdown) == 2  # agregado em uma unica tx por endereco
    by_address = {item["address"]: item["amount"] for item in breakdown}
    # miner_a (peso agregado 10) e miner_b (peso 10) devem receber a mesma fatia
    assert by_address[miner_a.address] == by_address[miner_b.address]


def test_is_chain_valid_detects_tampering_after_mining():
    chain = Blockchain(difficulty_mode="demo")
    alice = Wallet.create()
    miner = Wallet.create()
    credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                          amount=1.0, tx_type="coinbase_purchase")
    chain.add_transaction(credit)
    _mine_and_submit(chain, miner.address)
    assert chain.is_chain_valid()

    # adultera o valor de uma tx ja minerada, sem re-minerar - hash do bloco nao bate mais
    chain.chain[1].transactions[0].amount = 999.0
    assert chain.is_chain_valid() is False


def test_mempool_priority_orders_by_fee_descending():
    chain = Blockchain(difficulty_mode="demo")
    alice = Wallet.create()
    bob = Wallet.create()
    miner = Wallet.create()
    credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                          amount=10.0, tx_type="coinbase_purchase")
    chain.add_transaction(credit)
    _mine_and_submit(chain, miner.address)

    low_fee = Transaction(sender=alice.address, recipient=bob.address, amount=1.0, fee=0.001)
    low_fee.sign(alice.private_key, alice.public_key)
    high_fee = Transaction(sender=alice.address, recipient=bob.address, amount=1.0, fee=0.5)
    high_fee.sign(alice.private_key, alice.public_key)
    assert chain.add_transaction(low_fee)
    assert chain.add_transaction(high_fee)

    block = chain.build_candidate_block(miner.address, max_tx=1)
    # com max_tx=1 (mais a coinbase), so a tx de maior taxa deve ter sido escolhida
    non_coinbase = [t for t in block.transactions if t.tx_type != "coinbase_mining"]
    assert len(non_coinbase) == 1
    assert non_coinbase[0].tx_id == high_fee.tx_id
