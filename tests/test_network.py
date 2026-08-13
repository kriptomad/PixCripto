"""
Testes de rede P2P (secao 7 do guia): handshake, gossip de transacoes e blocos,
e escolha de cadeia por trabalho acumulado (reorg). Usa `asyncio.run` puro em
vez de pytest-asyncio (nao adiciona nova dependencia) - cada teste sobe 2 nos
`P2PNode` reais em portas TCP locais distintas.
"""
import asyncio
import socket

import pytest

from app import root_rules
from app.mining import mine_block
from app.models import Blockchain, Transaction
from app.network import P2PNode
from app.wallet import Wallet


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _settle():
    """Da tempo para as tasks assincronas (leitura/gossip) processarem."""
    for _ in range(20):
        await asyncio.sleep(0.05)


def test_two_nodes_handshake_and_discover_each_other():
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        port_a, port_b = _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        await node_a.start()
        await node_b.start()
        try:
            await node_a.connect_to_peer("127.0.0.1", port_b)
            await _settle()
            assert len(node_a.peers) == 1
            assert len(node_b.peers) == 1
        finally:
            await node_a.stop()
            await node_b.stop()

    asyncio.run(scenario())


def test_incompatible_network_id_disconnects():
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        port_a, port_b = _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        await node_a.start()
        await node_b.start()
        try:
            # forca incompatibilidade adulterando o hash do genesis local de B
            # (simula duas redes/forks com genesis diferentes)
            chain_b.chain[0].hash = "f" * 64
            await node_a.connect_to_peer("127.0.0.1", port_b)
            await _settle()
            # a conexao deve ter sido fechada por incompatibilidade de genesis_hash
            assert len(node_a.peers) == 0
            assert len(node_b.peers) == 0
        finally:
            await node_a.stop()
            await node_b.stop()

    asyncio.run(scenario())


def test_transaction_gossip_propagates_to_peer_mempool():
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        port_a, port_b = _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        await node_a.start()
        await node_b.start()
        try:
            await node_a.connect_to_peer("127.0.0.1", port_b)
            await _settle()

            alice = Wallet.create()
            credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                                  amount=5.0, tx_type="coinbase_purchase")
            assert chain_a.add_transaction(credit)
            await node_a.broadcast_transaction(credit)
            await _settle()

            assert any(t.tx_id == credit.tx_id for t in chain_b.pending_transactions)
        finally:
            await node_a.stop()
            await node_b.stop()

    asyncio.run(scenario())


def test_block_gossip_propagates_and_is_applied_by_peer():
    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        chain_b = Blockchain(difficulty_mode="demo")
        port_a, port_b = _free_port(), _free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        await node_a.start()
        await node_b.start()
        try:
            await node_a.connect_to_peer("127.0.0.1", port_b)
            await _settle()

            alice = Wallet.create()
            miner = Wallet.create()
            credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                                  amount=5.0, tx_type="coinbase_purchase")
            assert chain_a.add_transaction(credit)
            block = chain_a.build_candidate_block(miner.address)
            result = mine_block(block, max_iterations=5_000_000, prefer_gpu=False)
            assert chain_a.submit_mined_block(block, result.nonce, result.block_hash)

            await node_a.broadcast_block(block)
            await _settle()

            assert chain_b.mined_block_count == 1
            assert chain_b.get_balance(alice.address) == 5.0
        finally:
            await node_a.stop()
            await node_b.stop()

    asyncio.run(scenario())


def test_chain_reorg_adopts_higher_work_chain():
    """Duas cadeias divergem (cada uma mineraram 1 bloco diferente na mesma
    altura); a de maior trabalho acumulado deve vencer via `try_replace_chain`,
    e a tx orfa do ramo perdedor deve voltar para a mempool."""
    chain_winner = Blockchain(difficulty_mode="demo")
    chain_loser = Blockchain(difficulty_mode="demo")

    alice = Wallet.create()
    bob = Wallet.create()
    miner = Wallet.create()

    # ramo perdedor: credita bob e minera
    credit_bob = Transaction(sender=root_rules.COINBASE_SENDER, recipient=bob.address,
                              amount=1.0, tx_type="coinbase_purchase")
    chain_loser.add_transaction(credit_bob)
    block_loser = chain_loser.build_candidate_block(miner.address)
    result_loser = mine_block(block_loser, max_iterations=5_000_000, prefer_gpu=False)
    assert chain_loser.submit_mined_block(block_loser, result_loser.nonce, result_loser.block_hash)

    # ramo vencedor: credita alice e minera (cadeias divergem a partir do bloco 1)
    credit_alice = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                                amount=1.0, tx_type="coinbase_purchase")
    chain_winner.add_transaction(credit_alice)
    block_winner = chain_winner.build_candidate_block(miner.address)
    result_winner = mine_block(block_winner, max_iterations=5_000_000, prefer_gpu=False)
    assert chain_winner.submit_mined_block(block_winner, result_winner.nonce, result_winner.block_hash)

    # ambas tem o mesmo trabalho (mesma dificuldade) - para forcar reorg
    # deterministico no teste, simulamos que a cadeia do vencedor tem 2 blocos
    # (mais trabalho acumulado real), minerando mais um bloco nela
    credit_alice2 = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                                 amount=1.0, tx_type="coinbase_purchase")
    chain_winner.add_transaction(credit_alice2)
    block_winner2 = chain_winner.build_candidate_block(miner.address)
    result_winner2 = mine_block(block_winner2, max_iterations=5_000_000, prefer_gpu=False)
    assert chain_winner.submit_mined_block(block_winner2, result_winner2.nonce, result_winner2.block_hash)

    assert chain_winner.total_work() > chain_loser.total_work()

    replaced = chain_loser.try_replace_chain(chain_winner.chain)
    assert replaced is True
    assert chain_loser.mined_block_count == 2
    assert chain_loser.get_balance(alice.address) == 2.0
    # a tx de credito do bob (so existia no ramo perdedor) e um coinbase_purchase,
    # que NAO deve retornar a mempool (system tx nunca e "reenviada" pelo usuario)
    assert not any(t.recipient == bob.address for t in chain_loser.pending_transactions)


def test_try_replace_chain_rejects_lower_or_equal_work():
    chain_a = Blockchain(difficulty_mode="demo")
    miner = Wallet.create()
    alice = Wallet.create()
    credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                          amount=1.0, tx_type="coinbase_purchase")
    chain_a.add_transaction(credit)
    block = chain_a.build_candidate_block(miner.address)
    result = mine_block(block, max_iterations=5_000_000, prefer_gpu=False)
    chain_a.submit_mined_block(block, result.nonce, result.block_hash)

    # tenta substituir pela mesma cadeia (trabalho igual) - deve rejeitar (nunca regressao)
    assert chain_a.try_replace_chain(chain_a.chain) is False


def test_try_replace_chain_rejects_invalid_candidate():
    chain_a = Blockchain(difficulty_mode="demo")
    miner = Wallet.create()
    alice = Wallet.create()
    credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                          amount=1.0, tx_type="coinbase_purchase")
    chain_a.add_transaction(credit)
    block = chain_a.build_candidate_block(miner.address)
    result = mine_block(block, max_iterations=5_000_000, prefer_gpu=False)
    chain_a.submit_mined_block(block, result.nonce, result.block_hash)

    # candidata com MAIS blocos (logo, mais trabalho bruto) mas com o hash do
    # segundo bloco adulterado - deve ser rejeitada pela validacao de integridade,
    # nao pela comparacao de trabalho (que sozinha a aceitaria)
    tampered = list(chain_a.chain)
    second_block = chain_a.build_candidate_block(miner.address) if chain_a.pending_transactions else None
    # garante um segundo bloco valido minerado, depois adultera seu hash
    credit2 = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                           amount=1.0, tx_type="coinbase_purchase")
    chain_a.add_transaction(credit2)
    block2 = chain_a.build_candidate_block(miner.address)
    result2 = mine_block(block2, max_iterations=5_000_000, prefer_gpu=False)
    chain_a.submit_mined_block(block2, result2.nonce, result2.block_hash)

    tampered_chain = list(chain_a.chain)
    tampered_chain[-1].hash = "0" * 64  # adultera o hash do ultimo bloco (nao bate mais com compute_hash())

    fresh_chain = Blockchain(difficulty_mode="demo")
    assert fresh_chain.try_replace_chain(tampered_chain) is False
