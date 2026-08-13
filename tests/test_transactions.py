"""
Testes de assinatura/validacao de Transaction: cobre a regra de replay via
`network_id`, a taxa opcional (`fee`), saldo insuficiente e adulteracao de
assinatura - as garantias criptograficas centrais do protocolo.
"""
import pytest

from app import root_rules
from app.models import Blockchain, Transaction
from app.wallet import Wallet


@pytest.fixture
def alice():
    return Wallet.create(label="alice")


@pytest.fixture
def bob():
    return Wallet.create(label="bob")


def _signed_tx(sender: Wallet, recipient: str, amount: float, fee: float = 0.0, **kwargs) -> Transaction:
    tx = Transaction(sender=sender.address, recipient=recipient, amount=amount, fee=fee, **kwargs)
    tx.sign(sender.private_key, sender.public_key)
    return tx


def test_valid_signed_transaction_passes(alice, bob):
    tx = _signed_tx(alice, bob.address, 1.0)
    assert tx.is_valid()


def test_tampered_amount_after_signing_is_rejected(alice, bob):
    tx = _signed_tx(alice, bob.address, 1.0)
    tx.amount = 1000.0  # adulteracao pos-assinatura: hash assinado nao bate mais
    assert not tx.is_valid()


def test_wrong_network_id_is_rejected_replay_protection(alice, bob):
    tx = _signed_tx(alice, bob.address, 1.0)
    tx.network_id = root_rules.NETWORK_ID_TESTNET
    # mesmo re-assinando com a chave certa, o consenso da rede ativa (mainnet)
    # deve rejeitar uma tx destinada a outra rede/fork (nunca deve validar cruzado)
    tx.sign(alice.private_key, alice.public_key)
    assert not tx.is_valid()


def test_negative_fee_is_rejected(alice, bob):
    tx = Transaction(sender=alice.address, recipient=bob.address, amount=1.0, fee=-0.01)
    tx.sign(alice.private_key, alice.public_key)
    assert not tx.is_valid()


def test_fee_is_bound_to_signature_cannot_be_raised_after_signing(alice, bob):
    tx = _signed_tx(alice, bob.address, 1.0, fee=0.01)
    tx.fee = 999.0  # tentar elevar a taxa depois de assinado
    assert not tx.is_valid()


def test_unsigned_transaction_is_rejected(alice, bob):
    tx = Transaction(sender=alice.address, recipient=bob.address, amount=1.0)
    assert not tx.is_valid()


def test_signature_from_wrong_key_is_rejected(alice, bob):
    tx = Transaction(sender=alice.address, recipient=bob.address, amount=1.0)
    # bob assina no lugar de alice - chave nao corresponde ao endereco remetente
    tx.sign(bob.private_key, bob.public_key)
    assert not tx.is_valid()


def test_add_transaction_rejects_insufficient_balance(alice, bob):
    chain = Blockchain(difficulty_mode="demo")
    tx = _signed_tx(alice, bob.address, 5.0)  # alice nao tem saldo algum ainda
    assert chain.add_transaction(tx) is False


def test_add_transaction_balance_check_includes_fee(alice, bob):
    chain = Blockchain(difficulty_mode="demo")
    # credita saldo exato de 1.0 via coinbase_purchase (tipo de sistema, sem assinatura)
    credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                          amount=1.0, tx_type="coinbase_purchase")
    assert chain.add_transaction(credit)
    block = chain.build_candidate_block(bob.address)
    from app.mining import mine_block
    result = mine_block(block, max_iterations=2_000_000, prefer_gpu=False)
    assert chain.submit_mined_block(block, result.nonce, result.block_hash)

    # agora alice tem exatamente 1.0 PXC; amount(1.0) + fee(0.001) excede o saldo
    tx = _signed_tx(alice, bob.address, 1.0, fee=0.001)
    assert chain.add_transaction(tx) is False

    # mas amount(0.5) + fee(0.001) cabe dentro do saldo
    tx2 = _signed_tx(alice, bob.address, 0.5, fee=0.001)
    assert chain.add_transaction(tx2) is True


def test_replay_of_already_pending_tx_id_is_rejected(alice, bob):
    from app.mining import mine_block

    chain = Blockchain(difficulty_mode="demo")
    miner = Wallet.create()
    credit = Transaction(sender=root_rules.COINBASE_SENDER, recipient=alice.address,
                          amount=5.0, tx_type="coinbase_purchase")
    chain.add_transaction(credit)
    block = chain.build_candidate_block(miner.address)
    result = mine_block(block, max_iterations=5_000_000, prefer_gpu=False)
    assert chain.submit_mined_block(block, result.nonce, result.block_hash)

    tx = _signed_tx(alice, bob.address, 1.0)
    tx2 = Transaction(**{**tx.to_dict()})  # copia identica (mesmo tx_id)
    assert chain.add_transaction(tx) is True
    assert chain.add_transaction(tx2) is False
