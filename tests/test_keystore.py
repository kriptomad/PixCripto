"""
Testes do modulo de keystore (scrypt + AES-256-GCM + MAC): cobre o ciclo
completo de criptografar/descriptografar uma chave privada, e a rejeicao
correta de senha errada / keystore corrompido.
"""
import pytest

from app import crypto_utils
from app.wallet import Wallet


def test_keystore_roundtrip_recovers_original_private_key():
    priv, pub = crypto_utils.generate_keypair()
    keystore = crypto_utils.create_keystore(priv, "senha-super-secreta-123")
    recovered = crypto_utils.load_keystore(keystore, "senha-super-secreta-123")
    assert recovered == priv


def test_keystore_contains_correct_address():
    priv, pub = crypto_utils.generate_keypair()
    expected_address = crypto_utils.public_key_to_address(pub)
    keystore = crypto_utils.create_keystore(priv, "outra-senha-valida")
    assert keystore["address"] == expected_address


def test_keystore_wrong_password_raises_value_error():
    priv, _ = crypto_utils.generate_keypair()
    keystore = crypto_utils.create_keystore(priv, "senha-correta")
    with pytest.raises(ValueError):
        crypto_utils.load_keystore(keystore, "senha-errada")


def test_keystore_corrupted_ciphertext_is_rejected():
    priv, _ = crypto_utils.generate_keypair()
    keystore = crypto_utils.create_keystore(priv, "senha-correta")
    # adultera o ciphertext - o MAC nao deve mais bater
    original = keystore["crypto"]["ciphertext"]
    tampered = ("00" if original[:2] != "00" else "ff") + original[2:]
    keystore["crypto"]["ciphertext"] = tampered
    with pytest.raises(ValueError):
        crypto_utils.load_keystore(keystore, "senha-correta")


def test_wallet_to_keystore_and_from_keystore_roundtrip():
    wallet = Wallet.create(label="carteira-teste")
    keystore = wallet.to_keystore("minha-senha-forte")
    recovered_wallet = Wallet.from_keystore(keystore, "minha-senha-forte", label="carteira-teste")
    assert recovered_wallet.address == wallet.address
    assert recovered_wallet.private_key == wallet.private_key
    assert recovered_wallet.public_key == wallet.public_key


def test_wallet_from_keystore_wrong_password_raises():
    wallet = Wallet.create()
    keystore = wallet.to_keystore("senha-certa")
    with pytest.raises(ValueError):
        Wallet.from_keystore(keystore, "senha-errada")
