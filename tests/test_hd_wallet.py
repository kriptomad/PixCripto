"""Testes da carteira HD (BIP39/32/44-style) - app/hd_wallet.py."""
from app import hd_wallet


def test_generate_mnemonic_12_words_and_valid():
    m = hd_wallet.generate_mnemonic(128)
    assert len(m.split()) == 12
    assert hd_wallet.validate_mnemonic(m)


def test_generate_mnemonic_24_words_and_valid():
    m = hd_wallet.generate_mnemonic(256)
    assert len(m.split()) == 24
    assert hd_wallet.validate_mnemonic(m)


def test_generate_mnemonic_is_random():
    m1 = hd_wallet.generate_mnemonic(128)
    m2 = hd_wallet.generate_mnemonic(128)
    assert m1 != m2


def test_known_bip39_test_vector_is_valid():
    # Vetor de teste padrao (entropia toda zero) - deve ser reconhecido como valido
    zero_entropy_mnemonic = "abandon " * 11 + "about"
    assert hd_wallet.validate_mnemonic(zero_entropy_mnemonic.strip())


def test_validate_mnemonic_rejects_bad_checksum():
    bad = "abandon " * 11 + "zoo"
    assert not hd_wallet.validate_mnemonic(bad.strip())


def test_validate_mnemonic_rejects_unknown_word():
    bad = "notaword " + "abandon " * 10 + "about"
    assert not hd_wallet.validate_mnemonic(bad.strip())


def test_validate_mnemonic_rejects_wrong_length():
    assert not hd_wallet.validate_mnemonic("abandon abandon")


def test_derive_account_is_deterministic():
    m = hd_wallet.generate_mnemonic(128)
    a = hd_wallet.derive_account(m, account_index=0)
    b = hd_wallet.derive_account(m, account_index=0)
    assert a == b


def test_derive_account_different_indexes_differ():
    m = hd_wallet.generate_mnemonic(128)
    priv0, pub0, addr0 = hd_wallet.derive_account(m, account_index=0)
    priv1, pub1, addr1 = hd_wallet.derive_account(m, account_index=1)
    assert priv0 != priv1
    assert addr0 != addr1


def test_derive_account_different_mnemonics_differ():
    m1 = hd_wallet.generate_mnemonic(128)
    m2 = hd_wallet.generate_mnemonic(128)
    _, _, addr1 = hd_wallet.derive_account(m1, account_index=0)
    _, _, addr2 = hd_wallet.derive_account(m2, account_index=0)
    assert addr1 != addr2


def test_derive_account_passphrase_changes_result():
    m = hd_wallet.generate_mnemonic(128)
    _, _, addr_no_pass = hd_wallet.derive_account(m, account_index=0)
    _, _, addr_with_pass = hd_wallet.derive_account(m, account_index=0, passphrase="extra-senha")
    assert addr_no_pass != addr_with_pass


def test_derive_account_rejects_invalid_mnemonic():
    import pytest
    with pytest.raises(ValueError):
        hd_wallet.derive_account("not a real seed phrase at all here nope", account_index=0)


def test_derived_address_has_valid_format():
    from app import crypto_utils
    m = hd_wallet.generate_mnemonic(128)
    _, _, address = hd_wallet.derive_account(m, account_index=0)
    assert crypto_utils.is_valid_address(address)


def test_derived_public_key_matches_private_key():
    from app import crypto_utils
    m = hd_wallet.generate_mnemonic(128)
    priv, pub, _ = hd_wallet.derive_account(m, account_index=0)
    assert crypto_utils._public_key_hex_from_private(priv) == pub


# ---------------------------------------------------------------------------
# Rotacao automatica de endereco ("conta auto-mutavel") - gap limit BIP-44
# ---------------------------------------------------------------------------

def test_find_next_unused_account_returns_first_index_when_all_unused():
    m = hd_wallet.generate_mnemonic(128)
    index, priv, pub, address = hd_wallet.find_next_unused_account(m, is_used_fn=lambda addr: False)
    assert index == 0
    expected = hd_wallet.derive_account(m, account_index=0)
    assert (priv, pub, address) == expected


def test_find_next_unused_account_skips_used_addresses():
    m = hd_wallet.generate_mnemonic(128)
    _, _, addr0 = hd_wallet.derive_account(m, account_index=0)
    _, _, addr1 = hd_wallet.derive_account(m, account_index=1)
    used = {addr0, addr1}
    index, _, _, address = hd_wallet.find_next_unused_account(m, is_used_fn=lambda addr: addr in used)
    assert index == 2
    assert address not in used


def test_find_next_unused_account_never_repeats_across_successive_calls():
    """Simula recebimentos sucessivos: a cada chamada, a conta anterior 'usada'
    nunca deve ser devolvida de novo - cada recebimento muda o endereco em uso."""
    m = hd_wallet.generate_mnemonic(128)
    used_addresses = set()
    returned = []
    for _ in range(5):
        index, _, _, address = hd_wallet.find_next_unused_account(
            m, is_used_fn=lambda addr: addr in used_addresses
        )
        assert address not in used_addresses
        used_addresses.add(address)
        returned.append(address)
    assert len(set(returned)) == 5  # 5 enderecos distintos, nenhuma reutilizacao


def test_find_next_unused_account_respects_gap_limit():
    m = hd_wallet.generate_mnemonic(128)
    # todos usados -> deve devolver o primeiro candidato (indice start_index)
    # em vez de escanear infinitamente
    index, _, _, address = hd_wallet.find_next_unused_account(
        m, is_used_fn=lambda addr: True, start_index=0, gap_limit=5
    )
    assert index == 0


def test_find_next_unused_account_rejects_invalid_mnemonic():
    import pytest
    with pytest.raises(ValueError):
        hd_wallet.find_next_unused_account("not a real seed phrase nope", is_used_fn=lambda addr: False)
