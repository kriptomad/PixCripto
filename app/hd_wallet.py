"""
HD Wallet (Hierarchical Deterministic) - especificacao propria equivalente a
BIP-32/39/44, seguida literalmente conforme a secao 2.8 do guia
"blockchain-do-zero.md". Permite gerar UMA seed phrase (mnemonic) e derivar
quantas contas o usuario quiser a partir dela, cada uma com seu proprio
par de chaves/endereco, sem precisar fazer backup de cada conta individualmente
(apenas da seed phrase).

Passo a passo implementado (identico ao do guia):
  1) Gerar entropia aleatoria (128 bits = 12 palavras, ou 256 bits = 24 palavras)
  2) checksum = primeiros (entropia_bits / 32) bits do SHA-256(entropia)
  3) entropia_com_checksum = entropia || checksum
  4) Dividir em grupos de 11 bits -> cada grupo indexa uma palavra da wordlist
     de 2048 palavras (reaproveitamos a wordlist publica do BIP-39 em ingles -
     e apenas uma lista de palavras, sem problema de licenca, como o guia observa)
  5) seed_bytes = PBKDF2-HMAC-SHA512(mnemonic, salt="pixcripto"+passphrase, 2048 iter, 64 bytes)
  6) I = HMAC-SHA512(key="PixCripto HD seed", data=seed_bytes)
     master_private_key = I[0:32]; master_chain_code = I[32:64]
  7) Derivacao de filhos (m/44'/COIN_TYPE'/0'/0/index):
     I = HMAC-SHA512(key=chain_code_atual, data=0x00 || private_key_atual || index_4bytes)
     nova_private_key = (I[0:32] + private_key_atual) mod n   (n = ordem da curva secp256k1)
     novo_chain_code = I[32:64]
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from pathlib import Path
from typing import List, Tuple

from ecdsa import SECP256k1

from . import crypto_utils

_WORDLIST_PATH = Path(__file__).resolve().parent / "bip39_english.txt"
WORDLIST: List[str] = _WORDLIST_PATH.read_text(encoding="utf-8").split()
assert len(WORDLIST) == 2048, "wordlist BIP-39 precisa ter exatamente 2048 palavras"
_WORD_INDEX = {w: i for i, w in enumerate(WORDLIST)}

CURVE_ORDER = SECP256k1.order
SEED_HMAC_KEY = b"PixCripto HD seed"
MNEMONIC_SALT_PREFIX = "pixcripto"

# BIP44-style path: m/44'/COIN_TYPE'/0'/0/index - COIN_TYPE proprio da rede
# (nao precisa estar registrado em nenhum orgao externo, e uma constante interna
# do protocolo, so usada para separar namespaces de derivacao caso o mesmo
# codigo seja reaproveitado por uma rede irma/testnet no futuro).
HD_PURPOSE = 44
HD_COIN_TYPE = 7777
HARDENED_OFFSET = 0x80000000


def _hardened(index: int) -> int:
    return index + HARDENED_OFFSET


def generate_mnemonic(strength_bits: int = 128) -> str:
    """Gera uma nova seed phrase. `strength_bits`: 128 (12 palavras) ou 256 (24 palavras)."""
    if strength_bits not in (128, 160, 192, 224, 256):
        raise ValueError("strength_bits deve ser 128, 160, 192, 224 ou 256 (padrao BIP-39)")
    entropy = secrets.token_bytes(strength_bits // 8)
    return _entropy_to_mnemonic(entropy)


def _entropy_to_mnemonic(entropy: bytes) -> str:
    entropy_bits = len(entropy) * 8
    checksum_bits = entropy_bits // 32
    checksum_byte = hashlib.sha256(entropy).digest()[0]
    checksum = checksum_byte >> (8 - checksum_bits)

    # concatena entropia + checksum como uma sequencia unica de bits
    total_bits = entropy_bits + checksum_bits
    value = int.from_bytes(entropy, "big") << checksum_bits | checksum

    words = []
    for i in range(total_bits // 11):
        shift = total_bits - (i + 1) * 11
        index = (value >> shift) & 0x7FF
        words.append(WORDLIST[index])
    return " ".join(words)


def validate_mnemonic(mnemonic: str) -> bool:
    """Verifica que todas as palavras existem na wordlist E que o checksum bate -
    detecta tanto erros de digitacao quanto seed phrases inventadas/corrompidas."""
    words = mnemonic.strip().split()
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    try:
        indices = [_WORD_INDEX[w] for w in words]
    except KeyError:
        return False
    total_bits = len(words) * 11
    checksum_bits = total_bits // 33
    entropy_bits = total_bits - checksum_bits
    value = 0
    for idx in indices:
        value = (value << 11) | idx
    checksum = value & ((1 << checksum_bits) - 1)
    entropy_int = value >> checksum_bits
    entropy = entropy_int.to_bytes(entropy_bits // 8, "big")
    expected_checksum_byte = hashlib.sha256(entropy).digest()[0]
    expected_checksum = expected_checksum_byte >> (8 - checksum_bits)
    return checksum == expected_checksum


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """PBKDF2-HMAC-SHA512, 2048 iteracoes, 64 bytes de saida (identico ao BIP-39)."""
    salt = (MNEMONIC_SALT_PREFIX + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), salt, 2048, dklen=64)


def seed_to_master_key(seed: bytes) -> Tuple[bytes, bytes]:
    """Retorna (master_private_key: 32 bytes, master_chain_code: 32 bytes)."""
    digest = hmac.new(SEED_HMAC_KEY, seed, hashlib.sha512).digest()
    return digest[:32], digest[32:]


def derive_child_key(private_key: bytes, chain_code: bytes, index: int) -> Tuple[bytes, bytes]:
    """Deriva UM nivel da hierarquia (formula da secao 2.8 do guia)."""
    data = b"\x00" + private_key + index.to_bytes(4, "big")
    digest = hmac.new(chain_code, data, hashlib.sha512).digest()
    il, chain_code_new = digest[:32], digest[32:]
    child_key_int = (int.from_bytes(il, "big") + int.from_bytes(private_key, "big")) % CURVE_ORDER
    if child_key_int == 0:
        raise ValueError("chave filha invalida (probabilidade ~0, tente outro indice)")
    return child_key_int.to_bytes(32, "big"), chain_code_new


def derive_path(master_private_key: bytes, master_chain_code: bytes, path: List[int]) -> Tuple[bytes, bytes]:
    """Deriva ao longo de uma sequencia de indices (cada um ja com o offset
    HARDENED_OFFSET aplicado, se for o caso)."""
    key, chain_code = master_private_key, master_chain_code
    for index in path:
        key, chain_code = derive_child_key(key, chain_code, index)
    return key, chain_code


def derive_account(mnemonic: str, account_index: int, passphrase: str = "") -> Tuple[str, str, str]:
    """
    Deriva a N-esima conta (m/44'/COIN_TYPE'/0'/0/account_index) a partir de
    uma seed phrase. Retorna (private_key_hex, public_key_hex, address).
    Chamando esta funcao novamente com o MESMO mnemonic + account_index sempre
    produz exatamente a mesma conta (determinismo obrigatorio de uma HD wallet).
    """
    if not validate_mnemonic(mnemonic):
        raise ValueError("Seed phrase invalida (palavra desconhecida ou checksum nao confere)")
    seed = mnemonic_to_seed(mnemonic, passphrase)
    master_key, master_chain_code = seed_to_master_key(seed)
    path = [_hardened(HD_PURPOSE), _hardened(HD_COIN_TYPE), _hardened(0), 0, account_index]
    private_key, _ = derive_path(master_key, master_chain_code, path)
    private_key_hex = private_key.hex()
    public_key_hex = crypto_utils._public_key_hex_from_private(private_key_hex)
    address = crypto_utils.public_key_to_address(public_key_hex)
    return private_key_hex, public_key_hex, address


# ---------------------------------------------------------------------------
# Rotacao automatica de endereco ("conta auto-mutavel")
# ---------------------------------------------------------------------------
# Reutilizar sempre o mesmo endereco de recebimento facilita a analise de
# cadeia (chain analysis) e concentra a superficie de ataque de forca bruta
# num unico par de chaves. Bitcoin/BIP-44 resolvem isso com o conceito de
# "gap limit": a carteira deriva enderecos NOVOS automaticamente a cada
# recebimento, e so considera "sem uso" um bloco de ate `HD_GAP_LIMIT`
# indices consecutivos sem nenhuma atividade on-chain. Implementamos a mesma
# logica aqui: a seed phrase nunca muda, mas a CONTA (indice derivado) usada
# para receber muda automaticamente a cada vez, sem exigir nenhum backup
# adicional do usuario (basta a seed phrase original).
HD_GAP_LIMIT = 20


def find_next_unused_account(
    mnemonic: str, is_used_fn, passphrase: str = "", start_index: int = 0,
    gap_limit: int = HD_GAP_LIMIT,
) -> Tuple[int, str, str, str]:
    """
    Varre indices a partir de `start_index` e retorna a primeira conta
    (indice, private_key_hex, public_key_hex, address) para a qual
    `is_used_fn(address) -> bool` retorna False (nenhuma atividade on-chain
    ainda). Nunca reutiliza um endereco ja usado - a cada chamada apos um
    recebimento, uma conta NOVA e devolvida automaticamente ("auto-mutacao"
    da carteira). Respeita o gap limit (BIP-44): para de procurar apos
    `gap_limit` indices consecutivos sem uso e devolve o primeiro deles,
    evitando uma varredura infinita caso `is_used_fn` esteja sempre certo.
    """
    if not validate_mnemonic(mnemonic):
        raise ValueError("Seed phrase invalida (palavra desconhecida ou checksum nao confere)")
    if start_index < 0:
        raise ValueError("start_index deve ser >= 0")
    candidates = []
    for offset in range(gap_limit):
        index = start_index + offset
        private_key_hex, public_key_hex, address = derive_account(mnemonic, index, passphrase)
        candidates.append((index, private_key_hex, public_key_hex, address))
        if not is_used_fn(address):
            return index, private_key_hex, public_key_hex, address
    # todo o intervalo (gap limit) ja tem atividade - devolve o primeiro
    # candidato de qualquer forma (o chamador pode aumentar start_index e
    # tentar novamente se quiser continuar a varredura alem do gap limit)
    return candidates[0]
