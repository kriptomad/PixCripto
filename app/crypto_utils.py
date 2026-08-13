"""
Utilitarios de criptografia assimetrica (ECDSA secp256k1 - mesma curva do Bitcoin/Ethereum).

Cada carteira possui um par de chaves (privada/publica). Toda transacao e assinada
com a chave privada do remetente e validada por qualquer no da rede com a chave
publica correspondente, garantindo que ninguem alem do dono da carteira possa
gastar seus fundos (nao-repudio + integridade).

Enderecos e chaves privadas seguem o MESMO padrao do Bitcoin:
- Endereco: Base58Check sobre RIPEMD160(SHA256(chave publica)) com byte de versao
  proprio da rede PixCripto (equivalente ao P2PKH do Bitcoin).
- Chave privada exportavel em WIF (Wallet Import Format), tambem Base58Check.
"""
from __future__ import annotations

import hashlib

import base58
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError

# Bytes de versao proprios da rede PixCripto (Bitcoin mainnet usa 0x00/0x80).
# Usar valores diferentes evita que enderecos/chaves sejam confundidos entre redes.
ADDRESS_VERSION_BYTE = 0x37   # produz enderecos comecando tipicamente por "P"
WIF_VERSION_BYTE = 0xB7      # produto compativel (versao privada = versao publica + 0x80)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def double_sha256(data: bytes) -> bytes:
    return sha256(sha256(data))


def ripemd160(data: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(data)
    return h.digest()


def merkle_root(leaf_hashes_hex: list) -> str:
    """Raiz de Merkle real (arvore binaria SHA-256) sobre uma lista de hashes hex
    (ex: tx_id ou hash de cada transacao). Duplica o ultimo elemento em niveis de
    tamanho impar (mesma regra usada pelo Bitcoin) - substitui o antigo esquema de
    "hash unico da lista serializada", que nao permitia provas de inclusao (Merkle
    proof) nem identificava QUAL transacao especifica mudou (gap identificado
    contra o guia "blockchain-do-zero.md", secao 3.1/3.3)."""
    if not leaf_hashes_hex:
        return "0" * 64
    layer = list(leaf_hashes_hex)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [
            hashlib.sha256((layer[i] + layer[i + 1]).encode("utf-8")).hexdigest()
            for i in range(0, len(layer), 2)
        ]
    return layer[0]


def generate_keypair() -> tuple[str, str]:
    """Gera (private_key_hex, public_key_hex)."""
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    return sk.to_string().hex(), vk.to_string().hex()


def public_key_to_address(public_key_hex: str) -> str:
    """
    Deriva o endereco da carteira a partir da chave publica, EXATAMENTE como o
    Bitcoin faz para enderecos P2PKH: SHA256 -> RIPEMD160 -> Base58Check
    (versao + payload + checksum de 4 bytes via double-SHA256).
    """
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
    except ValueError:
        raise ValueError("Chave publica invalida: nao e hexadecimal valido")
    # valida formato canonico de chave publica secp256k1 nao-comprimida (64 bytes,
    # coordenadas X||Y de 32 bytes cada) - o formato usado pela lib `ecdsa` aqui.
    # Rejeita blobs arbitrarios que nao sejam pontos validos da curva (correcao de
    # auditoria: antes qualquer hex de 64 bytes era aceito sem checar se e um
    # ponto valido da curva, permitindo enderecos derivados de "chaves" inuteis).
    if len(pub_bytes) != 64:
        raise ValueError("Chave publica invalida: tamanho incorreto (esperado 64 bytes, sem prefixo)")
    try:
        VerifyingKey.from_string(pub_bytes, curve=SECP256k1)
    except Exception as exc:
        raise ValueError(f"Chave publica invalida: nao e um ponto valido da curva secp256k1 ({exc})")
    pubkey_hash = ripemd160(sha256(pub_bytes))
    versioned = bytes([ADDRESS_VERSION_BYTE]) + pubkey_hash
    checksum = double_sha256(versioned)[:4]
    return base58.b58encode(versioned + checksum).decode("ascii")


def private_key_to_wif(private_key_hex: str, compressed: bool = True) -> str:
    """Exporta a chave privada no formato WIF (Wallet Import Format), como no Bitcoin."""
    key_bytes = bytes.fromhex(private_key_hex)
    payload = bytes([WIF_VERSION_BYTE]) + key_bytes + (b"\x01" if compressed else b"")
    checksum = double_sha256(payload)[:4]
    return base58.b58encode(payload + checksum).decode("ascii")


# ordem do subgrupo da curva secp256k1 - uma chave privada valida deve estar em [1, N-1]
_SECP256K1_ORDER = SECP256k1.order


def wif_to_private_key(wif: str) -> str:
    """Decodifica uma chave privada WIF de volta para hex, validando checksum,
    versao, comprimento EXATO do payload e se a chave e um escalar valido
    (1 <= chave < ordem da curva) - correcao de auditoria: a versao anterior
    apenas cortava `payload[1:33]` sem validar tamanho/flag de compressao,
    permitindo WIFs nao-canonicos mapearem ambiguamente para a mesma chave."""
    raw = base58.b58decode(wif)
    payload, checksum = raw[:-4], raw[-4:]
    if double_sha256(payload)[:4] != checksum:
        raise ValueError("WIF invalido: checksum nao confere")
    if payload[0] != WIF_VERSION_BYTE:
        raise ValueError("WIF invalido: byte de versao incorreto para a rede PixCripto")
    body = payload[1:]
    if len(body) == 33:
        if body[32] != 0x01:
            raise ValueError("WIF invalido: flag de compressao incorreta")
        key_bytes = body[:32]
    elif len(body) == 32:
        key_bytes = body
    else:
        raise ValueError("WIF invalido: comprimento de payload incorreto")
    key_int = int.from_bytes(key_bytes, "big")
    if not (1 <= key_int < _SECP256K1_ORDER):
        raise ValueError("WIF invalido: chave privada fora do intervalo valido da curva")
    return key_bytes.hex()


def is_valid_address(address: str) -> bool:
    """Valida um endereco PixCripto (Base58Check) - mesma logica de validacao do Bitcoin."""
    try:
        raw = base58.b58decode(address)
        if len(raw) != 25:
            return False
        payload, checksum = raw[:-4], raw[-4:]
        return double_sha256(payload)[:4] == checksum and payload[0] == ADDRESS_VERSION_BYTE
    except Exception:
        return False


def sign_message(private_key_hex: str, message: bytes) -> str:
    """
    Assina com ECDSA determinístico (RFC 6979 - `sign_deterministic`), em vez
    de assinatura aleatorizada. Correcao de auditoria: assinatura ECDSA com
    nonce (k) mal gerado/reaproveitado permite recuperar a chave privada
    (caso historico real: PS3/Sony, e vulnerabilidades tipo "Minerva" em
    implementacoes com vazamento de timing do nonce). RFC 6979 deriva o nonce
    deterministicamente a partir da chave privada + mensagem via HMAC, o que
    elimina a dependencia de uma fonte de aleatoriedade no momento de assinar.
    """
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    signature = sk.sign_deterministic(message, hashfunc=hashlib.sha256)
    return signature.hex()


def verify_signature(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
        return vk.verify(bytes.fromhex(signature_hex), message, hashfunc=hashlib.sha256)
    except (BadSignatureError, ValueError, Exception):
        return False


# ---------------------------------------------------------------------------
# Ofuscacao de transacao: memo confidencial via ECDH + AES-256-GCM
# ---------------------------------------------------------------------------
# Objetivo (pedido do usuario): "ofuscamento de transacao" real, nao apenas
# cosmetico. O ledger publico continua exibindo remetente/destinatario/valor
# em claro (necessario para qualquer um poder auditar saldos e validar a
# cadeia, exatamente como Bitcoin) - mas o CONTEUDO do memo (que pode conter
# um comentario, referencia de pagamento, dado de negocio) pode ser cifrado
# de ponta a ponta: apenas remetente e destinatario conseguem lê-lo, qualquer
# outro observador da blockchain ve apenas um blob opaco em base64.
#
# Esquema: Diffie-Hellman sobre secp256k1 (chave privada de quem cifra +
# chave publica do destinatario, ou vice-versa para decifrar) deriva um
# segredo compartilhado; HKDF-SHA256 disso deriva uma chave AES-256; o memo e
# cifrado com AES-256-GCM (autenticado - qualquer adulteracao do ciphertext e
# detectada na decifragem).
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import base64
import os as _os


def _ecdh_shared_key(private_key_hex: str, public_key_hex: str) -> bytes:
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
    # multiplica o ponto publico do outro lado pelo escalar privado local -
    # ambas as partes chegam ao MESMO ponto (property matematica do DH sobre
    # curvas elipticas), sem jamais transmitir a chave privada de ninguem.
    shared_point = vk.pubkey.point * sk.privkey.secret_multiplier
    shared_secret = shared_point.x().to_bytes(32, "big")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pixcripto-memo-v1").derive(shared_secret)


def encrypt_memo(sender_private_key_hex: str, recipient_public_key_hex: str, plaintext: str) -> str:
    """Cifra um memo para que SOMENTE o remetente e o destinatario possam lê-lo.
    Retorna uma string base64 (nonce || ciphertext-com-tag) pronta para ir no
    campo `memo` da transacao publica."""
    key = _ecdh_shared_key(sender_private_key_hex, recipient_public_key_hex)
    nonce = _os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return "ENC1:" + base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_memo(viewer_private_key_hex: str, counterparty_public_key_hex: str, encoded: str) -> str:
    """Decifra um memo produzido por `encrypt_memo`. Funciona tanto para o
    remetente (usando a chave publica do destinatario) quanto para o
    destinatario (usando a chave publica do remetente) - ECDH e simetrico."""
    if not encoded.startswith("ENC1:"):
        raise ValueError("Memo nao esta no formato cifrado esperado (prefixo ENC1: ausente)")
    raw = base64.b64decode(encoded[len("ENC1:"):])
    nonce, ciphertext = raw[:12], raw[12:]
    key = _ecdh_shared_key(viewer_private_key_hex, counterparty_public_key_hex)
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")


# ---------------------------------------------------------------------------
# Keystore criptografado da chave privada (formato estilo Ethereum/Bitcoin Core)
# ---------------------------------------------------------------------------
# Gap identificado contra o guia "blockchain-do-zero.md" (secao 9.3): a API ate
# aqui devolvia a chave privada em texto puro em `/wallet/create` (conveniencia
# de demo) e nunca oferecia um jeito padronizado de guarda-la CIFRADA em disco.
# As funcoes abaixo implementam exatamente o fluxo do guia: KDF lento (scrypt,
# memory-hard - resistente a forca bruta por GPU/ASIC) deriva uma chave de 32
# bytes da senha do usuario; AES-256-GCM (autenticado) cifra a chave privada;
# um MAC (HMAC-SHA256) adicional sobre o ciphertext detecta senha errada antes
# mesmo de tentar decifrar. O QUE NAO MUDA: o servidor nunca persiste isso em
# disco por conta propria - estas sao funcoes stateless de conversao, para uso
# por um cliente (wallet/CLI) que queira guardar sua propria chave cifrada.
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
_KEYSTORE_SALT_SIZE = 16
_KEYSTORE_NONCE_SIZE = 12


def _scrypt_derive(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN
    )


def create_keystore(private_key_hex: str, password: str) -> dict:
    """Cifra `private_key_hex` com `password`, retornando um dict pronto para
    ser salvo como JSON (formato compativel com a secao 9.3 do guia). A senha
    e a chave privada em texto puro NUNCA sao incluidas no resultado."""
    address = public_key_to_address(_public_key_hex_from_private(private_key_hex))
    salt = _os.urandom(_KEYSTORE_SALT_SIZE)
    nonce = _os.urandom(_KEYSTORE_NONCE_SIZE)
    derived_key = _scrypt_derive(password, salt)
    aesgcm = AESGCM(derived_key)
    ciphertext = aesgcm.encrypt(nonce, bytes.fromhex(private_key_hex), associated_data=None)
    # MAC adicional (alem da tag do proprio AES-GCM) sobre o ciphertext, para
    # detectar senha incorreta de forma explicita e amigavel (secao 9.3 do guia).
    mac = hashlib.new("sha256", derived_key + ciphertext).hexdigest()
    return {
        "version": 1,
        "address": address,
        "crypto": {
            "cipher": "aes-256-gcm",
            "ciphertext": ciphertext.hex(),
            "cipher_params": {"nonce": nonce.hex()},
            "kdf": "scrypt",
            "kdf_params": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "dklen": SCRYPT_DKLEN,
                           "salt": salt.hex()},
            "mac": mac,
        },
    }


def load_keystore(keystore: dict, password: str) -> str:
    """Decifra um keystore criado por `create_keystore`, retornando a chave
    privada em hex. Lanca ValueError se a senha estiver errada ou o keystore
    estiver corrompido/adulterado (MAC nao confere)."""
    c = keystore.get("crypto", {})
    if c.get("kdf") != "scrypt":
        raise ValueError("KDF desconhecido no keystore")
    kdf_params = c["kdf_params"]
    salt = bytes.fromhex(kdf_params["salt"])
    derived_key = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=kdf_params["n"], r=kdf_params["r"], p=kdf_params["p"], dklen=kdf_params["dklen"],
    )
    ciphertext = bytes.fromhex(c["ciphertext"])
    expected_mac = hashlib.new("sha256", derived_key + ciphertext).hexdigest()
    if expected_mac != c.get("mac"):
        raise ValueError("senha incorreta ou keystore corrompido (MAC nao confere)")
    nonce = bytes.fromhex(c["cipher_params"]["nonce"])
    aesgcm = AESGCM(derived_key)
    try:
        private_key_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception:
        raise ValueError("senha incorreta ou keystore corrompido")
    return private_key_bytes.hex()


def _public_key_hex_from_private(private_key_hex: str) -> str:
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    return sk.get_verifying_key().to_string().hex()

# ---------------------------------------------------------------------------
# Keccak-256 REAL (≠ SHA3-256 NIST) — usado pelo opcode SHA3 da EVM
# ---------------------------------------------------------------------------
# Por que importa: o opcode SHA3 da EVM usa o Keccak ORIGINAL (2012), NAO o
# SHA3 padronizado pelo NIST em 2015 (FIPS 202). A diferenca esta no padding:
#   - Keccak original: byte delimitador 0x01
#   - SHA3 NIST:       byte delimitador 0x06
# hashlib.sha3_256 implementa o SHA3 NIST (0x06) - produz hashes DIFERENTES
# do Keccak-256 da EVM para qualquer input. Exemplo: keccak256(b"") != sha3_256(b"").
# Como pycryptodome/pysha3 nao estao disponiveis no venv, implementamos em Python
# puro o Keccak-f[1600]: 25 lanes de 64 bits, 24 rounds, sponge rate=136 bytes.

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
# Offsets de rotacao ρ: _KECCAK_RHO[x][y] = bits de rotacao para lane (x,y)
_KECCAK_RHO = [
    [0, 36, 3, 41, 18],  # x=0
    [1, 44, 10, 45, 2],  # x=1
    [62, 6, 43, 15, 61],  # x=2
    [28, 55, 25, 21, 56],  # x=3
    [27, 20, 39, 8, 14],  # x=4
]
_MASK64 = (1 << 64) - 1


def _rot64(x: int, n: int) -> int:
    """Rotacao ciclica de 64 bits para a esquerda."""
    n &= 63
    return ((x << n) | (x >> (64 - n))) & _MASK64


def _keccak_f1600(state: list) -> None:
    """Permutacao Keccak-f[1600] in-place (24 rounds de θρπχι)."""
    for r in range(24):
        # θ: C[x] = XOR de toda a coluna x; D[x] = C[x-1] XOR ROT(C[x+1], 1)
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rot64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # ρ + π combinados: B[y, 2x+3y] = ROT(A[x,y], offset_rho[x][y])
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rot64(state[x + 5 * y], _KECCAK_RHO[x][y])
        # χ: A[x,y] = B[x,y] XOR ((NOT B[x+1,y]) AND B[x+2,y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & _MASK64 & b[(x + 2) % 5 + 5 * y])
        # ι: A[0,0] ^= RC[r]
        state[0] ^= _KECCAK_RC[r]


def keccak256(data: bytes) -> bytes:
    """
    Keccak-256 REAL - diferente do SHA3-256 NIST.
    Vetor de teste: keccak256(b"") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    """
    rate = 136  # bytes (rate = 1600 - 2*256 bits = 1088 bits)
    state = [0] * 25
    # Padding Keccak: 0x01 (nao 0x06 do SHA3 NIST), zeros, 0x80 no ultimo byte
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % rate != 0:
        msg.append(0x00)
    msg[-1] |= 0x80
    # Absorcao
    for block_start in range(0, len(msg), rate):
        block = msg[block_start:block_start + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:(i + 1) * 8], "little")
            state[i] ^= lane
        _keccak_f1600(state)
    # Extracao: primeiros 32 bytes (4 lanes de 64 bits em little-endian)
    result = bytearray()
    for i in range(4):
        result += state[i].to_bytes(8, "little")
    return bytes(result)


# ---------------------------------------------------------------------------
# RLP (Recursive Length Prefix) — serializacao canonica do Ethereum
# ---------------------------------------------------------------------------
# Spec publica: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
# Vetor de teste: rlp_encode(b"dog") == bytes([0x83, 0x64, 0x6f, 0x67])
#
# Suporta: bytes, str (UTF-8 -> bytes), int (big-endian sem zeros a esquerda),
# e listas aninhadas de qualquer profundidade.


def _rlp_encode_length(length: int, offset: int) -> bytes:
    """Codifica o prefixo de comprimento RLP (string ou lista)."""
    if length <= 55:
        return bytes([offset + length])
    len_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(len_bytes)]) + len_bytes


def rlp_encode(item) -> bytes:
    """
    RLP encode de um item (bytes, str, int, ou lista aninhada).
    Segue a especificacao publica do Ethereum.
    """
    if isinstance(item, str):
        item = item.encode("utf-8")
    if isinstance(item, int):
        if item == 0:
            item = b""
        else:
            item = item.to_bytes((item.bit_length() + 7) // 8, "big")
    if isinstance(item, (bytes, bytearray)):
        if len(item) == 1 and item[0] < 0x80:
            return bytes(item)  # byte unico em [0x00, 0x7f]: encode como ele mesmo
        return _rlp_encode_length(len(item), 0x80) + bytes(item)
    if isinstance(item, (list, tuple)):
        payload = b"".join(rlp_encode(i) for i in item)
        return _rlp_encode_length(len(payload), 0xC0) + payload
    raise TypeError(f"rlp_encode: tipo nao suportado {type(item)}")


def rlp_decode(data: bytes, offset: int = 0):
    """
    RLP decode a partir de `offset` em `data`.
    Retorna (valor_decodificado, novo_offset).
    valor_decodificado e bytes (string RLP) ou list (lista RLP).
    """
    if offset >= len(data):
        raise ValueError("rlp_decode: dados insuficientes")
    first = data[offset]
    if first < 0x80:
        # byte unico
        return bytes([first]), offset + 1
    if first <= 0xB7:
        # string curta (0-55 bytes)
        length = first - 0x80
        return bytes(data[offset + 1: offset + 1 + length]), offset + 1 + length
    if first <= 0xBF:
        # string longa (> 55 bytes)
        len_of_len = first - 0xB7
        length = int.from_bytes(data[offset + 1: offset + 1 + len_of_len], "big")
        start = offset + 1 + len_of_len
        return bytes(data[start:start + length]), start + length
    if first <= 0xF7:
        # lista curta (payload total <= 55 bytes)
        total_len = first - 0xC0
        end = offset + 1 + total_len
        items = []
        pos = offset + 1
        while pos < end:
            item, pos = rlp_decode(data, pos)
            items.append(item)
        return items, end
    # lista longa (payload > 55 bytes)
    len_of_len = first - 0xF7
    total_len = int.from_bytes(data[offset + 1: offset + 1 + len_of_len], "big")
    start = offset + 1 + len_of_len
    end = start + total_len
    items = []
    pos = start
    while pos < end:
        item, pos = rlp_decode(data, pos)
        items.append(item)
    return items, end

