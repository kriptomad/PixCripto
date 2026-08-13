"""
Carteira digital especifica do PixCripto.

Cada carteira tem:
- chave privada (nunca deve sair do dispositivo do usuario / cliente)
- chave publica
- endereco derivado (formato pix1...)

O saldo NAO fica armazenado na carteira: ele e sempre recalculado a partir do
historico de transacoes confirmadas na blockchain (mesmo modelo do Bitcoin/UTXO
simplificado / conta-saldo estilo Ethereum).
"""
from __future__ import annotations

from dataclasses import dataclass

from . import crypto_utils


@dataclass
class Wallet:
    private_key: str
    public_key: str
    address: str
    label: str = ""

    @staticmethod
    def create(label: str = "") -> "Wallet":
        priv, pub = crypto_utils.generate_keypair()
        address = crypto_utils.public_key_to_address(pub)
        return Wallet(private_key=priv, public_key=pub, address=address, label=label)

    def to_public_dict(self) -> dict:
        """Dados que podem ser compartilhados com seguranca (nunca a chave privada)."""
        return {"address": self.address, "public_key": self.public_key, "label": self.label}

    def to_full_dict(self) -> dict:
        """Inclui a chave privada (hex e WIF) - deve ser devolvido apenas uma vez, na criacao."""
        return {
            "address": self.address,
            "public_key": self.public_key,
            "private_key": self.private_key,
            "private_key_wif": crypto_utils.private_key_to_wif(self.private_key),
            "label": self.label,
        }

    def to_keystore(self, password: str) -> dict:
        """Cifra a chave privada com `password` (scrypt + AES-256-GCM, formato
        estilo Ethereum/Bitcoin Core - ver `crypto_utils.create_keystore`).
        O keystore resultante pode ser salvo em disco pelo cliente com seguranca:
        sem a senha, a chave privada nao pode ser recuperada dele."""
        return crypto_utils.create_keystore(self.private_key, password)

    @staticmethod
    def from_keystore(keystore: dict, password: str, label: str = "") -> "Wallet":
        """Reconstroi a Wallet a partir de um keystore cifrado + senha. Lanca
        ValueError se a senha estiver incorreta ou o keystore corrompido."""
        private_key = crypto_utils.load_keystore(keystore, password)
        public_key = crypto_utils._public_key_hex_from_private(private_key)
        address = crypto_utils.public_key_to_address(public_key)
        return Wallet(private_key=private_key, public_key=public_key, address=address, label=label)
