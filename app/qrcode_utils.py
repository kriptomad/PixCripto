"""
Geracao de QR Code para pagamentos, no mesmo espirito do Pix (payload "copia e cola").

O payload e um JSON compacto assinado apenas por conveniencia de leitura (nao
precisa de assinatura criptografica em si, pois quem assina de fato e a
transacao que o pagador criara ao ler o QR code).
"""
from __future__ import annotations

import base64
import io
import json

import qrcode


def build_payment_payload(address: str, amount: float | None = None, memo: str = "") -> str:
    payload = {
        "protocol": "PIXCRIPTO01",
        "address": address,
        "amount": amount,
        "memo": memo,
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    encoded = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
    return f"pixcripto://pay?data={encoded}"


def decode_payment_payload(payload: str) -> dict:
    data_part = payload.split("data=", 1)[-1]
    padding = "=" * (-len(data_part) % 4)
    raw = base64.urlsafe_b64decode(data_part + padding)
    return json.loads(raw)


def generate_qr_base64(payload: str) -> str:
    """Gera a imagem do QR code em PNG, codificada em base64 (pronta para <img src=...>)."""
    img = qrcode.make(payload)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("ascii")
