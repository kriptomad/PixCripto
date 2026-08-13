"""
Compra de moeda PixCripto com Reais (BRL).

Regra de negocio definida pelo usuario: incide uma taxa de 7,38% sobre o valor,
aplicada a cada faixa de R$100. Ou seja, para cada R$100 (ou fracao) comprados,
cobra-se 7,38% de taxa sobre essa faixa.

Exemplo: comprar R$250 -> 3 faixas de R$100 (100 + 100 + 50)
  taxa = 100*0.0738 + 100*0.0738 + 50*0.0738 = 250 * 0.0738 = 18.45
(matematicamente equivale a aplicar 7,38% sobre o valor total, pois a taxa e
linear por faixa; mantemos o calculo por faixa explicito para ficar fiel ao
enunciado e permitir facilmente trocar por uma taxa progressiva no futuro).

SEGURANCA (corrigido apos auditoria): a versao anterior permitia que qualquer
cliente chamasse `/purchase/confirm` repetidamente e recebesse PXC recem-cunhado
ILIMITADAMENTE, sem nenhuma verificacao de pagamento real - uma falha CRITICA de
cunhagem arbitraria. Agora a compra segue um fluxo de 3 passos com cotacao
travada + assinatura HMAC do "gateway de pagamento" (simulado aqui; em producao
DEVE ser substituido pela verificacao de assinatura real do webhook do provedor
de pagamento - PIX, cartao, etc.):

  1. `quote_purchase()` gera uma cotacao com `quote_id` unico, valor/endereco
     TRAVADOS (nao podem ser alterados depois) e prazo de expiracao curto.
  2. O gateway de pagamento (em producao: PIX/cartao real; aqui: endpoint de
     simulacao) aprova o pagamento e assina `quote_id` com uma chave secreta
     que SOMENTE o servidor conhece.
  3. `confirm_purchase()` so cunha PXC se a assinatura for valida, a cotacao
     nao tiver expirado e o mesmo `quote_id`/`payment_reference` nunca tiver
     sido usado antes (idempotencia - impede reuso/replay).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
import uuid
from dataclasses import dataclass
from typing import Dict, Optional

from .gold_oracle import gold_oracle

FEE_RATE_PER_100 = 0.0738
BRACKET_SIZE = 100.0
COIN_NAME = "PXC"

QUOTE_EXPIRY_SECONDS = 5 * 60

# Chave secreta do "gateway de pagamento". Em producao isto NUNCA deve ser um
# valor padrao/hardcoded - deve vir de uma variavel de ambiente/segredo gerenciado
# (ex.: AWS Secrets Manager, Azure Key Vault) e ser o segredo compartilhado com o
# provedor de pagamento real (PIX/adquirente de cartao) para validar webhooks.
_GATEWAY_SECRET = os.environ.get("PIXCRIPTO_GATEWAY_SECRET", "").strip()
if not _GATEWAY_SECRET:
    # gera um segredo efemero por processo so para permitir rodar/testar localmente;
    # em producao real, DEFINA `PIXCRIPTO_GATEWAY_SECRET` explicitamente (senao o
    # segredo muda a cada reinicio e nenhum webhook antigo mais validaria).
    _GATEWAY_SECRET = uuid.uuid4().hex


@dataclass
class PurchaseQuote:
    quote_id: str
    amount_brl: float
    fee_brl: float
    total_charged_brl: float
    coins_credited: float
    pxc_brl_rate: float
    recipient_address: str
    expires_at: float


class _QuoteAlreadyUsed(Exception):
    pass


class PurchaseLedger:
    """Registro de cotacoes emitidas e pagamentos ja confirmados (idempotencia)."""

    def __init__(self) -> None:
        self._quotes: Dict[str, PurchaseQuote] = {}
        self._used_payment_references: set[str] = set()
        self._used_quote_ids: set[str] = set()

    def create_quote(self, amount_brl: float, recipient_address: str) -> PurchaseQuote:
        fee = calculate_purchase_fee(amount_brl)
        snapshot = gold_oracle.snapshot()
        coins = round(amount_brl / snapshot.pxc_brl_rate, 8)
        quote = PurchaseQuote(
            quote_id=uuid.uuid4().hex,
            amount_brl=amount_brl,
            fee_brl=fee,
            total_charged_brl=round(amount_brl + fee, 2),
            coins_credited=coins,
            pxc_brl_rate=snapshot.pxc_brl_rate,
            recipient_address=recipient_address,
            expires_at=time.time() + QUOTE_EXPIRY_SECONDS,
        )
        self._quotes[quote.quote_id] = quote
        return quote

    def get_quote(self, quote_id: str) -> Optional[PurchaseQuote]:
        return self._quotes.get(quote_id)

    def sign_for_gateway_simulation(self, quote_id: str, payment_reference: str) -> str:
        """SOMENTE para fins de teste/demo local - simula o que o provedor de
        pagamento real assinaria apos aprovar o pagamento. Em producao, este
        metodo NAO EXISTE no seu servico; quem assina e o provedor externo, e
        voce apenas VERIFICA a assinatura dele (ver `verify_gateway_signature`)."""
        return _sign(quote_id, payment_reference)

    def confirm_via_webhook(self, quote_id: str, payment_reference: str) -> PurchaseQuote:
        """Confirma a compra a partir de um webhook PSP ja autenticado por HMAC
        na camada HTTP (ver `POST /purchase/webhook/confirm`).  Nao exige a
        assinatura interna do gateway porque a autenticacao ja foi feita pelo
        middleware do endpoint antes de chegar aqui."""
        from . import storage
        quote = self._quotes.get(quote_id)
        if quote is None:
            raise ValueError("quote_id desconhecido ou expirado")
        if time.time() > quote.expires_at:
            del self._quotes[quote_id]
            raise ValueError("Cotacao expirada; solicite uma nova em /purchase/quote-locked")
        if not payment_reference:
            raise ValueError("payment_reference obrigatorio")
        if (quote_id in self._used_quote_ids or payment_reference in self._used_payment_references
                or storage.is_payment_reference_used(payment_reference)):
            raise _QuoteAlreadyUsed("Este pagamento ja foi confirmado anteriormente (idempotencia)")
        self._used_quote_ids.add(quote_id)
        self._used_payment_references.add(payment_reference)
        storage.record_purchase_confirmation(payment_reference, quote_id, quote.recipient_address, quote.coins_credited)
        return quote

    def confirm(self, quote_id: str, payment_reference: str, gateway_signature: str) -> PurchaseQuote:
        from . import storage
        quote = self._quotes.get(quote_id)
        if quote is None:
            raise ValueError("quote_id desconhecido ou expirado")
        if time.time() > quote.expires_at:
            del self._quotes[quote_id]
            raise ValueError("Cotacao expirada; solicite uma nova em /purchase/quote")
        if not payment_reference:
            raise ValueError("payment_reference obrigatorio")
        if not hmac.compare_digest(_sign(quote_id, payment_reference), gateway_signature):
            raise ValueError("Assinatura do gateway de pagamento invalida")
        if (quote_id in self._used_quote_ids or payment_reference in self._used_payment_references
                or storage.is_payment_reference_used(payment_reference)):
            raise _QuoteAlreadyUsed("Esta cotacao/pagamento ja foi confirmado anteriormente (idempotencia)")
        self._used_quote_ids.add(quote_id)
        self._used_payment_references.add(payment_reference)
        storage.record_purchase_confirmation(payment_reference, quote_id, quote.recipient_address, quote.coins_credited)
        return quote


def _sign(quote_id: str, payment_reference: str) -> str:
    msg = f"{quote_id}:{payment_reference}".encode("utf-8")
    return hmac.new(_GATEWAY_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()


purchase_ledger = PurchaseLedger()


def calculate_purchase_fee(amount_brl: float) -> float:
    if amount_brl <= 0:
        return 0.0
    remaining = amount_brl
    total_fee = 0.0
    while remaining > 0:
        bracket = min(BRACKET_SIZE, remaining)
        total_fee += bracket * FEE_RATE_PER_100
        remaining -= bracket
    return round(total_fee, 2)


def quote_purchase(amount_brl: float) -> PurchaseQuote:
    """
    Cotacao de compra "livre" (sem travar endereco/quote_id) - usada apenas pelo
    endpoint informativo `/purchase/quote` (preview de preco). A compra real
    (`/purchase/confirm`) exige um quote travado via `PurchaseLedger.create_quote`.
    """
    fee = calculate_purchase_fee(amount_brl)
    snapshot = gold_oracle.snapshot()
    coins = round(amount_brl / snapshot.pxc_brl_rate, 8)
    return PurchaseQuote(
        quote_id="",
        amount_brl=amount_brl,
        fee_brl=fee,
        total_charged_brl=round(amount_brl + fee, 2),
        coins_credited=coins,
        pxc_brl_rate=snapshot.pxc_brl_rate,
        recipient_address="",
        expires_at=0.0,
    )

