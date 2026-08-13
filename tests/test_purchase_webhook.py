"""
Testes do webhook de confirmacao de pagamento com verificacao HMAC real.

Cobre:
- /purchase/webhook/confirm (novo endpoint de producao)
  - assinatura HMAC correta → 200, credita PXC
  - assinatura errada → 401
  - sem segredo configurado em mainnet → 503
  - sem segredo configurado em devnet → aceita sem verificacao
  - replay do mesmo payment_reference → 409
- /purchase/webhook/simulate-payment-gateway (endpoint legado de dev)
  - fora de devnet (mainnet/testnet) → 403
  - em devnet → funciona como antes (200, retorna gateway_signature)
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import importlib
import json

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixtures helpers
# ---------------------------------------------------------------------------

def _make_client(tmp_path, monkeypatch, *, env="devnet", webhook_secret=""):
    """Sobe a API com storage isolado e as variaveis de ambiente configuradas."""
    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(tmp_path / "chain.db"))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "compliance.db"))
    monkeypatch.setenv("PIXCRIPTO_ENV", env)
    monkeypatch.setenv("PIXCRIPTO_PAYMENT_WEBHOOK_SECRET", webhook_secret)
    monkeypatch.setenv("PIXCRIPTO_PAYMENT_WEBHOOK_SIGNATURE_HEADER", "X-Webhook-Signature")

    import app.storage as storage_mod
    importlib.reload(storage_mod)
    import app.bruteforce_guard as bg
    bg.guard.reset_all()
    # Recarrega settings para pegar as novas variaveis de ambiente
    import app.settings as settings_mod
    importlib.reload(settings_mod)
    import app.purchase as purchase_mod
    importlib.reload(purchase_mod)
    import app.api as api_mod
    importlib.reload(api_mod)
    return TestClient(api_mod.app), api_mod


def _sign_body(secret: str, body_bytes: bytes) -> str:
    return _hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()


def _create_locked_quote(client, *, amount_brl=100.0):
    """Cria uma carteira e uma cotacao travada, retornando (quote_id, address)."""
    wallet = client.post("/wallet/create", json={}).json()
    address = wallet["address"]
    resp = client.post("/purchase/quote-locked", json={"amount_brl": amount_brl, "recipient_address": address})
    assert resp.status_code == 200, resp.text
    return resp.json()["quote_id"], address


# ---------------------------------------------------------------------------
# Testes do novo endpoint /purchase/webhook/confirm
# ---------------------------------------------------------------------------

class TestWebhookConfirmWithSecret:
    """Testes com PIXCRIPTO_PAYMENT_WEBHOOK_SECRET configurado."""

    @pytest.fixture
    def setup(self, tmp_path, monkeypatch):
        secret = "test-webhook-secret-1234"
        client, api_mod = _make_client(tmp_path, monkeypatch, env="devnet", webhook_secret=secret)
        return client, secret

    def test_valid_signature_returns_200_and_credits_pxc(self, setup):
        client, secret = setup
        quote_id, address = _create_locked_quote(client)

        payment_reference = "psp-pay-abc123"
        body = json.dumps({"quote_id": quote_id, "payment_reference": payment_reference}).encode()
        sig = _sign_body(secret, body)

        resp = client.post(
            "/purchase/webhook/confirm",
            content=body,
            headers={"Content-Type": "application/json", "X-Webhook-Signature": sig},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "tx_id" in data
        assert data["coins_credited"] > 0
        assert data["amount_brl"] == 100.0

    def test_wrong_signature_returns_401(self, setup):
        client, secret = setup
        quote_id, _ = _create_locked_quote(client)

        body = json.dumps({"quote_id": quote_id, "payment_reference": "pay-xyz"}).encode()
        resp = client.post(
            "/purchase/webhook/confirm",
            content=body,
            headers={"Content-Type": "application/json", "X-Webhook-Signature": "deadbeef" * 8},
        )
        assert resp.status_code == 401

    def test_missing_signature_header_returns_401(self, setup):
        client, secret = setup
        quote_id, _ = _create_locked_quote(client)
        body = json.dumps({"quote_id": quote_id, "payment_reference": "pay-nohdr"}).encode()
        resp = client.post(
            "/purchase/webhook/confirm",
            content=body,
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 401

    def test_replay_same_payment_reference_returns_409(self, setup):
        client, secret = setup
        quote_id, _ = _create_locked_quote(client)

        payment_reference = "psp-pay-replay-test"
        body = json.dumps({"quote_id": quote_id, "payment_reference": payment_reference}).encode()
        sig = _sign_body(secret, body)
        headers = {"Content-Type": "application/json", "X-Webhook-Signature": sig}

        r1 = client.post("/purchase/webhook/confirm", content=body, headers=headers)
        assert r1.status_code == 200, r1.text

        # Segunda chamada com o mesmo payment_reference deve ser rejeitada
        r2 = client.post("/purchase/webhook/confirm", content=body, headers=headers)
        assert r2.status_code == 409

    def test_unknown_quote_id_returns_400(self, setup):
        client, secret = setup
        body = json.dumps({"quote_id": "nao-existe", "payment_reference": "pay-111"}).encode()
        sig = _sign_body(secret, body)
        resp = client.post(
            "/purchase/webhook/confirm",
            content=body,
            headers={"Content-Type": "application/json", "X-Webhook-Signature": sig},
        )
        assert resp.status_code == 400


class TestWebhookConfirmWithoutSecretDevnet:
    """Em devnet sem segredo configurado, o endpoint aceita sem verificacao."""

    @pytest.fixture
    def setup(self, tmp_path, monkeypatch):
        client, api_mod = _make_client(tmp_path, monkeypatch, env="devnet", webhook_secret="")
        return client

    def test_no_secret_devnet_accepts_without_signature(self, setup):
        client = setup
        quote_id, _ = _create_locked_quote(client)
        body = json.dumps({"quote_id": quote_id, "payment_reference": "dev-pay-001"}).encode()
        resp = client.post(
            "/purchase/webhook/confirm",
            content=body,
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 200, resp.text


class TestWebhookConfirmWithoutSecretProduction:
    """Em ambientes nao-devnet sem segredo, o endpoint deve retornar 503."""

    @pytest.mark.parametrize("env", ["mainnet", "testnet"])
    def test_no_secret_production_returns_503(self, env, tmp_path, monkeypatch):
        client, _ = _make_client(tmp_path, monkeypatch, env=env, webhook_secret="")
        body = json.dumps({"quote_id": "any", "payment_reference": "pay-1"}).encode()
        resp = client.post(
            "/purchase/webhook/confirm",
            content=body,
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 503
        assert "PIXCRIPTO_PAYMENT_WEBHOOK_SECRET" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Testes do endpoint legado /purchase/webhook/simulate-payment-gateway
# ---------------------------------------------------------------------------

class TestSimulateGatewayEndpoint:

    def test_simulate_disabled_in_mainnet(self, tmp_path, monkeypatch):
        client, _ = _make_client(tmp_path, monkeypatch, env="mainnet")
        wallet = client.post("/wallet/create", json={}).json()
        ql_resp = client.post(
            "/purchase/quote-locked",
            json={"amount_brl": 50.0, "recipient_address": wallet["address"]},
        )
        assert ql_resp.status_code == 200
        quote_id = ql_resp.json()["quote_id"]

        resp = client.post(
            "/purchase/webhook/simulate-payment-gateway",
            json={"quote_id": quote_id, "payment_reference": "ref-001"},
        )
        assert resp.status_code == 403
        assert "devnet" in resp.json()["detail"].lower()

    def test_simulate_disabled_in_testnet(self, tmp_path, monkeypatch):
        client, _ = _make_client(tmp_path, monkeypatch, env="testnet")
        wallet = client.post("/wallet/create", json={}).json()
        ql_resp = client.post(
            "/purchase/quote-locked",
            json={"amount_brl": 50.0, "recipient_address": wallet["address"]},
        )
        assert ql_resp.status_code == 200
        quote_id = ql_resp.json()["quote_id"]
        resp = client.post(
            "/purchase/webhook/simulate-payment-gateway",
            json={"quote_id": quote_id, "payment_reference": "ref-002"},
        )
        assert resp.status_code == 403

    def test_simulate_works_in_devnet(self, tmp_path, monkeypatch):
        client, _ = _make_client(tmp_path, monkeypatch, env="devnet")
        wallet = client.post("/wallet/create", json={}).json()
        ql_resp = client.post(
            "/purchase/quote-locked",
            json={"amount_brl": 100.0, "recipient_address": wallet["address"]},
        )
        assert ql_resp.status_code == 200
        quote_id = ql_resp.json()["quote_id"]

        sim_resp = client.post(
            "/purchase/webhook/simulate-payment-gateway",
            json={"quote_id": quote_id, "payment_reference": "ref-devnet-ok"},
        )
        assert sim_resp.status_code == 200, sim_resp.text
        data = sim_resp.json()
        assert data["quote_id"] == quote_id
        assert "gateway_signature" in data

        # Confirma a compra usando a assinatura retornada
        confirm_resp = client.post(
            "/purchase/confirm",
            json={
                "quote_id": quote_id,
                "payment_reference": "ref-devnet-ok",
                "gateway_signature": data["gateway_signature"],
            },
        )
        assert confirm_resp.status_code == 200, confirm_resp.text
        assert confirm_resp.json()["coins_credited"] > 0
