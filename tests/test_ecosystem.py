"""
Testes do "ecossistema completo" adicionado nesta rodada:

- Conformidade regulatoria (KYC/AML) - `app/compliance.py`
- API estilo exchange (Binance-like) - `app/exchange_api.py`
- Configuracao central/rede - `app/settings.py`, `app/network_config.py`
- UI web de carteira - rotas Jinja2 em `app/api.py`
- Painel de Administracao (fora de `app/`, nunca distribuido) - `admin_panel/main.py`

Cada modulo usa um banco SQLite proprio isolado por teste (via `tmp_path` +
`monkeypatch`), seguindo o mesmo padrao ja usado em `test_mempool_persistence.py`.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Conformidade regulatoria (KYC/AML)
# ---------------------------------------------------------------------------

@pytest.fixture
def compliance_engine_fresh(tmp_path):
    from app.compliance import ComplianceEngine
    return ComplianceEngine(db_path=tmp_path / "test_compliance.db")


def test_kyc_register_and_status(compliance_engine_fresh):
    engine = compliance_engine_fresh
    record = engine.register_kyc("PAddr1", "Fulano de Tal", "123.456.789-01", tier=1)
    assert record.tier == 1
    assert engine.get_kyc_tier("PAddr1") == 1
    assert engine.limit_for_address("PAddr1") == 50_000.0
    # endereco nunca registrado fica no tier 0 (nao verificado)
    assert engine.get_kyc_tier("PAddrNunca") == 0


def test_kyc_tier2_requires_document_hash(compliance_engine_fresh):
    engine = compliance_engine_fresh
    with pytest.raises(ValueError):
        engine.register_kyc("PAddr2", "Beltrano", "111.222.333-44", tier=2)  # sem document_hash
    engine.register_kyc("PAddr2", "Beltrano", "111.222.333-44", tier=2, document_hash="abc123")
    assert engine.get_kyc_tier("PAddr2") == 2
    assert engine.limit_for_address("PAddr2") == float("inf")


def test_cpf_is_never_stored_in_plaintext(compliance_engine_fresh, tmp_path):
    """Verifica a garantia de privacidade documentada: o CPF em texto claro
    NUNCA aparece no banco de dados - apenas seu hash SHA-256."""
    import sqlite3
    engine = compliance_engine_fresh
    cpf = "999.888.777-66"
    engine.register_kyc("PAddr3", "Ciclano", cpf, tier=1)
    conn = sqlite3.connect(engine.db_path)
    row = conn.execute("SELECT cpf_hash FROM kyc_records WHERE address = ?", ("PAddr3",)).fetchone()
    conn.close()
    assert row is not None
    assert cpf not in row[0]
    assert "".join(ch for ch in cpf if ch.isdigit()) not in row[0]
    assert len(row[0]) == 64  # hex de SHA-256


def test_sanctions_list_blocks_transaction(compliance_engine_fresh):
    engine = compliance_engine_fresh
    engine.add_to_sanctions_list("PBadGuy", "OFAC SDN list (exemplo)")
    assert engine.is_sanctioned("PBadGuy") is True
    from app.compliance import ComplianceError
    with pytest.raises(ComplianceError):
        engine.check_transaction("PBadGuy", "PGoodGuy", 10.0)
    with pytest.raises(ComplianceError):
        engine.check_transaction("PGoodGuy", "PBadGuy", 10.0)

    engine.remove_from_sanctions_list("PBadGuy")
    assert engine.is_sanctioned("PBadGuy") is False
    result = engine.check_transaction("PGoodGuy", "PBadGuy", 10.0)
    assert result["alerts"] == []


def test_transaction_above_tier0_limit_generates_alert_but_does_not_block(compliance_engine_fresh):
    engine = compliance_engine_fresh
    result = engine.check_transaction("PUnverified", "PAny", 999_999.0)
    assert any("excede o limite" in a for a in result["alerts"])
    # nao levanta excecao - apenas alerta (a decisao de bloquear por limite fica no chamador)


def test_structuring_pattern_generates_aml_alert(compliance_engine_fresh):
    engine = compliance_engine_fresh
    tier0_limit = 1000.0  # default
    recent = [500.0, 500.0, 500.0]  # 3 tx recentes abaixo do limiar
    result = engine.check_transaction("PSmurf", "PDest", 500.0, sender_recent_amounts=recent)
    assert any("estruturacao" in a or "smurfing" in a for a in result["alerts"])


def test_suspicious_activity_report_lists_events(compliance_engine_fresh):
    engine = compliance_engine_fresh
    engine.add_to_sanctions_list("PBadGuy2", "teste")
    from app.compliance import ComplianceError
    with pytest.raises(ComplianceError):
        engine.check_transaction("PBadGuy2", "PVictim", 5.0)
    events = engine.suspicious_activity_report("critical")
    assert any(e["event_type"] == "sanction_block" for e in events)


# ---------------------------------------------------------------------------
# API estilo exchange (Binance-like)
# ---------------------------------------------------------------------------

@pytest.fixture
def app_client(tmp_path, monkeypatch):
    """Sobe uma instancia completa da API (mesma usada pelo resto da suite)
    com storage isolado, para testar os novos endpoints de exchange/compliance/UI."""
    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(tmp_path / "chain.db"))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "compliance.db"))
    import importlib
    import app.storage as storage_mod
    importlib.reload(storage_mod)
    import app.bruteforce_guard as bruteforce_guard_mod
    bruteforce_guard_mod.guard.reset_all()
    import app.api as api_mod
    importlib.reload(api_mod)
    return TestClient(api_mod.app)


def test_exchange_info_endpoint(app_client):
    data = app_client.get("/api/v1/exchangeInfo").json()
    assert data["symbol"] == "PXCBRL"
    assert data["baseAsset"] == "PXC"
    assert data["quoteAsset"] == "BRL"


def test_ticker_24hr_endpoint_returns_price_fields(app_client):
    data = app_client.get("/api/v1/ticker/24hr").json()
    assert data["symbol"] == "PXCBRL"
    assert "lastPrice" in data
    assert data["lastPrice"] > 0


def test_klines_endpoint_returns_valid_candles(app_client):
    candles = app_client.get("/api/v1/klines?interval=1h&limit=10").json()
    assert len(candles) == 10
    for candle in candles:
        assert len(candle) == 7  # [open_time, o, h, l, c, volume, close_time]


def test_klines_rejects_invalid_interval(app_client):
    resp = app_client.get("/api/v1/klines?interval=3x")
    assert resp.status_code == 400


def test_depth_endpoint_reflects_open_swap_orders(app_client):
    data = app_client.get("/api/v1/depth").json()
    assert data["symbol"] == "PXCBRL"
    assert "asks" in data and "bids" in data


def test_trades_endpoint_returns_list(app_client):
    trades = app_client.get("/api/v1/trades").json()
    assert isinstance(trades, list)


def test_apikey_create_and_order_flow(app_client):
    wallet = app_client.post("/wallet/create", json={"label": "trader"}).json()
    apikey = app_client.post("/api/v1/apikey/create", json={"address": wallet["address"]}).json()
    assert "api_key" in apikey and "api_secret" in apikey

    # sem saldo suficiente -> ordem deve falhar (400), mas a autenticacao
    # HMAC em si deve passar antes de chegar na validacao de saldo
    import hmac, hashlib
    amount, price = 1.0, 5.0
    payload = f"{amount}:{price}"
    signature = hmac.new(
        hashlib.sha256(apikey["api_secret"].encode()).hexdigest().encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    resp = app_client.post("/api/v1/order", json={
        "api_key": apikey["api_key"], "signature": signature,
        "maker_private_key": wallet["private_key"], "maker_public_key": wallet["public_key"],
        "amount": amount, "price_brl_per_pxc": price,
    })
    assert resp.status_code == 400  # saldo insuficiente (carteira nova, sem PXC)
    assert "insuficiente" in resp.json()["detail"].lower() or "saldo" in resp.json()["detail"].lower()


def test_apikey_order_rejects_invalid_signature(app_client):
    wallet = app_client.post("/wallet/create", json={"label": "trader2"}).json()
    apikey = app_client.post("/api/v1/apikey/create", json={"address": wallet["address"]}).json()
    resp = app_client.post("/api/v1/order", json={
        "api_key": apikey["api_key"], "signature": "0" * 64,
        "maker_private_key": wallet["private_key"], "maker_public_key": wallet["public_key"],
        "amount": 1.0, "price_brl_per_pxc": 5.0,
    })
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Mineracao colaborativa em pool via API (/mining/mine, /mining/submit-proof)
# ---------------------------------------------------------------------------

def test_mine_endpoint_splits_reward_between_pool_contributors(app_client):
    from app import root_rules as rr
    from app.models import Transaction as Tx
    alice = app_client.post("/wallet/create", json={"label": "alice"}).json()
    bob = app_client.post("/wallet/create", json={"label": "bob"}).json()
    pool_a = app_client.post("/wallet/create", json={"label": "pool-a"}).json()
    pool_b = app_client.post("/wallet/create", json={"label": "pool-b"}).json()

    import app.api as api_mod
    credit_tx = Tx(sender=rr.COINBASE_SENDER, recipient=alice["address"], amount=50.0, tx_type="coinbase_purchase")
    assert api_mod.blockchain.add_transaction(credit_tx)
    mine1 = app_client.post("/mining/mine", json={"miner_address": alice["address"]})
    assert mine1.status_code == 200 and "block_index" in mine1.json()

    transfer = app_client.post("/transaction/send", json={
        "sender_private_key": alice["private_key"], "sender_public_key": alice["public_key"],
        "recipient": bob["address"], "amount": 10.0, "memo": "", "fee": 0.05,
    })
    assert transfer.status_code == 200

    resp = app_client.post("/mining/mine", json={
        "miner_address": alice["address"],
        "pool_contributors": [
            {"address": pool_a["address"], "shares": 70.0},
            {"address": pool_b["address"], "shares": 30.0},
        ],
    })
    assert resp.status_code == 200
    body = resp.json()
    breakdown = {item["address"]: item["amount"] for item in body["reward_breakdown"]}
    assert set(breakdown) == {pool_a["address"], pool_b["address"]}
    assert round(sum(breakdown.values()), 8) == body["miner_reward"]
    assert breakdown[pool_a["address"]] > breakdown[pool_b["address"]]


def test_mine_endpoint_rejects_too_many_pool_contributors(app_client):
    from app import root_rules as rr
    from app.models import Transaction as Tx
    alice = app_client.post("/wallet/create", json={"label": "alice2"}).json()
    import app.api as api_mod
    credit_tx = Tx(sender=rr.COINBASE_SENDER, recipient=alice["address"], amount=10.0, tx_type="coinbase_purchase")
    assert api_mod.blockchain.add_transaction(credit_tx)
    contributors = [{"address": alice["address"], "shares": 1.0}] * (rr.MAX_POOL_CONTRIBUTORS_PER_BLOCK + 1)
    resp = app_client.post("/mining/mine", json={
        "miner_address": alice["address"], "pool_contributors": contributors,
    })
    assert resp.status_code == 422  # rejeitado pela validacao pydantic (max_length)


# ---------------------------------------------------------------------------
# Rotacao automatica de endereco HD ("conta auto-mutavel") via API
# ---------------------------------------------------------------------------

def test_hd_next_address_rotates_and_never_repeats(app_client):
    hd = app_client.post("/wallet/hd/create", json={"strength_bits": 128}).json()
    mnemonic = hd["mnemonic"]

    first = app_client.post("/wallet/hd/next-address", json={"mnemonic": mnemonic}).json()
    # conta 0 ja foi criada por /wallet/hd/create mas ainda esta sem atividade
    # on-chain (nenhuma transacao/saldo) -> deve ser devolvida como "nao usada"
    assert first["account_index"] == 0
    assert first["address"] == hd["address"]

    second = app_client.post("/wallet/hd/next-address", json={
        "mnemonic": mnemonic, "start_index": first["account_index"] + 1,
    }).json()
    assert second["account_index"] == 1
    assert second["address"] != first["address"]


def test_hd_next_address_rejects_invalid_mnemonic(app_client):
    resp = app_client.post("/wallet/hd/next-address", json={"mnemonic": "invalid seed phrase"})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Conformidade via API (KYC/AML endpoints em app/api.py)
# ---------------------------------------------------------------------------

def test_compliance_endpoints_via_api(app_client):
    wallet = app_client.post("/wallet/create", json={"label": "kyc-user"}).json()
    reg = app_client.post("/compliance/kyc/register", json={
        "address": wallet["address"], "full_name": "Fulano de Tal", "cpf": "12345678901", "tier": 1,
    })
    assert reg.status_code == 200
    assert reg.json()["tier"] == 1

    status = app_client.get(f"/compliance/kyc/status/{wallet['address']}").json()
    assert status["tier"] == 1

    screen = app_client.get(f"/compliance/screen/{wallet['address']}").json()
    assert screen["sanctioned"] is False

    sar = app_client.get("/compliance/reports/sar").json()
    assert "events" in sar


def test_compliance_sanctions_add_and_remove_via_api(app_client):
    entry = "PSomeAddressToSanction"
    add_resp = app_client.post("/compliance/sanctions/add", json={"entry": entry, "reason": "teste automatizado"})
    assert add_resp.status_code == 200
    screen = app_client.get(f"/compliance/screen/{entry}").json()
    assert screen["sanctioned"] is True

    del_resp = app_client.delete(f"/compliance/sanctions/{entry}")
    assert del_resp.status_code == 200
    screen_after = app_client.get(f"/compliance/screen/{entry}").json()
    assert screen_after["sanctioned"] is False


def test_send_transaction_blocked_when_recipient_sanctioned(app_client):
    sender = app_client.post("/wallet/create", json={"label": "s"}).json()
    recipient = app_client.post("/wallet/create", json={"label": "r"}).json()
    app_client.post("/compliance/sanctions/add", json={"entry": recipient["address"], "reason": "teste"})
    resp = app_client.post("/transaction/send", json={
        "sender_private_key": sender["private_key"], "sender_public_key": sender["public_key"],
        "recipient": recipient["address"], "amount": 1.0, "memo": "", "fee": 0.0,
    })
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# UI web de carteira
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/wallet", "/wallet/send", "/wallet/receive", "/wallet/history", "/wallet/market"])
def test_wallet_ui_pages_render(app_client, path):
    resp = app_client.get(path)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_static_assets_are_served(app_client):
    css = app_client.get("/static/css/style.css")
    assert css.status_code == 200
    js = app_client.get("/static/js/pixcripto.js")
    assert js.status_code == 200


# ---------------------------------------------------------------------------
# Feed de noticias (site principal) - leitura publica, escrita protegida por
# token de administracao de conteudo (fail-closed sem PIXCRIPTO_ADMIN_CONTENT_TOKEN)
# ---------------------------------------------------------------------------

def test_news_write_disabled_by_default_fail_closed(app_client):
    """Sem PIXCRIPTO_ADMIN_CONTENT_TOKEN configurado, a escrita fica bloqueada
    (503) mesmo sem nenhum token informado - nunca fica aberta por padrao."""
    resp = app_client.post("/news", json={"title": "Teste", "summary": "s", "body": "b"})
    assert resp.status_code == 503


@pytest.fixture
def app_client_with_news_token(tmp_path, monkeypatch):
    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(tmp_path / "chain.db"))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "compliance.db"))
    monkeypatch.setenv("PIXCRIPTO_ADMIN_CONTENT_TOKEN", "test-secret-token")
    import importlib
    import app.storage as storage_mod
    importlib.reload(storage_mod)
    import app.settings as settings_mod
    importlib.reload(settings_mod)
    import app.news as news_mod
    importlib.reload(news_mod)
    import app.bruteforce_guard as bruteforce_guard_mod
    bruteforce_guard_mod.guard.reset_all()
    import app.api as api_mod
    importlib.reload(api_mod)
    return TestClient(api_mod.app)


def test_news_create_requires_valid_admin_token(app_client_with_news_token):
    client = app_client_with_news_token
    unauthorized = client.post("/news", json={"title": "Teste", "summary": "", "body": ""})
    assert unauthorized.status_code == 401

    wrong_token = client.post(
        "/news", json={"title": "Teste", "summary": "", "body": ""},
        headers={"X-Admin-Token": "wrong"},
    )
    assert wrong_token.status_code == 401

    ok = client.post(
        "/news", json={"title": "PixCripto atinge novo marco", "summary": "resumo", "body": "corpo completo"},
        headers={"X-Admin-Token": "test-secret-token"},
    )
    assert ok.status_code == 200
    assert ok.json()["title"] == "PixCripto atinge novo marco"


def test_news_list_and_get_are_public(app_client_with_news_token):
    client = app_client_with_news_token
    client.post(
        "/news", json={"title": "Noticia publica", "summary": "", "body": ""},
        headers={"X-Admin-Token": "test-secret-token"},
    )
    listing = client.get("/news").json()
    assert len(listing["posts"]) == 1
    post_id = listing["posts"][0]["id"]
    fetched = client.get(f"/news/{post_id}").json()
    assert fetched["title"] == "Noticia publica"


def test_news_update_and_delete(app_client_with_news_token):
    client = app_client_with_news_token
    headers = {"X-Admin-Token": "test-secret-token"}
    created = client.post("/news", json={"title": "Original", "summary": "", "body": ""}, headers=headers).json()
    post_id = created["id"]

    updated = client.put(
        f"/news/{post_id}", json={"title": "Atualizado", "summary": "", "body": ""}, headers=headers
    )
    assert updated.status_code == 200
    assert updated.json()["title"] == "Atualizado"

    deleted = client.delete(f"/news/{post_id}", headers=headers)
    assert deleted.status_code == 200
    assert client.get(f"/news/{post_id}").status_code == 404


def test_news_upload_image_rejects_disallowed_extension(app_client_with_news_token):
    client = app_client_with_news_token
    resp = client.post(
        "/news/upload-image",
        files={"file": ("malware.exe", b"fake-binary-content", "application/octet-stream")},
        headers={"X-Admin-Token": "test-secret-token"},
    )
    assert resp.status_code == 400


def test_news_upload_image_accepts_valid_png(app_client_with_news_token):
    client = app_client_with_news_token
    png_bytes = bytes.fromhex(
        "89504e470d0a1a0a0000000d4948445200000001000000010802000000907753"
        "de0000000c4944415478da6360000002000155a4a55a0000000049454e44ae426082"
    )
    resp = client.post(
        "/news/upload-image",
        files={"file": ("cover.png", png_bytes, "image/png")},
        headers={"X-Admin-Token": "test-secret-token"},
    )
    assert resp.status_code == 200
    assert resp.json()["image_url"].startswith("/static/uploads/news/")


def test_cors_headers_present_for_configured_origin(app_client):
    resp = app_client.options(
        "/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.status_code in (200, 204)
    assert "access-control-allow-origin" in {k.lower() for k in resp.headers.keys()}


# ---------------------------------------------------------------------------
# Configuracao central (settings.py) e rede (network_config.py)
# ---------------------------------------------------------------------------

def test_settings_default_environment_is_valid():
    from app.settings import Settings, VALID_ENVIRONMENTS
    s = Settings()
    assert s.environment in VALID_ENVIRONMENTS
    assert s.is_valid()


def test_settings_invalid_environment_raises():
    from app.settings import Settings
    s = Settings(environment="not-a-real-env")
    assert not s.is_valid()


def test_network_config_resolve_dns_seed_never_raises_on_bad_hostname():
    from app import network_config
    result = network_config.resolve_dns_seed("this-hostname-does-not-exist.invalid.example", 9333)
    assert result == []


def test_network_config_discover_bootstrap_peers_includes_explicit_peers(tmp_path, monkeypatch):
    from app import network_config
    from app.settings import Settings
    monkeypatch.setattr(network_config, "SEEDS_FILE", tmp_path / "seeds.json")
    monkeypatch.setattr(network_config, "settings", Settings(peer_discovery_enabled=False))
    peers = network_config.discover_bootstrap_peers(["1.2.3.4:9333"])
    assert "1.2.3.4:9333" in peers


def test_network_config_curated_seeds_roundtrip(tmp_path, monkeypatch):
    from app import network_config
    seeds_file = tmp_path / "seeds.json"
    monkeypatch.setattr(network_config, "SEEDS_FILE", seeds_file)
    network_config.save_curated_seeds(["5.6.7.8:9333", "9.9.9.9:9333"])
    loaded = network_config.load_curated_seeds()
    assert set(loaded) == {"5.6.7.8:9333", "9.9.9.9:9333"}


def test_network_config_load_curated_seeds_missing_file_returns_empty(tmp_path, monkeypatch):
    from app import network_config
    monkeypatch.setattr(network_config, "SEEDS_FILE", tmp_path / "does_not_exist.json")
    assert network_config.load_curated_seeds() == []


# ---------------------------------------------------------------------------
# Painel de Administracao (smoke test - roda fora de app/, nunca distribuido)
# ---------------------------------------------------------------------------

@pytest.fixture
def admin_client(tmp_path, monkeypatch):
    root_dir = Path(__file__).resolve().parent.parent
    if str(root_dir) not in sys.path:
        sys.path.insert(0, str(root_dir))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "admin_compliance.db"))
    import importlib
    import app.compliance as compliance_mod
    importlib.reload(compliance_mod)
    import admin_panel.main as admin_mod
    importlib.reload(admin_mod)
    monkeypatch.setattr(admin_mod, "compliance_engine", compliance_mod.compliance_engine)
    monkeypatch.setattr(admin_mod, "ENV_FILE", tmp_path / ".env")
    return TestClient(admin_mod.app), admin_mod


def test_admin_dashboard_renders(admin_client):
    client, _ = admin_client
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Painel de Administra" in resp.text


def test_admin_seeds_add_and_remove(admin_client, tmp_path, monkeypatch):
    client, admin_mod = admin_client
    from app import network_config
    monkeypatch.setattr(network_config, "SEEDS_FILE", tmp_path / "admin_seeds.json")
    resp = client.post("/seeds/add", data={"peer": "1.1.1.1:9333"}, follow_redirects=False)
    assert resp.status_code == 303
    assert "1.1.1.1:9333" in network_config.load_curated_seeds()
    resp2 = client.post("/seeds/remove", data={"peer": "1.1.1.1:9333"}, follow_redirects=False)
    assert resp2.status_code == 303
    assert "1.1.1.1:9333" not in network_config.load_curated_seeds()


def test_admin_sanctions_add_and_remove(admin_client):
    client, admin_mod = admin_client
    resp = client.post("/compliance/sanctions/add", data={"entry": "PBad", "reason": "teste"}, follow_redirects=False)
    assert resp.status_code == 303
    assert admin_mod.compliance_engine.is_sanctioned("PBad") is True
    resp2 = client.post("/compliance/sanctions/remove", data={"entry": "PBad"}, follow_redirects=False)
    assert resp2.status_code == 303
    assert admin_mod.compliance_engine.is_sanctioned("PBad") is False
