"""
Testes do sistema de contas de usuario final (cadastro/login do site) e do
fluxo completo de KYC com documento com foto real - `app/user_accounts.py`.

Cobre: registro, login, sessao, vinculo de carteira, envio de KYC (CPF, RG,
documento frente/verso + selfie cifrados em repouso), listagem/aprovacao/
rejeicao administrativa, e a integracao com `app/compliance.py` (tier de KYC
elevado automaticamente ao aprovar).
"""
from __future__ import annotations

import importlib
import io

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def user_app_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(tmp_path / "chain.db"))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "compliance.db"))
    monkeypatch.setenv("PIXCRIPTO_ADMIN_USERNAME", "operator")
    monkeypatch.setenv("PIXCRIPTO_ADMIN_PASSWORD", "SenhaForte1234!")
    monkeypatch.setenv("PIXCRIPTO_KYC_MASTER_KEY", "chave-mestra-de-teste-nao-usar-em-producao")
    monkeypatch.setenv("PIXCRIPTO_HOUSEKEEPING_INTERVAL_SECONDS", "999999")

    import app.storage as storage_mod
    importlib.reload(storage_mod)
    import app.settings as settings_mod
    importlib.reload(settings_mod)
    import app.compliance as compliance_mod
    importlib.reload(compliance_mod)
    import app.admin_auth as admin_auth_mod
    importlib.reload(admin_auth_mod)
    import app.user_accounts as user_accounts_mod
    importlib.reload(user_accounts_mod)
    import app.cms as cms_mod
    importlib.reload(cms_mod)
    import app.media as media_mod
    importlib.reload(media_mod)
    import app.feature_flags as feature_flags_mod
    importlib.reload(feature_flags_mod)
    import app.housekeeping as housekeeping_mod
    importlib.reload(housekeeping_mod)
    import app.site_settings as site_settings_mod
    importlib.reload(site_settings_mod)
    import app.news as news_mod
    importlib.reload(news_mod)
    import app.bruteforce_guard as bruteforce_guard_mod
    bruteforce_guard_mod.guard.reset_all()
    import app.api as api_mod
    importlib.reload(api_mod)
    client = TestClient(api_mod.app)
    yield client
    api_mod.housekeeping.stop_scheduler()


def _register(client, username="alice", email="alice@example.com", password="SenhaForte1234!"):
    resp = client.post("/auth/register", json={"username": username, "email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _login(client, username="alice", password="SenhaForte1234!"):
    resp = client.post("/auth/login", json={"username_or_email": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def _admin_login(client):
    resp = client.post("/admin/auth/login", json={"username": "operator", "password": "SenhaForte1234!"})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def _fake_image(name="doc.jpg"):
    return (name, io.BytesIO(b"\xff\xd8\xff fake jpeg bytes for testing" * 10), "image/jpeg")


VALID_CPF = "111.444.777-35"  # CPF matematicamente valido (digitos verificadores corretos)


def test_register_and_login(user_app_client):
    client = user_app_client
    data = _register(client)
    assert data["username"] == "alice"

    token = _login(client)
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    body = me.json()
    assert body["username"] == "alice"
    assert body["kyc_status"] == "none"


def test_register_rejects_duplicate_username_and_email(user_app_client):
    client = user_app_client
    _register(client)
    dup_username = client.post("/auth/register", json={"username": "alice", "email": "other@example.com", "password": "SenhaForte1234!"})
    assert dup_username.status_code == 409
    dup_email = client.post("/auth/register", json={"username": "other", "email": "alice@example.com", "password": "SenhaForte1234!"})
    assert dup_email.status_code == 409


def test_register_rejects_weak_password(user_app_client):
    client = user_app_client
    resp = client.post("/auth/register", json={"username": "bob", "email": "bob@example.com", "password": "123"})
    assert resp.status_code in (400, 422)


def test_login_rejects_wrong_password(user_app_client):
    client = user_app_client
    _register(client)
    resp = client.post("/auth/login", json={"username_or_email": "alice", "password": "senhaerrada"})
    assert resp.status_code == 401


def test_link_and_list_wallet(user_app_client):
    client = user_app_client
    _register(client)
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    wallet_resp = client.post("/wallet/create", json={"label": "principal"})
    assert wallet_resp.status_code == 200
    address = wallet_resp.json()["address"]

    link = client.post("/auth/wallets", json={"address": address, "label": "principal"}, headers=headers)
    assert link.status_code == 200

    wallets = client.get("/auth/wallets", headers=headers)
    assert wallets.status_code == 200
    assert any(w["address"] == address for w in wallets.json()["wallets"])

    unlink = client.delete(f"/auth/wallets/{address}", headers=headers)
    assert unlink.status_code == 200
    wallets2 = client.get("/auth/wallets", headers=headers)
    assert not any(w["address"] == address for w in wallets2.json()["wallets"])


def test_link_wallet_rejects_invalid_address(user_app_client):
    client = user_app_client
    _register(client)
    token = _login(client)
    resp = client.post(
        "/auth/wallets", json={"address": "nao-e-um-endereco-valido"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400


def test_kyc_submit_full_flow_and_admin_approval(user_app_client):
    client = user_app_client
    _register(client)
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    wallet_resp = client.post("/wallet/create", json={"label": "principal"})
    address = wallet_resp.json()["address"]
    client.post("/auth/wallets", json={"address": address}, headers=headers)

    files = {
        "document_front": _fake_image("frente.jpg"),
        "document_back": _fake_image("verso.jpg"),
        "selfie": _fake_image("selfie.jpg"),
    }
    data = {"full_name": "Alice da Silva", "cpf": VALID_CPF, "rg": "12.345.678-9", "birth_date": "1990-01-01"}
    submit = client.post("/kyc/submit", data=data, files=files, headers=headers)
    assert submit.status_code == 200, submit.text
    submission_id = submit.json()["submission_id"]

    my_submissions = client.get("/kyc/my-submissions", headers=headers)
    assert my_submissions.status_code == 200
    assert my_submissions.json()["submissions"][0]["status"] == "pending"

    me_after = client.get("/auth/me", headers=headers)
    assert me_after.json()["kyc_status"] == "pending"

    admin_token = _admin_login(client)
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    pending_list = client.get("/admin/kyc/submissions?status=pending", headers=admin_headers)
    assert pending_list.status_code == 200
    assert len(pending_list.json()["submissions"]) == 1

    detail = client.get(f"/admin/kyc/submissions/{submission_id}", headers=admin_headers)
    assert detail.status_code == 200
    detail_body = detail.json()
    assert detail_body["full_name"] == "Alice da Silva"
    assert detail_body["cpf"] == VALID_CPF
    assert detail_body["document_front_data_uri"].startswith("data:")

    approve = client.post(f"/admin/kyc/submissions/{submission_id}/approve", json={"tier": 2}, headers=admin_headers)
    assert approve.status_code == 200

    me_final = client.get("/auth/me", headers=headers)
    assert me_final.json()["kyc_status"] == "approved"
    assert me_final.json()["kyc_tier"] == 2

    kyc_status = client.get(f"/compliance/kyc/status/{address}")
    assert kyc_status.status_code == 200
    assert kyc_status.json()["tier"] == 2
    assert kyc_status.json()["limit_pxc"] is None  # tier completo = sem limite


def test_kyc_submit_rejects_invalid_cpf(user_app_client):
    client = user_app_client
    _register(client)
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    files = {
        "document_front": _fake_image(), "document_back": _fake_image(), "selfie": _fake_image(),
    }
    data = {"full_name": "Alice da Silva", "cpf": "000.000.000-00", "rg": "12.345.678-9", "birth_date": "1990-01-01"}
    resp = client.post("/kyc/submit", data=data, files=files, headers=headers)
    assert resp.status_code == 400


def test_admin_can_reject_kyc_with_reason(user_app_client):
    client = user_app_client
    _register(client)
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    files = {
        "document_front": _fake_image(), "document_back": _fake_image(), "selfie": _fake_image(),
    }
    data = {"full_name": "Alice da Silva", "cpf": VALID_CPF, "rg": "12.345.678-9", "birth_date": "1990-01-01"}
    submit = client.post("/kyc/submit", data=data, files=files, headers=headers)
    submission_id = submit.json()["submission_id"]

    admin_token = _admin_login(client)
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    reject = client.post(
        f"/admin/kyc/submissions/{submission_id}/reject",
        json={"reason": "Foto do documento ilegivel"}, headers=admin_headers,
    )
    assert reject.status_code == 200

    me = client.get("/auth/me", headers=headers)
    assert me.json()["kyc_status"] == "rejected"


def test_kyc_duplicate_cpf_rejected_for_other_account(user_app_client):
    client = user_app_client
    _register(client, username="alice", email="alice@example.com")
    _register(client, username="carol", email="carol@example.com")
    token_alice = _login(client, username="alice")
    token_carol = _login(client, username="carol")

    files = {
        "document_front": _fake_image(), "document_back": _fake_image(), "selfie": _fake_image(),
    }
    data = {"full_name": "Alice da Silva", "cpf": VALID_CPF, "rg": "12.345.678-9", "birth_date": "1990-01-01"}
    first = client.post("/kyc/submit", data=data, files=files, headers={"Authorization": f"Bearer {token_alice}"})
    assert first.status_code == 200

    data2 = {"full_name": "Carol Souza", "cpf": VALID_CPF, "rg": "98.765.432-1", "birth_date": "1991-02-02"}
    second = client.post("/kyc/submit", data=data2, files=files, headers={"Authorization": f"Bearer {token_carol}"})
    assert second.status_code == 409


def test_unauthenticated_requests_rejected(user_app_client):
    client = user_app_client
    assert client.get("/auth/me").status_code == 401
    assert client.get("/auth/wallets").status_code == 401
    assert client.get("/kyc/my-submissions").status_code == 401
