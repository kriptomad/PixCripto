"""
Testes do sistema completo de housekeeping + administracao do site
(login real, CMS de paginas, biblioteca de midia, chaves de funcionalidade
e o motor de housekeeping automatico) adicionados nesta rodada:

- `app/admin_auth.py`  - login real (usuario/senha, sessao expiravel)
- `app/cms.py`         - CMS de paginas estaticas
- `app/media.py`       - biblioteca de midia centralizada
- `app/feature_flags.py` - chaves de funcionalidade (incl. modo manutencao)
- `app/housekeeping.py`  - manutencao automatica do sistema

Segue o mesmo padrao de isolamento por teste (banco SQLite proprio via
`tmp_path` + `monkeypatch` + `importlib.reload`) usado em `test_ecosystem.py`.
"""
from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def admin_app_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(tmp_path / "chain.db"))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "compliance.db"))
    monkeypatch.setenv("PIXCRIPTO_ADMIN_USERNAME", "operator")
    monkeypatch.setenv("PIXCRIPTO_ADMIN_PASSWORD", "SenhaForte1234!")
    monkeypatch.setenv("PIXCRIPTO_HOUSEKEEPING_INTERVAL_SECONDS", "999999")  # nao dispara sozinho durante o teste

    import app.storage as storage_mod
    importlib.reload(storage_mod)
    import app.settings as settings_mod
    importlib.reload(settings_mod)
    import app.admin_auth as admin_auth_mod
    importlib.reload(admin_auth_mod)
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


def _login(client, username="operator", password="SenhaForte1234!"):
    resp = client.post("/admin/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def test_admin_login_bootstrap_and_success(admin_app_client):
    client = admin_app_client
    status = client.get("/admin/auth/status").json()
    assert status["login_enabled"] is True

    token = _login(client)
    me = client.get("/admin/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["username"] == "operator"


def test_admin_login_rejects_wrong_password(admin_app_client):
    client = admin_app_client
    resp = client.post("/admin/auth/login", json={"username": "operator", "password": "errada"})
    assert resp.status_code == 401


def test_admin_login_not_configured_when_no_bootstrap(tmp_path, monkeypatch):
    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(tmp_path / "chain.db"))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "compliance.db"))
    monkeypatch.delenv("PIXCRIPTO_ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("PIXCRIPTO_ADMIN_PASSWORD", raising=False)
    import app.storage as storage_mod
    importlib.reload(storage_mod)
    import app.settings as settings_mod
    importlib.reload(settings_mod)
    import app.admin_auth as admin_auth_mod
    importlib.reload(admin_auth_mod)
    import app.bruteforce_guard as bruteforce_guard_mod
    bruteforce_guard_mod.guard.reset_all()
    import app.api as api_mod
    importlib.reload(api_mod)
    client = TestClient(api_mod.app)
    status = client.get("/admin/auth/status").json()
    assert status["login_enabled"] is False
    resp = client.post("/admin/auth/login", json={"username": "x", "password": "y"})
    assert resp.status_code == 401


def test_admin_session_required_for_protected_endpoints(admin_app_client):
    client = admin_app_client
    resp = client.get("/admin/pages")
    assert resp.status_code == 401
    resp = client.get("/admin/pages", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


def test_admin_logout_invalidates_session(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/admin/auth/me", headers=headers).status_code == 200
    client.post("/admin/auth/logout", headers=headers)
    assert client.get("/admin/auth/me", headers=headers).status_code == 401


def test_admin_change_password(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.post(
        "/admin/auth/change-password",
        json={"old_password": "SenhaForte1234!", "new_password": "NovaSenhaForte9999!"},
        headers=headers,
    )
    assert resp.status_code == 200
    # senha antiga nao funciona mais
    assert client.post("/admin/auth/login", json={"username": "operator", "password": "SenhaForte1234!"}).status_code == 401
    # nova senha funciona
    assert client.post("/admin/auth/login", json={"username": "operator", "password": "NovaSenhaForte9999!"}).status_code == 200


def test_cms_pages_crud_and_public_visibility(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    created = client.put(
        "/admin/pages/sobre-nos",
        json={"title": "Sobre nos", "body": "Somos o PixCripto.", "published": True},
        headers=headers,
    )
    assert created.status_code == 200
    assert created.json()["slug"] == "sobre-nos"

    public = client.get("/pages/sobre-nos")
    assert public.status_code == 200
    assert public.json()["title"] == "Sobre nos"

    listing = client.get("/admin/pages", headers=headers).json()
    assert len(listing["pages"]) == 1

    draft = client.put(
        "/admin/pages/rascunho",
        json={"title": "Rascunho", "body": "nao publicado", "published": False},
        headers=headers,
    )
    assert draft.status_code == 200
    # rascunho nao publicado nao aparece na rota publica
    assert client.get("/pages/rascunho").status_code == 404

    deleted = client.delete("/admin/pages/sobre-nos", headers=headers)
    assert deleted.status_code == 200
    assert client.get("/pages/sobre-nos").status_code == 404


def test_cms_page_requires_auth_to_write(admin_app_client):
    client = admin_app_client
    resp = client.put("/admin/pages/sobre-nos", json={"title": "X", "body": "Y", "published": True})
    assert resp.status_code == 401


def test_media_upload_registered_and_listed(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    png_bytes = bytes.fromhex(
        "89504e470d0a1a0a0000000d494844520000000100000001080600000"
        "01f15c4890000000a4944415478da6360000002000155e621bc0000000049454e44ae426082"
    )
    upload = client.post(
        "/news/upload-image",
        files={"file": ("test.png", png_bytes, "image/png")},
        headers=headers,
    )
    assert upload.status_code == 200
    image_url = upload.json()["image_url"]

    media_list = client.get("/admin/media", headers=headers).json()
    assert media_list["stats"]["total_files"] == 1
    assert media_list["files"][0]["url"] == image_url
    assert media_list["files"][0]["purpose"] == "news"


def test_feature_flags_default_and_toggle(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    flags = client.get("/admin/features", headers=headers).json()["flags"]
    by_key = {f["key"]: f for f in flags}
    assert by_key["maintenance_mode"]["enabled"] is False
    assert by_key["mining_enabled"]["enabled"] is True

    toggled = client.post("/admin/features/mining_enabled", json={"enabled": False}, headers=headers)
    assert toggled.status_code == 200
    flags_after = client.get("/admin/features", headers=headers).json()["flags"]
    by_key_after = {f["key"]: f for f in flags_after}
    assert by_key_after["mining_enabled"]["enabled"] is False

    # mineracao bloqueada de verdade quando a flag esta desligada
    mine_resp = client.post("/mining/mine", json={"miner_address": "PXaddress000000000000000000000000"})
    assert mine_resp.status_code == 503


def test_feature_flags_unknown_key_rejected(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.post("/admin/features/nao_existe", json={"enabled": True}, headers=headers)
    assert resp.status_code == 400


def test_maintenance_mode_blocks_public_api_but_not_admin(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    client.post("/admin/features/maintenance_mode", json={"enabled": True}, headers=headers)
    blocked = client.get("/mining/gpu-status")
    assert blocked.status_code == 503

    # o proprio painel de administracao continua acessivel durante a manutencao
    still_ok = client.get("/admin/auth/me", headers=headers)
    assert still_ok.status_code == 200

    client.post("/admin/features/maintenance_mode", json={"enabled": False}, headers=headers)
    assert client.get("/mining/gpu-status").status_code == 200


def test_public_feature_flags_endpoint_exposes_safe_subset(admin_app_client):
    client = admin_app_client
    data = client.get("/features/public").json()
    assert set(data.keys()) == {"maintenance_mode", "purchases_enabled", "trading_enabled", "mining_enabled"}


def test_housekeeping_manual_run_and_history(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    run = client.post("/admin/housekeeping/run", headers=headers)
    assert run.status_code == 200
    body = run.json()
    assert "actions" in body and "database_vacuumed" in body["actions"]

    history = client.get("/admin/housekeeping/history", headers=headers).json()
    assert len(history["runs"]) == 1
    assert history["runs"][0]["triggered_by"].startswith("manual:")

    status = client.get("/admin/housekeeping/status", headers=headers).json()
    assert status["last_run"] is not None


def test_housekeeping_requires_admin_session(admin_app_client):
    client = admin_app_client
    assert client.post("/admin/housekeeping/run").status_code == 401
    assert client.get("/admin/housekeeping/status").status_code == 401


def test_news_creation_accepts_admin_session_without_legacy_token(admin_app_client):
    """A sessao real de login deve funcionar para o CMS de noticias mesmo
    sem o antigo X-Admin-Token (compatibilidade dupla, ver `_require_content_admin`)."""
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    created = client.post(
        "/news", json={"title": "Publicado via sessao", "summary": "", "body": ""}, headers=headers
    )
    assert created.status_code == 200
    assert created.json()["title"] == "Publicado via sessao"


# ---------------------------------------------------------------------------
# 2FA (TOTP)
# ---------------------------------------------------------------------------

def test_2fa_full_enrollment_and_login_flow(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    setup_resp = client.post("/admin/auth/2fa/setup", headers=headers)
    assert setup_resp.status_code == 200, setup_resp.text
    secret = setup_resp.json()["secret"]
    assert setup_resp.json()["qr_code_base64"]

    import app.totp as totp_mod
    code = totp_mod.generate_code(secret)

    enable_resp = client.post("/admin/auth/2fa/enable", json={"code": code}, headers=headers)
    assert enable_resp.status_code == 200, enable_resp.text
    backup_codes = enable_resp.json()["backup_codes"]
    assert len(backup_codes) == 10

    # login sem otp_code agora deve exigir 2FA (428)
    no_otp = client.post("/admin/auth/login", json={"username": "operator", "password": "SenhaForte1234!"})
    assert no_otp.status_code == 428
    assert no_otp.json()["detail"] == "2fa_required"

    # login com codigo TOTP valido funciona
    fresh_code = totp_mod.generate_code(secret)
    with_otp = client.post("/admin/auth/login", json={"username": "operator", "password": "SenhaForte1234!", "otp_code": fresh_code})
    assert with_otp.status_code == 200, with_otp.text
    assert with_otp.json()["token"]

    # login com codigo de backup (uso unico) tambem funciona
    backup_login = client.post("/admin/auth/login", json={"username": "operator", "password": "SenhaForte1234!", "otp_code": backup_codes[0]})
    assert backup_login.status_code == 200

    # reutilizar o MESMO codigo de backup deve falhar (uso unico)
    backup_reuse = client.post("/admin/auth/login", json={"username": "operator", "password": "SenhaForte1234!", "otp_code": backup_codes[0]})
    assert backup_reuse.status_code == 401


def test_2fa_invalid_code_rejected(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/admin/auth/2fa/setup", headers=headers)
    resp = client.post("/admin/auth/2fa/enable", json={"code": "000000"}, headers=headers)
    assert resp.status_code == 401


def test_2fa_disable_requires_password(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    setup_resp = client.post("/admin/auth/2fa/setup", headers=headers)
    secret = setup_resp.json()["secret"]
    import app.totp as totp_mod
    client.post("/admin/auth/2fa/enable", json={"code": totp_mod.generate_code(secret)}, headers=headers)

    wrong_pw = client.post("/admin/auth/2fa/disable", json={"password": "senhaerrada"}, headers=headers)
    assert wrong_pw.status_code == 401

    ok = client.post("/admin/auth/2fa/disable", json={"password": "SenhaForte1234!"}, headers=headers)
    assert ok.status_code == 200

    # apos desativar, login sem otp funciona de novo normalmente
    fresh_login = client.post("/admin/auth/login", json={"username": "operator", "password": "SenhaForte1234!"})
    assert fresh_login.status_code == 200


# ---------------------------------------------------------------------------
# Gestao multi-usuario (owner/editor)
# ---------------------------------------------------------------------------

def test_owner_can_create_and_delete_operator(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    create_resp = client.post("/admin/users", json={"username": "editorx", "password": "SenhaEditor123", "role": "editor"}, headers=headers)
    assert create_resp.status_code == 200, create_resp.text

    users_resp = client.get("/admin/users", headers=headers)
    usernames = {u["username"] for u in users_resp.json()["users"]}
    assert "editorx" in usernames

    # editor consegue logar
    editor_login = client.post("/admin/auth/login", json={"username": "editorx", "password": "SenhaEditor123"})
    assert editor_login.status_code == 200
    editor_token = editor_login.json()["token"]
    editor_headers = {"Authorization": f"Bearer {editor_token}"}

    # editor NAO pode criar outro operador (nao e owner)
    forbidden = client.post("/admin/users", json={"username": "outro", "password": "SenhaOutro123", "role": "editor"}, headers=editor_headers)
    assert forbidden.status_code == 403

    # owner remove o editor criado
    delete_resp = client.delete("/admin/users/editorx", headers=headers)
    assert delete_resp.status_code == 200


def test_cannot_delete_last_owner(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.delete("/admin/users/operator", headers=headers)
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# CMS: revisoes/rollback + menu
# ---------------------------------------------------------------------------

def test_cms_page_revisions_and_rollback(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    client.put("/admin/pages/sobre", json={"title": "Sobre v1", "body": "corpo v1", "published": True}, headers=headers)
    client.put("/admin/pages/sobre", json={"title": "Sobre v2", "body": "corpo v2", "published": True}, headers=headers)

    revisions_resp = client.get("/admin/pages/sobre/revisions", headers=headers)
    assert revisions_resp.status_code == 200
    revisions = revisions_resp.json()["revisions"]
    assert len(revisions) == 1
    assert revisions[0]["title"] == "Sobre v1"

    restore_resp = client.post(f"/admin/pages/sobre/revisions/{revisions[0]['version']}/restore", headers=headers)
    assert restore_resp.status_code == 200
    assert restore_resp.json()["title"] == "Sobre v1"

    public = client.get("/pages/sobre")
    assert public.json()["title"] == "Sobre v1"


def test_cms_menu_listing(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    client.put("/admin/pages/faq", json={"title": "FAQ", "body": "...", "published": True, "show_in_menu": True, "menu_order": 1}, headers=headers)
    client.put("/admin/pages/oculta", json={"title": "Oculta", "body": "...", "published": True, "show_in_menu": False}, headers=headers)
    resp = client.get("/pages")
    slugs = {p["slug"] for p in resp.json()["pages"]}
    assert "faq" in slugs
    assert "oculta" not in slugs


# ---------------------------------------------------------------------------
# Noticias: rascunho/agendamento
# ---------------------------------------------------------------------------

def test_news_draft_not_visible_publicly(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    draft = client.post("/news", json={"title": "Rascunho", "status": "draft"}, headers=headers)
    assert draft.status_code == 200
    post_id = draft.json()["id"]

    public_list = client.get("/news")
    assert all(p["id"] != post_id for p in public_list.json()["posts"])

    admin_list = client.get("/admin/news", headers=headers)
    assert any(p["id"] == post_id for p in admin_list.json()["posts"])


# ---------------------------------------------------------------------------
# Site settings
# ---------------------------------------------------------------------------

def test_site_settings_update_and_public_read(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    update_resp = client.put("/admin/settings", json={"site_name": "PixCripto Prod", "unknown_key": "ignored"}, headers=headers)
    assert update_resp.status_code == 200
    assert update_resp.json()["site_name"] == "PixCripto Prod"

    public = client.get("/settings/public")
    assert public.json()["site_name"] == "PixCripto Prod"


# ---------------------------------------------------------------------------
# Housekeeping: backups + dashboard
# ---------------------------------------------------------------------------

def test_housekeeping_manual_backup_lifecycle(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}

    create_resp = client.post("/admin/housekeeping/backups", headers=headers)
    assert create_resp.status_code == 200, create_resp.text
    filename = create_resp.json()["filename"]

    list_resp = client.get("/admin/housekeeping/backups", headers=headers)
    assert any(b["filename"] == filename for b in list_resp.json()["backups"])

    delete_resp = client.delete(f"/admin/housekeeping/backups/{filename}", headers=headers)
    assert delete_resp.status_code == 200


def test_admin_dashboard_returns_live_chain_stats(admin_app_client):
    client = admin_app_client
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/admin/dashboard", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "chain" in body and "difficulty" in body and "network" in body
    assert "dump_control" in body
    assert "feature_flags" in body

