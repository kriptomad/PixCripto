"""
Testes do sistema de monitoramento e alertas (`app/monitoring.py`).

Cobre:
  - GET /metrics retorna formato Prometheus valido e metricas corretas
  - send_alert persiste em alert_log e GET /monitoring/alerts/recent retorna
  - Rate-limit: dois alertas identicos rapidos -> so 1 persiste
  - Webhook: POST correto para URL mock (via httpx + respx ou servidor local)
  - Reorg da blockchain dispara alerta de monitoramento
  - Honeypot record() dispara alerta
  - Bruteforce lockout dispara alerta
  - Source integrity tampered dispara alerta
  - Housekeeping db integrity fail dispara alerta
"""
from __future__ import annotations

import importlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def monitoring_client(tmp_path, monkeypatch):
    """
    Cliente de teste com banco SQLite isolado e sem webhook configurado
    (testa persistencia local e /monitoring/alerts/recent).
    """
    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(tmp_path / "chain.db"))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "compliance.db"))
    monkeypatch.setenv("PIXCRIPTO_ADMIN_USERNAME", "operator")
    monkeypatch.setenv("PIXCRIPTO_ADMIN_PASSWORD", "SenhaForte1234!")
    monkeypatch.setenv("PIXCRIPTO_HOUSEKEEPING_INTERVAL_SECONDS", "999999")
    monkeypatch.delenv("PIXCRIPTO_ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.setenv("PIXCRIPTO_ALERT_RATE_LIMIT_SECONDS", "0")

    import app.storage as storage_mod
    importlib.reload(storage_mod)
    storage_mod.init_db()
    import app.settings as settings_mod
    importlib.reload(settings_mod)
    import app.monitoring as monitoring_mod
    importlib.reload(monitoring_mod)
    monitoring_mod.reset_rate_limit_cache()
    import app.admin_auth as admin_auth_mod
    importlib.reload(admin_auth_mod)
    import app.bruteforce_guard as bruteforce_guard_mod
    bruteforce_guard_mod.guard.reset_all()
    import app.honeypot as honeypot_mod
    importlib.reload(honeypot_mod)
    import app.source_integrity as si_mod
    importlib.reload(si_mod)
    monkeypatch.setattr(si_mod, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(si_mod, "BASELINE_PATH", tmp_path / "data" / "source_integrity_baseline.json")
    import app.housekeeping as housekeeping_mod
    importlib.reload(housekeeping_mod)
    import app.api as api_mod
    importlib.reload(api_mod)
    client = TestClient(api_mod.app)
    yield client, monitoring_mod, api_mod
    api_mod.housekeeping.stop_scheduler()


def test_metrics_returns_prometheus_format(monitoring_client):
    client, _, _ = monitoring_client
    resp = client.get("/metrics")
    assert resp.status_code == 200
    ct = resp.headers.get("content-type", "")
    assert "text/plain" in ct
    assert "version=0.0.4" in ct
    body = resp.text
    assert "pixcripto_chain_height" in body
    assert "pixcripto_mempool_size" in body
    assert "pixcripto_current_difficulty" in body
    assert "pixcripto_chain_mined_blocks_total" in body
    assert "pixcripto_honeypot_events_total" in body
    assert "pixcripto_bruteforce_active_lockouts" in body
    assert "pixcripto_source_integrity_ok" in body
    assert "pixcripto_admin_sessions_active" in body
    assert "pixcripto_user_accounts_total" in body
    assert "pixcripto_kyc_submissions_pending" in body


def test_metrics_contains_help_and_type_lines(monitoring_client):
    client, _, _ = monitoring_client
    body = client.get("/metrics").text
    assert "# HELP pixcripto_chain_height" in body
    assert "# TYPE pixcripto_chain_height gauge" in body
    assert "# HELP pixcripto_mempool_size" in body
    assert "# TYPE pixcripto_mempool_size gauge" in body


def test_metrics_chain_height_reflects_mined_blocks(monitoring_client):
    from app import root_rules
    from app.models import Transaction
    from app.wallet import Wallet

    client, _, api_mod = monitoring_client

    def _parse_metric(body: str, name: str) -> float:
        for line in body.splitlines():
            if line.startswith(name + " ") or line.startswith(name + "{"):
                parts = line.rsplit(" ", 1)
                if len(parts) == 2:
                    try:
                        return float(parts[1])
                    except ValueError:
                        pass
        raise KeyError(f"Metrica '{name}' nao encontrada no body")

    body_before = client.get("/metrics").text
    height_before = _parse_metric(body_before, "pixcripto_chain_height")

    recipient = Wallet.create()
    api_mod.blockchain.add_transaction(
        Transaction(
            sender=root_rules.COINBASE_SENDER,
            recipient=recipient.address,
            amount=10.0,
            tx_type="coinbase_purchase",
        )
    )

    mine_resp = client.post("/mining/mine", json={"miner_address": Wallet.create().address})
    assert mine_resp.status_code == 200

    body_after = client.get("/metrics").text
    height_after = _parse_metric(body_after, "pixcripto_chain_height")
    assert height_after > height_before


def test_metrics_mempool_size(monitoring_client):
    from app import root_rules
    from app.models import Transaction
    from app.wallet import Wallet

    client, _, api_mod = monitoring_client

    def _parse_metric(body, name):
        for line in body.splitlines():
            if line.startswith(name + " "):
                return float(line.split(" ", 1)[1])
        raise KeyError(name)

    body_before = client.get("/metrics").text
    mem_before = _parse_metric(body_before, "pixcripto_mempool_size")

    w = Wallet.create()
    credit = Transaction(
        sender=root_rules.COINBASE_SENDER, recipient=w.address,
        amount=10.0, tx_type="coinbase_purchase",
    )
    api_mod.blockchain.add_transaction(credit)

    body_after = client.get("/metrics").text
    mem_after = _parse_metric(body_after, "pixcripto_mempool_size")
    assert mem_after > mem_before


def test_send_alert_persists_without_webhook(monitoring_client):
    _, monitoring_mod, _ = monitoring_client
    monitoring_mod.send_alert(
        event_type="test_event",
        severity="warning",
        message="Mensagem de teste",
        details={"chave": "valor"},
    )
    alerts = monitoring_mod.get_recent_alerts(limit=10)
    assert len(alerts) >= 1
    last = alerts[0]
    assert last["event_type"] == "test_event"
    assert last["severity"] == "warning"
    assert last["message"] == "Mensagem de teste"
    assert last["details"] == {"chave": "valor"}
    assert last["webhook_delivered"] is False


def test_get_recent_alerts_endpoint(monitoring_client):
    client, monitoring_mod, _ = monitoring_client
    monitoring_mod.send_alert("endpoint_test", "info", "Teste endpoint", {})
    resp = client.get("/monitoring/alerts/recent?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert "alerts" in data
    assert any(a["event_type"] == "endpoint_test" for a in data["alerts"])


def test_rate_limit_blocks_duplicate_alerts(tmp_path, monkeypatch):
    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(tmp_path / "rl.db"))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "rl_compliance.db"))
    monkeypatch.setenv("PIXCRIPTO_ALERT_RATE_LIMIT_SECONDS", "60")
    monkeypatch.delenv("PIXCRIPTO_ALERT_WEBHOOK_URL", raising=False)

    import app.storage as storage_mod
    importlib.reload(storage_mod)
    storage_mod.init_db()
    import app.settings as settings_mod
    importlib.reload(settings_mod)
    import app.monitoring as monitoring_mod
    importlib.reload(monitoring_mod)
    monitoring_mod.reset_rate_limit_cache()

    monitoring_mod.send_alert("dup_event", "warning", "Primeiro alerta", {})
    monitoring_mod.send_alert("dup_event", "warning", "Segundo alerta (deve ser descartado)", {})

    alerts = monitoring_mod.get_recent_alerts(limit=10)
    dup_alerts = [a for a in alerts if a["event_type"] == "dup_event"]
    assert len(dup_alerts) == 1


def test_rate_limit_allows_after_window(tmp_path, monkeypatch):
    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(tmp_path / "rl2.db"))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "rl2_compliance.db"))
    monkeypatch.setenv("PIXCRIPTO_ALERT_RATE_LIMIT_SECONDS", "0")
    monkeypatch.delenv("PIXCRIPTO_ALERT_WEBHOOK_URL", raising=False)

    import app.storage as storage_mod
    importlib.reload(storage_mod)
    storage_mod.init_db()
    import app.settings as settings_mod
    importlib.reload(settings_mod)
    import app.monitoring as monitoring_mod
    importlib.reload(monitoring_mod)
    monitoring_mod.reset_rate_limit_cache()

    monitoring_mod.send_alert("zero_window_event", "info", "Primeiro", {})
    monitoring_mod.send_alert("zero_window_event", "info", "Segundo", {})

    alerts = monitoring_mod.get_recent_alerts(limit=10)
    this_alerts = [a for a in alerts if a["event_type"] == "zero_window_event"]
    assert len(this_alerts) == 2


def test_webhook_post_correct_payload(tmp_path, monkeypatch):
    received_payloads: List[dict] = []
    event = threading.Event()

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("content-length", 0))
            body = self.rfile.read(length)
            received_payloads.append(json.loads(body.decode("utf-8")))
            self.send_response(200)
            self.end_headers()
            event.set()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    threading.Thread(target=server.handle_request, daemon=True).start()

    webhook_url = f"http://127.0.0.1:{port}/"
    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(tmp_path / "wh.db"))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "wh_compliance.db"))
    monkeypatch.setenv("PIXCRIPTO_ALERT_WEBHOOK_URL", webhook_url)
    monkeypatch.setenv("PIXCRIPTO_ALERT_RATE_LIMIT_SECONDS", "0")

    import app.storage as storage_mod
    importlib.reload(storage_mod)
    storage_mod.init_db()
    import app.settings as settings_mod
    importlib.reload(settings_mod)
    import app.monitoring as monitoring_mod
    importlib.reload(monitoring_mod)
    monitoring_mod.reset_rate_limit_cache()

    monitoring_mod.send_alert("webhook_test", "critical", "Teste webhook", {"k": "v"})

    assert event.wait(timeout=5.0)
    server.server_close()

    assert len(received_payloads) == 1
    payload = received_payloads[0]
    assert payload["event_type"] == "webhook_test"
    assert payload["severity"] == "critical"
    assert payload["message"] == "Teste webhook"
    assert payload["details"] == {"k": "v"}
    assert "timestamp" in payload


def test_webhook_persists_with_delivered_flag(tmp_path, monkeypatch):
    received = threading.Event()

    class _OKHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("content-length", 0))
            self.rfile.read(length)
            self.send_response(200)
            self.end_headers()
            received.set()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), _OKHandler)
    port = server.server_address[1]
    threading.Thread(target=server.handle_request, daemon=True).start()

    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(tmp_path / "wh2.db"))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "wh2_compliance.db"))
    monkeypatch.setenv("PIXCRIPTO_ALERT_WEBHOOK_URL", f"http://127.0.0.1:{port}/")
    monkeypatch.setenv("PIXCRIPTO_ALERT_RATE_LIMIT_SECONDS", "0")

    import app.storage as storage_mod
    importlib.reload(storage_mod)
    storage_mod.init_db()
    import app.settings as settings_mod
    importlib.reload(settings_mod)
    import app.monitoring as monitoring_mod
    importlib.reload(monitoring_mod)
    monitoring_mod.reset_rate_limit_cache()

    monitoring_mod.send_alert("delivered_test", "info", "Deve marcar delivered=True", {})
    assert received.wait(timeout=5.0), "Webhook nao recebeu o POST em 5s"
    server.server_close()

    # Polling com timeout para aguardar a thread de background persistir no banco.
    # Um sleep fixo pode falhar em maquinas lentas; polling e mais robusto.
    deadline = time.time() + 5.0
    delivered = []
    while time.time() < deadline:
        alerts = monitoring_mod.get_recent_alerts(limit=5)
        delivered = [a for a in alerts if a["event_type"] == "delivered_test"]
        if delivered:
            break
        time.sleep(0.05)

    assert len(delivered) == 1, (
        f"Alerta 'delivered_test' nao encontrado no alert_log apos 5s: "
        f"{[a['event_type'] for a in monitoring_mod.get_recent_alerts(10)]}"
    )
    assert delivered[0]["webhook_delivered"] is True


def test_honeypot_record_triggers_alert(monitoring_client):
    _, monitoring_mod, api_mod = monitoring_client
    monitoring_mod.reset_rate_limit_cache()

    hp = api_mod.honeypot
    hp.record(
        ip="1.2.3.4", path="/admin/backup", user_agent="EvilBot/1.0",
        detail="acesso a rota sensivel", score=15,
    )
    time.sleep(0.1)
    alerts = monitoring_mod.get_recent_alerts(limit=20)
    hp_alerts = [a for a in alerts if a["event_type"] == "honeypot_exploit_attempt"]
    assert len(hp_alerts) >= 1
    assert hp_alerts[0]["severity"] == "warning"
    assert "1.2.3.4" in hp_alerts[0]["details"].get("ip", "")


def test_bruteforce_lockout_triggers_alert(monitoring_client):
    _, monitoring_mod, _ = monitoring_client
    monitoring_mod.reset_rate_limit_cache()

    from app.bruteforce_guard import BruteForceGuard
    g = BruteForceGuard()
    g.record_failure("test_scope", "attacker_ip")
    g.record_failure("test_scope", "attacker_ip")
    g.record_failure("test_scope", "attacker_ip")

    time.sleep(0.1)
    alerts = monitoring_mod.get_recent_alerts(limit=20)
    bf_alerts = [a for a in alerts if a["event_type"] == "bruteforce_lockout"]
    assert len(bf_alerts) >= 1
    assert bf_alerts[0]["severity"] == "warning"
    assert bf_alerts[0]["details"]["scope"] == "test_scope"


def test_source_integrity_tampering_triggers_alert(tmp_path, monkeypatch):
    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(tmp_path / "si.db"))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "si_compliance.db"))
    monkeypatch.setenv("PIXCRIPTO_ALERT_RATE_LIMIT_SECONDS", "0")
    monkeypatch.delenv("PIXCRIPTO_ALERT_WEBHOOK_URL", raising=False)

    import app.storage as storage_mod
    importlib.reload(storage_mod)
    storage_mod.init_db()
    import app.settings as settings_mod
    importlib.reload(settings_mod)
    import app.monitoring as monitoring_mod
    importlib.reload(monitoring_mod)
    monitoring_mod.reset_rate_limit_cache()
    import app.source_integrity as si_mod
    importlib.reload(si_mod)
    monkeypatch.setattr(si_mod, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(si_mod, "BASELINE_PATH", tmp_path / "data" / "source_integrity_baseline.json")

    import json as _json
    fake_baseline = {
        "merkle_root": "aaa" * 21 + "bb",
        "file_hashes": {"modulo_inexistente.py": "0" * 64},
        "recorded_at": time.time() - 100,
        "file_count": 1,
    }
    si_mod.BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    original_baseline = si_mod.BASELINE_PATH.read_text(encoding="utf-8") if si_mod.BASELINE_PATH.exists() else None
    si_mod.BASELINE_PATH.write_text(_json.dumps(fake_baseline), encoding="utf-8")

    try:
        result = si_mod.check_integrity()
        assert result["status"] == "tampering_detected"
        time.sleep(0.1)
        alerts = monitoring_mod.get_recent_alerts(limit=10)
        si_alerts = [a for a in alerts if a["event_type"] == "source_integrity_tampered"]
        assert len(si_alerts) >= 1
        assert si_alerts[0]["severity"] == "critical"
    finally:
        if original_baseline is None:
            si_mod.BASELINE_PATH.unlink(missing_ok=True)
        else:
            si_mod.BASELINE_PATH.write_text(original_baseline, encoding="utf-8")


def test_housekeeping_db_integrity_fail_triggers_alert(tmp_path, monkeypatch):
    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(tmp_path / "hk.db"))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "hk_compliance.db"))
    monkeypatch.setenv("PIXCRIPTO_ALERT_RATE_LIMIT_SECONDS", "0")
    monkeypatch.delenv("PIXCRIPTO_ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.setenv("PIXCRIPTO_HOUSEKEEPING_INTERVAL_SECONDS", "999999")

    import app.storage as storage_mod
    importlib.reload(storage_mod)
    storage_mod.init_db()
    import app.settings as settings_mod
    importlib.reload(settings_mod)
    import app.monitoring as monitoring_mod
    importlib.reload(monitoring_mod)
    monitoring_mod.reset_rate_limit_cache()
    import app.feature_flags as ff_mod
    importlib.reload(ff_mod)
    import app.honeypot as hp_mod
    importlib.reload(hp_mod)
    import app.media as media_mod
    importlib.reload(media_mod)
    import app.housekeeping as hk_mod
    importlib.reload(hk_mod)

    original_check = storage_mod.integrity_check_database
    storage_mod.integrity_check_database = lambda: "error - corrupted page"

    try:
        result = hk_mod.run_housekeeping(triggered_by="test")
        assert any("integrity" in w.lower() for w in result["stats"]["warnings"])
    finally:
        storage_mod.integrity_check_database = original_check

    time.sleep(0.1)
    alerts = monitoring_mod.get_recent_alerts(limit=10)
    hk_alerts = [a for a in alerts if a["event_type"] == "db_integrity_check_failed"]
    assert len(hk_alerts) >= 1
    assert hk_alerts[0]["severity"] == "critical"


def test_reorg_triggers_alert(monitoring_client):
    import asyncio
    import socket

    from app import root_rules
    from app.mining import mine_block
    from app.models import Blockchain, Transaction
    from app.network import P2PNode
    from app.wallet import Wallet

    _, monitoring_mod, _ = monitoring_client
    monitoring_mod.reset_rate_limit_cache()

    def free_port():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    async def scenario():
        chain_a = Blockchain(difficulty_mode="demo")
        w = Wallet.create()
        credit = Transaction(
            sender=root_rules.COINBASE_SENDER, recipient=w.address,
            amount=10.0, tx_type="coinbase_purchase",
        )
        chain_a.add_transaction(credit)
        block_a = chain_a.build_candidate_block(Wallet.create().address)
        assert block_a is not None
        mined_a = mine_block(block_a)
        assert mined_a.success
        chain_a.submit_mined_block(block_a, mined_a.nonce, mined_a.block_hash)

        chain_b = Blockchain(difficulty_mode="demo")
        credit2 = Transaction(
            sender=root_rules.COINBASE_SENDER, recipient=w.address,
            amount=10.0, tx_type="coinbase_purchase",
        )
        chain_b.add_transaction(credit2)
        block_b1 = chain_b.build_candidate_block(Wallet.create().address)
        assert block_b1 is not None
        mined_b1 = mine_block(block_b1)
        assert mined_b1.success
        chain_b.submit_mined_block(block_b1, mined_b1.nonce, mined_b1.block_hash)
        credit3 = Transaction(
            sender=root_rules.COINBASE_SENDER, recipient=w.address,
            amount=10.0, tx_type="coinbase_purchase",
        )
        chain_b.add_transaction(credit3)
        block_b2 = chain_b.build_candidate_block(Wallet.create().address)
        assert block_b2 is not None
        mined_b2 = mine_block(block_b2)
        assert mined_b2.success
        chain_b.submit_mined_block(block_b2, mined_b2.nonce, mined_b2.block_hash)

        port_a, port_b = free_port(), free_port()
        node_a = P2PNode(chain_a, host="127.0.0.1", port=port_a)
        node_b = P2PNode(chain_b, host="127.0.0.1", port=port_b)
        await node_a.start()
        await node_b.start()
        try:
            await node_a.connect_to_peer("127.0.0.1", port_b)
            for _ in range(30):
                await asyncio.sleep(0.05)
        finally:
            await node_a.stop()
            await node_b.stop()

    asyncio.run(scenario())

    time.sleep(0.3)
    alerts = monitoring_mod.get_recent_alerts(limit=20)
    reorg_alerts = [a for a in alerts if a["event_type"] == "blockchain_reorg"]
    assert len(reorg_alerts) >= 1
    assert reorg_alerts[0]["severity"] == "warning"
    assert "reorg_depth" in reorg_alerts[0]["details"]
