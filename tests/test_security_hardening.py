"""
Testes para os mecanismos de "codigo auto-mutavel" pedidos explicitamente pelo
usuario para se defender de forca-bruta e adulteracao de codigo-fonte:

- `app/bruteforce_guard.py`: guarda adaptativo com cooldown exponencial por
  identidade (mais severo a cada nova tentativa falha).
- `app/source_integrity.py`: deteccao de adulteracao de arquivos `.py` via
  hash SHA-256 + raiz Merkle-like comparada contra uma baseline persistida.
"""
from __future__ import annotations

import importlib
import time

import pytest

from app import bruteforce_guard as bfg_mod
from app.bruteforce_guard import BruteForceGuard, BruteForceLockedError


# ---------------------------------------------------------------------------
# BruteForceGuard
# ---------------------------------------------------------------------------

@pytest.fixture
def guard() -> BruteForceGuard:
    return BruteForceGuard()


def test_first_two_failures_do_not_lock(guard: BruteForceGuard):
    guard.check("scope", "1.2.3.4")  # nao deve levantar - identidade nova
    guard.record_failure("scope", "1.2.3.4")
    guard.check("scope", "1.2.3.4")  # 1a falha nao bloqueia
    guard.record_failure("scope", "1.2.3.4")
    guard.check("scope", "1.2.3.4")  # 2a falha ainda nao bloqueia (tolerancia a erro real)


def test_third_failure_locks_out(guard: BruteForceGuard):
    guard.record_failure("scope", "9.9.9.9")
    guard.record_failure("scope", "9.9.9.9")
    guard.record_failure("scope", "9.9.9.9")
    with pytest.raises(BruteForceLockedError):
        guard.check("scope", "9.9.9.9")


def test_cooldown_grows_exponentially_per_failure(guard: BruteForceGuard):
    identity = "10.0.0.1"
    cooldowns = []
    for _ in range(5):
        guard.record_failure("scope", identity)
        status = guard.status("scope", identity)
        cooldowns.append(status["retry_after_seconds"])
    # a partir da 3a falha o cooldown deve estritamente crescer a cada nova falha
    growing = cooldowns[2:]
    assert all(b >= a for a, b in zip(growing, growing[1:]))
    assert growing[-1] > growing[0]


def test_cooldown_capped_at_max(guard: BruteForceGuard):
    identity = "10.0.0.2"
    for _ in range(30):
        guard.record_failure("scope", identity)
    status = guard.status("scope", identity)
    assert status["retry_after_seconds"] <= bfg_mod.MAX_COOLDOWN_SECONDS


def test_success_resets_failure_counter(guard: BruteForceGuard):
    identity = "10.0.0.3"
    guard.record_failure("scope", identity)
    guard.record_failure("scope", identity)
    guard.record_success("scope", identity)
    status = guard.status("scope", identity)
    assert status["failures"] == 0
    assert status["locked"] is False
    # depois de resetar, precisa de novo 3 falhas para travar de novo
    guard.check("scope", identity)


def test_identities_are_isolated_from_each_other(guard: BruteForceGuard):
    for _ in range(5):
        guard.record_failure("scope", "attacker-ip")
    with pytest.raises(BruteForceLockedError):
        guard.check("scope", "attacker-ip")
    # outra identidade no MESMO escopo nao deve ser afetada
    guard.check("scope", "innocent-ip")


def test_scopes_are_isolated_from_each_other(guard: BruteForceGuard):
    for _ in range(5):
        guard.record_failure("scope-a", "same-ip")
    with pytest.raises(BruteForceLockedError):
        guard.check("scope-a", "same-ip")
    # mesmo IP, escopo protegido diferente - nao deve herdar o bloqueio
    guard.check("scope-b", "same-ip")


def test_reset_all_clears_every_identity(guard: BruteForceGuard):
    for _ in range(5):
        guard.record_failure("scope", "some-ip")
    guard.reset_all()
    status = guard.status("scope", "some-ip")
    assert status == {"failures": 0, "locked": False, "retry_after_seconds": 0.0}
    guard.check("scope", "some-ip")


def test_lockout_expires_after_cooldown_elapses(guard: BruteForceGuard, monkeypatch):
    identity = "10.0.0.4"
    fake_now = [1_000_000.0]
    monkeypatch.setattr(time, "time", lambda: fake_now[0])
    guard.record_failure("scope", identity)
    guard.record_failure("scope", identity)
    guard.record_failure("scope", identity)
    with pytest.raises(BruteForceLockedError):
        guard.check("scope", identity)
    # avanca o relogio alem do cooldown (3a falha => BASE * GROWTH**1 = 2s)
    fake_now[0] += 10.0
    guard.check("scope", identity)  # nao deve mais levantar


def test_prune_removes_stale_entries(guard: BruteForceGuard, monkeypatch):
    fake_now = [1_000_000.0]
    monkeypatch.setattr(time, "time", lambda: fake_now[0])
    guard.record_failure("scope", "old-ip")
    fake_now[0] += bfg_mod.STALE_ENTRY_SECONDS + 10
    # forca a poda oportunista via nova falha de outra identidade, ultrapassando o teto
    monkeypatch.setattr(bfg_mod, "MAX_TRACKED_IDENTITIES", 1)
    guard.record_failure("scope", "new-ip")
    assert guard.status("scope", "old-ip")["failures"] == 0


# ---------------------------------------------------------------------------
# source_integrity
# ---------------------------------------------------------------------------

@pytest.fixture
def integrity_env(tmp_path, monkeypatch):
    """Isola o modulo `source_integrity` num diretorio `app/` fake, temporario,
    para nao interferir (nem depender) do codigo-fonte real do projeto."""
    fake_app_dir = tmp_path / "app"
    fake_app_dir.mkdir()
    (fake_app_dir / "module_a.py").write_text("value = 1\n", encoding="utf-8")
    (fake_app_dir / "module_b.py").write_text("value = 2\n", encoding="utf-8")

    from app import source_integrity as si_mod
    importlib.reload(si_mod)
    monkeypatch.setattr(si_mod, "APP_DIR", fake_app_dir)
    monkeypatch.setattr(si_mod, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(si_mod, "BASELINE_PATH", tmp_path / "data" / "source_integrity_baseline.json")
    return si_mod, fake_app_dir


def test_first_check_creates_baseline(integrity_env):
    si_mod, _ = integrity_env
    result = si_mod.check_integrity()
    assert result["status"] == "baseline_created"
    assert result["file_count"] == 2
    assert si_mod.BASELINE_PATH.exists()


def test_second_check_with_no_changes_reports_ok(integrity_env):
    si_mod, _ = integrity_env
    si_mod.check_integrity()  # cria baseline
    result = si_mod.check_integrity()
    assert result["status"] == "ok"
    assert result["changed_files"] == []
    assert result["added_files"] == []
    assert result["removed_files"] == []


def test_modifying_a_file_is_detected(integrity_env):
    si_mod, app_dir = integrity_env
    si_mod.check_integrity()
    (app_dir / "module_a.py").write_text("value = 999  # adulterado\n", encoding="utf-8")
    result = si_mod.check_integrity()
    assert result["status"] == "tampering_detected"
    assert result["changed_files"] == ["module_a.py"]
    assert result["added_files"] == []
    assert result["removed_files"] == []


def test_adding_a_file_is_detected(integrity_env):
    si_mod, app_dir = integrity_env
    si_mod.check_integrity()
    (app_dir / "module_c.py").write_text("value = 3\n", encoding="utf-8")
    result = si_mod.check_integrity()
    assert result["status"] == "tampering_detected"
    assert result["added_files"] == ["module_c.py"]


def test_removing_a_file_is_detected(integrity_env):
    si_mod, app_dir = integrity_env
    si_mod.check_integrity()
    (app_dir / "module_b.py").unlink()
    result = si_mod.check_integrity()
    assert result["status"] == "tampering_detected"
    assert result["removed_files"] == ["module_b.py"]


def test_reset_baseline_accepts_current_state_as_trusted(integrity_env):
    si_mod, app_dir = integrity_env
    si_mod.check_integrity()
    (app_dir / "module_a.py").write_text("value = 999  # mudanca legitima\n", encoding="utf-8")
    assert si_mod.check_integrity()["status"] == "tampering_detected"
    si_mod.reset_baseline()
    assert si_mod.check_integrity()["status"] == "ok"


def test_merkle_root_changes_when_any_hash_changes():
    from app import source_integrity as si_mod
    snap_a = {"x.py": "hash1", "y.py": "hash2"}
    snap_b = {"x.py": "hash1", "y.py": "different"}
    assert si_mod.compute_merkle_root(snap_a) != si_mod.compute_merkle_root(snap_b)


def test_merkle_root_is_order_independent():
    from app import source_integrity as si_mod
    snap_a = {"x.py": "hash1", "y.py": "hash2"}
    snap_b = {"y.py": "hash2", "x.py": "hash1"}
    assert si_mod.compute_merkle_root(snap_a) == si_mod.compute_merkle_root(snap_b)
