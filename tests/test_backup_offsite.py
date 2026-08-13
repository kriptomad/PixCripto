"""
Testes para o backup offsite configuravel via PIXCRIPTO_BACKUP_OFFSITE_DIR.

Valida que:
- Quando a variavel estiver configurada, o zip e copiado para o segundo destino.
- Quando NAO estiver configurada, o comportamento e exatamente o mesmo de antes
  (so local, sem erros, sem campos extras no retorno).
- Falha no destino offsite NAO cancela o backup local (tolerancia a falhas).
- O arquivo copiado e identico byte-a-byte ao backup local.
- O script restore_backup.py funciona: extrai, valida integridade e restaura.
"""
from __future__ import annotations

import importlib
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def hk_env(tmp_path, monkeypatch):
    """Ambiente isolado de housekeeping com banco proprio."""
    db_path = tmp_path / "chain.db"
    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(db_path))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "compliance.db"))
    monkeypatch.setenv("PIXCRIPTO_HOUSEKEEPING_INTERVAL_SECONDS", "999999")
    # garante que offsite NAO esta configurado por padrao (isolamento)
    monkeypatch.delenv("PIXCRIPTO_BACKUP_OFFSITE_DIR", raising=False)

    import app.storage as storage_mod
    importlib.reload(storage_mod)
    import app.settings as settings_mod
    importlib.reload(settings_mod)
    import app.housekeeping as hk_mod
    importlib.reload(hk_mod)
    return hk_mod, storage_mod, tmp_path


def test_backup_local_only_when_offsite_not_configured(hk_env):
    """Sem PIXCRIPTO_BACKUP_OFFSITE_DIR, o backup funciona exatamente como antes."""
    hk_mod, storage_mod, tmp_path = hk_env
    result = hk_mod.create_backup()
    assert result is not None
    assert "filename" in result
    assert result["size_bytes"] > 0
    # nao deve conter chave offsite quando nao configurado
    assert "offsite" not in result

    # o arquivo local existe
    local_zip = storage_mod.DB_PATH.parent / "backups" / result["filename"]
    assert local_zip.exists()
    assert zipfile.is_zipfile(local_zip)


def test_backup_copies_to_offsite_dir(hk_env, monkeypatch):
    """Com PIXCRIPTO_BACKUP_OFFSITE_DIR configurado, o zip e copiado para o segundo destino."""
    hk_mod, storage_mod, tmp_path = hk_env
    offsite_dir = tmp_path / "offsite_backup"
    monkeypatch.setenv("PIXCRIPTO_BACKUP_OFFSITE_DIR", str(offsite_dir))

    # Precisa recarregar settings (le a var de ambiente na construcao)
    import app.settings as settings_mod
    importlib.reload(settings_mod)
    importlib.reload(hk_mod)

    result = hk_mod.create_backup()
    assert result is not None
    assert "offsite" in result
    assert result["offsite"]["status"] == "ok"

    # diretorio foi criado automaticamente
    assert offsite_dir.exists()

    # arquivo offsite existe e tem o mesmo nome do backup local
    offsite_zip = offsite_dir / result["filename"]
    assert offsite_zip.exists()

    # conteudo identico ao backup local
    local_zip = storage_mod.DB_PATH.parent / "backups" / result["filename"]
    assert local_zip.read_bytes() == offsite_zip.read_bytes()

    # offsite e um zip valido com o banco dentro
    assert zipfile.is_zipfile(offsite_zip)
    with zipfile.ZipFile(offsite_zip) as zf:
        assert "pixcripto_chain.db" in zf.namelist()


def test_offsite_failure_does_not_cancel_local_backup(hk_env, monkeypatch, tmp_path):
    """Falha ao copiar para offsite nao derruba o backup local — apenas reporta
    erro no campo 'offsite'. Usa um caminho invalido criado colocando um FILE
    no lugar onde o diretorio deveria ser criado (funciona em todos os SO)."""
    hk_mod, storage_mod, _ = hk_env
    # Cria um ARQUIVO onde o diretorio de destino offsite deveria ser criado —
    # tentar mkdir dentro de um arquivo levanta excecao em qualquer SO.
    blocker = tmp_path / "offsite_blocker_file"
    blocker.write_bytes(b"sou um arquivo, nao um diretorio")
    # tenta usar um subdiretorio DENTRO do arquivo (impossivel)
    bad_dir = str(blocker / "nao_pode_ser_criado")
    monkeypatch.setenv("PIXCRIPTO_BACKUP_OFFSITE_DIR", bad_dir)

    import app.settings as settings_mod
    importlib.reload(settings_mod)
    importlib.reload(hk_mod)

    result = hk_mod.create_backup()
    assert result is not None

    # backup local deve ter sido criado com sucesso
    local_zip = storage_mod.DB_PATH.parent / "backups" / result["filename"]
    assert local_zip.exists()
    assert result["size_bytes"] > 0

    # offsite deve reportar erro (nao lancar excecao)
    assert "offsite" in result
    assert result["offsite"]["status"] == "error"
    assert "error" in result["offsite"]


def test_restore_backup_script_dry_run(hk_env, tmp_path):
    """--dry-run valida o backup sem sobrescrever nada no destino."""
    hk_mod, storage_mod, _ = hk_env
    result = hk_mod.create_backup()
    backup_zip = storage_mod.DB_PATH.parent / "backups" / result["filename"]

    dest = tmp_path / "restore_dest"
    dest.mkdir()

    proc = subprocess.run(
        [sys.executable, "scripts/restore_backup.py",
         str(backup_zip), str(dest), "--dry-run"],
        capture_output=True, text=True,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    assert proc.returncode == 0, f"dry-run falhou:\n{proc.stdout}\n{proc.stderr}"
    assert "dry-run" in proc.stdout.lower() or "DRY-RUN" in proc.stdout or "dry_run" in proc.stdout.lower()
    # nenhum arquivo de banco deve ter sido criado no destino
    assert not (dest / "pixcripto_chain.db").exists()


def test_restore_backup_script_real_restore(hk_env, tmp_path):
    """Restore real extrai o banco, valida integridade e o arquivo e utilizavel."""
    hk_mod, storage_mod, _ = hk_env
    result = hk_mod.create_backup()
    backup_zip = storage_mod.DB_PATH.parent / "backups" / result["filename"]

    dest = tmp_path / "restore_real"
    dest.mkdir()

    proc = subprocess.run(
        [sys.executable, "scripts/restore_backup.py",
         str(backup_zip), str(dest), "--force"],
        capture_output=True, text=True,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    assert proc.returncode == 0, f"restore falhou:\n{proc.stdout}\n{proc.stderr}"

    # banco restaurado existe e passa em integrity_check
    restored_db = dest / "pixcripto_chain.db"
    assert restored_db.exists()

    conn = sqlite3.connect(str(restored_db))
    try:
        row = conn.execute("PRAGMA integrity_check").fetchone()
        assert row[0] == "ok"
    finally:
        conn.close()


def test_restore_backup_script_rejects_invalid_zip(tmp_path):
    """Script rejeita arquivo que nao e um zip valido."""
    bad_file = tmp_path / "not_a_backup.zip"
    bad_file.write_bytes(b"isso nao e um zip")
    dest = tmp_path / "dest"
    dest.mkdir()

    proc = subprocess.run(
        [sys.executable, "scripts/restore_backup.py",
         str(bad_file), str(dest)],
        capture_output=True, text=True,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    assert proc.returncode != 0


def test_restore_backup_script_aborts_if_db_exists_without_force(hk_env, tmp_path):
    """Sem --force, script aborta se o banco ja existir no destino."""
    hk_mod, storage_mod, _ = hk_env
    result = hk_mod.create_backup()
    backup_zip = storage_mod.DB_PATH.parent / "backups" / result["filename"]

    dest = tmp_path / "restore_existing"
    dest.mkdir()
    # cria banco ficticio no destino para simular "servidor rodando"
    (dest / "pixcripto_chain.db").write_bytes(b"banco existente")

    proc = subprocess.run(
        [sys.executable, "scripts/restore_backup.py",
         str(backup_zip), str(dest)],
        capture_output=True, text=True,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    assert proc.returncode != 0
    # conteudo original nao deve ter sido sobrescrito
    assert (dest / "pixcripto_chain.db").read_bytes() == b"banco existente"
