"""
Sistema de housekeeping automatico do PixCripto (`app/housekeeping.py`).

Executa periodicamente (e sob demanda, via Painel de Administracao) as
tarefas de manutencao que TODO sistema de producao real precisa e que, sem
isto, causariam degradacao silenciosa com o tempo:

  1. Poda de sessoes de administrador expiradas (`admin_sessions`).
  2. Poda do estado do `bruteforce_guard` (entradas de anti-forca-bruta sem
     atividade recente).
  3. Poda de eventos/desafios antigos do honeypot (evita crescimento
     ilimitado de memoria em nos de longa duracao).
  4. Remocao de ARQUIVOS ORFAOS (uploads em disco que nao estao registrados
     em `media_files` nem referenciados por nenhuma noticia publicada).
  5. Poda do historico de precos (`price_history`) alem do periodo de
     retencao configurado - mantem o grafico de mercado utilizavel sem o
     banco crescer sem limite.
  6. `PRAGMA integrity_check` do SQLite - detecta corrupcao de banco cedo,
     antes que vire uma perda de dados silenciosa.
  7. Backup compactado (banco de dados + uploads) com rotacao/retencao -
     protege contra corrupcao/erro humano/falha de disco.
  8. `VACUUM` do SQLite - recompacta o arquivo do banco apos as remocoes
     acima, liberando espaco em disco de fato (sem isto, SQLite mantem o
     espaco de linhas deletadas alocado no arquivo).
  9. Relatorio de uso de disco (banco, uploads, backups) - visibilidade real
     de capacidade para o operador, sem precisar acessar o servidor via SSH.

Cada tarefa acima e individualmente liga/desliga-vel via feature flag
(`housekeeping_task_*`, ver `app/feature_flags.py`) - o operador pode, por
exemplo, desativar backups automaticos temporariamente sem desativar o resto
do housekeeping.

Cada execucao fica registrada em `housekeeping_runs` (auditoria: quando
rodou, o que foi feito, quanto tempo levou) e pode ser disparada:
  - automaticamente, por um agendador em background (thread dedicada,
    iniciada no startup do servidor, intervalo configuravel via
    `PIXCRIPTO_HOUSEKEEPING_INTERVAL_SECONDS`);
  - manualmente, pelo operador, via `/admin/housekeeping/run` no painel.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import threading
import time
import zipfile
from pathlib import Path
from typing import Optional

# importacao tardia para evitar ciclo de imports (settings importa os, nao app)
# — acessada via funcao para permitir reload nos testes de integracao.

from . import feature_flags
from . import honeypot as honeypot_module
from . import media, storage
from .bruteforce_guard import guard as bruteforce_guard
from .settings import settings

logger = logging.getLogger("pixcripto.housekeeping")

_scheduler_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()

_BACKUP_DIR = storage.DB_PATH.parent / "backups"
_BACKUP_RETENTION_COUNT = 14  # mantem as ultimas 14 execucoes de backup (rotacao)
_STATIC_DIR = Path(__file__).resolve().parent / "static"


def _task_enabled(key: str) -> bool:
    try:
        return feature_flags.is_enabled(key)
    except Exception:  # tabela ainda nao inicializada em algum cenario de teste isolado
        return True


def _dir_size_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def create_backup() -> Optional[dict]:
    """Cria um arquivo .zip com uma copia consistente do banco (via API de
    backup do sqlite3, segura mesmo com o banco em uso) + o diretorio de
    uploads, e aplica rotacao (mantem apenas as `_BACKUP_RETENTION_COUNT`
    mais recentes, apagando as demais).

    Se `PIXCRIPTO_BACKUP_OFFSITE_DIR` estiver configurado, copia o zip gerado
    para esse segundo destino de forma atomica (gravacao num arquivo temporario
    e renomeacao final, evitando um zip incompleto visivel no destino).
    Falha na copia offsite NUNCA cancela ou desfaz o backup local — apenas
    registra um warning no log, para que o operador possa corrigir o destino
    sem perder o backup principal."""
    _BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    db_snapshot_path = _BACKUP_DIR / f"_tmp_db_snapshot_{timestamp}.db"
    backup_zip_path = _BACKUP_DIR / f"backup-{timestamp}.zip"

    try:
        source_conn = sqlite3.connect(storage.DB_PATH)
        dest_conn = sqlite3.connect(db_snapshot_path)
        with dest_conn:
            source_conn.backup(dest_conn)
        dest_conn.close()
        source_conn.close()

        with zipfile.ZipFile(backup_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(db_snapshot_path, arcname="pixcripto_chain.db")
            uploads_dir = _STATIC_DIR / "uploads"
            if uploads_dir.exists():
                for file_path in uploads_dir.rglob("*"):
                    if file_path.is_file():
                        zf.write(file_path, arcname=str(Path("uploads") / file_path.relative_to(uploads_dir)))
    finally:
        db_snapshot_path.unlink(missing_ok=True)

    # rotacao: mantem apenas os N backups mais recentes
    all_backups = sorted(_BACKUP_DIR.glob("backup-*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    removed = 0
    for old_backup in all_backups[_BACKUP_RETENTION_COUNT:]:
        old_backup.unlink(missing_ok=True)
        removed += 1

    # copia offsite atomica: grava em arquivo temporario no destino e renomeia —
    # evita janela de tempo onde o arquivo offsite existe mas esta incompleto.
    offsite_result = _copy_backup_offsite(backup_zip_path)

    result: dict = {
        "filename": backup_zip_path.name,
        "size_bytes": backup_zip_path.stat().st_size,
        "rotated_out": removed,
    }
    if offsite_result is not None:
        result["offsite"] = offsite_result
    return result


def _copy_backup_offsite(backup_zip_path: Path) -> Optional[dict]:
    """Copia o zip de backup para o destino offsite configurado em
    `PIXCRIPTO_BACKUP_OFFSITE_DIR`. Retorna um dict descrevendo o resultado
    (sucesso ou falha) ou None se o destino nao estiver configurado.

    A copia e feita de forma ATOMICA via arquivo temporario + renomeacao:
    isso garante que o arquivo final no destino so aparece completamente
    gravado, nunca como um zip truncado que passaria despercebido."""
    offsite_dir_str = settings.backup_offsite_dir
    if not offsite_dir_str:
        return None  # destino nao configurado — comportamento padrao (so local)

    if os.name == "nt" and offsite_dir_str[:1] in ("/", "\\") and not Path(offsite_dir_str).drive:
        return {
            "status": "error",
            "error": "Caminho offsite invalido no Windows: use um caminho absoluto com letra de unidade",
        }

    offsite_dir = Path(offsite_dir_str)
    try:
        offsite_dir.mkdir(parents=True, exist_ok=True)
        # arquivo temporario no mesmo diretorio para que o rename seja atomico
        # (rename de volumes diferentes pode nao ser atomico no Windows)
        tmp_path = offsite_dir / f"_tmp_{backup_zip_path.name}"
        shutil.copy2(backup_zip_path, tmp_path)
        dest_path = offsite_dir / backup_zip_path.name
        tmp_path.rename(dest_path)
        logger.info("housekeeping: backup copiado para destino offsite: %s", dest_path)
        return {"status": "ok", "path": str(dest_path)}
    except Exception as exc:
        # NUNCA deixa a falha do offsite derrubar o backup local ja concluido
        logger.warning(
            "housekeeping: falha ao copiar backup para destino offsite '%s': %s "
            "(backup local esta intacto em %s)",
            offsite_dir_str, exc, backup_zip_path,
        )
        return {"status": "error", "error": str(exc)}


def list_backups() -> list:
    if not _BACKUP_DIR.exists():
        return []
    backups = sorted(_BACKUP_DIR.glob("backup-*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    return [
        {"filename": p.name, "size_bytes": p.stat().st_size, "created_at": p.stat().st_mtime}
        for p in backups
    ]


def delete_backup(filename: str) -> bool:
    candidate = (_BACKUP_DIR / filename).resolve()
    if not str(candidate).startswith(str(_BACKUP_DIR.resolve())) or not candidate.is_file():
        return False
    candidate.unlink()
    return True


def disk_usage_report() -> dict:
    db_size = storage.DB_PATH.stat().st_size if storage.DB_PATH.exists() else 0
    uploads_size = _dir_size_bytes(_STATIC_DIR / "uploads")
    backups_size = _dir_size_bytes(_BACKUP_DIR)
    return {
        "database_bytes": db_size,
        "uploads_bytes": uploads_size,
        "backups_bytes": backups_size,
        "total_bytes": db_size + uploads_size + backups_size,
    }


def run_housekeeping(triggered_by: str = "scheduler") -> dict:
    """Executa as tarefas de manutencao habilitadas uma vez e retorna um
    relatorio completo (acoes realizadas + estatisticas + avisos). Seguro
    para rodar concorrente com o resto do sistema (cada tarefa usa suas
    proprias secoes criticas)."""
    started_at = time.time()
    actions: dict = {}
    warnings: list = []

    if _task_enabled("housekeeping_task_sessions"):
        actions["expired_admin_sessions_removed"] = storage.purge_expired_admin_sessions()
        actions["expired_user_sessions_removed"] = storage.purge_expired_user_sessions()

    if _task_enabled("housekeeping_task_bruteforce"):
        actions["bruteforce_guard_entries_pruned"] = bruteforce_guard.purge_expired()

    if _task_enabled("housekeeping_task_honeypot"):
        actions["honeypot_events_pruned"] = honeypot_module.honeypot.prune_older_than(
            settings.honeypot_retention_seconds
        )
        actions["honeypot_challenges_expired"] = honeypot_module.honeypot.expire_challenges()

    if _task_enabled("housekeeping_task_orphaned_media"):
        orphans = media.find_orphaned_files()
        removed_bytes = 0
        for path in orphans:
            try:
                removed_bytes += path.stat().st_size
                path.unlink()
            except OSError as exc:  # arquivo removido/alterado concorrentemente - nao fatal
                logger.warning("housekeeping: falha ao remover arquivo orfao %s: %s", path, exc)
        actions["orphaned_files_removed"] = len(orphans)
        actions["orphaned_bytes_freed"] = removed_bytes

    if _task_enabled("housekeeping_task_price_history"):
        price_cutoff = time.time() - (settings.price_history_retention_days * 86400)
        actions["price_history_rows_pruned"] = storage.prune_price_history(price_cutoff)

    if _task_enabled("housekeeping_task_integrity_check"):
        integrity_result = storage.integrity_check_database()
        actions["integrity_check_result"] = integrity_result
        if integrity_result != "ok":
            warnings.append(f"PRAGMA integrity_check retornou '{integrity_result}' - possivel corrupcao do banco!")
            try:
                from . import monitoring as _monitoring
                _monitoring.send_alert(
                    event_type="db_integrity_check_failed",
                    severity="critical",
                    message=f"PRAGMA integrity_check do SQLite retornou resultado anormal: '{integrity_result}'",
                    details={"integrity_check_result": integrity_result, "triggered_by": triggered_by},
                )
            except Exception:
                pass

    if _task_enabled("housekeeping_task_backup"):
        try:
            backup_info = create_backup()
            actions["backup_created"] = backup_info
        except Exception as exc:
            logger.exception("housekeeping: falha ao criar backup")
            warnings.append(f"Falha ao criar backup: {exc}")
            actions["backup_created"] = None

    if _task_enabled("housekeeping_task_vacuum"):
        storage.vacuum_database()
        actions["database_vacuumed"] = True

    finished_at = time.time()
    stats = {
        "media_storage": media.storage_stats(),
        "disk_usage": disk_usage_report(),
        "duration_seconds": round(finished_at - started_at, 4),
        "warnings": warnings,
    }

    storage.record_housekeeping_run(
        started_at, finished_at, json.dumps(actions), json.dumps(stats), triggered_by
    )
    logger.info("housekeeping executado (%s): %s", triggered_by, actions)
    return {"started_at": started_at, "finished_at": finished_at, "actions": actions, "stats": stats}


def status() -> dict:
    """Snapshot do agendador + ultima execucao registrada + uso de disco."""
    runs = storage.list_housekeeping_runs(limit=1)
    return {
        "scheduler_running": _scheduler_thread is not None and _scheduler_thread.is_alive(),
        "interval_seconds": settings.housekeeping_interval_seconds,
        "last_run": runs[0] if runs else None,
        "disk_usage": disk_usage_report(),
    }


def history(limit: int = 20) -> list:
    return storage.list_housekeeping_runs(limit=limit)


def _scheduler_loop(interval_seconds: float) -> None:
    # roda a primeira execucao logo apos um pequeno atraso inicial (deixa o
    # resto do startup do servidor terminar antes de competir por I/O de disco)
    _stop_event.wait(min(30.0, interval_seconds))
    while not _stop_event.is_set():
        try:
            run_housekeeping(triggered_by="scheduler")
        except Exception:
            logger.exception("housekeeping: execucao agendada falhou")
        _stop_event.wait(interval_seconds)


def start_scheduler(interval_seconds: Optional[float] = None) -> None:
    """Inicia a thread de agendamento em background (idempotente - chamar
    mais de uma vez nao cria threads duplicadas)."""
    global _scheduler_thread
    if _scheduler_thread is not None and _scheduler_thread.is_alive():
        return
    _stop_event.clear()
    interval = interval_seconds if interval_seconds is not None else settings.housekeeping_interval_seconds
    _scheduler_thread = threading.Thread(
        target=_scheduler_loop, args=(interval,), name="pixcripto-housekeeping", daemon=True
    )
    _scheduler_thread.start()


def stop_scheduler() -> None:
    _stop_event.set()
    if _scheduler_thread is not None:
        _scheduler_thread.join(timeout=2.0)
