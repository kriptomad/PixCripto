"""
Verificacao de integridade do codigo-fonte em runtime (`app/source_integrity.py`).

Defesa contra "source-code hacking" (adulteracao do binario/arquivos-fonte
apos o deploy, seja por um invasor com acesso ao disco, seja por um pacote de
distribuicao corrompido): calcula um hash SHA-256 de CADA arquivo `.py` sob
`app/`, combina todos em uma raiz Merkle-like (hash dos hashes, ordenado por
caminho para ser deterministico) e compara contra uma baseline assinada,
gravada em `data/source_integrity_baseline.json` na PRIMEIRA vez que o node
roda.

Em toda inicializacao subsequente, se qualquer arquivo `.py` sob `app/` for
diferente do que estava no baseline (adicionado, removido ou modificado), o
node registra um alerta de alta severidade e o expoe via
`GET /security/integrity-status` (protegido pelo mesmo token de administracao
de conteudo) - permitindo que o operador detecte imediatamente uma alteracao
nao autorizada do codigo em producao, algo que um ataque de "source-code
hacking" silencioso dependeria de passar despercebido.

Isto NAO substitui assinatura de pacote/verificacao de integridade do SO
(ex: dm-verity, code signing) - e uma camada adicional de defesa em
profundidade, adequada para detectar adulteracao de arquivos individuais em
uma instalacao onde o operador nao tem controle total da infraestrutura de
hospedagem.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Dict, Optional

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR.parent / "data"
BASELINE_PATH = DATA_DIR / "source_integrity_baseline.json"

# arquivos que sabidamente mudam em runtime (nunca fazem parte da logica de
# consenso/seguranca) - excluidos do hash para evitar falsos positivos
_EXCLUDED_SUFFIXES = {".pyc"}
_EXCLUDED_DIR_NAMES = {"__pycache__"}


def _iter_source_files() -> list[Path]:
    files = []
    for path in APP_DIR.rglob("*.py"):
        if any(part in _EXCLUDED_DIR_NAMES for part in path.parts):
            continue
        if path.suffix in _EXCLUDED_SUFFIXES:
            continue
        files.append(path)
    return sorted(files, key=lambda p: str(p.relative_to(APP_DIR)).replace("\\", "/"))


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compute_snapshot() -> Dict[str, str]:
    """Retorna `{caminho_relativo: sha256_hex}` para todo `app/**/*.py` atual."""
    snapshot = {}
    for path in _iter_source_files():
        rel = str(path.relative_to(APP_DIR)).replace("\\", "/")
        snapshot[rel] = _hash_file(path)
    return snapshot


def compute_merkle_root(snapshot: Dict[str, str]) -> str:
    """Combina todos os hashes de arquivo (ja ordenados por caminho) em uma
    unica raiz - qualquer mudanca em qualquer arquivo muda esta raiz."""
    hasher = hashlib.sha256()
    for rel_path in sorted(snapshot.keys()):
        hasher.update(rel_path.encode("utf-8"))
        hasher.update(b":")
        hasher.update(snapshot[rel_path].encode("utf-8"))
        hasher.update(b"\n")
    return hasher.hexdigest()


def load_baseline() -> Optional[dict]:
    if not BASELINE_PATH.exists():
        return None
    try:
        return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def save_baseline(snapshot: Dict[str, str]) -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    baseline = {
        "merkle_root": compute_merkle_root(snapshot),
        "file_hashes": snapshot,
        "recorded_at": time.time(),
        "file_count": len(snapshot),
    }
    BASELINE_PATH.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")
    return baseline


def check_integrity() -> dict:
    """
    Compara o estado ATUAL do codigo-fonte contra a baseline gravada.

    Se nao existir baseline ainda (primeira execucao do node nesta maquina),
    GRAVA uma nova baseline automaticamente e reporta `status="baseline_created"`
    (nao ha nada para comparar ainda - isso e esperado e normal na primeira vez).
    """
    current = compute_snapshot()
    current_root = compute_merkle_root(current)
    baseline = load_baseline()

    if baseline is None:
        baseline = save_baseline(current)
        return {
            "status": "baseline_created",
            "merkle_root": current_root,
            "file_count": len(current),
            "changed_files": [],
            "added_files": [],
            "removed_files": [],
            "recorded_at": baseline["recorded_at"],
        }

    baseline_hashes = baseline.get("file_hashes", {})
    changed = [p for p in current if p in baseline_hashes and current[p] != baseline_hashes[p]]
    added = [p for p in current if p not in baseline_hashes]
    removed = [p for p in baseline_hashes if p not in current]

    tampered = bool(changed or added or removed)
    if tampered:
        try:
            from . import monitoring as _monitoring
            _monitoring.send_alert(
                event_type="source_integrity_tampered",
                severity="critical",
                message="Adulteracao de codigo-fonte detectada - baseline diverge do estado atual!",
                details={
                    "changed_files": sorted(changed),
                    "added_files": sorted(added),
                    "removed_files": sorted(removed),
                    "baseline_merkle_root": baseline.get("merkle_root"),
                    "current_merkle_root": current_root,
                },
            )
        except Exception:
            pass
    return {
        "status": "tampering_detected" if tampered else "ok",
        "merkle_root": current_root,
        "baseline_merkle_root": baseline.get("merkle_root"),
        "file_count": len(current),
        "changed_files": sorted(changed),
        "added_files": sorted(added),
        "removed_files": sorted(removed),
        "recorded_at": baseline.get("recorded_at"),
    }


def reset_baseline() -> dict:
    """Aceita o estado ATUAL do codigo como novo baseline confiavel (uso
    deliberado do operador apos um deploy/atualizacao legitima)."""
    return save_baseline(compute_snapshot())
