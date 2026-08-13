#!/usr/bin/env python3
"""
Script de restore do PixCripto — `scripts/restore_backup.py`

Restaura um backup .zip gerado por `app/housekeeping.create_backup()` para um
diretorio de destino, validando a integridade do banco SQLite restaurado antes
de sobrescrever qualquer arquivo em producao.

USO:
    python scripts/restore_backup.py <caminho-do-backup.zip> <diretorio-destino>
                                     [--dry-run] [--force]

ARGUMENTOS:
    backup_zip      Caminho do arquivo .zip de backup a ser restaurado
                    (gerado por create_backup(); nome tipico: backup-YYYYMMDD-HHMMSS.zip)
    dest_dir        Diretorio de destino onde os arquivos serao extraidos.
                    O banco restaurado ficara em <dest_dir>/pixcripto_chain.db e
                    os uploads em <dest_dir>/uploads/.
                    ATENCAO: o servidor PRECISA estar parado antes de apontar
                    o destino para o diretorio de dados em producao — SQLite
                    nao suporta multiplos escritores e o restore sobrescreve
                    o banco sem aviso se --force for passado.

FLAGS:
    --dry-run       Extrai e valida o backup sem sobrescrever nada no destino.
                    Util para verificar integridade de um backup antes de uma
                    janela de manutencao real.
    --force         Sobrescreve arquivos existentes no destino sem perguntar.
                    Sem esta flag, o script aborta se o banco ja existir no
                    destino (protecao contra restore acidental em producao).

SAIDAS:
    0 — restore concluido com sucesso (ou dry-run validado sem erros)
    1 — erro: arquivo de backup invalido, integridade falhou, ou destino
        ocupado sem --force

RUNBOOK DE DESASTRE REAL (resumo — veja o README para versao completa):
    1. Pare o servico:  systemctl stop pixcripto  (ou equivalente)
    2. Identifique o backup mais recente em data/backups/
    3. python scripts/restore_backup.py data/backups/backup-YYYYMMDD-HHMMSS.zip \\
           data/ --force
    4. Reinicie:  systemctl start pixcripto
    5. Verifique: curl http://localhost:8000/chain  (deve retornar a chain)
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
import tempfile
import zipfile
from pathlib import Path


def _integrity_check(db_path: Path) -> tuple[bool, str]:
    """Executa `PRAGMA integrity_check` no banco apontado. Retorna
    (ok: bool, mensagem: str). Um banco valido retorna 'ok'; qualquer
    outra saida indica corrupcao e o restore deve ser abortado."""
    conn = sqlite3.connect(str(db_path))
    try:
        cursor = conn.execute("PRAGMA integrity_check")
        rows = cursor.fetchall()
        result = rows[0][0] if rows else "sem resposta"
        ok = result == "ok"
        return ok, result
    finally:
        conn.close()


def _report_chain_stats(db_path: Path) -> dict:
    """Le metadados basicos da chain restaurada para o relatorio final.
    Retorna um dict com altura da chain, numero de blocos e de transacoes."""
    stats: dict = {
        "chain_height": "N/D",
        "block_count": "N/D",
        "tx_count": "N/D",
        "tables": [],
    }
    conn = sqlite3.connect(str(db_path))
    try:
        # lista tabelas existentes
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()]
        stats["tables"] = tables

        if "blocks" in tables:
            row = conn.execute("SELECT COUNT(*), MAX(idx) FROM blocks").fetchone()
            if row:
                stats["block_count"] = row[0]
                stats["chain_height"] = row[1] if row[1] is not None else 0

        if "transactions" in tables:
            row = conn.execute("SELECT COUNT(*) FROM transactions").fetchone()
            if row:
                stats["tx_count"] = row[0]
    except sqlite3.OperationalError:
        pass  # banco pode ter esquema diferente — relatorio parcial nao e fatal
    finally:
        conn.close()
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="restore_backup.py",
        description="Restaura um backup .zip do PixCripto para o diretorio de destino.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "backup_zip",
        help="Caminho do arquivo .zip de backup a ser restaurado.",
    )
    parser.add_argument(
        "dest_dir",
        help="Diretorio de destino. O servidor PRECISA estar parado.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Valida o backup sem sobrescrever nada no destino.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Sobrescreve arquivos existentes sem confirmacao.",
    )
    args = parser.parse_args()

    backup_path = Path(args.backup_zip)
    dest_dir = Path(args.dest_dir)

    # --- Validacao de entrada ---
    if not backup_path.exists():
        print(f"ERRO: arquivo de backup nao encontrado: {backup_path}", file=sys.stderr)
        return 1
    if not zipfile.is_zipfile(backup_path):
        print(f"ERRO: o arquivo nao e um zip valido: {backup_path}", file=sys.stderr)
        return 1

    print("=" * 60)
    print("  RESTORE DO PIXCRIPTO")
    print("=" * 60)
    print(f"  Backup:   {backup_path.resolve()}")
    print(f"  Destino:  {dest_dir.resolve()}")
    print(f"  Modo:     {'DRY-RUN (sem sobrescrever)' if args.dry_run else 'RESTORE REAL'}")
    print("=" * 60)

    # --- Extrai para diretorio temporario para validar antes de tocar o destino ---
    with tempfile.TemporaryDirectory(prefix="pixcripto_restore_") as tmp_str:
        tmp_dir = Path(tmp_str)
        print("\n[1/4] Extraindo backup para diretorio temporario...")
        try:
            with zipfile.ZipFile(backup_path, "r") as zf:
                zf.extractall(tmp_dir)
        except zipfile.BadZipFile as exc:
            print(f"ERRO: nao foi possivel extrair o zip: {exc}", file=sys.stderr)
            return 1

        extracted_files = list(tmp_dir.rglob("*"))
        db_in_tmp = tmp_dir / "pixcripto_chain.db"
        uploads_in_tmp = tmp_dir / "uploads"

        print(f"      {len([f for f in extracted_files if f.is_file()])} arquivo(s) extraido(s)")
        if db_in_tmp.exists():
            print(f"      Banco de dados: {db_in_tmp.name} ({db_in_tmp.stat().st_size:,} bytes)")
        else:
            print("ERRO: banco de dados 'pixcripto_chain.db' nao encontrado no backup.", file=sys.stderr)
            return 1

        # --- Valida integridade do SQLite ---
        print("\n[2/4] Validando integridade do banco restaurado (PRAGMA integrity_check)...")
        ok, check_result = _integrity_check(db_in_tmp)
        if ok:
            print("      Resultado: OK — banco integro.")
        else:
            print(f"ERRO: integrity_check retornou '{check_result}' — banco corrompido.", file=sys.stderr)
            print("      Nao e seguro restaurar este backup. Tente um backup mais antigo.", file=sys.stderr)
            return 1

        # --- Le metadados da chain para relatorio ---
        print("\n[3/4] Lendo metadados da chain...")
        stats = _report_chain_stats(db_in_tmp)
        print(f"      Altura da chain (MAX index): {stats['chain_height']}")
        print(f"      Total de blocos:              {stats['block_count']}")
        print(f"      Total de transacoes:          {stats['tx_count']}")
        print(f"      Tabelas encontradas:          {', '.join(stats['tables']) or '(nenhuma)'}")

        n_uploads = len([f for f in uploads_in_tmp.rglob("*") if f.is_file()]) if uploads_in_tmp.exists() else 0
        print(f"      Uploads no backup:            {n_uploads} arquivo(s)")

        if args.dry_run:
            print("\n[4/4] Modo --dry-run: nenhum arquivo foi modificado no destino.")
            print("\n[OK] Validacao concluida com SUCESSO. Backup integro e pronto para restore.")
            print("  Para restaurar de verdade, execute sem --dry-run.")
            return 0

        # --- Verifica se destino esta livre (sem --force) ---
        print("\n[4/4] Copiando arquivos para o destino...")
        dest_db_path = dest_dir / "pixcripto_chain.db"
        if dest_db_path.exists() and not args.force:
            print(
                f"ERRO: '{dest_db_path}' ja existe no destino.\n"
                "  Use --force para sobrescrever (certifique-se de que o servidor esta PARADO).",
                file=sys.stderr,
            )
            return 1

        dest_dir.mkdir(parents=True, exist_ok=True)

        # Copia o banco (operacao critica — destino deve estar parado)
        import shutil
        shutil.copy2(db_in_tmp, dest_db_path)
        print(f"      Banco copiado para: {dest_db_path}")

        # Copia os uploads se existirem no backup
        if uploads_in_tmp.exists():
            dest_uploads = dest_dir / "uploads"
            dest_uploads.mkdir(parents=True, exist_ok=True)
            n_copied = 0
            for src_file in uploads_in_tmp.rglob("*"):
                if src_file.is_file():
                    rel = src_file.relative_to(uploads_in_tmp)
                    dst_file = dest_uploads / rel
                    dst_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_file, dst_file)
                    n_copied += 1
            print(f"      {n_copied} upload(s) copiado(s) para: {dest_uploads}")

    print("\n" + "=" * 60)
    print("[OK] RESTORE CONCLUIDO COM SUCESSO")
    print("=" * 60)
    print(f"  Chain restaurada com {stats['block_count']} bloco(s) "
          f"(altura {stats['chain_height']}).")
    print(f"  Banco em: {dest_db_path.resolve()}")
    print("\nPROXIMOS PASSOS:")
    print("  1. Verifique os logs para qualquer aviso inesperado.")
    print("  2. Reinicie o servico PixCripto.")
    print("  3. Valide: curl http://localhost:8000/chain/metadata")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
