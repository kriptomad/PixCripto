"""
Camada de persistencia em SQLite.

Simula o uso de "setores" de disco (SSD/HD) para armazenar:
- metadata de cada bloco minerado (hash, nonce, dificuldade, timestamp, minerador)
- as transacoes de cada bloco
- os ajustes de dificuldade calculados a cada N blocos (reajuste matematico)
- as carteiras registradas no no local

Isso permite que o estado da blockchain sobreviva a reinicializacoes do processo,
assim como acontece em nos reais de Bitcoin/Ethereum (LevelDB/RocksDB), aqui
substituido por um banco relacional simples para fins didaticos.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import List, Optional

from .models import Block, Blockchain, Transaction

# Permite sobrepor o caminho do banco via variavel de ambiente
# (PIXCRIPTO_DB_PATH) - essencial para rodar multiplos nos locais no mesmo
# checkout de codigo (cada no precisa do seu proprio estado/SQLite isolado),
# como usado nos testes de rede multi-no (`tests/test_network.py`).
DB_PATH = Path(os.environ.get("PIXCRIPTO_DB_PATH") or (Path(__file__).resolve().parent.parent / "data" / "pixcripto_chain.db"))


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")  # melhor para gravacao concorrente em disco
    return conn


def init_db() -> None:
    conn = _connect()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS blocks (
            idx INTEGER PRIMARY KEY,
            previous_hash TEXT NOT NULL,
            hash TEXT NOT NULL,
            nonce INTEGER NOT NULL,
            difficulty INTEGER NOT NULL,
            miner_address TEXT,
            timestamp REAL NOT NULL,
            block_value REAL NOT NULL,
            reward REAL NOT NULL DEFAULT 0,
            state_root TEXT,
            contracts_root TEXT
        );

        CREATE TABLE IF NOT EXISTS transactions (
            tx_id TEXT PRIMARY KEY,
            block_index INTEGER NOT NULL,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            amount REAL NOT NULL,
            tx_type TEXT NOT NULL,
            memo TEXT,
            timestamp REAL NOT NULL,
            signature TEXT,
            public_key TEXT,
            network_id INTEGER NOT NULL DEFAULT 7777,
            fee REAL NOT NULL DEFAULT 0,
            data TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(block_index) REFERENCES blocks(idx)
        );

        -- Mempool persistida: sem isto, transacoes assinadas e aceitas mas ainda
        -- nao mineradas eram perdidas a cada restart do processo, obrigando o
        -- usuario a reenviar manualmente uma tx que ja havia sido validada e
        -- aceita pela rede (gap identificado contra o guia "blockchain-do-zero.md",
        -- secao 8.1 "mempool" - toda tx aceita deve sobreviver ate ser minerada).
        CREATE TABLE IF NOT EXISTS pending_transactions (
            tx_id TEXT PRIMARY KEY,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            amount REAL NOT NULL,
            tx_type TEXT NOT NULL,
            memo TEXT,
            timestamp REAL NOT NULL,
            signature TEXT,
            public_key TEXT,
            network_id INTEGER NOT NULL DEFAULT 7777,
            fee REAL NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS wallets (
            address TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            created_at REAL NOT NULL,
            label TEXT
        );

        CREATE TABLE IF NOT EXISTS difficulty_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_index INTEGER NOT NULL,
            old_difficulty INTEGER NOT NULL,
            new_difficulty INTEGER NOT NULL,
            avg_seconds_per_block REAL NOT NULL,
            created_at REAL NOT NULL
        );

        -- Estado da L2 (rollup): persistido para que o anti-replay de depositos e
        -- os saldos sobrevivam a reinicializacoes do processo (correcao de auditoria
        -- critica: antes, `_processed_deposits`/`balances` viviam so em RAM, permitindo
        -- reprocessar o MESMO deposito apos um restart e drenar a bridge L1).
        CREATE TABLE IF NOT EXISTS l2_processed_deposits (
            l1_tx_id TEXT PRIMARY KEY,
            address TEXT NOT NULL,
            amount REAL NOT NULL,
            processed_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS l2_balances (
            address TEXT PRIMARY KEY,
            balance REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS purchase_confirmations (
            payment_reference TEXT PRIMARY KEY,
            quote_id TEXT NOT NULL,
            recipient_address TEXT NOT NULL,
            coins_credited REAL NOT NULL,
            confirmed_at REAL NOT NULL
        );

        -- Serie historica de preco (PXC/BRL, PXC/USD, ouro/onca) - alimenta
        -- os "klines" (candles OHLC) da API estilo exchange (`app/exchange_api.py`),
        -- equivalente ao historico de preco que qualquer corretora precisa
        -- para desenhar graficos. Uma linha por atualizacao efetiva do
        -- oraculo de ouro (GoldOracle.refresh), nao por requisicao HTTP.
        CREATE TABLE IF NOT EXISTS price_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pxc_brl REAL NOT NULL,
            pxc_usd REAL NOT NULL,
            gold_usd_per_oz REAL NOT NULL,
            recorded_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_price_history_time ON price_history(recorded_at);

        -- Chaves de API estilo exchange (Binance-like) para autenticar
        -- endpoints de trading (`/api/v1/order`) via HMAC-SHA256, sem expor
        -- a chave privada da carteira a nenhum site/exchange parceiro.
        CREATE TABLE IF NOT EXISTS api_keys (
            api_key TEXT PRIMARY KEY,
            api_secret_hash TEXT NOT NULL,
            address TEXT NOT NULL,
            created_at REAL NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        );

        -- Feed de noticias exibido no site principal (React). Publicado pelo
        -- operador via `/news` (protegido por `X-Admin-Token`, ver `app/settings.py`).
        CREATE TABLE IF NOT EXISTS news_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            summary TEXT NOT NULL DEFAULT '',
            body TEXT NOT NULL DEFAULT '',
            image_url TEXT NOT NULL DEFAULT '',
            author TEXT NOT NULL DEFAULT 'PixCripto',
            published_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_news_published ON news_posts(published_at);

        -- Login real do Painel de Administracao do site (`/admin`, React) -
        -- usuario/senha com hash PBKDF2-HMAC-SHA256 (ver `app/admin_auth.py`),
        -- substitui o antigo modelo de "colar um token compartilhado" por uma
        -- conta de operador de verdade, com sessao expiravel.
        CREATE TABLE IF NOT EXISTS admin_users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            created_at REAL NOT NULL,
            last_login_at REAL,
            role TEXT NOT NULL DEFAULT 'owner',
            totp_secret TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT 'bootstrap'
        );

        -- Codigos de backup de uso unico do 2FA (RFC 6238) - permitem
        -- recuperar acesso caso o operador perca o dispositivo autenticador.
        CREATE TABLE IF NOT EXISTS admin_backup_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL,
            used_at REAL
        );
        CREATE INDEX IF NOT EXISTS idx_backup_codes_username ON admin_backup_codes(username);

        CREATE TABLE IF NOT EXISTS admin_sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            last_seen_at REAL NOT NULL,
            ip TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at);

        -- Biblioteca de midia centralizada: TODO upload feito pelo site
        -- (capa de noticia, KYC, etc.) e registrado aqui, permitindo ao painel
        -- de administracao listar, auditar uso de armazenamento e remover
        -- arquivos orfaos (housekeeping) - antes cada modulo geria seus proprios
        -- arquivos sem nenhum inventario central.
        CREATE TABLE IF NOT EXISTS media_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            url TEXT NOT NULL,
            purpose TEXT NOT NULL DEFAULT 'generic',
            size_bytes INTEGER NOT NULL DEFAULT 0,
            mime_type TEXT NOT NULL DEFAULT '',
            uploaded_by TEXT NOT NULL DEFAULT 'unknown',
            uploaded_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_media_url ON media_files(url);

        -- CMS de paginas estaticas do site (Sobre, Termos de uso, Politica de
        -- privacidade, FAQ etc.) - editaveis pelo operador sem precisar tocar
        -- em codigo/deploy, complementando o feed de noticias (`news_posts`,
        -- que e cronologico) com conteudo institucional fixo por slug.
        CREATE TABLE IF NOT EXISTS cms_pages (
            slug TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            body TEXT NOT NULL DEFAULT '',
            published INTEGER NOT NULL DEFAULT 1,
            updated_by TEXT NOT NULL DEFAULT 'PixCripto',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            menu_order INTEGER NOT NULL DEFAULT 0,
            show_in_menu INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 1
        );

        -- Historico de revisoes do CMS de paginas - cada UPDATE guarda a
        -- versao ANTERIOR aqui antes de sobrescrever, permitindo ao operador
        -- consultar o historico e reverter uma edicao indevida (rollback).
        CREATE TABLE IF NOT EXISTS cms_page_revisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL,
            version INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            published INTEGER NOT NULL,
            saved_by TEXT NOT NULL,
            saved_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_cms_revisions_slug ON cms_page_revisions(slug);

        -- Chaves de funcionalidade (feature flags) do site - liga/desliga
        -- modulos inteiros em runtime (modo manutencao, compras, trading,
        -- mineracao) sem precisar de novo deploy, controlado pelo painel.
        CREATE TABLE IF NOT EXISTS feature_flags (
            key TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 1,
            updated_at REAL NOT NULL
        );

        -- Historico de execucoes do housekeeping automatico (limpeza de
        -- sessoes expiradas, arquivos orfaos, poda de historico antigo,
        -- VACUUM do SQLite) - permite auditar quando/o-que foi limpo.
        CREATE TABLE IF NOT EXISTS housekeeping_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at REAL NOT NULL,
            finished_at REAL NOT NULL,
            duration_seconds REAL NOT NULL,
            actions_json TEXT NOT NULL DEFAULT '{}',
            stats_json TEXT NOT NULL DEFAULT '{}',
            triggered_by TEXT NOT NULL DEFAULT 'scheduler'
        );

        -- Configuracao geral do site (nome, contato, SEO, links sociais,
        -- mensagem de manutencao customizada) - editavel pelo painel sem
        -- precisar de deploy, chave-valor generico (valor sempre JSON).
        CREATE TABLE IF NOT EXISTS site_settings (
            key TEXT PRIMARY KEY,
            value_json TEXT NOT NULL,
            updated_at REAL NOT NULL,
            updated_by TEXT NOT NULL DEFAULT 'PixCripto'
        );

        -- Contas de USUARIO final (correntista da rede - diferente de
        -- `admin_users`, que sao operadores do painel). Senha com o mesmo
        -- padrao de KDF (PBKDF2-HMAC-SHA256) usado no restante do projeto.
        -- CPF e sempre armazenado apenas como hash (nunca em claro) para
        -- permitir checar duplicidade sem reter o dado sensivel em si.
        CREATE TABLE IF NOT EXISTS user_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            cpf_hash TEXT,
            kyc_status TEXT NOT NULL DEFAULT 'none',   -- none | pending | approved | rejected
            kyc_tier INTEGER NOT NULL DEFAULT 0,
            totp_secret TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL,
            last_login_at REAL,
            is_active INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_user_accounts_cpf ON user_accounts(cpf_hash);

        CREATE TABLE IF NOT EXISTS user_sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            last_seen_at REAL NOT NULL,
            ip TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id);

        -- Carteiras vinculadas a conta do usuario (uma conta pode ter varias
        -- carteiras - a chave privada NUNCA e enviada/armazenada aqui, apenas
        -- o endereco publico, para permitir consulta de saldo/historico
        -- dentro da area logada "Minha conta" sem custodiar fundos).
        CREATE TABLE IF NOT EXISTS user_wallets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            address TEXT NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            linked_at REAL NOT NULL,
            UNIQUE(user_id, address)
        );
        CREATE INDEX IF NOT EXISTS idx_user_wallets_user ON user_wallets(user_id);

        -- Submissoes de verificacao de identidade (KYC) com documento com
        -- foto real. CPF/RG e as 3 imagens (frente/verso do documento +
        -- selfie de prova de vida) sao armazenados SOMENTE cifrados
        -- (AES-256-GCM, chave mestra do servidor - ver `app/user_accounts.py`);
        -- nunca em texto claro no banco, e o binario da imagem fica em disco
        -- (`data/kyc_documents/`), tambem cifrado, referenciado por nome de
        -- arquivo aleatorio (nao correlacionavel ao usuario s6em consultar o
        -- banco). Fluxo de aprovacao manual por um operador (owner/editor)
        -- do painel, nunca automatico.
        CREATE TABLE IF NOT EXISTS kyc_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            full_name_enc TEXT NOT NULL,
            cpf_enc TEXT NOT NULL,
            rg_enc TEXT NOT NULL,
            birth_date_enc TEXT NOT NULL,
            document_front_file TEXT NOT NULL,
            document_back_file TEXT NOT NULL,
            selfie_file TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | rejected
            submitted_at REAL NOT NULL,
            reviewed_by TEXT,
            reviewed_at REAL,
            rejection_reason TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_kyc_submissions_user ON kyc_submissions(user_id);
        CREATE INDEX IF NOT EXISTS idx_kyc_submissions_status ON kyc_submissions(status);

        -- Carteiras multi-assinatura M-de-N (multisig).
        -- Cada carteira e definida por N chaves publicas participantes e um
        -- threshold M (minimo de assinaturas para autorizar um gasto).
        -- O endereco e derivado deterministicamente de M + chaves ordenadas
        -- via ripemd160(sha256("multisig:M:chave1:chave2:...")) com Base58Check,
        -- igual ao conceito P2SH do Bitcoin mas em formato nativo PixCripto.
        CREATE TABLE IF NOT EXISTS multisig_wallets (
            address TEXT PRIMARY KEY,
            threshold INTEGER NOT NULL,
            participant_pubkeys_json TEXT NOT NULL,  -- JSON list[str] de N chaves publicas
            created_at REAL NOT NULL
        );

        -- Propostas de transacao multisig (PSBT-like simplificado).
        -- Uma proposta e criada pelo iniciador com os dados economicos da tx
        -- (remetente multisig, destinatario, valor) e fica em estado "pending"
        -- enquanto os participantes assinam. Quando >= M assinaturas validas
        -- estiverem coletadas, a proposta pode ser "finalizada": a Transaction
        -- e montada com os campos multisig e submetida a blockchain normalmente.
        CREATE TABLE IF NOT EXISTS multisig_proposals (
            proposal_id TEXT PRIMARY KEY,
            multisig_address TEXT NOT NULL,
            recipient TEXT NOT NULL,
            amount REAL NOT NULL,
            fee REAL NOT NULL DEFAULT 0.0,
            memo TEXT NOT NULL DEFAULT '',
            network_id INTEGER NOT NULL DEFAULT 7777,
            tx_id TEXT NOT NULL,
            timestamp_val REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',  -- pending | finalized | expired
            signatures_json TEXT NOT NULL DEFAULT '[]',  -- JSON list de {"public_key", "signature"}
            created_at REAL NOT NULL,
            FOREIGN KEY(multisig_address) REFERENCES multisig_wallets(address)
        );
        CREATE INDEX IF NOT EXISTS idx_multisig_proposals_address
            ON multisig_proposals(multisig_address);

        -- Log de alertas de monitoramento: persiste cada alerta disparado pelo
        -- sistema (honeypot, brute-force, reorg, integridade de codigo/banco)
        -- para auditoria e debug sem depender de um webhook externo configurado.
        CREATE TABLE IF NOT EXISTS alert_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            details_json TEXT NOT NULL DEFAULT '{}',
            sent_at REAL NOT NULL,
            webhook_delivered INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_alert_log_sent ON alert_log(sent_at);

        -- Logs emitidos por contratos durante a execucao (opcodes LOG0-LOG4).
        -- Persiste o historico de eventos para consulta via GET /contracts/{addr}/logs.
        -- Equivalente ao eth_getLogs do Ethereum.
        -- Campos: contrato que emitiu, topicos (lista JSON), dados hex, indice do bloco, tx_id, posicao no bloco.
        CREATE TABLE IF NOT EXISTS contract_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contract_address TEXT NOT NULL,
            topics_json TEXT NOT NULL DEFAULT '[]',
            data_hex TEXT NOT NULL DEFAULT '',
            block_index INTEGER NOT NULL,
            tx_id TEXT NOT NULL,
            log_index INTEGER NOT NULL DEFAULT 0,
            UNIQUE(block_index, tx_id, log_index)
        );
        CREATE INDEX IF NOT EXISTS idx_contract_logs_address ON contract_logs(contract_address);
        CREATE INDEX IF NOT EXISTS idx_contract_logs_block ON contract_logs(block_index);
        """
    )
    # migracao leve para bancos criados antes das colunas `state_root`/`contracts_root`/`data`
    # existirem (SQLite nao suporta "ADD COLUMN IF NOT EXISTS" - checamos manualmente)
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(blocks)").fetchall()}
    if "state_root" not in existing_cols:
        conn.execute("ALTER TABLE blocks ADD COLUMN state_root TEXT")
    if "contracts_root" not in existing_cols:
        conn.execute("ALTER TABLE blocks ADD COLUMN contracts_root TEXT")
    existing_tx_cols = {row[1] for row in conn.execute("PRAGMA table_info(transactions)").fetchall()}
    if "data" not in existing_tx_cols:
        conn.execute("ALTER TABLE transactions ADD COLUMN data TEXT NOT NULL DEFAULT ''")
    existing_pending_cols = {row[1] for row in conn.execute("PRAGMA table_info(pending_transactions)").fetchall()}
    if "data" not in existing_pending_cols:
        conn.execute("ALTER TABLE pending_transactions ADD COLUMN data TEXT NOT NULL DEFAULT ''")

    # migracao leve: colunas de suporte a transacoes multisig (adicionadas com o
    # modulo app/multisig.py - compativel com bancos criados antes desta versao)
    existing_tx_cols2 = {row[1] for row in conn.execute("PRAGMA table_info(transactions)").fetchall()}
    for col, ddl in (
        ("multisig_participants", "ALTER TABLE transactions ADD COLUMN multisig_participants TEXT"),
        ("multisig_threshold",    "ALTER TABLE transactions ADD COLUMN multisig_threshold INTEGER"),
        ("multisig_signatures",   "ALTER TABLE transactions ADD COLUMN multisig_signatures TEXT"),
    ):
        if col not in existing_tx_cols2:
            conn.execute(ddl)

    existing_pending_cols2 = {row[1] for row in conn.execute("PRAGMA table_info(pending_transactions)").fetchall()}
    for col, ddl in (
        ("multisig_participants", "ALTER TABLE pending_transactions ADD COLUMN multisig_participants TEXT"),
        ("multisig_threshold",    "ALTER TABLE pending_transactions ADD COLUMN multisig_threshold INTEGER"),
        ("multisig_signatures",   "ALTER TABLE pending_transactions ADD COLUMN multisig_signatures TEXT"),
    ):
        if col not in existing_pending_cols2:
            conn.execute(ddl)

    # migracao leve: colunas de 2FA/roles em admin_users, CMS avancado, noticias
    # com categorias/agendamento e midia com metadata - adicionadas em versao
    # posterior do painel de administracao (housekeeping/CMS/2FA "profissional").
    existing_admin_cols = {row[1] for row in conn.execute("PRAGMA table_info(admin_users)").fetchall()}
    for col, ddl in (
        ("role", "ALTER TABLE admin_users ADD COLUMN role TEXT NOT NULL DEFAULT 'owner'"),
        ("totp_secret", "ALTER TABLE admin_users ADD COLUMN totp_secret TEXT"),
        ("totp_enabled", "ALTER TABLE admin_users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0"),
        ("created_by", "ALTER TABLE admin_users ADD COLUMN created_by TEXT NOT NULL DEFAULT 'bootstrap'"),
    ):
        if col not in existing_admin_cols:
            conn.execute(ddl)

    existing_cms_cols = {row[1] for row in conn.execute("PRAGMA table_info(cms_pages)").fetchall()}
    for col, ddl in (
        ("menu_order", "ALTER TABLE cms_pages ADD COLUMN menu_order INTEGER NOT NULL DEFAULT 0"),
        ("show_in_menu", "ALTER TABLE cms_pages ADD COLUMN show_in_menu INTEGER NOT NULL DEFAULT 0"),
        ("version", "ALTER TABLE cms_pages ADD COLUMN version INTEGER NOT NULL DEFAULT 1"),
    ):
        if col not in existing_cms_cols:
            conn.execute(ddl)

    existing_news_cols = {row[1] for row in conn.execute("PRAGMA table_info(news_posts)").fetchall()}
    for col, ddl in (
        ("status", "ALTER TABLE news_posts ADD COLUMN status TEXT NOT NULL DEFAULT 'published'"),
        ("category", "ALTER TABLE news_posts ADD COLUMN category TEXT NOT NULL DEFAULT 'geral'"),
        ("tags", "ALTER TABLE news_posts ADD COLUMN tags TEXT NOT NULL DEFAULT ''"),
        ("scheduled_at", "ALTER TABLE news_posts ADD COLUMN scheduled_at REAL"),
        ("views", "ALTER TABLE news_posts ADD COLUMN views INTEGER NOT NULL DEFAULT 0"),
    ):
        if col not in existing_news_cols:
            conn.execute(ddl)

    existing_media_cols = {row[1] for row in conn.execute("PRAGMA table_info(media_files)").fetchall()}
    for col, ddl in (
        ("alt_text", "ALTER TABLE media_files ADD COLUMN alt_text TEXT NOT NULL DEFAULT ''"),
        ("tags", "ALTER TABLE media_files ADD COLUMN tags TEXT NOT NULL DEFAULT ''"),
        ("folder", "ALTER TABLE media_files ADD COLUMN folder TEXT NOT NULL DEFAULT ''"),
    ):
        if col not in existing_media_cols:
            conn.execute(ddl)

    conn.commit()
    conn.close()


def persist_block(block: Block) -> None:
    conn = _connect()
    reward = sum(tx.amount for tx in block.transactions if tx.tx_type == "coinbase_mining")
    conn.execute(
        """INSERT OR REPLACE INTO blocks
           (idx, previous_hash, hash, nonce, difficulty, miner_address, timestamp, block_value, reward, state_root, contracts_root)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (block.index, block.previous_hash, block.hash, block.nonce, block.difficulty,
         block.miner_address, block.timestamp, block.block_value(), reward, block.state_root, block.contracts_root),
    )
    for tx in block.transactions:
        conn.execute(
            """INSERT OR REPLACE INTO transactions
               (tx_id, block_index, sender, recipient, amount, tx_type, memo, timestamp, signature,
                public_key, network_id, fee, data, multisig_participants, multisig_threshold, multisig_signatures)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (tx.tx_id, block.index, tx.sender, tx.recipient, tx.amount, tx.tx_type,
             tx.memo, tx.timestamp, tx.signature, tx.public_key, tx.network_id, tx.fee, tx.data,
             tx.multisig_participants, tx.multisig_threshold, tx.multisig_signatures),
        )
    conn.commit()
    conn.close()


def recent_sender_amounts(sender: str, window_seconds: float) -> List[float]:
    """Retorna os valores (em PXC) das transacoes mais recentes de `sender`
    dentro da janela de tempo informada (blocos ja minerados + mempool
    pendente) - usado pelo motor de conformidade (`app/compliance.py`) para
    detectar possivel estruturacao/smurfing (fracionamento de valor)."""
    cutoff = time.time() - window_seconds
    conn = _connect()
    mined = conn.execute(
        "SELECT amount FROM transactions WHERE sender = ? AND timestamp >= ? AND tx_type = 'transfer'",
        (sender, cutoff),
    ).fetchall()
    pending = conn.execute(
        "SELECT amount FROM pending_transactions WHERE sender = ? AND timestamp >= ? AND tx_type = 'transfer'",
        (sender, cutoff),
    ).fetchall()
    conn.close()
    return [float(r[0]) for r in mined] + [float(r[0]) for r in pending]


def persist_wallet(address: str, public_key: str, label: str = "") -> None:
    import time
    conn = _connect()
    conn.execute(
        "INSERT OR IGNORE INTO wallets (address, public_key, created_at, label) VALUES (?, ?, ?, ?)",
        (address, public_key, time.time(), label),
    )
    conn.commit()
    conn.close()


def log_difficulty_adjustment(block_index: int, old_diff: int, new_diff: int, avg_seconds: float) -> None:
    import time
    conn = _connect()
    conn.execute(
        """INSERT INTO difficulty_log (block_index, old_difficulty, new_difficulty, avg_seconds_per_block, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (block_index, old_diff, new_diff, avg_seconds, time.time()),
    )
    conn.commit()
    conn.close()


def load_chain_metadata() -> List[dict]:
    conn = _connect()
    cur = conn.execute(
        "SELECT idx, hash, difficulty, miner_address, timestamp, block_value, reward, state_root, contracts_root FROM blocks ORDER BY idx"
    )
    rows = [dict(zip([c[0] for c in cur.description], row)) for row in cur.fetchall()]
    conn.close()
    return rows


def load_full_chain() -> List[Block]:
    """
    Reconstroi a cadeia COMPLETA (blocos + transacoes) a partir do SQLite para
    reidratar `Blockchain.chain` na inicializacao do processo - sem isto, o
    estado da L1 (saldos, historico) seria perdido a cada restart mesmo com
    os blocos ja persistidos em disco (bug de inconsistencia: `/chain/metadata`
    mostraria historico antigo enquanto `/chain`/saldos reiniciariam do zero).
    """
    conn = _connect()
    block_rows = conn.execute(
        "SELECT idx, previous_hash, hash, nonce, difficulty, miner_address, timestamp, state_root, contracts_root FROM blocks ORDER BY idx"
    ).fetchall()
    blocks: List[Block] = []
    for idx, previous_hash, block_hash, nonce, difficulty, miner_address, timestamp, state_root, contracts_root in block_rows:
        tx_rows = conn.execute(
            """SELECT tx_id, sender, recipient, amount, tx_type, memo, timestamp, signature, public_key,
                      network_id, fee, data, multisig_participants, multisig_threshold, multisig_signatures
               FROM transactions WHERE block_index = ? ORDER BY rowid""",
            (idx,),
        ).fetchall()
        txs = [
            Transaction(
                sender=sender, recipient=recipient, amount=amount, memo=memo or "",
                tx_type=tx_type, tx_id=tx_id, timestamp=ts, signature=signature, public_key=public_key,
                network_id=network_id, fee=fee, data=data or "",
                multisig_participants=multisig_participants,
                multisig_threshold=multisig_threshold,
                multisig_signatures=multisig_signatures,
            )
            for tx_id, sender, recipient, amount, tx_type, memo, ts, signature, public_key,
                network_id, fee, data, multisig_participants, multisig_threshold, multisig_signatures
            in tx_rows
        ]
        blocks.append(Block(
            index=idx, previous_hash=previous_hash, transactions=txs, difficulty=difficulty,
            timestamp=timestamp, nonce=nonce, miner_address=miner_address, hash=block_hash,
            state_root=state_root, contracts_root=contracts_root,
        ))
    conn.close()
    return blocks


# -- persistencia da mempool: transacoes pendentes sobrevivem a restart -------
def persist_pending_transaction(tx: Transaction) -> None:
    conn = _connect()
    conn.execute(
        """INSERT OR REPLACE INTO pending_transactions
           (tx_id, sender, recipient, amount, tx_type, memo, timestamp, signature, public_key,
            network_id, fee, data, multisig_participants, multisig_threshold, multisig_signatures)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (tx.tx_id, tx.sender, tx.recipient, tx.amount, tx.tx_type, tx.memo, tx.timestamp,
         tx.signature, tx.public_key, tx.network_id, tx.fee, tx.data,
         tx.multisig_participants, tx.multisig_threshold, tx.multisig_signatures),
    )
    conn.commit()
    conn.close()


def remove_pending_transaction(tx_id: str) -> None:
    conn = _connect()
    conn.execute("DELETE FROM pending_transactions WHERE tx_id = ?", (tx_id,))
    conn.commit()
    conn.close()


def load_pending_transactions() -> List[Transaction]:
    """Recarrega a mempool persistida no startup do processo (ver `persist_pending_transaction`)."""
    conn = _connect()
    rows = conn.execute(
        """SELECT tx_id, sender, recipient, amount, tx_type, memo, timestamp, signature, public_key,
                  network_id, fee, data, multisig_participants, multisig_threshold, multisig_signatures
           FROM pending_transactions ORDER BY timestamp"""
    ).fetchall()
    conn.close()
    return [
        Transaction(
            sender=sender, recipient=recipient, amount=amount, memo=memo or "",
            tx_type=tx_type, tx_id=tx_id, timestamp=ts, signature=signature, public_key=public_key,
            network_id=network_id, fee=fee, data=data or "",
            multisig_participants=multisig_participants,
            multisig_threshold=multisig_threshold,
            multisig_signatures=multisig_signatures,
        )
        for tx_id, sender, recipient, amount, tx_type, memo, ts, signature, public_key,
            network_id, fee, data, multisig_participants, multisig_threshold, multisig_signatures
        in rows
    ]



# -- persistencia da L2 (rollup): deposito anti-replay + saldos --------------
def record_l2_deposit(l1_tx_id: str, address: str, amount: float) -> None:
    import time
    conn = _connect()
    conn.execute(
        "INSERT INTO l2_processed_deposits (l1_tx_id, address, amount, processed_at) VALUES (?, ?, ?, ?)",
        (l1_tx_id, address, amount, time.time()),
    )
    conn.commit()
    conn.close()


def is_l2_deposit_processed(l1_tx_id: str) -> bool:
    conn = _connect()
    cur = conn.execute("SELECT 1 FROM l2_processed_deposits WHERE l1_tx_id = ?", (l1_tx_id,))
    found = cur.fetchone() is not None
    conn.close()
    return found


def save_l2_balance(address: str, balance: float) -> None:
    conn = _connect()
    conn.execute(
        "INSERT INTO l2_balances (address, balance) VALUES (?, ?) "
        "ON CONFLICT(address) DO UPDATE SET balance = excluded.balance",
        (address, balance),
    )
    conn.commit()
    conn.close()


def load_l2_state() -> tuple[dict, set]:
    """Recarrega saldos L2 e o conjunto de depositos ja processados no startup,
    para que o estado sobreviva a reinicializacoes do processo."""
    conn = _connect()
    balances = {row[0]: row[1] for row in conn.execute("SELECT address, balance FROM l2_balances")}
    processed = {row[0] for row in conn.execute("SELECT l1_tx_id FROM l2_processed_deposits")}
    conn.close()
    return balances, processed


def record_purchase_confirmation(payment_reference: str, quote_id: str, recipient_address: str,
                                  coins_credited: float) -> None:
    import time
    conn = _connect()
    conn.execute(
        "INSERT INTO purchase_confirmations (payment_reference, quote_id, recipient_address, coins_credited, confirmed_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (payment_reference, quote_id, recipient_address, coins_credited, time.time()),
    )
    conn.commit()
    conn.close()


def is_payment_reference_used(payment_reference: str) -> bool:
    conn = _connect()
    cur = conn.execute("SELECT 1 FROM purchase_confirmations WHERE payment_reference = ?", (payment_reference,))
    found = cur.fetchone() is not None
    conn.close()
    return found


def record_price_snapshot(pxc_brl: float, pxc_usd: float, gold_usd_per_oz: float) -> None:
    """Grava um ponto da serie historica de preco - alimenta os candles
    (klines) da API estilo exchange. Chamado pelo `GoldOracle` sempre que ele
    de fato busca uma cotacao nova (nao a cada requisicao HTTP, que usa cache)."""
    conn = _connect()
    conn.execute(
        "INSERT INTO price_history (pxc_brl, pxc_usd, gold_usd_per_oz, recorded_at) VALUES (?, ?, ?, ?)",
        (pxc_brl, pxc_usd, gold_usd_per_oz, time.time()),
    )
    conn.commit()
    conn.close()


def load_price_history(since_ts: float = 0.0, limit: int = 5000) -> List[dict]:
    conn = _connect()
    rows = conn.execute(
        "SELECT pxc_brl, pxc_usd, gold_usd_per_oz, recorded_at FROM price_history "
        "WHERE recorded_at >= ? ORDER BY recorded_at ASC LIMIT ?",
        (since_ts, limit),
    ).fetchall()
    conn.close()
    return [{"pxc_brl": r[0], "pxc_usd": r[1], "gold_usd_per_oz": r[2], "recorded_at": r[3]} for r in rows]


def create_api_key(api_key: str, api_secret_hash: str, address: str) -> None:
    conn = _connect()
    conn.execute(
        "INSERT INTO api_keys (api_key, api_secret_hash, address, created_at) VALUES (?, ?, ?, ?)",
        (api_key, api_secret_hash, address, time.time()),
    )
    conn.commit()
    conn.close()


def get_api_key(api_key: str) -> Optional[dict]:
    conn = _connect()
    row = conn.execute(
        "SELECT api_key, api_secret_hash, address, revoked FROM api_keys WHERE api_key = ?", (api_key,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {"api_key": row[0], "api_secret_hash": row[1], "address": row[2], "revoked": bool(row[3])}


def revoke_api_key(api_key: str) -> None:
    conn = _connect()
    conn.execute("UPDATE api_keys SET revoked = 1 WHERE api_key = ?", (api_key,))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Feed de noticias (site principal)
# ---------------------------------------------------------------------------

def create_news_post(
    title: str, summary: str, body: str, image_url: str, author: str,
    status: str = "published", category: str = "geral", tags: str = "",
    scheduled_at: Optional[float] = None,
) -> int:
    now = time.time()
    conn = _connect()
    cursor = conn.execute(
        "INSERT INTO news_posts (title, summary, body, image_url, author, published_at, updated_at, "
        "status, category, tags, scheduled_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (title, summary, body, image_url, author, now, now, status, category, tags, scheduled_at),
    )
    conn.commit()
    post_id = cursor.lastrowid
    conn.close()
    return post_id


def update_news_post(
    post_id: int, title: str, summary: str, body: str, image_url: str,
    status: Optional[str] = None, category: Optional[str] = None,
    tags: Optional[str] = None, scheduled_at: Optional[float] = None,
) -> bool:
    conn = _connect()
    if status is not None:
        conn.execute(
            "UPDATE news_posts SET title = ?, summary = ?, body = ?, image_url = ?, updated_at = ?, "
            "status = ?, category = COALESCE(?, category), tags = COALESCE(?, tags), scheduled_at = ? WHERE id = ?",
            (title, summary, body, image_url, time.time(), status, category, tags, scheduled_at, post_id),
        )
    else:
        conn.execute(
            "UPDATE news_posts SET title = ?, summary = ?, body = ?, image_url = ?, updated_at = ? WHERE id = ?",
            (title, summary, body, image_url, time.time(), post_id),
        )
    cursor = conn.execute("SELECT changes()")
    updated = cursor.fetchone()[0] > 0
    conn.commit()
    conn.close()
    return updated


def delete_news_post(post_id: int) -> bool:
    conn = _connect()
    cursor = conn.execute("DELETE FROM news_posts WHERE id = ?", (post_id,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def increment_news_views(post_id: int) -> None:
    conn = _connect()
    conn.execute("UPDATE news_posts SET views = views + 1 WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()


_NEWS_COLS = (
    "id, title, summary, body, image_url, author, published_at, updated_at, "
    "status, category, tags, scheduled_at, views"
)


def _row_to_news(r) -> dict:
    return {
        "id": r[0], "title": r[1], "summary": r[2], "body": r[3],
        "image_url": r[4], "author": r[5], "published_at": r[6], "updated_at": r[7],
        "status": r[8], "category": r[9], "tags": r[10], "scheduled_at": r[11], "views": r[12],
    }


def get_news_post(post_id: int) -> Optional[dict]:
    conn = _connect()
    row = conn.execute(f"SELECT {_NEWS_COLS} FROM news_posts WHERE id = ?", (post_id,)).fetchone()
    conn.close()
    if not row:
        return None
    return _row_to_news(row)


def list_news_posts(limit: int = 20, offset: int = 0, only_published: bool = True) -> List[dict]:
    conn = _connect()
    now = time.time()
    if only_published:
        rows = conn.execute(
            f"SELECT {_NEWS_COLS} FROM news_posts WHERE status = 'published' "
            "AND (scheduled_at IS NULL OR scheduled_at <= ?) "
            "ORDER BY published_at DESC LIMIT ? OFFSET ?", (now, limit, offset)
        ).fetchall()
    else:
        rows = conn.execute(
            f"SELECT {_NEWS_COLS} FROM news_posts ORDER BY published_at DESC LIMIT ? OFFSET ?", (limit, offset)
        ).fetchall()
    conn.close()
    return [_row_to_news(r) for r in rows]


# ---------------------------------------------------------------------------
# Login real do painel de administracao (app/admin_auth.py)
# ---------------------------------------------------------------------------

def create_admin_user(username: str, password_hash: str, password_salt: str, role: str = "owner", created_by: str = "bootstrap") -> None:
    conn = _connect()
    conn.execute(
        "INSERT OR REPLACE INTO admin_users (username, password_hash, password_salt, created_at, last_login_at, role, created_by) "
        "VALUES (?, ?, ?, ?, NULL, ?, ?)",
        (username, password_hash, password_salt, time.time(), role, created_by),
    )
    conn.commit()
    conn.close()


def _row_to_admin_user(row) -> dict:
    return {
        "username": row[0], "password_hash": row[1], "password_salt": row[2], "created_at": row[3],
        "last_login_at": row[4], "role": row[5], "totp_secret": row[6], "totp_enabled": bool(row[7]),
        "created_by": row[8],
    }


_ADMIN_COLS = "username, password_hash, password_salt, created_at, last_login_at, role, totp_secret, totp_enabled, created_by"


def get_admin_user(username: str) -> Optional[dict]:
    conn = _connect()
    row = conn.execute(f"SELECT {_ADMIN_COLS} FROM admin_users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not row:
        return None
    return _row_to_admin_user(row)


def list_admin_users() -> List[dict]:
    conn = _connect()
    rows = conn.execute(f"SELECT {_ADMIN_COLS} FROM admin_users ORDER BY created_at").fetchall()
    conn.close()
    return [_row_to_admin_user(r) for r in rows]


def count_admin_users_by_role(role: str) -> int:
    conn = _connect()
    row = conn.execute("SELECT COUNT(*) FROM admin_users WHERE role = ?", (role,)).fetchone()
    conn.close()
    return row[0]


def delete_admin_user_row(username: str) -> bool:
    conn = _connect()
    cursor = conn.execute("DELETE FROM admin_users WHERE username = ?", (username,))
    conn.execute("DELETE FROM admin_sessions WHERE username = ?", (username,))
    conn.execute("DELETE FROM admin_backup_codes WHERE username = ?", (username,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def set_admin_password(username: str, password_hash: str, password_salt: str) -> None:
    conn = _connect()
    conn.execute(
        "UPDATE admin_users SET password_hash = ?, password_salt = ? WHERE username = ?",
        (password_hash, password_salt, username),
    )
    conn.commit()
    conn.close()


def set_admin_totp_secret(username: str, secret: Optional[str], enabled: bool) -> None:
    conn = _connect()
    conn.execute(
        "UPDATE admin_users SET totp_secret = ?, totp_enabled = ? WHERE username = ?",
        (secret, 1 if enabled else 0, username),
    )
    conn.commit()
    conn.close()


def replace_admin_backup_codes(username: str, code_hashes: List[str]) -> None:
    now = time.time()
    conn = _connect()
    conn.execute("DELETE FROM admin_backup_codes WHERE username = ?", (username,))
    conn.executemany(
        "INSERT INTO admin_backup_codes (username, code_hash, used, created_at) VALUES (?, ?, 0, ?)",
        [(username, h, now) for h in code_hashes],
    )
    conn.commit()
    conn.close()


def consume_admin_backup_code(username: str, code_hash: str) -> bool:
    conn = _connect()
    row = conn.execute(
        "SELECT id FROM admin_backup_codes WHERE username = ? AND code_hash = ? AND used = 0",
        (username, code_hash),
    ).fetchone()
    if not row:
        conn.close()
        return False
    conn.execute(
        "UPDATE admin_backup_codes SET used = 1, used_at = ? WHERE id = ?", (time.time(), row[0])
    )
    conn.commit()
    conn.close()
    return True


def persist_contract_logs(logs: list) -> None:
    """Persiste logs emitidos por contratos durante a execucao de um bloco.
    Usa INSERT OR IGNORE com chave unica (block_index, tx_id, log_index) para
    ser idempotente - chamadas repetidas para o mesmo bloco nao geram duplicatas."""
    if not logs:
        return
    conn = _connect()
    for log in logs:
        conn.execute(
            """INSERT OR IGNORE INTO contract_logs
               (contract_address, topics_json, data_hex, block_index, tx_id, log_index)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                log["address"],
                json.dumps(log.get("topics", [])),
                log.get("data", ""),
                log["block_index"],
                log["tx_id"],
                log.get("log_index", 0),
            ),
        )
    conn.commit()
    conn.close()


def get_contract_logs(
    address: str,
    topic_filter: Optional[str] = None,
    from_block: int = 0,
    to_block: Optional[int] = None,
) -> list:
    """Consulta logs emitidos por um contrato - equivalente ao eth_getLogs.

    Args:
        address: endereco do contrato
        topic_filter: filtra por topico 0 (hex string, opcional)
        from_block: indice minimo do bloco (inclusive, default 0)
        to_block: indice maximo do bloco (inclusive, None = sem limite)
    """
    conn = _connect()
    query = """
        SELECT contract_address, topics_json, data_hex, block_index, tx_id, log_index
        FROM contract_logs
        WHERE contract_address = ? AND block_index >= ?
    """
    params: list = [address, from_block]
    if to_block is not None:
        query += " AND block_index <= ?"
        params.append(to_block)
    query += " ORDER BY block_index, log_index"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    result = []
    for row in rows:
        addr, topics_json, data_hex, blk, tx_id, log_idx = row
        topics = json.loads(topics_json)
        if topic_filter is not None and (not topics or topics[0] != topic_filter):
            continue
        result.append({
            "address": addr,
            "topics": topics,
            "data": data_hex,
            "block_index": blk,
            "tx_id": tx_id,
            "log_index": log_idx,
        })
    return result


def count_unused_backup_codes(username: str) -> int:
    conn = _connect()
    row = conn.execute(
        "SELECT COUNT(*) FROM admin_backup_codes WHERE username = ? AND used = 0", (username,)
    ).fetchone()
    conn.close()
    return row[0]


def any_admin_user_exists() -> bool:
    conn = _connect()
    row = conn.execute("SELECT 1 FROM admin_users LIMIT 1").fetchone()
    conn.close()
    return row is not None


def touch_admin_user_login(username: str) -> None:
    conn = _connect()
    conn.execute("UPDATE admin_users SET last_login_at = ? WHERE username = ?", (time.time(), username))
    conn.commit()
    conn.close()


def create_admin_session(token: str, username: str, expires_at: float, ip: str) -> None:
    now = time.time()
    conn = _connect()
    conn.execute(
        "INSERT INTO admin_sessions (token, username, created_at, expires_at, last_seen_at, ip) VALUES (?, ?, ?, ?, ?, ?)",
        (token, username, now, expires_at, now, ip),
    )
    conn.commit()
    conn.close()


def get_admin_session(token: str) -> Optional[dict]:
    conn = _connect()
    row = conn.execute(
        "SELECT token, username, created_at, expires_at, last_seen_at, ip FROM admin_sessions WHERE token = ?",
        (token,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {"token": row[0], "username": row[1], "created_at": row[2], "expires_at": row[3], "last_seen_at": row[4], "ip": row[5]}


def touch_admin_session(token: str) -> None:
    conn = _connect()
    conn.execute("UPDATE admin_sessions SET last_seen_at = ? WHERE token = ?", (time.time(), token))
    conn.commit()
    conn.close()


def delete_admin_session(token: str) -> None:
    conn = _connect()
    conn.execute("DELETE FROM admin_sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()


def purge_expired_admin_sessions() -> int:
    conn = _connect()
    cursor = conn.execute("DELETE FROM admin_sessions WHERE expires_at < ?", (time.time(),))
    conn.commit()
    removed = cursor.rowcount
    conn.close()
    return removed


# ---------------------------------------------------------------------------
# Biblioteca de midia (app/media.py)
# ---------------------------------------------------------------------------

def register_media_file(
    filename: str, url: str, purpose: str, size_bytes: int, mime_type: str, uploaded_by: str,
    alt_text: str = "", tags: str = "", folder: str = "",
) -> int:
    conn = _connect()
    cursor = conn.execute(
        "INSERT INTO media_files (filename, url, purpose, size_bytes, mime_type, uploaded_by, uploaded_at, "
        "alt_text, tags, folder) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (filename, url, purpose, size_bytes, mime_type, uploaded_by, time.time(), alt_text, tags, folder),
    )
    conn.commit()
    media_id = cursor.lastrowid
    conn.close()
    return media_id


_MEDIA_COLS = "id, filename, url, purpose, size_bytes, mime_type, uploaded_by, uploaded_at, alt_text, tags, folder"


def _row_to_media(r) -> dict:
    return {"id": r[0], "filename": r[1], "url": r[2], "purpose": r[3], "size_bytes": r[4],
            "mime_type": r[5], "uploaded_by": r[6], "uploaded_at": r[7],
            "alt_text": r[8], "tags": r[9], "folder": r[10]}


def list_media_files(limit: int = 100, offset: int = 0) -> List[dict]:
    conn = _connect()
    rows = conn.execute(
        f"SELECT {_MEDIA_COLS} FROM media_files ORDER BY uploaded_at DESC LIMIT ? OFFSET ?", (limit, offset)
    ).fetchall()
    conn.close()
    return [_row_to_media(r) for r in rows]


def get_media_file(media_id: int) -> Optional[dict]:
    conn = _connect()
    row = conn.execute(f"SELECT {_MEDIA_COLS} FROM media_files WHERE id = ?", (media_id,)).fetchone()
    conn.close()
    if not row:
        return None
    return _row_to_media(row)


def update_media_metadata(media_id: int, alt_text: Optional[str] = None, tags: Optional[str] = None, folder: Optional[str] = None) -> bool:
    conn = _connect()
    conn.execute(
        "UPDATE media_files SET alt_text = COALESCE(?, alt_text), tags = COALESCE(?, tags), "
        "folder = COALESCE(?, folder) WHERE id = ?",
        (alt_text, tags, folder, media_id),
    )
    cursor = conn.execute("SELECT changes()")
    updated = cursor.fetchone()[0] > 0
    conn.commit()
    conn.close()
    return updated


def delete_media_file_row(media_id: int) -> bool:
    conn = _connect()
    cursor = conn.execute("DELETE FROM media_files WHERE id = ?", (media_id,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def media_storage_stats() -> dict:
    conn = _connect()
    row = conn.execute("SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM media_files").fetchone()
    by_purpose = conn.execute(
        "SELECT purpose, COUNT(*), COALESCE(SUM(size_bytes), 0) FROM media_files GROUP BY purpose"
    ).fetchall()
    conn.close()
    return {
        "total_files": row[0],
        "total_bytes": row[1],
        "by_purpose": [{"purpose": p, "count": c, "bytes": b} for p, c, b in by_purpose],
    }


def all_referenced_media_urls() -> set:
    """URLs de imagem ainda em uso por algum conteudo publicado (noticias) -
    usado pelo housekeeping para nao apagar um arquivo que ainda esta
    referenciado por um post existente, mesmo que so exista o registro em
    `media_files` (nunca apaga por engano conteudo em uso)."""
    conn = _connect()
    rows = conn.execute("SELECT image_url FROM news_posts WHERE image_url != ''").fetchall()
    conn.close()
    return {r[0] for r in rows}


# ---------------------------------------------------------------------------
# CMS de paginas estaticas (app/cms.py)
# ---------------------------------------------------------------------------

def upsert_cms_page(slug: str, title: str, body: str, published: bool, updated_by: str, menu_order: int = 0, show_in_menu: bool = False) -> dict:
    now = time.time()
    conn = _connect()
    existing = conn.execute("SELECT created_at, version, title, body, published FROM cms_pages WHERE slug = ?", (slug,)).fetchone()
    created_at = existing[0] if existing else now
    next_version = (existing[1] + 1) if existing else 1
    if existing:
        # Guarda a versao ANTERIOR no historico de revisoes antes de sobrescrever,
        # permitindo reverter (rollback) uma edicao indevida pelo painel.
        conn.execute(
            "INSERT INTO cms_page_revisions (slug, version, title, body, published, saved_by, saved_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (slug, existing[1], existing[2], existing[3], existing[4], updated_by, now),
        )
    conn.execute(
        "INSERT OR REPLACE INTO cms_pages (slug, title, body, published, updated_by, created_at, updated_at, "
        "menu_order, show_in_menu, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (slug, title, body, 1 if published else 0, updated_by, created_at, now, menu_order, 1 if show_in_menu else 0, next_version),
    )
    conn.commit()
    conn.close()
    return get_cms_page(slug)


_CMS_COLS = "slug, title, body, published, updated_by, created_at, updated_at, menu_order, show_in_menu, version"


def _row_to_cms(r) -> dict:
    return {"slug": r[0], "title": r[1], "body": r[2], "published": bool(r[3]),
            "updated_by": r[4], "created_at": r[5], "updated_at": r[6],
            "menu_order": r[7], "show_in_menu": bool(r[8]), "version": r[9]}


def get_cms_page(slug: str) -> Optional[dict]:
    conn = _connect()
    row = conn.execute(f"SELECT {_CMS_COLS} FROM cms_pages WHERE slug = ?", (slug,)).fetchone()
    conn.close()
    if not row:
        return None
    return _row_to_cms(row)


def list_cms_pages(only_published: bool = False) -> List[dict]:
    conn = _connect()
    query = f"SELECT {_CMS_COLS} FROM cms_pages"
    if only_published:
        query += " WHERE published = 1"
    query += " ORDER BY menu_order ASC, updated_at DESC"
    rows = conn.execute(query).fetchall()
    conn.close()
    return [_row_to_cms(r) for r in rows]


def delete_cms_page(slug: str) -> bool:
    conn = _connect()
    cursor = conn.execute("DELETE FROM cms_pages WHERE slug = ?", (slug,))
    conn.execute("DELETE FROM cms_page_revisions WHERE slug = ?", (slug,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def list_cms_page_revisions(slug: str, limit: int = 20) -> List[dict]:
    conn = _connect()
    rows = conn.execute(
        "SELECT version, title, body, published, saved_by, saved_at FROM cms_page_revisions "
        "WHERE slug = ? ORDER BY version DESC LIMIT ?", (slug, limit)
    ).fetchall()
    conn.close()
    return [
        {"version": r[0], "title": r[1], "body": r[2], "published": bool(r[3]), "saved_by": r[4], "saved_at": r[5]}
        for r in rows
    ]


def get_cms_page_revision(slug: str, version: int) -> Optional[dict]:
    conn = _connect()
    row = conn.execute(
        "SELECT version, title, body, published, saved_by, saved_at FROM cms_page_revisions "
        "WHERE slug = ? AND version = ?", (slug, version)
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {"version": row[0], "title": row[1], "body": row[2], "published": bool(row[3]), "saved_by": row[4], "saved_at": row[5]}


# ---------------------------------------------------------------------------
# Chaves de funcionalidade / feature flags (app/feature_flags.py)
# ---------------------------------------------------------------------------

def set_feature_flag(key: str, enabled: bool) -> None:
    conn = _connect()
    conn.execute(
        "INSERT OR REPLACE INTO feature_flags (key, enabled, updated_at) VALUES (?, ?, ?)",
        (key, 1 if enabled else 0, time.time()),
    )
    conn.commit()
    conn.close()


def get_feature_flag(key: str) -> Optional[bool]:
    conn = _connect()
    row = conn.execute("SELECT enabled FROM feature_flags WHERE key = ?", (key,)).fetchone()
    conn.close()
    return bool(row[0]) if row else None


def list_feature_flags() -> List[dict]:
    conn = _connect()
    rows = conn.execute("SELECT key, enabled, updated_at FROM feature_flags ORDER BY key").fetchall()
    conn.close()
    return [{"key": r[0], "enabled": bool(r[1]), "updated_at": r[2]} for r in rows]


# ---------------------------------------------------------------------------
# Housekeeping (app/housekeeping.py)
# ---------------------------------------------------------------------------

def record_housekeeping_run(started_at: float, finished_at: float, actions_json: str, stats_json: str, triggered_by: str) -> int:
    conn = _connect()
    cursor = conn.execute(
        "INSERT INTO housekeeping_runs (started_at, finished_at, duration_seconds, actions_json, stats_json, triggered_by) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (started_at, finished_at, finished_at - started_at, actions_json, stats_json, triggered_by),
    )
    conn.commit()
    run_id = cursor.lastrowid
    conn.close()
    return run_id


def list_housekeeping_runs(limit: int = 20) -> List[dict]:
    conn = _connect()
    rows = conn.execute(
        "SELECT id, started_at, finished_at, duration_seconds, actions_json, stats_json, triggered_by "
        "FROM housekeeping_runs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [
        {"id": r[0], "started_at": r[1], "finished_at": r[2], "duration_seconds": r[3],
         "actions": json.loads(r[4]), "stats": json.loads(r[5]), "triggered_by": r[6]}
        for r in rows
    ]


def prune_price_history(cutoff_timestamp: float) -> int:
    conn = _connect()
    cursor = conn.execute("DELETE FROM price_history WHERE recorded_at < ?", (cutoff_timestamp,))
    conn.commit()
    removed = cursor.rowcount
    conn.close()
    return removed


def vacuum_database() -> None:
    conn = _connect()
    conn.execute("VACUUM")
    conn.close()


def integrity_check_database() -> str:
    conn = _connect()
    row = conn.execute("PRAGMA integrity_check").fetchone()
    conn.close()
    return row[0] if row else "unknown"


# ---------------------------------------------------------------------------
# Log de alertas de monitoramento (app/monitoring.py)
# ---------------------------------------------------------------------------

def persist_alert(event_type: str, severity: str, message: str, details_json: str, webhook_delivered: bool) -> int:
    """Persiste um alerta disparado no log auditavel."""
    conn = _connect()
    cursor = conn.execute(
        "INSERT INTO alert_log (event_type, severity, message, details_json, sent_at, webhook_delivered) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (event_type, severity, message, details_json, time.time(), 1 if webhook_delivered else 0),
    )
    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return row_id


def list_recent_alerts(limit: int = 50) -> List[dict]:
    """Retorna os ultimos N alertas em ordem decrescente de data."""
    conn = _connect()
    rows = conn.execute(
        "SELECT id, event_type, severity, message, details_json, sent_at, webhook_delivered "
        "FROM alert_log ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [
        {
            "id": r[0], "event_type": r[1], "severity": r[2], "message": r[3],
            "details": json.loads(r[4]), "sent_at": r[5], "webhook_delivered": bool(r[6]),
        }
        for r in rows
    ]


def count_active_admin_sessions() -> int:
    """Conta sessoes de administrador ainda nao expiradas."""
    conn = _connect()
    row = conn.execute("SELECT COUNT(*) FROM admin_sessions WHERE expires_at > ?", (time.time(),)).fetchone()
    conn.close()
    return row[0] if row else 0


def count_user_accounts() -> int:
    """Total de contas de usuario cadastradas (ativas + inativas)."""
    conn = _connect()
    row = conn.execute("SELECT COUNT(*) FROM user_accounts").fetchone()
    conn.close()
    return row[0] if row else 0


def count_pending_kyc() -> int:
    """Submissoes de KYC aguardando revisao manual."""
    conn = _connect()
    row = conn.execute("SELECT COUNT(*) FROM kyc_submissions WHERE status = 'pending'").fetchone()
    conn.close()
    return row[0] if row else 0


# ---------------------------------------------------------------------------
# Configuracoes gerais do site (app/site_settings.py)
# ---------------------------------------------------------------------------

def set_site_setting(key: str, value_json: str, updated_by: str) -> None:
    conn = _connect()
    conn.execute(
        "INSERT OR REPLACE INTO site_settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, ?)",
        (key, value_json, time.time(), updated_by),
    )
    conn.commit()
    conn.close()


def get_site_setting(key: str) -> Optional[str]:
    conn = _connect()
    row = conn.execute("SELECT value_json FROM site_settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row[0] if row else None


def list_site_settings() -> List[dict]:
    conn = _connect()
    rows = conn.execute("SELECT key, value_json, updated_at, updated_by FROM site_settings ORDER BY key").fetchall()
    conn.close()
    return [{"key": r[0], "value_json": r[1], "updated_at": r[2], "updated_by": r[3]} for r in rows]


# ---------------------------------------------------------------------------
# Contas de usuario final + KYC (app/user_accounts.py)
# ---------------------------------------------------------------------------

_USER_COLS = (
    "id, username, email, password_hash, password_salt, cpf_hash, kyc_status, kyc_tier, "
    "totp_secret, totp_enabled, created_at, last_login_at, is_active"
)


def _row_to_user(row) -> dict:
    return {
        "id": row[0], "username": row[1], "email": row[2], "password_hash": row[3], "password_salt": row[4],
        "cpf_hash": row[5], "kyc_status": row[6], "kyc_tier": row[7], "totp_secret": row[8],
        "totp_enabled": bool(row[9]), "created_at": row[10], "last_login_at": row[11], "is_active": bool(row[12]),
    }


def create_user_account(username: str, email: str, password_hash: str, password_salt: str) -> int:
    conn = _connect()
    try:
        cursor = conn.execute(
            "INSERT INTO user_accounts (username, email, password_hash, password_salt, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, email, password_hash, password_salt, time.time()),
        )
        conn.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError as exc:
        raise ValueError("username_or_email_taken") from exc
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[dict]:
    conn = _connect()
    row = conn.execute(f"SELECT {_USER_COLS} FROM user_accounts WHERE username = ?", (username,)).fetchone()
    conn.close()
    return _row_to_user(row) if row else None


def get_user_by_email(email: str) -> Optional[dict]:
    conn = _connect()
    row = conn.execute(f"SELECT {_USER_COLS} FROM user_accounts WHERE email = ?", (email,)).fetchone()
    conn.close()
    return _row_to_user(row) if row else None


def get_user_by_id(user_id: int) -> Optional[dict]:
    conn = _connect()
    row = conn.execute(f"SELECT {_USER_COLS} FROM user_accounts WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return _row_to_user(row) if row else None


def touch_user_login(user_id: int) -> None:
    conn = _connect()
    conn.execute("UPDATE user_accounts SET last_login_at = ? WHERE id = ?", (time.time(), user_id))
    conn.commit()
    conn.close()


def set_user_password(user_id: int, password_hash: str, password_salt: str) -> None:
    conn = _connect()
    conn.execute(
        "UPDATE user_accounts SET password_hash = ?, password_salt = ? WHERE id = ?",
        (password_hash, password_salt, user_id),
    )
    conn.commit()
    conn.close()


def set_user_cpf_hash(user_id: int, cpf_hash: str) -> None:
    conn = _connect()
    conn.execute("UPDATE user_accounts SET cpf_hash = ? WHERE id = ?", (cpf_hash, user_id))
    conn.commit()
    conn.close()


def cpf_hash_in_use(cpf_hash: str, exclude_user_id: Optional[int] = None) -> bool:
    conn = _connect()
    row = conn.execute(
        "SELECT id FROM user_accounts WHERE cpf_hash = ? AND id != ?",
        (cpf_hash, exclude_user_id or -1),
    ).fetchone()
    conn.close()
    return row is not None


def set_user_kyc_status(user_id: int, status: str, tier: int) -> None:
    conn = _connect()
    conn.execute("UPDATE user_accounts SET kyc_status = ?, kyc_tier = ? WHERE id = ?", (status, tier, user_id))
    conn.commit()
    conn.close()


def create_user_session(token: str, user_id: int, expires_at: float, ip: str) -> None:
    conn = _connect()
    conn.execute(
        "INSERT INTO user_sessions (token, user_id, created_at, expires_at, last_seen_at, ip) VALUES (?, ?, ?, ?, ?, ?)",
        (token, user_id, time.time(), expires_at, time.time(), ip),
    )
    conn.commit()
    conn.close()


def get_user_session(token: str) -> Optional[dict]:
    conn = _connect()
    row = conn.execute(
        "SELECT token, user_id, created_at, expires_at, last_seen_at, ip FROM user_sessions WHERE token = ?",
        (token,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {"token": row[0], "user_id": row[1], "created_at": row[2], "expires_at": row[3],
            "last_seen_at": row[4], "ip": row[5]}


def touch_user_session(token: str) -> None:
    conn = _connect()
    conn.execute("UPDATE user_sessions SET last_seen_at = ? WHERE token = ?", (time.time(), token))
    conn.commit()
    conn.close()


def delete_user_session(token: str) -> None:
    conn = _connect()
    conn.execute("DELETE FROM user_sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()


def purge_expired_user_sessions() -> int:
    conn = _connect()
    cursor = conn.execute("DELETE FROM user_sessions WHERE expires_at < ?", (time.time(),))
    conn.commit()
    removed = cursor.rowcount
    conn.close()
    return removed


def link_user_wallet(user_id: int, address: str, label: str = "") -> None:
    conn = _connect()
    conn.execute(
        "INSERT OR IGNORE INTO user_wallets (user_id, address, label, linked_at) VALUES (?, ?, ?, ?)",
        (user_id, address, label, time.time()),
    )
    conn.commit()
    conn.close()


def list_user_wallets(user_id: int) -> List[dict]:
    conn = _connect()
    rows = conn.execute(
        "SELECT address, label, linked_at FROM user_wallets WHERE user_id = ? ORDER BY linked_at", (user_id,)
    ).fetchall()
    conn.close()
    return [{"address": r[0], "label": r[1], "linked_at": r[2]} for r in rows]


def unlink_user_wallet(user_id: int, address: str) -> bool:
    conn = _connect()
    cursor = conn.execute("DELETE FROM user_wallets WHERE user_id = ? AND address = ?", (user_id, address))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


# --- KYC submissions (documentos cifrados - app/user_accounts.py cuida da cifra) ---

def create_kyc_submission(
    user_id: int, full_name_enc: str, cpf_enc: str, rg_enc: str, birth_date_enc: str,
    document_front_file: str, document_back_file: str, selfie_file: str,
) -> int:
    conn = _connect()
    cursor = conn.execute(
        "INSERT INTO kyc_submissions (user_id, full_name_enc, cpf_enc, rg_enc, birth_date_enc, "
        "document_front_file, document_back_file, selfie_file, status, submitted_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)",
        (user_id, full_name_enc, cpf_enc, rg_enc, birth_date_enc,
         document_front_file, document_back_file, selfie_file, time.time()),
    )
    conn.commit()
    submission_id = cursor.lastrowid
    conn.close()
    return submission_id


_KYC_COLS = (
    "id, user_id, full_name_enc, cpf_enc, rg_enc, birth_date_enc, document_front_file, "
    "document_back_file, selfie_file, status, submitted_at, reviewed_by, reviewed_at, rejection_reason"
)


def _row_to_kyc(row) -> dict:
    return {
        "id": row[0], "user_id": row[1], "full_name_enc": row[2], "cpf_enc": row[3], "rg_enc": row[4],
        "birth_date_enc": row[5], "document_front_file": row[6], "document_back_file": row[7],
        "selfie_file": row[8], "status": row[9], "submitted_at": row[10], "reviewed_by": row[11],
        "reviewed_at": row[12], "rejection_reason": row[13],
    }


def get_kyc_submission(submission_id: int) -> Optional[dict]:
    conn = _connect()
    row = conn.execute(f"SELECT {_KYC_COLS} FROM kyc_submissions WHERE id = ?", (submission_id,)).fetchone()
    conn.close()
    return _row_to_kyc(row) if row else None


def list_kyc_submissions(status: Optional[str] = None, limit: int = 100) -> List[dict]:
    conn = _connect()
    if status:
        rows = conn.execute(
            f"SELECT {_KYC_COLS} FROM kyc_submissions WHERE status = ? ORDER BY submitted_at DESC LIMIT ?",
            (status, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            f"SELECT {_KYC_COLS} FROM kyc_submissions ORDER BY submitted_at DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [_row_to_kyc(r) for r in rows]


def list_kyc_submissions_for_user(user_id: int) -> List[dict]:
    conn = _connect()
    rows = conn.execute(
        f"SELECT {_KYC_COLS} FROM kyc_submissions WHERE user_id = ? ORDER BY submitted_at DESC", (user_id,)
    ).fetchall()
    conn.close()
    return [_row_to_kyc(r) for r in rows]


def review_kyc_submission(submission_id: int, status: str, reviewed_by: str, rejection_reason: Optional[str] = None) -> bool:
    conn = _connect()
    cursor = conn.execute(
        "UPDATE kyc_submissions SET status = ?, reviewed_by = ?, reviewed_at = ?, rejection_reason = ? WHERE id = ?",
        (status, reviewed_by, time.time(), rejection_reason, submission_id),
    )
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated


# ---------------------------------------------------------------------------
# Carteiras multisig e propostas de transacao (app/multisig.py)
# ---------------------------------------------------------------------------

def persist_multisig_wallet(address: str, threshold: int, participant_pubkeys_json: str) -> None:
    """Persiste uma carteira multisig recem-criada no banco de dados."""
    conn = _connect()
    conn.execute(
        "INSERT OR IGNORE INTO multisig_wallets (address, threshold, participant_pubkeys_json, created_at) "
        "VALUES (?, ?, ?, ?)",
        (address, threshold, participant_pubkeys_json, time.time()),
    )
    conn.commit()
    conn.close()


def get_multisig_wallet(address: str) -> Optional[dict]:
    """Retorna os dados de uma carteira multisig pelo endereco, ou None se nao existir."""
    conn = _connect()
    row = conn.execute(
        "SELECT address, threshold, participant_pubkeys_json, created_at FROM multisig_wallets WHERE address = ?",
        (address,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {
        "address": row[0],
        "threshold": row[1],
        "participant_pubkeys_json": row[2],
        "created_at": row[3],
    }


def persist_multisig_proposal(
    proposal_id: str, multisig_address: str, recipient: str, amount: float,
    fee: float, memo: str, network_id: int, tx_id: str, timestamp_val: float,
) -> None:
    """Cria uma nova proposta de transacao multisig no estado 'pending'."""
    conn = _connect()
    conn.execute(
        """INSERT INTO multisig_proposals
           (proposal_id, multisig_address, recipient, amount, fee, memo, network_id,
            tx_id, timestamp_val, status, signatures_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', '[]', ?)""",
        (proposal_id, multisig_address, recipient, amount, fee, memo, network_id,
         tx_id, timestamp_val, time.time()),
    )
    conn.commit()
    conn.close()


def get_multisig_proposal(proposal_id: str) -> Optional[dict]:
    """Retorna uma proposta de transacao multisig pelo ID, ou None se nao existir."""
    conn = _connect()
    row = conn.execute(
        """SELECT proposal_id, multisig_address, recipient, amount, fee, memo, network_id,
                  tx_id, timestamp_val, status, signatures_json, created_at
           FROM multisig_proposals WHERE proposal_id = ?""",
        (proposal_id,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {
        "proposal_id": row[0], "multisig_address": row[1], "recipient": row[2],
        "amount": row[3], "fee": row[4], "memo": row[5], "network_id": row[6],
        "tx_id": row[7], "timestamp_val": row[8], "status": row[9],
        "signatures_json": row[10], "created_at": row[11],
    }


def update_multisig_proposal_signatures(proposal_id: str, signatures_json: str) -> None:
    """Substitui a lista de assinaturas de uma proposta pendente."""
    conn = _connect()
    conn.execute(
        "UPDATE multisig_proposals SET signatures_json = ? WHERE proposal_id = ?",
        (signatures_json, proposal_id),
    )
    conn.commit()
    conn.close()


def set_multisig_proposal_status(proposal_id: str, status: str) -> None:
    """Atualiza o status de uma proposta (ex: 'pending' -> 'finalized')."""
    conn = _connect()
    conn.execute(
        "UPDATE multisig_proposals SET status = ? WHERE proposal_id = ?",
        (status, proposal_id),
    )
    conn.commit()
    conn.close()


def list_multisig_proposals_by_address(multisig_address: str) -> List[dict]:
    """Lista todas as propostas de uma carteira multisig (mais recentes primeiro)."""
    conn = _connect()
    rows = conn.execute(
        """SELECT proposal_id, multisig_address, recipient, amount, fee, memo, network_id,
                  tx_id, timestamp_val, status, signatures_json, created_at
           FROM multisig_proposals WHERE multisig_address = ? ORDER BY created_at DESC""",
        (multisig_address,),
    ).fetchall()
    conn.close()
    return [
        {
            "proposal_id": r[0], "multisig_address": r[1], "recipient": r[2],
            "amount": r[3], "fee": r[4], "memo": r[5], "network_id": r[6],
            "tx_id": r[7], "timestamp_val": r[8], "status": r[9],
            "signatures_json": r[10], "created_at": r[11],
        }
        for r in rows
    ]
