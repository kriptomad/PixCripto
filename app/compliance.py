"""
Modulo de conformidade regulatoria (KYC/AML) do PixCripto.

Objetivo: dar ao PixCripto um sistema de conformidade PROPRIO e REAL o
suficiente para operar como instituicao de pagamento (ainda que a
homologacao final junto ao Banco Central/COAF exija tambem processos
humanos/juridicos fora do escopo de codigo). Este modulo implementa a parte
que PODE ser codificada de forma verificavel:

1. **KYC (Know Your Customer)** - registro de identidade vinculado a um
   endereco de carteira, com niveis (tiers) que liberam limites de valor
   maiores conforme mais documentacao e verificada:
     - Tier 0 (nao verificado): pode operar ate `kyc_required_above_pxc`
       (configuravel via `PIXCRIPTO_KYC_THRESHOLD_PXC`) sem se identificar -
       equivalente ao limite "sem cadastro" do Pix/carteiras digitais reais.
     - Tier 1 (basico): CPF/CNPJ + nome completo + data de nascimento.
     - Tier 2 (completo): Tier 1 + documento com foto + comprovante de
       endereco (hash do documento armazenado, nunca o arquivo em si neste
       protótipo - ver nota de privacidade abaixo).
2. **Screening de sancoes/PEP** - checagem local contra uma lista de
   endereços/CPFs bloqueados (equivalente as listas OFAC/ONU/COAF), com hook
   explicito para integrar um provedor externo de compliance real
   (Chainalysis, TRM Labs, etc. - fora do escopo deste protótipo, mas a
   interface `screen_counterparty` foi desenhada para receber um resultado
   externo sem mudar a assinatura).
3. **Monitoramento de transacoes (AML)** - regras automaticas que sinalizam
   comportamento suspeito para revisão humana (nunca bloqueiam a rede
   sozinhas, exceto sanção confirmada):
     - **estruturação/smurfing**: N transações abaixo do limiar de KYC em uma
       janela curta de tempo, somando acima do limiar - clássico padrão de
       "fracionamento" para evitar identificação;
     - **limite diário excedido** sem o tier de KYC necessário;
     - contraparte constante na lista de sanções.
4. **Trilha de auditoria** - todo evento de compliance (registro, alerta,
   bloqueio) é persistido de forma append-only em SQLite, consultável via
   `GET /compliance/reports/sar` (Suspicious Activity Report, nomenclatura
   usada por reguladores financeiros).

Nota de privacidade/segurança: este é um protótipo educacional. Em produção
real, dados de KYC (CPF, documentos) DEVEM ser criptografados em repouso com
uma chave gerida por HSM/KMS dedicado e nunca ficar em texto plano no mesmo
banco da blockchain pública - aqui, para permitir testes determinísticos e
manter o escopo gerenciável, os dados de identidade são armazenados com um
hash SHA-256 do CPF (nunca o CPF em texto plano) e os demais campos como
texto simples em um banco SEPARADO do `pixcripto_chain.db` público.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
COMPLIANCE_DB_PATH = Path(
    os.environ.get("PIXCRIPTO_COMPLIANCE_DB_PATH")
    or (ROOT_DIR / "data" / "pixcripto_compliance.db")
)

# Janela e limiar usados para detectar estruturacao/smurfing (fracionamento
# de valor para escapar do limite de KYC). Configuravel via ambiente para
# permitir ajuste de politica sem alterar codigo.
STRUCTURING_WINDOW_SECONDS = int(os.environ.get("PIXCRIPTO_AML_STRUCTURING_WINDOW", str(24 * 3600)))
STRUCTURING_MIN_TX_COUNT = int(os.environ.get("PIXCRIPTO_AML_STRUCTURING_MIN_TXS", "3"))

KYC_TIER_UNVERIFIED = 0
KYC_TIER_BASIC = 1
KYC_TIER_FULL = 2

KYC_TIER_LIMITS_PXC = {
    KYC_TIER_UNVERIFIED: float(os.environ.get("PIXCRIPTO_KYC_THRESHOLD_PXC", "1000")),
    KYC_TIER_BASIC: 50_000.0,
    KYC_TIER_FULL: float("inf"),
}


class ComplianceError(Exception):
    """Levantado quando uma transacao/operacao viola uma regra de
    conformidade que a REDE nao pode permitir (ex: contraparte sancionada) -
    diferente de um alerta AML, que apenas registra para revisao humana."""


def _hash_cpf(cpf: str) -> str:
    digits = "".join(ch for ch in cpf if ch.isdigit())
    return hashlib.sha256(digits.encode("utf-8")).hexdigest()


@dataclass
class KYCRecord:
    address: str
    tier: int
    full_name: str
    cpf_hash: str
    created_at: float
    document_hash: Optional[str] = None


class ComplianceEngine:
    """Motor de conformidade: KYC, screening de sancoes e monitoramento AML.
    Uma instancia por processo (mesmo padrao de `MarketEngine`/`L2Rollup`),
    persistindo em um banco SQLite proprio e SEPARADO da blockchain publica."""

    def __init__(self, db_path: Path = COMPLIANCE_DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS kyc_records (
                address TEXT PRIMARY KEY,
                tier INTEGER NOT NULL,
                full_name TEXT NOT NULL,
                cpf_hash TEXT NOT NULL,
                document_hash TEXT,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sanctions_list (
                entry TEXT PRIMARY KEY,   -- endereco OU hash de CPF sancionado
                reason TEXT NOT NULL,
                added_at REAL NOT NULL
            );

            -- Trilha de auditoria append-only: nenhuma linha e jamais
            -- atualizada/apagada apos inserida (equivalente a um log
            -- imutavel de compliance, auditavel externamente).
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,   -- kyc_register | aml_alert | sanction_block
                address TEXT,
                details TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info',  -- info | warning | critical
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_address ON audit_log(address);
            """
        )
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # KYC
    # ------------------------------------------------------------------
    def register_kyc(self, address: str, full_name: str, cpf: str, tier: int = KYC_TIER_BASIC,
                      document_hash: Optional[str] = None) -> KYCRecord:
        if tier not in (KYC_TIER_BASIC, KYC_TIER_FULL):
            raise ValueError("tier de registro deve ser 1 (basico) ou 2 (completo)")
        if tier == KYC_TIER_FULL and not document_hash:
            raise ValueError("tier 2 (completo) exige document_hash (hash do documento com foto)")
        record = KYCRecord(
            address=address, tier=tier, full_name=full_name.strip(),
            cpf_hash=_hash_cpf(cpf), created_at=time.time(), document_hash=document_hash,
        )
        conn = self._connect()
        conn.execute(
            "INSERT INTO kyc_records (address, tier, full_name, cpf_hash, document_hash, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(address) DO UPDATE SET tier=excluded.tier, full_name=excluded.full_name, "
            "cpf_hash=excluded.cpf_hash, document_hash=excluded.document_hash",
            (record.address, record.tier, record.full_name, record.cpf_hash, record.document_hash, record.created_at),
        )
        conn.commit()
        conn.close()
        self._log_event("kyc_register", address, f"tier={tier} nome={full_name}", "info")
        return record

    def get_kyc_tier(self, address: str) -> int:
        conn = self._connect()
        row = conn.execute("SELECT tier FROM kyc_records WHERE address = ?", (address,)).fetchone()
        conn.close()
        return int(row[0]) if row else KYC_TIER_UNVERIFIED

    def get_kyc_record(self, address: str) -> Optional[dict]:
        conn = self._connect()
        row = conn.execute(
            "SELECT address, tier, full_name, created_at FROM kyc_records WHERE address = ?", (address,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        return {"address": row[0], "tier": row[1], "full_name": row[2], "created_at": row[3]}

    def limit_for_address(self, address: str) -> float:
        return KYC_TIER_LIMITS_PXC[self.get_kyc_tier(address)]

    # ------------------------------------------------------------------
    # Sanções / PEP
    # ------------------------------------------------------------------
    def add_to_sanctions_list(self, entry: str, reason: str) -> None:
        conn = self._connect()
        conn.execute(
            "INSERT INTO sanctions_list (entry, reason, added_at) VALUES (?, ?, ?) "
            "ON CONFLICT(entry) DO UPDATE SET reason=excluded.reason",
            (entry, reason, time.time()),
        )
        conn.commit()
        conn.close()

    def remove_from_sanctions_list(self, entry: str) -> None:
        conn = self._connect()
        conn.execute("DELETE FROM sanctions_list WHERE entry = ?", (entry,))
        conn.commit()
        conn.close()

    def is_sanctioned(self, address: str) -> bool:
        conn = self._connect()
        row = conn.execute("SELECT 1 FROM sanctions_list WHERE entry = ?", (address,)).fetchone()
        conn.close()
        return row is not None

    def screen_counterparty(self, address: str) -> dict:
        """Verifica um endereco contra a lista de sancoes local. Ponto de
        extensao para um provedor externo real (Chainalysis/TRM/etc.):
        um deploy de producao pode sobrescrever este metodo (ou compor com
        ele) para tambem consultar uma API externa antes de retornar."""
        sanctioned = self.is_sanctioned(address)
        return {"address": address, "sanctioned": sanctioned}

    # ------------------------------------------------------------------
    # AML - monitoramento de transacoes
    # ------------------------------------------------------------------
    def check_transaction(self, sender: str, recipient: str, amount_pxc: float,
                           sender_recent_amounts: Optional[List[float]] = None) -> dict:
        """Avalia uma transacao ANTES dela ser aceita na mempool (chamado
        pela API). Levanta `ComplianceError` apenas para violacoes que a
        rede deve bloquear de fato (contraparte sancionada); demais achados
        (limite excedido, estruturacao) apenas geram um alerta na trilha de
        auditoria e retornam no resultado, sem impedir a transacao - a
        decisao de bloquear ou nao por limite fica a cargo do chamador
        (mesma logica: o KYC gate eh aplicado no endpoint, nao aqui)."""
        alerts: List[str] = []

        for who, addr in (("sender", sender), ("recipient", recipient)):
            if self.is_sanctioned(addr):
                self._log_event("sanction_block", addr, f"{who} sancionado bloqueou tx de {amount_pxc} PXC", "critical")
                raise ComplianceError(f"Endereco {addr} ({who}) esta na lista de sancoes - transacao bloqueada")

        sender_limit = self.limit_for_address(sender)
        if amount_pxc > sender_limit:
            alerts.append(f"valor {amount_pxc} PXC excede o limite do tier de KYC do remetente ({sender_limit} PXC)")
            self._log_event("aml_alert", sender, alerts[-1], "warning")

        recent = sender_recent_amounts or []
        if len(recent) >= STRUCTURING_MIN_TX_COUNT:
            total = sum(recent) + amount_pxc
            tier0_limit = KYC_TIER_LIMITS_PXC[KYC_TIER_UNVERIFIED]
            if all(a < tier0_limit for a in recent + [amount_pxc]) and total > tier0_limit:
                alerts.append(
                    f"possivel estruturacao/smurfing: {len(recent) + 1} transacoes recentes somam "
                    f"{total:.2f} PXC (acima do limiar de KYC {tier0_limit} PXC) em fracoes individuais menores"
                )
                self._log_event("aml_alert", sender, alerts[-1], "warning")

        return {"sender": sender, "recipient": recipient, "amount_pxc": amount_pxc, "alerts": alerts}

    # ------------------------------------------------------------------
    # Trilha de auditoria / relatorios
    # ------------------------------------------------------------------
    def _log_event(self, event_type: str, address: Optional[str], details: str, severity: str) -> None:
        conn = self._connect()
        conn.execute(
            "INSERT INTO audit_log (event_type, address, details, severity, created_at) VALUES (?, ?, ?, ?, ?)",
            (event_type, address, details, severity, time.time()),
        )
        conn.commit()
        conn.close()

    def suspicious_activity_report(self, min_severity: str = "warning", limit: int = 200) -> List[dict]:
        """Equivalente a um relatorio SAR (Suspicious Activity Report) -
        lista os eventos de auditoria de severidade >= `min_severity`
        (warning/critical), mais recentes primeiro."""
        severities = {"info": 0, "warning": 1, "critical": 2}
        min_level = severities.get(min_severity, 1)
        conn = self._connect()
        rows = conn.execute(
            "SELECT id, event_type, address, details, severity, created_at FROM audit_log "
            "ORDER BY id DESC LIMIT ?",
            (limit * 3,),  # busca uma folga extra antes de filtrar por severidade em Python
        ).fetchall()
        conn.close()
        results = [
            {"id": r[0], "event_type": r[1], "address": r[2], "details": r[3], "severity": r[4], "created_at": r[5]}
            for r in rows if severities.get(r[4], 0) >= min_level
        ]
        return results[:limit]


compliance_engine = ComplianceEngine()
