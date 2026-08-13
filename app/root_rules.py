"""
ROOT RULES — a "constituicao" imutavel da blockchain PixCripto (PXC).

Este modulo e a UNICA fonte da verdade para todos os parametros de consenso,
economicos e de seguranca do sistema. Nenhum outro modulo deve redefinir estes
valores — eles devem ser IMPORTADOS daqui. Isso evita "drift" (divergencia)
entre o que o codigo faz e o que o "Book of Rules" documenta.

Para tornar as regras verificaveis (tamper-evident), o hash SHA-256 canonico
deste conjunto de regras e calculado e pode ser conferido a qualquer momento
via `GET /rules/root-hash` — se alguem alterar um paraemetro aqui sem atualizar
a documentacao (BOOK_OF_RULES.md) e o numero de versao, o hash muda e a
divergencia fica evidente (governanca transparente e auditavel).

Qualquer mudanca em um valor abaixo é, por definicao, um **hard fork** e exige:
  1. incrementar `RULES_VERSION`;
  2. documentar a mudanca em `BOOK_OF_RULES.md` (secao "Historico de versoes");
  3. um numero de bloco de ativacao (`activation_block`) a partir do qual a nova
     regra passa a valer — nunca retroativo.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from typing import Dict, List


RULES_VERSION = "1.4.0"

# ---------------------------------------------------------------------------
# 1. IDENTIDADE DA REDE
# ---------------------------------------------------------------------------
NETWORK_NAME = "PixCripto"
NETWORK_SYMBOL = "PXC"
GENESIS_MESSAGE = "PixCripto Genesis — pagamento descentralizado ancorado em ouro, 30/07/2026"
ADDRESS_VERSION_BYTE = 0x37          # byte de versao Base58Check exclusivo do PXC (mainnet)
ADDRESS_VERSION_BYTE_TESTNET = 0x6F  # reservado para uma futura testnet

# identificador de rede assinado dentro de TODA transacao (`Transaction.network_id`,
# ver signing_payload em models.py) — protecao contra replay attack: uma tx assinada
# para a mainnet nunca sera valida numa testnet/fork futuro que use NETWORK_ID
# diferente, mesmo reutilizando a mesma chave/endereco/nonce (achado do gap-analysis
# contra o guia "blockchain-do-zero.md", secao 8.5 "Replay Protection").
NETWORK_ID = 7777
NETWORK_ID_TESTNET = 7778

# ---------------------------------------------------------------------------
# 2. REGRAS ECONOMICAS (EMISSAO / SUPRIMENTO)
# ---------------------------------------------------------------------------
# PXC NAO e finito como o Bitcoin (21M) por design do usuario, mas TEM limites
# de emissao por unidade de tempo para impedir hiperinflacao instantanea:
MAX_SUPPLY_HARD_CAP = None                 # sem teto absoluto (moeda "elastica", nao escassa)
MAX_MINT_PER_BLOCK_PXC = 100_000.0         # teto de emissao (compra+mineracao) por bloco
MAX_MINT_PER_HOUR_PXC = 2_000_000.0        # teto de emissao agregada por hora (janela deslizante)

MINER_REWARD_RATE = 0.04                   # 4% do valor do bloco vai ao(s) minerador(es)
PURCHASE_FEE_RATE = 0.0738                 # 7,38% de taxa de compra
PURCHASE_FEE_BASIS_BRL = 100.0             # taxa cobrada "a cada R$100"

# ---------------------------------------------------------------------------
# 2b. MINERACAO COLABORATIVA (POOL) — divisao da recompensa entre validadores
# ---------------------------------------------------------------------------
# A recompensa de 4% do bloco (MINER_REWARD_RATE) pode ser dividida entre
# VARIAS pessoas que contribuiram para encontrar aquele bloco especifico
# (estilo pool de mineracao Bitcoin: PPLNS/proporcional por "shares"), em vez
# de ir inteira para um unico endereco. Quem monta/submete o bloco informa a
# lista de contribuidores e o peso (numero de shares) de cada um; o protocolo
# paga uma transacao coinbase_mining PROPORCIONAL para cada contribuidor,
# dentro do MESMO bloco (todas participam do hash minerado, como no Bitcoin).
MAX_POOL_CONTRIBUTORS_PER_BLOCK = 500       # teto de contribuidores por bloco (anti-DoS: cada um vira uma tx)
MIN_POOL_CONTRIBUTOR_SHARE = 1e-9           # peso minimo aceito por contribuidor (evita divisao degenerada)

PXC_GOLD_BACKING_OZ = 0.00025               # lastro: fracao de onca de ouro por PXC

# ---------------------------------------------------------------------------
# 3. REGRAS DE DIFICULDADE / MINERACAO (Proof-of-Work)
# ---------------------------------------------------------------------------
DIFFICULTY_GROWTH_FACTOR = 20               # cresce 20x a cada N blocos
DIFFICULTY_GROWTH_INTERVAL_BLOCKS = 2
MAX_BITS_DEMO_MODE = 21
MAX_BITS_MAINNET_LIKE = 76                  # equivalente aproximado a dificuldade Bitcoin ~2020
ANTI_MONOPOLY_WINDOW_BLOCKS = 20            # janela de blocos p/ calculo de market-share do minerador
ANTI_MONOPOLY_ALPHA_BASE = 0.15
ANTI_MONOPOLY_ALPHA_STREAK_GROWTH = 0.08
ANTI_MONOPOLY_MAX_PENALTY_BITS = 24

# ---------------------------------------------------------------------------
# 4. REGRAS DE TRANSACAO
# ---------------------------------------------------------------------------
MIN_TRANSACTION_AMOUNT = 0.00000001          # 1 satoshi-PXC (8 casas decimais)
MAX_TRANSACTION_AMOUNT = 10_000_000.0        # teto de sanidade por transacao (anti-overflow/DoS)
MAX_MEMO_LENGTH_BYTES = 512
MAX_PENDING_TX_PER_ADDRESS = 50               # anti-flood de mempool por endereco
TX_EXPIRY_SECONDS = 24 * 3600                 # transacao pendente expira do mempool apos 24h
MAX_BLOCK_FUTURE_SKEW_SECONDS = 120           # bloco com timestamp > "agora + isso" e rejeitado
                                               # (impede um minerador anunciar blocos "do futuro"
                                               # para manipular o recalculo de dificuldade)
MIN_BLOCK_TIMESTAMP_ADVANCE_SECONDS = -60     # tolerancia de relogio: timestamp do bloco pode ficar
                                               # ate 60s ANTES do timestamp do bloco anterior (clock
                                               # skew entre nos), mas nao mais que isso (nao-monotonico
                                               # demais indica manipulacao deliberada)

# tipos de transacao reconhecidos pelo protocolo (qualquer tx_type fora desta
# lista e rejeitada automaticamente por `Transaction.is_valid()`)
VALID_TX_TYPES = {
    "transfer", "coinbase_mining", "coinbase_purchase", "sell_burn",
    "liquidation_burn", "swap_escrow", "swap_fill", "swap_cancel_refund",
    "rollup_commit", "l2_withdrawal", "contract_deploy", "contract_call",
}

# ---------------------------------------------------------------------------
# 4b. MAQUINA VIRTUAL / SMART CONTRACTS (secao 5 do guia)
# ---------------------------------------------------------------------------
# `tx.fee`, para contract_deploy/contract_call, e reaproveitado como o
# ORCAMENTO DE GAS em PXC (mesmo campo usado para priorizar a mempool nas
# demais tx) - convertido para unidades de gas por este preco fixo. Manter
# o preco de gas em PXC (nao em unidade separada) evita introduzir um
# segundo ativo/unidade de conta so para a VM.
GAS_PRICE_PXC = 0.00000001            # preco de 1 unidade de gas, em PXC
MAX_CONTRACT_BYTECODE_BYTES = 24_576  # mesmo teto pratico usado por clientes Ethereum (EIP-170)
MAX_CONTRACT_CALLDATA_BYTES = 16_384

# ---------------------------------------------------------------------------
# 5. REGRAS DE CONTROLE DE DUMP / AUTO-REGULACAO
# ---------------------------------------------------------------------------
DUMP_WINDOW_SECONDS = 600
MAX_WALLET_DUMP_RATIO = 0.30
NETWORK_DUMP_RATIO_FLOOR = 0.01
NETWORK_DUMP_RATIO_CEILING = 0.08

# ---------------------------------------------------------------------------
# 6. REGRAS DE REDE / API (anti-abuso)
# ---------------------------------------------------------------------------
RATE_LIMIT_REQUESTS_PER_MINUTE = 60           # por IP, por rota sensivel
MAX_MINING_ITERATIONS_PER_CALL = 5_000_000    # teto de `max_iterations` em /mining/mine
ORACLE_MAX_DELTA_PCT_PER_FETCH = 15.0         # circuit-breaker: rejeita cotacao de ouro
                                               # que varie mais que 15% de uma vez (anti-manipulacao)

# ---------------------------------------------------------------------------
# 7. ENDERECOS DO SISTEMA (nao sao carteiras de usuario, nunca tem chave privada)
# ---------------------------------------------------------------------------
COINBASE_SENDER = "SISTEMA_EMISSAO"
L2_BRIDGE_ADDRESS = "PXC_L2_BRIDGE_ESCROW"
SWAP_ESCROW_ADDRESS = "PXC_SWAP_ESCROW_POOL"
SYSTEM_ADDRESSES = {COINBASE_SENDER, L2_BRIDGE_ADDRESS, SWAP_ESCROW_ADDRESS}


@dataclass(frozen=True)
class RootRulesSnapshot:
    version: str
    rules: Dict[str, object]


def _serializable_rules() -> Dict[str, object]:
    return {
        "network_name": NETWORK_NAME,
        "network_symbol": NETWORK_SYMBOL,
        "genesis_message": GENESIS_MESSAGE,
        "address_version_byte": ADDRESS_VERSION_BYTE,
        "network_id": NETWORK_ID,
        "max_supply_hard_cap": MAX_SUPPLY_HARD_CAP,
        "max_mint_per_block_pxc": MAX_MINT_PER_BLOCK_PXC,
        "max_mint_per_hour_pxc": MAX_MINT_PER_HOUR_PXC,
        "miner_reward_rate": MINER_REWARD_RATE,
        "max_pool_contributors_per_block": MAX_POOL_CONTRIBUTORS_PER_BLOCK,
        "min_pool_contributor_share": MIN_POOL_CONTRIBUTOR_SHARE,
        "purchase_fee_rate": PURCHASE_FEE_RATE,
        "purchase_fee_basis_brl": PURCHASE_FEE_BASIS_BRL,
        "pxc_gold_backing_oz": PXC_GOLD_BACKING_OZ,
        "difficulty_growth_factor": DIFFICULTY_GROWTH_FACTOR,
        "difficulty_growth_interval_blocks": DIFFICULTY_GROWTH_INTERVAL_BLOCKS,
        "max_bits_demo_mode": MAX_BITS_DEMO_MODE,
        "max_bits_mainnet_like": MAX_BITS_MAINNET_LIKE,
        "anti_monopoly_window_blocks": ANTI_MONOPOLY_WINDOW_BLOCKS,
        "anti_monopoly_alpha_base": ANTI_MONOPOLY_ALPHA_BASE,
        "anti_monopoly_alpha_streak_growth": ANTI_MONOPOLY_ALPHA_STREAK_GROWTH,
        "anti_monopoly_max_penalty_bits": ANTI_MONOPOLY_MAX_PENALTY_BITS,
        "min_transaction_amount": MIN_TRANSACTION_AMOUNT,
        "max_transaction_amount": MAX_TRANSACTION_AMOUNT,
        "max_memo_length_bytes": MAX_MEMO_LENGTH_BYTES,
        "max_pending_tx_per_address": MAX_PENDING_TX_PER_ADDRESS,
        "tx_expiry_seconds": TX_EXPIRY_SECONDS,
        "max_block_future_skew_seconds": MAX_BLOCK_FUTURE_SKEW_SECONDS,
        "min_block_timestamp_advance_seconds": MIN_BLOCK_TIMESTAMP_ADVANCE_SECONDS,
        "valid_tx_types": sorted(VALID_TX_TYPES),
        "dump_window_seconds": DUMP_WINDOW_SECONDS,
        "max_wallet_dump_ratio": MAX_WALLET_DUMP_RATIO,
        "network_dump_ratio_floor": NETWORK_DUMP_RATIO_FLOOR,
        "network_dump_ratio_ceiling": NETWORK_DUMP_RATIO_CEILING,
        "rate_limit_requests_per_minute": RATE_LIMIT_REQUESTS_PER_MINUTE,
        "max_mining_iterations_per_call": MAX_MINING_ITERATIONS_PER_CALL,
        "oracle_max_delta_pct_per_fetch": ORACLE_MAX_DELTA_PCT_PER_FETCH,
        "system_addresses": sorted(SYSTEM_ADDRESSES),
    }


def root_rules_hash() -> str:
    """Hash SHA-256 canonico do conjunto de regras — muda se QUALQUER parametro
    acima for alterado. Serve como "assinatura" da versao de consenso rodando."""
    payload = json.dumps({"version": RULES_VERSION, "rules": _serializable_rules()},
                          sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def snapshot() -> RootRulesSnapshot:
    return RootRulesSnapshot(version=RULES_VERSION, rules=_serializable_rules())


def snapshot_dict() -> dict:
    s = snapshot()
    return {"version": s.version, "rules": s.rules, "root_hash": root_rules_hash()}
