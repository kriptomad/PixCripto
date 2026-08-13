"""
Motor de dificuldade (Proof-of-Work) com:

1) Crescimento matematico agressivo: a dificuldade-base e multiplicada por 20x
   a cada 2 blocos minerados, ate atingir um teto equivalente (em ordem de
   grandeza) a dificuldade de rede do Bitcoin por volta de 2020 (~19 trilhoes).
2) Anti-monopolio de hashrate: mineradores que concentram uma fatia alta dos
   blocos recentes (ou que mineram em sequencia consecutiva) sofrem uma
   penalidade extra de dificuldade ("alpha"), calculada de forma vetorizada
   com numpy sobre a janela de mineradores recentes. Isso torna
   progressivamente mais dificil (nunca mais facil) para um unico
   grupo/pool dominar a rede.

A dificuldade e representada em "bits" (numero de bits zero exigidos no
inicio do hash em binario), o que da granularidade muito mais fina que os
"nibbles" hexadecimais usados na v1 (cada +1 bit dobra a dificuldade, cada
+4 bits equivale a 1 nibble hex).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List

import numpy as np

# ---------------------------------------------------------------------------
# Parametros de crescimento de dificuldade
# ---------------------------------------------------------------------------

GENESIS_DIFFICULTY_BITS = 12          # dificuldade inicial (leve, mineravel em CPU/GPU comum)
GROWTH_FACTOR = 20.0                  # multiplicador de dificuldade a cada intervalo
GROWTH_INTERVAL_BLOCKS = 2            # a cada 2 blocos minerados, aplica o multiplicador

# Bitcoin: dificuldade=1 equivale a ~32 bits de zero exigidos (aprox. target genesis).
# Em dezembro/2020 a dificuldade de rede do Bitcoin era ~= 1.8e13 (18-19 trilhoes).
BITCOIN_GENESIS_EQUIVALENT_BITS = 32.0
BITCOIN_2020_NETWORK_DIFFICULTY = 1.8e13
BITCOIN_2020_EQUIVALENT_BITS = BITCOIN_GENESIS_EQUIVALENT_BITS + math.log2(BITCOIN_2020_NETWORK_DIFFICULTY)
# ~= 32 + 44.03 = 76 bits. Teto matematico de dificuldade que a rede pode alcançar.

# Alcancar ~76 bits de zeros exigidos em SHA-256 exige ~2^76 tentativas de hash,
# o que e astronomicamente inviavel para qualquer hardware unico (mesmo GPU) -
# exatamente como no Bitcoin real, onde so uma rede inteira de ASICs consegue.
# Por isso o modo "demo" limita o teto pratico para permitir mineracao real em
# ambiente de desenvolvimento, enquanto o modo "mainnet_like" usa o teto real.
MAX_BITS_DEMO_MODE = 21
MAX_BITS_MAINNET_LIKE = int(round(BITCOIN_2020_EQUIVALENT_BITS))


# ---------------------------------------------------------------------------
# Anti-monopolio (vetorizado com numpy)
# ---------------------------------------------------------------------------

ANTI_MONOPOLY_WINDOW = 20         # tamanho da janela de blocos recentes analisada
ALPHA_BASE = 0.15                 # peso base da penalidade por concentracao de market-share
ALPHA_STREAK_GROWTH = 0.08        # o quanto o alpha cresce a cada vitoria CONSECUTIVA do mesmo minerador
MAX_PENALTY_BITS = 18             # teto de bits extras que a penalidade anti-monopolio pode adicionar


@dataclass
class DifficultyStatus:
    mode: str
    base_bits: int
    base_difficulty_units: float
    max_bits: int
    bitcoin_2020_equivalent_bits: int


class DifficultyEngine:
    """
    Calcula a dificuldade-base da rede (crescimento 20x a cada 2 blocos) e a
    dificuldade EFETIVA aplicada a um minerador especifico (base + penalidade
    anti-monopolio vetorizada).
    """

    def __init__(self, mode: str = "demo"):
        assert mode in ("demo", "mainnet_like")
        self.mode = mode
        self.max_bits = MAX_BITS_DEMO_MODE if mode == "demo" else MAX_BITS_MAINNET_LIKE

    # -- dificuldade-base da rede -------------------------------------------------
    def base_difficulty_bits(self, mined_block_count: int) -> int:
        """
        mined_block_count = numero de blocos ja minerados (excluindo o genesis).
        Cresce 20x a cada GROWTH_INTERVAL_BLOCKS blocos, ate o teto do modo ativo.
        """
        steps = mined_block_count // GROWTH_INTERVAL_BLOCKS
        difficulty_units = (GROWTH_FACTOR ** steps)  # unidades multiplicativas (base 1.0 = genesis)
        extra_bits = math.log2(difficulty_units) if difficulty_units > 0 else 0.0
        bits = GENESIS_DIFFICULTY_BITS + extra_bits
        return int(min(round(bits), self.max_bits))

    def status(self, mined_block_count: int) -> DifficultyStatus:
        steps = mined_block_count // GROWTH_INTERVAL_BLOCKS
        return DifficultyStatus(
            mode=self.mode,
            base_bits=self.base_difficulty_bits(mined_block_count),
            base_difficulty_units=GROWTH_FACTOR ** steps,
            max_bits=self.max_bits,
            bitcoin_2020_equivalent_bits=int(round(BITCOIN_2020_EQUIVALENT_BITS)),
        )

    # -- anti-monopolio (vetorizado) ---------------------------------------------
    @staticmethod
    def hash_concentration_stats(recent_miners: List[str]) -> dict:
        """
        Calcula, de forma vetorizada com numpy, a distribuicao (market-share) de
        blocos minerados por endereco na janela recente, alem do indice
        Herfindahl-Hirschman (HHI) de concentracao (quanto mais proximo de 1,
        mais monopolizada esta a rede).
        """
        if not recent_miners:
            return {"addresses": [], "shares": [], "hhi": 0.0}
        addresses, counts = np.unique(np.array(recent_miners), return_counts=True)
        shares = counts / counts.sum()
        hhi = float(np.sum(shares ** 2))
        order = np.argsort(-shares)
        return {
            "addresses": addresses[order].tolist(),
            "shares": shares[order].round(4).tolist(),
            "hhi": round(hhi, 4),
        }

    def effective_difficulty_bits(self, miner_address: str, base_bits: int,
                                   recent_miners: List[str]) -> tuple[int, dict]:
        """
        Dificuldade efetiva = dificuldade-base + penalidade anti-monopolio.

        A penalidade cresce com:
          - a fatia (market-share) do minerador na janela recente (vetorizado via numpy)
          - o "alpha" da operacao, que aumenta a cada vitoria CONSECUTIVA do mesmo
            minerador (streak), tornando cada vitoria subsequente progressivamente
            mais custosa - desestimulando pools/grupos a dominarem a mineracao.
        """
        stats = self.hash_concentration_stats(recent_miners)
        if not recent_miners:
            return base_bits, {"share": 0.0, "streak": 0, "alpha": ALPHA_BASE, "penalty_bits": 0, **stats}

        miners_arr = np.array(recent_miners)
        share = float(np.mean(miners_arr == miner_address))

        # streak: quantos dos ultimos blocos (a partir do mais recente) foram minerados
        # consecutivamente pelo mesmo endereco
        streak = 0
        for m in reversed(recent_miners):
            if m == miner_address:
                streak += 1
            else:
                break

        alpha = ALPHA_BASE + ALPHA_STREAK_GROWTH * streak
        penalty_bits = min(MAX_PENALTY_BITS, alpha * share * base_bits)
        effective_cap = self.max_bits if self.mode == "demo" else self.max_bits + MAX_PENALTY_BITS
        effective_bits = min(effective_cap, int(round(base_bits + penalty_bits)))

        return effective_bits, {
            "share": round(share, 4),
            "streak": streak,
            "alpha": round(alpha, 4),
            "penalty_bits": round(penalty_bits, 4),
            **stats,
        }


def target_from_bits(bits: int) -> int:
    """Retorna o alvo maximo (target) de 256 bits que o hash deve ser menor que."""
    return (1 << (256 - bits)) - 1 if bits < 256 else 0


def hash_meets_bits(hash_hex: str, bits: int) -> bool:
    return int(hash_hex, 16) <= target_from_bits(bits)


def block_work(bits: int) -> int:
    """Trabalho computacional esperado para minerar um bloco com esta dificuldade
    (regra de escolha de cadeia de Nakamoto - secao 1.3 do guia): quanto menor o
    target, maior o trabalho esperado. work = 2^256 / (target + 1). Usado para
    decidir, entre duas cadeias concorrentes recebidas via P2P, qual tem MAIS
    trabalho acumulado (nunca "a mais longa em numero de blocos")."""
    target = target_from_bits(bits)
    return (1 << 256) // (target + 1)
