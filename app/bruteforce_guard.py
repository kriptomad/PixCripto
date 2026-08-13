"""
Guarda anti-forca-bruta ADAPTATIVO e AUTO-MUTANTE (`app/bruteforce_guard.py`).

Diferente do `RateLimitMiddleware` em `app/api.py` (janela deslizante FIXA de
N requisicoes/minuto, igual para todo mundo), este modulo implementa um
mecanismo de bloqueio que MUTA A PROPRIA POLITICA de bloqueio em tempo real,
por identidade (IP + escopo protegido), com base no HISTORICO de tentativas
daquela identidade especifica:

  - as duas primeiras tentativas falhas NAO bloqueiam (tolerancia a erro de
    digitacao real do usuario legitimo - padrao comum em sistemas de producao);
  - a partir da 3a falha CONSECUTIVA, o tempo de bloqueio cresce
    EXPONENCIALMENTE (`BASE_COOLDOWN_SECONDS * (GROWTH_FACTOR ** falhas)`),
    ou seja, a "regra" de quanto tempo aquele atacante especifico fica preso
    muda (auto-muta) a cada tentativa nova, ficando cada vez mais cara —
    exatamente o oposto de um rate-limit estatico, que um atacante consegue
    calcular e contornar esperando um tempo fixo previsivel;
  - o teto (`MAX_COOLDOWN_SECONDS`) evita bloqueio permanente/DoS acidental
    contra o proprio usuario legitimo;
  - uma tentativa BEM-SUCEDIDA reseta o contador daquela identidade
    imediatamente (nao pune o usuario legitimo por erros passados de um
    atacante que tentou o mesmo endpoint antes dele, se IPs diferentes -
    o estado e sempre por identidade, nunca global);
  - o estado vive em memoria (thread-safe via lock), com poda periodica de
    entradas antigas para nao crescer sem limite (defesa contra memory-DoS).

Usado para proteger os pontos de verificacao de segredo que sao os alvos mais
obvios de forca bruta no sistema: token de administracao de conteudo
(`app/news.py`), assinatura HMAC de API key de exchange (`app/exchange_api.py`)
e senha de keystore na importacao de carteira (`/wallet/import-keystore`).
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Tuple

BASE_COOLDOWN_SECONDS = 1.0
GROWTH_FACTOR = 2.0
MAX_COOLDOWN_SECONDS = 300.0            # teto de 5 minutos - nunca bloqueia "para sempre"
STALE_ENTRY_SECONDS = 3600.0            # entradas sem atividade ha 1h sao podadas
MAX_TRACKED_IDENTITIES = 50_000         # teto de memoria (defesa contra memory-exhaustion DoS)


@dataclass
class _GuardState:
    failures: int = 0
    locked_until: float = 0.0
    last_seen: float = field(default_factory=time.time)


class BruteForceGuard:
    """Rastreador de tentativas por `(scope, identity)`, thread-safe."""

    def __init__(self) -> None:
        self._states: Dict[Tuple[str, str], _GuardState] = {}
        self._lock = threading.Lock()

    def _cooldown_for(self, failures: int) -> float:
        if failures <= 2:
            return 0.0
        # cresce exponencialmente a partir da 3a falha - a "regra" de bloqueio
        # se torna progressivamente mais severa para aquela identidade especifica
        cooldown = BASE_COOLDOWN_SECONDS * (GROWTH_FACTOR ** (failures - 2))
        return min(cooldown, MAX_COOLDOWN_SECONDS)

    def check(self, scope: str, identity: str) -> None:
        """Levanta `BruteForceLockedError` se esta identidade estiver
        atualmente em cooldown para este escopo. Deve ser chamado ANTES de
        verificar o segredo em si."""
        key = (scope, identity)
        now = time.time()
        with self._lock:
            state = self._states.get(key)
            if state is not None and now < state.locked_until:
                retry_after = state.locked_until - now
                raise BruteForceLockedError(retry_after)

    def record_failure(self, scope: str, identity: str) -> None:
        key = (scope, identity)
        now = time.time()
        should_alert = False
        failures_count = 0
        locked_until_val = 0.0
        with self._lock:
            self._prune_if_needed(now)
            state = self._states.setdefault(key, _GuardState())
            state.failures += 1
            state.last_seen = now
            state.locked_until = now + self._cooldown_for(state.failures)
            if state.failures >= 3 and state.locked_until > now:
                should_alert = True
                failures_count = state.failures
                locked_until_val = state.locked_until
        if should_alert:
            try:
                from . import monitoring as _monitoring
                _monitoring.send_alert(
                    event_type="bruteforce_lockout",
                    severity="warning",
                    message=f"Bloqueio por forca bruta aplicado: escopo={scope} identidade={identity}",
                    details={
                        "scope": scope,
                        "identity": identity,
                        "failures": failures_count,
                        "locked_until": locked_until_val,
                        "cooldown_seconds": round(locked_until_val - now, 1),
                    },
                )
            except Exception:
                pass

    def record_success(self, scope: str, identity: str) -> None:
        key = (scope, identity)
        with self._lock:
            self._states.pop(key, None)

    def reset_all(self) -> None:
        """Limpa TODO o estado rastreado - uso exclusivo em testes/isolamento
        entre suites (nunca deve ser chamado por um endpoint publico, o que
        anularia a protecao contra forca bruta)."""
        with self._lock:
            self._states.clear()

    def purge_expired(self) -> int:
        """Remove explicitamente todas as entradas obsoletas (sem atividade
        ha mais de `STALE_ENTRY_SECONDS`). Diferente de `_prune_if_needed`
        (poda oportunista/condicional chamada a cada falha), este metodo e
        chamado pelo housekeeping automatico (`app/housekeeping.py`) em
        intervalo fixo, garantindo poda mesmo em nos com pouco trafego de
        falhas. Retorna quantas entradas foram removidas."""
        now = time.time()
        with self._lock:
            before = len(self._states)
            self._states = {
                key: state
                for key, state in self._states.items()
                if now - state.last_seen <= STALE_ENTRY_SECONDS
            }
            return before - len(self._states)

    def _prune_if_needed(self, now: float) -> None:
        # poda entradas obsoletas oportunisticamente, sem precisar de uma
        # thread de background dedicada (barato o suficiente para rodar a
        # cada nova falha registrada)
        if len(self._states) < MAX_TRACKED_IDENTITIES:
            stale_check_needed = False
            for state in self._states.values():
                if now - state.last_seen > STALE_ENTRY_SECONDS:
                    stale_check_needed = True
                    break
            if not stale_check_needed:
                return
        self._states = {
            key: state
            for key, state in self._states.items()
            if now - state.last_seen <= STALE_ENTRY_SECONDS
        }

    def status(self, scope: str, identity: str) -> dict:
        """Snapshot somente-leitura do estado atual (uso em testes/observabilidade)."""
        key = (scope, identity)
        with self._lock:
            state = self._states.get(key)
            if state is None:
                return {"failures": 0, "locked": False, "retry_after_seconds": 0.0}
            now = time.time()
            locked = now < state.locked_until
            return {
                "failures": state.failures,
                "locked": locked,
                "retry_after_seconds": max(0.0, state.locked_until - now) if locked else 0.0,
            }


class BruteForceLockedError(Exception):
    """Identidade temporariamente bloqueada por excesso de tentativas falhas."""

    def __init__(self, retry_after_seconds: float) -> None:
        self.retry_after_seconds = round(retry_after_seconds, 3)
        super().__init__(
            f"Muitas tentativas invalidas; tente novamente em {self.retry_after_seconds:.1f}s"
        )


# instancia global unica do processo - o estado precisa ser compartilhado por
# todas as requisicoes concorrentes do mesmo node (assim como o rate limiter)
guard = BruteForceGuard()
