"""
Honeypot / decepcao ativa contra atacantes.

Objetivo (pedido pelo usuario): se alguem tentar explorar uma vulnerabilidade
(real ou aparente), a resposta do sistema deve PRENDER o hardware do atacante
(CPU/GPU) numa tarefa de mineracao praticamente impossivel de resolver em
tempo util, em troca de uma recompensa que nunca sera paga - desperdicando o
tempo/energia do atacante e, ao mesmo tempo, coletando um "fingerprint"
(impressao digital) de quem tentou, para deteccao e bloqueio futuro.

Componentes:
1. `HoneypotLedger` - registra toda tentativa de acesso a uma rota-isca
   (IP, User-Agent, headers, timestamp, rota, "score" de suspeita).
2. Rotas-isca (`decoy_router`) com nomes deliberadamente tentadores para um
   atacante que esteja fazendo reconhecimento (`/admin/...`, `/internal/...`,
   `/debug/...`, `/_backup/...`) - qualquer uma delas devolve um desafio de
   Proof-of-Work com dificuldade proxima do "mainnet_like" (dezenas de bits
   a mais que a rede real usa) e uma recompensa fake enorme. Mesmo que, por
   sorte, o atacante encontre um nonce valido, o "pagamento" nunca ocorre de
   verdade (nao existe tal transacao no ledger real) - e apenas uma isca.
3. Uma carteira-isca ("honeypot wallet") com saldo fake grande, exposta como
   se tivesse "vazado" por engano - qualquer tentativa de gastar dela e
   registrada e automaticamente rejeitada (ninguem tem a chave privada dela).
"""
from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from .difficulty import hash_meets_bits, target_from_bits

# dificuldade do desafio-isca: bem acima do que a rede real pede no modo demo,
# para manter o hardware do atacante ocupado por muito tempo tentando (mas
# ainda "plausivel" o bastante para nao ser obviamente impossivel de cara).
HONEYPOT_CHALLENGE_BITS = 40          # ~ 2^40 tentativas esperadas em media
HONEYPOT_FAKE_REWARD_PXC = 250_000.0  # nunca pago de verdade - so a isca


@dataclass
class HoneypotEvent:
    timestamp: float
    ip: str
    path: str
    user_agent: str
    detail: str
    threat_score: int
    fingerprint: str


@dataclass
class HoneypotChallenge:
    challenge_id: str
    seed: str
    target_bits: int
    fake_reward_pxc: float
    issued_at: float
    ip: str


class HoneypotLedger:
    """Estado central do honeypot: eventos capturados, desafios emitidos e
    score de ameaca acumulado por IP (para futura decisao de bloqueio/WAF)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.events: List[HoneypotEvent] = []
        self.challenges: Dict[str, HoneypotChallenge] = {}
        self.threat_score_by_ip: Dict[str, int] = {}
        self.decoy_wallet_address = "P" + secrets.token_hex(16)[:33]
        self.decoy_wallet_fake_balance = 4_820_000.5

    def _fingerprint(self, ip: str, user_agent: str) -> str:
        return hashlib.sha256(f"{ip}|{user_agent}".encode("utf-8")).hexdigest()[:16]

    def record(self, ip: str, path: str, user_agent: str, detail: str, score: int = 10) -> HoneypotEvent:
        with self._lock:
            event = HoneypotEvent(
                timestamp=time.time(), ip=ip, path=path, user_agent=user_agent,
                detail=detail, threat_score=score, fingerprint=self._fingerprint(ip, user_agent),
            )
            self.events.append(event)
            self.events[:] = self.events[-5000:]
            self.threat_score_by_ip[ip] = self.threat_score_by_ip.get(ip, 0) + score
        try:
            from . import monitoring as _monitoring
            _monitoring.send_alert(
                event_type="honeypot_exploit_attempt",
                severity="warning",
                message=f"Honeypot: acesso suspeito detectado em {path} de {ip}",
                details={
                    "ip": ip, "path": path, "user_agent": user_agent,
                    "detail": detail, "threat_score": score,
                    "fingerprint": event.fingerprint,
                },
            )
        except Exception:
            pass
        return event

    def issue_challenge(self, ip: str) -> HoneypotChallenge:
        challenge = HoneypotChallenge(
            challenge_id=secrets.token_hex(12),
            seed=secrets.token_hex(16),
            target_bits=HONEYPOT_CHALLENGE_BITS,
            fake_reward_pxc=HONEYPOT_FAKE_REWARD_PXC,
            issued_at=time.time(),
            ip=ip,
        )
        with self._lock:
            self.challenges[challenge.challenge_id] = challenge
        return challenge

    def check_proof(self, challenge_id: str, nonce: int) -> bool:
        """Mesmo que o atacante consiga um nonce valido (estatisticamente
        improvavel em tempo humano razoavel), a funcao apenas confirma
        matematicamente - NENHUM pagamento real e feito (retorno permanece
        um "quase la" simulado no endpoint que chama isto)."""
        challenge = self.challenges.get(challenge_id)
        if challenge is None:
            return False
        candidate = hashlib.sha256(f"{challenge.seed}:{nonce}".encode()).hexdigest()
        return hash_meets_bits(candidate, challenge.target_bits)

    def top_suspects(self, limit: int = 20) -> List[dict]:
        with self._lock:
            ranked = sorted(self.threat_score_by_ip.items(), key=lambda kv: kv[1], reverse=True)
        return [{"ip": ip, "threat_score": score} for ip, score in ranked[:limit]]

    def recent_events(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return [asdict(e) for e in self.events[-limit:][::-1]]

    def prune_older_than(self, max_age_seconds: float) -> int:
        """Remove eventos capturados ha mais de `max_age_seconds` - chamado
        pelo housekeeping automatico (`app/housekeeping.py`) para evitar
        crescimento ilimitado da lista de eventos em memoria em nos de
        longa duracao sob ataque continuo. Retorna quantos foram removidos."""
        cutoff = time.time() - max_age_seconds
        with self._lock:
            before = len(self.events)
            self.events[:] = [e for e in self.events if e.timestamp >= cutoff]
            return before - len(self.events)

    def expire_challenges(self, max_age_seconds: float = 300.0) -> int:
        """Remove desafios de prova-de-trabalho ja emitidos ha mais de
        `max_age_seconds` e nunca resolvidos - evita acumulo indefinido de
        desafios abandonados em `self.challenges`."""
        cutoff = time.time() - max_age_seconds
        with self._lock:
            before = len(self.challenges)
            self.challenges = {cid: c for cid, c in self.challenges.items() if c.issued_at >= cutoff}
            return before - len(self.challenges)


honeypot = HoneypotLedger()
