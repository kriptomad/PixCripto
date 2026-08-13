"""
Configuracao central do PixCripto (servidor web, rede, ambiente).

Todos os parametros configuraveis do nO (host/porta HTTP, TLS, CORS, ambiente
mainnet/testnet/devnet, rate limits) vivem AQUI, lidos de variaveis de ambiente
(prefixo `PIXCRIPTO_`) ou de um arquivo `.env` na raiz do projeto (formato
simples `CHAVE=valor`, sem dependencia extra de `python-dotenv`).

Por que um modulo dedicado (em vez de `os.environ.get(...)` espalhado pelo
codigo, como antes)? Porque agora existem MUITOS parametros operacionais
(exchange API, compliance, DNS seeds, TLS) e um unico ponto de leitura:
  1. evita drift entre modulos que leem a "mesma" variavel de formas diferentes;
  2. permite ao Painel de Administracao (`admin_panel/`) escrever um `.env`
     novo e o node simplesmente reiniciar para aplicar;
  3. deixa claro, em um unico lugar, TODA a superficie de configuracao externa
     do sistema - importante para auditoria de seguranca.

Uso:
    from app.settings import settings
    settings.http_port
"""
from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass, field
from typing import List


ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
ENV_FILE = ROOT_DIR / ".env"


def _load_dotenv_into_os_environ(path: pathlib.Path = ENV_FILE) -> None:
    """Carrega um arquivo `.env` simples (`CHAVE=valor`, `#` para comentario)
    para `os.environ`, SEM sobrescrever variaveis ja definidas no ambiente real
    (o ambiente do processo/systemd/docker sempre tem prioridade sobre o
    arquivo - mesma semantica do `python-dotenv`)."""
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv_into_os_environ()


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _env_list(name: str, default: str = "") -> List[str]:
    return [p.strip() for p in os.environ.get(name, default).split(",") if p.strip()]


VALID_ENVIRONMENTS = ("mainnet", "testnet", "devnet")


@dataclass(frozen=True)
class Settings:
    # ------------------------------------------------------------------
    # Ambiente / rede logica (afeta ADDRESS_VERSION_BYTE, seeds default etc.)
    # ------------------------------------------------------------------
    environment: str = field(default_factory=lambda: os.environ.get("PIXCRIPTO_ENV", "devnet"))

    # ------------------------------------------------------------------
    # Servidor HTTP (API REST + JSON-RPC + WebSocket + UI)
    # ------------------------------------------------------------------
    http_host: str = field(default_factory=lambda: os.environ.get("PIXCRIPTO_HTTP_HOST", "0.0.0.0"))
    http_port: int = field(default_factory=lambda: int(os.environ.get("PIXCRIPTO_HTTP_PORT", "8000")))

    # TLS opcional - se ambos os caminhos existirem, `main.py` sobe HTTPS direto;
    # em producao real, o recomendado e terminar TLS num reverse proxy
    # (nginx/Caddy) na frente do uvicorn, mas a opcao nativa fica disponivel.
    tls_cert_file: str = field(default_factory=lambda: os.environ.get("PIXCRIPTO_TLS_CERT", ""))
    tls_key_file: str = field(default_factory=lambda: os.environ.get("PIXCRIPTO_TLS_KEY", ""))

    cors_origins: List[str] = field(default_factory=lambda: _env_list("PIXCRIPTO_CORS_ORIGINS", "*"))

    # ------------------------------------------------------------------
    # Rate limiting (anti-spam/DoS na API publica)
    # ------------------------------------------------------------------
    rate_limit_requests: int = field(default_factory=lambda: int(os.environ.get("PIXCRIPTO_RATE_LIMIT_REQUESTS", "120")))
    rate_limit_window_seconds: int = field(default_factory=lambda: int(os.environ.get("PIXCRIPTO_RATE_LIMIT_WINDOW", "60")))

    # ------------------------------------------------------------------
    # P2P (mantido compativel com as variaveis ja existentes em api.py)
    # ------------------------------------------------------------------
    p2p_host: str = field(default_factory=lambda: os.environ.get("PIXCRIPTO_P2P_HOST", "0.0.0.0"))
    p2p_port: int = field(default_factory=lambda: int(os.environ.get("PIXCRIPTO_P2P_PORT", "9333")))
    p2p_peers: List[str] = field(default_factory=lambda: _env_list("PIXCRIPTO_P2P_PEERS"))
    dns_seeds: List[str] = field(default_factory=lambda: _env_list(
        "PIXCRIPTO_DNS_SEEDS", "seed1.pixcripto.example,seed2.pixcripto.example"
    ))
    peer_discovery_enabled: bool = field(default_factory=lambda: _env_bool("PIXCRIPTO_PEER_DISCOVERY", True))
    # Limite maximo de peers conectados simultaneamente. Valor padrao conservador
    # (50) para evitar amplificacao excessiva de mensagens numa rede pequena; o
    # Bitcoin Core usa 125. Configuravel separadamente do limite hard-coded interno
    # para facilitar ajuste operacional sem recompilar.
    max_peers: int = field(default_factory=lambda: int(os.environ.get("PIXCRIPTO_MAX_PEERS", "50")))

    # ------------------------------------------------------------------
    # Exchange API (chaves HMAC para endpoints de trading estilo Binance)
    # ------------------------------------------------------------------
    exchange_api_enabled: bool = field(default_factory=lambda: _env_bool("PIXCRIPTO_EXCHANGE_API_ENABLED", True))

    # ------------------------------------------------------------------
    # Conformidade regulatoria (KYC/AML)
    # ------------------------------------------------------------------
    compliance_enabled: bool = field(default_factory=lambda: _env_bool("PIXCRIPTO_COMPLIANCE_ENABLED", True))
    kyc_required_above_pxc: float = field(default_factory=lambda: float(os.environ.get("PIXCRIPTO_KYC_THRESHOLD_PXC", "1000")))

    # ------------------------------------------------------------------
    # Administracao de conteudo (feed de noticias exibido no site principal)
    # ------------------------------------------------------------------
    # Token simples (compartilhado) exigido no header `X-Admin-Token` para
    # criar/editar/excluir noticias e fazer upload de imagens pelo site
    # principal. Isto e DIFERENTE do Painel de Administracao completo
    # (`admin_panel/`, porta 8600, nunca distribuido) - aqui e apenas o
    # necessario para o operador publicar noticias pela propria UI do site,
    # sem precisar acessar o painel interno.
    admin_content_token: str = field(default_factory=lambda: os.environ.get("PIXCRIPTO_ADMIN_CONTENT_TOKEN", ""))

    # ------------------------------------------------------------------
    # Login real do Painel de Administracao do site (`app/admin_auth.py`)
    # ------------------------------------------------------------------
    # Credenciais de BOOTSTRAP: usadas apenas para criar a PRIMEIRA conta
    # administradora, na primeira inicializacao (se nenhuma conta ja existir
    # no banco). Depois disso o operador deve trocar a senha pelo proprio
    # painel (`/admin/auth/change-password`) - fail-closed: sem estas
    # variaveis configuradas, o login do painel fica desabilitado.
    admin_bootstrap_username: str = field(default_factory=lambda: os.environ.get("PIXCRIPTO_ADMIN_USERNAME", ""))
    admin_bootstrap_password: str = field(default_factory=lambda: os.environ.get("PIXCRIPTO_ADMIN_PASSWORD", ""))
    admin_session_ttl_seconds: int = field(
        default_factory=lambda: int(os.environ.get("PIXCRIPTO_ADMIN_SESSION_TTL_SECONDS", str(12 * 3600)))
    )

    # ------------------------------------------------------------------
    # Gateway de pagamento externo (PSP real: Mercado Pago, Stripe, PagSeguro, etc.)
    # ------------------------------------------------------------------
    # Segredo compartilhado com o PSP escolhido para verificar a assinatura HMAC
    # dos webhooks de confirmacao de pagamento recebidos em
    # `POST /purchase/webhook/confirm`.
    # OBRIGATORIO em producao (PIXCRIPTO_ENV != devnet) - se ausente, o endpoint
    # retorna 503 e recusa todas as requisicoes (NUNCA processa sem verificacao).
    # Em devnet sem este segredo configurado, o endpoint opera sem verificacao
    # de assinatura (util para desenvolvimento local sem PSP real configurado).
    payment_webhook_secret: str = field(default_factory=lambda: os.environ.get("PIXCRIPTO_PAYMENT_WEBHOOK_SECRET", "").strip())
    # Nome do header HTTP que o PSP usa para enviar a assinatura HMAC-SHA256.
    # Todos os PSPs principais usam alguma variacao (ex.: Mercado Pago usa
    # `x-signature`, Stripe usa `Stripe-Signature`, PagSeguro usa um header
    # proprio). Padrao: `X-Webhook-Signature` (convencao generica).
    payment_webhook_signature_header: str = field(default_factory=lambda: os.environ.get("PIXCRIPTO_PAYMENT_WEBHOOK_SIGNATURE_HEADER", "X-Webhook-Signature").strip())

    # ------------------------------------------------------------------
    # Housekeeping automatico (`app/housekeeping.py`)
    # ------------------------------------------------------------------
    housekeeping_interval_seconds: int = field(
        default_factory=lambda: int(os.environ.get("PIXCRIPTO_HOUSEKEEPING_INTERVAL_SECONDS", str(6 * 3600)))
    )
    price_history_retention_days: int = field(
        default_factory=lambda: int(os.environ.get("PIXCRIPTO_PRICE_HISTORY_RETENTION_DAYS", "180"))
    )
    honeypot_retention_seconds: int = field(
        default_factory=lambda: int(os.environ.get("PIXCRIPTO_HONEYPOT_RETENTION_SECONDS", str(30 * 86400)))
    )
    # Destino secundario para backup offsite (drive de rede, pasta sincronizada
    # com nuvem local tipo OneDrive/Dropbox, segundo disco, etc.). Quando
    # configurado, o zip gerado por `create_backup()` e copiado automaticamente
    # para este diretorio logo apos o backup local. Se a copia falhar, apenas
    # um warning e registrado — o backup local ja concluido NAO e desfeito.
    # Deixar vazio (padrao) desabilita o backup secundario sem nenhum efeito.
    backup_offsite_dir: str = field(
        default_factory=lambda: os.environ.get("PIXCRIPTO_BACKUP_OFFSITE_DIR", "").strip()
    )
    # ------------------------------------------------------------------
    # Monitoramento e alertas (app/monitoring.py)
    # ------------------------------------------------------------------
    # URL do webhook para onde os alertas sao enviados via HTTP POST.
    # Aceita qualquer servico que consuma JSON (Slack, Discord, PagerDuty, etc.)
    # Se vazio, alertas sao apenas logados localmente e persistidos no banco.
    alert_webhook_url: str = field(default_factory=lambda: os.environ.get("PIXCRIPTO_ALERT_WEBHOOK_URL", ""))
    # Janela de rate-limiting: no maximo 1 alerta por event_type neste intervalo (segundos).
    # Evita inundar o webhook com alertas identicos repetidos (ex: falha de brute-force em massa).
    alert_rate_limit_seconds: int = field(
        default_factory=lambda: int(os.environ.get("PIXCRIPTO_ALERT_RATE_LIMIT_SECONDS", "60"))
    )

    def is_valid(self) -> bool:
        return self.environment in VALID_ENVIRONMENTS

    def tls_enabled(self) -> bool:
        return bool(self.tls_cert_file and self.tls_key_file)


settings = Settings()

if not settings.is_valid():
    raise ValueError(
        f"PIXCRIPTO_ENV invalido: {settings.environment!r} - use um de {VALID_ENVIRONMENTS}"
    )
