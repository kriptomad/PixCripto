"""
Painel de Administração do PixCripto (Sentimento: "cockpit" do operador).

⚠️ **NÃO É PARTE DO PRODUTO DISTRIBUÍDO.** Este painel roda como um processo
SEPARADO, em uma porta diferente do node (`ADMIN_PANEL_PORT`, padrão 8600), e
NÃO fica dentro do pacote `app/` — por isso `scripts/build_distribution.py`
(que só compila o conteúdo de `app/`) nunca o inclui na distribuição final.
Use-o apenas na SUA máquina de operação/administração, nunca o exponha
publicamente na internet (ele tem poder de configurar toda a rede e disparar
o build de distribuição).

O que dá para fazer aqui:
  1. Editar as configurações operacionais do node (`.env` -> `app/settings.py`):
     ambiente (mainnet/testnet/devnet), porta HTTP/P2P, CORS, rate limit,
     DNS seeds, limite de KYC.
  2. Gerenciar a lista curada de peers (`seeds.json`) usada pela descoberta
     de rede (`app/network_config.py`).
  3. Administrar conformidade regulatória: ver/editar a lista de sanções,
     consultar o relatório de atividade suspeita (SAR).
  4. Ver o relatório do honeypot (tentativas de exploração detectadas).
  5. Disparar `scripts/build_distribution.py` para gerar a distribuição
     bytecode-only pronta para lançar na rede real.

Uso:
    cd PixCripto
    python admin_panel/main.py
    # abre em http://127.0.0.1:8600
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))  # permite `from app import ...` rodando este script diretamente

from app import network_config          # noqa: E402
from app.settings import ENV_FILE, settings, VALID_ENVIRONMENTS  # noqa: E402
from app.compliance import compliance_engine  # noqa: E402
from app.honeypot import honeypot        # noqa: E402

import os

# Porta configuravel via variavel de ambiente (util quando 8600 estiver
# bloqueada por firewall/antivirus ou reservada pelo Windows -
# `netsh interface ipv4 show excludedportrange protocol=tcp`).
ADMIN_PANEL_PORT = int(os.environ.get("PIXCRIPTO_ADMIN_PANEL_PORT", "8600"))

app = FastAPI(title="PixCripto - Painel de Administração (uso interno, NAO distribuir)")
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))


def _read_env_file() -> dict:
    values: dict[str, str] = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                values[k.strip()] = v.strip()
    return values


def _write_env_file(values: dict) -> None:
    lines = ["# Gerado/editado pelo Painel de Administracao do PixCripto", ""]
    for key, value in sorted(values.items()):
        lines.append(f"{key}={value}")
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    env_values = _read_env_file()
    seeds = network_config.load_curated_seeds()
    sar_events = compliance_engine.suspicious_activity_report("warning", 50)
    honeypot_report = {
        "top_suspects": honeypot.top_suspects(20),
        "recent_events": honeypot.recent_events(30),
    }
    return templates.TemplateResponse(request, "dashboard.html", {
        "env_values": env_values,
        "settings": settings,
        "valid_environments": VALID_ENVIRONMENTS,
        "seeds": seeds,
        "sar_events": sar_events,
        "honeypot_report": honeypot_report,
    })


@app.post("/settings/save")
def save_settings(
    PIXCRIPTO_ENV: str = Form(...),
    PIXCRIPTO_HTTP_HOST: str = Form(...),
    PIXCRIPTO_HTTP_PORT: str = Form(...),
    PIXCRIPTO_CORS_ORIGINS: str = Form(...),
    PIXCRIPTO_RATE_LIMIT_REQUESTS: str = Form(...),
    PIXCRIPTO_RATE_LIMIT_WINDOW: str = Form(...),
    PIXCRIPTO_P2P_HOST: str = Form(...),
    PIXCRIPTO_P2P_PORT: str = Form(...),
    PIXCRIPTO_P2P_PEERS: str = Form(""),
    PIXCRIPTO_DNS_SEEDS: str = Form(""),
    PIXCRIPTO_PEER_DISCOVERY: str = Form("true"),
    PIXCRIPTO_EXCHANGE_API_ENABLED: str = Form("true"),
    PIXCRIPTO_COMPLIANCE_ENABLED: str = Form("true"),
    PIXCRIPTO_KYC_THRESHOLD_PXC: str = Form(...),
):
    """Escreve os valores no `.env` da raiz do projeto. O node precisa ser
    REINICIADO para aplicar (o processo do servidor le o `.env` apenas na
    inicializacao, via `app/settings.py`) - mesma semantica de qualquer
    servico 12-factor configurado por variaveis de ambiente."""
    values = {
        "PIXCRIPTO_ENV": PIXCRIPTO_ENV,
        "PIXCRIPTO_HTTP_HOST": PIXCRIPTO_HTTP_HOST,
        "PIXCRIPTO_HTTP_PORT": PIXCRIPTO_HTTP_PORT,
        "PIXCRIPTO_CORS_ORIGINS": PIXCRIPTO_CORS_ORIGINS,
        "PIXCRIPTO_RATE_LIMIT_REQUESTS": PIXCRIPTO_RATE_LIMIT_REQUESTS,
        "PIXCRIPTO_RATE_LIMIT_WINDOW": PIXCRIPTO_RATE_LIMIT_WINDOW,
        "PIXCRIPTO_P2P_HOST": PIXCRIPTO_P2P_HOST,
        "PIXCRIPTO_P2P_PORT": PIXCRIPTO_P2P_PORT,
        "PIXCRIPTO_P2P_PEERS": PIXCRIPTO_P2P_PEERS,
        "PIXCRIPTO_DNS_SEEDS": PIXCRIPTO_DNS_SEEDS,
        "PIXCRIPTO_PEER_DISCOVERY": PIXCRIPTO_PEER_DISCOVERY,
        "PIXCRIPTO_EXCHANGE_API_ENABLED": PIXCRIPTO_EXCHANGE_API_ENABLED,
        "PIXCRIPTO_COMPLIANCE_ENABLED": PIXCRIPTO_COMPLIANCE_ENABLED,
        "PIXCRIPTO_KYC_THRESHOLD_PXC": PIXCRIPTO_KYC_THRESHOLD_PXC,
    }
    _write_env_file(values)
    return RedirectResponse("/", status_code=303)


@app.post("/seeds/add")
def seeds_add(peer: str = Form(...)):
    current = network_config.load_curated_seeds()
    current.append(peer.strip())
    network_config.save_curated_seeds(current)
    return RedirectResponse("/", status_code=303)


@app.post("/seeds/remove")
def seeds_remove(peer: str = Form(...)):
    current = [p for p in network_config.load_curated_seeds() if p != peer]
    network_config.save_curated_seeds(current)
    return RedirectResponse("/", status_code=303)


@app.post("/compliance/sanctions/add")
def sanctions_add(entry: str = Form(...), reason: str = Form(...)):
    compliance_engine.add_to_sanctions_list(entry.strip(), reason.strip())
    return RedirectResponse("/", status_code=303)


@app.post("/compliance/sanctions/remove")
def sanctions_remove(entry: str = Form(...)):
    compliance_engine.remove_from_sanctions_list(entry.strip())
    return RedirectResponse("/", status_code=303)


@app.post("/build/distribution")
def build_distribution():
    """Dispara `scripts/build_distribution.py` (gera `dist/app/` bytecode-only,
    SEM incluir este painel nem o `.env`/`seeds.json` - ver o proprio script
    e `scripts/build_distribution.py` para a lista explicita de exclusoes)."""
    result = subprocess.run(
        [sys.executable, str(ROOT_DIR / "scripts" / "build_distribution.py")],
        capture_output=True, text=True, cwd=str(ROOT_DIR),
    )
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


if __name__ == "__main__":
    import uvicorn
    # host 127.0.0.1 explicito: NUNCA expor este painel na rede (0.0.0.0)
    uvicorn.run(app, host="127.0.0.1", port=ADMIN_PANEL_PORT)
