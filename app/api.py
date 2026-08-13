"""
API REST do PixCripto - construida com FastAPI.

Endpoints principais:
- Carteiras: criar carteira, consultar saldo
- Transacoes: criar/enviar transacao (assinada no cliente ou aqui para fins de demo)
- Pagamento via QR Code: gerar QR de cobranca, decodificar QR e pagar
- Mineracao: obter bloco candidato, minerar (endpoint dispara o motor GPU/CPU),
  submeter prova de trabalho encontrada por um minerador externo (pool/hardware proprio)
- Compra de moeda: cotar e comprar PXC com Reais (taxa de 7,38% a cada R$100)
- Explorador simples da cadeia (blocos, dificuldade, status do backend de mineracao)
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac as _hmac
import logging
import os
import pathlib
import secrets
import time
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, UploadFile, File, Form, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from . import crypto_utils, mining, purchase, qrcode_utils, storage, root_rules
from .bruteforce_guard import BruteForceLockedError, guard as bruteforce_guard
from .settings import settings
from . import network_config
from .compliance import compliance_engine, ComplianceError, STRUCTURING_WINDOW_SECONDS
from . import exchange_api
from . import news
from .gold_oracle import gold_oracle
from .honeypot import honeypot, HONEYPOT_CHALLENGE_BITS
from .layer2 import L2Rollup, L2Transaction, L2_BRIDGE_ADDRESS
from .market import MarketEngine, MarketError
from .models import Blockchain, Transaction, COINBASE_SENDER
from .network import P2PNode
from .rpc import dispatcher, RPCError, INVALID_PARAMS
from .wallet import Wallet
from .ws_hub import ws_hub
from . import hd_wallet
from . import source_integrity
from . import admin_auth
from . import cms
from . import feature_flags
from . import housekeeping
from . import media
from . import monitoring
from . import site_settings
from . import user_accounts
from . import multisig as multisig_mod

app = FastAPI(
    title="PixCripto API",
    description="Pagamento instantaneo descentralizado inspirado em Pix + Bitcoin/Ethereum, "
                "com arquitetura L2 (rollup), mineracao GPU (CUDA/NVIDIA ou OpenCL-ROCm/AMD), "
                "rede P2P real (gossip/IBD/reorg) e lastro em ouro (XAU) com controle automatico de dump",
    version="0.5.0",
)

_APP_DIR = pathlib.Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(_APP_DIR / "static")), name="static")
_templates = Jinja2Templates(directory=str(_APP_DIR / "templates"))

# CORS: necessario para a nova UI web (React SPA em `frontend/`), que roda em
# seu proprio servidor de desenvolvimento (porta do Vite) e, em producao, pode
# ser servida de um dominio/porta diferente do node antes de um build final.
# `PIXCRIPTO_CORS_ORIGINS` (settings.py) controla as origens permitidas -
# "*" por padrao em devnet, restrinja para a(s) origem(ns) reais em producao.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,  # sem cookies/sessao - autenticacao e via chave assimetrica/token, nao cookie
    allow_methods=["*"],
    allow_headers=["*"],
)

# difficulty_mode="demo": teto de dificuldade reduzido para permitir mineracao real
# em hardware comum durante testes. Use "mainnet_like" para refletir o crescimento
# matematico completo (20x a cada 2 blocos) ate o teto equivalente ao Bitcoin ~2020.
storage.init_db()  # garante que as tabelas existam ANTES de L2Rollup recarregar seu estado
admin_auth.bootstrap_admin_user()  # cria a 1a conta do painel se configurada via .env (idempotente)
blockchain = Blockchain(difficulty_mode="demo")
blockchain.rehydrate_from_persisted_blocks(storage.load_full_chain())
blockchain.rehydrate_pending_transactions(storage.load_pending_transactions())

# ---------------------------------------------------------------------------
# Rede P2P (secao 7 do guia) - cada no real conecta a bootnodes/peers via
# variaveis de ambiente e participa do gossip de tx/blocos com o resto da rede.
# Configuracao via env: PIXCRIPTO_P2P_HOST, PIXCRIPTO_P2P_PORT, PIXCRIPTO_P2P_PEERS
# (lista "host:porta,host2:porta2" de bootnodes/peers conhecidos).
# ---------------------------------------------------------------------------
P2P_HOST = settings.p2p_host
P2P_PORT = settings.p2p_port
# Separa peers manuais (configurados pelo operador) de peers resolvidos via DNS
# seed para que o campo `discovered_via` de cada peer seja correto desde o inicio.
# Peers manuais: PIXCRIPTO_P2P_PEERS + seeds.json curado.
# Peers DNS seed: resolvidos por `discover_bootstrap_peers` via PIXCRIPTO_DNS_SEEDS.
_manual_bootstrap = list(settings.p2p_peers) + network_config.load_curated_seeds()
_dns_seed_bootstrap = network_config.discover_bootstrap_peers([]) if settings.peer_discovery_enabled else []
# Remove dos dns_seed_bootstrap os peers que ja estao em manual (evita duplicata)
_manual_set = set(_manual_bootstrap)
_dns_seed_bootstrap = [p for p in _dns_seed_bootstrap if p not in _manual_set]

p2p_node: Optional[P2PNode] = None
_p2p_loop: Optional[asyncio.AbstractEventLoop] = None


def _ws_broadcast(event: dict) -> None:
    """Envia um evento para todos os clientes WebSocket conectados
    (`/ws/events`). Assim como o broadcast P2P, precisa de
    `run_coroutine_threadsafe` quando chamado de um handler sincrono do
    FastAPI (threadpool) - o hub roda no event loop asyncio principal."""
    if _p2p_loop is not None:
        asyncio.run_coroutine_threadsafe(ws_hub.broadcast(event), _p2p_loop)


def _on_tx_pending_broadcast(tx: Transaction) -> None:
    """Gancho unico chamado sempre que uma tx entra na mempool (de QUALQUER
    origem: API HTTP, swap engine, ponte L2 ou rede P2P): persiste no SQLite
    E propaga (gossip) para os peers conectados. `asyncio.run_coroutine_threadsafe`
    e necessario porque este gancho e chamado de dentro do threadpool sincrono
    do FastAPI, mas o `P2PNode` roda no event loop asyncio principal."""
    storage.persist_pending_transaction(tx)
    if p2p_node is not None and _p2p_loop is not None:
        asyncio.run_coroutine_threadsafe(p2p_node.broadcast_transaction(tx), _p2p_loop)
    _ws_broadcast({"event": "pendingTransaction", "data": tx.to_dict()})


blockchain.set_persistence_hooks(
    on_pending=_on_tx_pending_broadcast,
    on_confirmed=lambda tx: storage.remove_pending_transaction(tx.tx_id),
)
l2 = L2Rollup(blockchain)
market = MarketEngine(blockchain)


def broadcast_mined_block(block) -> None:
    """Propaga um bloco recem-minerado LOCALMENTE para os peers da rede P2P -
    chamado apos `storage.persist_block(block)` nos dois endpoints de mineracao
    (`/mining/mine` e `/mining/submit-proof`). Sem isto, cada no minerador
    ficaria "ilhado": os demais nos da rede nunca saberiam do bloco novo."""
    if p2p_node is not None and _p2p_loop is not None:
        asyncio.run_coroutine_threadsafe(p2p_node.broadcast_block(block), _p2p_loop)
    _ws_broadcast({"event": "newBlock", "data": block.to_dict()})


def _on_block_received_from_network(block) -> None:
    """Chamado pelo `P2PNode` quando um UNICO bloco novo (extensao simples da
    ponta da cadeia, nao um reorg) e recebido de um peer e aceito - persiste
    no SQLite local (sem isto, blocos recebidos via P2P nunca eram gravados
    em disco, um gap real de persistencia) e notifica clientes WebSocket."""
    storage.persist_block(block)
    storage.persist_contract_logs(blockchain._last_accepted_block_logs)
    _ws_broadcast({"event": "newBlock", "data": block.to_dict()})


def _on_chain_replaced_from_network(candidate) -> None:
    """Chamado pelo `P2PNode` apos um reorg (`try_replace_chain` bem sucedido) -
    persiste TODOS os blocos da nova cadeia vencedora (idempotente: usa
    INSERT OR REPLACE) e notifica clientes WebSocket com o novo topo."""
    for block in candidate[1:]:
        storage.persist_block(block)
    if len(candidate) > 1:
        _ws_broadcast({"event": "chainReorg", "data": candidate[-1].to_dict()})


@app.on_event("startup")
async def _start_p2p_node() -> None:
    global p2p_node, _p2p_loop
    _p2p_loop = asyncio.get_event_loop()
    p2p_node = P2PNode(
        blockchain, host=P2P_HOST, port=P2P_PORT,
        on_block_applied=_on_block_received_from_network,
        on_chain_replaced=_on_chain_replaced_from_network,
    )
    await p2p_node.start(bootstrap_peers=_manual_bootstrap, dns_seed_peers=_dns_seed_bootstrap)


@app.on_event("shutdown")
async def _stop_p2p_node() -> None:
    if p2p_node is not None:
        await p2p_node.stop()


def _is_valid_recipient(address: str) -> bool:
    """
    Endereco de destinatario valido = ou um endereco de carteira normal
    (Base58Check secp256k1), ou um dos enderecos de SISTEMA reconhecidos
    (ex.: ponte L2, escrow de swap) - usuarios legitimamente enviam PXC para
    esses enderecos-pseudocontrato (deposito L2, criacao de ordem de troca).
    """
    return address in root_rules.SYSTEM_ADDRESSES or crypto_utils.is_valid_address(address)


def _run_aml_check(sender: str, recipient: str, amount: float) -> None:
    """Gancho de conformidade chamado ANTES de qualquer transacao de
    transferencia entrar na mempool: bloqueia contrapartes sancionadas
    (levanta 403) e registra alertas de AML (limite/estruturacao) na trilha
    de auditoria sem impedir a transacao em si (mesmo comportamento de um
    banco real: o alerta vai para compliance revisar, a tx segue seu curso
    normalmente a menos que a contraparte esteja sancionada)."""
    if not settings.compliance_enabled:
        return
    if sender in root_rules.SYSTEM_ADDRESSES or recipient in root_rules.SYSTEM_ADDRESSES:
        return  # pontes/escrow do proprio sistema nao passam por AML de usuario final
    try:
        recent = storage.recent_sender_amounts(sender, STRUCTURING_WINDOW_SECONDS)
        compliance_engine.check_transaction(sender, recipient, amount, sender_recent_amounts=recent)
    except ComplianceError as exc:
        raise HTTPException(status_code=403, detail=str(exc))


@app.exception_handler(ValueError)
def _value_error_handler(request, exc: ValueError):
    # normaliza erros de validacao internos (ex.: endereco malformado) para 400,
    # sem vazar stack trace/detalhes internos ao cliente (endurecimento pos-auditoria).
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(Exception)
def _generic_error_handler(request, exc: Exception):
    # qualquer excecao nao tratada retorna uma mensagem GENERICA ao cliente -
    # detalhes (stack trace, versoes de biblioteca, paths internos) NUNCA vazam
    # na resposta HTTP (mitigacao de "erros verbosos" apontada na auditoria).
    # O detalhe real fica apenas no log do servidor (stderr/uvicorn).
    import logging
    logging.getLogger("pixcripto").exception("Erro interno nao tratado: %s", exc)
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=500, content={"detail": "Erro interno do servidor"})


# ---------------------------------------------------------------------------
# Rate limiting simples (token bucket em memoria, por IP) - mitigacao basica de
# flood/DoS/bruteforce. Para producao real, prefira um rate-limiter dedicado
# (ex.: proxy reverso, Redis + sliding window) compartilhado entre instancias.
# ---------------------------------------------------------------------------
import collections
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse as _JSONResponse

_rate_buckets: dict = collections.defaultdict(list)
_RATE_LIMIT_LOCK = __import__("threading").Lock()


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        key = f"{client_ip}:{request.url.path}"
        with _RATE_LIMIT_LOCK:
            bucket = _rate_buckets[key]
            # mantem apenas timestamps do ultimo minuto (janela deslizante)
            bucket[:] = [t for t in bucket if now - t < 60]
            if len(bucket) >= root_rules.RATE_LIMIT_REQUESTS_PER_MINUTE:
                return _JSONResponse(
                    status_code=429,
                    content={"detail": "Muitas requisicoes; aguarde um momento antes de tentar novamente."},
                )
            bucket.append(now)
        return await call_next(request)


app.add_middleware(RateLimitMiddleware)


@app.on_event("startup")
def _startup():
    storage.init_db()
    admin_auth.bootstrap_admin_user()
    housekeeping.start_scheduler()


@app.on_event("shutdown")
def _shutdown_housekeeping():
    housekeeping.stop_scheduler()


# ---------------------------------------------------------------------------
# Modo manutencao: quando ligado pelo painel de administracao
# (`feature_flags.maintenance_mode`), TODA a API publica responde 503,
# exceto o proprio login/painel de administracao (`/admin/*`), health-check
# basico e os arquivos estaticos do SPA (para a tela de login continuar
# carregando mesmo com o site em manutencao).
# ---------------------------------------------------------------------------
_MAINTENANCE_ALLOWED_PREFIXES = ("/admin", "/app", "/static", "/rules/root-hash", "/docs", "/openapi.json", "/redoc")


class MaintenanceModeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        path = request.url.path
        if any(path == p or path.startswith(p + "/") for p in _MAINTENANCE_ALLOWED_PREFIXES) or path in _MAINTENANCE_ALLOWED_PREFIXES:
            return await call_next(request)
        try:
            if feature_flags.is_enabled("maintenance_mode"):
                return _JSONResponse(
                    status_code=503,
                    content={"detail": "PixCripto esta em manutencao programada. Tente novamente em instantes."},
                )
        except Exception:
            pass  # nunca deixa uma falha ao ler a flag derrubar o servidor inteiro
        return await call_next(request)


app.add_middleware(MaintenanceModeMiddleware)


# ---------------------------------------------------------------------------
# Carteiras
# ---------------------------------------------------------------------------

class CreateWalletRequest(BaseModel):
    label: str = ""


@app.post("/wallet/create")
def create_wallet(req: CreateWalletRequest):
    wallet = Wallet.create(label=req.label)
    storage.persist_wallet(wallet.address, wallet.public_key, wallet.label)
    return {
        "message": "Guarde sua chave privada em local seguro. Ela NAO sera mostrada novamente.",
        **wallet.to_full_dict(),
    }


@app.get("/wallet/{address}/balance")
def get_balance(address: str):
    return {"address": address, "balance": blockchain.get_balance(address), "coin": purchase.COIN_NAME}


@app.get("/wallet/{address}/qrcode")
def wallet_qrcode(address: str, amount: Optional[float] = None, memo: str = ""):
    payload = qrcode_utils.build_payment_payload(address, amount, memo)
    image_b64 = qrcode_utils.generate_qr_base64(payload)
    return {"payload": payload, "qrcode_png_base64": image_b64}


class ExportKeystoreRequest(BaseModel):
    private_key: str = Field(..., description="Chave privada a ser criptografada (nunca e persistida no servidor)")
    password: str = Field(..., min_length=8, description="Senha usada para derivar a chave de criptografia (scrypt)")
    label: str = ""


@app.post("/wallet/export-keystore")
def export_keystore(req: ExportKeystoreRequest):
    """
    Converte uma chave privada em um arquivo keystore JSON criptografado
    (scrypt + AES-256-GCM + MAC), no mesmo espirito do formato Ethereum V3.
    ⚠️ Esta rota e uma CONVENIENCIA - o ideal em producao e gerar o keystore
    localmente no cliente (a chave privada nunca deveria trafegar pela rede,
    nem em texto claro nem via TLS); ela existe para permitir migrar
    facilmente uma carteira ja criada via `/wallet/create` para um arquivo
    protegido por senha, adequado para backup/armazenamento em disco.
    """
    try:
        keystore = crypto_utils.create_keystore(req.private_key, req.password)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Chave privada invalida: {exc}")
    keystore["label"] = req.label
    return {"message": "Guarde este keystore e a senha usada - sem ambos e impossivel recuperar a chave.",
            "keystore": keystore}


class ImportKeystoreRequest(BaseModel):
    keystore: dict = Field(..., description="Objeto keystore JSON gerado por /wallet/export-keystore")
    password: str = Field(..., min_length=1)


@app.post("/wallet/import-keystore")
def import_keystore(req: ImportKeystoreRequest, request: Request):
    """Recupera a chave privada de um keystore JSON, dado a senha correta.
    Retorna a chave privada em texto claro na resposta - use apenas em
    ambiente confiavel (ideal: fazer isto localmente no cliente, nunca
    enviando a senha para um servidor remoto).

    Protegido por `bruteforce_guard`: tentativas repetidas de senha errada a
    partir do mesmo IP sofrem bloqueio (cooldown) exponencialmente crescente -
    o scrypt do keystore ja torna cada tentativa computacionalmente cara,
    e este guard adiciona uma segunda camada no nivel da API contra scripts
    que tentem paralelizar tentativas de senha via multiplas requisicoes."""
    scope = "wallet_import_keystore"
    identity = _client_ip(request)
    try:
        bruteforce_guard.check(scope, identity)
    except BruteForceLockedError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    try:
        private_key = crypto_utils.load_keystore(req.keystore, req.password)
    except ValueError as exc:
        bruteforce_guard.record_failure(scope, identity)
        raise HTTPException(status_code=400, detail=str(exc))
    bruteforce_guard.record_success(scope, identity)
    address = req.keystore.get("address", "")
    return {"address": address, "private_key": private_key}


# ---------------------------------------------------------------------------
# Carteira HD (Hierarquica Deterministica - BIP39/32/44-style)
# ---------------------------------------------------------------------------

class CreateMnemonicRequest(BaseModel):
    strength_bits: int = Field(128, description="128 = 12 palavras, 256 = 24 palavras (mais entropia)")


@app.post("/wallet/hd/create")
def create_hd_wallet(req: CreateMnemonicRequest):
    """
    Gera uma NOVA seed phrase (mnemonic) de 12 ou 24 palavras e ja deriva a
    primeira conta (indice 0) a partir dela, exatamente como MetaMask/carteiras
    Bitcoin modernas fazem. Guarde a seed phrase com MAXIMO cuidado: quem a
    possuir controla TODAS as contas derivadas dela, presentes e futuras -
    ela nunca e enviada nem armazenada pelo servidor.
    """
    mnemonic = hd_wallet.generate_mnemonic(req.strength_bits)
    private_key_hex, public_key_hex, address = hd_wallet.derive_account(mnemonic, account_index=0)
    storage.persist_wallet(address, public_key_hex, "hd-account-0")
    return {
        "message": ("Guarde estas palavras em ordem, offline, em local seguro. "
                     "Quem tiver a seed phrase controla todas as contas derivadas dela. "
                     "Ela NAO sera mostrada novamente."),
        "mnemonic": mnemonic,
        "account_index": 0,
        "address": address,
        "public_key": public_key_hex,
        "private_key": private_key_hex,
    }


class DeriveAccountRequest(BaseModel):
    mnemonic: str = Field(..., description="Seed phrase existente (12 ou 24 palavras)")
    account_index: int = Field(0, ge=0, description="Indice da conta a derivar (0, 1, 2, ...)")
    passphrase: str = Field("", description="Passphrase opcional extra (25a palavra / BIP-39 'senha')")


@app.post("/wallet/hd/derive")
def derive_hd_account(req: DeriveAccountRequest):
    """
    Deriva (ou re-deriva) uma conta especifica a partir de uma seed phrase ja
    existente, seguindo o caminho m/44'/7777'/0'/0/{account_index}. Chamar
    novamente com a MESMA seed phrase + indice sempre retorna a MESMA conta -
    e assim que uma carteira HD permite recuperar todas as contas apenas
    com as 12/24 palavras, sem precisar guardar cada chave privada individualmente.
    """
    try:
        private_key_hex, public_key_hex, address = hd_wallet.derive_account(
            req.mnemonic, account_index=req.account_index, passphrase=req.passphrase
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    storage.persist_wallet(address, public_key_hex, f"hd-account-{req.account_index}")
    return {
        "account_index": req.account_index,
        "address": address,
        "public_key": public_key_hex,
        "private_key": private_key_hex,
    }


class ValidateMnemonicRequest(BaseModel):
    mnemonic: str


@app.post("/wallet/hd/validate")
def validate_hd_mnemonic(req: ValidateMnemonicRequest):
    """Verifica se uma seed phrase e valida (palavras conhecidas + checksum
    correto) SEM derivar nenhuma chave - util para validar entrada do usuario
    numa UI antes de tentar recuperar a carteira."""
    return {"valid": hd_wallet.validate_mnemonic(req.mnemonic)}


class NextAddressRequest(BaseModel):
    mnemonic: str = Field(..., description="Seed phrase existente (12 ou 24 palavras)")
    passphrase: str = Field("", description="Passphrase opcional extra (25a palavra / BIP-39 'senha')")
    start_index: int = Field(0, ge=0, description="Indice a partir do qual comecar a busca")


@app.post("/wallet/hd/next-address")
def hd_next_unused_address(req: NextAddressRequest):
    """
    Rotacao automatica de endereco ("conta auto-mutavel"): devolve sempre uma
    conta NOVA e ainda sem uso derivada da mesma seed phrase, seguindo o
    conceito de "gap limit" do BIP-44 (Bitcoin/Ethereum modernos fazem o
    mesmo). Usar um endereco novo a cada recebimento reduz drasticamente a
    superficie de ataque de forca bruta/analise de cadeia contra um unico
    par de chaves, sem exigir nenhum backup alem da seed phrase original.
    """
    def _is_used(address: str) -> bool:
        history = market.address_history(address)
        has_activity = bool(history.get("confirmed_transactions") or history.get("pending_transactions"))
        has_balance = blockchain.get_balance(address) > 0
        return has_activity or has_balance

    try:
        index, private_key_hex, public_key_hex, address = hd_wallet.find_next_unused_account(
            req.mnemonic, _is_used, passphrase=req.passphrase, start_index=req.start_index,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    storage.persist_wallet(address, public_key_hex, f"hd-account-{index}-auto-rotated")
    return {
        "account_index": index,
        "address": address,
        "public_key": public_key_hex,
        "private_key": private_key_hex,
        "gap_limit": hd_wallet.HD_GAP_LIMIT,
    }


# ---------------------------------------------------------------------------
# Carteiras Multi-assinatura M-de-N (multisig)
# ---------------------------------------------------------------------------
# Implementa o fluxo PSBT-like simplificado para carteiras M-de-N:
#   POST /multisig/create             — cria a carteira (address derivado deterministicamente)
#   GET  /multisig/proposals/{id}     — consulta estado de uma proposta
#   GET  /multisig/{address}          — consulta dados de uma carteira multisig
#   POST /multisig/propose            — cria proposta de transacao
#   POST /multisig/{id}/sign          — um participante assina a proposta
#   POST /multisig/{id}/finalize      — submete a tx quando M assinaturas coletadas
# ---------------------------------------------------------------------------

class CreateMultisigWalletRequest(BaseModel):
    participant_public_keys: List[str] = Field(
        ..., min_length=1,
        description="Lista de N chaves publicas (hex secp256k1) dos participantes"
    )
    threshold: int = Field(
        ..., ge=1,
        description="M: numero minimo de assinaturas necessarias para gastar"
    )


@app.post("/multisig/create")
def create_multisig_wallet(req: CreateMultisigWalletRequest):
    """Cria uma carteira multi-assinatura M-de-N.

    O endereco e derivado deterministicamente de M e das N chaves publicas
    ordenadas — nenhum segredo e gerado nem armazenado pelo servidor.
    """
    try:
        result = multisig_mod.create_multisig_wallet(
            req.participant_public_keys, req.threshold
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


class ProposeMultisigTransactionRequest(BaseModel):
    multisig_address: str
    recipient: str
    amount: float = Field(..., gt=0, le=root_rules.MAX_TRANSACTION_AMOUNT)
    memo: str = Field("", max_length=root_rules.MAX_MEMO_LENGTH_BYTES)
    fee: float = Field(0.0, ge=0, le=root_rules.MAX_TRANSACTION_AMOUNT)
    network_id: int = Field(default_factory=lambda: root_rules.NETWORK_ID)


@app.post("/multisig/propose")
def propose_multisig_transaction(req: ProposeMultisigTransactionRequest):
    """Cria uma proposta de transacao multisig aguardando coleta de assinaturas.

    Retorna o `signing_payload` (JSON canonico) que cada participante deve
    assinar localmente com sua chave privada.
    """
    try:
        result = multisig_mod.propose_multisig_transaction(
            multisig_address=req.multisig_address,
            recipient=req.recipient,
            amount=req.amount,
            memo=req.memo,
            fee=req.fee,
            network_id=req.network_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


class SignMultisigProposalRequest(BaseModel):
    public_key: str = Field(..., description="Chave publica do participante que esta assinando")
    signature: str = Field(
        ..., description="Assinatura ECDSA hex sobre o signing_payload da proposta"
    )


@app.post("/multisig/{proposal_id}/sign")
def sign_multisig_proposal(proposal_id: str, req: SignMultisigProposalRequest):
    """Adiciona a assinatura de um participante a proposta.

    A assinatura deve ser produzida sobre o `signing_payload` da proposta
    com `crypto_utils.sign_message(private_key, payload.encode('utf-8'))`.
    Rejeita assinaturas invalidas, de chaves estranhas ou duplicadas.
    """
    try:
        result = multisig_mod.sign_multisig_proposal(
            proposal_id=proposal_id,
            public_key=req.public_key,
            signature=req.signature,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


@app.get("/multisig/proposals/{proposal_id}")
def get_multisig_proposal(proposal_id: str):
    """Retorna o estado atual de uma proposta multisig (assinaturas coletadas,
    threshold, payload para assinatura, status)."""
    info = multisig_mod.get_proposal_info(proposal_id)
    if not info:
        raise HTTPException(status_code=404, detail="Proposta nao encontrada")
    return info


@app.post("/multisig/{proposal_id}/finalize")
def finalize_multisig_proposal(proposal_id: str):
    """Finaliza a proposta: monta a Transaction com os campos multisig e a
    submete ao fluxo normal da blockchain.

    Exige que o numero de assinaturas coletadas seja >= threshold da carteira.
    A proposta e marcada como 'finalized' para evitar dupla submissao.
    """
    try:
        tx = multisig_mod.finalize_and_submit_multisig_proposal(proposal_id, blockchain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "message": "Transacao multisig aceita e aguardando mineracao",
        "tx_id": tx.tx_id,
        "proposal_id": proposal_id,
    }


@app.get("/multisig/{address}")
def get_multisig_wallet(address: str):
    """Retorna informacoes de uma carteira multisig cadastrada (threshold,
    participantes, data de criacao)."""
    info = multisig_mod.get_multisig_wallet_info(address)
    if not info:
        raise HTTPException(status_code=404, detail="Carteira multisig nao encontrada")
    return info


# ---------------------------------------------------------------------------
# Transacoes / Pagamentos (direto em carteira ou via QR code)
# ---------------------------------------------------------------------------

class SendTransactionRequest(BaseModel):
    sender_private_key: str = Field(..., description="Chave privada do pagador (assinatura local)")
    sender_public_key: str
    recipient: str
    amount: float = Field(..., gt=0, le=root_rules.MAX_TRANSACTION_AMOUNT)
    memo: str = Field("", max_length=root_rules.MAX_MEMO_LENGTH_BYTES)
    fee: float = Field(0.0, ge=0, le=root_rules.MAX_TRANSACTION_AMOUNT,
                       description="Taxa opcional (PXC) para priorizar a mineracao desta tx")


@app.post("/transaction/send")
def send_transaction(req: SendTransactionRequest):
    """
    ⚠️ CONVENIENCIA DE DEMONSTRACAO: esta rota recebe a chave privada e assina
    NO SERVIDOR. Isso significa que a chave privada trafega pela rede - aceitavel
    apenas para testes locais. Para uso real, prefira `/transaction/submit-signed`,
    que recebe uma transacao JA ASSINADA NO CLIENTE (a chave privada nunca sai
    do dispositivo do usuario, exatamente como uma carteira Bitcoin de verdade).
    """
    if not _is_valid_recipient(req.recipient):
        raise HTTPException(status_code=400, detail="Endereco de destinatario invalido")
    sender_address = crypto_utils.public_key_to_address(req.sender_public_key)
    _run_aml_check(sender_address, req.recipient, req.amount)
    tx = Transaction(sender=sender_address, recipient=req.recipient, amount=req.amount, memo=req.memo,
                      fee=req.fee)
    tx.sign(req.sender_private_key, req.sender_public_key)
    if not blockchain.add_transaction(tx):
        raise HTTPException(status_code=400, detail="Transacao invalida (assinatura, saldo ou dados incorretos)")
    return {"message": "Transacao aceita e aguardando mineracao", "tx_id": tx.tx_id}


class SubmitSignedTransactionRequest(BaseModel):
    sender: str
    recipient: str
    amount: float = Field(..., gt=0, le=root_rules.MAX_TRANSACTION_AMOUNT)
    tx_id: str
    timestamp: float
    memo: str = Field("", max_length=root_rules.MAX_MEMO_LENGTH_BYTES)
    signature: str
    public_key: str
    network_id: int = Field(default_factory=lambda: root_rules.NETWORK_ID)
    fee: float = Field(0.0, ge=0, le=root_rules.MAX_TRANSACTION_AMOUNT)


@app.post("/transaction/submit-signed")
def submit_signed_transaction(req: SubmitSignedTransactionRequest):
    """
    Rota RECOMENDADA para producao: recebe uma transacao ja assinada localmente
    pelo cliente (carteira do usuario) - a chave privada NUNCA trafega pela rede.
    O cliente monta o payload de assinatura (ver `Transaction.signing_payload`),
    assina com `ecdsa`/secp256k1 localmente e envia apenas o resultado publico.
    """
    if not _is_valid_recipient(req.recipient):
        raise HTTPException(status_code=400, detail="Endereco de destinatario invalido")
    _run_aml_check(req.sender, req.recipient, req.amount)
    tx = Transaction(
        sender=req.sender, recipient=req.recipient, amount=req.amount, tx_id=req.tx_id,
        timestamp=req.timestamp, memo=req.memo, signature=req.signature, public_key=req.public_key,
        tx_type="transfer", network_id=req.network_id, fee=req.fee,
    )
    if not blockchain.add_transaction(tx):
        raise HTTPException(status_code=400, detail="Transacao invalida (assinatura, saldo, replay ou dados incorretos)")
    return {"message": "Transacao aceita e aguardando mineracao", "tx_id": tx.tx_id}


# ---------------------------------------------------------------------------
# 🔒 Ofuscacao de transacao: memo confidencial (ECDH + AES-256-GCM)
# ---------------------------------------------------------------------------
# O ledger permanece publico e auditavel (remetente/destinatario/valor sempre
# visiveis, como no Bitcoin) - mas o CONTEUDO do memo pode ser cifrado de
# ponta a ponta, de forma que somente as duas partes da transacao consigam
# lê-lo. Qualquer outro observador da cadeia enxerga apenas um blob opaco
# ("ENC1:...") no campo memo.
# ⚠️ Assim como /transaction/send, estes helpers aceitam a chave privada por
# CONVENIENCIA DE DEMONSTRACAO. Em producao, a cifragem/decifragem devem
# ocorrer inteiramente no dispositivo do usuario (a chave privada nunca sai
# da carteira) - use `crypto_utils.encrypt_memo`/`decrypt_memo` localmente.
class EncryptMemoRequest(BaseModel):
    sender_private_key: str
    recipient_public_key: str
    memo: str = Field(..., max_length=400)


@app.post("/wallet/memo/encrypt")
def encrypt_memo(req: EncryptMemoRequest):
    try:
        encoded = crypto_utils.encrypt_memo(req.sender_private_key, req.recipient_public_key, req.memo)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Falha ao cifrar memo: {exc}")
    return {"encrypted_memo": encoded}


class DecryptMemoRequest(BaseModel):
    viewer_private_key: str
    counterparty_public_key: str
    encrypted_memo: str


@app.post("/wallet/memo/decrypt")
def decrypt_memo(req: DecryptMemoRequest):
    try:
        plaintext = crypto_utils.decrypt_memo(req.viewer_private_key, req.counterparty_public_key, req.encrypted_memo)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Falha ao decifrar memo (chaves incorretas ou dado adulterado): {exc}")
    return {"memo": plaintext}


class PayViaQrRequest(BaseModel):
    sender_private_key: str
    sender_public_key: str
    qr_payload: str
    override_amount: Optional[float] = None


@app.post("/transaction/pay-qrcode")
def pay_via_qrcode(req: PayViaQrRequest):
    data = qrcode_utils.decode_payment_payload(req.qr_payload)
    amount = req.override_amount if req.override_amount is not None else data.get("amount")
    if amount is None:
        raise HTTPException(status_code=400, detail="QR code nao especifica valor; informe override_amount")
    sender_address = crypto_utils.public_key_to_address(req.sender_public_key)
    tx = Transaction(sender=sender_address, recipient=data["address"], amount=amount, memo=data.get("memo", ""))
    tx.sign(req.sender_private_key, req.sender_public_key)
    if not blockchain.add_transaction(tx):
        raise HTTPException(status_code=400, detail="Transacao invalida (assinatura, saldo ou dados incorretos)")
    return {"message": "Pagamento via QR code aceito e aguardando mineracao", "tx_id": tx.tx_id}


@app.get("/transaction/pending")
def list_pending():
    return {"pending": [tx.to_dict() for tx in blockchain.pending_transactions]}


# ---------------------------------------------------------------------------
# Mineracao
# ---------------------------------------------------------------------------

@app.get("/mining/gpu-status")
def gpu_status():
    """Detecta GPUs AMD/NVIDIA/Intel disponiveis via OpenCL/ROCm para mineracao acelerada."""
    return mining.gpu_backend_status()


@app.get("/mining/candidate-block/{miner_address}")
def candidate_block(miner_address: str):
    block = blockchain.build_candidate_block(miner_address)
    if block is None:
        return {"message": "Sem transacoes pendentes para minerar"}
    return block.to_dict()


class PoolContributor(BaseModel):
    """Um participante da mineracao colaborativa (pool) que ajudou a validar
    este bloco especifico — recebe uma fracao proporcional ao seu peso
    (numero de "shares" de trabalho parcial submetidos) da recompensa total
    de 4% do bloco, dividida entre TODOS os contribuidores listados."""
    address: str
    shares: float = Field(gt=0, description="Peso/numero de shares de trabalho parcial contribuidos")


class MineRequest(BaseModel):
    miner_address: str
    max_iterations: int = Field(2_000_000, gt=0, le=root_rules.MAX_MINING_ITERATIONS_PER_CALL,
                                 description="Teto de tentativas de hash por chamada (anti-DoS)")
    prefer_gpu: bool = True
    pool_contributors: Optional[List[PoolContributor]] = Field(
        None, max_length=root_rules.MAX_POOL_CONTRIBUTORS_PER_BLOCK,
        description=(
            "Mineracao colaborativa estilo pool (Bitcoin): lista de enderecos e "
            "pesos (shares) de TODOS que ajudaram a minerar este bloco. Se "
            "informado, a recompensa de 4% do bloco + taxas e dividida "
            "proporcionalmente entre eles em vez de ir integralmente para "
            "`miner_address`."
        ),
    )


@app.post("/mining/mine")
def mine(req: MineRequest):
    if not feature_flags.is_enabled("mining_enabled"):
        raise HTTPException(status_code=503, detail="Mineracao temporariamente desabilitada pelo operador")
    if not crypto_utils.is_valid_address(req.miner_address):
        raise HTTPException(status_code=400, detail="Endereco de minerador invalido")
    contributors = None
    if req.pool_contributors:
        contributors = [(c.address, c.shares) for c in req.pool_contributors]
    try:
        block = blockchain.build_candidate_block(req.miner_address, contributors=contributors)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if block is None:
        return {"message": "Sem transacoes pendentes para minerar"}

    result = mining.mine_block(block, max_iterations=req.max_iterations, prefer_gpu=req.prefer_gpu)
    if not result.success:
        return {
            "message": "Nao foi encontrado um nonce valido dentro do limite de iteracoes",
            "hashes_tried": result.hashes_tried,
            "elapsed_seconds": result.elapsed_seconds,
            "backend": result.backend,
        }

    accepted = blockchain.submit_mined_block(block, result.nonce, result.block_hash)
    if not accepted:
        raise HTTPException(status_code=409, detail="A cadeia avancou durante a mineracao; bloco descartado (reorg)")

    storage.persist_block(block)
    storage.persist_contract_logs(blockchain._last_accepted_block_logs)
    broadcast_mined_block(block)
    storage.log_difficulty_adjustment(
        block.index, block.base_difficulty_bits or block.difficulty, blockchain.difficulty, result.elapsed_seconds
    )

    return {
        "message": "Bloco minerado e adicionado a cadeia com sucesso",
        "block_index": block.index,
        "block_hash": block.hash,
        "nonce": result.nonce,
        "miner_reward": block.miner_reward(),
        "reward_breakdown": block.reward_breakdown(),
        "backend": result.backend,
        "hashes_tried": result.hashes_tried,
        "elapsed_seconds": round(result.elapsed_seconds, 4),
        "base_difficulty_bits": block.base_difficulty_bits,
        "effective_difficulty_bits": block.difficulty,
        "anti_monopoly": block.anti_monopoly_info,
        "next_base_difficulty_bits": blockchain.difficulty,
    }


class SubmitProofRequest(BaseModel):
    miner_address: str
    nonce: int
    block_hash: str
    pool_contributors: Optional[List[PoolContributor]] = Field(
        None, max_length=root_rules.MAX_POOL_CONTRIBUTORS_PER_BLOCK,
        description="Mesma semantica de mineracao em pool de /mining/mine.",
    )


@app.post("/mining/submit-proof")
def submit_external_proof(req: SubmitProofRequest):
    """
    Permite que um minerador externo (hardware proprio rodando o kernel OpenCL/CUDA-like
    de forma independente, ou um coordenador de pool agregando o hashrate de varios
    participantes) envie apenas o nonce/hash encontrados, sem depender do servidor
    para realizar o proof-of-work.
    """
    contributors = None
    if req.pool_contributors:
        contributors = [(c.address, c.shares) for c in req.pool_contributors]
    try:
        block = blockchain.build_candidate_block(req.miner_address, contributors=contributors)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if block is None:
        raise HTTPException(status_code=400, detail="Sem transacoes pendentes")
    accepted = blockchain.submit_mined_block(block, req.nonce, req.block_hash)
    if not accepted:
        raise HTTPException(status_code=400, detail="Prova de trabalho invalida ou cadeia desatualizada")
    storage.persist_block(block)
    storage.persist_contract_logs(blockchain._last_accepted_block_logs)
    broadcast_mined_block(block)
    return {
        "message": "Prova aceita",
        "block_index": block.index,
        "miner_reward": block.miner_reward(),
        "reward_breakdown": block.reward_breakdown(),
        "effective_difficulty_bits": block.difficulty,
        "anti_monopoly": block.anti_monopoly_info,
    }


# ---------------------------------------------------------------------------
# Dificuldade (crescimento 20x a cada 2 blocos) e anti-monopolio (vetorizado)
# ---------------------------------------------------------------------------

@app.get("/mining/difficulty-status")
def difficulty_status():
    """
    Mostra a dificuldade-base atual da rede, o teto do modo ativo (demo ou
    mainnet_like) e o equivalente aproximado a dificuldade do Bitcoin em 2020.
    """
    status = blockchain.difficulty_engine.status(blockchain.mined_block_count)
    return {
        "mined_blocks": blockchain.mined_block_count,
        "mode": status.mode,
        "base_difficulty_bits": status.base_bits,
        "base_difficulty_units": status.base_difficulty_units,
        "max_bits_this_mode": status.max_bits,
        "bitcoin_2020_equivalent_bits": status.bitcoin_2020_equivalent_bits,
        "growth_rule": "difficulty_units *= 20 a cada 2 blocos minerados, ate o teto do modo",
    }


@app.get("/mining/network-stats")
def network_stats():
    """
    Estatisticas anti-monopolio: distribuicao (market-share) de blocos minerados
    por endereco na janela recente e indice de concentracao HHI, calculados de
    forma vetorizada (numpy) a partir do historico de mineradores.
    """
    stats = blockchain.difficulty_engine.hash_concentration_stats(blockchain.recent_miners[-20:])
    return {
        "window_size": len(blockchain.recent_miners[-20:]),
        **stats,
        "interpretation": "HHI proximo de 1.0 = alta concentracao (risco de monopolio/51%)",
    }



# ---------------------------------------------------------------------------
# Compra de moeda (BRL -> PXC) com taxa de 7,38% a cada R$100
# ---------------------------------------------------------------------------

class QuotePurchaseRequest(BaseModel):
    amount_brl: float = Field(..., gt=0, le=1_000_000, description="Valor em BRL a comprar")


@app.post("/purchase/quote")
def purchase_quote(req: QuotePurchaseRequest):
    """Cotacao informativa (preview de preco). Para comprar de fato, gere uma
    cotacao TRAVADA com `/purchase/quote-locked`, pague, e confirme com
    `/purchase/confirm` usando a assinatura do gateway de pagamento."""
    q = purchase.quote_purchase(req.amount_brl)
    return {k: v for k, v in q.__dict__.items() if k not in ("quote_id", "recipient_address", "expires_at")}


class LockedQuoteRequest(BaseModel):
    amount_brl: float = Field(..., gt=0, le=1_000_000)
    recipient_address: str


@app.post("/purchase/quote-locked")
def purchase_quote_locked(req: LockedQuoteRequest):
    """
    Gera uma cotacao TRAVADA (valor, endereco destino e taxa de ouro fixados no
    momento), valida por 5 minutos. O `quote_id` retornado deve ser usado no
    pagamento real (gateway externo) e depois em `/purchase/confirm`.
    """
    if not feature_flags.is_enabled("purchases_enabled"):
        raise HTTPException(status_code=503, detail="Compra de PXC temporariamente desabilitada pelo operador")
    if not crypto_utils.is_valid_address(req.recipient_address):
        raise HTTPException(status_code=400, detail="Endereco de destino invalido")
    quote = purchase.purchase_ledger.create_quote(req.amount_brl, req.recipient_address)
    return quote.__dict__


class SimulateGatewayRequest(BaseModel):
    quote_id: str
    payment_reference: str


@app.post("/purchase/webhook/simulate-payment-gateway")
def simulate_payment_gateway(req: SimulateGatewayRequest):
    """
    ⚠️ SOMENTE PARA DEMONSTRACAO/TESTE (apenas quando PIXCRIPTO_ENV=devnet).
    Em producao este endpoint retorna 403. Para integrar um PSP real, aponte
    o webhook do PSP para `POST /purchase/webhook/confirm`.
    """
    if settings.environment != "devnet":
        raise HTTPException(
            status_code=403,
            detail="Endpoint de simulacao desabilitado - configure PIXCRIPTO_ENV=devnet para usar",
        )
    quote = purchase.purchase_ledger.get_quote(req.quote_id)
    if quote is None:
        raise HTTPException(status_code=404, detail="quote_id desconhecido ou expirado")
    signature = purchase.purchase_ledger.sign_for_gateway_simulation(req.quote_id, req.payment_reference)
    return {"quote_id": req.quote_id, "payment_reference": req.payment_reference, "gateway_signature": signature}


class WebhookConfirmRequest(BaseModel):
    quote_id: str = Field(..., description="quote_id gerado em /purchase/quote-locked")
    payment_reference: str = Field(..., min_length=1, description="ID unico do pagamento gerado pelo PSP")


@app.post("/purchase/webhook/confirm")
async def webhook_confirm_purchase(request: Request):
    """
    Webhook de confirmacao de pagamento para integracao com PSP real
    (Mercado Pago, Stripe, PagSeguro, etc.).

    Autenticacao: o PSP deve assinar o corpo RAW da requisicao com o segredo
    compartilhado (`PIXCRIPTO_PAYMENT_WEBHOOK_SECRET`) usando HMAC-SHA256 e
    enviar o resultado hexadecimal no header configurado em
    `PIXCRIPTO_PAYMENT_WEBHOOK_SIGNATURE_HEADER` (padrao: `X-Webhook-Signature`).

    Formato esperado do corpo JSON:
        {"quote_id": "<id-da-cotacao>", "payment_reference": "<id-psp-unico>"}

    O campo `payment_reference` funciona como chave de idempotencia: a mesma
    referencia enviada duas vezes credita PXC apenas uma vez (anti-replay).
    """
    webhook_secret = settings.payment_webhook_secret
    is_devnet = settings.environment == "devnet"

    if not webhook_secret:
        if not is_devnet:
            raise HTTPException(
                status_code=503,
                detail="Gateway de pagamento nao configurado - defina PIXCRIPTO_PAYMENT_WEBHOOK_SECRET",
            )
        # devnet sem segredo: aceita sem verificacao (apenas para desenvolvimento local)
        raw_body = await request.body()
    else:
        raw_body = await request.body()
        sig_header = settings.payment_webhook_signature_header.lower()
        received_sig = request.headers.get(sig_header) or request.headers.get(settings.payment_webhook_signature_header)
        if not received_sig:
            raise HTTPException(
                status_code=401,
                detail=f"Header de assinatura ausente: {settings.payment_webhook_signature_header}",
            )
        expected_sig = _hmac.new(
            webhook_secret.encode("utf-8"),
            raw_body,
            hashlib.sha256,
        ).hexdigest()
        if not secrets.compare_digest(expected_sig, received_sig.strip()):
            raise HTTPException(status_code=401, detail="Assinatura do webhook invalida")

    import json as _json
    try:
        body = _json.loads(raw_body)
    except Exception:
        raise HTTPException(status_code=400, detail="Corpo da requisicao nao e JSON valido")

    try:
        req = WebhookConfirmRequest(**body)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    if not feature_flags.is_enabled("purchases_enabled"):
        raise HTTPException(status_code=503, detail="Compra de PXC temporariamente desabilitada pelo operador")

    try:
        quote = purchase.purchase_ledger.confirm_via_webhook(req.quote_id, req.payment_reference)
    except purchase._QuoteAlreadyUsed as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    tx = Transaction(
        sender=COINBASE_SENDER,
        recipient=quote.recipient_address,
        amount=quote.coins_credited,
        memo=f"Compra de {quote.coins_credited} PXC (taxa R${quote.fee_brl:.2f}) ref={hashlib.sha256(req.payment_reference.encode()).hexdigest()[:16]}",
        tx_type="coinbase_purchase",
    )
    if not blockchain.add_transaction(tx):
        raise HTTPException(status_code=400, detail="Falha ao registrar credito de compra")
    return {
        "message": "Compra confirmada; credito aguardando mineracao do proximo bloco",
        "tx_id": tx.tx_id,
        "amount_brl": quote.amount_brl,
        "fee_brl": quote.fee_brl,
        "total_charged_brl": quote.total_charged_brl,
        "coins_credited": quote.coins_credited,
        "pxc_brl_rate": quote.pxc_brl_rate,
    }


class ConfirmPurchaseRequest(BaseModel):
    quote_id: str
    payment_reference: str = Field(..., min_length=1, description="Id do pagamento externo (cartao/boleto/pix real)")
    gateway_signature: str = Field(..., description="Assinatura HMAC do gateway de pagamento aprovando a transacao")


@app.post("/purchase/confirm")
def confirm_purchase(req: ConfirmPurchaseRequest):
    """
    Credita PXC na carteira do comprador via transacao de emissao (coinbase_purchase),
    SOMENTE apos validar a assinatura do gateway de pagamento e garantir que esta
    cotacao/pagamento nunca foi confirmado antes (idempotencia - corrige a falha
    critica de cunhagem arbitraria encontrada em auditoria: antes, qualquer chamada
    repetida a este endpoint mintava PXC sem nenhuma verificacao de pagamento real).
    """
    try:
        quote = purchase.purchase_ledger.confirm(req.quote_id, req.payment_reference, req.gateway_signature)
    except purchase._QuoteAlreadyUsed as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    tx = Transaction(
        sender=COINBASE_SENDER,
        recipient=quote.recipient_address,
        amount=quote.coins_credited,
        memo=f"Compra de {quote.coins_credited} PXC (taxa R${quote.fee_brl:.2f}) ref={hashlib.sha256(req.payment_reference.encode()).hexdigest()[:16]}",
        tx_type="coinbase_purchase",
    )
    if not blockchain.add_transaction(tx):
        raise HTTPException(status_code=400, detail="Falha ao registrar credito de compra")
    return {
        "message": "Compra confirmada; credito aguardando mineracao do proximo bloco",
        "tx_id": tx.tx_id,
        "amount_brl": quote.amount_brl,
        "fee_brl": quote.fee_brl,
        "total_charged_brl": quote.total_charged_brl,
        "coins_credited": quote.coins_credited,
        "pxc_brl_rate": quote.pxc_brl_rate,
    }


# ---------------------------------------------------------------------------
# Ouro (lastro / peg) - preco real do PXC ancorado em XAU/USD + cambio USD/BRL
# ---------------------------------------------------------------------------

@app.get("/market/gold-price")
def gold_price():
    """
    Cotacao do ouro (XAU/USD) e cambio USD/BRL usados para ancorar o valor do
    PXC. `delta_pct_gold` mostra a variacao percentual do ouro desde a ultima
    atualizacao - o preco do PXC acompanha essa variacao automaticamente.
    """
    snapshot = gold_oracle.snapshot()
    return {
        "gold_usd_per_oz": snapshot.gold_usd_per_oz,
        "usd_brl": snapshot.usd_brl,
        "pxc_brl_rate": snapshot.pxc_brl_rate,
        "delta_pct_gold": snapshot.delta_pct_gold,
        "stale": snapshot.stale,
        "rejected_manipulation_attempt": snapshot.rejected_manipulation_attempt,
        "fetched_at": snapshot.fetched_at,
        "note": "1 PXC = %.8f oz de ouro (lastro fixo, ajustavel por governanca)" % 0.00025,
    }


# ---------------------------------------------------------------------------
# 📜 Book of Rules / Root Rules - governanca e transparencia do consenso
# ---------------------------------------------------------------------------

@app.get("/rules/root-hash")
def rules_root_hash():
    """
    'Constituicao' da rede: todas as constantes de consenso, emissao,
    dificuldade/anti-monopolio, limites de transacao e auto-regulacao de dump
    em um unico snapshot, mais seu hash SHA-256 (`root_rules_hash`) - qualquer
    alteracao em uma unica constante muda esse hash, tornando adulteracoes
    silenciosas da governanca detectaveis publicamente (qualquer no pode
    comparar o hash anunciado com o hash calculado localmente a partir do
    proprio codigo-fonte que esta rodando).
    """
    return {
        "root_rules_hash": root_rules.root_rules_hash(),
        "rules": root_rules.snapshot_dict(),
    }


@app.get("/rules/book")
def rules_book():
    """Retorna o texto integral do Book of Rules (BOOK_OF_RULES.md) para
    consulta programatica por wallets/exploradores/clientes de terceiros."""
    import os
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "BOOK_OF_RULES.md")
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        content = "Book of Rules ainda nao publicado nesta instancia."
    return {"root_rules_hash": root_rules.root_rules_hash(), "book_of_rules_markdown": content}


# ---------------------------------------------------------------------------
# Venda, liquidacao e troca (swap) - com controle automatico de dump
# ---------------------------------------------------------------------------

class SellRequest(BaseModel):
    sender_private_key: str
    sender_public_key: str
    amount: float


@app.post("/market/sell")
def sell(req: SellRequest):
    """Venda de PXC de volta ao protocolo (queima), pagando a cotacao ancorada em ouro."""
    address = crypto_utils.public_key_to_address(req.sender_public_key)
    try:
        tx = market.sell(req.sender_private_key, req.sender_public_key, address, req.amount)
    except MarketError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "message": "Venda aceita e aguardando mineracao",
        "tx_id": tx.tx_id,
        "payout_brl": tx.payout_brl,
        "pxc_brl_rate": tx.pxc_brl_rate,
    }


class LiquidateRequest(BaseModel):
    sender_private_key: str
    sender_public_key: str
    amount: Optional[float] = Field(None, description="Se omitido, liquida 100% do saldo disponivel")


@app.post("/market/liquidate")
def liquidate(req: LiquidateRequest):
    """Liquidacao (venda total ou parcial da posicao), sujeita ao mesmo controle de dump."""
    address = crypto_utils.public_key_to_address(req.sender_public_key)
    try:
        tx = market.liquidate(req.sender_private_key, req.sender_public_key, address, req.amount)
    except MarketError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "message": "Liquidacao aceita e aguardando mineracao",
        "tx_id": tx.tx_id,
        "payout_brl": tx.payout_brl,
        "pxc_brl_rate": tx.pxc_brl_rate,
    }


@app.get("/market/dump-status")
def dump_status():
    """
    Status do controle de dump: quanto ja foi vendido na janela atual, o limite
    de rede AUTO-REGULADO (self-regulating, baseado na concentracao de saldo
    entre carteiras) e se a negociacao esta suspensa no momento.
    """
    return market.network_dump_stats()


@app.get("/market/wallet-dump-status/{address}")
def wallet_dump_status(address: str):
    return {"address": address, **market.wallet_dump_stats(address)}


class CreateSwapOrderRequest(BaseModel):
    sender_private_key: str
    sender_public_key: str
    amount: float = Field(..., gt=0, le=root_rules.MAX_TRANSACTION_AMOUNT)
    price_brl_per_pxc: float = Field(..., gt=0)


@app.post("/market/swap/create-order")
def create_swap_order(req: CreateSwapOrderRequest):
    """Cria uma ordem de troca (swap) P2P: custodia (escrow) o PXC ate ser preenchida ou cancelada."""
    if not feature_flags.is_enabled("trading_enabled"):
        raise HTTPException(status_code=503, detail="Trading temporariamente desabilitado pelo operador")
    maker_address = crypto_utils.public_key_to_address(req.sender_public_key)
    try:
        order = market.create_swap_order(req.sender_private_key, req.sender_public_key,
                                          maker_address, req.amount, req.price_brl_per_pxc)
    except MarketError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"message": "Ordem de troca criada e fundos custodiados", "order_id": order.order_id}


class SignSwapReleaseRequest(BaseModel):
    maker_private_key: str
    action: str = Field(..., pattern="^(fill|cancel)$")
    order_id: str
    counterparty_address: str = Field(..., description="Endereco do taker (fill) ou do proprio maker (cancel)")


@app.post("/market/swap/sign-release")
def sign_swap_release(req: SignSwapReleaseRequest):
    """
    Helper para o MAKER assinar a liberacao (fill) ou o cancelamento (cancel) de
    sua propria ordem. Em um cliente real (app/carteira), esta assinatura seria
    gerada localmente no dispositivo do usuario, sem a chave privada jamais
    trafegar pela rede - aqui simplificamos para fins de demonstracao da API.
    """
    payload = MarketEngine._swap_release_payload(req.action, req.order_id, req.counterparty_address)
    signature = crypto_utils.sign_message(req.maker_private_key, payload)
    return {"signature": signature}


class FillSwapOrderRequest(BaseModel):
    order_id: str
    taker_address: str
    maker_signature: str = Field(..., description="Assinatura do maker autorizando a liberacao para ESTE taker")


@app.post("/market/swap/fill-order")
def fill_swap_order(req: FillSwapOrderRequest):
    """Exige assinatura do MAKER autorizando especificamente este taker - corrige
    falha CRITICA de auditoria que permitia a qualquer pessoa roubar o escrow."""
    try:
        tx = market.fill_swap_order(req.order_id, req.taker_address, req.maker_signature)
    except MarketError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"message": "Ordem de troca preenchida", "tx_id": tx.tx_id}


class CancelSwapOrderRequest(BaseModel):
    order_id: str
    requester_address: str
    maker_signature: str = Field(..., description="Assinatura do maker autorizando o cancelamento")


@app.post("/market/swap/cancel-order")
def cancel_swap_order(req: CancelSwapOrderRequest):
    try:
        tx = market.cancel_swap_order(req.order_id, req.requester_address, req.maker_signature)
    except MarketError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"message": "Ordem de troca cancelada e fundos estornados", "tx_id": tx.tx_id}


@app.get("/market/swap/orders")
def list_swap_orders(status: Optional[str] = None):
    orders = market.swap_orders.values()
    if status:
        orders = [o for o in orders if o.status == status]
    # nunca expor a chave publica do maker num campo que sugira ser sensivel -
    # e publica por natureza (endereco deriva dela), mas omitimos por higiene de API.
    return {"orders": [{k: v for k, v in vars(o).items()} for o in orders]}


# ---------------------------------------------------------------------------
# Explorer publico: consulta de movimentacao por carteira e atividade de mercado
# ---------------------------------------------------------------------------

@app.get("/explorer/address/{address}")
def explorer_address(address: str):
    """
    Consulta publica e transparente do historico de movimentacao de um
    endereco (public key derivada) - qualquer pessoa pode auditar o fluxo de
    fundos de uma carteira, mantendo o anonimato pseudonimo (nao ha vinculo
    entre endereco e identidade real), exatamente como no Bitcoin.
    """
    return market.address_history(address)


@app.get("/explorer/market-activity")
def explorer_market_activity(top_n: int = 10):
    """Movimento real do mercado: volume total, oferta circulante, concentracao de
    saldo (HHI) e as maiores transacoes (whale-watch) - visao agregada e transparente."""
    return market.market_activity(top_n=top_n)


# ---------------------------------------------------------------------------
# Layer 2 (Rollup): transferencias instantaneas fora da cadeia + commit em lote na L1
# ---------------------------------------------------------------------------

@app.get("/l2/bridge-address")
def l2_bridge_address():
    return {"bridge_address": L2_BRIDGE_ADDRESS, "note": "Deposite na L1 para este endereco e confirme em /l2/deposit"}


class L2DepositRequest(BaseModel):
    l1_tx_id: str = Field(..., description="tx_id da transferencia L1 ja MINERADA para o endereco-ponte")


@app.post("/l2/deposit")
def l2_deposit(req: L2DepositRequest):
    try:
        result = l2.deposit(req.l1_tx_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"message": "Deposito confirmado; saldo disponivel na L2 instantaneamente", **result}


@app.get("/l2/balance/{address}")
def l2_balance(address: str):
    return {"address": address, "l2_balance": l2.get_balance(address)}


class L2TransferRequest(BaseModel):
    sender_private_key: str
    sender_public_key: str
    recipient: str
    amount: float = Field(..., gt=0, le=root_rules.MAX_TRANSACTION_AMOUNT)
    memo: str = Field("", max_length=root_rules.MAX_MEMO_LENGTH_BYTES)


@app.post("/l2/transfer")
def l2_transfer(req: L2TransferRequest):
    sender_address = crypto_utils.public_key_to_address(req.sender_public_key)
    tx = L2Transaction(sender=sender_address, recipient=req.recipient, amount=req.amount, memo=req.memo)
    tx.sign(req.sender_private_key, req.sender_public_key)
    if not l2.transfer(tx):
        raise HTTPException(status_code=400, detail="Transferencia L2 invalida (assinatura ou saldo)")
    return {"message": "Transferencia L2 confirmada instantaneamente (sem mineracao)", "tx_id": tx.tx_id}


class L2WithdrawRequest(BaseModel):
    address: str
    amount: float = Field(..., gt=0, le=root_rules.MAX_TRANSACTION_AMOUNT)
    public_key: str
    signature: str = Field(..., description="Assinatura ECDSA de 'withdraw:{address}:{amount}' pela chave privada do dono")


@app.post("/l2/withdraw")
def l2_withdraw(req: L2WithdrawRequest):
    """Requer prova de posse da chave privada (assinatura) do endereco L2 - corrige
    falha de auditoria que permitia forcar o saque de saldo L2 de terceiros."""
    try:
        tx = l2.withdraw(req.address, req.amount, req.public_key, req.signature)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"message": "Saque solicitado; sera efetivado na L1 apos mineracao", "l1_tx_id": tx.tx_id}


@app.post("/l2/commit-batch")
def l2_commit_batch():
    """
    Agrega as transferencias L2 pendentes numa unica raiz de Merkle e ancora
    esse commit na L1 (uma unica transacao a ser minerada), independentemente
    de quantas transferencias L2 tenham ocorrido no lote.
    """
    record = l2.commit_batch()
    if record is None:
        return {"message": "Sem transferencias L2 pendentes para commit"}
    return {"message": "Lote L2 ancorado na L1 (aguardando mineracao)", **record}


@app.get("/l2/status")
def l2_status():
    return {
        "pending_l2_transfers": len(l2.pending_l2_txs),
        "committed_batches": len(l2.committed_batches),
        "last_batches": l2.committed_batches[-5:],
    }


# ---------------------------------------------------------------------------
# 🍯 HONEYPOT - rotas-isca deliberadamente tentadoras a um atacante fazendo
# reconhecimento (nomes sugerem "backdoor"/"admin"/"exploit"). Qualquer acesso
# e registrado (IP, User-Agent, fingerprint) e responde com um desafio de
# Proof-of-Work de dificuldade MUITO acima da rede real - o objetivo e prender
# o hardware (CPU/GPU) do atacante tentando "quebrar o hash" para liberar uma
# recompensa fake que NUNCA existe de verdade em lugar nenhum do ledger real.
# ---------------------------------------------------------------------------

def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _bait(request: Request, label: str, score: int = 25) -> dict:
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "-")
    honeypot.record(ip, str(request.url.path), ua, label, score=score)
    challenge = honeypot.issue_challenge(ip)
    return {
        "message": "Exploit confirmado! Complete o desafio de prova-de-trabalho abaixo para "
                    "liberar a recompensa antes que outro minerador a capture.",
        "challenge_id": challenge.challenge_id,
        "seed": challenge.seed,
        "target_bits": challenge.target_bits,
        "fake_reward_pxc": challenge.fake_reward_pxc,
        "hint": "hash = sha256(f'{seed}:{nonce}'); precisa comecar com "
                f"{challenge.target_bits} bits zerados. Envie o nonce em /honeypot/claim.",
    }


@app.get("/admin/backup-all-wallets")
def _honeypot_admin_backup(request: Request):
    return _bait(request, "acesso a rota-isca de backup administrativo de carteiras", score=40)


@app.get("/admin/mint-unlimited")
def _honeypot_admin_mint(request: Request):
    return _bait(request, "tentativa de acesso a rota-isca de cunhagem irrestrita", score=60)


@app.get("/internal/debug/private-keys")
def _honeypot_debug_keys(request: Request):
    return _bait(request, "tentativa de acesso a rota-isca de dump de chaves privadas", score=80)


@app.get("/_backup/{path:path}")
def _honeypot_backup_path(path: str, request: Request):
    return _bait(request, f"varredura de backup/arquivo sensivel: {path}", score=30)


@app.get("/wallet/{addr}/private-key")
def _honeypot_wallet_private_key(addr: str, request: Request):
    # rota inexistente de verdade na API real (a chave privada NUNCA e recuperavel
    # via endereco) - qualquer chamada aqui e, por definicao, uma tentativa de ataque.
    return _bait(request, f"tentativa de recuperar chave privada via endereco {addr}", score=90)


@app.get("/honeypot/decoy-wallet")
def honeypot_decoy_wallet(request: Request):
    """
    Carteira-isca com saldo "vazado" enorme (fake). Ninguem possui a chave
    privada correspondente - qualquer tentativa de gastar dela e assinatura
    invalida por definicao e e rejeitada normalmente pelo consenso; serve
    apenas para atrair e registrar bots que tentam decodificar/forjar saques.
    """
    ip = _client_ip(request)
    honeypot.record(ip, "/honeypot/decoy-wallet", request.headers.get("user-agent", "-"),
                     "consulta a carteira-isca (possivel reconhecimento automatizado)", score=15)
    return {
        "address": honeypot.decoy_wallet_address,
        "balance": honeypot.decoy_wallet_fake_balance,
        "coin": "PXC",
        "note": "⚠️ carteira monitorada - qualquer tentativa de transacao a partir dela e registrada",
    }


class HoneypotClaimRequest(BaseModel):
    challenge_id: str
    nonce: int


@app.post("/honeypot/claim")
def honeypot_claim(req: HoneypotClaimRequest, request: Request):
    """Verifica a 'prova' do desafio-isca. Mesmo em caso de sucesso matematico
    (extremamente improvavel na dificuldade configurada), NENHUM pagamento real
    ocorre - a recompensa nunca existiu de verdade em nenhum lugar do ledger."""
    ip = _client_ip(request)
    solved = honeypot.check_proof(req.challenge_id, req.nonce)
    honeypot.record(ip, "/honeypot/claim", request.headers.get("user-agent", "-"),
                     f"tentativa de resolver desafio-isca (sucesso_matematico={solved})",
                     score=5 if not solved else 100)
    if solved:
        return {"message": "Prova valida recebida - processando liberacao de fundos (revisao manual necessaria).",
                "status": "pending_manual_review"}
    return {"message": "Nonce nao atinge a dificuldade exigida - continue tentando.", "status": "rejected"}


@app.get("/honeypot/report")
def honeypot_report():
    """Painel simples de deteccao: IPs com maior 'score' de ameaca acumulado e
    os eventos mais recentes - use para alimentar um firewall/blocklist real."""
    return {
        "top_suspects": honeypot.top_suspects(),
        "recent_events": honeypot.recent_events(),
        "decoy_wallet_address": honeypot.decoy_wallet_address,
    }


# ---------------------------------------------------------------------------
# Explorador da cadeia
# ---------------------------------------------------------------------------

@app.get("/chain")
def get_chain():
    return {
        "length": len(blockchain.chain),
        "difficulty": blockchain.difficulty,
        "is_valid": blockchain.is_chain_valid(),
        "blocks": [b.to_dict() for b in blockchain.chain],
    }


@app.get("/chain/metadata")
def chain_metadata():
    """Metadata persistida em disco (SQLite), analogo aos indices de blocos em Bitcoin/Ethereum."""
    return {"blocks": storage.load_chain_metadata()}


@app.get("/chain/state-root")
def current_state_root():
    """
    Hash (SHA-256) do snapshot de TODOS os saldos da rede no bloco mais
    recente - uma versao simplificada de "state root" (o guia autoriza esta
    simplificacao em vez de uma Merkle Patricia Trie completa, secao 1.5).
    Permite que dois nos comparem rapidamente (32 bytes) se seus estados
    (saldos de TODAS as carteiras) estao identicos, sem trafegar o dict inteiro -
    util para diagnosticar divergencia de consenso entre peers.
    """
    return {
        "block_index": blockchain.last_block.index,
        "state_root": blockchain.last_block.state_root,
    }


# ---------------------------------------------------------------------------
# 🖥️ Smart contracts / maquina virtual (secao 5 do guia)
# ---------------------------------------------------------------------------
# NOTA de escopo (documentada, como toda simplificacao deste projeto): a VM
# EXECUTA de forma determinística no momento em que um bloco a inclui
# (`build_candidate_block`/mineracao), nao no momento de aceitacao na mempool -
# exatamente como Ethereum de verdade (uma tx sentada na mempool nunca alterou
# storage; so altera quando um bloco a inclui e todo no re-executa o mesmo
# bytecode para chegar ao mesmo `contracts_root`). Isso resolve corretamente o
# caso de reorg: se o bloco que continha uma chamada de contrato e orfanado,
# o efeito da chamada e revertido automaticamente (o `contracts_root` do novo
# ramo vencedor e recalculado do zero via replay, sem nenhum estado "grudado").


class ContractDeployRequest(BaseModel):
    sender_public_key: str
    sender_private_key: str
    bytecode_hex: str = Field(..., description="Bytecode da VM, codificado em hex")
    fee: float = Field(0.001, ge=0, le=root_rules.MAX_TRANSACTION_AMOUNT,
                        description="Orcamento de gas em PXC (convertido via GAS_PRICE_PXC)")
    memo: str = ""


@app.post("/contracts/deploy")
def deploy_contract(req: ContractDeployRequest):
    """
    ⚠️ CONVENIENCIA DE DEMONSTRACAO (mesma ressalva de `/transaction/send`): a
    chave privada e recebida e usada para assinar NO SERVIDOR. Para producao,
    monte e assine a transacao localmente (`tx_type="contract_deploy"`) e
    envie via `/transaction/submit-signed`.
    """
    sender_address = crypto_utils.public_key_to_address(req.sender_public_key)
    try:
        bytecode = bytes.fromhex(req.bytecode_hex)
    except ValueError:
        raise HTTPException(status_code=400, detail="bytecode_hex invalido (nao e hex)")
    if len(bytecode) > root_rules.MAX_CONTRACT_BYTECODE_BYTES:
        raise HTTPException(status_code=400, detail="Bytecode excede o teto de tamanho")
    tx = Transaction(sender=sender_address, recipient="", amount=0.0, memo=req.memo,
                      fee=req.fee, tx_type="contract_deploy", data=bytecode.hex())
    tx.sign(req.sender_private_key, req.sender_public_key)
    if not blockchain.add_transaction(tx):
        raise HTTPException(status_code=400, detail="Transacao de deploy invalida (assinatura, saldo ou dados)")
    return {
        "message": "Deploy aceito e aguardando mineracao - o endereco final do contrato so e "
                   "conhecido apos o bloco ser minerado (consulte /contracts/by-creator/{endereco})",
        "tx_id": tx.tx_id,
    }


class ContractCallRequest(BaseModel):
    sender_public_key: str
    sender_private_key: str
    contract_address: str
    calldata_hex: str = ""
    amount: float = Field(0.0, ge=0, le=root_rules.MAX_TRANSACTION_AMOUNT)
    fee: float = Field(0.001, ge=0, le=root_rules.MAX_TRANSACTION_AMOUNT)
    memo: str = ""


@app.post("/contracts/call")
def call_contract(req: ContractCallRequest):
    """⚠️ Mesma ressalva de conveniencia de demonstracao de `/contracts/deploy`."""
    if not crypto_utils.is_valid_address(req.contract_address):
        raise HTTPException(status_code=400, detail="Endereco de contrato invalido")
    sender_address = crypto_utils.public_key_to_address(req.sender_public_key)
    try:
        calldata = bytes.fromhex(req.calldata_hex or "")
    except ValueError:
        raise HTTPException(status_code=400, detail="calldata_hex invalido (nao e hex)")
    tx = Transaction(sender=sender_address, recipient=req.contract_address, amount=req.amount,
                      memo=req.memo, fee=req.fee, tx_type="contract_call", data=calldata.hex())
    tx.sign(req.sender_private_key, req.sender_public_key)
    if not blockchain.add_transaction(tx):
        raise HTTPException(status_code=400, detail="Transacao de chamada invalida (assinatura, saldo ou dados)")
    return {"message": "Chamada aceita e aguardando mineracao", "tx_id": tx.tx_id}


@app.get("/contracts/by-creator/{address}")
def list_contracts_by_creator(address: str):
    """Lista os enderecos de todos os contratos implantados por um criador -
    util para descobrir o endereco final de um deploy recem-minerado (o
    endereco e deterministico, mas depende do nonce do criador no momento em
    que o bloco foi minerado, entao so pode ser confirmado apos a mineracao)."""
    state = blockchain._contracts_snapshot()
    deployed = [acc.address for acc in state.contracts.values() if acc.creator == address]
    return {"creator": address, "contracts": deployed}


@app.get("/contracts/{address}/code")
def get_contract_code(address: str):
    """Bytecode implantado no endereco (hex) - recalculado por replay
    determinístico de toda a cadeia (mesmo padrao de `state_root`)."""
    state = blockchain._contracts_snapshot()
    account = state.get(address)
    if account is None:
        raise HTTPException(status_code=404, detail="Nenhum contrato implantado neste endereco")
    return {"address": address, "creator": account.creator, "code_hex": account.code.hex(),
             "code_size_bytes": len(account.code)}


@app.get("/contracts/{address}/storage/{key}")
def get_contract_storage(address: str, key: int):
    """Le um slot de storage (256 bits, indexado por inteiro) de um contrato -
    equivalente ao `eth_getStorageAt` de um cliente Ethereum real."""
    state = blockchain._contracts_snapshot()
    account = state.get(address)
    if account is None:
        raise HTTPException(status_code=404, detail="Nenhum contrato implantado neste endereco")
    return {"address": address, "key": key, "value": account.storage.get(key, 0)}


@app.get("/contracts/{address}/logs")
def get_contract_logs_endpoint(
    address: str,
    topic: Optional[str] = None,
    from_block: int = 0,
    to_block: Optional[int] = None,
):
    """Consulta logs (eventos) emitidos por um contrato - equivalente ao
    eth_getLogs do Ethereum. Suporta filtros opcionais por topico (topic0)
    e por range de blocos (from_block/to_block).

    Os logs sao persistidos durante a mineracao (no mesmo momento em que
    o bloco e aceito e gravado no SQLite) - nao requerem replay da chain."""
    state = blockchain._contracts_snapshot()
    if state.get(address) is None:
        raise HTTPException(status_code=404, detail="Nenhum contrato implantado neste endereco")
    logs = storage.get_contract_logs(address, topic_filter=topic,
                                     from_block=from_block, to_block=to_block)
    return {"address": address, "logs": logs, "count": len(logs)}


class EstimateGasRequest(BaseModel):
    sender: str
    contract_address: Optional[str] = None  # None => estima um deploy
    bytecode_hex: str = ""      # usado se contract_address for None (deploy)
    calldata_hex: str = ""      # usado se contract_address for informado (call)
    amount: float = 0.0
    gas_limit: int = 10_000_000


@app.post("/contracts/estimate-gas")
def estimate_gas(req: EstimateGasRequest):
    """
    Simula a execucao (dry-run) SEM mutar o estado real da cadeia nem cobrar
    nenhuma taxa - equivalente ao `eth_estimateGas` de um cliente Ethereum,
    permitindo que uma carteira mostre ao usuario o custo esperado ANTES de
    assinar/enviar a transacao de fato.
    """
    from .vm import VM, CallContext, ContractsState as _CS

    # roda contra uma CÓPIA do estado real (nunca contra o objeto vivo da cadeia)
    state = blockchain._contracts_snapshot()
    if req.contract_address:
        if not crypto_utils.is_valid_address(req.contract_address):
            raise HTTPException(status_code=400, detail="Endereco de contrato invalido")
        account = state.get(req.contract_address)
        if account is None:
            raise HTTPException(status_code=404, detail="Nenhum contrato implantado neste endereco")
        try:
            calldata = bytes.fromhex(req.calldata_hex or "")
        except ValueError:
            raise HTTPException(status_code=400, detail="calldata_hex invalido")
    else:
        try:
            bytecode = bytes.fromhex(req.bytecode_hex or "")
        except ValueError:
            raise HTTPException(status_code=400, detail="bytecode_hex invalido")
        account = state.deploy(req.sender, bytecode)  # dry-run: so existe nesta copia descartavel
        calldata = b""

    vm = VM(state, req.gas_limit, get_balance=blockchain.get_balance)
    ctx = CallContext(contract=account, caller=req.sender,
                       call_value=int(round(req.amount * 10 ** 8)), calldata=calldata, depth=0)
    result = vm.execute(ctx)
    return {
        "success": result.success,
        "reverted": result.reverted,
        "revert_reason": result.revert_reason,
        "gas_used": result.gas_used,
        "estimated_fee_pxc": round(result.gas_used * root_rules.GAS_PRICE_PXC, 8),
        "return_data_hex": result.return_data.hex(),
    }


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": time.time(), "chain_length": len(blockchain.chain)}


# ---------------------------------------------------------------------------
# Rede P2P (nao e mais um sistema de no unico: consulta/gerencia peers reais)
# ---------------------------------------------------------------------------

@app.get("/network/status")
def network_status():
    """Estado atual da rede P2P deste no: peers conectados, versao de cliente
    de cada peer, altura conhecida de cada um, e hosts banidos por comportamento
    invalido repetido."""
    if p2p_node is None:
        return {"enabled": False, "message": "Rede P2P ainda nao iniciada"}
    return {"enabled": True, "total_work": blockchain.total_work(), **p2p_node.status()}


@app.get("/network/peers")
def network_peers():
    """Lista detalhada de todos os peers conectados, incluindo `discovered_via`
    (como cada peer foi descoberto: "manual", "dns_seed", "pex" ou "inbound").
    Util para auditar a saude da descoberta automatica de peers em producao:
    se todos os peers forem "manual", a descoberta automatica nao esta funcionando."""
    if p2p_node is None:
        return {"peers": [], "total": 0, "enabled": False}
    peers = p2p_node.peers_detail()
    return {"peers": peers, "total": len(peers), "enabled": True}


class ConnectPeerRequest(BaseModel):
    host: str
    port: int = Field(..., gt=0, le=65535)


@app.post("/network/connect")
def network_connect(req: ConnectPeerRequest):
    """Conecta manualmente a um peer conhecido (host:porta) - util para formar
    a rede inicial entre nos antes de haver bootnodes fixos publicados."""
    if p2p_node is None or _p2p_loop is None:
        raise HTTPException(status_code=503, detail="Rede P2P ainda nao iniciada")
    asyncio.run_coroutine_threadsafe(p2p_node.connect_to_peer(req.host, req.port), _p2p_loop)
    return {"message": f"Tentando conectar a {req.host}:{req.port}"}


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 (secao 7.4 do guia) - endpoint unico para clientes de terceiros
# (carteiras, explorers, outros nos) chamarem o protocolo pelo padrao usado por
# Bitcoin Core / clientes Ethereum, em vez de conhecer cada rota REST especifica.
# ---------------------------------------------------------------------------

@dispatcher.method("chain_getLength")
def _rpc_chain_length():
    return {"length": len(blockchain.chain), "mined_blocks": blockchain.mined_block_count}


@dispatcher.method("chain_getBlockByIndex")
def _rpc_block_by_index(index: int):
    if not isinstance(index, int) or index < 0 or index >= len(blockchain.chain):
        raise RPCError(INVALID_PARAMS, f"Bloco de indice {index!r} nao existe")
    return blockchain.chain[index].to_dict()


@dispatcher.method("chain_getBlockByHash")
def _rpc_block_by_hash(block_hash: str):
    for b in blockchain.chain:
        if b.hash == block_hash:
            return b.to_dict()
    raise RPCError(INVALID_PARAMS, "Bloco nao encontrado para o hash informado")


@dispatcher.method("chain_getStateRoot")
def _rpc_state_root():
    return {"block_index": blockchain.last_block.index, "state_root": blockchain.last_block.state_root}


@dispatcher.method("chain_isValid")
def _rpc_chain_is_valid():
    return {"is_valid": blockchain.is_chain_valid(), "total_work": blockchain.total_work()}


@dispatcher.method("account_getBalance")
def _rpc_get_balance(address: str):
    if not isinstance(address, str) or not address:
        raise RPCError(INVALID_PARAMS, "'address' e obrigatorio")
    return {"address": address, "balance": blockchain.get_balance(address), "coin": purchase.COIN_NAME}


@dispatcher.method("tx_getPending")
def _rpc_pending():
    return [tx.to_dict() for tx in blockchain.pending_transactions]


@dispatcher.method("tx_send")
def _rpc_tx_send(tx: dict):
    if not isinstance(tx, dict):
        raise RPCError(INVALID_PARAMS, "'tx' deve ser um objeto com os campos de uma transacao assinada")
    try:
        transaction = Transaction.from_dict(tx)
    except TypeError as exc:
        raise RPCError(INVALID_PARAMS, f"Transacao malformada: {exc}")
    if not blockchain.add_transaction(transaction):
        raise RPCError(INVALID_PARAMS, "Transacao invalida (assinatura, saldo, replay ou dados incorretos)")
    return {"tx_id": transaction.tx_id, "message": "Transacao aceita e aguardando mineracao"}


@dispatcher.method("net_chainId")
def _rpc_chain_id():
    return {"network_id": root_rules.NETWORK_ID}


@dispatcher.method("net_peerCount")
def _rpc_peer_count():
    return {"peer_count": len(p2p_node.peers) if p2p_node is not None else 0}


@dispatcher.method("net_status")
def _rpc_net_status():
    if p2p_node is None:
        return {"enabled": False}
    return {"enabled": True, "total_work": blockchain.total_work(), **p2p_node.status()}


@dispatcher.method("mining_getDifficulty")
def _rpc_difficulty():
    return {"base_difficulty_bits": blockchain.difficulty}


@app.post("/rpc")
async def json_rpc_endpoint(request: Request):
    """
    Endpoint JSON-RPC 2.0 unico (`chain_getLength`, `chain_getBlockByIndex`,
    `chain_getBlockByHash`, `chain_getStateRoot`, `chain_isValid`,
    `account_getBalance`, `tx_getPending`, `tx_send`, `net_chainId`,
    `net_peerCount`, `net_status`, `mining_getDifficulty`). Aceita tanto uma
    requisicao unica quanto um batch (lista de requisicoes) no mesmo POST,
    exatamente como a especificacao JSON-RPC 2.0 exige.
    """
    from fastapi import Response
    try:
        payload = await request.json()
    except Exception:
        return {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None}
    response = dispatcher.handle(payload)
    if response is None:
        return Response(status_code=204)
    return response


# ---------------------------------------------------------------------------
# WebSocket de eventos em tempo real (secao 7.5 do guia) - `newBlock` e
# `pendingTransaction` sao empurrados no instante em que acontecem, cobrindo
# blocos/tx originados tanto localmente (API HTTP) quanto recebidos via P2P.
# ---------------------------------------------------------------------------

@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await ws_hub.connect(websocket)
    try:
        while True:
            # o cliente nao precisa enviar nada; apenas mantemos a conexao viva
            # e descartamos qualquer mensagem recebida (ping/keep-alive futuro)
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_hub.disconnect(websocket)


# ---------------------------------------------------------------------------
# UI web de carteira (Jinja2 + JS puro) - `app/templates/` e `app/static/`.
# Serve como front-end funcional para criar/importar carteira (HD), enviar/
# receber pagamentos (inclusive via QR code), consultar histórico e operar no
# mercado (comprar/vender/liquidar), tudo conversando com a MESMA API REST já
# documentada acima. Pensada para rodar localmente contra o PROPRIO node do
# usuário (mesmo modelo de confiança do GUI oficial do Bitcoin Core).
# ---------------------------------------------------------------------------

def _render(request: Request, template_name: str):
    return _templates.TemplateResponse(request, template_name, {"environment": settings.environment})


@app.get("/wallet", response_class=HTMLResponse)
def ui_wallet_home(request: Request):
    return _render(request, "wallet_home.html")


@app.get("/wallet/send", response_class=HTMLResponse)
def ui_wallet_send(request: Request):
    return _render(request, "wallet_send.html")


@app.get("/wallet/receive", response_class=HTMLResponse)
def ui_wallet_receive(request: Request):
    return _render(request, "wallet_receive.html")


@app.get("/wallet/history", response_class=HTMLResponse)
def ui_wallet_history(request: Request):
    return _render(request, "wallet_history.html")


@app.get("/wallet/market", response_class=HTMLResponse)
def ui_wallet_market(request: Request):
    return _render(request, "wallet_market.html")


# ---------------------------------------------------------------------------
# Contas de usuario final (cadastro/login do site) + KYC com documento real
# (CPF, RG, foto do documento e selfie) - app/user_accounts.py.
# Diferente do login do painel admin (`/admin/auth/*`): este e o cadastro do
# CORRENTISTA da rede, usado para vincular carteiras e solicitar verificacao
# de identidade antes de operar acima do limite tier-0 (ver app/compliance.py).
# ---------------------------------------------------------------------------

class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    email: str = Field(..., min_length=5, max_length=200)
    password: str = Field(..., min_length=10, max_length=500)


class UserLoginRequest(BaseModel):
    username_or_email: str = Field(..., min_length=1, max_length=200)
    password: str = Field(..., min_length=1, max_length=500)


class UserChangePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=1, max_length=500)
    new_password: str = Field(..., min_length=10, max_length=500)


class LinkWalletRequest(BaseModel):
    address: str = Field(..., min_length=10, max_length=200)
    label: str = Field("", max_length=100)


def _require_user_session(authorization: Optional[str] = Header(None)) -> dict:
    token = _extract_bearer_token(authorization)
    return user_accounts.verify_session(token)


@app.post("/auth/register")
def auth_register(req: UserRegisterRequest):
    """Cria uma nova conta de usuario (correntista) - usuario/e-mail/senha.
    Nao exige CPF/documento neste momento (equivalente ao 'tier 0' do Pix -
    poder criar conta e navegar sem KYC); o KYC completo e feito depois via
    `/kyc/submit`, exigido para destravar limites maiores de transacao."""
    return user_accounts.register(req.username, req.email, req.password)


@app.post("/auth/login")
def auth_login(req: UserLoginRequest, request: Request):
    result = user_accounts.login(
        req.username_or_email, req.password,
        client_identity=_client_ip(request), ip=_client_ip(request),
    )
    return {**result, "expires_in_seconds": user_accounts.SESSION_TTL_SECONDS}


@app.post("/auth/logout")
def auth_logout(authorization: Optional[str] = Header(None)):
    token = _extract_bearer_token(authorization)
    if token:
        user_accounts.logout(token)
    return {"message": "Sessao encerrada"}


@app.get("/auth/me")
def auth_me(authorization: Optional[str] = Header(None)):
    user = _require_user_session(authorization)
    return user_accounts.public_profile(user)


@app.post("/auth/change-password")
def auth_change_password(req: UserChangePasswordRequest, authorization: Optional[str] = Header(None)):
    user = _require_user_session(authorization)
    user_accounts.change_password(user["id"], req.old_password, req.new_password)
    return {"message": "Senha alterada com sucesso"}


@app.post("/auth/wallets")
def auth_link_wallet(req: LinkWalletRequest, authorization: Optional[str] = Header(None)):
    user = _require_user_session(authorization)
    user_accounts.link_wallet(user["id"], req.address.strip(), req.label.strip())
    return {"message": "Carteira vinculada a conta", "address": req.address.strip()}


@app.get("/auth/wallets")
def auth_list_wallets(authorization: Optional[str] = Header(None)):
    user = _require_user_session(authorization)
    return {"wallets": storage.list_user_wallets(user["id"])}


@app.delete("/auth/wallets/{address}")
def auth_unlink_wallet(address: str, authorization: Optional[str] = Header(None)):
    user = _require_user_session(authorization)
    user_accounts.unlink_wallet(user["id"], address)
    return {"message": "Carteira desvinculada da conta"}


@app.post("/kyc/submit")
async def kyc_submit(
    full_name: str = Form(...),
    cpf: str = Form(...),
    rg: str = Form(...),
    birth_date: str = Form(...),
    document_front: UploadFile = File(...),
    document_back: UploadFile = File(...),
    selfie: UploadFile = File(...),
    authorization: Optional[str] = Header(None),
):
    """Envia uma solicitacao de verificacao de identidade (KYC) com documento
    com foto REAL - frente e verso do RG/CNH + uma selfie de prova de vida.
    Tudo e cifrado (AES-256-GCM) antes de tocar o disco e revisado
    MANUALMENTE por um operador do painel (`/admin/kyc/submissions`) - nunca
    aprovado automaticamente."""
    user = _require_user_session(authorization)
    front_bytes = await document_front.read()
    back_bytes = await document_back.read()
    selfie_bytes = await selfie.read()
    result = user_accounts.submit_kyc(
        user["id"], full_name, cpf, rg, birth_date,
        (front_bytes, document_front.content_type or ""),
        (back_bytes, document_back.content_type or ""),
        (selfie_bytes, selfie.content_type or ""),
    )
    return result


@app.get("/kyc/my-submissions")
def kyc_my_submissions(authorization: Optional[str] = Header(None)):
    user = _require_user_session(authorization)
    return {"submissions": user_accounts.my_kyc_submissions(user["id"])}


# ---------------------------------------------------------------------------
# Conformidade regulatoria (KYC/AML) - app/compliance.py
# ---------------------------------------------------------------------------

class KYCRegisterRequest(BaseModel):
    address: str
    full_name: str = Field(..., min_length=3, max_length=200)
    cpf: str = Field(..., min_length=11, max_length=14)
    tier: int = Field(1, ge=1, le=2)
    document_hash: Optional[str] = Field(None, max_length=128,
                                          description="SHA-256 do documento com foto (obrigatorio para tier 2)")


@app.post("/compliance/kyc/register")
def compliance_kyc_register(req: KYCRegisterRequest):
    """Registra/atualiza o KYC de um endereco de carteira. Tier 1 (basico)
    exige apenas nome+CPF; tier 2 (completo) tambem exige `document_hash`
    (hash do documento com foto - o arquivo em si NUNCA e enviado/armazenado
    por este endpoint, apenas seu hash, preservando privacidade)."""
    if not crypto_utils.is_valid_address(req.address):
        raise HTTPException(status_code=400, detail="Endereco invalido")
    try:
        record = compliance_engine.register_kyc(
            req.address, req.full_name, req.cpf, tier=req.tier, document_hash=req.document_hash,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "address": record.address, "tier": record.tier, "full_name": record.full_name,
        "created_at": record.created_at, "limit_pxc": _json_safe_limit(compliance_engine.limit_for_address(record.address)),
    }


def _json_safe_limit(limit_pxc: float) -> Optional[float]:
    """`float('inf')` (tier 2/completo = sem limite) nao e um valor JSON
    valido - convertido para `null` (semantica: "sem limite"), que qualquer
    cliente HTTP consegue interpretar sem quebrar o parser."""
    return None if limit_pxc == float("inf") else limit_pxc


@app.get("/compliance/kyc/status/{address}")
def compliance_kyc_status(address: str):
    """Consulta publica do TIER de KYC e limite de transacao vigente de um
    endereco (nunca expoe CPF/nome - apenas o nivel de verificacao e o
    limite resultante, informacao necessaria para qualquer carteira/exchange
    integrar corretamente os limites operacionais). `limit_pxc: null`
    significa tier completo (sem limite de valor por transacao)."""
    tier = compliance_engine.get_kyc_tier(address)
    return {"address": address, "tier": tier, "limit_pxc": _json_safe_limit(compliance_engine.limit_for_address(address))}



class SanctionEntryRequest(BaseModel):
    entry: str
    reason: str = Field(..., min_length=3, max_length=500)


@app.post("/compliance/sanctions/add")
def compliance_sanctions_add(req: SanctionEntryRequest):
    """Adiciona um endereco a lista de sancoes local (equivalente as listas
    OFAC/ONU/COAF) - qualquer transacao de/para este endereco passa a ser
    bloqueada pela rede. Operacao administrativa (produção real: restringir
    a operadores autorizados/Painel de Administracao)."""
    compliance_engine.add_to_sanctions_list(req.entry, req.reason)
    return {"message": "Endereco adicionado a lista de sancoes", "entry": req.entry}


@app.delete("/compliance/sanctions/{entry}")
def compliance_sanctions_remove(entry: str):
    compliance_engine.remove_from_sanctions_list(entry)
    return {"message": "Endereco removido da lista de sancoes", "entry": entry}


@app.get("/compliance/screen/{address}")
def compliance_screen(address: str):
    """Screening publico de contraparte (equivalente a uma checagem rapida
    de sancoes antes de enviar uma transacao) - qualquer carteira/exchange
    parceira pode consultar antes de liberar um envio para o endereco."""
    return compliance_engine.screen_counterparty(address)


@app.get("/compliance/reports/sar")
def compliance_sar_report(min_severity: str = "warning", limit: int = 200):
    """Relatorio de Atividade Suspeita (Suspicious Activity Report) - lista
    os alertas de AML/bloqueios de sancao mais recentes, nomenclatura usada
    por reguladores financeiros (COAF/FinCEN). Operacao administrativa."""
    if min_severity not in ("info", "warning", "critical"):
        raise HTTPException(status_code=400, detail="min_severity deve ser info, warning ou critical")
    return {"events": compliance_engine.suspicious_activity_report(min_severity, limit)}


# ---------------------------------------------------------------------------
# API estilo exchange (Binance-like) - app/exchange_api.py
# Permite que sites/exchanges parceiros (agregadores de preco, corretoras)
# se conectem usando o formato de API JA CONHECIDO da Binance, reduzindo o
# atrito de integracao para qualquer parceiro que ja opere com cripto.
# ---------------------------------------------------------------------------

@app.get("/api/v1/exchangeInfo")
def exchange_info_endpoint():
    return exchange_api.exchange_info()


@app.get("/api/v1/ticker/24hr")
def exchange_ticker_24hr():
    return exchange_api.get_ticker_24hr(market)


@app.get("/api/v1/klines")
def exchange_klines(interval: str = "1h", limit: int = 100):
    if not (1 <= limit <= 1000):
        raise HTTPException(status_code=400, detail="limit deve estar entre 1 e 1000")
    try:
        return exchange_api.get_klines(interval, limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/v1/depth")
def exchange_depth(limit: int = 50):
    return exchange_api.get_depth(market, limit)


@app.get("/api/v1/trades")
def exchange_trades(limit: int = 100):
    return exchange_api.get_recent_trades(blockchain, limit)


class ApiKeyCreateRequest(BaseModel):
    address: str


@app.post("/api/v1/apikey/create")
def exchange_apikey_create(req: ApiKeyCreateRequest):
    """Gera um par api_key/api_secret para automatizar trading (endpoints
    estilo Binance) sem nunca expor a chave privada da carteira. O
    `api_secret` retornado so aparece nesta resposta - guarde-o com
    seguranca (mesma UX de qualquer exchange real: AWS, Binance, etc.)."""
    if not crypto_utils.is_valid_address(req.address):
        raise HTTPException(status_code=400, detail="Endereco invalido")
    return exchange_api.create_api_key(req.address)


class ExchangeOrderRequest(BaseModel):
    api_key: str
    signature: str
    maker_private_key: str
    maker_public_key: str
    amount: float = Field(..., gt=0)
    price_brl_per_pxc: float = Field(..., gt=0)


@app.post("/api/v1/order")
def exchange_place_order(req: ExchangeOrderRequest, request: Request):
    """Cria uma ordem de venda no DEX de troca (`MarketEngine.create_swap_order`)
    autenticada via API key/HMAC (estilo Binance) em vez do fluxo interativo
    de carteira - pensado para bots/exchanges parceiras automatizarem
    negociacao. `signature = HMAC-SHA256(api_secret, f"{amount}:{price_brl_per_pxc}")`.

    Protegido por `bruteforce_guard`: tentativas repetidas de assinatura HMAC
    invalida a partir do mesmo IP sofrem bloqueio (cooldown) exponencialmente
    crescente, dificultando ataques de forca bruta contra o `api_secret`."""
    scope = "exchange_order_hmac"
    identity = _client_ip(request)
    try:
        bruteforce_guard.check(scope, identity)
    except BruteForceLockedError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    payload = f"{req.amount}:{req.price_brl_per_pxc}"
    try:
        address = exchange_api.verify_signature(req.api_key, payload, req.signature)
    except exchange_api.ExchangeAuthError as exc:
        bruteforce_guard.record_failure(scope, identity)
        raise HTTPException(status_code=401, detail=str(exc))
    bruteforce_guard.record_success(scope, identity)
    expected_address = crypto_utils.public_key_to_address(req.maker_public_key)
    if expected_address != address:
        raise HTTPException(status_code=403, detail="A chave publica informada nao pertence ao endereco da API key")
    try:
        order = market.create_swap_order(req.maker_private_key, req.maker_public_key, expected_address,
                                          req.amount, req.price_brl_per_pxc)
    except MarketError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"message": "Ordem criada", "order_id": order.order_id}


# ---------------------------------------------------------------------------
# Feed de noticias (site principal / React) - leitura publica, escrita
# protegida por token de administracao de conteudo (settings.admin_content_token)
# OU por uma sessao valida do Painel de Administracao (login real,
# `app/admin_auth.py`) - qualquer um dos dois e aceito, mantendo
# compatibilidade com scripts/integracoes que ja usavam so o token.
# ---------------------------------------------------------------------------

def _extract_bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


def _require_content_admin(
    request: Request,
    x_admin_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
) -> str:
    """Aceita QUALQUER um dos dois mecanismos de autenticacao de conteudo:
    o token compartilhado legado (`X-Admin-Token`) ou uma sessao de login
    real do painel (`Authorization: Bearer <token>`). Retorna a identidade
    do administrador (username da sessao, ou 'content-token' se autenticado
    via token legado) para fins de auditoria/log."""
    session_token = _extract_bearer_token(authorization)
    if session_token:
        return admin_auth.verify_session(session_token)
    news.require_admin_token(x_admin_token, client_identity=_client_ip(request))
    return "content-token"


@app.get("/news")
def list_news(limit: int = 20, offset: int = 0):
    limit = max(1, min(limit, 100))
    return {"posts": storage.list_news_posts(limit=limit, offset=offset, only_published=True)}


@app.get("/admin/news")
def admin_list_all_news(limit: int = 50, offset: int = 0, authorization: Optional[str] = Header(None)):
    """Lista TODAS as noticias (incluindo rascunhos e agendadas) - visao do
    operador no CMS, diferente do feed publico `/news` (so publicadas)."""
    _require_admin_session(authorization)
    limit = max(1, min(limit, 200))
    return {"posts": storage.list_news_posts(limit=limit, offset=offset, only_published=False)}


@app.get("/news/{post_id}")
def get_news(post_id: int):
    post = storage.get_news_post(post_id)
    if post is None:
        raise HTTPException(status_code=404, detail="Noticia nao encontrada")
    if post["status"] == "published" and (not post["scheduled_at"] or post["scheduled_at"] <= time.time()):
        storage.increment_news_views(post_id)
    return post


class CreateNewsRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    summary: str = Field("", max_length=500)
    body: str = Field("", max_length=20_000)
    image_url: str = Field("", max_length=500)
    author: str = Field("PixCripto", max_length=100)
    status: str = Field("published", pattern="^(draft|scheduled|published)$")
    category: str = Field("geral", max_length=50)
    tags: str = Field("", max_length=300)
    scheduled_at: Optional[float] = None


@app.post("/news")
def create_news(req: CreateNewsRequest, request: Request, x_admin_token: Optional[str] = Header(None), authorization: Optional[str] = Header(None)):
    if not feature_flags.is_enabled("news_publishing_enabled"):
        raise HTTPException(status_code=503, detail="Publicacao de noticias temporariamente desabilitada")
    _require_content_admin(request, x_admin_token, authorization)
    try:
        return news.create_post(
            req.title, req.summary, req.body, req.image_url, req.author,
            status=req.status, category=req.category, tags=req.tags, scheduled_at=req.scheduled_at,
        )
    except news.NewsError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.put("/news/{post_id}")
def update_news(post_id: int, req: CreateNewsRequest, request: Request, x_admin_token: Optional[str] = Header(None), authorization: Optional[str] = Header(None)):
    _require_content_admin(request, x_admin_token, authorization)
    if storage.get_news_post(post_id) is None:
        raise HTTPException(status_code=404, detail="Noticia nao encontrada")
    storage.update_news_post(
        post_id, req.title.strip(), req.summary.strip(), req.body.strip(), req.image_url.strip(),
        status=req.status, category=req.category.strip(), tags=req.tags.strip(), scheduled_at=req.scheduled_at,
    )
    return storage.get_news_post(post_id)


@app.delete("/news/{post_id}")
def delete_news(post_id: int, request: Request, x_admin_token: Optional[str] = Header(None), authorization: Optional[str] = Header(None)):
    _require_content_admin(request, x_admin_token, authorization)
    if not storage.delete_news_post(post_id):
        raise HTTPException(status_code=404, detail="Noticia nao encontrada")
    return {"message": "Noticia removida", "id": post_id}


@app.post("/news/upload-image")
async def upload_news_image(request: Request, file: UploadFile = File(...), x_admin_token: Optional[str] = Header(None), authorization: Optional[str] = Header(None)):
    admin_identity = _require_content_admin(request, x_admin_token, authorization)
    try:
        image_url = await news.save_uploaded_image(file)
    except news.NewsError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    disk_path = news.UPLOADS_DIR / image_url.rsplit("/", 1)[-1]
    size_bytes = disk_path.stat().st_size if disk_path.exists() else 0
    media.register_upload(disk_path.name, image_url, "news", size_bytes, file.content_type or "", admin_identity)
    return {"image_url": image_url}


# ---------------------------------------------------------------------------
# Painel de Administracao do site (`/admin`, React) - login real (usuario +
# senha), CMS de paginas estaticas, biblioteca de midia, chaves de
# funcionalidade e housekeeping. Tudo abaixo requer uma sessao valida
# (`Authorization: Bearer <token>` obtido em `/admin/auth/login`).
# ---------------------------------------------------------------------------

class AdminLoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=500)
    otp_code: Optional[str] = Field(None, min_length=4, max_length=20)


class AdminChangePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=1, max_length=500)
    new_password: str = Field(..., min_length=10, max_length=500)


def _require_admin_session(authorization: Optional[str] = Header(None)) -> str:
    token = _extract_bearer_token(authorization)
    return admin_auth.verify_session(token)


@app.get("/admin/auth/status")
def admin_auth_status():
    """Informa se o login do painel ja esta configurado (existe conta ou
    bootstrap definido no .env) - usado pela tela de login para diferenciar
    'nao configurado ainda' de 'usuario/senha incorretos'."""
    return {"login_enabled": admin_auth.is_login_enabled()}


@app.post("/admin/auth/login")
def admin_login(req: AdminLoginRequest, request: Request):
    result = admin_auth.login(
        req.username.strip(), req.password, client_identity=_client_ip(request), ip=_client_ip(request),
        otp_code=req.otp_code,
    )
    return {**result, "expires_in_seconds": settings.admin_session_ttl_seconds}


@app.post("/admin/auth/logout")
def admin_logout(authorization: Optional[str] = Header(None)):
    token = _extract_bearer_token(authorization)
    if token:
        admin_auth.logout(token)
    return {"message": "Sessao encerrada"}


@app.get("/admin/auth/me")
def admin_me(authorization: Optional[str] = Header(None)):
    username = _require_admin_session(authorization)
    user = storage.get_admin_user(username)
    return {"username": username, "role": user["role"] if user else "editor", "totp_enabled": bool(user and user["totp_enabled"])}


@app.post("/admin/auth/change-password")
def admin_change_password(req: AdminChangePasswordRequest, authorization: Optional[str] = Header(None)):
    current_username = _require_admin_session(authorization)
    admin_auth.change_password(current_username, req.old_password, req.new_password)
    return {"message": "Senha alterada com sucesso"}


# --- 2FA (TOTP) --------------------------------------------------------------

class Admin2faEnableRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)


class Admin2faDisableRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=500)


@app.post("/admin/auth/2fa/setup")
def admin_2fa_setup(authorization: Optional[str] = Header(None)):
    username = _require_admin_session(authorization)
    return admin_auth.start_totp_enrollment(username)


@app.post("/admin/auth/2fa/enable")
def admin_2fa_enable(req: Admin2faEnableRequest, authorization: Optional[str] = Header(None)):
    username = _require_admin_session(authorization)
    backup_codes = admin_auth.confirm_totp_enrollment(username, req.code)
    return {"message": "2FA ativado com sucesso", "backup_codes": backup_codes}


@app.post("/admin/auth/2fa/disable")
def admin_2fa_disable(req: Admin2faDisableRequest, authorization: Optional[str] = Header(None)):
    username = _require_admin_session(authorization)
    admin_auth.disable_totp(username, req.password)
    return {"message": "2FA desativado"}


# --- Gestao multi-usuario (somente 'owner') ----------------------------------

class CreateOperatorRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=10, max_length=500)
    role: str = Field("editor", pattern="^(owner|editor)$")


@app.get("/admin/users")
def admin_list_users(authorization: Optional[str] = Header(None)):
    _require_admin_session(authorization)
    return {"users": admin_auth.list_operators()}


@app.post("/admin/users")
def admin_create_user(req: CreateOperatorRequest, authorization: Optional[str] = Header(None)):
    username = _require_admin_session(authorization)
    admin_auth.create_operator(username, req.username.strip(), req.password, req.role)
    return {"message": "Operador criado", "username": req.username.strip(), "role": req.role}


@app.delete("/admin/users/{target_username}")
def admin_delete_user(target_username: str, authorization: Optional[str] = Header(None)):
    username = _require_admin_session(authorization)
    admin_auth.delete_operator(username, target_username)
    return {"message": "Operador removido", "username": target_username}


# --- Revisao de KYC (documentos com foto enviados pelos usuarios) -----------

class KycReviewRejectRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)


class KycReviewApproveRequest(BaseModel):
    tier: int = Field(2, ge=1, le=2)


@app.get("/admin/kyc/submissions")
def admin_kyc_list(status: Optional[str] = None, authorization: Optional[str] = Header(None)):
    """Lista as solicitacoes de verificacao de identidade enviadas pelos
    usuarios (filtravel por status: pending/approved/rejected) - NUNCA expoe
    CPF/RG/imagens aqui, apenas metadados; o detalhe cifrado so e decifrado
    em `/admin/kyc/submissions/{id}`, sob demanda explicita do operador."""
    _require_admin_session(authorization)
    return {"submissions": user_accounts.admin_list_kyc_submissions(status=status)}


@app.get("/admin/kyc/submissions/{submission_id}")
def admin_kyc_detail(submission_id: int, authorization: Optional[str] = Header(None)):
    """Decifra e retorna nome/CPF/RG/data de nascimento e as 3 imagens
    (documento frente/verso + selfie) como data-URI base64, para o operador
    validar visualmente antes de aprovar/rejeitar. Toda consulta a este
    endpoint deveria, em producao, tambem ser registrada em log de auditoria
    dedicado (dado extremamente sensivel)."""
    _require_admin_session(authorization)
    return user_accounts.admin_get_kyc_submission_detail(submission_id)


@app.post("/admin/kyc/submissions/{submission_id}/approve")
def admin_kyc_approve(submission_id: int, req: KycReviewApproveRequest, authorization: Optional[str] = Header(None)):
    username = _require_admin_session(authorization)
    user_accounts.admin_approve_kyc(submission_id, username, req.tier)
    return {"message": "KYC aprovado", "tier": req.tier}


@app.post("/admin/kyc/submissions/{submission_id}/reject")
def admin_kyc_reject(submission_id: int, req: KycReviewRejectRequest, authorization: Optional[str] = Header(None)):
    username = _require_admin_session(authorization)
    user_accounts.admin_reject_kyc(submission_id, username, req.reason)
    return {"message": "KYC rejeitado"}


# --- CMS de paginas estaticas -----------------------------------------------

class CmsPageRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    body: str = Field("", max_length=200_000)
    published: bool = True
    menu_order: int = 0
    show_in_menu: bool = False


@app.get("/pages/{slug}")
def get_public_page(slug: str):
    page = cms.get_page(slug, only_published=True)
    if page is None:
        raise HTTPException(status_code=404, detail="Pagina nao encontrada")
    return page


@app.get("/pages")
def list_public_pages():
    """Lista as paginas publicadas marcadas para exibir no menu (rodape/nav
    do site), ordenadas por `menu_order` - permite ao operador montar um menu
    institucional dinamico sem alterar codigo do front-end."""
    pages = [p for p in cms.list_pages(only_published=True) if p["show_in_menu"]]
    return {"pages": pages}


@app.get("/admin/pages")
def admin_list_pages(authorization: Optional[str] = Header(None)):
    _require_admin_session(authorization)
    return {"pages": cms.list_pages(only_published=False)}


@app.put("/admin/pages/{slug}")
def admin_upsert_page(slug: str, req: CmsPageRequest, authorization: Optional[str] = Header(None)):
    username = _require_admin_session(authorization)
    try:
        return cms.upsert_page(slug, req.title, req.body, req.published, username, menu_order=req.menu_order, show_in_menu=req.show_in_menu)
    except cms.CmsError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/admin/pages/{slug}")
def admin_delete_page(slug: str, authorization: Optional[str] = Header(None)):
    _require_admin_session(authorization)
    if not cms.delete_page(slug):
        raise HTTPException(status_code=404, detail="Pagina nao encontrada")
    return {"message": "Pagina removida", "slug": slug}


@app.get("/admin/pages/{slug}/revisions")
def admin_list_page_revisions(slug: str, authorization: Optional[str] = Header(None)):
    _require_admin_session(authorization)
    return {"revisions": cms.list_revisions(slug)}


@app.post("/admin/pages/{slug}/revisions/{version}/restore")
def admin_restore_page_revision(slug: str, version: int, authorization: Optional[str] = Header(None)):
    username = _require_admin_session(authorization)
    try:
        return cms.restore_revision(slug, version, username)
    except cms.CmsError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# --- Biblioteca de midia -----------------------------------------------------

@app.get("/admin/media")
def admin_list_media(limit: int = 100, offset: int = 0, authorization: Optional[str] = Header(None)):
    _require_admin_session(authorization)
    return {"files": media.list_media(limit=min(limit, 500), offset=offset), "stats": media.storage_stats()}


class MediaMetadataRequest(BaseModel):
    alt_text: Optional[str] = Field(None, max_length=300)
    tags: Optional[str] = Field(None, max_length=300)
    folder: Optional[str] = Field(None, max_length=100)


@app.put("/admin/media/{media_id}")
def admin_update_media(media_id: int, req: MediaMetadataRequest, authorization: Optional[str] = Header(None)):
    _require_admin_session(authorization)
    return media.update_metadata(media_id, alt_text=req.alt_text, tags=req.tags, folder=req.folder)


@app.delete("/admin/media/{media_id}")
def admin_delete_media(media_id: int, force: bool = False, authorization: Optional[str] = Header(None)):
    _require_admin_session(authorization)
    return media.delete_media(media_id, force=force)


# --- Chaves de funcionalidade (feature flags) -------------------------------

class FeatureFlagRequest(BaseModel):
    enabled: bool


@app.get("/admin/features")
def admin_list_features(authorization: Optional[str] = Header(None)):
    _require_admin_session(authorization)
    return {"flags": feature_flags.list_flags()}


@app.get("/features/public")
def public_feature_flags():
    """Subconjunto de flags que o frontend publico precisa saber ANTES de
    autenticar (ex.: exibir banner de manutencao, esconder botao de compra) -
    nunca expoe flags sensiveis de configuracao interna."""
    all_flags = {f["key"]: f["enabled"] for f in feature_flags.list_flags()}
    return {k: all_flags.get(k, True) for k in (
        "maintenance_mode", "purchases_enabled", "trading_enabled", "mining_enabled",
    )}


@app.post("/admin/features/{key}")
def admin_set_feature(key: str, req: FeatureFlagRequest, authorization: Optional[str] = Header(None)):
    _require_admin_session(authorization)
    try:
        feature_flags.set_flag(key, req.enabled)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"key": key, "enabled": req.enabled}


# --- Housekeeping ------------------------------------------------------------

@app.get("/admin/housekeeping/status")
def admin_housekeeping_status(authorization: Optional[str] = Header(None)):
    _require_admin_session(authorization)
    return housekeeping.status()


@app.get("/admin/housekeeping/history")
def admin_housekeeping_history(limit: int = 20, authorization: Optional[str] = Header(None)):
    _require_admin_session(authorization)
    return {"runs": housekeeping.history(limit=min(limit, 100))}


@app.post("/admin/housekeeping/run")
def admin_housekeeping_run(authorization: Optional[str] = Header(None)):
    username = _require_admin_session(authorization)
    return housekeeping.run_housekeeping(triggered_by=f"manual:{username}")


@app.get("/admin/housekeeping/backups")
def admin_list_backups(authorization: Optional[str] = Header(None)):
    _require_admin_session(authorization)
    return {"backups": housekeeping.list_backups()}


@app.post("/admin/housekeeping/backups")
def admin_create_backup(authorization: Optional[str] = Header(None)):
    _require_admin_session(authorization)
    return housekeeping.create_backup()


@app.delete("/admin/housekeeping/backups/{filename}")
def admin_delete_backup(filename: str, authorization: Optional[str] = Header(None)):
    _require_admin_session(authorization)
    if not housekeeping.delete_backup(filename):
        raise HTTPException(status_code=404, detail="Backup nao encontrado")
    return {"message": "Backup removido", "filename": filename}


# --- Configuracoes gerais do site --------------------------------------------

@app.get("/admin/settings")
def admin_get_settings(authorization: Optional[str] = Header(None)):
    _require_admin_session(authorization)
    return site_settings.get_all()


@app.put("/admin/settings")
def admin_update_settings(payload: dict, authorization: Optional[str] = Header(None)):
    username = _require_admin_session(authorization)
    return site_settings.update(payload, username)


@app.get("/settings/public")
def public_settings():
    """Configuracoes de identidade/institucionais seguras para expor
    publicamente (nome do site, tagline, contato, SEO, redes sociais) -
    usadas pelo front-end publico para montar cabecalho/rodape/meta tags."""
    return site_settings.get_all()


# --- Dashboard administrativo integrado ao PixCripto (chain/rede ao vivo) ----

@app.get("/admin/dashboard")
def admin_dashboard(authorization: Optional[str] = Header(None)):
    """Painel de controle que amarra o Painel de Administracao a rede
    PixCripto DE VERDADE em execucao no mesmo processo - nao apenas um CMS
    isolado. Mostra altura da cadeia, dificuldade atual, concentracao de
    hashrate (anti-monopolio), status de dump-control do mercado, oferta
    total e tamanho do mempool, tudo em tempo real."""
    _require_admin_session(authorization)
    difficulty = blockchain.difficulty_engine.status(blockchain.mined_block_count)
    concentration = blockchain.difficulty_engine.hash_concentration_stats(blockchain.recent_miners[-20:])
    try:
        dump = dump_status()
    except Exception:
        dump = None
    return {
        "chain": {
            "height": len(blockchain.chain),
            "mined_blocks": blockchain.mined_block_count,
            "mempool_size": len(blockchain.pending_transactions),
            "total_supply": blockchain.total_supply() if hasattr(blockchain, "total_supply") else None,
        },
        "difficulty": {
            "mode": difficulty.mode,
            "base_difficulty_bits": difficulty.base_bits,
            "max_bits_this_mode": difficulty.max_bits,
            "bitcoin_2020_equivalent_bits": difficulty.bitcoin_2020_equivalent_bits,
        },
        "network": {
            "window_size": len(blockchain.recent_miners[-20:]),
            **concentration,
        },
        "dump_control": dump,
        "feature_flags": {f["key"]: f["enabled"] for f in feature_flags.list_flags()},
        "housekeeping": housekeeping.status(),
    }


@app.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics():
    """Metricas no formato texto Prometheus."""
    now = time.time()

    chain_height = len(blockchain.chain)
    mined_blocks = blockchain.mined_block_count
    mempool_size = len(blockchain.pending_transactions)
    difficulty = getattr(blockchain, "current_difficulty", blockchain.difficulty)

    with honeypot._lock:
        events_snap = list(honeypot.events)
    low_count = sum(1 for e in events_snap if e.threat_score < 10)
    med_count = sum(1 for e in events_snap if 10 <= e.threat_score < 25)
    high_count = sum(1 for e in events_snap if e.threat_score >= 25)

    with bruteforce_guard._lock:
        active_lockouts = sum(1 for st in bruteforce_guard._states.values() if st.locked_until > now)

    try:
        integrity_result = source_integrity.check_integrity()
        integrity_ok = 0 if integrity_result["status"] == "tampering_detected" else 1
    except Exception:
        integrity_ok = -1

    try:
        admin_sessions = storage.count_active_admin_sessions()
        user_count = storage.count_user_accounts()
        kyc_pending = storage.count_pending_kyc()
    except Exception:
        admin_sessions = user_count = kyc_pending = -1

    lines = [
        "# HELP pixcripto_chain_height Numero total de blocos na cadeia (incluindo genesis)",
        "# TYPE pixcripto_chain_height gauge",
        f"pixcripto_chain_height {chain_height}",
        "",
        "# HELP pixcripto_chain_mined_blocks_total Total de blocos efetivamente minerados (excluindo genesis)",
        "# TYPE pixcripto_chain_mined_blocks_total counter",
        f"pixcripto_chain_mined_blocks_total {mined_blocks}",
        "",
        "# HELP pixcripto_mempool_size Numero de transacoes pendentes na mempool",
        "# TYPE pixcripto_mempool_size gauge",
        f"pixcripto_mempool_size {mempool_size}",
        "",
        "# HELP pixcripto_current_difficulty Dificuldade atual de mineracao (bits de leading zeros exigidos)",
        "# TYPE pixcripto_current_difficulty gauge",
        f"pixcripto_current_difficulty {difficulty}",
        "",
        "# HELP pixcripto_honeypot_events_total Total de eventos capturados pelo honeypot por faixa de ameaca",
        "# TYPE pixcripto_honeypot_events_total gauge",
        f'pixcripto_honeypot_events_total{{severity="low"}} {low_count}',
        f'pixcripto_honeypot_events_total{{severity="medium"}} {med_count}',
        f'pixcripto_honeypot_events_total{{severity="high"}} {high_count}',
        "",
        "# HELP pixcripto_bruteforce_active_lockouts Numero de identidades atualmente bloqueadas pelo anti-brute-force",
        "# TYPE pixcripto_bruteforce_active_lockouts gauge",
        f"pixcripto_bruteforce_active_lockouts {active_lockouts}",
        "",
        "# HELP pixcripto_source_integrity_ok 1 se o codigo-fonte esta integro, 0 se adulteracao detectada, -1 se verificacao falhou",
        "# TYPE pixcripto_source_integrity_ok gauge",
        f"pixcripto_source_integrity_ok {integrity_ok}",
        "",
        "# HELP pixcripto_admin_sessions_active Numero de sessoes de administrador ativas (nao expiradas)",
        "# TYPE pixcripto_admin_sessions_active gauge",
        f"pixcripto_admin_sessions_active {admin_sessions}",
        "",
        "# HELP pixcripto_user_accounts_total Total de contas de usuario cadastradas",
        "# TYPE pixcripto_user_accounts_total gauge",
        f"pixcripto_user_accounts_total {user_count}",
        "",
        "# HELP pixcripto_kyc_submissions_pending Submissoes de KYC aguardando revisao manual",
        "# TYPE pixcripto_kyc_submissions_pending gauge",
        f"pixcripto_kyc_submissions_pending {kyc_pending}",
    ]

    body = "\n".join(lines) + "\n"
    return PlainTextResponse(content=body, media_type="text/plain; version=0.0.4")


@app.get("/monitoring/alerts/recent")
def get_recent_alerts(limit: int = 50):
    """Retorna os ultimos N alertas disparados pelo sistema."""
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit deve estar entre 1 e 500")
    return {"alerts": monitoring.get_recent_alerts(limit=limit), "count": limit}





# ---------------------------------------------------------------------------
# Seguranca: verificacao de integridade do codigo-fonte + status anti-forca-bruta
# ---------------------------------------------------------------------------

@app.get("/security/integrity-status")
def security_integrity_status(request: Request, x_admin_token: Optional[str] = Header(None), authorization: Optional[str] = Header(None)):
    """
    Verifica se algum arquivo .py sob app/ foi alterado desde a ultima
    baseline confiavel registrada (defesa contra "source-code hacking" -
    adulteracao nao autorizada do codigo em producao). Aceita o token de
    administracao de conteudo legado OU uma sessao valida do painel.
    """
    _require_content_admin(request, x_admin_token, authorization)
    return source_integrity.check_integrity()


@app.post("/security/integrity-reset-baseline")
def security_integrity_reset(request: Request, x_admin_token: Optional[str] = Header(None), authorization: Optional[str] = Header(None)):
    """Aceita o estado ATUAL do codigo como novo baseline confiavel - usar
    deliberadamente pelo operador logo apos um deploy/atualizacao legitima
    do codigo, nunca automaticamente."""
    _require_content_admin(request, x_admin_token, authorization)
    return source_integrity.reset_baseline()


# ---------------------------------------------------------------------------
# UI de producao: React SPA (frontend/) servida pelo proprio FastAPI
# ---------------------------------------------------------------------------
# Em desenvolvimento o frontend roda no seu proprio servidor Vite (porta 5173),
# consumindo esta API via CORS. Para uma release real ("npm run build" em
# frontend/), o resultado (frontend/dist/) e servido diretamente por este
# processo sob o prefixo /app/, evitando depender de um servidor Node/nginx
# separado so para os arquivos estaticos. As rotas antigas em HTML/Jinja2
# (/wallet, /market, etc. na raiz) continuam funcionando sem conflito,
# pois o SPA vive inteiramente sob /app/*.
_FRONTEND_DIST = _APP_DIR.parent / "frontend" / "dist"
if (_FRONTEND_DIST / "index.html").exists():
    _frontend_assets_dir = _FRONTEND_DIST / "assets"
    if _frontend_assets_dir.exists():
        app.mount(
            "/app/assets",
            StaticFiles(directory=str(_frontend_assets_dir)),
            name="frontend-assets",
        )

    @app.get("/app", include_in_schema=False)
    @app.get("/app/", include_in_schema=False)
    @app.get("/app/{full_path:path}", include_in_schema=False)
    async def serve_frontend_spa(full_path: str = "") -> FileResponse:
        """Serve o SPA React para qualquer sub-rota de /app/* (roteamento
        client-side), delegando arquivos estaticos concretos (favicon, etc.)
        quando existem e caindo em index.html caso contrario."""
        candidate = (_FRONTEND_DIST / full_path).resolve() if full_path else None
        if (
            candidate is not None
            and str(candidate).startswith(str(_FRONTEND_DIST.resolve()))
            and candidate.is_file()
        ):
            return FileResponse(candidate)
        return FileResponse(_FRONTEND_DIST / "index.html")
else:
    logging.getLogger("pixcripto").warning(
        "frontend/dist nao encontrado - UI React nao sera servida em /app/. "
        "Rode 'npm run build' em frontend/ para gerar a build de producao."
    )
