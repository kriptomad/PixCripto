"""
Testes de robustez ampliados (secao 8 do guia "blockchain-do-zero.md" -
"testes de rede e seguranca"): fuzzing leve de payloads malformados contra a
API HTTP (garante que entradas invalidas gerem 4xx tratado, nunca um 500/crash
nao tratado) e testes de carga/throughput da mempool (muitas tx simultaneas,
priorizacao por fee, e o limite `max_tx` por bloco).

Usa `fastapi.testclient.TestClient` SEM o context manager (`with ... as`) -
isso evita disparar os eventos de `startup` (que sobem o `P2PNode` real numa
porta TCP), mantendo estes testes rapidos e sem efeitos colaterais de rede.
"""
import time

import pytest
from fastapi.testclient import TestClient

from app import crypto_utils, root_rules
from app.api import app, blockchain
from app.models import Transaction

client = TestClient(app)


# ---------------------------------------------------------------------------
# Fuzzing leve de payloads malformados - a API nunca deve retornar 500 para
# entrada malformada, apenas 4xx (erro de validacao tratado)
# ---------------------------------------------------------------------------

MALFORMED_JSON_PAYLOADS = [
    {},
    {"sender_private_key": None, "sender_public_key": None, "recipient": None, "amount": None},
    {"sender_private_key": "", "sender_public_key": "", "recipient": "", "amount": -1},
    {"sender_private_key": 12345, "sender_public_key": [], "recipient": {}, "amount": "abc"},
    {"sender_private_key": "x" * 100_000, "sender_public_key": "y" * 100_000,
     "recipient": "z" * 100_000, "amount": 1.0},
]


@pytest.mark.parametrize("payload", MALFORMED_JSON_PAYLOADS)
def test_transaction_send_never_500s_on_malformed_input(payload):
    resp = client.post("/transaction/send", json=payload)
    assert resp.status_code < 500, f"payload {payload} causou erro de servidor: {resp.text}"


def test_transaction_send_never_500s_on_non_finite_amount():
    """`inf`/`nan` nao sao JSON valido pelo padrao estrito - httpx (cliente)
    recusa serializa-los via `json=`, entao construimos o corpo bruto
    manualmente (como um atacante enviando bytes crus faria) para garantir
    que o SERVIDOR trata isso com um 4xx, nunca um 500."""
    for raw_body in (
        b'{"sender_private_key":"a","sender_public_key":"b","recipient":"c","amount":Infinity}',
        b'{"sender_private_key":"a","sender_public_key":"b","recipient":"c","amount":NaN}',
        b'{"sender_private_key":"a","sender_public_key":"b","recipient":"c","amount":1e400}',
    ):
        resp = client.post("/transaction/send", content=raw_body,
                            headers={"Content-Type": "application/json"})
        assert resp.status_code < 500, f"corpo {raw_body!r} causou erro de servidor: {resp.text}"


@pytest.mark.parametrize("payload", [
    {},
    {"sender": None, "recipient": None, "amount": None, "tx_id": None, "timestamp": None,
     "signature": None, "public_key": None},
    {"sender": "a" * 10_000, "recipient": "b", "amount": 1, "tx_id": "x", "timestamp": 0,
     "signature": "s", "public_key": "p"},
    {"sender": "a", "recipient": "b", "amount": "not-a-number", "tx_id": "x", "timestamp": "not-a-number",
     "signature": "s", "public_key": "p"},
])
def test_submit_signed_transaction_never_500s_on_malformed_input(payload):
    resp = client.post("/transaction/submit-signed", json=payload)
    assert resp.status_code < 500, f"payload {payload} causou erro de servidor: {resp.text}"


@pytest.mark.parametrize("payload", [
    {},
    {"sender_public_key": None, "sender_private_key": None, "bytecode_hex": None},
    {"sender_public_key": "x", "sender_private_key": "y", "bytecode_hex": "not-hex-zz"},
    {"sender_public_key": "x", "sender_private_key": "y", "bytecode_hex": "ff" * 50_000},  # excede o teto
    {"sender_public_key": 123, "sender_private_key": [], "bytecode_hex": {}},
])
def test_contract_deploy_never_500s_on_malformed_input(payload):
    resp = client.post("/contracts/deploy", json=payload)
    assert resp.status_code < 500, f"payload {payload} causou erro de servidor: {resp.text}"


@pytest.mark.parametrize("payload", [
    {},
    {"sender_public_key": "x", "sender_private_key": "y", "contract_address": "endereco-invalido"},
    {"sender_public_key": "x", "sender_private_key": "y", "contract_address": "P" + "1" * 40,
     "calldata_hex": "not-hex"},
    {"sender_public_key": None, "sender_private_key": None, "contract_address": None},
])
def test_contract_call_never_500s_on_malformed_input(payload):
    resp = client.post("/contracts/call", json=payload)
    assert resp.status_code < 500, f"payload {payload} causou erro de servidor: {resp.text}"


@pytest.mark.parametrize("payload", [
    None,
    {},
    {"jsonrpc": "1.0", "method": "chain_getLength", "id": 1},   # versao errada
    {"jsonrpc": "2.0", "method": None, "id": 1},
    {"jsonrpc": "2.0", "method": "metodo_que_nao_existe", "params": {}, "id": 1},
    {"jsonrpc": "2.0", "method": "tx_send", "params": "nao-e-dict-nem-lista", "id": 1},
    [{"jsonrpc": "2.0", "method": "chain_getLength", "id": 1}, "lixo", 12345],  # batch com item invalido
    "isso nem e um objeto json valido de rpc",
])
def test_rpc_endpoint_never_500s_on_malformed_input(payload):
    resp = client.post("/rpc", json=payload)
    assert resp.status_code < 500, f"payload {payload!r} causou erro de servidor: {resp.text}"


def test_get_contract_code_handles_bogus_address_gracefully():
    resp = client.get("/contracts/isso-nao-e-um-endereco-valido/code")
    assert resp.status_code == 404


def test_get_contract_storage_handles_non_integer_key_gracefully():
    resp = client.get("/contracts/PabcdefPabcdefPabcdefPabcdefPabc/storage/not-an-int")
    assert resp.status_code == 422  # FastAPI rejeita o path param `key: int` antes de chegar no handler


# ---------------------------------------------------------------------------
# Testes de carga/throughput da mempool
# ---------------------------------------------------------------------------

def _make_funded_wallet(chain, amount: float = 100_000.0):
    priv, pub = crypto_utils.generate_keypair()
    address = crypto_utils.public_key_to_address(pub)
    fund_tx = Transaction(sender=root_rules.COINBASE_SENDER, recipient=address, amount=amount,
                           tx_type="coinbase_purchase")
    assert chain.add_transaction(fund_tx)
    block = chain.build_candidate_block(address)
    # dificuldade "demo" e trivial o bastante para minerar em memoria rapido
    nonce = 0
    while True:
        block.nonce = nonce
        h = block.compute_hash()
        if block.meets_difficulty(h):
            break
        nonce += 1
    assert chain.submit_mined_block(block, nonce, h)
    return priv, pub, address


def test_mempool_accepts_high_volume_of_transactions_quickly():
    from app.models import Blockchain
    chain = Blockchain(difficulty_mode="demo")
    priv, pub, address = _make_funded_wallet(chain, amount=100_000.0)

    n = 300
    start = time.time()
    accepted = 0
    for i in range(n):
        tx = Transaction(sender=address, recipient=address, amount=0.01, fee=float(i) / 1000.0,
                          memo=f"carga-{i}")
        tx.sign(priv, pub)
        if chain.add_transaction(tx):
            accepted += 1
    elapsed = time.time() - start

    # limite anti-flood por remetente (`MAX_PENDING_TX_PER_ADDRESS`) deve ser
    # respeitado - nem toda tx enviada e aceita se exceder o teto por endereco
    assert accepted <= root_rules.MAX_PENDING_TX_PER_ADDRESS
    assert accepted > 0
    assert elapsed < 5.0, f"processar {n} tx pendentes levou {elapsed:.2f}s (esperado < 5s)"


def test_mempool_prioritizes_highest_fee_first_under_load():
    from app.models import Blockchain
    chain = Blockchain(difficulty_mode="demo")
    priv, pub, address = _make_funded_wallet(chain, amount=100_000.0)

    fees = [0.001, 0.5, 0.01, 0.9, 0.05]
    for fee in fees:
        tx = Transaction(sender=address, recipient=address, amount=0.01, fee=fee)
        tx.sign(priv, pub)
        assert chain.add_transaction(tx)

    block = chain.build_candidate_block(address, max_tx=3)  # so cabem as 3 de maior fee
    non_coinbase = [t for t in block.transactions if t.tx_type != "coinbase_mining"]
    assert len(non_coinbase) == 3
    included_fees = sorted((t.fee for t in non_coinbase), reverse=True)
    assert included_fees == sorted(fees, reverse=True)[:3]


def test_max_tx_per_block_is_enforced_under_heavy_mempool():
    from app.models import Blockchain
    chain = Blockchain(difficulty_mode="demo")
    priv, pub, address = _make_funded_wallet(chain, amount=100_000.0)

    for i in range(40):
        tx = Transaction(sender=address, recipient=address, amount=0.01, fee=float(i))
        tx.sign(priv, pub)
        assert chain.add_transaction(tx)

    block = chain.build_candidate_block(address, max_tx=10)
    non_coinbase = [t for t in block.transactions if t.tx_type != "coinbase_mining"]
    assert len(non_coinbase) == 10
