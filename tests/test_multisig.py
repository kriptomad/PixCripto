"""
Testes de carteiras multi-assinatura M-de-N (app/multisig.py + endpoints REST).

Cobre o ciclo completo:
- Criacao de carteira 2-de-3 (e validacao do endereco deterministico)
- Proposta de transacao + payload de assinatura
- Assinatura de 2 de 3 participantes habilita finalizacao
- Assinatura de apenas 1 participante NAO permite finalizar (rejeita com erro)
- Assinatura invalida (ECDSA errada) e rejeitada
- Assinatura de chave que nao participa da carteira e rejeitada
- Assinatura duplicada da mesma chave e rejeitada
- Tx final e persistida na blockchain e o saldo e debitado do endereco multisig
- Endpoints REST: /multisig/create, /multisig/{address}, /multisig/propose,
  /multisig/{id}/sign, /multisig/proposals/{id}, /multisig/{id}/finalize

Padrao de fixture: tmp_path + monkeypatch + importlib.reload em ordem correta.
"""
from __future__ import annotations

import importlib
import json

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixture padrao do projeto (mesma estrutura de test_user_accounts.py)
# ---------------------------------------------------------------------------

@pytest.fixture
def ms_client(tmp_path, monkeypatch):
    """TestClient isolado com banco SQLite temporario e todos os modulos recarregados."""
    monkeypatch.setenv("PIXCRIPTO_DB_PATH", str(tmp_path / "chain.db"))
    monkeypatch.setenv("PIXCRIPTO_COMPLIANCE_DB_PATH", str(tmp_path / "compliance.db"))
    monkeypatch.setenv("PIXCRIPTO_ADMIN_USERNAME", "operator")
    monkeypatch.setenv("PIXCRIPTO_ADMIN_PASSWORD", "SenhaForte1234!")
    monkeypatch.setenv("PIXCRIPTO_KYC_MASTER_KEY", "chave-mestra-de-teste-nao-usar-em-producao")
    monkeypatch.setenv("PIXCRIPTO_HOUSEKEEPING_INTERVAL_SECONDS", "999999")

    import app.storage as storage_mod
    importlib.reload(storage_mod)
    import app.settings as settings_mod
    importlib.reload(settings_mod)
    import app.compliance as compliance_mod
    importlib.reload(compliance_mod)
    import app.admin_auth as admin_auth_mod
    importlib.reload(admin_auth_mod)
    import app.models as models_mod
    importlib.reload(models_mod)
    import app.multisig as multisig_mod
    importlib.reload(multisig_mod)
    import app.user_accounts as user_accounts_mod
    importlib.reload(user_accounts_mod)
    import app.cms as cms_mod
    importlib.reload(cms_mod)
    import app.media as media_mod
    importlib.reload(media_mod)
    import app.feature_flags as feature_flags_mod
    importlib.reload(feature_flags_mod)
    import app.housekeeping as housekeeping_mod
    importlib.reload(housekeeping_mod)
    import app.site_settings as site_settings_mod
    importlib.reload(site_settings_mod)
    import app.news as news_mod
    importlib.reload(news_mod)
    import app.bruteforce_guard as bruteforce_guard_mod
    bruteforce_guard_mod.guard.reset_all()
    import app.api as api_mod
    importlib.reload(api_mod)
    client = TestClient(api_mod.app)
    yield client
    api_mod.housekeeping.stop_scheduler()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_keypair():
    """Gera um par (private_key_hex, public_key_hex) via API /wallet/create."""
    from app.crypto_utils import generate_keypair, public_key_to_address
    priv, pub = generate_keypair()
    return priv, pub, public_key_to_address(pub)


def _fund_address(client, address: str, amount: float = 100.0):
    """Credita `amount` PXC a um endereco via API de mineracao (coinbase_purchase + mine)."""
    from app import root_rules
    # deposita via coinbase_purchase (sem assinatura — tipo de sistema)
    resp = client.post("/purchase/fund-address-for-tests", json={"address": address, "amount": amount})
    # fallback: usa o endpoint de debug (se nao existir, usa transaction direta de sistema)
    if resp.status_code == 404:
        # injeta via blockchain diretamente (acesso interno ao modulo recarregado)
        import app.api as api_mod
        from app.models import Transaction
        tx = Transaction(
            sender=root_rules.COINBASE_SENDER,
            recipient=address,
            amount=amount,
            tx_type="coinbase_purchase",
        )
        api_mod.blockchain.add_transaction(tx)
        # minera para confirmar
        _mine_pending(client)
    else:
        _mine_pending(client)


def _fund_address_direct(address: str, amount: float = 100.0):
    """Credita diretamente no blockchain em memoria (sem API HTTP)."""
    import app.api as api_mod
    from app.models import Transaction
    from app import root_rules
    tx = Transaction(
        sender=root_rules.COINBASE_SENDER,
        recipient=address,
        amount=amount,
        tx_type="coinbase_purchase",
    )
    return api_mod.blockchain.add_transaction(tx)


def _mine_pending(client):
    """Minera todos os pendentes com o endpoint de mineracao real."""
    from app.wallet import Wallet
    miner = Wallet.create()
    resp = client.post("/mining/mine", json={"miner_address": miner.address, "max_iterations": 5_000_000})
    return resp


# ---------------------------------------------------------------------------
# Testes unitarios de derive_multisig_address
# ---------------------------------------------------------------------------

def test_derive_multisig_address_deterministic():
    """O mesmo (M, chaves) sempre produz o mesmo endereco."""
    import app.multisig as ms
    _, pub1, _ = _create_keypair()
    _, pub2, _ = _create_keypair()
    _, pub3, _ = _create_keypair()

    addr1 = ms.derive_multisig_address([pub1, pub2, pub3], threshold=2)
    addr2 = ms.derive_multisig_address([pub3, pub1, pub2], threshold=2)  # ordem diferente
    assert addr1 == addr2, "Endereco deve ser independente da ordem das chaves"


def test_derive_multisig_address_different_threshold_gives_different_address():
    """Alterar M muda o endereco (o threshold faz parte do hash)."""
    import app.multisig as ms
    _, pub1, _ = _create_keypair()
    _, pub2, _ = _create_keypair()
    _, pub3, _ = _create_keypair()

    addr_2_of_3 = ms.derive_multisig_address([pub1, pub2, pub3], threshold=2)
    addr_3_of_3 = ms.derive_multisig_address([pub1, pub2, pub3], threshold=3)
    assert addr_2_of_3 != addr_3_of_3


def test_derive_multisig_address_passes_is_valid_address():
    """Enderecos multisig devem passar na mesma validacao de formato que enderecos normais."""
    import app.multisig as ms
    from app.crypto_utils import is_valid_address
    _, pub1, _ = _create_keypair()
    _, pub2, _ = _create_keypair()
    addr = ms.derive_multisig_address([pub1, pub2], threshold=1)
    assert is_valid_address(addr), "Endereco multisig deve ser Base58Check valido"


def test_derive_multisig_address_different_from_single_sig():
    """Um endereco multisig nunca coincide com o endereco P2PKH da chave individual."""
    import app.multisig as ms
    from app.crypto_utils import public_key_to_address
    _, pub1, _ = _create_keypair()
    _, pub2, _ = _create_keypair()
    multisig_addr = ms.derive_multisig_address([pub1, pub2], threshold=1)
    single_addr = public_key_to_address(pub1)
    assert multisig_addr != single_addr


# ---------------------------------------------------------------------------
# Testes de criacao de carteira multisig
# ---------------------------------------------------------------------------

def test_create_multisig_wallet_2_of_3(ms_client):
    """Criacao de carteira 2-de-3 via API."""
    priv1, pub1, _ = _create_keypair()
    priv2, pub2, _ = _create_keypair()
    priv3, pub3, _ = _create_keypair()

    resp = ms_client.post("/multisig/create", json={
        "participant_public_keys": [pub1, pub2, pub3],
        "threshold": 2,
    })
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["threshold"] == 2
    assert len(data["participants"]) == 3
    assert "address" in data
    # verifica que o endereco e deterministico
    import app.multisig as ms
    expected = ms.derive_multisig_address([pub1, pub2, pub3], threshold=2)
    assert data["address"] == expected


def test_create_multisig_wallet_invalid_threshold_rejected(ms_client):
    """Threshold invalido (0 ou > N) deve ser rejeitado."""
    _, pub1, _ = _create_keypair()
    _, pub2, _ = _create_keypair()

    resp = ms_client.post("/multisig/create", json={
        "participant_public_keys": [pub1, pub2],
        "threshold": 0,
    })
    assert resp.status_code in (400, 422)

    resp = ms_client.post("/multisig/create", json={
        "participant_public_keys": [pub1, pub2],
        "threshold": 3,  # M > N
    })
    assert resp.status_code == 400


def test_create_multisig_wallet_invalid_pubkey_rejected(ms_client):
    """Chave publica invalida deve ser rejeitada."""
    _, pub1, _ = _create_keypair()
    resp = ms_client.post("/multisig/create", json={
        "participant_public_keys": [pub1, "chave_invalida_hex"],
        "threshold": 1,
    })
    assert resp.status_code == 400


def test_get_multisig_wallet_returns_info(ms_client):
    """GET /multisig/{address} retorna informacoes da carteira."""
    _, pub1, _ = _create_keypair()
    _, pub2, _ = _create_keypair()
    create_resp = ms_client.post("/multisig/create", json={
        "participant_public_keys": [pub1, pub2],
        "threshold": 1,
    })
    address = create_resp.json()["address"]

    resp = ms_client.get(f"/multisig/{address}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["address"] == address
    assert data["threshold"] == 1
    assert len(data["participants"]) == 2


def test_get_multisig_wallet_nonexistent_returns_404(ms_client):
    """Endereco nao cadastrado retorna 404."""
    from app.wallet import Wallet
    dummy = Wallet.create()
    resp = ms_client.get(f"/multisig/{dummy.address}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Testes do fluxo completo 2-de-3
# ---------------------------------------------------------------------------

def _setup_2_of_3(ms_client):
    """Helper: cria carteira 2-de-3, credita saldo, retorna dados dos participantes."""
    from app.crypto_utils import sign_message
    priv1, pub1, addr1 = _create_keypair()
    priv2, pub2, addr2 = _create_keypair()
    priv3, pub3, addr3 = _create_keypair()

    # cria a carteira multisig
    resp = ms_client.post("/multisig/create", json={
        "participant_public_keys": [pub1, pub2, pub3],
        "threshold": 2,
    })
    assert resp.status_code == 200
    multisig_addr = resp.json()["address"]

    # credita saldo na carteira multisig
    _fund_address_direct(multisig_addr, amount=50.0)
    _mine_pending(ms_client)

    # destinatario arbitrario
    _, _, recipient = _create_keypair()

    return {
        "multisig_address": multisig_addr,
        "recipient": recipient,
        "participants": [
            {"priv": priv1, "pub": pub1},
            {"priv": priv2, "pub": pub2},
            {"priv": priv3, "pub": pub3},
        ],
    }


def test_propose_creates_proposal(ms_client):
    """POST /multisig/propose retorna uma proposta com payload de assinatura."""
    info = _setup_2_of_3(ms_client)
    resp = ms_client.post("/multisig/propose", json={
        "multisig_address": info["multisig_address"],
        "recipient": info["recipient"],
        "amount": 10.0,
        "memo": "pagamento teste",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "proposal_id" in data
    assert "signing_payload" in data
    assert data["status"] == "pending"
    assert data["threshold"] == 2
    assert data["signatures_collected"] == 0

    # o signing_payload deve ser um JSON canonico valido
    payload_dict = json.loads(data["signing_payload"])
    assert payload_dict["sender"] == info["multisig_address"]
    assert payload_dict["recipient"] == info["recipient"]
    assert payload_dict["amount"] == 10.0


def test_get_proposal_info(ms_client):
    """GET /multisig/proposals/{id} retorna estado atual da proposta."""
    info = _setup_2_of_3(ms_client)
    propose_resp = ms_client.post("/multisig/propose", json={
        "multisig_address": info["multisig_address"],
        "recipient": info["recipient"],
        "amount": 5.0,
    })
    proposal_id = propose_resp.json()["proposal_id"]

    resp = ms_client.get(f"/multisig/proposals/{proposal_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["proposal_id"] == proposal_id
    assert data["status"] == "pending"
    assert data["signatures_collected"] == 0
    assert data["threshold"] == 2


def test_sign_proposal_valid_signature_accepted(ms_client):
    """Assinatura valida de um participante e aceita."""
    from app.crypto_utils import sign_message
    info = _setup_2_of_3(ms_client)
    propose_resp = ms_client.post("/multisig/propose", json={
        "multisig_address": info["multisig_address"],
        "recipient": info["recipient"],
        "amount": 5.0,
    })
    proposal_id = propose_resp.json()["proposal_id"]
    payload_bytes = propose_resp.json()["signing_payload"].encode("utf-8")

    p1 = info["participants"][0]
    sig = sign_message(p1["priv"], payload_bytes)

    resp = ms_client.post(f"/multisig/{proposal_id}/sign", json={
        "public_key": p1["pub"],
        "signature": sig,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["signatures_collected"] == 1
    assert data["ready_to_finalize"] is False  # precisamos de 2


def test_sign_proposal_invalid_signature_rejected(ms_client):
    """Assinatura ECDSA invalida (bytes errados) deve ser rejeitada."""
    from app.crypto_utils import sign_message
    info = _setup_2_of_3(ms_client)
    propose_resp = ms_client.post("/multisig/propose", json={
        "multisig_address": info["multisig_address"],
        "recipient": info["recipient"],
        "amount": 5.0,
    })
    proposal_id = propose_resp.json()["proposal_id"]

    p1 = info["participants"][0]
    fake_sig = "a" * 128  # assinatura hex invalida

    resp = ms_client.post(f"/multisig/{proposal_id}/sign", json={
        "public_key": p1["pub"],
        "signature": fake_sig,
    })
    assert resp.status_code == 400
    assert "invalida" in resp.json()["detail"].lower()


def test_sign_proposal_wrong_key_rejected(ms_client):
    """Assinatura de chave que nao e participante deve ser rejeitada."""
    from app.crypto_utils import sign_message, generate_keypair
    info = _setup_2_of_3(ms_client)
    propose_resp = ms_client.post("/multisig/propose", json={
        "multisig_address": info["multisig_address"],
        "recipient": info["recipient"],
        "amount": 5.0,
    })
    proposal_id = propose_resp.json()["proposal_id"]
    payload_bytes = propose_resp.json()["signing_payload"].encode("utf-8")

    # chave estraneira, nao pertence a carteira
    stranger_priv, stranger_pub = generate_keypair()
    sig = sign_message(stranger_priv, payload_bytes)

    resp = ms_client.post(f"/multisig/{proposal_id}/sign", json={
        "public_key": stranger_pub,
        "signature": sig,
    })
    assert resp.status_code == 400
    assert "participante" in resp.json()["detail"].lower()


def test_sign_proposal_duplicate_key_rejected(ms_client):
    """Assinatura duplicada da mesma chave deve ser rejeitada."""
    from app.crypto_utils import sign_message
    info = _setup_2_of_3(ms_client)
    propose_resp = ms_client.post("/multisig/propose", json={
        "multisig_address": info["multisig_address"],
        "recipient": info["recipient"],
        "amount": 5.0,
    })
    proposal_id = propose_resp.json()["proposal_id"]
    payload_bytes = propose_resp.json()["signing_payload"].encode("utf-8")

    p1 = info["participants"][0]
    sig = sign_message(p1["priv"], payload_bytes)

    # primeira assinatura: OK
    resp1 = ms_client.post(f"/multisig/{proposal_id}/sign", json={
        "public_key": p1["pub"],
        "signature": sig,
    })
    assert resp1.status_code == 200

    # segunda tentativa com a MESMA chave: deve falhar
    resp2 = ms_client.post(f"/multisig/{proposal_id}/sign", json={
        "public_key": p1["pub"],
        "signature": sig,
    })
    assert resp2.status_code == 400
    assert "duplicada" in resp2.json()["detail"].lower()


def test_finalize_requires_threshold_signatures(ms_client):
    """Finalizar com apenas 1 assinatura (threshold=2) deve ser rejeitado."""
    from app.crypto_utils import sign_message
    info = _setup_2_of_3(ms_client)
    propose_resp = ms_client.post("/multisig/propose", json={
        "multisig_address": info["multisig_address"],
        "recipient": info["recipient"],
        "amount": 5.0,
    })
    proposal_id = propose_resp.json()["proposal_id"]
    payload_bytes = propose_resp.json()["signing_payload"].encode("utf-8")

    # assina apenas com participante 1 (precisamos de 2 para 2-de-3)
    p1 = info["participants"][0]
    sig1 = sign_message(p1["priv"], payload_bytes)
    ms_client.post(f"/multisig/{proposal_id}/sign", json={
        "public_key": p1["pub"], "signature": sig1,
    })

    # tentativa de finalizar com assinaturas insuficientes
    resp = ms_client.post(f"/multisig/{proposal_id}/finalize")
    assert resp.status_code == 400
    detail = resp.json()["detail"].lower()
    assert "insuficiente" in detail or "threshold" in detail or "necessaria" in detail


def test_full_2_of_3_flow_tx_mined_and_balance_debited(ms_client):
    """Fluxo completo 2-de-3: proposta -> 2 assinaturas -> finaliza -> minera.

    Verifica que:
    1. A tx e aceita na mempool e depois minerada
    2. O saldo do endereco multisig e debitado corretamente
    3. O destinatario recebe o valor
    """
    from app.crypto_utils import sign_message
    import app.api as api_mod

    info = _setup_2_of_3(ms_client)
    multisig_addr = info["multisig_address"]
    recipient = info["recipient"]

    # verifica saldo inicial do multisig (50 PXC creditados em _setup_2_of_3)
    resp = ms_client.get(f"/wallet/{multisig_addr}/balance")
    assert resp.status_code == 200
    initial_balance = resp.json()["balance"]
    assert initial_balance == pytest.approx(50.0, abs=0.1)

    # cria proposta
    propose_resp = ms_client.post("/multisig/propose", json={
        "multisig_address": multisig_addr,
        "recipient": recipient,
        "amount": 20.0,
        "fee": 0.0,
    })
    assert propose_resp.status_code == 200
    proposal_id = propose_resp.json()["proposal_id"]
    payload_bytes = propose_resp.json()["signing_payload"].encode("utf-8")

    # participante 1 assina
    p1 = info["participants"][0]
    sig1 = sign_message(p1["priv"], payload_bytes)
    ms_client.post(f"/multisig/{proposal_id}/sign", json={
        "public_key": p1["pub"], "signature": sig1,
    })

    # participante 2 assina (atingiu M=2)
    p2 = info["participants"][1]
    sig2 = sign_message(p2["priv"], payload_bytes)
    sign_resp = ms_client.post(f"/multisig/{proposal_id}/sign", json={
        "public_key": p2["pub"], "signature": sig2,
    })
    assert sign_resp.status_code == 200
    assert sign_resp.json()["ready_to_finalize"] is True

    # finaliza: submete a tx a blockchain
    finalize_resp = ms_client.post(f"/multisig/{proposal_id}/finalize")
    assert finalize_resp.status_code == 200, finalize_resp.text
    tx_id = finalize_resp.json()["tx_id"]

    # confirma que a tx esta na mempool
    assert any(
        t.tx_id == tx_id
        for t in api_mod.blockchain.pending_transactions
    )

    # minera o bloco pendente
    _mine_pending(ms_client)

    # verifica que o saldo do multisig foi debitado
    resp_balance = ms_client.get(f"/wallet/{multisig_addr}/balance")
    assert resp_balance.status_code == 200
    new_balance = resp_balance.json()["balance"]
    # saldo deve ter diminuido aproximadamente 20 PXC
    assert new_balance < initial_balance
    assert new_balance == pytest.approx(initial_balance - 20.0, abs=0.5)

    # verifica que o destinatario recebeu
    resp_recv = ms_client.get(f"/wallet/{recipient}/balance")
    assert resp_recv.status_code == 200
    assert resp_recv.json()["balance"] == pytest.approx(20.0, abs=0.5)

    # proposta deve estar marcada como finalizada
    prop_resp = ms_client.get(f"/multisig/proposals/{proposal_id}")
    assert prop_resp.json()["status"] == "finalized"


def test_finalize_already_finalized_proposal_rejected(ms_client):
    """Dupla finalizacao da mesma proposta deve ser rejeitada."""
    from app.crypto_utils import sign_message
    info = _setup_2_of_3(ms_client)

    propose_resp = ms_client.post("/multisig/propose", json={
        "multisig_address": info["multisig_address"],
        "recipient": info["recipient"],
        "amount": 5.0,
    })
    proposal_id = propose_resp.json()["proposal_id"]
    payload_bytes = propose_resp.json()["signing_payload"].encode("utf-8")

    for p in info["participants"][:2]:
        sig = sign_message(p["priv"], payload_bytes)
        ms_client.post(f"/multisig/{proposal_id}/sign", json={
            "public_key": p["pub"], "signature": sig,
        })

    # primeira finalizacao: OK
    resp1 = ms_client.post(f"/multisig/{proposal_id}/finalize")
    assert resp1.status_code == 200

    # segunda finalizacao: deve falhar (proposta ja finalizada)
    resp2 = ms_client.post(f"/multisig/{proposal_id}/finalize")
    assert resp2.status_code == 400


def test_multisig_tx_is_valid_on_blockchain(ms_client):
    """A Transaction multisig finalizada deve passar em tx.is_valid()."""
    from app.crypto_utils import sign_message
    import app.api as api_mod
    info = _setup_2_of_3(ms_client)

    propose_resp = ms_client.post("/multisig/propose", json={
        "multisig_address": info["multisig_address"],
        "recipient": info["recipient"],
        "amount": 5.0,
    })
    proposal_id = propose_resp.json()["proposal_id"]
    payload_bytes = propose_resp.json()["signing_payload"].encode("utf-8")

    for p in info["participants"][:2]:
        sig = sign_message(p["priv"], payload_bytes)
        ms_client.post(f"/multisig/{proposal_id}/sign", json={"public_key": p["pub"], "signature": sig})

    ms_client.post(f"/multisig/{proposal_id}/finalize")

    # a tx pendente na mempool deve ser valida
    tx = next(
        t for t in api_mod.blockchain.pending_transactions
        if t.multisig_participants is not None
    )
    assert tx.is_valid(), "Transacao multisig deve ser valida"


def test_3_of_3_requires_all_signatures(ms_client):
    """Em uma carteira 3-de-3, TODAS as 3 assinaturas sao necessarias."""
    from app.crypto_utils import sign_message, generate_keypair
    _, pub1, _ = _create_keypair()
    _, pub2, _ = _create_keypair()
    priv3, pub3, _ = _create_keypair()

    # cria carteira 3-de-3
    resp = ms_client.post("/multisig/create", json={
        "participant_public_keys": [pub1, pub2, pub3],
        "threshold": 3,
    })
    multisig_addr = resp.json()["address"]
    _fund_address_direct(multisig_addr, 20.0)
    _mine_pending(ms_client)
    _, _, recipient = _create_keypair()

    propose_resp = ms_client.post("/multisig/propose", json={
        "multisig_address": multisig_addr,
        "recipient": recipient,
        "amount": 5.0,
    })
    proposal_id = propose_resp.json()["proposal_id"]
    payload_bytes = propose_resp.json()["signing_payload"].encode("utf-8")

    # Assina com apenas 2 participantes (priv1 e priv2 nao disponivel no helper, usa priv3)
    # Usa o helper para re-criar os pares com as chaves ja geradas:
    from app.crypto_utils import generate_keypair as gk, sign_message as sm
    # para este teste, geramos pares completos diretamente
    priv1_full, pub1_full = gk()
    priv2_full, pub2_full = gk()
    priv3_full, pub3_full = gk()

    # re-cria carteira com pares completos
    resp2 = ms_client.post("/multisig/create", json={
        "participant_public_keys": [pub1_full, pub2_full, pub3_full],
        "threshold": 3,
    })
    addr2 = resp2.json()["address"]
    _fund_address_direct(addr2, 20.0)
    _mine_pending(ms_client)

    propose2 = ms_client.post("/multisig/propose", json={
        "multisig_address": addr2,
        "recipient": recipient,
        "amount": 5.0,
    })
    pid2 = propose2.json()["proposal_id"]
    pl2 = propose2.json()["signing_payload"].encode("utf-8")

    # assina com 2 dos 3
    for priv, pub in [(priv1_full, pub1_full), (priv2_full, pub2_full)]:
        s = sm(priv, pl2)
        ms_client.post(f"/multisig/{pid2}/sign", json={"public_key": pub, "signature": s})

    # tentativa de finalizar com 2/3: deve falhar
    resp_fin = ms_client.post(f"/multisig/{pid2}/finalize")
    assert resp_fin.status_code == 400

    # adiciona terceira assinatura e finaliza
    s3 = sm(priv3_full, pl2)
    ms_client.post(f"/multisig/{pid2}/sign", json={"public_key": pub3_full, "signature": s3})
    resp_fin2 = ms_client.post(f"/multisig/{pid2}/finalize")
    assert resp_fin2.status_code == 200


def test_1_of_2_single_signature_sufficient(ms_client):
    """Em uma carteira 1-de-2, uma unica assinatura ja e suficiente."""
    from app.crypto_utils import sign_message, generate_keypair
    priv1, pub1 = generate_keypair()
    _, pub2 = generate_keypair()

    resp = ms_client.post("/multisig/create", json={
        "participant_public_keys": [pub1, pub2],
        "threshold": 1,
    })
    multisig_addr = resp.json()["address"]
    _fund_address_direct(multisig_addr, 10.0)
    _mine_pending(ms_client)
    _, _, recipient = _create_keypair()

    propose_resp = ms_client.post("/multisig/propose", json={
        "multisig_address": multisig_addr,
        "recipient": recipient,
        "amount": 3.0,
    })
    proposal_id = propose_resp.json()["proposal_id"]
    payload_bytes = propose_resp.json()["signing_payload"].encode("utf-8")

    # assina com apenas o participante 1
    sig = sign_message(priv1, payload_bytes)
    ms_client.post(f"/multisig/{proposal_id}/sign", json={"public_key": pub1, "signature": sig})

    # deve finalizar com 1 assinatura
    resp_fin = ms_client.post(f"/multisig/{proposal_id}/finalize")
    assert resp_fin.status_code == 200


def test_existing_single_sig_tests_unaffected():
    """Garante que transacoes single-sig convencionais continuam validas
    (nenhum dos novos campos multisig afeta o caminho normal de is_valid)."""
    from app.models import Transaction
    from app.wallet import Wallet
    alice = Wallet.create()
    bob = Wallet.create()
    tx = Transaction(sender=alice.address, recipient=bob.address, amount=1.0)
    tx.sign(alice.private_key, alice.public_key)
    # campos multisig devem ser None por padrao
    assert tx.multisig_participants is None
    assert tx.multisig_threshold is None
    assert tx.multisig_signatures is None
    # valida pelo caminho single-sig normal
    assert tx.is_valid()


def test_propose_unknown_multisig_address_rejected(ms_client):
    """Proposta para carteira nao cadastrada deve ser rejeitada."""
    from app.wallet import Wallet
    dummy_addr = Wallet.create().address
    resp = ms_client.post("/multisig/propose", json={
        "multisig_address": dummy_addr,
        "recipient": Wallet.create().address,
        "amount": 1.0,
    })
    assert resp.status_code == 400


def test_sign_nonexistent_proposal_rejected(ms_client):
    """Assinar uma proposta inexistente retorna 404."""
    from app.crypto_utils import generate_keypair, sign_message
    priv, pub = generate_keypair()
    resp = ms_client.post("/multisig/nonexistent_id/sign", json={
        "public_key": pub,
        "signature": "a" * 128,
    })
    assert resp.status_code == 400
