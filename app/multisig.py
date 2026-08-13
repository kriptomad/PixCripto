"""
Carteiras Multi-assinatura M-de-N para o PixCripto.

Design geral
============
Uma carteira multisig e definida por:
  - N chaves publicas participantes (secp256k1, mesmas usadas em carteiras normais)
  - M (threshold): quantas assinaturas validas sao exigidas para autorizar um gasto

Endereco multisig (P2SH-like simplificado)
==========================================
O endereco e derivado deterministicamente de M e das N chaves publicas ordenadas
lexicograficamente:

    script  = "multisig:{M}:{pubkey1}:{pubkey2}:...:{pubkeyN}"  (chaves em ordem)
    address = Base58Check(ripemd160(sha256(script.encode("utf-8"))), version=ADDRESS_VERSION_BYTE)

Usar o mesmo byte de versao (0x37) das carteiras normais permite que enderecos
multisig passem nas mesmas validacoes de formato (is_valid_address). A unicidade
e garantida pelo prefixo "multisig:" + a lista completa de chaves: e matematicamente
impossivel colidir com um endereco P2PKH (que e derivado de uma unica chave publica
sem prefixo textual).

Fluxo de uma transacao multisig (PSBT-like simplificado)
=========================================================
1. Qualquer parte cria uma "proposta" com os dados economicos da tx
   (carteira multisig remetente, destinatario, valor, taxa, memo).
   A proposta e persistida em `multisig_proposals` com status "pending".

2. Cada participante:
   a. Obtem o payload de assinatura da proposta (via GET /multisig/proposals/{id})
   b. Assina localmente com sua chave privada usando `crypto_utils.sign_message`
   c. Envia sua assinatura via POST /multisig/{proposal_id}/sign

3. Quando M assinaturas validas forem coletadas, qualquer parte pode chamar
   POST /multisig/{proposal_id}/finalize, que:
   - Monta a Transaction com campos multisig (participants, threshold, signatures)
   - Submete ao fluxo normal de blockchain via `blockchain.add_transaction`
   - Marca a proposta como "finalized"

Validacao na blockchain
=======================
`Transaction.is_valid()` detecta transacoes multisig pelo campo `multisig_participants`
(nao-None) e executa `_is_valid_multisig()`:
  - Recomputa o endereco multisig a partir de (participants, threshold) e verifica
    que bate com `sender` (auto-validavel, sem consulta ao banco)
  - Verifica cada assinatura via ECDSA real (crypto_utils.verify_signature)
  - Garante M assinaturas distintas de chaves participantes
  - Rejeita duplicatas, chaves estranhas e assinaturas invalidas

Retro-compatibilidade total
============================
Transacoes existentes (single-sig) nao sao afetadas: os campos multisig sao
Optional com default None e nao fazem parte do signing_payload() — o payload
de assinatura e identico ao de qualquer transfer normal, para que ferramentas
existentes de assinatura funcionem sem modificacao.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import List, Optional

from . import crypto_utils, storage, root_rules
from .models import Transaction

# Limite de participantes por carteira multisig (anti-DoS de armazenamento e
# custo de verificacao: cada assinatura exige uma operacao ECDSA).
MULTISIG_MAX_PARTICIPANTS = 15


# ---------------------------------------------------------------------------
# Derivacao de endereco multisig
# ---------------------------------------------------------------------------

def derive_multisig_address(participant_public_keys: List[str], threshold: int) -> str:
    """Deriva o endereco multisig deterministicamente a partir de M e das N
    chaves publicas participantes.

    O endereco e determinístico: as mesmas N chaves + mesmo M sempre produzem
    o mesmo endereco, em qualquer maquina e a qualquer momento — isso e
    essencial para que pagadores possam auditar e verificar o endereco de uma
    carteira multisig sem precisar confiar em quem a criou.

    Formato do "script" (inspirado em P2SH do Bitcoin, simplificado):
        "multisig:{M}:{pub1}:{pub2}:...:{pubN}"  (chaves em ordem lexicografica)

    Hash: ripemd160(sha256(script.encode("utf-8"))) com Base58Check e o mesmo
    byte de versao (0x37) das carteiras normais.

    Garantia de nao-colisao com enderecos P2PKH: o prefixo "multisig:" garante
    que a entrada do hash nunca e igual a uma chave publica nua de 64 bytes.
    """
    if not participant_public_keys:
        raise ValueError("Lista de participantes nao pode ser vazia")
    if not (1 <= threshold <= len(participant_public_keys)):
        raise ValueError(f"Threshold invalido: M={threshold} fora do intervalo [1, {len(participant_public_keys)}]")
    # ordena as chaves para que o endereco seja independente da ordem de passagem
    sorted_keys = sorted(participant_public_keys)
    script = f"multisig:{threshold}:{':'.join(sorted_keys)}"
    script_bytes = script.encode("utf-8")
    # hash duplo identico ao pipeline P2PKH, substituindo "chave publica" pelo "script"
    hash_bytes = crypto_utils.ripemd160(crypto_utils.sha256(script_bytes))
    versioned = bytes([crypto_utils.ADDRESS_VERSION_BYTE]) + hash_bytes
    checksum = crypto_utils.double_sha256(versioned)[:4]
    import base58
    return base58.b58encode(versioned + checksum).decode("ascii")


# ---------------------------------------------------------------------------
# CRUD de carteiras multisig
# ---------------------------------------------------------------------------

def create_multisig_wallet(participant_public_keys: List[str], threshold: int) -> dict:
    """Cria e persiste uma carteira multisig M-de-N.

    Validacoes:
    - 1 <= M <= N <= MULTISIG_MAX_PARTICIPANTS
    - Cada chave publica deve ser um ponto valido da curva secp256k1
    - Nenhuma chave publica duplicada na lista

    Retorna um dict com: address, threshold, participants (list), created_at.
    Idempotente: se a carteira ja existir no banco, retorna os dados existentes.
    """
    n = len(participant_public_keys)
    if n < 1 or n > MULTISIG_MAX_PARTICIPANTS:
        raise ValueError(
            f"Numero de participantes invalido: {n} (permitido: 1..{MULTISIG_MAX_PARTICIPANTS})"
        )
    if not (1 <= threshold <= n):
        raise ValueError(
            f"Threshold invalido: M={threshold} deve estar em [1, {n}]"
        )
    # valida cada chave publica — chaves invalidas sao rejeitadas antes de qualquer
    # persistencia, evitando carteiras com chaves impossivel de usar para assinar
    seen: set = set()
    for pk in participant_public_keys:
        if pk in seen:
            raise ValueError(f"Chave publica duplicada na lista de participantes: {pk[:16]}...")
        seen.add(pk)
        try:
            crypto_utils.public_key_to_address(pk)
        except ValueError as exc:
            raise ValueError(f"Chave publica invalida: {exc}") from exc

    address = derive_multisig_address(participant_public_keys, threshold)
    sorted_keys = sorted(participant_public_keys)
    pubkeys_json = json.dumps(sorted_keys)

    # verifica se ja existe (idempotente)
    existing = storage.get_multisig_wallet(address)
    if existing:
        return {
            "address": existing["address"],
            "threshold": existing["threshold"],
            "participants": json.loads(existing["participant_pubkeys_json"]),
            "created_at": existing["created_at"],
        }

    storage.persist_multisig_wallet(address, threshold, pubkeys_json)
    return {
        "address": address,
        "threshold": threshold,
        "participants": sorted_keys,
        "created_at": time.time(),
    }


def get_multisig_wallet_info(address: str) -> Optional[dict]:
    """Retorna informacoes de uma carteira multisig pelo endereco.

    Retorna None se o endereco nao corresponder a uma carteira multisig conhecida.
    """
    row = storage.get_multisig_wallet(address)
    if not row:
        return None
    return {
        "address": row["address"],
        "threshold": row["threshold"],
        "participants": json.loads(row["participant_pubkeys_json"]),
        "created_at": row["created_at"],
    }


# ---------------------------------------------------------------------------
# Fluxo de proposta de transacao multisig
# ---------------------------------------------------------------------------

def propose_multisig_transaction(
    multisig_address: str,
    recipient: str,
    amount: float,
    memo: str = "",
    fee: float = 0.0,
    network_id: int = root_rules.NETWORK_ID,
) -> dict:
    """Cria uma proposta de transacao multisig pendente de coleta de assinaturas.

    A proposta captura todos os campos economicos da transacao final
    (remetente, destinatario, valor, taxa, memo) e gera um `tx_id` e
    `timestamp` canonicos que todos os participantes assinarao — garantindo
    que cada assinatura cubra exatamente a mesma transacao (sem ambiguidade).

    O `signing_payload` devolvido e o JSON que cada participante deve assinar
    com `crypto_utils.sign_message(private_key, payload.encode("utf-8"))`.

    Validacoes:
    - `multisig_address` deve ser uma carteira multisig cadastrada
    - `recipient` deve ser um endereco PixCripto valido
    - `amount` e `fee` devem satisfazer as regras de Root Rules
    """
    wallet = storage.get_multisig_wallet(multisig_address)
    if not wallet:
        raise ValueError(f"Carteira multisig nao encontrada: {multisig_address}")
    if not crypto_utils.is_valid_address(recipient):
        raise ValueError(f"Endereco de destinatario invalido: {recipient}")
    amount = float(amount)
    fee = float(fee)
    if amount < root_rules.MIN_TRANSACTION_AMOUNT or amount > root_rules.MAX_TRANSACTION_AMOUNT:
        raise ValueError(f"Valor invalido: {amount}")
    if fee < 0 or fee > root_rules.MAX_TRANSACTION_AMOUNT:
        raise ValueError(f"Taxa invalida: {fee}")

    proposal_id = uuid.uuid4().hex
    tx_id = uuid.uuid4().hex
    timestamp_val = time.time()

    storage.persist_multisig_proposal(
        proposal_id=proposal_id,
        multisig_address=multisig_address,
        recipient=recipient,
        amount=amount,
        fee=fee,
        memo=memo,
        network_id=network_id,
        tx_id=tx_id,
        timestamp_val=timestamp_val,
    )

    # monta o payload de assinatura para que os participantes possam assinar
    # localmente sem precisar do servidor (mesmo formato de signing_payload()
    # da Transaction — garante que qualquer ferramenta de carteira compatible)
    signing_payload = _build_signing_payload(
        tx_id=tx_id,
        sender=multisig_address,
        recipient=recipient,
        amount=amount,
        timestamp=timestamp_val,
        memo=memo,
        tx_type="transfer",
        network_id=network_id,
        fee=fee,
    )

    threshold = wallet["threshold"]
    return {
        "proposal_id": proposal_id,
        "multisig_address": multisig_address,
        "recipient": recipient,
        "amount": amount,
        "fee": fee,
        "memo": memo,
        "network_id": network_id,
        "tx_id": tx_id,
        "timestamp": timestamp_val,
        "status": "pending",
        "threshold": threshold,
        "signatures_collected": 0,
        "signing_payload": signing_payload,
    }


def _build_signing_payload(
    tx_id: str, sender: str, recipient: str, amount: float,
    timestamp: float, memo: str, tx_type: str, network_id: int, fee: float,
) -> str:
    """Reconstroi o JSON canonico que deve ser assinado pelos participantes,
    identico ao produzido por `Transaction.signing_payload()` — garantia de
    compatibilidade: qualquer carteira que implemente o protocolo PixCripto
    consegue assinar propostas multisig sem codigo especial."""
    payload = {
        "tx_id": tx_id,
        "sender": sender,
        "recipient": recipient,
        "amount": amount,
        "timestamp": timestamp,
        "memo": memo,
        "tx_type": tx_type,
        "network_id": network_id,
        "fee": fee,
        "data": "",
    }
    return json.dumps(payload, sort_keys=True)


def sign_multisig_proposal(
    proposal_id: str,
    public_key: str,
    signature: str,
) -> dict:
    """Adiciona uma assinatura valida de um participante a proposta.

    Rejeita (ValueError) se:
    - A proposta nao existir ou nao estiver em estado "pending"
    - A chave publica nao pertencer aos participantes da carteira
    - A assinatura for invalida (ECDSA real sobre o payload correto)
    - A chave publica ja tiver assinado esta proposta (assinatura duplicada)

    Retorna o estado atualizado da proposta (incluindo contador de assinaturas).
    """
    proposal = storage.get_multisig_proposal(proposal_id)
    if not proposal:
        raise ValueError(f"Proposta nao encontrada: {proposal_id}")
    if proposal["status"] != "pending":
        raise ValueError(f"Proposta nao esta pendente (status atual: {proposal['status']})")

    wallet = storage.get_multisig_wallet(proposal["multisig_address"])
    if not wallet:
        raise ValueError("Carteira multisig associada a proposta nao encontrada")

    participants: List[str] = json.loads(wallet["participant_pubkeys_json"])

    # verifica que a chave pertence aos participantes declarados da carteira
    if public_key not in participants:
        raise ValueError("Chave publica nao pertence aos participantes desta carteira multisig")

    # verifica assinaturas ja coletadas (duplicata + validade)
    current_sigs: List[dict] = json.loads(proposal["signatures_json"])
    for entry in current_sigs:
        if entry["public_key"] == public_key:
            raise ValueError("Esta chave publica ja assinou esta proposta (assinatura duplicada)")

    # verifica a assinatura ECDSA real sobre o payload canonico da tx
    signing_payload_str = _build_signing_payload(
        tx_id=proposal["tx_id"],
        sender=proposal["multisig_address"],
        recipient=proposal["recipient"],
        amount=proposal["amount"],
        timestamp=proposal["timestamp_val"],
        memo=proposal["memo"],
        tx_type="transfer",
        network_id=proposal["network_id"],
        fee=proposal["fee"],
    )
    payload_bytes = signing_payload_str.encode("utf-8")
    if not crypto_utils.verify_signature(public_key, payload_bytes, signature):
        raise ValueError("Assinatura ECDSA invalida para este payload de transacao")

    # adiciona a nova assinatura valida e persiste
    current_sigs.append({"public_key": public_key, "signature": signature})
    storage.update_multisig_proposal_signatures(proposal_id, json.dumps(current_sigs))

    threshold = wallet["threshold"]
    return {
        "proposal_id": proposal_id,
        "status": "pending",
        "signatures_collected": len(current_sigs),
        "threshold": threshold,
        "ready_to_finalize": len(current_sigs) >= threshold,
    }


def get_proposal_info(proposal_id: str) -> Optional[dict]:
    """Retorna o estado atual de uma proposta, incluindo quantas assinaturas
    foram coletadas e se ja atingiu o threshold para finalizacao."""
    proposal = storage.get_multisig_proposal(proposal_id)
    if not proposal:
        return None
    wallet = storage.get_multisig_wallet(proposal["multisig_address"])
    threshold = wallet["threshold"] if wallet else None
    sigs = json.loads(proposal["signatures_json"])
    signing_payload_str = _build_signing_payload(
        tx_id=proposal["tx_id"],
        sender=proposal["multisig_address"],
        recipient=proposal["recipient"],
        amount=proposal["amount"],
        timestamp=proposal["timestamp_val"],
        memo=proposal["memo"],
        tx_type="transfer",
        network_id=proposal["network_id"],
        fee=proposal["fee"],
    )
    return {
        "proposal_id": proposal["proposal_id"],
        "multisig_address": proposal["multisig_address"],
        "recipient": proposal["recipient"],
        "amount": proposal["amount"],
        "fee": proposal["fee"],
        "memo": proposal["memo"],
        "network_id": proposal["network_id"],
        "tx_id": proposal["tx_id"],
        "timestamp": proposal["timestamp_val"],
        "status": proposal["status"],
        "threshold": threshold,
        "signatures_collected": len(sigs),
        "signers": [s["public_key"] for s in sigs],
        "ready_to_finalize": (threshold is not None and len(sigs) >= threshold),
        "signing_payload": signing_payload_str,
        "created_at": proposal["created_at"],
    }


def finalize_and_submit_multisig_proposal(
    proposal_id: str,
    blockchain,  # Blockchain — tipagem em string para evitar import circular
) -> Transaction:
    """Finaliza uma proposta multisig: monta a Transaction com todos os campos
    multisig preenchidos e a submete ao fluxo normal da blockchain.

    Exige que a proposta esteja em estado "pending" e que o numero de
    assinaturas coletadas seja >= threshold da carteira.

    Lanca ValueError se:
    - Proposta nao existir, ja estiver finalizada ou com assinaturas insuficientes
    - A transacao for rejeitada pela blockchain (saldo insuficiente, etc.)

    Em caso de sucesso, marca a proposta como "finalized" e retorna a Transaction.
    """
    proposal = storage.get_multisig_proposal(proposal_id)
    if not proposal:
        raise ValueError(f"Proposta nao encontrada: {proposal_id}")
    if proposal["status"] != "pending":
        raise ValueError(f"Proposta nao esta pendente (status atual: {proposal['status']})")

    wallet = storage.get_multisig_wallet(proposal["multisig_address"])
    if not wallet:
        raise ValueError("Carteira multisig associada a proposta nao encontrada")

    participants: List[str] = json.loads(wallet["participant_pubkeys_json"])
    threshold = wallet["threshold"]
    sigs: List[dict] = json.loads(proposal["signatures_json"])

    if len(sigs) < threshold:
        raise ValueError(
            f"Assinaturas insuficientes: {len(sigs)} coletadas, {threshold} necessarias"
        )

    # monta a Transaction completa com campos multisig para ser auto-validavel
    # pelo consenso sem consultar o banco (ver Transaction._is_valid_multisig())
    tx = Transaction(
        sender=proposal["multisig_address"],
        recipient=proposal["recipient"],
        amount=proposal["amount"],
        tx_id=proposal["tx_id"],
        timestamp=proposal["timestamp_val"],
        memo=proposal["memo"],
        tx_type="transfer",
        network_id=proposal["network_id"],
        fee=proposal["fee"],
        # campos multisig: tornam a tx auto-validavel sem consulta ao banco
        multisig_participants=json.dumps(participants),
        multisig_threshold=threshold,
        multisig_signatures=json.dumps(sigs),
    )

    # submete ao fluxo padrao da blockchain (validacao + mempool)
    if not blockchain.add_transaction(tx):
        raise ValueError(
            "Transacao multisig rejeitada pela blockchain "
            "(saldo insuficiente, replay, assinatura invalida ou dados incorretos)"
        )

    # marca a proposta como finalizada (idempotente: novas tentativas de
    # finalizacao serao rejeitadas pela checagem de status acima)
    storage.set_multisig_proposal_status(proposal_id, "finalized")
    return tx
