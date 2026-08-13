"""
Testes do dispatcher JSON-RPC 2.0 - cobre chamada unica, batch, notificacoes
(sem resposta) e os codigos de erro padrao da especificacao. Testa o
dispatcher diretamente (sem TestClient/httpx) para nao adicionar uma nova
dependencia de teste so para isto; os metodos sao os MESMOS registrados por
`api.py` em `POST /rpc` (import de `app.api` e o que dispara os
`@dispatcher.method(...)` na importacao do modulo)."""
import app.api  # noqa: F401 - garante que os metodos RPC sejam registrados
from app.rpc import dispatcher


def test_single_request_returns_result():
    body = dispatcher.handle({"jsonrpc": "2.0", "method": "net_chainId", "id": 1})
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 1
    assert "network_id" in body["result"]


def test_chain_getlength_reflects_local_chain():
    body = dispatcher.handle({"jsonrpc": "2.0", "method": "chain_getLength", "id": 1})
    assert body["result"]["length"] >= 1


def test_unknown_method_returns_method_not_found_error():
    body = dispatcher.handle({"jsonrpc": "2.0", "method": "does_not_exist", "id": 5})
    assert body["error"]["code"] == -32601
    assert body["id"] == 5


def test_missing_jsonrpc_field_returns_invalid_request():
    body = dispatcher.handle({"method": "net_chainId", "id": 1})
    assert body["error"]["code"] == -32600


def test_notification_without_id_returns_none():
    body = dispatcher.handle({"jsonrpc": "2.0", "method": "net_chainId"})
    assert body is None


def test_batch_request_returns_matching_responses_in_order():
    payload = [
        {"jsonrpc": "2.0", "method": "chain_getLength", "id": 1},
        {"jsonrpc": "2.0", "method": "mining_getDifficulty", "id": 2},
        {"jsonrpc": "2.0", "method": "unknown_thing", "id": 3},
    ]
    body = dispatcher.handle(payload)
    assert len(body) == 3
    assert body[0]["id"] == 1 and "result" in body[0]
    assert body[1]["id"] == 2 and "result" in body[1]
    assert body[2]["id"] == 3 and body[2]["error"]["code"] == -32601


def test_account_getbalance_returns_zero_for_unknown_address():
    body = dispatcher.handle({
        "jsonrpc": "2.0", "method": "account_getBalance",
        "params": {"address": "PdoesNotExistAtAll"}, "id": 1,
    })
    assert body["result"]["balance"] == 0.0


def test_tx_send_rejects_malformed_transaction():
    body = dispatcher.handle({
        "jsonrpc": "2.0", "method": "tx_send",
        "params": {"tx": {"not": "a valid tx"}}, "id": 1,
    })
    assert body["error"]["code"] == -32602


def test_chain_getblockbyindex_out_of_range_is_invalid_params():
    body = dispatcher.handle({
        "jsonrpc": "2.0", "method": "chain_getBlockByIndex",
        "params": {"index": 999999}, "id": 1,
    })
    assert body["error"]["code"] == -32602


def test_batch_of_only_notifications_returns_none():
    payload = [
        {"jsonrpc": "2.0", "method": "net_chainId"},
        {"jsonrpc": "2.0", "method": "chain_getLength"},
    ]
    assert dispatcher.handle(payload) is None


def test_empty_batch_is_invalid_request():
    body = dispatcher.handle([])
    assert body["error"]["code"] == -32600
