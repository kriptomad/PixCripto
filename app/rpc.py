"""
Dispatcher JSON-RPC 2.0 (spec: https://www.jsonrpc.org/specification) - secao
7.4 do guia "blockchain-do-zero.md". Permite que qualquer cliente (carteira,
explorer, outro no, script) chame metodos do protocolo por um UNICO endpoint
HTTP (`POST /rpc`), no mesmo padrao usado por Bitcoin Core / clientes Ethereum
(`eth_getBalance`, `eth_sendRawTransaction`, etc.), em vez de precisar
conhecer as rotas REST especificas do PixCripto.

Suporta:
- Chamada unica: {"jsonrpc":"2.0","method":"...","params":{...},"id":1}
- Batch (varias chamadas num unico POST): lista de objetos acima
- Notificacoes (sem campo "id"): executadas mas NUNCA gera resposta
- Codigos de erro padrao da especificacao (-32700..-32603)
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Union

JSONRPC_VERSION = "2.0"

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class RPCError(Exception):
    """Erro de aplicacao a ser retornado ao cliente JSON-RPC (nao um bug interno -
    ex: bloco inexistente, transacao invalida, endereco malformado)."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class RPCDispatcher:
    def __init__(self):
        self._methods: Dict[str, Callable[..., Any]] = {}

    def method(self, name: str):
        """Decorator: registra uma funcao Python como metodo JSON-RPC `name`."""
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            self._methods[name] = fn
            return fn
        return decorator

    @staticmethod
    def _error_response(req_id: Any, code: int, message: str, data: Any = None) -> dict:
        error: Dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": JSONRPC_VERSION, "error": error, "id": req_id}

    def _call_single(self, req: Any) -> Optional[dict]:
        if not isinstance(req, dict):
            return self._error_response(None, INVALID_REQUEST, "Invalid Request")
        req_id = req.get("id")
        is_notification = "id" not in req
        if req.get("jsonrpc") != JSONRPC_VERSION or "method" not in req or not isinstance(req.get("method"), str):
            return None if is_notification else self._error_response(req_id, INVALID_REQUEST, "Invalid Request")

        method_name = req["method"]
        params = req.get("params", {})
        fn = self._methods.get(method_name)
        if fn is None:
            return None if is_notification else self._error_response(
                req_id, METHOD_NOT_FOUND, f"Metodo desconhecido: {method_name}")

        try:
            if isinstance(params, dict):
                result = fn(**params)
            elif isinstance(params, list):
                result = fn(*params)
            elif params is None:
                result = fn()
            else:
                raise RPCError(INVALID_PARAMS, "'params' deve ser um objeto, uma lista ou omitido")
        except RPCError as exc:
            return None if is_notification else self._error_response(req_id, exc.code, exc.message, exc.data)
        except TypeError as exc:
            return None if is_notification else self._error_response(
                req_id, INVALID_PARAMS, f"Parametros invalidos para '{method_name}': {exc}")
        except Exception as exc:  # nunca vaza stack trace/detalhes internos ao cliente
            return None if is_notification else self._error_response(
                req_id, INTERNAL_ERROR, "Erro interno ao processar o metodo")

        if is_notification:
            return None
        return {"jsonrpc": JSONRPC_VERSION, "result": result, "id": req_id}

    def handle(self, payload: Union[dict, list]) -> Optional[Union[dict, list]]:
        """Processa uma requisicao (unica ou batch) e retorna a(s) resposta(s).
        Retorna None quando NENHUMA resposta deve ser enviada (ex: uma unica
        notificacao, ou um batch composto so de notificacoes) - o chamador
        HTTP deve entao responder 204 No Content, como manda a especificacao."""
        if isinstance(payload, list):
            if not payload:
                return self._error_response(None, INVALID_REQUEST, "Invalid Request")
            responses = [r for r in (self._call_single(item) for item in payload) if r is not None]
            return responses if responses else None
        return self._call_single(payload)


dispatcher = RPCDispatcher()
