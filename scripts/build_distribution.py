"""
Build de distribuição ofuscada (bytecode-only) do PixCripto.

Motivação: o usuário pediu para "criptografar os códigos" e "utilizar métodos
de embaralhamento de código". A ferramenta ideal para isso (`pyarmor`) está
instalada no projeto, mas sua licença trial não permite ofuscar um projeto
deste tamanho (`pyarmor gen` retorna `ERROR: out of license` ao processar
`app/`). Como alternativa funcional e sem custo, este script gera uma
distribuição somente-bytecode (.pyc) do pacote `app/`, removendo o código-fonte
Python legível: qualquer pessoa com acesso ao diretório `dist/` só encontra
bytecode compilado (que ainda pode ser desmontado por uma ferramenta dedicada,
mas já não é texto plano legível a olho nu, e não expõe comentários/nomes de
variáveis originais tão diretamente).

Para uma ofuscação de nível produção, recomenda-se:
  1. Uma licença paga do PyArmor (`pyarmor gen --obf-mod 2 --obf-code 2 -r app`)
     - criptografa cada função e a decifra em runtime, MUITO mais forte que
       bytecode puro.
  2. Compilar os módulos mais sensíveis (crypto_utils.py, models.py, root_rules.py)
     com Cython/Nuitka para binário nativo.

Uso:
    python scripts/build_distribution.py
Gera `dist/app/` contendo apenas os `.pyc` (sem os `.py` originais) prontos
para rodar com `python -m dist.app` (mantendo o pacote executável), e
`dist/frontend/dist/` com o build de producao (`npm run build`) da UI React,
no mesmo caminho relativo que `app/api.py` procura em runtime
(`Path(__file__).resolve().parent.parent / "frontend" / "dist"`), para que a
UI continue sendo servida em `/app/*` sem nenhuma mudanca de codigo entre o
ambiente de desenvolvimento e a distribuicao final.

⚠️ **O que NUNCA é incluído nesta distribuição** (verificado explicitamente
abaixo, além do fato de já estarem fora de `app/`):
  - `admin_panel/` (Painel de Administração - ferramenta de OPERADOR, nunca
    deve ir para a rede/usuários finais - ver `admin_panel/main.py`);
  - `.env` (configuração local, pode conter segredos como `PIXCRIPTO_GATEWAY_SECRET`);
  - `seeds.json` (lista curada de peers - dado operacional, não de produto);
  - `data/*.db` (bancos SQLite locais: blockchain, compliance - dados, não código);
  - `frontend/node_modules/` e `frontend/src/` (dependências e código-fonte do
    frontend não são necessários em produção - apenas `frontend/dist/`, o
    build ja compilado/minificado, é copiado).
"""
from __future__ import annotations

import pathlib
import py_compile
import shutil

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "app"
DIST = ROOT / "dist" / "app"
FRONTEND_SRC_DIST = ROOT / "frontend" / "dist"
FRONTEND_TARGET_DIST = ROOT / "dist" / "frontend" / "dist"

# Nomes de arquivo que, por engano, jamais devem ser copiados para a
# distribuição mesmo que apareçam dentro de `app/` no futuro (defesa em
# profundidade - hoje nenhum deles vive de fato ali).
_EXCLUDED_FILENAMES = {".env", "seeds.json"}
_EXCLUDED_SUFFIXES = {".db", ".db-wal", ".db-shm"}


def _is_excluded(path: pathlib.Path) -> bool:
    if "__pycache__" in path.parts:
        return True
    return path.name in _EXCLUDED_FILENAMES or path.suffix in _EXCLUDED_SUFFIXES


def build() -> None:
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True)

    for py_file in SRC.rglob("*.py"):
        if _is_excluded(py_file):
            continue
        rel = py_file.relative_to(SRC)
        target_pyc = (DIST / rel).with_suffix(".pyc")
        target_pyc.parent.mkdir(parents=True, exist_ok=True)
        py_compile.compile(str(py_file), cfile=str(target_pyc), doraise=True)

    # copia arquivos nao-Python necessarios (templates HTML, CSS, JS da UI de
    # carteira, wordlist BIP39 etc.) sem alteracao - exceto os explicitamente
    # excluidos acima (defesa em profundidade).
    for other in SRC.rglob("*"):
        if other.is_file() and other.suffix != ".py" and not _is_excluded(other):
            rel = other.relative_to(SRC)
            target = DIST / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(other, target)

    print(f"Distribuicao bytecode-only gerada em: {DIST}")
    print("Codigo-fonte .py NAO incluido nesta pasta - apenas .pyc compilado.")
    print("admin_panel/, .env e seeds.json NAO fazem parte desta distribuicao (uso interno apenas).")

    _copy_frontend_build()


def _copy_frontend_build() -> None:
    """Copia o build de producao da UI React (`frontend/dist/`) para
    `dist/frontend/dist/`, preservando o mesmo caminho relativo que
    `app/api.py` usa para localizar os arquivos em runtime. Se o build ainda
    nao existir, avisa o operador em vez de falhar silenciosamente (a UI
    simplesmente nao sera servida em `/app/*` ate `npm run build` ser rodado)."""
    if not (FRONTEND_SRC_DIST / "index.html").exists():
        print(
            "AVISO: frontend/dist/ nao encontrado - rode 'npm run build' em "
            "frontend/ antes de distribuir para incluir a UI web. A distribuicao "
            "continuara funcional via API/rotas HTML legadas, mas sem a UI React em /app/."
        )
        return

    if FRONTEND_TARGET_DIST.exists():
        shutil.rmtree(FRONTEND_TARGET_DIST)
    shutil.copytree(FRONTEND_SRC_DIST, FRONTEND_TARGET_DIST)
    print(f"Build de producao do frontend copiado para: {FRONTEND_TARGET_DIST}")


if __name__ == "__main__":
    build()
