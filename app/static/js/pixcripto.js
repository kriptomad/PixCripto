// PixCripto Wallet UI - funcoes utilitarias compartilhadas por todas as paginas.
//
// Modelo de confianca: esta UI e servida PELO PROPRIO NO que voce controla
// (mesma logica do GUI oficial do Bitcoin Core: voce roda seu proprio node E
// sua propria interface, conversando via localhost/rede privada). Por isso,
// para simplificar a assinatura de transacoes sem depender de uma biblioteca
// de ECDSA secp256k1 em JavaScript, esta UI usa o endpoint de conveniencia
// `/transaction/send` (chave privada enviada ao SEU PROPRIO servidor, nunca a
// terceiros). Para producao publica multi-usuario (varios usuarios
// desconhecidos compartilhando o mesmo servidor), prefira assinar no cliente
// com uma extensao/carteira dedicada e usar `/transaction/submit-signed`.
//
// As chaves ficam em `localStorage` do navegador (nunca enviadas a nenhum
// lugar alem do proprio node ao assinar).

const PXC_STORAGE_KEY = "pixcripto_wallet_v1";

function pxcSaveWallet(wallet) {
    localStorage.setItem(PXC_STORAGE_KEY, JSON.stringify(wallet));
}

function pxcLoadWallet() {
    const raw = localStorage.getItem(PXC_STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
}

function pxcClearWallet() {
    localStorage.removeItem(PXC_STORAGE_KEY);
}

async function pxcApi(path, options = {}) {
    const resp = await fetch(path, {
        method: options.method || "GET",
        headers: { "Content-Type": "application/json", ...(options.headers || {}) },
        body: options.body ? JSON.stringify(options.body) : undefined,
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
        throw new Error(data.detail || `Erro HTTP ${resp.status}`);
    }
    return data;
}

function pxcFormatAmount(value) {
    return Number(value).toLocaleString("pt-BR", { minimumFractionDigits: 2, maximumFractionDigits: 8 });
}

function pxcShowAlert(containerId, message, type = "error") {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = `<div class="alert alert-${type}">${message}</div>`;
}

function pxcRequireWalletOrRedirect() {
    const wallet = pxcLoadWallet();
    if (!wallet) {
        window.location.href = "/wallet";
        return null;
    }
    return wallet;
}
