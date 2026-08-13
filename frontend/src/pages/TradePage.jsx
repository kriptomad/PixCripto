import { useEffect, useState } from 'react';
import api from '../api/client.js';
import { useWallet } from '../context/WalletContext.jsx';

/**
 * Painel de negociacao real: compra (on-ramp com taxa de 7,38%), venda,
 * liquidacao (parcial ou total) e troca P2P (swap com escrow), alem do
 * status de controle de dump/auto-regulacao da rede.
 *
 * A compra segue o fluxo real de 3 passos exposto pelo backend
 * (`/purchase/quote-locked` -> pagamento no gateway -> `/purchase/confirm`
 * com a assinatura do gateway). Como este projeto ainda nao tem um gateway
 * de pagamento (PIX/cartao) real integrado, o passo intermediario usa o
 * endpoint de simulacao do proprio backend (`/purchase/webhook/simulate-payment-gateway`,
 * marcado explicitamente como "somente para demonstracao" no backend) -
 * quando um gateway real for integrado, basta trocar esta chamada pelo
 * webhook do provedor, sem mudar o restante do fluxo.
 */
export default function TradePage() {
  const { activeWallet } = useWallet();
  const [tab, setTab] = useState('buy');

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Negociar PXC</h1>
        <p className="text-gray-500 text-sm mt-1">
          Compra, venda, liquidacao e troca P2P (swap) com cotacao ancorada em ouro e controle
          automatico de dump (auto-regulacao da rede).
        </p>
      </div>

      <DumpStatusBanner />

      <div className="flex gap-2 border-b border-[var(--color-border)]">
        {[
          ['buy', 'Comprar'],
          ['sell', 'Vender'],
          ['liquidate', 'Liquidar posicao'],
          ['swap', 'Troca P2P (swap)'],
        ].map(([key, label]) => (
          <button
            key={key}
            type="button"
            onClick={() => setTab(key)}
            className={`px-3 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === key ? 'border-[var(--color-accent)] text-[var(--color-accent)]' : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === 'buy' && <BuyPanel activeWallet={activeWallet} />}
      {tab === 'sell' && <SellPanel activeWallet={activeWallet} />}
      {tab === 'liquidate' && <LiquidatePanel activeWallet={activeWallet} />}
      {tab === 'swap' && <SwapPanel activeWallet={activeWallet} />}
    </div>
  );
}

function DumpStatusBanner() {
  const [status, setStatus] = useState(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const { data } = await api.get('/market/dump-status');
        if (!cancelled) setStatus(data);
      } catch {
        /* silencioso - banner e informativo, nao critico */
      }
    }
    load();
    const id = setInterval(load, 15_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  if (!status) return null;

  const pct = (status.dump_ratio * 100).toFixed(2);
  const limitPct = (status.limit_ratio * 100).toFixed(2);

  return (
    <div className={`card p-4 flex items-center justify-between ${status.trading_halted ? 'border-[var(--color-down)]' : ''}`}>
      <div>
        <p className="label !mb-1">Controle de dump (auto-regulacao)</p>
        <p className="text-sm text-gray-400">
          Vendido na janela de {Math.round(status.window_seconds / 60)}min: <span className="text-white font-medium">{pct}%</span> do
          limite de {limitPct}% (concentracao de carteiras HHI: {status.wallet_concentration_hhi.toFixed(3)})
        </p>
      </div>
      {status.trading_halted && (
        <span className="text-xs font-semibold text-[var(--color-down)] bg-[var(--color-down)]/10 px-3 py-1.5 rounded-md">
          Negociacao suspensa temporariamente
        </span>
      )}
    </div>
  );
}

function BuyPanel({ activeWallet }) {
  const [amountBrl, setAmountBrl] = useState('100');
  const [quote, setQuote] = useState(null);
  const [lockedQuote, setLockedQuote] = useState(null);
  const [step, setStep] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  async function getPreview(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const { data } = await api.post('/purchase/quote', { amount_brl: Number(amountBrl) });
      setQuote(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function lockAndPay() {
    if (!activeWallet) {
      setError('Selecione ou crie uma carteira para receber os PXC comprados.');
      return;
    }
    setError('');
    setLoading(true);
    try {
      const { data: locked } = await api.post('/purchase/quote-locked', {
        amount_brl: Number(amountBrl),
        recipient_address: activeWallet.address,
      });
      setLockedQuote(locked);

      // Simulacao do gateway de pagamento real (PIX/cartao) - ver nota no topo do arquivo.
      const paymentReference = `sim-${locked.quote_id}`;
      const { data: gw } = await api.post('/purchase/webhook/simulate-payment-gateway', {
        quote_id: locked.quote_id,
        payment_reference: paymentReference,
      });

      const { data: confirmed } = await api.post('/purchase/confirm', {
        quote_id: locked.quote_id,
        payment_reference: paymentReference,
        gateway_signature: gw.gateway_signature,
      });
      setResult(confirmed);
      setStep(1);
      setLockedQuote(null);
      setQuote(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="card p-6 space-y-4">
      <p className="text-sm text-gray-400">
        Taxa de compra: <span className="text-white font-medium">7,38%</span> sobre o valor, cotacao ancorada em ouro no
        momento da confirmacao.
      </p>
      <form onSubmit={getPreview} className="flex gap-3 items-end">
        <div className="flex-1">
          <label className="label">Valor a investir (BRL)</label>
          <input
            type="number"
            min="1"
            step="any"
            className="input"
            value={amountBrl}
            onChange={(e) => setAmountBrl(e.target.value)}
          />
        </div>
        <button type="submit" className="btn btn-secondary" disabled={loading}>
          Ver cotacao
        </button>
      </form>

      {quote && (
        <div className="bg-[var(--color-panel-alt)] p-4 rounded-md text-sm space-y-1">
          <p>Valor: R$ {quote.amount_brl.toFixed(2)}</p>
          <p>Taxa (7,38%): R$ {quote.fee_brl.toFixed(2)}</p>
          <p className="font-semibold">Total cobrado: R$ {quote.total_charged_brl.toFixed(2)}</p>
          <p>
            Voce recebe: <span className="text-[var(--color-up)] font-semibold">{quote.coins_credited.toFixed(8)} PXC</span> (cotacao
            R$ {quote.pxc_brl_rate.toFixed(4)}/PXC)
          </p>
          <button type="button" className="btn btn-primary w-full mt-2" disabled={loading || !activeWallet} onClick={lockAndPay}>
            {loading ? 'Processando pagamento...' : 'Comprar agora'}
          </button>
          {!activeWallet && <p className="text-xs text-[var(--color-down)]">Crie ou selecione uma carteira primeiro.</p>}
        </div>
      )}

      {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
      {result && (
        <div className="text-sm text-[var(--color-up)] bg-black/20 p-3 rounded-md">
          Compra confirmada: {result.coins_credited.toFixed(8)} PXC creditados (tx {result.tx_id}) — aguardando mineracao do
          proximo bloco.
        </div>
      )}
    </div>
  );
}

function SellPanel({ activeWallet }) {
  const [amount, setAmount] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  async function submit(e) {
    e.preventDefault();
    if (!activeWallet?.private_key) {
      setError('Carteira ativa sem chave privada disponivel neste navegador. Importe a chave privada para vender.');
      return;
    }
    setError('');
    setLoading(true);
    try {
      const { data } = await api.post('/market/sell', {
        sender_private_key: activeWallet.private_key,
        sender_public_key: activeWallet.public_key,
        amount: Number(amount),
      });
      setResult(data);
      setAmount('');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  if (!activeWallet) return <p className="text-gray-400">Selecione ou crie uma carteira primeiro.</p>;

  return (
    <form onSubmit={submit} className="card p-6 space-y-4 max-w-md">
      <p className="text-sm text-gray-400">Venda PXC de volta ao protocolo (queima) pela cotacao ancorada em ouro.</p>
      <div>
        <label className="label">Quantidade (PXC)</label>
        <input type="number" step="any" min="0" className="input" required value={amount} onChange={(e) => setAmount(e.target.value)} />
      </div>
      <button type="submit" className="btn btn-primary w-full" disabled={loading}>
        {loading ? 'Enviando...' : 'Vender'}
      </button>
      {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
      {result && (
        <div className="text-sm text-[var(--color-up)] bg-black/20 p-3 rounded-md">
          Venda aceita: payout R$ {result.payout_brl.toFixed(2)} (tx {result.tx_id})
        </div>
      )}
    </form>
  );
}

function LiquidatePanel({ activeWallet }) {
  const [amount, setAmount] = useState('');
  const [full, setFull] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  async function submit(e) {
    e.preventDefault();
    if (!activeWallet?.private_key) {
      setError('Carteira ativa sem chave privada disponivel neste navegador. Importe a chave privada para liquidar.');
      return;
    }
    setError('');
    setLoading(true);
    try {
      const { data } = await api.post('/market/liquidate', {
        sender_private_key: activeWallet.private_key,
        sender_public_key: activeWallet.public_key,
        amount: full ? null : Number(amount),
      });
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  if (!activeWallet) return <p className="text-gray-400">Selecione ou crie uma carteira primeiro.</p>;

  return (
    <form onSubmit={submit} className="card p-6 space-y-4 max-w-md">
      <p className="text-sm text-gray-400">
        Liquidacao total ou parcial da posicao — sujeita ao mesmo controle de dump que a venda comum.
      </p>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={full} onChange={(e) => setFull(e.target.checked)} />
        Liquidar 100% do saldo disponivel
      </label>
      {!full && (
        <div>
          <label className="label">Quantidade (PXC)</label>
          <input type="number" step="any" min="0" className="input" value={amount} onChange={(e) => setAmount(e.target.value)} />
        </div>
      )}
      <button type="submit" className="btn btn-primary w-full" disabled={loading}>
        {loading ? 'Processando...' : 'Liquidar posicao'}
      </button>
      {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
      {result && (
        <div className="text-sm text-[var(--color-up)] bg-black/20 p-3 rounded-md">
          Liquidacao aceita: payout R$ {result.payout_brl.toFixed(2)} (tx {result.tx_id})
        </div>
      )}
    </form>
  );
}

function SwapPanel({ activeWallet }) {
  const [amount, setAmount] = useState('');
  const [price, setPrice] = useState('');
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  async function loadOrders() {
    try {
      const { data } = await api.get('/market/swap/orders', { params: { status: 'open' } });
      setOrders(data.orders || []);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    loadOrders();
    const id = setInterval(loadOrders, 10_000);
    return () => clearInterval(id);
  }, []);

  async function createOrder(e) {
    e.preventDefault();
    if (!activeWallet?.private_key) {
      setError('Carteira ativa sem chave privada disponivel neste navegador. Importe a chave privada para criar uma ordem.');
      return;
    }
    setError('');
    setMessage('');
    setLoading(true);
    try {
      await api.post('/market/swap/create-order', {
        sender_private_key: activeWallet.private_key,
        sender_public_key: activeWallet.public_key,
        amount: Number(amount),
        price_brl_per_pxc: Number(price),
      });
      setMessage('Ordem criada e fundos custodiados (escrow) com sucesso.');
      setAmount('');
      setPrice('');
      loadOrders();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function cancelOwnOrder(order) {
    if (!activeWallet?.private_key) {
      setError('Chave privada nao disponivel para assinar o cancelamento.');
      return;
    }
    setError('');
    try {
      const { data: signed } = await api.post('/market/swap/sign-release', {
        maker_private_key: activeWallet.private_key,
        action: 'cancel',
        order_id: order.order_id,
        counterparty_address: order.maker_address,
      });
      await api.post('/market/swap/cancel-order', {
        order_id: order.order_id,
        requester_address: order.maker_address,
        maker_signature: signed.signature,
      });
      setMessage('Ordem cancelada e fundos estornados.');
      loadOrders();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="space-y-6">
      <form onSubmit={createOrder} className="card p-6 space-y-4 max-w-md">
        <p className="text-sm text-gray-400">
          Cria uma ordem de troca P2P: seu PXC fica custodiado (escrow) ate outro usuario preencher a ordem ou voce
          cancelar.
        </p>
        {!activeWallet && <p className="text-xs text-[var(--color-down)]">Selecione ou crie uma carteira primeiro.</p>}
        <div>
          <label className="label">Quantidade (PXC)</label>
          <input type="number" step="any" min="0" className="input" required value={amount} onChange={(e) => setAmount(e.target.value)} />
        </div>
        <div>
          <label className="label">Preco por PXC (BRL)</label>
          <input type="number" step="any" min="0" className="input" required value={price} onChange={(e) => setPrice(e.target.value)} />
        </div>
        <button type="submit" className="btn btn-primary w-full" disabled={loading || !activeWallet}>
          {loading ? 'Criando...' : 'Criar ordem de troca'}
        </button>
        {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
        {message && <p className="text-sm text-[var(--color-up)]">{message}</p>}
      </form>

      <div className="card p-5">
        <p className="label">Ordens abertas</p>
        {orders.length === 0 ? (
          <p className="text-gray-500 text-sm mt-2">Nenhuma ordem de troca aberta no momento.</p>
        ) : (
          <table className="w-full text-sm mt-2">
            <thead>
              <tr className="text-left text-xs text-gray-500 uppercase">
                <th className="py-1.5 font-medium">Maker</th>
                <th className="py-1.5 font-medium">Quantidade</th>
                <th className="py-1.5 font-medium">Preco (BRL)</th>
                <th className="py-1.5 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {orders.map((o) => (
                <tr key={o.order_id} className="border-t border-[var(--color-border)]">
                  <td className="py-1.5 mono text-xs">{o.maker_address.slice(0, 10)}...</td>
                  <td className="py-1.5">{Number(o.amount).toFixed(4)}</td>
                  <td className="py-1.5">{Number(o.price_brl_per_pxc).toFixed(4)}</td>
                  <td className="py-1.5 text-right">
                    {activeWallet && o.maker_address === activeWallet.address && (
                      <button type="button" className="text-xs text-[var(--color-down)] hover:underline" onClick={() => cancelOwnOrder(o)}>
                        cancelar
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
