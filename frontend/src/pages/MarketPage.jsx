import { useEffect, useState } from 'react';
import api from '../api/client.js';
import PriceTicker from '../components/PriceTicker.jsx';
import CandlestickChart from '../components/CandlestickChart.jsx';

const INTERVALS = ['1m', '5m', '15m', '1h', '4h', '1d'];

function fmtTime(ms) {
  return new Date(ms).toLocaleTimeString('pt-BR');
}

export default function MarketPage() {
  const [interval, setInterval_] = useState('1h');
  const [candles, setCandles] = useState([]);
  const [depth, setDepth] = useState(null);
  const [trades, setTrades] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    async function loadCandles() {
      try {
        const { data } = await api.get('/api/v1/klines', { params: { interval, limit: 150 } });
        if (!cancelled) setCandles(data);
      } catch (err) {
        if (!cancelled) setError(err.message);
      }
    }
    loadCandles();
    const id = setInterval(loadCandles, 20_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [interval]);

  useEffect(() => {
    let cancelled = false;
    async function loadBookAndTrades() {
      try {
        const [depthRes, tradesRes] = await Promise.all([
          api.get('/api/v1/depth', { params: { limit: 20 } }),
          api.get('/api/v1/trades', { params: { limit: 30 } }),
        ]);
        if (!cancelled) {
          setDepth(depthRes.data);
          setTrades(tradesRes.data);
        }
      } catch (err) {
        if (!cancelled) setError(err.message);
      }
    }
    loadBookAndTrades();
    const id = setInterval(loadBookAndTrades, 10_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  return (
    <div className="space-y-6">
      <PriceTicker />

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="card p-4 lg:col-span-3">
          <div className="flex items-center justify-between mb-3">
            <p className="label !mb-0">PXC/BRL</p>
            <div className="flex gap-1">
              {INTERVALS.map((i) => (
                <button
                  key={i}
                  type="button"
                  onClick={() => setInterval_(i)}
                  className={`px-2.5 py-1 text-xs rounded-md font-medium ${
                    interval === i ? 'bg-[var(--color-accent)] text-[#14161d]' : 'text-gray-400 hover:bg-white/5'
                  }`}
                >
                  {i}
                </button>
              ))}
            </div>
          </div>
          <CandlestickChart candles={candles} />
        </div>

        <div className="card p-4">
          <p className="label">Livro de ofertas (swap DEX)</p>
          {depth ? (
            <div className="mt-2 space-y-1 max-h-[380px] overflow-y-auto">
              <div className="grid grid-cols-2 text-xs text-gray-500 uppercase mb-1">
                <span>Preco (BRL)</span>
                <span className="text-right">Qtd (PXC)</span>
              </div>
              {depth.asks.length === 0 && <p className="text-xs text-gray-500">Sem ordens abertas no momento.</p>}
              {depth.asks.map(([price, qty], idx) => (
                <div key={idx} className="grid grid-cols-2 text-sm">
                  <span className="text-[var(--color-down)]">{Number(price).toFixed(4)}</span>
                  <span className="text-right">{Number(qty).toFixed(4)}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 text-sm">Carregando...</p>
          )}
        </div>
      </div>

      <div className="card p-4">
        <p className="label">Negociacoes recentes (venda/liquidacao/swap)</p>
        {trades.length === 0 ? (
          <p className="text-gray-500 text-sm mt-2">Nenhuma negociacao registrada ainda.</p>
        ) : (
          <table className="w-full text-sm mt-2">
            <thead>
              <tr className="text-left text-xs text-gray-500 uppercase">
                <th className="py-1.5 font-medium">Tipo</th>
                <th className="py-1.5 font-medium">Quantidade</th>
                <th className="py-1.5 font-medium">Hora</th>
              </tr>
            </thead>
            <tbody>
              {trades.map((t) => (
                <tr key={t.id} className="border-t border-[var(--color-border)]">
                  <td className="py-1.5 text-gray-400 text-xs">{t.type}</td>
                  <td className="py-1.5 font-medium">{Number(t.qty).toFixed(4)}</td>
                  <td className="py-1.5 text-xs text-gray-500">{fmtTime(t.time)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
    </div>
  );
}
