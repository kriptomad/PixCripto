import { useEffect, useState } from 'react';
import api from '../api/client.js';

/**
 * Banner/carrossel estilo Binance com o preco atual do PXC, variacao 24h
 * (com simbolo de subida/descida) e a cotacao do ouro que serve de lastro.
 * Atualiza sozinho a cada poucos segundos.
 */
export default function PriceTicker() {
  const [ticker, setTicker] = useState(null);
  const [gold, setGold] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const [tickerRes, goldRes] = await Promise.all([
          api.get('/api/v1/ticker/24hr'),
          api.get('/market/gold-price'),
        ]);
        if (!cancelled) {
          setTicker(tickerRes.data);
          setGold(goldRes.data);
          setError('');
        }
      } catch (err) {
        if (!cancelled) setError(err.message || 'Falha ao carregar cotacoes');
      }
    }

    load();
    const interval = setInterval(load, 15_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  if (error) {
    return (
      <div className="card px-4 py-3 text-sm text-[var(--color-down)]">Ticker indisponivel: {error}</div>
    );
  }

  if (!ticker || !gold) {
    return <div className="card px-4 py-3 text-sm text-gray-500 animate-pulse">Carregando cotacoes...</div>;
  }

  const isUp = ticker.priceChangePercent >= 0;
  const items = [
    { label: 'PXC/BRL', value: `R$ ${Number(ticker.lastPrice).toFixed(4)}`, change: ticker.priceChangePercent, isUp },
    { label: 'Maxima 24h', value: `R$ ${Number(ticker.highPrice).toFixed(4)}` },
    { label: 'Minima 24h', value: `R$ ${Number(ticker.lowPrice).toFixed(4)}` },
    { label: 'Volume 24h (PXC)', value: Number(ticker.volume).toFixed(2) },
    { label: 'Ouro (XAU/USD)', value: `US$ ${Number(gold.gold_usd_per_oz).toFixed(2)}`, change: gold.delta_pct_gold },
    { label: 'USD/BRL', value: Number(gold.usd_brl).toFixed(4) },
  ];

  return (
    <div className="card overflow-hidden">
      <div className="flex divide-x divide-[var(--color-border)] overflow-x-auto">
        {items.map((item) => (
          <div key={item.label} className="px-5 py-3 min-w-[150px] flex-shrink-0">
            <p className="label !mb-1">{item.label}</p>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-sm">{item.value}</span>
              {typeof item.change === 'number' && (
                <span
                  className={`text-xs font-semibold ${
                    item.change >= 0 ? 'text-[var(--color-up)]' : 'text-[var(--color-down)]'
                  }`}
                >
                  {item.change >= 0 ? '▲ +' : '▼ '}
                  {item.change.toFixed(2)}%
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
      {gold.stale && (
        <div className="px-5 py-1.5 text-xs bg-yellow-500/10 text-yellow-400 border-t border-[var(--color-border)]">
          ⚠ cotacao de ouro em modo defasado (stale) — usando ultimo valor confiavel conhecido
        </div>
      )}
    </div>
  );
}
