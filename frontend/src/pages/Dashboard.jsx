import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/client.js';
import { useWallet } from '../context/WalletContext.jsx';
import PriceTicker from '../components/PriceTicker.jsx';

export default function Dashboard() {
  const { activeWallet } = useWallet();
  const [balance, setBalance] = useState(null);
  const [goldPrice, setGoldPrice] = useState(null);
  const [networkStats, setNetworkStats] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const [goldRes, statsRes] = await Promise.all([
          api.get('/market/gold-price'),
          api.get('/mining/network-stats'),
        ]);
        if (!cancelled) {
          setGoldPrice(goldRes.data);
          setNetworkStats(statsRes.data);
        }
      } catch (err) {
        if (!cancelled) setError(err.message);
      }
    }
    load();
    const id = setInterval(load, 20_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  useEffect(() => {
    if (!activeWallet) {
      setBalance(null);
      return undefined;
    }
    let cancelled = false;
    async function loadBalance() {
      try {
        const { data } = await api.get(`/wallet/${activeWallet.address}/balance`);
        if (!cancelled) setBalance(data);
      } catch {
        /* ignore transient errors on the dashboard poll */
      }
    }
    loadBalance();
    const id = setInterval(loadBalance, 10_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [activeWallet]);

  return (
    <div className="space-y-6">
      <PriceTicker />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card p-5 md:col-span-1">
          <p className="label">Sua carteira</p>
          {activeWallet ? (
            <>
              <p className="mono text-sm break-all mb-3">{activeWallet.address}</p>
              <p className="text-3xl font-bold">
                {balance ? balance.balance.toFixed(4) : '—'} <span className="text-base text-gray-500">PXC</span>
              </p>
              {balance && goldPrice && (
                <p className="text-sm text-gray-500 mt-1">
                  ≈ R$ {(balance.balance * goldPrice.pxc_brl_rate).toFixed(2)}
                </p>
              )}
              <div className="flex gap-2 mt-4">
                <Link to="/send" className="btn btn-primary flex-1">
                  Enviar
                </Link>
                <Link to="/receive" className="btn btn-secondary flex-1">
                  Receber
                </Link>
              </div>
            </>
          ) : (
            <div className="text-center py-6">
              <p className="text-gray-400 text-sm mb-3">Voce ainda nao tem uma carteira ativa.</p>
              <Link to="/wallet" className="btn btn-primary">
                Criar carteira
              </Link>
            </div>
          )}
        </div>

        <div className="card p-5">
          <p className="label">Lastro em ouro</p>
          {goldPrice ? (
            <>
              <p className="text-2xl font-bold">US$ {goldPrice.gold_usd_per_oz.toFixed(2)}/oz</p>
              <p className="text-sm text-gray-500 mt-1">1 PXC = {goldPrice.pxc_brl_rate.toFixed(4)} BRL</p>
              <p
                className={`text-sm mt-2 font-semibold ${
                  goldPrice.delta_pct_gold >= 0 ? 'text-[var(--color-up)]' : 'text-[var(--color-down)]'
                }`}
              >
                {goldPrice.delta_pct_gold >= 0 ? '▲' : '▼'} {goldPrice.delta_pct_gold.toFixed(2)}% (variacao do ouro)
              </p>
              {goldPrice.rejected_manipulation_attempt && (
                <p className="text-xs text-yellow-400 mt-2">
                  ⚠ uma tentativa de manipulacao de preco foi detectada e rejeitada automaticamente
                </p>
              )}
            </>
          ) : (
            <p className="text-gray-500 text-sm">Carregando...</p>
          )}
        </div>

        <div className="card p-5">
          <p className="label">Rede / anti-monopolio</p>
          {networkStats ? (
            <>
              <p className="text-sm text-gray-400">
                Janela de {networkStats.window_size} blocos minerados
              </p>
              <p className="text-2xl font-bold mt-1">HHI {Number(networkStats.hhi ?? 0).toFixed(3)}</p>
              <p className="text-xs text-gray-500 mt-1">{networkStats.interpretation}</p>
            </>
          ) : (
            <p className="text-gray-500 text-sm">Carregando...</p>
          )}
        </div>
      </div>

      {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
    </div>
  );
}
