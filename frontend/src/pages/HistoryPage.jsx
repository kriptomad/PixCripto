import { useEffect, useState } from 'react';
import api from '../api/client.js';
import { useWallet } from '../context/WalletContext.jsx';

function fmtTime(ts) {
  if (!ts) return '';
  return new Date(ts * 1000).toLocaleString('pt-BR');
}

function TxRow({ tx, address }) {
  const isOutgoing = tx.sender === address;
  return (
    <tr className="border-b border-[var(--color-border)] last:border-0">
      <td className="py-2 pr-3">
        <span className={`text-xs font-semibold px-2 py-0.5 rounded ${isOutgoing ? 'bg-red-500/10 text-[var(--color-down)]' : 'bg-green-500/10 text-[var(--color-up)]'}`}>
          {isOutgoing ? 'Enviado' : 'Recebido'}
        </span>
      </td>
      <td className="py-2 pr-3 mono text-xs text-gray-400">{tx.tx_type}</td>
      <td className="py-2 pr-3 mono text-xs break-all">{isOutgoing ? tx.recipient : tx.sender}</td>
      <td className="py-2 pr-3 font-semibold">{Number(tx.amount).toFixed(4)}</td>
      <td className="py-2 text-xs text-gray-500">{fmtTime(tx.timestamp)}</td>
    </tr>
  );
}

export default function HistoryPage() {
  const { activeWallet } = useWallet();
  const [history, setHistory] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!activeWallet) return undefined;
    let cancelled = false;
    async function load() {
      try {
        const { data } = await api.get(`/explorer/address/${activeWallet.address}`);
        if (!cancelled) setHistory(data);
      } catch (err) {
        if (!cancelled) setError(err.message);
      }
    }
    load();
    const id = setInterval(load, 15_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [activeWallet]);

  if (!activeWallet) {
    return <p className="text-gray-400">Selecione ou crie uma carteira primeiro.</p>;
  }

  const confirmed = history?.confirmed_transactions || [];
  const pending = history?.pending_transactions || [];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Historico de transacoes</h1>
      {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}

      {pending.length > 0 && (
        <div className="card p-5">
          <p className="label">Pendentes (aguardando mineracao)</p>
          <table className="w-full text-sm mt-2">
            <tbody>
              {pending.map((tx) => (
                <TxRow key={tx.tx_id} tx={tx} address={activeWallet.address} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="card p-5">
        <p className="label">Confirmadas na blockchain</p>
        {confirmed.length === 0 ? (
          <p className="text-gray-500 text-sm mt-3">Nenhuma transacao confirmada ainda.</p>
        ) : (
          <table className="w-full text-sm mt-2">
            <thead>
              <tr className="text-left text-xs text-gray-500 uppercase">
                <th className="py-2 font-medium">Tipo</th>
                <th className="py-2 font-medium">Categoria</th>
                <th className="py-2 font-medium">Contraparte</th>
                <th className="py-2 font-medium">Valor</th>
                <th className="py-2 font-medium">Data</th>
              </tr>
            </thead>
            <tbody>
              {confirmed.map((tx) => (
                <TxRow key={tx.tx_id} tx={tx} address={activeWallet.address} />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
