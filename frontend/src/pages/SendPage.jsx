import { useState } from 'react';
import api from '../api/client.js';
import { useWallet } from '../context/WalletContext.jsx';

export default function SendPage() {
  const { activeWallet } = useWallet();
  const [recipient, setRecipient] = useState('');
  const [amount, setAmount] = useState('');
  const [memo, setMemo] = useState('');
  const [fee, setFee] = useState('0');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  async function submit(e) {
    e.preventDefault();
    setError('');
    setResult(null);
    if (!activeWallet?.private_key) {
      setError(
        'A carteira ativa nao tem a chave privada disponivel neste navegador (ex: recuperada de seed sem re-derivar). Importe a chave privada para poder assinar transacoes.'
      );
      return;
    }
    setLoading(true);
    try {
      const { data } = await api.post('/transaction/send', {
        sender_private_key: activeWallet.private_key,
        sender_public_key: activeWallet.public_key,
        recipient,
        amount: Number(amount),
        memo,
        fee: Number(fee) || 0,
      });
      setResult(data);
      setAmount('');
      setMemo('');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  if (!activeWallet) {
    return <p className="text-gray-400">Selecione ou crie uma carteira primeiro.</p>;
  }

  return (
    <div className="max-w-lg mx-auto">
      <h1 className="text-2xl font-bold mb-1">Enviar PXC</h1>
      <p className="text-gray-500 text-sm mb-6">
        De <span className="mono">{activeWallet.address}</span>
      </p>

      <form onSubmit={submit} className="card p-6 space-y-4">
        <div>
          <label className="label">Endereco de destino</label>
          <input className="input mono" required value={recipient} onChange={(e) => setRecipient(e.target.value)} />
        </div>
        <div>
          <label className="label">Quantidade (PXC)</label>
          <input
            type="number"
            step="any"
            min="0"
            className="input"
            required
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
          />
        </div>
        <div>
          <label className="label">Taxa opcional (priorizar mineracao)</label>
          <input type="number" step="any" min="0" className="input" value={fee} onChange={(e) => setFee(e.target.value)} />
        </div>
        <div>
          <label className="label">Memo (opcional, criptografavel)</label>
          <input className="input" value={memo} onChange={(e) => setMemo(e.target.value)} maxLength={280} />
        </div>
        <button type="submit" className="btn btn-primary w-full" disabled={loading}>
          {loading ? 'Enviando...' : 'Enviar transacao'}
        </button>
        {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
        {result && (
          <div className="text-sm text-[var(--color-up)] bg-black/20 p-3 rounded-md">
            {result.message} — tx <span className="mono">{result.tx_id}</span>
          </div>
        )}
      </form>
    </div>
  );
}
