import { useEffect, useState } from 'react';
import api from '../api/client.js';
import { useWallet } from '../context/WalletContext.jsx';

export default function ReceivePage() {
  const { activeWallet } = useWallet();
  const [amount, setAmount] = useState('');
  const [memo, setMemo] = useState('');
  const [qr, setQr] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function generateQr(e) {
    e?.preventDefault();
    if (!activeWallet) return;
    setLoading(true);
    setError('');
    try {
      const { data } = await api.get(`/wallet/${activeWallet.address}/qrcode`, {
        params: { amount: amount || undefined, memo: memo || undefined },
      });
      setQr(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (activeWallet) generateQr();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeWallet?.address]);

  if (!activeWallet) {
    return <p className="text-gray-400">Selecione ou crie uma carteira primeiro.</p>;
  }

  return (
    <div className="max-w-lg mx-auto">
      <h1 className="text-2xl font-bold mb-1">Receber PXC</h1>
      <p className="text-gray-500 text-sm mb-6">Compartilhe seu QR code ou endereco para receber pagamentos.</p>

      <div className="card p-6 space-y-4">
        <div className="flex flex-col items-center gap-3">
          {qr?.qrcode_png_base64 && (
            <img
              src={`data:image/png;base64,${qr.qrcode_png_base64}`}
              alt="QR code de pagamento"
              className="w-56 h-56 rounded-lg bg-white p-3"
            />
          )}
          <p className="mono text-xs break-all text-center text-gray-400">{activeWallet.address}</p>
        </div>

        <form onSubmit={generateQr} className="grid grid-cols-2 gap-3">
          <div>
            <label className="label">Quantidade (opcional)</label>
            <input type="number" step="any" min="0" className="input" value={amount} onChange={(e) => setAmount(e.target.value)} />
          </div>
          <div>
            <label className="label">Memo (opcional)</label>
            <input className="input" value={memo} onChange={(e) => setMemo(e.target.value)} />
          </div>
          <button type="submit" className="btn btn-primary col-span-2" disabled={loading}>
            {loading ? 'Gerando...' : 'Atualizar QR code'}
          </button>
        </form>
        {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
      </div>
    </div>
  );
}
