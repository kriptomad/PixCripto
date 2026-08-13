import { useEffect, useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import api from '../api/client.js';
import { useAuth } from '../context/AuthContext.jsx';
import { authHeaders } from '../context/AuthContext.jsx';
import { useWallet } from '../context/WalletContext.jsx';

const KYC_STATUS_LABEL = {
  none: 'Nao verificado',
  pending: 'Em analise',
  approved: 'Verificado',
  rejected: 'Rejeitado - reenvie a solicitacao',
};

/**
 * Area logada "Minha conta": perfil, carteiras vinculadas e verificacao de
 * identidade (KYC) com documento com foto REAL (frente/verso + selfie) -
 * tudo cifrado no backend (`app/user_accounts.py`) e revisado manualmente
 * por um operador antes de qualquer tier ser concedido.
 */
export default function AccountPage() {
  const { token, profile, loading, logout, refresh } = useAuth();
  const { wallets, activeWallet } = useWallet();
  const navigate = useNavigate();

  if (!loading && !token) {
    return <Navigate to="/auth" replace />;
  }

  if (loading || !profile) {
    return <p className="text-gray-500">Carregando...</p>;
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold">Minha conta</h1>
          <p className="text-gray-500 text-sm mt-1">
            <span className="mono">{profile.username}</span> · {profile.email}
          </p>
        </div>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => {
            logout();
            navigate('/');
          }}
        >
          Sair
        </button>
      </div>

      <div className="card p-6 space-y-3">
        <p className="label !mb-1">Verificacao de identidade (KYC)</p>
        <p className="text-sm">
          Status atual: <span className="font-semibold">{KYC_STATUS_LABEL[profile.kyc_status] || profile.kyc_status}</span>
          {profile.kyc_tier > 0 && ` · tier ${profile.kyc_tier}`}
        </p>
      </div>

      <WalletLinkPanel token={token} wallets={profile.wallets} activeWallet={activeWallet} localWallets={wallets} onChanged={refresh} />

      {(profile.kyc_status === 'none' || profile.kyc_status === 'rejected') && (
        <KycForm token={token} onSubmitted={refresh} rejectionContext={profile.kyc_status === 'rejected'} />
      )}
      {profile.kyc_status === 'pending' && (
        <div className="card p-6">
          <p className="text-sm text-gray-400">
            Sua verificacao esta em analise por um operador. Voce sera notificado quando o resultado sair.
          </p>
        </div>
      )}
    </div>
  );
}

function WalletLinkPanel({ token, wallets, localWallets, activeWallet, onChanged }) {
  const [address, setAddress] = useState('');
  const [label, setLabel] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (activeWallet && !address) setAddress(activeWallet.address);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeWallet]);

  async function link(e) {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      await api.post('/auth/wallets', { address: address.trim(), label: label.trim() }, { headers: authHeaders(token) });
      setAddress('');
      setLabel('');
      onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function unlink(addr) {
    setLoading(true);
    setError('');
    try {
      await api.delete(`/auth/wallets/${addr}`, { headers: authHeaders(token) });
      onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="card p-6 space-y-4">
      <p className="label !mb-1">Carteiras vinculadas a conta</p>
      <p className="text-sm text-gray-500">
        Apenas o endereco publico e vinculado — sua chave privada nunca sai deste navegador.
      </p>

      <ul className="space-y-2">
        {wallets.map((w) => (
          <li key={w.address} className="flex items-center justify-between gap-3 text-sm bg-[var(--color-panel-alt)] rounded-md px-3 py-2">
            <span className="mono truncate">{w.label ? `${w.label} — ` : ''}{w.address}</span>
            <button type="button" className="text-xs text-[var(--color-down)] hover:underline" onClick={() => unlink(w.address)} disabled={loading}>
              desvincular
            </button>
          </li>
        ))}
        {wallets.length === 0 && <li className="text-sm text-gray-500">Nenhuma carteira vinculada ainda.</li>}
      </ul>

      <form onSubmit={link} className="flex flex-col sm:flex-row gap-2">
        <select className="input sm:!w-64" value={address} onChange={(e) => setAddress(e.target.value)}>
          <option value="">Selecionar carteira salva neste navegador</option>
          {localWallets.map((w) => (
            <option key={w.address} value={w.address}>
              {w.label ? `${w.label} — ` : ''}{w.address}
            </option>
          ))}
        </select>
        <input className="input flex-1" placeholder="ou cole um endereco" value={address} onChange={(e) => setAddress(e.target.value)} />
        <input className="input sm:!w-40" placeholder="rotulo (opcional)" value={label} onChange={(e) => setLabel(e.target.value)} />
        <button type="submit" className="btn btn-primary" disabled={loading || !address}>
          Vincular
        </button>
      </form>
      {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
    </div>
  );
}

const emptyKycForm = { full_name: '', cpf: '', rg: '', birth_date: '' };

function KycForm({ token, onSubmitted, rejectionContext }) {
  const [form, setForm] = useState(emptyKycForm);
  const [documentFront, setDocumentFront] = useState(null);
  const [documentBack, setDocumentBack] = useState(null);
  const [selfie, setSelfie] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  function updateField(field, value) {
    setForm((prev) => ({ ...prev, [field]: value }));
  }

  async function submit(e) {
    e.preventDefault();
    setError('');
    setMessage('');
    if (!documentFront || !documentBack || !selfie) {
      setError('Envie as 3 fotos: documento (frente), documento (verso) e selfie.');
      return;
    }
    setLoading(true);
    try {
      const body = new FormData();
      body.append('full_name', form.full_name);
      body.append('cpf', form.cpf);
      body.append('rg', form.rg);
      body.append('birth_date', form.birth_date);
      body.append('document_front', documentFront);
      body.append('document_back', documentBack);
      body.append('selfie', selfie);
      await api.post('/kyc/submit', body, {
        headers: { ...authHeaders(token), 'Content-Type': 'multipart/form-data' },
      });
      setMessage('Verificacao enviada! Ela sera analisada por um operador em breve.');
      setForm(emptyKycForm);
      setDocumentFront(null);
      setDocumentBack(null);
      setSelfie(null);
      onSubmitted();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={submit} className="card p-6 space-y-4">
      <div>
        <p className="label !mb-1">{rejectionContext ? 'Reenviar verificacao de identidade' : 'Enviar verificacao de identidade (KYC)'}</p>
        <p className="text-sm text-gray-500">
          CPF, RG e as fotos sao cifrados (AES-256-GCM) antes de tocar o disco e so podem ser vistos por um
          operador humano no momento da revisao — nunca aprovado automaticamente.
        </p>
      </div>

      <div className="grid sm:grid-cols-2 gap-3">
        <div>
          <label className="label">Nome completo</label>
          <input className="input" required value={form.full_name} onChange={(e) => updateField('full_name', e.target.value)} />
        </div>
        <div>
          <label className="label">Data de nascimento</label>
          <input type="date" className="input" required value={form.birth_date} onChange={(e) => updateField('birth_date', e.target.value)} />
        </div>
        <div>
          <label className="label">CPF</label>
          <input className="input" required placeholder="000.000.000-00" value={form.cpf} onChange={(e) => updateField('cpf', e.target.value)} />
        </div>
        <div>
          <label className="label">RG</label>
          <input className="input" required value={form.rg} onChange={(e) => updateField('rg', e.target.value)} />
        </div>
      </div>

      <div className="grid sm:grid-cols-3 gap-3">
        <div>
          <label className="label">Documento (frente)</label>
          <input type="file" accept="image/*,.pdf" required className="text-sm" onChange={(e) => setDocumentFront(e.target.files?.[0] || null)} />
        </div>
        <div>
          <label className="label">Documento (verso)</label>
          <input type="file" accept="image/*,.pdf" required className="text-sm" onChange={(e) => setDocumentBack(e.target.files?.[0] || null)} />
        </div>
        <div>
          <label className="label">Selfie (prova de vida)</label>
          <input type="file" accept="image/*" required className="text-sm" onChange={(e) => setSelfie(e.target.files?.[0] || null)} />
        </div>
      </div>

      <button type="submit" className="btn btn-primary w-full" disabled={loading}>
        {loading ? 'Enviando...' : 'Enviar verificacao'}
      </button>
      {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
      {message && <p className="text-sm text-[var(--color-up)]">{message}</p>}
    </form>
  );
}
