import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/client.js';
import { useWallet } from '../context/WalletContext.jsx';

const TABS = ['Nova carteira', 'Carteira HD (seed phrase)', 'Importar chave privada'];

export default function WalletPage() {
  const { addWallet, wallets, activeWallet, removeWallet, setActiveAddress } = useWallet();
  const navigate = useNavigate();
  const [tab, setTab] = useState(0);
  const [label, setLabel] = useState('');
  const [mnemonicWords, setMnemonicWords] = useState(24);
  const [importMnemonic, setImportMnemonic] = useState('');
  const [importPrivateKey, setImportPrivateKey] = useState('');
  const [importPublicKey, setImportPublicKey] = useState('');
  const [importAddress, setImportAddress] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  async function createSimpleWallet() {
    setLoading(true);
    setError('');
    try {
      const { data } = await api.post('/wallet/create', { label });
      addWallet({ address: data.address, public_key: data.public_key, private_key: data.private_key, label, type: 'simple' });
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function createHdWallet() {
    setLoading(true);
    setError('');
    try {
      const { data } = await api.post('/wallet/hd/create', { strength_bits: mnemonicWords === 24 ? 256 : 128 });
      addWallet({
        address: data.address,
        public_key: data.public_key,
        private_key: data.private_key,
        label,
        type: 'hd',
        mnemonic: data.mnemonic,
      });
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function recoverFromMnemonic() {
    setLoading(true);
    setError('');
    try {
      const { data } = await api.post('/wallet/hd/derive', { mnemonic: importMnemonic.trim(), account_index: 0 });
      addWallet({
        address: data.address,
        public_key: data.public_key,
        private_key: data.private_key,
        label,
        type: 'hd-recovered',
      });
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function importRawKey() {
    setError('');
    if (!importPrivateKey || !importPublicKey || !importAddress) {
      setError('Preencha chave privada, chave publica e endereco.');
      return;
    }
    addWallet({
      address: importAddress,
      public_key: importPublicKey,
      private_key: importPrivateKey,
      label,
      type: 'imported',
    });
    setResult({ address: importAddress, public_key: importPublicKey, private_key: importPrivateKey });
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Carteira PixCripto</h1>
        <p className="text-gray-500 text-sm mt-1">
          Chaves privadas e seed phrases sao geradas pelo backend mas NUNCA armazenadas nele — ficam somente
          neste navegador (localStorage). Guarde backups offline.
        </p>
      </div>

      {wallets.length > 0 && (
        <div className="card p-4">
          <p className="label">Carteiras salvas neste navegador</p>
          <ul className="space-y-2 mt-2">
            {wallets.map((w) => (
              <li key={w.address} className="flex items-center justify-between gap-3 text-sm">
                <button
                  type="button"
                  onClick={() => setActiveAddress(w.address)}
                  className={`mono truncate text-left flex-1 ${
                    activeWallet?.address === w.address ? 'text-[var(--color-accent)]' : 'text-gray-300'
                  }`}
                >
                  {w.label ? `${w.label} — ` : ''}
                  {w.address}
                </button>
                <button type="button" onClick={() => removeWallet(w.address)} className="text-xs text-[var(--color-down)] hover:underline">
                  remover
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="card p-6">
        <div className="flex gap-2 mb-5 border-b border-[var(--color-border)]">
          {TABS.map((t, i) => (
            <button
              key={t}
              type="button"
              onClick={() => {
                setTab(i);
                setResult(null);
                setError('');
              }}
              className={`px-3 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
                tab === i ? 'border-[var(--color-accent)] text-[var(--color-accent)]' : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              {t}
            </button>
          ))}
        </div>

        <div className="mb-4">
          <label className="label" htmlFor="label">
            Rotulo (opcional)
          </label>
          <input id="label" className="input" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Ex: Carteira principal" />
        </div>

        {tab === 0 && (
          <button type="button" className="btn btn-primary w-full" disabled={loading} onClick={createSimpleWallet}>
            {loading ? 'Gerando...' : 'Gerar nova carteira'}
          </button>
        )}

        {tab === 1 && (
          <div className="space-y-4">
            <div>
              <label className="label">Numero de palavras</label>
              <div className="flex gap-3">
                <label className="flex items-center gap-2 text-sm">
                  <input type="radio" checked={mnemonicWords === 12} onChange={() => setMnemonicWords(12)} /> 12 palavras
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <input type="radio" checked={mnemonicWords === 24} onChange={() => setMnemonicWords(24)} /> 24 palavras (mais seguro)
                </label>
              </div>
            </div>
            <button type="button" className="btn btn-primary w-full" disabled={loading} onClick={createHdWallet}>
              {loading ? 'Gerando...' : 'Gerar seed phrase + carteira'}
            </button>

            <div className="pt-4 border-t border-[var(--color-border)]">
              <label className="label">Ja tenho uma seed phrase — recuperar carteira</label>
              <textarea
                className="input h-20"
                value={importMnemonic}
                onChange={(e) => setImportMnemonic(e.target.value)}
                placeholder="palavra1 palavra2 palavra3 ..."
              />
              <button type="button" className="btn btn-secondary w-full mt-2" disabled={loading || !importMnemonic} onClick={recoverFromMnemonic}>
                Recuperar conta 0 desta seed
              </button>
            </div>
          </div>
        )}

        {tab === 2 && (
          <div className="space-y-3">
            <div>
              <label className="label">Endereco</label>
              <input className="input mono" value={importAddress} onChange={(e) => setImportAddress(e.target.value)} />
            </div>
            <div>
              <label className="label">Chave publica</label>
              <input className="input mono" value={importPublicKey} onChange={(e) => setImportPublicKey(e.target.value)} />
            </div>
            <div>
              <label className="label">Chave privada</label>
              <input type="password" className="input mono" value={importPrivateKey} onChange={(e) => setImportPrivateKey(e.target.value)} />
            </div>
            <button type="button" className="btn btn-primary w-full" onClick={importRawKey}>
              Importar
            </button>
          </div>
        )}

        {error && <p className="text-sm text-[var(--color-down)] mt-4">{error}</p>}

        {result && (
          <div className="mt-5 card p-4 bg-[var(--color-panel-alt)] space-y-2">
            <p className="text-sm text-[var(--color-up)] font-semibold">
              Carteira criada! Guarde estas informacoes AGORA — nao serao mostradas novamente.
            </p>
            {result.mnemonic && (
              <div>
                <p className="label">Seed phrase (24/12 palavras)</p>
                <p className="mono text-sm break-words bg-black/30 p-3 rounded-md">{result.mnemonic}</p>
              </div>
            )}
            <div>
              <p className="label">Endereco</p>
              <p className="mono text-sm break-all">{result.address}</p>
            </div>
            <div>
              <p className="label">Chave privada</p>
              <p className="mono text-sm break-all">{result.private_key}</p>
            </div>
            <button type="button" className="btn btn-primary mt-2" onClick={() => navigate('/')}>
              Ir para o painel
            </button>
          </div>
        )}
      </div>

      {activeWallet && <KycPanel address={activeWallet.address} />}
    </div>
  );
}

/**
 * Painel de conformidade regulatoria (KYC/AML) - registra nome+CPF (tier 1,
 * basico) ou tier 2 (completo, com hash do documento com foto - o arquivo em
 * si nunca sai do navegador do usuario sem antes ser transformado em hash
 * SHA-256 aqui mesmo no cliente) e mostra o limite de transacao vigente
 * (`app/compliance.py`). Backend real: `POST /compliance/kyc/register`.
 */
function KycPanel({ address }) {
  const [status, setStatus] = useState(null);
  const [fullName, setFullName] = useState('');
  const [cpf, setCpf] = useState('');
  const [documentFile, setDocumentFile] = useState(null);
  const [tier, setTier] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  async function loadStatus() {
    try {
      const { data } = await api.get(`/compliance/kyc/status/${address}`);
      setStatus(data);
    } catch {
      /* consulta informativa - falha silenciosa nao bloqueia o restante da pagina */
    }
  }

  useEffect(() => {
    loadStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [address]);

  async function hashFile(file) {
    const buffer = await file.arrayBuffer();
    const digest = await crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async function submit(e) {
    e.preventDefault();
    setError('');
    setMessage('');
    setLoading(true);
    try {
      let document_hash;
      if (tier === 2) {
        if (!documentFile) {
          setError('Tier 2 exige o upload de um documento com foto (apenas o hash e enviado, nunca o arquivo).');
          setLoading(false);
          return;
        }
        document_hash = await hashFile(documentFile);
      }
      const { data } = await api.post('/compliance/kyc/register', {
        address,
        full_name: fullName,
        cpf,
        tier,
        document_hash,
      });
      setMessage(`Verificacao registrada: tier ${data.tier}, limite de ${data.limit_pxc} PXC por transacao.`);
      loadStatus();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="card p-6 space-y-4">
      <div>
        <p className="label !mb-1">Verificacao de identidade (KYC/AML)</p>
        <p className="text-sm text-gray-500">
          Conformidade regulatoria propria da rede — o documento nunca e enviado nem armazenado, apenas seu hash
          SHA-256, calculado aqui no seu navegador.
        </p>
      </div>

      {status && (
        <p className="text-sm">
          Nivel atual: <span className="font-semibold">tier {status.tier}</span> · limite por transacao:{' '}
          <span className="font-semibold">{status.limit_pxc} PXC</span>
        </p>
      )}

      <form onSubmit={submit} className="space-y-3">
        <div className="flex gap-3">
          <label className="flex items-center gap-2 text-sm">
            <input type="radio" checked={tier === 1} onChange={() => setTier(1)} /> Tier 1 (basico — nome + CPF)
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input type="radio" checked={tier === 2} onChange={() => setTier(2)} /> Tier 2 (completo — + documento)
          </label>
        </div>
        <div>
          <label className="label">Nome completo</label>
          <input className="input" required value={fullName} onChange={(e) => setFullName(e.target.value)} />
        </div>
        <div>
          <label className="label">CPF</label>
          <input className="input" required value={cpf} onChange={(e) => setCpf(e.target.value)} placeholder="000.000.000-00" />
        </div>
        {tier === 2 && (
          <div>
            <label className="label">Documento com foto (RG/CNH) — apenas o hash e enviado</label>
            <input type="file" accept="image/*,.pdf" onChange={(e) => setDocumentFile(e.target.files?.[0] || null)} className="text-sm" />
          </div>
        )}
        <button type="submit" className="btn btn-primary w-full" disabled={loading}>
          {loading ? 'Enviando...' : 'Registrar verificacao'}
        </button>
        {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
        {message && <p className="text-sm text-[var(--color-up)]">{message}</p>}
      </form>
    </div>
  );
}
