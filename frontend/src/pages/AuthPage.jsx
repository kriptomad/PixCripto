import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import api from '../api/client.js';
import { useAuth } from '../context/AuthContext.jsx';

/**
 * Cadastro e login da conta de USUARIO do site (correntista da rede) -
 * distinto do login do painel de administracao (`/admin`). Uma conta aqui
 * permite vincular carteira(s) e enviar a verificacao de identidade (KYC)
 * em `/account`.
 */
export default function AuthPage() {
  const [mode, setMode] = useState('login'); // 'login' | 'register'
  const [form, setForm] = useState({ username: '', email: '', password: '', confirmPassword: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const { login } = useAuth();
  const navigate = useNavigate();

  function updateField(field, value) {
    setForm((prev) => ({ ...prev, [field]: value }));
  }

  async function handleLogin(e) {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const { data } = await api.post('/auth/login', {
        username_or_email: form.username,
        password: form.password,
      });
      login(data.token);
      navigate('/account');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleRegister(e) {
    e.preventDefault();
    setError('');
    setMessage('');
    if (form.password !== form.confirmPassword) {
      setError('As senhas nao coincidem.');
      return;
    }
    if (form.password.length < 10) {
      setError('A senha deve ter ao menos 10 caracteres.');
      return;
    }
    setLoading(true);
    try {
      await api.post('/auth/register', {
        username: form.username,
        email: form.email,
        password: form.password,
      });
      setMessage('Conta criada com sucesso! Faca login para continuar.');
      setMode('login');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-md mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">{mode === 'login' ? 'Entrar' : 'Criar conta'}</h1>
        <p className="text-gray-500 text-sm mt-1">
          Sua conta permite vincular carteiras, consultar historico e enviar a verificacao de identidade (KYC)
          necessaria para destravar limites maiores de transacao.
        </p>
      </div>

      <div className="flex gap-2 border-b border-[var(--color-border)]">
        {[
          ['login', 'Entrar'],
          ['register', 'Criar conta'],
        ].map(([key, label]) => (
          <button
            key={key}
            type="button"
            onClick={() => {
              setMode(key);
              setError('');
              setMessage('');
            }}
            className={`px-3 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
              mode === key ? 'border-[var(--color-accent)] text-[var(--color-accent)]' : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {message && <p className="text-sm text-[var(--color-up)]">{message}</p>}
      {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}

      {mode === 'login' ? (
        <form onSubmit={handleLogin} className="card p-6 space-y-4">
          <div>
            <label className="label">Usuario ou e-mail</label>
            <input className="input" required value={form.username} onChange={(e) => updateField('username', e.target.value)} />
          </div>
          <div>
            <label className="label">Senha</label>
            <input
              type="password"
              className="input"
              required
              value={form.password}
              onChange={(e) => updateField('password', e.target.value)}
            />
          </div>
          <button type="submit" className="btn btn-primary w-full" disabled={loading}>
            {loading ? 'Entrando...' : 'Entrar'}
          </button>
        </form>
      ) : (
        <form onSubmit={handleRegister} className="card p-6 space-y-4">
          <div>
            <label className="label">Nome de usuario</label>
            <input className="input" required minLength={3} maxLength={32} value={form.username} onChange={(e) => updateField('username', e.target.value)} />
          </div>
          <div>
            <label className="label">E-mail</label>
            <input type="email" className="input" required value={form.email} onChange={(e) => updateField('email', e.target.value)} />
          </div>
          <div>
            <label className="label">Senha (minimo 10 caracteres)</label>
            <input
              type="password"
              className="input"
              required
              minLength={10}
              value={form.password}
              onChange={(e) => updateField('password', e.target.value)}
            />
          </div>
          <div>
            <label className="label">Confirmar senha</label>
            <input
              type="password"
              className="input"
              required
              value={form.confirmPassword}
              onChange={(e) => updateField('confirmPassword', e.target.value)}
            />
          </div>
          <button type="submit" className="btn btn-primary w-full" disabled={loading}>
            {loading ? 'Criando conta...' : 'Criar conta'}
          </button>
        </form>
      )}

      <p className="text-xs text-gray-500 text-center">
        Precisa apenas criar uma carteira sem conta?{' '}
        <Link to="/wallet" className="text-[var(--color-accent)] hover:underline">
          va para Carteira
        </Link>
        .
      </p>
    </div>
  );
}
