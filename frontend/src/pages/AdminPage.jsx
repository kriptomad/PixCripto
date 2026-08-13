import { useEffect, useState } from 'react';
import api, { API_BASE_URL } from '../api/client.js';

const SESSION_KEY = 'pixcripto.adminSessionToken';
const USERNAME_KEY = 'pixcripto.adminUsername';

function authHeaders(token) {
  return { Authorization: `Bearer ${token}` };
}

/**
 * Painel de Administracao do site (login real, nao mais um token compartilhado
 * colado manualmente): usuario/senha autenticam contra `/admin/auth/login`
 * (hash PBKDF2 + sessao expiravel, ver `app/admin_auth.py`), e a sessao
 * resultante da acesso a TODAS as ferramentas de administracao do site:
 * CMS de noticias, CMS de paginas estaticas, biblioteca de midia (upload/
 * remocao de arquivos), chaves de funcionalidade (feature flags, incluindo
 * modo manutencao) e o housekeeping automatico do sistema.
 *
 * Para configuracoes profundas da REDE (P2P, DNS seeds, compliance,
 * distribuicao) o painel completo continua sendo `admin_panel/` (porta 8600,
 * nunca distribuido) - este painel aqui e o de administracao do SITE.
 */
export default function AdminPage() {
  const [token, setToken] = useState(() => sessionStorage.getItem(SESSION_KEY) || '');
  const [username, setUsername] = useState(() => sessionStorage.getItem(USERNAME_KEY) || '');

  function handleLogin(newToken, newUsername) {
    sessionStorage.setItem(SESSION_KEY, newToken);
    sessionStorage.setItem(USERNAME_KEY, newUsername);
    setToken(newToken);
    setUsername(newUsername);
  }

  function handleLogout() {
    if (token) {
      api.post('/admin/auth/logout', {}, { headers: authHeaders(token) }).catch(() => {});
    }
    sessionStorage.removeItem(SESSION_KEY);
    sessionStorage.removeItem(USERNAME_KEY);
    setToken('');
    setUsername('');
  }

  if (!token) {
    return <LoginGate onLogin={handleLogin} />;
  }

  return <AdminDashboard token={token} username={username} onUnauthorized={handleLogout} onLogout={handleLogout} />;
}

function LoginGate({ onLogin }) {
  const [form, setForm] = useState({ username: '', password: '' });
  const [otp, setOtp] = useState('');
  const [needs2fa, setNeeds2fa] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [loginEnabled, setLoginEnabled] = useState(true);

  useEffect(() => {
    api.get('/admin/auth/status').then(({ data }) => setLoginEnabled(data.login_enabled)).catch(() => {});
  }, []);

  async function submit(e) {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const payload = needs2fa ? { ...form, otp_code: otp } : form;
      const { data } = await api.post('/admin/auth/login', payload);
      onLogin(data.token, data.username);
    } catch (err) {
      if (err?.response?.status === 428) {
        setNeeds2fa(true);
        setError('Digite o codigo do seu app autenticador (2FA) ou um codigo de backup.');
      } else {
        setError(err.response?.data?.detail || err.message || 'Falha ao autenticar');
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-md mx-auto mt-12 space-y-6">
      <div className="text-center">
        <h1 className="text-2xl font-bold">Painel de Administracao</h1>
        <p className="text-gray-500 text-sm mt-1">Acesso restrito ao operador do site PixCripto.</p>
      </div>

      {!loginEnabled && (
        <div className="card p-4 border-[var(--color-down)] text-sm text-[var(--color-down)]">
          Login ainda nao configurado no servidor. Defina <span className="mono">PIXCRIPTO_ADMIN_USERNAME</span> e{' '}
          <span className="mono">PIXCRIPTO_ADMIN_PASSWORD</span> no arquivo <span className="mono">.env</span> do backend
          e reinicie o processo.
        </div>
      )}

      <form onSubmit={submit} className="card p-6 space-y-4">
        <div>
          <label className="label">Usuario</label>
          <input
            className="input"
            autoComplete="username"
            value={form.username}
            disabled={needs2fa}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
            required
          />
        </div>
        <div>
          <label className="label">Senha</label>
          <input
            type="password"
            className="input"
            autoComplete="current-password"
            value={form.password}
            disabled={needs2fa}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            required
          />
        </div>
        {needs2fa && (
          <div>
            <label className="label">Codigo de verificacao (2FA)</label>
            <input
              className="input mono"
              autoComplete="one-time-code"
              placeholder="000000 ou codigo de backup"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              autoFocus
              required
            />
          </div>
        )}
        {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
        <button type="submit" className="btn btn-primary w-full" disabled={loading}>
          {loading ? 'Entrando...' : needs2fa ? 'Verificar e entrar' : 'Entrar'}
        </button>
      </form>
    </div>
  );
}

const TABS = [
  ['dashboard', 'Dashboard'],
  ['news', 'Noticias'],
  ['pages', 'Paginas (CMS)'],
  ['media', 'Midia'],
  ['kyc', 'Verificacoes KYC'],
  ['features', 'Funcoes do site'],
  ['housekeeping', 'Housekeeping'],
  ['settings', 'Configuracoes do site'],
  ['users', 'Equipe'],
  ['security', 'Seguranca'],
  ['account', 'Conta'],
];

function AdminDashboard({ token, username, onUnauthorized, onLogout }) {
  const [tab, setTab] = useState('news');

  // Wrapper que trata 401 (sessao expirada) deslogando automaticamente.
  async function guarded(fn) {
    try {
      return await fn();
    } catch (err) {
      if (err?.response?.status === 401) {
        onUnauthorized();
      }
      throw err;
    }
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold">Painel de Administracao</h1>
          <p className="text-gray-500 text-sm mt-1">
            Autenticado como <span className="mono">{username}</span>. Para configuracoes profundas de rede/P2P, use o{' '}
            <a href="http://127.0.0.1:8600" target="_blank" rel="noreferrer" className="text-[var(--color-accent)]">
              painel de rede (porta 8600)
            </a>
            .
          </p>
        </div>
        <button type="button" className="btn btn-secondary" onClick={onLogout}>
          Sair
        </button>
      </div>

      <div className="flex gap-2 border-b border-[var(--color-border)] overflow-x-auto">
        {TABS.map(([key, label]) => (
          <button
            key={key}
            type="button"
            onClick={() => setTab(key)}
            className={`px-3 py-2 text-sm font-medium border-b-2 -mb-px whitespace-nowrap transition-colors ${
              tab === key ? 'border-[var(--color-accent)] text-[var(--color-accent)]' : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === 'dashboard' && <DashboardTab token={token} guarded={guarded} />}
      {tab === 'news' && <NewsTab token={token} guarded={guarded} />}
      {tab === 'pages' && <PagesTab token={token} guarded={guarded} />}
      {tab === 'media' && <MediaTab token={token} guarded={guarded} />}
      {tab === 'kyc' && <KycReviewTab token={token} guarded={guarded} />}
      {tab === 'features' && <FeaturesTab token={token} guarded={guarded} />}
      {tab === 'housekeeping' && <HousekeepingTab token={token} guarded={guarded} />}
      {tab === 'settings' && <SiteSettingsTab token={token} guarded={guarded} />}
      {tab === 'users' && <UsersTab token={token} username={username} guarded={guarded} />}
      {tab === 'security' && <SecurityTab token={token} guarded={guarded} />}
      {tab === 'account' && <AccountTab token={token} username={username} guarded={guarded} onLogout={onLogout} />}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Dashboard (integracao ao vivo com a rede/blockchain PixCripto)
// ---------------------------------------------------------------------------

function DashboardTab({ token, guarded }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  async function load() {
    try {
      const { data } = await guarded(() => api.get('/admin/dashboard', { headers: authHeaders(token) }));
      setData(data);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    load();
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (error) return <p className="text-sm text-[var(--color-down)]">{error}</p>;
  if (!data) return <p className="text-sm text-gray-500">Carregando...</p>;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Altura da cadeia" value={data.chain.height} />
        <StatCard label="Blocos minerados" value={data.chain.mined_blocks} />
        <StatCard label="Mempool" value={data.chain.mempool_size} />
        <StatCard label="Modo de dificuldade" value={data.difficulty.mode} />
      </div>
      <div className="card p-5 space-y-2">
        <p className="label">Dificuldade e anti-monopolio</p>
        <p className="text-sm">
          Dificuldade base: <span className="mono">{data.difficulty.base_difficulty_bits ?? data.difficulty.base_bits}</span> bits · Teto do
          modo: <span className="mono">{data.difficulty.max_bits_this_mode}</span> · Equivalente Bitcoin 2020:{' '}
          <span className="mono">{data.difficulty.bitcoin_2020_equivalent_bits}</span>
        </p>
        <p className="text-sm text-gray-400">
          Concentracao de hashrate (HHI): <span className="mono">{data.network.hhi?.toFixed?.(4) ?? '-'}</span> (janela de{' '}
          {data.network.window_size} blocos)
        </p>
      </div>
      {data.dump_control && (
        <div className="card p-5">
          <p className="label">Controle de dump / auto-regulacao</p>
          <pre className="mono text-xs whitespace-pre-wrap break-all text-gray-400 mt-2">{JSON.stringify(data.dump_control, null, 2)}</pre>
        </div>
      )}
      <div className="card p-5">
        <p className="label">Funcoes do site (resumo)</p>
        <div className="flex flex-wrap gap-2 mt-2">
          {Object.entries(data.feature_flags || {}).map(([key, enabled]) => (
            <span
              key={key}
              className={`text-xs px-2 py-1 rounded-md ${enabled ? 'bg-[var(--color-up)]/10 text-[var(--color-up)]' : 'bg-[var(--color-down)]/10 text-[var(--color-down)]'}`}
            >
              {key}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value }) {
  return (
    <div className="card p-4">
      <p className="label">{label}</p>
      <p className="text-lg font-semibold mono">{value ?? '-'}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Noticias (CMS cronologico do feed do site)
// ---------------------------------------------------------------------------

const emptyNewsForm = { title: '', summary: '', body: '', image_url: '', author: 'PixCripto', status: 'published', category: 'geral', tags: '' };

function NewsTab({ token, guarded }) {
  const [posts, setPosts] = useState([]);
  const [form, setForm] = useState(emptyNewsForm);
  const [editingId, setEditingId] = useState(null);
  const [imageFile, setImageFile] = useState(null);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function loadPosts() {
    try {
      const { data } = await guarded(() => api.get('/admin/news', { params: { limit: 50 }, headers: authHeaders(token) }));
      setPosts(data.posts || []);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    loadPosts();
  }, []);

  async function uploadImageIfNeeded() {
    if (!imageFile) return form.image_url;
    const fd = new FormData();
    fd.append('file', imageFile);
    const { data } = await guarded(() =>
      api.post('/news/upload-image', fd, { headers: { ...authHeaders(token), 'Content-Type': 'multipart/form-data' } })
    );
    return data.image_url;
  }

  async function submit(e) {
    e.preventDefault();
    setLoading(true);
    setError('');
    setMessage('');
    try {
      const image_url = await uploadImageIfNeeded();
      const payload = { ...form, image_url };
      if (editingId) {
        await guarded(() => api.put(`/news/${editingId}`, payload, { headers: authHeaders(token) }));
        setMessage('Noticia atualizada.');
      } else {
        await guarded(() => api.post('/news', payload, { headers: authHeaders(token) }));
        setMessage('Noticia publicada.');
      }
      setForm(emptyNewsForm);
      setImageFile(null);
      setEditingId(null);
      loadPosts();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function editPost(post) {
    setEditingId(post.id);
    setForm({
      title: post.title,
      summary: post.summary || '',
      body: post.body || '',
      image_url: post.image_url || '',
      author: post.author || 'PixCripto',
      status: post.status || 'published',
      category: post.category || 'geral',
      tags: post.tags || '',
    });
  }

  async function deletePost(id) {
    if (!window.confirm('Remover esta noticia?')) return;
    try {
      await guarded(() => api.delete(`/news/${id}`, { headers: authHeaders(token) }));
      loadPosts();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="space-y-6">
      <form onSubmit={submit} className="card p-6 space-y-3">
        <p className="label !mb-2">{editingId ? `Editando noticia #${editingId}` : 'Nova noticia'}</p>
        <input className="input" placeholder="Titulo" required value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
        <input
          className="input"
          placeholder="Resumo (aparece no feed)"
          value={form.summary}
          onChange={(e) => setForm({ ...form, summary: e.target.value })}
        />
        <textarea
          className="input h-32"
          placeholder="Corpo da noticia"
          value={form.body}
          onChange={(e) => setForm({ ...form, body: e.target.value })}
        />
        <input className="input" placeholder="Autor" value={form.author} onChange={(e) => setForm({ ...form, author: e.target.value })} />
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="label">Status</label>
            <select className="input" value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}>
              <option value="draft">Rascunho</option>
              <option value="scheduled">Agendada</option>
              <option value="published">Publicada</option>
            </select>
          </div>
          <div>
            <label className="label">Categoria</label>
            <input className="input" placeholder="geral" value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })} />
          </div>
        </div>
        <input className="input" placeholder="Tags (separadas por virgula)" value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} />
        <div>
          <label className="label">Imagem de capa (upload)</label>
          <input type="file" accept="image/*" onChange={(e) => setImageFile(e.target.files?.[0] || null)} className="text-sm" />
          {form.image_url && !imageFile && (
            <img src={`${API_BASE_URL}${form.image_url}`} alt="capa atual" className="h-24 mt-2 rounded-md" />
          )}
        </div>
        <div className="flex gap-2">
          <button type="submit" className="btn btn-primary" disabled={loading}>
            {loading ? 'Enviando...' : editingId ? 'Salvar alteracoes' : 'Publicar'}
          </button>
          {editingId && (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                setEditingId(null);
                setForm(emptyNewsForm);
                setImageFile(null);
              }}
            >
              Cancelar edicao
            </button>
          )}
        </div>
        {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
        {message && <p className="text-sm text-[var(--color-up)]">{message}</p>}
      </form>

      <div className="card p-5">
        <p className="label">Noticias publicadas</p>
        <ul className="divide-y divide-[var(--color-border)] mt-2">
          {posts.map((post) => (
            <li key={post.id} className="py-3 flex items-center justify-between gap-3">
              <span className="text-sm">
                {post.title}{' '}
                <span className={`text-xs ml-1 ${post.status === 'published' ? 'text-[var(--color-up)]' : 'text-gray-500'}`}>
                  ({post.status === 'published' ? 'publicada' : post.status === 'draft' ? 'rascunho' : 'agendada'})
                </span>
              </span>
              <div className="flex gap-2 text-xs">
                <button type="button" className="text-[var(--color-accent)] hover:underline" onClick={() => editPost(post)}>
                  editar
                </button>
                <button type="button" className="text-[var(--color-down)] hover:underline" onClick={() => deletePost(post.id)}>
                  remover
                </button>
              </div>
            </li>
          ))}
          {posts.length === 0 && <li className="py-3 text-sm text-gray-500">Nenhuma noticia publicada ainda.</li>}
        </ul>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Paginas estaticas (CMS institucional: Sobre, Termos, etc.)
// ---------------------------------------------------------------------------

const emptyPageForm = { slug: '', title: '', body: '', published: true, menu_order: 0, show_in_menu: false };

function PagesTab({ token, guarded }) {
  const [pages, setPages] = useState([]);
  const [form, setForm] = useState(emptyPageForm);
  const [editingSlug, setEditingSlug] = useState(null);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [revisionsSlug, setRevisionsSlug] = useState(null);
  const [revisions, setRevisions] = useState([]);

  async function loadPages() {
    try {
      const { data } = await guarded(() => api.get('/admin/pages', { headers: authHeaders(token) }));
      setPages(data.pages || []);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    loadPages();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function submit(e) {
    e.preventDefault();
    setLoading(true);
    setError('');
    setMessage('');
    try {
      const slug = editingSlug || form.slug;
      await guarded(() =>
        api.put(
          `/admin/pages/${slug}`,
          { title: form.title, body: form.body, published: form.published, menu_order: Number(form.menu_order) || 0, show_in_menu: form.show_in_menu },
          { headers: authHeaders(token) }
        )
      );
      setMessage(`Pagina '${slug}' salva.`);
      setForm(emptyPageForm);
      setEditingSlug(null);
      loadPages();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function editPage(page) {
    setEditingSlug(page.slug);
    setForm({
      slug: page.slug,
      title: page.title,
      body: page.body,
      published: page.published,
      menu_order: page.menu_order || 0,
      show_in_menu: !!page.show_in_menu,
    });
  }

  async function removePage(slug) {
    if (!window.confirm(`Remover a pagina '${slug}'?`)) return;
    try {
      await guarded(() => api.delete(`/admin/pages/${slug}`, { headers: authHeaders(token) }));
      loadPages();
    } catch (err) {
      setError(err.message);
    }
  }

  async function viewRevisions(slug) {
    try {
      const { data } = await guarded(() => api.get(`/admin/pages/${slug}/revisions`, { headers: authHeaders(token) }));
      setRevisions(data.revisions || []);
      setRevisionsSlug(slug);
    } catch (err) {
      setError(err.message);
    }
  }

  async function restoreRevision(slug, version) {
    if (!window.confirm(`Reverter '${slug}' para a versao ${version}?`)) return;
    try {
      await guarded(() => api.post(`/admin/pages/${slug}/revisions/${version}/restore`, {}, { headers: authHeaders(token) }));
      setRevisionsSlug(null);
      loadPages();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="space-y-6">
      <form onSubmit={submit} className="card p-6 space-y-3">
        <p className="label !mb-2">{editingSlug ? `Editando '${editingSlug}'` : 'Nova pagina'}</p>
        {!editingSlug && (
          <input
            className="input mono"
            placeholder="slug (ex.: sobre-nos)"
            required
            value={form.slug}
            onChange={(e) => setForm({ ...form, slug: e.target.value })}
          />
        )}
        <input className="input" placeholder="Titulo" required value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
        <textarea className="input h-40" placeholder="Conteudo (HTML/Markdown)" value={form.body} onChange={(e) => setForm({ ...form, body: e.target.value })} />
        <label className="flex items-center gap-2 text-sm text-gray-300">
          <input type="checkbox" checked={form.published} onChange={(e) => setForm({ ...form, published: e.target.checked })} />
          Publicada (visivel publicamente em /pages/&lt;slug&gt;)
        </label>
        <label className="flex items-center gap-2 text-sm text-gray-300">
          <input type="checkbox" checked={form.show_in_menu} onChange={(e) => setForm({ ...form, show_in_menu: e.target.checked })} />
          Exibir no menu institucional do site
        </label>
        <div>
          <label className="label">Ordem no menu</label>
          <input type="number" className="input w-24" value={form.menu_order} onChange={(e) => setForm({ ...form, menu_order: e.target.value })} />
        </div>
        <div className="flex gap-2">
          <button type="submit" className="btn btn-primary" disabled={loading}>
            {loading ? 'Salvando...' : 'Salvar'}
          </button>
          {editingSlug && (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                setEditingSlug(null);
                setForm(emptyPageForm);
              }}
            >
              Cancelar
            </button>
          )}
        </div>
        {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
        {message && <p className="text-sm text-[var(--color-up)]">{message}</p>}
      </form>

      <div className="card p-5">
        <p className="label">Paginas cadastradas</p>
        <ul className="divide-y divide-[var(--color-border)] mt-2">
          {pages.map((page) => (
            <li key={page.slug} className="py-3 flex items-center justify-between gap-3">
              <div>
                <span className="text-sm">{page.title}</span>{' '}
                <span className="text-xs text-gray-500 mono">/{page.slug}</span>{' '}
                {!page.published && <span className="text-xs text-[var(--color-down)]">(rascunho)</span>}
                {page.show_in_menu && <span className="text-xs text-[var(--color-accent)] ml-1">(no menu)</span>}
              </div>
              <div className="flex gap-2 text-xs">
                <button type="button" className="text-gray-400 hover:underline" onClick={() => viewRevisions(page.slug)}>
                  historico
                </button>
                <button type="button" className="text-[var(--color-accent)] hover:underline" onClick={() => editPage(page)}>
                  editar
                </button>
                <button type="button" className="text-[var(--color-down)] hover:underline" onClick={() => removePage(page.slug)}>
                  remover
                </button>
              </div>
            </li>
          ))}
          {pages.length === 0 && <li className="py-3 text-sm text-gray-500">Nenhuma pagina cadastrada ainda.</li>}
        </ul>
      </div>

      {revisionsSlug && (
        <div className="card p-5">
          <div className="flex items-center justify-between">
            <p className="label">Historico de revisoes: /{revisionsSlug}</p>
            <button type="button" className="text-xs text-gray-400 hover:underline" onClick={() => setRevisionsSlug(null)}>
              fechar
            </button>
          </div>
          <ul className="divide-y divide-[var(--color-border)] mt-2">
            {revisions.map((rev) => (
              <li key={rev.version} className="py-3 flex items-center justify-between gap-3 text-sm">
                <div>
                  <p>v{rev.version} · {rev.title}</p>
                  <p className="text-xs text-gray-500">
                    salvo por {rev.saved_by} em {new Date(rev.saved_at * 1000).toLocaleString('pt-BR')}
                  </p>
                </div>
                <button
                  type="button"
                  className="text-xs text-[var(--color-accent)] hover:underline"
                  onClick={() => restoreRevision(revisionsSlug, rev.version)}
                >
                  restaurar
                </button>
              </li>
            ))}
            {revisions.length === 0 && <li className="py-3 text-sm text-gray-500">Nenhuma revisao anterior.</li>}
          </ul>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Biblioteca de midia (uploads centralizados)
// ---------------------------------------------------------------------------

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(1)} ${units[i]}`;
}

function MediaTab({ token, guarded }) {
  const [files, setFiles] = useState([]);
  const [stats, setStats] = useState(null);
  const [error, setError] = useState('');
  const [editingId, setEditingId] = useState(null);
  const [metaForm, setMetaForm] = useState({ alt_text: '', tags: '', folder: '' });

  async function load() {
    try {
      const { data } = await guarded(() => api.get('/admin/media', { headers: authHeaders(token) }));
      setFiles(data.files || []);
      setStats(data.stats || null);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function remove(id, force) {
    if (!window.confirm('Remover este arquivo de midia?')) return;
    try {
      await guarded(() => api.delete(`/admin/media/${id}`, { params: { force }, headers: authHeaders(token) }));
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  function startEdit(f) {
    setEditingId(f.id);
    setMetaForm({ alt_text: f.alt_text || '', tags: f.tags || '', folder: f.folder || '' });
  }

  async function saveMeta(id) {
    try {
      await guarded(() => api.put(`/admin/media/${id}`, metaForm, { headers: authHeaders(token) }));
      setEditingId(null);
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="space-y-6">
      {stats && (
        <div className="card p-5 grid grid-cols-2 sm:grid-cols-3 gap-4 text-sm">
          <div>
            <p className="label">Total de arquivos</p>
            <p className="text-lg font-semibold">{stats.total_files}</p>
          </div>
          <div>
            <p className="label">Espaco usado</p>
            <p className="text-lg font-semibold">{formatBytes(stats.total_bytes)}</p>
          </div>
          <div>
            <p className="label">Por categoria</p>
            <p className="text-xs text-gray-400">
              {(stats.by_purpose || []).map((p) => `${p.purpose}: ${p.count}`).join(', ') || '-'}
            </p>
          </div>
        </div>
      )}

      {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}

      <div className="card p-5">
        <p className="label">Arquivos enviados</p>
        <ul className="divide-y divide-[var(--color-border)] mt-2">
          {files.map((f) => (
            <li key={f.id} className="py-3 space-y-2">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <img src={`${API_BASE_URL}${f.url}`} alt={f.alt_text || f.filename} className="w-10 h-10 object-cover rounded-md bg-[var(--color-panel-alt)]" />
                  <div>
                    <p className="text-sm">{f.filename}</p>
                    <p className="text-xs text-gray-500">
                      {f.purpose} · {formatBytes(f.size_bytes)} · por {f.uploaded_by}
                      {f.tags && ` · tags: ${f.tags}`}
                    </p>
                  </div>
                </div>
                <div className="flex gap-2 text-xs shrink-0">
                  <button type="button" className="text-gray-400 hover:underline" onClick={() => startEdit(f)}>
                    editar
                  </button>
                  <button type="button" className="text-[var(--color-down)] hover:underline" onClick={() => remove(f.id, false)}>
                    remover
                  </button>
                </div>
              </div>
              {editingId === f.id && (
                <div className="flex flex-wrap gap-2 pl-13">
                  <input
                    className="input text-xs"
                    placeholder="Texto alternativo (alt)"
                    value={metaForm.alt_text}
                    onChange={(e) => setMetaForm({ ...metaForm, alt_text: e.target.value })}
                  />
                  <input
                    className="input text-xs"
                    placeholder="Tags"
                    value={metaForm.tags}
                    onChange={(e) => setMetaForm({ ...metaForm, tags: e.target.value })}
                  />
                  <input
                    className="input text-xs"
                    placeholder="Pasta"
                    value={metaForm.folder}
                    onChange={(e) => setMetaForm({ ...metaForm, folder: e.target.value })}
                  />
                  <button type="button" className="btn btn-primary text-xs" onClick={() => saveMeta(f.id)}>
                    salvar
                  </button>
                </div>
              )}
            </li>
          ))}
          {files.length === 0 && <li className="py-3 text-sm text-gray-500">Nenhum arquivo enviado ainda.</li>}
        </ul>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Revisao de KYC (verificacao de identidade dos usuarios finais - CPF, RG,
// documento com foto + selfie, tudo cifrado no backend e decifrado apenas
// aqui, sob demanda, para o operador validar visualmente antes de aprovar).
// ---------------------------------------------------------------------------

function KycReviewTab({ token, guarded }) {
  const [statusFilter, setStatusFilter] = useState('pending');
  const [submissions, setSubmissions] = useState([]);
  const [detail, setDetail] = useState(null);
  const [rejectReason, setRejectReason] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

  async function load() {
    setError('');
    try {
      const qs = statusFilter ? `?status=${statusFilter}` : '';
      const { data } = await guarded(() => api.get(`/admin/kyc/submissions${qs}`, { headers: authHeaders(token) }));
      setSubmissions(data.submissions);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter]);

  async function openDetail(id) {
    setError('');
    setDetail(null);
    setRejectReason('');
    try {
      const { data } = await guarded(() => api.get(`/admin/kyc/submissions/${id}`, { headers: authHeaders(token) }));
      setDetail(data);
    } catch (err) {
      setError(err.message);
    }
  }

  async function approve(tier) {
    setLoading(true);
    setError('');
    setMessage('');
    try {
      await guarded(() =>
        api.post(`/admin/kyc/submissions/${detail.id}/approve`, { tier }, { headers: authHeaders(token) })
      );
      setMessage(`Verificacao aprovada (tier ${tier}).`);
      setDetail(null);
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function reject() {
    if (!rejectReason.trim()) {
      setError('Informe o motivo da rejeicao.');
      return;
    }
    setLoading(true);
    setError('');
    setMessage('');
    try {
      await guarded(() =>
        api.post(
          `/admin/kyc/submissions/${detail.id}/reject`,
          { reason: rejectReason.trim() },
          { headers: authHeaders(token) }
        )
      );
      setMessage('Verificacao rejeitada.');
      setDetail(null);
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <p className="label !mb-1">Verificacoes de identidade (KYC) pendentes de revisao</p>
        <p className="text-sm text-gray-500">
          CPF, RG, documento com foto (frente/verso) e selfie sao enviados cifrados pelo usuario e so sao
          decifrados aqui, sob demanda, para a sua revisao visual manual. Nunca aprovado automaticamente.
        </p>
      </div>

      <div className="flex gap-2">
        {['pending', 'approved', 'rejected', ''].map((s) => (
          <button
            key={s || 'all'}
            type="button"
            onClick={() => setStatusFilter(s)}
            className={`px-3 py-1.5 rounded-md text-xs font-medium border ${
              statusFilter === s
                ? 'border-[var(--color-accent)] text-[var(--color-accent)]'
                : 'border-[var(--color-border)] text-gray-400 hover:text-white'
            }`}
          >
            {s === 'pending' ? 'Pendentes' : s === 'approved' ? 'Aprovadas' : s === 'rejected' ? 'Rejeitadas' : 'Todas'}
          </button>
        ))}
      </div>

      {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
      {message && <p className="text-sm text-[var(--color-up)]">{message}</p>}

      <div className="card p-4 overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-500 border-b border-[var(--color-border)]">
              <th className="py-2 pr-3">Usuario</th>
              <th className="py-2 pr-3">E-mail</th>
              <th className="py-2 pr-3">Status</th>
              <th className="py-2 pr-3">Enviado em</th>
              <th className="py-2 pr-3" />
            </tr>
          </thead>
          <tbody>
            {submissions.map((s) => (
              <tr key={s.id} className="border-b border-[var(--color-border)]/50">
                <td className="py-2 pr-3 mono">{s.username}</td>
                <td className="py-2 pr-3 text-gray-400">{s.email}</td>
                <td className="py-2 pr-3">{s.status}</td>
                <td className="py-2 pr-3 text-gray-400">{new Date(s.submitted_at * 1000).toLocaleString('pt-BR')}</td>
                <td className="py-2 pr-3">
                  <button type="button" className="btn btn-secondary text-xs" onClick={() => openDetail(s.id)}>
                    revisar
                  </button>
                </td>
              </tr>
            ))}
            {submissions.length === 0 && (
              <tr>
                <td colSpan={5} className="py-4 text-gray-500 text-center">
                  Nenhuma submissao encontrada.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {detail && (
        <div className="card p-6 space-y-4">
          <div className="flex items-center justify-between">
            <p className="font-semibold">
              Revisao de {detail.username} ({detail.email})
            </p>
            <button type="button" className="text-xs text-gray-400 hover:text-white" onClick={() => setDetail(null)}>
              fechar
            </button>
          </div>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <p className="label !mb-1">Nome completo</p>
              <p>{detail.full_name}</p>
            </div>
            <div>
              <p className="label !mb-1">Data de nascimento</p>
              <p>{detail.birth_date}</p>
            </div>
            <div>
              <p className="label !mb-1">CPF</p>
              <p className="mono">{detail.cpf}</p>
            </div>
            <div>
              <p className="label !mb-1">RG</p>
              <p className="mono">{detail.rg}</p>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <p className="label !mb-1">Documento (frente)</p>
              <img src={detail.document_front_data_uri} alt="Documento frente" className="rounded-md border border-[var(--color-border)] w-full" />
            </div>
            <div>
              <p className="label !mb-1">Documento (verso)</p>
              <img src={detail.document_back_data_uri} alt="Documento verso" className="rounded-md border border-[var(--color-border)] w-full" />
            </div>
            <div>
              <p className="label !mb-1">Selfie</p>
              <img src={detail.selfie_data_uri} alt="Selfie" className="rounded-md border border-[var(--color-border)] w-full" />
            </div>
          </div>

          {detail.status === 'pending' ? (
            <div className="space-y-3 pt-3 border-t border-[var(--color-border)]">
              <div className="flex gap-3">
                <button type="button" className="btn btn-primary" disabled={loading} onClick={() => approve(2)}>
                  Aprovar (tier completo)
                </button>
                <button type="button" className="btn btn-secondary" disabled={loading} onClick={() => approve(1)}>
                  Aprovar (tier basico)
                </button>
              </div>
              <div className="flex gap-3">
                <input
                  className="input flex-1"
                  placeholder="Motivo da rejeicao"
                  value={rejectReason}
                  onChange={(e) => setRejectReason(e.target.value)}
                />
                <button
                  type="button"
                  className="btn"
                  style={{ borderColor: 'var(--color-down)', color: 'var(--color-down)' }}
                  disabled={loading}
                  onClick={reject}
                >
                  Rejeitar
                </button>
              </div>
            </div>
          ) : (
            <p className="text-sm text-gray-400 pt-3 border-t border-[var(--color-border)]">
              Ja revisado por <span className="mono">{detail.reviewed_by}</span> em{' '}
              {new Date(detail.reviewed_at * 1000).toLocaleString('pt-BR')}
              {detail.rejection_reason ? ` — motivo: ${detail.rejection_reason}` : ''}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Chaves de funcionalidade (feature flags)
// ---------------------------------------------------------------------------

function FeaturesTab({ token, guarded }) {
  const [flags, setFlags] = useState([]);
  const [error, setError] = useState('');
  const [busyKey, setBusyKey] = useState('');

  async function load() {
    try {
      const { data } = await guarded(() => api.get('/admin/features', { headers: authHeaders(token) }));
      setFlags(data.flags || []);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function toggle(key, enabled) {
    setBusyKey(key);
    try {
      await guarded(() => api.post(`/admin/features/${key}`, { enabled }, { headers: authHeaders(token) }));
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyKey('');
    }
  }

  return (
    <div className="space-y-4">
      {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
      <div className="card divide-y divide-[var(--color-border)]">
        {flags.map((flag) => (
          <div key={flag.key} className="p-5 flex items-center justify-between gap-4">
            <div>
              <p className="font-medium text-sm">{flag.key}</p>
              <p className="text-xs text-gray-500 mt-1">{flag.description}</p>
              {flag.key === 'maintenance_mode' && flag.enabled && (
                <p className="text-xs text-[var(--color-down)] mt-1">
                  ⚠ Site em manutencao agora - toda a API publica esta bloqueada.
                </p>
              )}
            </div>
            <button
              type="button"
              disabled={busyKey === flag.key}
              onClick={() => toggle(flag.key, !flag.enabled)}
              className={`btn ${flag.enabled ? 'btn-primary' : 'btn-secondary'} text-xs shrink-0`}
            >
              {flag.enabled ? 'Ativado' : 'Desativado'}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Housekeeping (manutencao automatica do sistema)
// ---------------------------------------------------------------------------

function HousekeepingTab({ token, guarded }) {
  const [status, setStatus] = useState(null);
  const [runs, setRuns] = useState([]);
  const [backups, setBackups] = useState([]);
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);
  const [backingUp, setBackingUp] = useState(false);

  async function load() {
    try {
      const [s, h, b] = await Promise.all([
        guarded(() => api.get('/admin/housekeeping/status', { headers: authHeaders(token) })),
        guarded(() => api.get('/admin/housekeeping/history', { headers: authHeaders(token) })),
        guarded(() => api.get('/admin/housekeeping/backups', { headers: authHeaders(token) })),
      ]);
      setStatus(s.data);
      setRuns(h.data.runs || []);
      setBackups(b.data.backups || []);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function runNow() {
    setRunning(true);
    setError('');
    try {
      await guarded(() => api.post('/admin/housekeeping/run', {}, { headers: authHeaders(token) }));
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setRunning(false);
    }
  }

  async function backupNow() {
    setBackingUp(true);
    setError('');
    try {
      await guarded(() => api.post('/admin/housekeeping/backups', {}, { headers: authHeaders(token) }));
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBackingUp(false);
    }
  }

  async function removeBackup(filename) {
    if (!window.confirm(`Remover o backup '${filename}'?`)) return;
    try {
      await guarded(() => api.delete(`/admin/housekeeping/backups/${filename}`, { headers: authHeaders(token) }));
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="space-y-6">
      <div className="card p-5 flex items-center justify-between gap-4 flex-wrap">
        <div>
          <p className="label">Agendador automatico</p>
          <p className="text-sm">
            {status?.scheduler_running ? 'Ativo' : 'Parado'} · executa a cada{' '}
            {status ? Math.round(status.interval_seconds / 3600) : '-'}h
          </p>
        </div>
        <button type="button" className="btn btn-primary" disabled={running} onClick={runNow}>
          {running ? 'Executando...' : 'Executar agora'}
        </button>
      </div>

      {status?.disk_usage && (
        <div className="card p-5 grid grid-cols-3 gap-4 text-sm">
          <div>
            <p className="label">Banco de dados</p>
            <p className="font-semibold">{formatBytes(status.disk_usage.database_bytes)}</p>
          </div>
          <div>
            <p className="label">Uploads</p>
            <p className="font-semibold">{formatBytes(status.disk_usage.uploads_bytes)}</p>
          </div>
          <div>
            <p className="label">Backups</p>
            <p className="font-semibold">{formatBytes(status.disk_usage.backups_bytes)}</p>
          </div>
        </div>
      )}

      {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}

      <div className="card p-5">
        <div className="flex items-center justify-between">
          <p className="label">Backups (banco + uploads, com rotacao automatica)</p>
          <button type="button" className="btn btn-secondary text-xs" disabled={backingUp} onClick={backupNow}>
            {backingUp ? 'Criando...' : 'Criar backup agora'}
          </button>
        </div>
        <ul className="divide-y divide-[var(--color-border)] mt-2">
          {backups.map((b) => (
            <li key={b.filename} className="py-2 flex items-center justify-between text-sm">
              <span className="mono text-xs">{b.filename}</span>
              <div className="flex items-center gap-3 text-xs text-gray-400">
                <span>{formatBytes(b.size_bytes)}</span>
                <button type="button" className="text-[var(--color-down)] hover:underline" onClick={() => removeBackup(b.filename)}>
                  remover
                </button>
              </div>
            </li>
          ))}
          {backups.length === 0 && <li className="py-3 text-sm text-gray-500">Nenhum backup criado ainda.</li>}
        </ul>
      </div>

      <div className="card p-5">
        <p className="label">Historico de execucoes</p>
        <div className="space-y-3 mt-2 max-h-96 overflow-y-auto">
          {runs.map((run) => (
            <div key={run.id} className="text-xs border border-[var(--color-border)] rounded-md p-3 space-y-1">
              <p className="text-gray-400">
                {new Date(run.finished_at * 1000).toLocaleString('pt-BR')} · {run.triggered_by} · {run.duration_seconds.toFixed(2)}s
              </p>
              {run.stats?.warnings?.length > 0 && (
                <p className="text-[var(--color-down)]">⚠ {run.stats.warnings.join('; ')}</p>
              )}
              <pre className="mono whitespace-pre-wrap break-all text-gray-500">{JSON.stringify(run.actions)}</pre>
            </div>
          ))}
          {runs.length === 0 && <p className="text-sm text-gray-500">Nenhuma execucao registrada ainda.</p>}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Configuracoes gerais do site (identidade, contato, SEO, redes sociais)
// ---------------------------------------------------------------------------

function SiteSettingsTab({ token, guarded }) {
  const [form, setForm] = useState(null);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

  async function load() {
    try {
      const { data } = await guarded(() => api.get('/admin/settings', { headers: authHeaders(token) }));
      setForm(data);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function submit(e) {
    e.preventDefault();
    setLoading(true);
    setError('');
    setMessage('');
    try {
      const { data } = await guarded(() => api.put('/admin/settings', form, { headers: authHeaders(token) }));
      setForm(data);
      setMessage('Configuracoes salvas.');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  if (!form) return <p className="text-sm text-gray-500">Carregando...</p>;

  const fields = [
    ['site_name', 'Nome do site'],
    ['tagline', 'Slogan / tagline'],
    ['support_email', 'E-mail de suporte'],
    ['contact_phone', 'Telefone de contato'],
    ['seo_description', 'Descricao SEO (meta description)'],
    ['social_twitter', 'Twitter/X (URL)'],
    ['social_instagram', 'Instagram (URL)'],
    ['social_telegram', 'Telegram (URL)'],
    ['maintenance_message', 'Mensagem exibida em modo manutencao'],
  ];

  return (
    <form onSubmit={submit} className="card p-6 space-y-3 max-w-2xl">
      <p className="label !mb-2">Configuracoes gerais do site</p>
      {fields.map(([key, label]) => (
        <div key={key}>
          <label className="label">{label}</label>
          <input className="input" value={form[key] || ''} onChange={(e) => setForm({ ...form, [key]: e.target.value })} />
        </div>
      ))}
      {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
      {message && <p className="text-sm text-[var(--color-up)]">{message}</p>}
      <button type="submit" className="btn btn-primary" disabled={loading}>
        {loading ? 'Salvando...' : 'Salvar configuracoes'}
      </button>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Equipe (gestao multi-usuario - somente contas 'owner')
// ---------------------------------------------------------------------------

function UsersTab({ token, username, guarded }) {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({ username: '', password: '', role: 'editor' });
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

  async function load() {
    try {
      const { data } = await guarded(() => api.get('/admin/users', { headers: authHeaders(token) }));
      setUsers(data.users || []);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function createUser(e) {
    e.preventDefault();
    setLoading(true);
    setError('');
    setMessage('');
    try {
      await guarded(() => api.post('/admin/users', form, { headers: authHeaders(token) }));
      setMessage(`Operador '${form.username}' criado.`);
      setForm({ username: '', password: '', role: 'editor' });
      load();
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  }

  async function removeUser(target) {
    if (!window.confirm(`Remover o operador '${target}'?`)) return;
    try {
      await guarded(() => api.delete(`/admin/users/${target}`, { headers: authHeaders(token) }));
      load();
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  }

  return (
    <div className="space-y-6">
      <form onSubmit={createUser} className="card p-6 space-y-3 max-w-md">
        <p className="label !mb-2">Novo operador</p>
        <input
          className="input"
          placeholder="Usuario"
          required
          minLength={3}
          value={form.username}
          onChange={(e) => setForm({ ...form, username: e.target.value })}
        />
        <input
          type="password"
          className="input"
          placeholder="Senha (min. 10 caracteres)"
          required
          minLength={10}
          value={form.password}
          onChange={(e) => setForm({ ...form, password: e.target.value })}
        />
        <select className="input" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
          <option value="editor">Editor (sem gestao de equipe)</option>
          <option value="owner">Owner (acesso total)</option>
        </select>
        {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
        {message && <p className="text-sm text-[var(--color-up)]">{message}</p>}
        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? 'Criando...' : 'Criar operador'}
        </button>
      </form>

      <div className="card p-5">
        <p className="label">Operadores cadastrados</p>
        <ul className="divide-y divide-[var(--color-border)] mt-2">
          {users.map((u) => (
            <li key={u.username} className="py-3 flex items-center justify-between gap-3 text-sm">
              <div>
                <p className="mono">
                  {u.username} {u.username === username && <span className="text-xs text-gray-500">(voce)</span>}
                </p>
                <p className="text-xs text-gray-500">
                  {u.role} · {u.totp_enabled ? '2FA ativo' : '2FA inativo'} ·{' '}
                  {u.last_login_at ? `ultimo login ${new Date(u.last_login_at * 1000).toLocaleString('pt-BR')}` : 'nunca logou'}
                </p>
              </div>
              {u.username !== username && (
                <button type="button" className="text-xs text-[var(--color-down)] hover:underline" onClick={() => removeUser(u.username)}>
                  remover
                </button>
              )}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Seguranca (integridade do codigo-fonte)
// ---------------------------------------------------------------------------

function SecurityTab({ token, guarded }) {
  const [status, setStatus] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const { data } = await guarded(() => api.get('/security/integrity-status', { headers: authHeaders(token) }));
      setStatus(data);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function resetBaseline() {
    if (!window.confirm('Aceitar o estado ATUAL do codigo como novo baseline confiavel?')) return;
    setBusy(true);
    try {
      await guarded(() => api.post('/security/integrity-reset-baseline', {}, { headers: authHeaders(token) }));
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
      {status && (
        <div className="card p-5 space-y-3">
          <p className={`text-sm font-medium ${status.tampered ? 'text-[var(--color-down)]' : 'text-[var(--color-up)]'}`}>
            {status.tampered ? '⚠ Adulteracao detectada no codigo-fonte!' : '✓ Codigo-fonte integro (confere com o baseline)'}
          </p>
          {status.changed_files?.length > 0 && (
            <ul className="text-xs text-gray-400 list-disc list-inside">
              {status.changed_files.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
          )}
          <button type="button" className="btn btn-secondary text-xs" disabled={busy} onClick={resetBaseline}>
            Aceitar estado atual como novo baseline
          </button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Conta (trocar senha)
// ---------------------------------------------------------------------------

function AccountTab({ token, username, guarded, onLogout }) {
  const [form, setForm] = useState({ old_password: '', new_password: '', confirm: '' });
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [me, setMe] = useState(null);

  // --- 2FA ---
  const [setup2fa, setSetup2fa] = useState(null); // { secret, qr_code_base64, otpauth_uri }
  const [otpCode, setOtpCode] = useState('');
  const [backupCodes, setBackupCodes] = useState(null);
  const [disablePassword, setDisablePassword] = useState('');
  const [twofaError, setTwofaError] = useState('');
  const [twofaMessage, setTwofaMessage] = useState('');
  const [twofaBusy, setTwofaBusy] = useState(false);

  async function loadMe() {
    try {
      const { data } = await guarded(() => api.get('/admin/auth/me', { headers: authHeaders(token) }));
      setMe(data);
    } catch (err) {
      setTwofaError(err.message);
    }
  }

  useEffect(() => {
    loadMe();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function submit(e) {
    e.preventDefault();
    setError('');
    setMessage('');
    if (form.new_password !== form.confirm) {
      setError('A confirmacao de senha nao confere');
      return;
    }
    setLoading(true);
    try {
      await api.post(
        '/admin/auth/change-password',
        { old_password: form.old_password, new_password: form.new_password },
        { headers: authHeaders(token) }
      );
      setMessage('Senha alterada com sucesso.');
      setForm({ old_password: '', new_password: '', confirm: '' });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function startSetup() {
    setTwofaError('');
    setTwofaMessage('');
    try {
      const { data } = await guarded(() => api.post('/admin/auth/2fa/setup', {}, { headers: authHeaders(token) }));
      setSetup2fa(data);
      setBackupCodes(null);
    } catch (err) {
      setTwofaError(err.message);
    }
  }

  async function confirmSetup(e) {
    e.preventDefault();
    setTwofaBusy(true);
    setTwofaError('');
    try {
      const { data } = await guarded(() => api.post('/admin/auth/2fa/enable', { code: otpCode }, { headers: authHeaders(token) }));
      setBackupCodes(data.backup_codes);
      setSetup2fa(null);
      setOtpCode('');
      loadMe();
    } catch (err) {
      setTwofaError(err.response?.data?.detail || err.message);
    } finally {
      setTwofaBusy(false);
    }
  }

  async function disable2fa(e) {
    e.preventDefault();
    setTwofaBusy(true);
    setTwofaError('');
    try {
      await guarded(() => api.post('/admin/auth/2fa/disable', { password: disablePassword }, { headers: authHeaders(token) }));
      setTwofaMessage('2FA desativado.');
      setDisablePassword('');
      loadMe();
    } catch (err) {
      setTwofaError(err.response?.data?.detail || err.message);
    } finally {
      setTwofaBusy(false);
    }
  }

  return (
    <div className="max-w-md space-y-6">
      <div className="card p-5">
        <p className="label">Conta autenticada</p>
        <p className="text-sm mono">{username}</p>
        {me && <p className="text-xs text-gray-500 mt-1">Papel: {me.role}</p>}
      </div>
      <form onSubmit={submit} className="card p-6 space-y-3">
        <p className="label !mb-2">Trocar senha</p>
        <input
          type="password"
          className="input"
          placeholder="Senha atual"
          required
          value={form.old_password}
          onChange={(e) => setForm({ ...form, old_password: e.target.value })}
        />
        <input
          type="password"
          className="input"
          placeholder="Nova senha (min. 10 caracteres)"
          required
          value={form.new_password}
          onChange={(e) => setForm({ ...form, new_password: e.target.value })}
        />
        <input
          type="password"
          className="input"
          placeholder="Confirmar nova senha"
          required
          value={form.confirm}
          onChange={(e) => setForm({ ...form, confirm: e.target.value })}
        />
        {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
        {message && <p className="text-sm text-[var(--color-up)]">{message}</p>}
        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? 'Salvando...' : 'Salvar nova senha'}
        </button>
      </form>

      <div className="card p-6 space-y-3">
        <p className="label !mb-2">Autenticacao em duas etapas (2FA)</p>
        <p className="text-xs text-gray-500">
          Status atual: <span className={me?.totp_enabled ? 'text-[var(--color-up)]' : 'text-[var(--color-down)]'}>
            {me?.totp_enabled ? 'Ativado' : 'Desativado'}
          </span>
        </p>

        {twofaError && <p className="text-sm text-[var(--color-down)]">{twofaError}</p>}
        {twofaMessage && <p className="text-sm text-[var(--color-up)]">{twofaMessage}</p>}

        {backupCodes && (
          <div className="text-xs bg-[var(--color-panel-alt)] rounded-md p-3 space-y-1">
            <p className="font-medium">Guarde estes codigos de backup - so sao exibidos UMA VEZ:</p>
            <ul className="mono grid grid-cols-2 gap-1">
              {backupCodes.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          </div>
        )}

        {!me?.totp_enabled && !setup2fa && (
          <button type="button" className="btn btn-primary text-sm" onClick={startSetup}>
            Ativar 2FA
          </button>
        )}

        {setup2fa && (
          <form onSubmit={confirmSetup} className="space-y-3">
            <p className="text-xs text-gray-400">
              Escaneie o QR code com Google Authenticator, Authy ou similar, ou use o segredo manual abaixo.
            </p>
            <img src={`data:image/png;base64,${setup2fa.qr_code_base64}`} alt="QR code 2FA" className="w-40 h-40 rounded-md bg-white p-2" />
            <p className="text-xs mono break-all">{setup2fa.secret}</p>
            <input
              className="input mono"
              placeholder="Codigo de 6 digitos do app"
              value={otpCode}
              onChange={(e) => setOtpCode(e.target.value)}
              required
            />
            <button type="submit" className="btn btn-primary text-sm" disabled={twofaBusy}>
              {twofaBusy ? 'Verificando...' : 'Confirmar e ativar'}
            </button>
          </form>
        )}

        {me?.totp_enabled && (
          <form onSubmit={disable2fa} className="space-y-3">
            <input
              type="password"
              className="input"
              placeholder="Senha atual (para desativar)"
              value={disablePassword}
              onChange={(e) => setDisablePassword(e.target.value)}
              required
            />
            <button type="submit" className="btn btn-secondary text-sm" disabled={twofaBusy}>
              {twofaBusy ? 'Desativando...' : 'Desativar 2FA'}
            </button>
          </form>
        )}
      </div>

      <button type="button" className="btn btn-secondary w-full" onClick={onLogout}>
        Sair
      </button>
    </div>
  );
}
