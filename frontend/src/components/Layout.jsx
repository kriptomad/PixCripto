import { NavLink, Outlet, Link } from 'react-router-dom';
import { useWallet } from '../context/WalletContext.jsx';
import { useAuth } from '../context/AuthContext.jsx';
import { API_BASE_URL } from '../api/client.js';

const navItems = [
  { to: '/', label: 'Painel', end: true },
  { to: '/send', label: 'Enviar' },
  { to: '/receive', label: 'Receber' },
  { to: '/history', label: 'Historico' },
  { to: '/market', label: 'Mercado' },
  { to: '/trade', label: 'Negociar' },
  { to: '/news', label: 'Noticias' },
];

function linkClass({ isActive }) {
  return `px-3 py-2 rounded-md text-sm font-medium transition-colors ${
    isActive ? 'bg-[var(--color-accent-soft)] text-[var(--color-accent)]' : 'text-gray-300 hover:text-white hover:bg-white/5'
  }`;
}

function shorten(address) {
  if (!address) return '';
  return `${address.slice(0, 8)}…${address.slice(-6)}`;
}

export default function Layout() {
  const { activeWallet, wallets, setActiveAddress } = useWallet();
  const { isAuthenticated, profile } = useAuth();

  return (
    <div className="min-h-full flex flex-col">
      <header className="border-b border-[var(--color-border)] bg-[var(--color-panel)] sticky top-0 z-20">
        <div className="max-w-7xl mx-auto px-4 flex items-center justify-between h-16">
          <Link to="/" className="flex items-center gap-2 font-bold text-lg tracking-tight">
            <span className="w-8 h-8 rounded-full bg-[var(--color-accent)] text-[#14161d] flex items-center justify-center font-black">
              P
            </span>
            <span>
              Pix<span className="text-[var(--color-accent)]">Cripto</span>
            </span>
          </Link>

          <nav className="hidden md:flex items-center gap-1">
            {navItems.map((item) => (
              <NavLink key={item.to} to={item.to} end={item.end} className={linkClass}>
                {item.label}
              </NavLink>
            ))}
          </nav>

          <div className="flex items-center gap-3">
            {wallets.length > 0 && (
              <select
                value={activeWallet?.address || ''}
                onChange={(e) => setActiveAddress(e.target.value)}
                className="input !w-auto text-xs mono hidden sm:block"
              >
                <option value="" disabled>
                  Selecionar carteira
                </option>
                {wallets.map((w) => (
                  <option key={w.address} value={w.address}>
                    {w.label ? `${w.label} · ` : ''}
                    {shorten(w.address)}
                  </option>
                ))}
              </select>
            )}
            <Link to="/wallet" className="btn btn-primary text-sm">
              {activeWallet ? shorten(activeWallet.address) : 'Criar carteira'}
            </Link>
            {isAuthenticated ? (
              <Link to="/account" className="btn btn-secondary text-sm">
                {profile?.username || 'Minha conta'}
              </Link>
            ) : (
              <Link to="/auth" className="btn btn-secondary text-sm">
                Entrar / Registrar
              </Link>
            )}
          </div>
        </div>
        <nav className="md:hidden flex overflow-x-auto gap-1 px-4 pb-2">
          {navItems.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end} className={linkClass}>
              {item.label}
            </NavLink>
          ))}
        </nav>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 py-6">
        <Outlet />
      </main>

      <footer className="border-t border-[var(--color-border)] py-6 mt-10">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row justify-between gap-3 text-xs text-gray-500">
          <p>© {new Date().getFullYear()} PixCripto — rede descentralizada ancorada em ouro.</p>
          <div className="flex gap-4">
            <Link to="/pages/sobre-nos" className="hover:text-gray-300">
              Sobre
            </Link>
            <Link to="/admin" className="hover:text-gray-300">
              Admin de conteudo
            </Link>
            <a href={`${API_BASE_URL}/rules/book`} target="_blank" rel="noreferrer" className="hover:text-gray-300">
              Book of Rules
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
