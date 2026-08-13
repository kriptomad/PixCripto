import { createContext, useContext, useEffect, useMemo, useState, useCallback } from 'react';
import api from '../api/client.js';

const TOKEN_KEY = 'pixcripto.user.token';

const AuthContext = createContext(null);

function authHeaders(token) {
  return { Authorization: `Bearer ${token}` };
}

/**
 * Sessao da conta de USUARIO do site (cadastro/login/KYC) - diferente do
 * `AdminPage`, que autentica operadores do painel. Guarda apenas o token de
 * sessao (nunca senha) em `localStorage`; o perfil completo (incl. status de
 * KYC) e recarregado do backend a cada montagem.
 */
export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || '');
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadProfile = useCallback(async (currentToken) => {
    if (!currentToken) {
      setProfile(null);
      setLoading(false);
      return;
    }
    try {
      const { data } = await api.get('/auth/me', { headers: authHeaders(currentToken) });
      setProfile(data);
    } catch {
      setToken('');
      localStorage.removeItem(TOKEN_KEY);
      setProfile(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadProfile(token);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  const login = useCallback((newToken) => {
    localStorage.setItem(TOKEN_KEY, newToken);
    setToken(newToken);
  }, []);

  const logout = useCallback(() => {
    if (token) {
      api.post('/auth/logout', {}, { headers: authHeaders(token) }).catch(() => {});
    }
    localStorage.removeItem(TOKEN_KEY);
    setToken('');
    setProfile(null);
  }, [token]);

  const refresh = useCallback(() => loadProfile(token), [token, loadProfile]);

  const value = useMemo(
    () => ({ token, profile, loading, isAuthenticated: Boolean(token && profile), login, logout, refresh }),
    [token, profile, loading, login, logout, refresh]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth deve ser usado dentro de <AuthProvider>');
  return ctx;
}

export { authHeaders };
