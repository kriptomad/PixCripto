import { createContext, useContext, useEffect, useMemo, useState, useCallback } from 'react';

const STORAGE_KEY = 'pixcripto.wallets';
const ACTIVE_KEY = 'pixcripto.activeAddress';

const WalletContext = createContext(null);

function loadWallets() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveWallets(wallets) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(wallets));
}

/**
 * Estado global de carteiras, guardado em localStorage no navegador do
 * usuario - o backend NUNCA armazena chaves privadas (o mesmo modelo de
 * confianca de uma carteira Bitcoin/Ethereum "self-custody" comum).
 */
export function WalletProvider({ children }) {
  const [wallets, setWallets] = useState(loadWallets);
  const [activeAddress, setActiveAddress] = useState(() => localStorage.getItem(ACTIVE_KEY) || '');

  useEffect(() => {
    saveWallets(wallets);
  }, [wallets]);

  useEffect(() => {
    if (activeAddress) {
      localStorage.setItem(ACTIVE_KEY, activeAddress);
    } else {
      localStorage.removeItem(ACTIVE_KEY);
    }
  }, [activeAddress]);

  const addWallet = useCallback((wallet) => {
    setWallets((prev) => {
      if (prev.some((w) => w.address === wallet.address)) return prev;
      return [...prev, wallet];
    });
    setActiveAddress(wallet.address);
  }, []);

  const removeWallet = useCallback((address) => {
    setWallets((prev) => prev.filter((w) => w.address !== address));
    setActiveAddress((prev) => (prev === address ? '' : prev));
  }, []);

  const activeWallet = useMemo(
    () => wallets.find((w) => w.address === activeAddress) || null,
    [wallets, activeAddress]
  );

  const value = useMemo(
    () => ({ wallets, activeWallet, activeAddress, setActiveAddress, addWallet, removeWallet }),
    [wallets, activeWallet, activeAddress, addWallet, removeWallet]
  );

  return <WalletContext.Provider value={value}>{children}</WalletContext.Provider>;
}

export function useWallet() {
  const ctx = useContext(WalletContext);
  if (!ctx) throw new Error('useWallet deve ser usado dentro de <WalletProvider>');
  return ctx;
}
