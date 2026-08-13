import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout.jsx';
import Dashboard from './pages/Dashboard.jsx';
import WalletPage from './pages/WalletPage.jsx';
import SendPage from './pages/SendPage.jsx';
import ReceivePage from './pages/ReceivePage.jsx';
import HistoryPage from './pages/HistoryPage.jsx';
import MarketPage from './pages/MarketPage.jsx';
import TradePage from './pages/TradePage.jsx';
import NewsPage from './pages/NewsPage.jsx';
import NewsDetailPage from './pages/NewsDetailPage.jsx';
import AdminPage from './pages/AdminPage.jsx';
import CmsPageView from './pages/CmsPageView.jsx';
import AuthPage from './pages/AuthPage.jsx';
import AccountPage from './pages/AccountPage.jsx';

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/wallet" element={<WalletPage />} />
        <Route path="/send" element={<SendPage />} />
        <Route path="/receive" element={<ReceivePage />} />
        <Route path="/history" element={<HistoryPage />} />
        <Route path="/market" element={<MarketPage />} />
        <Route path="/trade" element={<TradePage />} />
        <Route path="/news" element={<NewsPage />} />
        <Route path="/news/:id" element={<NewsDetailPage />} />
        <Route path="/admin" element={<AdminPage />} />
        <Route path="/pages/:slug" element={<CmsPageView />} />
        <Route path="/auth" element={<AuthPage />} />
        <Route path="/account" element={<AccountPage />} />
      </Route>
    </Routes>
  );
}
