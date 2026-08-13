import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import api, { API_BASE_URL } from '../api/client.js';

function fmtDate(iso) {
  if (!iso) return '';
  const date = typeof iso === 'number' ? new Date(iso * 1000) : new Date(iso);
  return date.toLocaleDateString('pt-BR', { day: '2-digit', month: 'long', year: 'numeric' });
}

function resolveImage(url) {
  if (!url) return null;
  if (url.startsWith('http')) return url;
  return `${API_BASE_URL}${url}`;
}

export default function NewsPage() {
  const [posts, setPosts] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const { data } = await api.get('/news', { params: { limit: 30 } });
        if (!cancelled) setPosts(data.posts || []);
      } catch (err) {
        if (!cancelled) setError(err.message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Noticias</h1>
      {error && <p className="text-sm text-[var(--color-down)]">{error}</p>}
      {loading && <p className="text-gray-500 text-sm">Carregando...</p>}
      {!loading && posts.length === 0 && (
        <p className="text-gray-500 text-sm">Nenhuma noticia publicada ainda.</p>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {posts.map((post) => (
          <Link key={post.id} to={`/news/${post.id}`} className="card overflow-hidden hover:border-[var(--color-accent)] transition-colors">
            {post.image_url && (
              <img src={resolveImage(post.image_url)} alt={post.title} className="w-full h-40 object-cover" />
            )}
            <div className="p-4">
              <p className="text-xs text-gray-500 mb-1">
                {post.author} · {fmtDate(post.published_at)}
              </p>
              <h2 className="font-semibold text-lg leading-snug">{post.title}</h2>
              {post.summary && <p className="text-sm text-gray-400 mt-2 line-clamp-3">{post.summary}</p>}
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
