import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import api, { API_BASE_URL } from '../api/client.js';

function fmtDate(iso) {
  if (!iso) return '';
  const date = typeof iso === 'number' ? new Date(iso * 1000) : new Date(iso);
  return date.toLocaleDateString('pt-BR', { day: '2-digit', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function resolveImage(url) {
  if (!url) return null;
  if (url.startsWith('http')) return url;
  return `${API_BASE_URL}${url}`;
}

export default function NewsDetailPage() {
  const { id } = useParams();
  const [post, setPost] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const { data } = await api.get(`/news/${id}`);
        if (!cancelled) setPost(data);
      } catch (err) {
        if (!cancelled) setError(err.message);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [id]);

  if (error) {
    return (
      <div>
        <p className="text-sm text-[var(--color-down)] mb-4">{error}</p>
        <Link to="/news" className="btn btn-secondary">
          Voltar
        </Link>
      </div>
    );
  }

  if (!post) return <p className="text-gray-500 text-sm">Carregando...</p>;

  return (
    <article className="max-w-3xl mx-auto space-y-5">
      <Link to="/news" className="text-sm text-gray-400 hover:text-white">
        ← Voltar para noticias
      </Link>
      <h1 className="text-3xl font-bold leading-tight">{post.title}</h1>
      <p className="text-sm text-gray-500">
        {post.author} · {fmtDate(post.published_at)}
      </p>
      {post.image_url && (
        <img src={resolveImage(post.image_url)} alt={post.title} className="w-full rounded-xl border border-[var(--color-border)]" />
      )}
      {post.summary && <p className="text-lg text-gray-300">{post.summary}</p>}
      <div className="prose prose-invert max-w-none whitespace-pre-wrap text-gray-200 leading-relaxed">{post.body}</div>
    </article>
  );
}
