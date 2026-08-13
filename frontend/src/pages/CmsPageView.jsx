import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../api/client.js';

/**
 * Renderizador publico de paginas estaticas do CMS (`app/cms.py`) - Sobre,
 * Termos de uso, Politica de privacidade, FAQ etc., editaveis pelo operador
 * no Painel de Administracao (aba "Paginas (CMS)") sem precisar de deploy.
 */
export default function CmsPageView() {
  const { slug } = useParams();
  const [page, setPage] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    setPage(null);
    setError('');
    api
      .get(`/pages/${slug}`)
      .then(({ data }) => setPage(data))
      .catch((err) => setError(err.message || 'Pagina nao encontrada'));
  }, [slug]);

  if (error) {
    return (
      <div className="max-w-2xl mx-auto text-center py-16 space-y-3">
        <h1 className="text-xl font-bold">Pagina nao encontrada</h1>
        <p className="text-gray-500 text-sm">{error}</p>
        <Link to="/" className="text-[var(--color-accent)] text-sm hover:underline">
          Voltar ao inicio
        </Link>
      </div>
    );
  }

  if (!page) {
    return <p className="text-center text-gray-500 py-16">Carregando...</p>;
  }

  return (
    <div className="max-w-3xl mx-auto space-y-4">
      <h1 className="text-2xl font-bold">{page.title}</h1>
      <div className="card p-6 whitespace-pre-wrap text-sm leading-relaxed text-gray-300">{page.body}</div>
    </div>
  );
}
