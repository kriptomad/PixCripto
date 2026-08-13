import axios from 'axios';

// URL base do backend FastAPI. Em producao, defina VITE_API_BASE_URL no
// momento do build (arquivo .env) apontando para o host real da API.
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 20_000,
});

// Normaliza mensagens de erro vindas do FastAPI (campo "detail") para que os
// componentes possam simplesmente mostrar `err.message` ao usuario.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const detail = error?.response?.data?.detail;
    if (detail) {
      const message = typeof detail === 'string' ? detail : JSON.stringify(detail);
      error.message = message;
    }
    return Promise.reject(error);
  }
);

export default api;
