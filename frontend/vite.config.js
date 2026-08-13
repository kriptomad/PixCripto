import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
// base '/app/' apenas no build de producao: e onde o FastAPI (app/api.py)
// monta os assets estaticos gerados. No `vite dev` mantemos base '/' para
// nao quebrar o servidor de desenvolvimento local.
export default defineConfig(({ command }) => ({
  base: command === 'build' ? '/app/' : '/',
  plugins: [react(), tailwindcss()],
  server: {
    host: '127.0.0.1',
    port: 5173,
  },
}))
