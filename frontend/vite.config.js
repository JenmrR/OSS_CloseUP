import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// /api/* 요청을 FastAPI(127.0.0.1:8000)로 넘긴다.
// 이렇게 하면 CORS 설정이 필요 없고, backend는 로컬 바인딩을 그대로 유지한다.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
