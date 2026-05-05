import axios from 'axios'
import { useAuthStore } from '@/stores/authStore'

export const api = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (r) => r,
  async (error) => {
    if (error.response?.status === 401) {
      useAuthStore.getState().logout()
      window.location.href = '/login'
    }
    return Promise.reject(error)
  },
)

// Auth
export const authApi = {
  login:    (data: { email: string; password: string }) => api.post('/auth/login', data),
  register: (data: { email: string; password: string; full_name: string }) => api.post('/auth/register', data),
  logout:   () => api.post('/auth/logout'),
  me:       () => api.get('/users/me'),
}

// Scans
export const scansApi = {
  list:   (params?: { page?: number; limit?: number }) => api.get('/scans', { params }),
  get:    (id: string) => api.get(`/scans/${id}`),
  create: (data: { target: string; scan_type: string; options?: Record<string, unknown> }) => api.post('/scans', data),
  delete: (id: string) => api.delete(`/scans/${id}`),
}

// Reports
export const reportsApi = {
  generate: (scanId: string, lang: 'ru' | 'en' = 'ru') =>
    api.post(`/reports/${scanId}/generate`, null, { params: { lang } }),
  list: (scanId: string) => api.get(`/reports/${scanId}`),
  download: (scanId: string, lang: 'ru' | 'en' = 'ru') =>
    api.get(`/reports/${scanId}/download`, { params: { lang }, responseType: 'blob' }),
}

// Admin
export const adminApi = {
  users:      (p?: { page?: number; limit?: number; search?: string; plan?: string }) =>
                api.get('/admin/users', { params: p }),
  updateUser: (id: string, data: { is_active?: boolean; role?: string; plan?: string }) =>
                api.patch(`/admin/users/${id}`, data),
  scans:      (p?: { page?: number; limit?: number; status?: string }) =>
                api.get('/admin/scans', { params: p }),
  stats:      () => api.get('/admin/stats'),
}

// DDoS
export const ddosApi = {
  start:  (data: {
    target: string; attack_type: string; method?: string
    concurrency?: number; duration?: number; intensity?: string
  }) => api.post('/ddos/start', data),
  stop:   (jobId: string) => api.post(`/ddos/stop/${jobId}`),
  status: (jobId: string) => api.get(`/ddos/status/${jobId}`),
}

// Billing
export const billingApi = {
  status:       () => api.get('/billing/status'),
  history:      () => api.get('/billing/history'),
  createKaspi:  () => api.post('/billing/kaspi/create'),
  createStripe: () => api.post('/billing/stripe/create-checkout'),
}
