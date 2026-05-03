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
  generate: (scanId: string) => api.post(`/reports/${scanId}/generate`),
  download: (scanId: string) => api.get(`/reports/${scanId}/download`, { responseType: 'blob' }),
}

// Billing
export const billingApi = {
  status: () => api.get('/billing/status'),
  createKaspi:  () => api.post('/billing/kaspi/create'),
  createStripe: () => api.post('/billing/stripe/create-checkout'),
}
