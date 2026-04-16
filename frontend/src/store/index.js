/**
 * Zustand Global State Store
 * Handles: auth, scan queue, alerts, UI preferences
 *
 * Usage (when using Vite/bundler setup):
 *   import { useAuthStore, useScanStore } from '@/store'
 */
import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:4000';

// ─── Auth Store ───────────────────────────────────────────────
export const useAuthStore = create(
  persist(
    (set, get) => ({
      user:  null,
      token: null,
      isAuthenticated: false,

      login: async (email, password) => {
        const res = await axios.post(`${API_BASE}/auth/login`, { email, password });
        const { token, user } = res.data;
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        set({ user, token, isAuthenticated: true });
        return user;
      },

      logout: () => {
        delete axios.defaults.headers.common['Authorization'];
        set({ user: null, token: null, isAuthenticated: false });
      },

      restoreSession: () => {
        const { token } = get();
        if (token) axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      },
    }),
    {
      name: 'cyberscope-auth',
      storage: createJSONStorage(() => sessionStorage), // session-only
      partialize: state => ({ user: state.user, token: state.token, isAuthenticated: state.isAuthenticated }),
    }
  )
);

// ─── Scan Store ───────────────────────────────────────────────
export const useScanStore = create((set, get) => ({
  results:    {},
  scanHistory: [],
  activeScans: {},

  runDomainScan: async (domain) => {
    const jobId = `domain-${Date.now()}`;
    set(s => ({ activeScans: { ...s.activeScans, [jobId]: { status: 'running', target: domain } } }));
    try {
      const res = await axios.get(`${API_BASE}/domain`, { params: { name: domain } });
      const result = { ...res.data.data, target: domain, type: 'domain', timestamp: new Date().toISOString() };
      set(s => ({
        results: { ...s.results, [domain]: result },
        scanHistory: [result, ...s.scanHistory].slice(0, 50),
        activeScans: Object.fromEntries(Object.entries(s.activeScans).filter(([k]) => k !== jobId)),
      }));
      return result;
    } catch (err) {
      set(s => ({ activeScans: Object.fromEntries(Object.entries(s.activeScans).filter(([k]) => k !== jobId)) }));
      throw err;
    }
  },

  runIPScan: async (ip) => {
    const res = await axios.get(`${API_BASE}/ip`, { params: { address: ip } });
    return res.data.data;
  },

  runSocialScan: async (username) => {
    const res = await axios.get(`${API_BASE}/osint/social`, { params: { username } });
    return res.data.data;
  },

  runThreatCheck: async (target) => {
    const res = await axios.get(`${API_BASE}/threat-check`, { params: { target } });
    return res.data.data;
  },

  computeRiskScore: async (features) => {
    const res = await axios.post(`${API_BASE}/risk-score`, features);
    return res.data.result;
  },

  clearHistory: () => set({ scanHistory: [], results: {} }),
}));

// ─── Alert Store ──────────────────────────────────────────────
export const useAlertStore = create((set) => ({
  alerts: [],
  unreadCount: 0,

  addAlert: (alert) =>
    set(s => ({
      alerts: [{ ...alert, id: Date.now(), createdAt: new Date().toISOString(), read: false }, ...s.alerts],
      unreadCount: s.unreadCount + 1,
    })),

  markAllRead: () =>
    set(s => ({
      alerts: s.alerts.map(a => ({ ...a, read: true })),
      unreadCount: 0,
    })),

  clearAlerts: () => set({ alerts: [], unreadCount: 0 }),
}));

// ─── UI Preferences Store ─────────────────────────────────────
export const useUIStore = create(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      activePage:       'dashboard',

      setSidebarCollapsed: (v) => set({ sidebarCollapsed: v }),
      setActivePage: (page) => set({ activePage: page }),
    }),
    { name: 'cyberscope-ui' }
  )
);
