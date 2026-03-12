import axios from 'axios';

const API = axios.create({ baseURL: '/api' });

export const getAlerts = (params) => API.get('/alerts', { params });
export const getAlert = (id) => API.get(`/alerts/${id}`);
export const getStats = () => API.get('/alerts/summary/stats');
export const syncAlerts = () => API.post('/sync');
export const getSyncStatus = () => API.get('/sync/status');
export const reprocessAlert = (id) => API.post(`/alerts/${id}/reprocess`);
export const getAgents = () => API.get('/alerts/agents/list');
export const getRuleGroups = () => API.get('/alerts/groups/list');
