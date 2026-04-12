import { request } from '@umijs/max';

// Clients
export async function getClients() {
  return request<any[]>('/api/clients');
}

export async function getClient(id: number) {
  return request<any>(`/api/clients/${id}`);
}

export async function createClient(data: any) {
  return request('/api/clients', { method: 'POST', data });
}

export async function updateClient(id: number, data: any) {
  return request(`/api/clients/${id}`, { method: 'PUT', data });
}

export async function deleteClient(id: number) {
  return request(`/api/clients/${id}`, { method: 'DELETE' });
}

// API Resources
export async function getApiResources() {
  return request<any[]>('/api/apiresources');
}

export async function createApiResource(data: any) {
  return request('/api/apiresources', { method: 'POST', data });
}

export async function updateApiResource(id: number, data: any) {
  return request(`/api/apiresources/${id}`, { method: 'PUT', data });
}

export async function deleteApiResource(id: number) {
  return request(`/api/apiresources/${id}`, { method: 'DELETE' });
}

// API Scopes
export async function getApiScopes() {
  return request<any[]>('/api/apiscopes');
}

export async function createApiScope(data: any) {
  return request('/api/apiscopes', { method: 'POST', data });
}

export async function deleteApiScope(id: number) {
  return request(`/api/apiscopes/${id}`, { method: 'DELETE' });
}

// Identity Resources
export async function getIdentityResources() {
  return request<any[]>('/api/identityresources');
}

export async function createIdentityResource(data: any) {
  return request('/api/identityresources', { method: 'POST', data });
}

export async function deleteIdentityResource(id: number) {
  return request(`/api/identityresources/${id}`, { method: 'DELETE' });
}
